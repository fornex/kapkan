//go:build linux

package dataplane

// The Manager: the lifecycle of the XDP data plane, from "does this kernel even
// have what we need" to "the program is attached and enforcing", and back.
//
// It owns four things the map helpers in maps_linux.go deliberately do not:
//
//  1. SIZE. dataplane.limits becomes real here, by rewriting max_entries on the
//     CollectionSpec before the maps are created. Until this file existed the
//     limits were validated and then discarded, so an operator who lowered
//     max_ratelimit_sources to fit a small box still paid for two 1,048,576-entry
//     LRU hashes — 94% of a measured 234.9 MiB, charged to the unit's memory
//     cgroup in one step at load. See limits.go.
//
//  2. IDENTITY. Pins let policy survive a restart, and adopting the wrong pins
//     is worse than not adopting any: same map names, same sizes, and every
//     field after a changed struct member read at the wrong offset. See
//     pins_linux.go.
//
//  3. ATTACHMENT, including what to do when a NIC disappears. An interface that
//     comes back must be re-attached, and one that does not come back must be
//     visible — a condition and a metric, never a crash and never a silent
//     no-op.
//
//  4. REFUSAL. Everything here that cannot be made to work fails at startup with
//     an error naming the kernel version, the capability or the mode. That is a
//     departure from how kapkan handles its other optional components, and the
//     justification is in probe_linux.go: a data plane that silently is not
//     there means the operator asked for a drop and is not dropping.
//
// WHAT IS NOT HERE. Dynamic rules. The mitigator's backend — turning an attack
// into policy blocks and victim entries — is a separate change, and the map
// helpers it needs (PutPolicy, AddVictim, EncodeRules, InactiveGeneration,
// Activate) already exist. Maps() is the seam.

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// Manager owns a loaded, attached and pinned data plane.
//
// Every exported method is safe for concurrent use. The lock is coarse — one
// mutex over the whole thing — because every operation it guards is a syscall
// batch measured in milliseconds that happens at startup, on a config reload, or
// on a 2-second watcher tick. Finer locking would buy nothing and cost the
// ability to reason about the generation flip.
type Manager struct {
	opts   Options
	log    *slog.Logger
	kernel string
	sizing MapSizing
	// progTag is the kernel tag of the program THIS binary loads, learned by
	// loading it (see probeLoad). It is the adoption test.
	progTag string
	now     func() time.Time

	mu         sync.Mutex
	objs       *Objects
	ifaces     []*ifaceState
	profileIDs map[string]uint32
	adopted    bool
	conds      []Condition
	closed     bool

	// watchStop/watchDone are the watcher goroutine's handles, and stopWatcher
	// is a Once because Close touches them BEFORE taking m.mu (the watcher takes
	// the same lock on every tick, so stopping it under the lock would deadlock
	// or wait a full interval). Without the Once, two concurrent Closes would
	// close(watchStop) twice and panic.
	watchStop   chan struct{}
	watchDone   chan struct{}
	stopWatcher sync.Once
}

// ifaceState is the manager's view of one configured interface.
type ifaceState struct {
	name  string
	index int
	mode  string
	link  link.Link

	attached bool
	attempts int
	lastErr  string
	since    time.Time

	// backoff is the delay before the next attach attempt, and nextTry the
	// earliest moment to make it. Both are only touched by the watcher and by
	// Open, under m.mu.
	backoff time.Duration
	nextTry time.Time
}

// Open brings the data plane up: probe, size, load or adopt, install static
// policy, attach.
//
// It returns an error rather than a degraded Manager when nothing can work at
// all — an unsupported kernel, a missing capability, an unsafe pin directory, a
// program the verifier rejects, or not one interface that would take the
// program. It returns a Manager with a degraded Health when SOME interfaces
// attached and others did not, because refusing to protect eth0 because eth1 is
// down is not a service to anybody.
func Open(opts Options) (*Manager, error) {
	if err := opts.normalize(); err != nil {
		return nil, err
	}
	log := opts.Log.With("component", "dataplane")

	kernel, err := preflight(opts.PinPath)
	if err != nil {
		return nil, err
	}

	// A no-op on 5.11+, where map memory is charged to the memory cgroup
	// instead of RLIMIT_MEMLOCK. Kept for the older kernels inside the
	// supported range, and only logged on failure: on a modern kernel a failure
	// here means nothing.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Debug("could not raise RLIMIT_MEMLOCK; harmless on kernels 5.11 and newer", "err", err)
	}

	sizing, err := opts.Limits.MapSizing()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		opts:       opts,
		log:        log,
		kernel:     kernel,
		sizing:     sizing,
		now:        time.Now,
		profileIDs: map[string]uint32{},
	}

	// Learn our own program's kernel tag, and prove the verifier accepts it,
	// BEFORE touching the operator's pins. Order matters: a schema mismatch
	// tears the existing pins down, and discovering only afterwards that the
	// replacement does not load would leave the box with no data plane at all.
	tag, verified, err := probeLoad()
	if err != nil {
		return nil, err
	}
	m.progTag = tag
	log.Info("data plane pre-flight passed",
		"kernel", kernel, "program_tag", tag, "verified_insns", verified,
		"policy_stride", sizing.PolicyStride, "static_stride", sizing.StaticStride,
		"ratelimit_sources", sizing.RLSources, "rule_stats", sizing.RuleStats)

	if err := m.load(); err != nil {
		return nil, err
	}

	// Static policy first, then attach: the program must never see a packet
	// before the operator's rules are in the map it is about to read.
	if err := m.installInitialPolicy(); err != nil {
		m.closeObjects()
		return nil, err
	}

	if err := m.attachAll(); err != nil {
		m.closeObjects()
		return nil, err
	}

	m.publishHealthLocked()
	m.startWatcher()
	return m, nil
}

// probeLoad loads the program with the maps shrunk to almost nothing, to learn
// two things cheaply: the kernel tag of the instruction stream this binary
// installs, and whether the verifier accepts it on this kernel.
//
// The tag cannot be computed from the ELF. kapkan_xdp.c uses global
// (non-inlined) functions for its rule scans — that shape is what keeps the
// verifier at 12% of its instruction budget instead of blowing past it — so the
// CollectionSpec's instruction stream for kapkan_xdp_filter does not yet include
// its callees, while the tag the kernel computes covers the linked whole. Asking
// the kernel is the only honest answer.
//
// The cost is one extra program load and a few tens of KiB of maps, once, at
// startup. Limits{1, 1, 256} runs it through the real applySizing path, so the
// probe also exercises the sizing arithmetic on every start.
func probeLoad() (tag string, verifiedInsns uint32, err error) {
	spec, err := loadKapkanXDP()
	if err != nil {
		return "", 0, fmt.Errorf("dataplane: parse embedded BPF object: %w", err)
	}
	probe, err := Limits{MaxDynamicRules: 1, MaxStaticRules: 1, MaxRatelimitSources: 256}.MapSizing()
	if err != nil {
		return "", 0, err
	}
	if err := applySizing(spec, probe); err != nil {
		return "", 0, err
	}

	var objs Objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return "", 0, fmt.Errorf("dataplane: the verifier rejected kapkan_xdp_filter on this kernel. "+
				"If the log below ends in \"pointer -= pointer prohibited\" the process is missing "+
				"CAP_PERFMON and this is not a kapkan bug (see engine/deploy/dataplane-operations.md §1):\n%+v", ve)
		}
		return "", 0, fmt.Errorf("dataplane: load BPF object: %w", err)
	}
	defer func() { _ = objs.Close() }()

	info, err := objs.KapkanXdpFilter.Info()
	if err != nil {
		return "", 0, fmt.Errorf("dataplane: program info: %w", err)
	}
	verifiedInsns, _ = info.VerifiedInstructions()
	return info.Tag, verifiedInsns, nil
}

// load fills m.objs, either by adopting an existing pinned set or by creating a
// new one. It holds no lock: Open is the only caller and nothing else exists
// yet.
func (m *Manager) load() error {
	dir := m.opts.PinPath
	existed, err := ensurePinDir(dir)
	if err != nil {
		return err
	}

	if existed {
		spec, err := m.sizedSpec()
		if err != nil {
			return err
		}
		res, err := tryAdopt(dir, spec, m.progTag)
		if err != nil {
			return err
		}
		if res.Objs != nil {
			m.objs, m.adopted = res.Objs, true
			metrics.DataplanePinsRebuilt.Set(0)
			m.log.Info("adopted the pinned data plane from a previous process; "+
				"dynamic rules and token buckets are preserved",
				"pin_path", dir, "program_tag", m.progTag)
			return nil
		}
		// Two very different outcomes end up here, and only one of them costs
		// the operator anything.
		//
		// A cold start is an empty (or program-less) pin directory: systemd's
		// RuntimeDirectory=, a packaging script, or our own previous run under
		// on_exit: detach all leave one behind. Nothing was ever attached
		// through those pins, so no dynamic rule can have been lost. Saying
		// "your rules are gone" here would fire the alarm on a healthy first
		// boot and teach operators to ignore it.
		//
		// A rejection is a pin set we looked at and refused — a schema bump, a
		// changed map layout, different limits. That really does discard the
		// previous process's dynamic rules, and it is the upgrade story working
		// as designed, so it gets a WARN, a condition and the metric.
		if res.ColdStart {
			m.log.Info("no pinned data plane found; creating one",
				"pin_path", dir, "detail", res.Reason)
		} else {
			m.log.Warn("REJECTED the existing pinned data plane and rebuilt it; "+
				"every dynamic rule installed by the previous process is gone "+
				"(static policy is not: it comes from the config file). "+
				"Active attacks will be re-mitigated on their next detection interval",
				"pin_path", dir, "reason", res.Reason)
		}
		removed, unknown, err := removeOurPins(dir)
		if err != nil {
			return err
		}
		if len(unknown) > 0 {
			m.log.Warn("pin directory holds entries this build does not recognise; leaving them alone",
				"pin_path", dir, "entries", unknown)
		}
		if len(removed) > 0 {
			m.log.Info("removed stale pins", "count", len(removed), "pins", removed)
		}
		if res.ColdStart {
			metrics.DataplanePinsRebuilt.Set(0)
		} else {
			m.setCondition(Condition{
				Kind:    CondPinsRebuilt,
				Message: "existing pins were rejected and rebuilt (" + res.Reason + "); dynamic rules from the previous process were lost",
				Since:   m.now(),
			})
			metrics.DataplanePinsRebuilt.Set(1)
		}
	} else {
		metrics.DataplanePinsRebuilt.Set(0)
	}

	spec, err := m.sizedSpec()
	if err != nil {
		return err
	}
	var objs Objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("dataplane: verifier rejected the program:\n%+v", ve)
		}
		return fmt.Errorf("dataplane: create the data plane: %w", err)
	}
	if err := pinObjects(dir, &objs); err != nil {
		_ = objs.Close()
		return err
	}
	m.objs = &objs
	m.log.Info("created and pinned a new data plane", "pin_path", dir)
	return nil
}

// sizedSpec parses the embedded object and applies the resolved limits. A fresh
// spec each time: LoadAndAssign consumes one, and reusing a spec that has been
// through the linker is how you get a program that loads once and never again.
func (m *Manager) sizedSpec() (*ebpf.CollectionSpec, error) {
	spec, err := loadKapkanXDP()
	if err != nil {
		return nil, fmt.Errorf("dataplane: parse embedded BPF object: %w", err)
	}
	if err := applySizing(spec, m.sizing); err != nil {
		return nil, err
	}
	return spec, nil
}

/* ========================================================================= */
/* Static policy                                                              */
/* ========================================================================= */

// installInitialPolicy writes the operator's static policy and publishes it.
//
// On a fresh load it builds generation 0 and stamps the whole of kapkan_cfg. On
// an adopted set it builds the INACTIVE generation and flips, exactly as a
// reload does, because the config file may have changed while this host was
// down and the attached program must not run yesterday's rules for a moment
// longer than the flip takes.
func (m *Manager) installInitialPolicy() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	maps := m.objs.MapSet()
	if m.adopted {
		// The flags BEFORE the policy, and unconditionally.
		//
		// dry_run and drop_malformed live in kapkan_cfg, which is map CONTENTS —
		// nothing in the adoption check looks at them (MapSpec.Compatible compares
		// shape, and the program tag covers instructions). So an adopted data plane
		// used to inherit the previous process's flags: run with dry_run: true,
		// satisfy yourself the rules match, set dry_run: false, restart, and the
		// pins are adopted while the kernel keeps rewriting every drop into a pass.
		// The config said the filter was armed and the kernel disagreed, with
		// nothing anywhere to say so. See TestAdoptionRewritesFlags.
		if err := putFlags(maps, m.opts.DryRun, m.opts.DropMalformed); err != nil {
			return err
		}
		gen, err := InactiveGeneration(maps)
		if err != nil {
			return err
		}
		rep, err := m.installPolicyLocked(m.opts.Policy, gen)
		if err != nil {
			return err
		}
		m.log.Info("re-installed static policy over the adopted data plane",
			"detail", rep.Summary(), "dry_run", m.opts.DryRun,
			"drop_malformed", m.opts.DropMalformed)
		return nil
	}

	// Fresh: stamp kapkan_cfg first so the strides and the schema version are
	// in place before anything reads them, then build generation 0 and publish.
	if err := PutConfig(maps, ConfigSpec{
		Generation:    0,
		DryRun:        m.opts.DryRun,
		DropMalformed: m.opts.DropMalformed,
	}); err != nil {
		return err
	}
	if got := PolicyStride(maps); got != m.sizing.PolicyStride {
		return fmt.Errorf("dataplane: kapkan_policies stride is %d, the resolved limits say %d "+
			"(the map was not created at the size this process asked for)", got, m.sizing.PolicyStride)
	}
	if got := StaticStride(maps); got != m.sizing.StaticStride {
		return fmt.Errorf("dataplane: kapkan_statics stride is %d, the resolved limits say %d", got, m.sizing.StaticStride)
	}
	rep, err := m.installPolicyLocked(m.opts.Policy, 0)
	if err != nil {
		return err
	}
	m.log.Info("installed static policy", "detail", rep.Summary())
	return nil
}

// installPolicyLocked compiles pol, writes it into generation gen, reconciles
// the prefix tries, and publishes gen. The caller holds m.mu.
//
// It never touches kapkan_policies or kapkan_victims: those hold the
// mitigator's dynamic rules, and a config reload that dropped an active
// mitigation would be a reload that un-mitigated a live attack.
func (m *Manager) installPolicyLocked(pol StaticPolicy, gen uint32) (ReloadReport, error) {
	// Timed here rather than around Reload because this is the span that holds
	// m.mu across kernel writes, and m.mu is what a rule install has to wait for
	// (WithMaps). A failed apply is timed too: the operator's question is how long
	// the lock was held, and a compile error that took 8ms held it for 8ms.
	defer func(start time.Time) {
		metrics.DataplanePolicyApplySeconds.Observe(time.Since(start).Seconds())
	}(m.now())

	maps := m.objs.MapSet()
	rep := ReloadReport{Generation: gen}

	c, err := compilePolicy(pol, m.sizing, m.profileIDs)
	if err != nil {
		return rep, err
	}

	// Profiles first: a rule published in the flip below may reference one, and
	// a rule whose profile is not yet written caps nothing (the datapath admits
	// when a profile has neither a packet nor a byte rate), which would be a
	// rate limit that silently is not there.
	for id, spec := range c.profileSpec {
		if err := PutProfile(maps, id, spec); err != nil {
			return rep, err
		}
	}
	// Then retire the ids that no longer belong to a declared profile. Zeroing
	// is the retirement: a zeroed profile caps neither packets nor bytes, so any
	// rule still pointing at it admits — which is the direction the charter
	// requires. Profiles live and die with the config, as config documents.
	for name, id := range m.profileIDs {
		if _, still := c.profileOf[name]; still {
			continue
		}
		if err := PutProfile(maps, id, ProfileSpec{}); err != nil {
			return rep, err
		}
	}
	m.profileIDs = c.profileOf
	rep.Profiles = len(c.profileSpec)

	count, err := PutStatics(maps, gen, c.rules)
	if err != nil {
		return rep, err
	}
	rep.StaticRules = int(count)

	// One rule_stats entry per encoded rule, created before the rules go live:
	// the datapath only bumps an entry that already exists, so creating them
	// afterwards would lose the first packets of every rule.
	if err := EnsureRuleStats(maps, c.ruleIDs...); err != nil {
		return rep, err
	}

	allowAdded, allowRemoved, err := reconcileTrie(maps.KapkanAllow4, maps.KapkanAllow6, pol.Allow, "allowlist",
		func(p netip.Prefix) error { return AddAllowSource(maps, p) },
		func(p netip.Prefix) error { return DeleteAllowSource(maps, p) })
	if err != nil {
		return rep, err
	}
	rep.AllowAdded, rep.AllowRemoved = prefixStrings(allowAdded), prefixStrings(allowRemoved)

	protAdded, protRemoved, err := reconcileTrie(maps.KapkanProtect4, maps.KapkanProtect6, pol.Protected, "protected list",
		func(p netip.Prefix) error { return AddProtectedDestination(maps, p) },
		func(p netip.Prefix) error { return DeleteProtectedDestination(maps, p) })
	if err != nil {
		return rep, err
	}
	rep.ProtectedAdded, rep.ProtectedRemoved = prefixStrings(protAdded), prefixStrings(protRemoved)

	// Reconciliation case config cannot see #1: a static rule that can never
	// fire, because the allowlist (precedence 1, which stops evaluation) or an
	// EARLIER static rule (precedence 3 is first match wins) already takes every
	// packet it selects. Reported rather than rejected — see shadow.go for why —
	// and reported loudly, because the symptom is a rule counter that sits at
	// zero, which is exactly what a healthy rule looks like on a quiet day.
	sh := ShadowedStatics(pol)
	metrics.DataplaneShadowedStaticRules.Set(float64(len(sh)))
	if len(sh) > 0 {
		rep.ShadowedStatics = sh
		m.log.Warn("static rules can never fire: something evaluated before them already takes every "+
			"packet they match. The allowlist is precedence 1 and static rules are first match wins "+
			"within precedence 3, so these rules are dead policy — remove them, move them above the "+
			"rule that covers them, or narrow the allowlist entry",
			"rules", sh)
		m.setConditionLocked(Condition{
			Kind:    CondPolicyShadowed,
			Message: fmt.Sprintf("%d static rule(s) can never fire: %v", len(sh), sh),
			Since:   m.now(),
		})
	} else {
		m.clearConditionLocked(CondPolicyShadowed, "")
	}

	// Reconciliation case config cannot see #2: an allowlist entry that now
	// covers something the MITIGATOR installed. Nothing to repair — the kernel
	// checks the allowlist before any rule — but the operator has to be told
	// that a live mitigation just stopped dropping. Scanned only when the
	// allowlist actually grew, because it costs one map read per policy block.
	if len(allowAdded) > 0 {
		live, err := ReadConfig(maps)
		if err != nil {
			return rep, err
		}
		n, err := shadowedDynamicRules(maps, live.Generation, m.sizing.PolicyStride, allowAdded)
		if err != nil {
			return rep, err
		}
		rep.ShadowedDynamicRules = n
		if n > 0 {
			m.log.Warn("new allowlist entries now cover sources that live mitigation rules were dropping; "+
				"those rules stopped taking effect the moment the allowlist entry landed",
				"rules", n, "allowlist_added", prefixStrings(allowAdded))
		}
	}

	// Carry the mitigator's dynamic rules into the half we are about to publish.
	// kapkan_policies shares the generation counter with kapkan_statics, so
	// without this the flip below would un-mitigate every live attack — see
	// mirrorPolicyBlocks.
	active, err := ReadConfig(maps)
	if err != nil {
		return rep, err
	}
	mirrored, err := mirrorPolicyBlocks(maps, active.Generation, gen, m.sizing.PolicyStride)
	if err != nil {
		return rep, err
	}
	rep.MirroredPolicyBlocks = mirrored

	// Publish. Statics and their count move together; see Activate's note on
	// why all four torn combinations are safe.
	if err := Activate(maps, gen, count); err != nil {
		return rep, err
	}
	return rep, nil
}

/* ========================================================================= */
/* Attach                                                                     */
/* ========================================================================= */

// attachAll attaches every configured interface, adopting a live pinned link
// where one exists.
//
// It fails only when NOT ONE interface ended up attached: a data plane attached
// to nothing is indistinguishable from a disabled one and must not start
// quietly. Partial success starts degraded, which is the honest state — eth0 is
// protected, eth1 is not, and both facts are visible.
func (m *Manager) attachAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stale link pins for interfaces this config no longer names would keep an
	// old attachment alive with no owner in this process. Remove them first.
	pinned, err := pinnedLinkPins(m.opts.PinPath)
	if err != nil {
		return err
	}
	configured := make(map[string]bool, len(m.opts.Interfaces))
	for _, n := range m.opts.Interfaces {
		configured[n] = true
	}
	for _, lp := range pinned {
		if configured[lp.iface] {
			continue
		}
		m.log.Warn("removing a pinned XDP attachment for an interface this configuration no longer names",
			"interface", lp.iface, "mode", lp.mode, "pin", lp.path)
		if err := discardLinkPin(lp.path); err != nil {
			return err
		}
	}

	attached := 0
	var firstErr error
	for _, name := range m.opts.Interfaces {
		st := &ifaceState{name: name, since: m.now(), backoff: m.opts.BackoffMin}
		m.ifaces = append(m.ifaces, st)
		if err := m.attachLocked(st, true); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		attached++
	}
	if attached == 0 {
		return fmt.Errorf("dataplane: could not attach to any of the configured interfaces (%v): %w",
			m.opts.Interfaces, firstErr)
	}
	if attached < len(m.ifaces) {
		m.log.Warn("the data plane is DEGRADED: some configured interfaces are not filtering",
			"attached", attached, "configured", len(m.ifaces), "first_error", firstErr)
	}
	return nil
}

// attachLocked brings one interface up: resolve it, adopt its pinned link if
// that link is still bound to it, otherwise attach and pin fresh. The caller
// holds m.mu.
//
// initial distinguishes startup from a watcher retry, which changes only the log
// level and whether a re-attach is counted: a re-attach is an event worth a
// counter, an initial attach is not.
func (m *Manager) attachLocked(st *ifaceState, initial bool) error {
	index, exists, err := resolveInterface(st.name)
	if err != nil {
		return m.attachFailedLocked(st, err)
	}
	if !exists {
		m.setConditionLocked(Condition{
			Kind: CondInterfaceMissing, Interface: st.name,
			Message: fmt.Sprintf("interface %q does not exist; the data plane is not filtering it", st.name),
			Since:   m.now(),
		})
		return m.attachFailedLocked(st, fmt.Errorf("interface %q does not exist", st.name))
	}
	m.clearConditionLocked(CondInterfaceMissing, st.name)

	// An existing pinned link for this interface is either still usable — in
	// which case adopting it keeps the attachment unbroken across the restart —
	// or it must go before a fresh attach can pin over it. "Usable" is two
	// questions: is it still bound to the interface that now carries this name,
	// and is it in a mode this configuration accepts.
	if lp, ok := findLinkPin(m.opts.PinPath, st.name); ok {
		if !m.modeAcceptsLocked(lp.mode) {
			// An operator who changed xdp_mode and restarted did so to get the
			// other mode. Adopting would give them the old one and say nothing,
			// which is precisely the class of silence this package exists to
			// avoid. (A runtime change is refused by Reload; a restart is how it
			// is meant to be applied, so it has to actually apply.)
			m.log.Warn("the pinned attachment is in a mode this configuration does not accept; "+
				"re-attaching", "interface", st.name, "pinned_mode", lp.mode, "xdp_mode", m.opts.XDPMode)
			if err := discardLinkPin(lp.path); err != nil {
				return m.attachFailedLocked(st, err)
			}
		} else {
			l, gotIndex, aerr := adoptLink(m.opts.PinPath, st.name, lp.mode, index)
			if aerr == nil {
				st.link, st.index, st.mode = l, index, lp.mode
				m.markAttachedLocked(st, initial, true)
				return nil
			}
			m.log.Warn("discarding a stale pinned XDP attachment",
				"interface", st.name, "pinned_ifindex", gotIndex, "current_ifindex", index, "err", aerr)
			if err := discardLinkPin(lp.path); err != nil {
				return m.attachFailedLocked(st, err)
			}
		}
	}

	l, mode, err := attachXDP(m.objs.KapkanXdpFilter, st.name, index, m.opts.XDPMode)
	if err != nil {
		return m.attachFailedLocked(st, err)
	}
	if err := l.Pin(linkPin(m.opts.PinPath, st.name, mode)); err != nil {
		_ = l.Close() // closing an unpinned link detaches it, which is right here
		return m.attachFailedLocked(st, fmt.Errorf("dataplane: pin the %s attachment: %w", st.name, err))
	}
	st.link, st.index, st.mode = l, index, mode
	m.markAttachedLocked(st, initial, false)
	return nil
}

// modeAcceptsLocked reports whether a pinned attachment in the given mode
// satisfies the configured xdp_mode.
//
// auto accepts either, on purpose. auto means "the fastest path this driver
// supports", and re-attaching to re-test that would break a working attachment
// for a result that is almost always the same one. The cost is that a driver
// which GAINS native XDP support (a kernel or firmware upgrade) will keep the
// generic attachment until the pins are rebuilt or the program detached — which
// is visible, because the mode is in Health and in the pin name.
func (m *Manager) modeAcceptsLocked(pinnedMode string) bool {
	if m.opts.XDPMode == config.XDPModeAuto {
		return true
	}
	return pinnedMode == m.opts.XDPMode
}

// markAttachedLocked records a successful attach and says so once.
func (m *Manager) markAttachedLocked(st *ifaceState, initial, wasAdopted bool) {
	wasDown := !st.attached
	st.attached = true
	st.attempts = 0
	st.lastErr = ""
	st.backoff = m.opts.BackoffMin
	if wasDown {
		st.since = m.now()
	}
	m.clearConditionLocked(CondUnattached, st.name)

	// A generic-mode attachment under xdp_mode: auto is not a failure, but it
	// costs roughly an order of magnitude of per-packet CPU, and an operator who
	// wrote "auto" and got "generic" should not have to infer it.
	if m.opts.XDPMode == config.XDPModeAuto && st.mode == config.XDPModeGeneric {
		m.setConditionLocked(Condition{
			Kind: CondModeDowngraded, Interface: st.name,
			Message: fmt.Sprintf("%s has no native XDP support, so the generic (skb) path is in use; "+
				"expect roughly an order of magnitude less capacity than native", st.name),
			Since: m.now(),
		})
	} else {
		m.clearConditionLocked(CondModeDowngraded, st.name)
	}

	verb := "attached"
	switch {
	case wasAdopted:
		verb = "adopted the existing attachment on"
	case !initial:
		verb = "re-attached"
		metrics.DataplaneReattachTotal.WithLabelValues(st.name).Inc()
	}
	m.log.Info("data plane "+verb, "interface", st.name, "ifindex", st.index, "mode", st.mode)
	metrics.SetDataplaneAttached(st.name, st.mode, true)
}

// attachFailedLocked records a failure, grows the backoff and returns the error
// unchanged so a caller can still report it.
func (m *Manager) attachFailedLocked(st *ifaceState, err error) error {
	if st.attached {
		st.since = m.now()
	}
	st.attached = false
	st.attempts++
	st.lastErr = err.Error()
	if st.link != nil {
		_ = st.link.Close()
		st.link = nil
	}
	metrics.DataplaneAttachErrorsTotal.WithLabelValues(st.name).Inc()
	metrics.SetDataplaneAttached(st.name, st.mode, false)

	st.nextTry = m.now().Add(st.backoff)
	if st.backoff *= 2; st.backoff > m.opts.BackoffMax {
		st.backoff = m.opts.BackoffMax
	}
	m.setConditionLocked(Condition{
		Kind: CondUnattached, Interface: st.name,
		Message: fmt.Sprintf("no XDP attachment on %s after %d attempt(s): %v", st.name, st.attempts, err),
		Since:   st.since,
	})
	return err
}

/* ========================================================================= */
/* The interface watcher                                                      */
/* ========================================================================= */

// startWatcher launches the re-attach loop unless it is disabled.
func (m *Manager) startWatcher() {
	if m.opts.WatchInterval < 0 {
		return
	}
	m.watchStop = make(chan struct{})
	m.watchDone = make(chan struct{})
	go m.watch(m.opts.WatchInterval)
}

// watch keeps every configured interface attached.
//
// It exists because a NIC going away is normal — a driver reload, a bond member
// cycling, a veth in a test — and every one of those silently detaches the XDP
// program. The kernel does not tell us: an unregistered netdevice leaves the
// bpf_link in place reporting ifindex 0, so liveness has to be POLLED. The
// alternative, an rtnetlink subscription, would mean promoting a netlink
// dependency and writing a message parser to learn the same fact.
//
// A failure here never crashes and never passes silently: it grows a backoff,
// raises a condition, and increments a counter.
func (m *Manager) watch(interval time.Duration) {
	defer close(m.watchDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-m.watchStop:
			return
		case <-t.C:
			m.Reconcile()
		}
	}
}

// Reconcile runs one pass of the attachment check. The watcher calls it on a
// ticker; it is exported so a test can drive it deterministically instead of
// sleeping, and so an operator-triggered "try again now" has somewhere to land.
func (m *Manager) Reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for _, st := range m.ifaces {
		m.reconcileOneLocked(st)
	}
	m.publishHealthLocked()
}

func (m *Manager) reconcileOneLocked(st *ifaceState) {
	if st.attached {
		if live, index := m.linkLiveLocked(st); live {
			st.index = index
			return
		}
		// The netdevice this link was bound to is gone. Drop the pin and the fd
		// so the next attempt can attach cleanly; the interface may be back
		// under the same name with a different ifindex.
		m.log.Warn("lost the XDP attachment: the interface's netdevice went away",
			"interface", st.name, "ifindex", st.index)
		if lp, ok := findLinkPin(m.opts.PinPath, st.name); ok {
			if err := discardLinkPin(lp.path); err != nil {
				m.log.Error("could not unpin the dead attachment", "interface", st.name, "err", err)
			}
		}
		_ = m.attachFailedLocked(st, errors.New("the interface's netdevice was unregistered"))
		// Retry immediately: the interface is often already back.
		st.nextTry = m.now()
		st.backoff = m.opts.BackoffMin
	}
	if m.now().Before(st.nextTry) {
		return
	}
	_ = m.attachLocked(st, false)
}

// linkLiveLocked asks the kernel whether the link is still bound to a
// netdevice, and to which one.
//
// ifindex 0 is the kernel's own answer for "the device is gone":
// bpf_xdp_link_fill_link_info reports xdp_link->dev->ifindex, or 0 when dev is
// NULL, which is what netdev unregistration leaves behind.
func (m *Manager) linkLiveLocked(st *ifaceState) (bool, int) {
	if st.link == nil {
		return false, 0
	}
	info, err := st.link.Info()
	if err != nil {
		m.log.Warn("could not read link info; treating the attachment as lost",
			"interface", st.name, "err", err)
		return false, 0
	}
	x := info.XDP()
	if x == nil || x.Ifindex == 0 {
		return false, 0
	}
	// A different ifindex under the same name means the NIC was replaced and
	// this link is filtering something else (or nothing).
	index, exists, _ := resolveInterface(st.name)
	if !exists || index != int(x.Ifindex) {
		return false, int(x.Ifindex)
	}
	return true, index
}

/* ========================================================================= */
/* Reload                                                                     */
/* ========================================================================= */

// Reload replaces the STATIC policy on a running program and nothing else.
//
// It refuses a change to the interface set, the attach mode, the pin path or the
// limits, naming the fields. config.Store.Reload already rejects those for the
// whole daemon; this exists as well because the two answer for different things.
// config refuses to accept the file; this refuses to pretend that a Manager
// holding maps the kernel already created at one size can honour another. There
// is no bpf(2) call that resizes a map, and an LRU cannot shrink: the only way
// to apply a new max_ratelimit_sources is a new map, and a new map means
// dropping every token bucket and every dynamic rule.
//
// Dynamic rules are never touched. A reload that un-mitigated a live attack
// because the operator fixed a typo in a notification template would be a
// spectacular own goal.
func (m *Manager) Reload(next Options) (ReloadReport, error) {
	if err := next.normalize(); err != nil {
		return ReloadReport{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ReloadReport{}, ErrClosed
	}
	if diff := m.opts.restartRequired(next); diff != "" {
		return ReloadReport{}, fmt.Errorf("%w: %s", ErrRestartRequired, diff)
	}

	maps := m.objs.MapSet()
	// Flags before the flip, so the two writes stay independent — see putFlags.
	if next.DryRun != m.opts.DryRun || next.DropMalformed != m.opts.DropMalformed {
		if err := putFlags(maps, next.DryRun, next.DropMalformed); err != nil {
			return ReloadReport{}, err
		}
		m.log.Info("data plane flags changed",
			"dry_run", next.DryRun, "drop_malformed", next.DropMalformed)
	}

	gen, err := InactiveGeneration(maps)
	if err != nil {
		return ReloadReport{}, err
	}
	rep, err := m.installPolicyLocked(next.Policy, gen)
	if err != nil {
		// The inactive generation may be half-built, which is harmless: nothing
		// reads it until Activate, and Activate did not run.
		return rep, err
	}

	// Only now commit the new options: a failed reload must leave the manager
	// describing what is actually in the kernel.
	keep := m.opts.Log
	m.opts = next
	m.opts.Log = keep
	m.log.Info("data plane static policy reloaded", "detail", rep.Summary())
	return rep, nil
}

/* ========================================================================= */
/* Health, statistics and accessors                                           */
/* ========================================================================= */

// Health reports the /healthz-consumable state.
func (m *Manager) Health() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthLocked()
}

func (m *Manager) healthLocked() Health {
	h := Health{Enabled: true, Adopted: m.adopted}
	for _, st := range m.ifaces {
		h.Interfaces = append(h.Interfaces, InterfaceStatus{
			Name: st.name, Index: st.index, Mode: st.mode, Attached: st.attached,
			Attempts: st.attempts, LastError: st.lastErr, Since: st.since,
		})
		if !st.attached {
			h.Degraded = true
		}
	}
	h.Conditions = append(h.Conditions, m.conds...)
	return h
}

// publishHealthLocked mirrors the degraded flag into the metric. Called after
// anything that can change it, so a scrape never lags the log.
func (m *Manager) publishHealthLocked() {
	degraded := 0.0
	for _, st := range m.ifaces {
		if !st.attached {
			degraded = 1
			break
		}
	}
	metrics.DataplaneDegraded.Set(degraded)
}

// Stats reads the whole data plane: counters, the live generation, and what the
// maps cost.
func (m *Manager) Stats() (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Snapshot{}, ErrClosed
	}
	maps := m.objs.MapSet()

	snap := Snapshot{Health: m.healthLocked(), Sizing: m.sizing}
	counters, err := ReadStats(maps)
	if err != nil {
		return Snapshot{}, err
	}
	snap.Counters = counters
	snap.Verdicts = make(map[string]Counter, StatMax)
	for s := Stat(0); s < StatMax; s++ {
		snap.Verdicts[s.String()] = counters[s]
	}

	cfg, err := ReadConfig(maps)
	if err != nil {
		return Snapshot{}, err
	}
	snap.Generation, snap.StaticCount, snap.SchemaVersion = cfg.Generation, cfg.StaticCount, cfg.MapSchemaVersion

	fields := mapFields(maps)
	for _, name := range AllMaps {
		info, err := (*fields[name]).Info()
		if err != nil {
			return Snapshot{}, fmt.Errorf("dataplane: info for map %s: %w", name, err)
		}
		bytes, _ := info.Memlock()
		snap.Maps = append(snap.Maps, MapStatus{
			Name: name, Type: info.Type.String(), MaxEntries: info.MaxEntries, Bytes: bytes,
		})
		snap.MapBytes += bytes
		metrics.DataplaneMapEntries.WithLabelValues(name).Set(float64(info.MaxEntries))
		metrics.DataplaneMapBytes.WithLabelValues(name).Set(float64(bytes))
	}
	sort.Slice(snap.Maps, func(i, j int) bool { return snap.Maps[i].Bytes > snap.Maps[j].Bytes })
	return snap, nil
}

// Maps returns the loaded map set for READING — counters, a bucket, a rule's
// per-rule statistics.
//
// Use WithMaps to WRITE. An install done through this accessor holds no lock and
// can therefore be published into the wrong half of the double buffer if a
// config reload flips the generation at the same moment.
//
// It returns nil after Close. A caller that holds the result across a Close is
// holding closed file descriptors, so ask each time rather than cache.
func (m *Manager) Maps() *Maps {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.objs == nil {
		return nil
	}
	return m.objs.MapSet()
}

// WithMaps runs fn with the map set and the LIVE generation, holding the
// manager's lock.
//
// This is the seam a rule installer must use, and the lock is the whole point.
// kapkan_policies is double-buffered on the same generation counter as
// kapkan_statics, so a static-policy reload flips the generation and mirrors the
// policy blocks across (see mirrorPolicyBlocks). A rule written to the active
// half in the window between that mirror and the flip would be published into
// the half nobody copied it to, and would simply not exist. Installing inside
// WithMaps makes that window unreachable: the reload cannot start until fn
// returns, and fn is given the generation that is actually live.
//
// Keep fn short. It holds a mutex that also serialises Reload, Stats and the
// watcher's re-attach pass.
func (m *Manager) WithMaps(fn func(maps *Maps, activeGeneration uint32) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.objs == nil {
		return ErrClosed
	}
	maps := m.objs.MapSet()
	cfg, err := ReadConfig(maps)
	if err != nil {
		return err
	}
	return fn(maps, cfg.Generation)
}

// Sizing reports the resolved map sizing, so a caller allocating rule or policy
// ids knows the bounds it must respect.
func (m *Manager) Sizing() MapSizing { return m.sizing }

// EffectiveDryRun reports whether the DATAPATH is currently rewriting drops into
// passes, read from kapkan_cfg rather than from the Options this process was
// given.
//
// The distinction is the point. Global dry_run is what the config file asked
// for; this is what the kernel is doing. They can disagree — an adopted pin set
// carries the previous process's flag (fixed in installInitialPolicy, and this
// is how the fix stays honest), and a reload writes the flag as a separate step
// from the config swap. The API exposes this as dataplane_dry_run next to the
// global dry_run precisely so a divergence is visible instead of assumed away.
//
// Falls back to the configured value only when the map cannot be read, which is
// a closed manager; a caller that cares about that distinction should use Stats.
func (m *Manager) EffectiveDryRun() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return m.opts.DryRun
	}
	cfg, err := ReadConfig(m.objs.MapSet())
	if err != nil {
		return m.opts.DryRun
	}
	return cfg.DryRun != 0
}

// ProfileID resolves a config profile name to the id the kernel knows it by.
//
// Ids are stable for the life of the process and NOT across a restart. Anything
// that re-installs a rate-limit rule after a restart must re-resolve the name
// rather than trust a profile id it remembered.
func (m *Manager) ProfileID(name string) (uint32, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.profileIDs[name]
	return id, ok
}

/* ========================================================================= */
/* Conditions                                                                 */
/* ========================================================================= */

func (m *Manager) setCondition(c Condition) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setConditionLocked(c)
}

// setConditionLocked adds or refreshes a condition, PRESERVING the original
// Since. A condition that resets its own timestamp every tick would make
// "unattached for 40 minutes" read as "unattached for 2 seconds", which is the
// one thing the field is for.
func (m *Manager) setConditionLocked(c Condition) {
	for i := range m.conds {
		if m.conds[i].Kind == c.Kind && m.conds[i].Interface == c.Interface {
			since := m.conds[i].Since
			m.conds[i] = c
			m.conds[i].Since = since
			return
		}
	}
	m.conds = append(m.conds, c)
}

func (m *Manager) clearConditionLocked(kind ConditionKind, iface string) {
	out := m.conds[:0]
	for _, c := range m.conds {
		if c.Kind == kind && c.Interface == iface {
			continue
		}
		out = append(out, c)
	}
	m.conds = out
}

/* ========================================================================= */
/* Shutdown                                                                   */
/* ========================================================================= */

// Close shuts the manager down, honouring onExit.
//
//   - config.OnExitKeep leaves the pinned program attached and enforcing. Static
//     policy keeps working with no userspace at all, and the mitigator's dynamic
//     rules age out on their own in-kernel expiry — which is the fail-safe that
//     makes a dead or restarting userspace harmless instead of leaving a
//     customer blackholed.
//   - config.OnExitDetach removes the attachment, the pins and the maps.
//
// onExit is a parameter rather than a read of the configured value so that a
// restart-for-upgrade can keep the program attached even when the operator's
// on_exit is detach — the same reason App.StopForRestart differs from App.Stop.
// Pass "" for the configured behaviour.
func (m *Manager) Close(onExit string) error {
	if onExit == "" {
		onExit = m.opts.OnExit
	}
	switch onExit {
	case config.OnExitKeep, config.OnExitDetach:
	default:
		return fmt.Errorf("dataplane: Close: on_exit must be %q or %q, got %q",
			config.OnExitKeep, config.OnExitDetach, onExit)
	}

	// Stop the watcher before taking the lock: it takes the same lock on every
	// tick, so stopping it first is what keeps Close from waiting a full
	// interval.
	m.stopWatcher.Do(func() {
		if m.watchStop == nil {
			return
		}
		close(m.watchStop)
		<-m.watchDone
	})

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true

	var errs []error
	if onExit == config.OnExitDetach {
		// Unpin each link, then close it. Closing an UNPINNED link breaks it,
		// which is exactly what detaching means; closing a pinned one would
		// leave the program attached with nobody holding it.
		for _, st := range m.ifaces {
			if st.link != nil {
				if err := st.link.Unpin(); err != nil {
					errs = append(errs, fmt.Errorf("unpin %s: %w", st.name, err))
				}
				if err := st.link.Close(); err != nil {
					errs = append(errs, fmt.Errorf("detach %s: %w", st.name, err))
				}
				st.link = nil
			}
			st.attached = false
			metrics.SetDataplaneAttached(st.name, st.mode, false)
		}
		removed, unknown, err := removeOurPins(m.opts.PinPath)
		if err != nil {
			errs = append(errs, err)
		}
		m.log.Info("data plane detached and unpinned", "pins_removed", len(removed), "left_alone", unknown)
	} else {
		// Keep: the pins hold the program, the maps and every link, so closing
		// our file descriptors changes nothing in the kernel.
		for _, st := range m.ifaces {
			if st.link != nil {
				if err := st.link.Close(); err != nil {
					errs = append(errs, fmt.Errorf("close link %s: %w", st.name, err))
				}
				st.link = nil
			}
		}
		m.log.Info("data plane left attached and pinned; static policy keeps enforcing and "+
			"dynamic rules will age out on their in-kernel expiry",
			"pin_path", m.opts.PinPath, "interfaces", m.opts.Interfaces)
	}

	m.closeObjectsLocked()
	metrics.DataplaneDegraded.Set(0)
	return errors.Join(errs...)
}

func (m *Manager) closeObjects() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeObjectsLocked()
}

func (m *Manager) closeObjectsLocked() {
	if m.objs == nil {
		return
	}
	if err := m.objs.Close(); err != nil {
		m.log.Warn("closing the data plane's file descriptors", "err", err)
	}
	m.objs = nil
}

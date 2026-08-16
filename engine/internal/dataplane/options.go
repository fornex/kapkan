package dataplane

// The Manager's inputs, in a form every host can build.
//
// This file is untagged on purpose. internal/app, the API and the tests all
// need to name Options and StaticPolicy, and half of them are compiled on the
// macOS development host where nothing here can actually be loaded. The rule
// that makes that work is one-directional: THIS package may import
// internal/config, and internal/config may never import this one — it compiles
// to wasm for the kapkan.io config builder, where there is no bpf(2) at all.
//
// The conversions below are the only place config's string-typed YAML becomes
// typed policy. They parse rather than re-validate: config.validate() has
// already rejected a malformed prefix or an unknown action, so a failure here
// is a bug in one of the two files and says so.

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// Options is everything the Manager needs to attach and enforce.
//
// The restart-required subset (Interfaces, XDPMode, PinPath, Limits) is exactly
// config.DataplaneSettings' comparable fields, because those are the ones that
// cannot change under a running, attached program. Reload compares them and
// refuses rather than pretending.
type Options struct {
	// Interfaces are the NICs to attach to. At least one.
	Interfaces []string
	// XDPMode is config.XDPModeAuto, XDPModeNative or XDPModeGeneric.
	XDPMode string
	// PinPath is the bpffs directory holding the pinned program, maps and
	// links, so an in-place restart re-adopts instead of rebuilding.
	PinPath string
	// OnExit is config.OnExitKeep or OnExitDetach. It is the DEFAULT for
	// Close; Close takes the mode explicitly so a restart-for-upgrade can keep
	// the program attached even when the configured behaviour is detach.
	OnExit string
	// DropMalformed and DryRun go straight into kapkan_cfg[0].
	DropMalformed bool
	DryRun        bool
	// Limits size the maps. See Limits.MapSizing.
	Limits Limits
	// Policy is the static (operator) half: allowlist, protected list,
	// profiles and static rules. It hot-reloads.
	Policy StaticPolicy

	// Log receives the lifecycle narration. Required in practice — a data
	// plane that attaches or degrades silently is the thing this package
	// exists to prevent — but a nil Log is tolerated and discards.
	Log *slog.Logger

	// WatchInterval is how often the interface watcher checks that every
	// attachment is still live. 0 selects defaultWatchInterval; a negative
	// value disables the watcher (tests that drive re-attachment by hand).
	WatchInterval time.Duration
	// BackoffMin and BackoffMax bound the re-attach backoff. 0 selects the
	// defaults.
	BackoffMin, BackoffMax time.Duration
}

// Watcher and backoff defaults. The watch interval is deliberately slower than
// the 1 Hz sweep elsewhere in kapkan: re-attaching is the remedy for an event
// (a NIC coming back) that no operator experiences as instantaneous, and each
// tick costs one link Info() syscall per interface.
const (
	defaultWatchInterval = 2 * time.Second
	defaultBackoffMin    = 1 * time.Second
	defaultBackoffMax    = 60 * time.Second
)

// StaticPolicy is the operator-authored half of the data plane — everything
// that can be replaced on a running program by building the inactive generation
// and flipping. Dynamic (mitigator-installed) rules are deliberately absent:
// they live in kapkan_policies and a reload must never touch them.
type StaticPolicy struct {
	// Allow holds SOURCE prefixes that always pass (precedence 1).
	Allow []netip.Prefix
	// Protected holds DESTINATION prefixes that are never banned
	// (precedence 2) — the protected_whitelist mirror. A different axis from
	// Allow, and both are enforced in the kernel so that a rule rehydrated
	// from a previous process cannot blackhole a protected customer for the
	// second it takes a userspace sweep to notice.
	Protected []netip.Prefix
	// Profiles are the named rate ceilings, in the order the config declares
	// them. Order is load-bearing only in that it fixes the profile ids.
	Profiles []NamedRate
	// Statics are the always-on operator rules, first match wins
	// (precedence 3).
	Statics []StaticRule
}

// NamedRate is one config ratelimit_profiles entry.
type NamedRate struct {
	Name string
	PPS  uint64
	Mbps uint64
}

// StaticRule is one config static_rules entry with its match parsed. An unset
// field matches anything; Src invalid means "any source", and because the
// datapath is family-strict a rule with no Src compiles to StaticExpansion
// kernel rules rather than one.
type StaticRule struct {
	// Name identifies the rule in logs, counters and the console.
	Name string
	// Src is the source prefix, or the zero Prefix for any.
	Src netip.Prefix
	// Proto is nil for any.
	Proto *uint8
	// SrcPort and DstPort are nil for any.
	SrcPort *uint16
	DstPort *uint16
	// Action is pass, drop or ratelimit.
	Action Action
	// Profile names a Profiles entry; set only for ActionRateLimit.
	Profile string
	// MatchExt is the extended-predicate bitset from match.payload. Zero for
	// every rule that does not name one, which is every rule written before
	// the field existed.
	MatchExt uint8
}

// IP protocol numbers for config's proto names. icmp is v4-only and icmp6 is
// v6-only, which is what lets the compiler pick one family for those two
// instead of emitting a rule per family.
const (
	protoICMP   uint8 = 1
	protoTCP    uint8 = 6
	protoUDP    uint8 = 17
	protoICMPv6 uint8 = 58
)

// OptionsFromConfig builds Options from a validated Config. It returns an error
// only on a disagreement between this package and config's validate() — a
// prefix that parsed there and not here, or an action neither file knows —
// because every such case is a bug rather than an operator mistake.
//
// The caller is expected to have checked Config.DataplaneEnabled first; a
// disabled or absent block yields an error rather than a zero Options, so a
// caller cannot accidentally attach to nothing.
func OptionsFromConfig(cfg *config.Config) (Options, error) {
	if cfg == nil || cfg.Dataplane == nil || !cfg.DataplaneCfg.Enabled {
		return Options{}, fmt.Errorf("dataplane: not enabled in the configuration")
	}
	return optionsFromBlock(cfg.Dataplane, cfg.DataplaneCfg, cfg.DryRun, cfg.WhitelistAddrs)
}

// OptionsFromScrub is OptionsFromConfig's twin for the scrub-node role, whose
// scrub.yaml carries the same dataplane block validated by the same code. The
// differences are exactly the role's: dry-run resolves from the role default
// (TRUE when absent), and there is no protected_whitelist — the brain's
// whitelist safety runs where bans are DECIDED, and a node is never handed a
// rule for a whitelisted victim in the first place.
func OptionsFromScrub(sc *config.ScrubConfig) (Options, error) {
	if sc == nil || sc.Dataplane == nil || !sc.DataplaneCfg.Enabled {
		return Options{}, fmt.Errorf("dataplane: not enabled in the scrub configuration")
	}
	return optionsFromBlock(sc.Dataplane, sc.DataplaneCfg, sc.DryRunResolved(), nil)
}

// optionsFromBlock converts one validated dataplane block + its resolved
// settings, shared by both roles.
func optionsFromBlock(d *config.Dataplane, set config.DataplaneSettings, dryRun bool, protected []netip.Addr) (Options, error) {
	pol, err := policyFromBlock(d, protected)
	if err != nil {
		return Options{}, err
	}
	return Options{
		Interfaces: strings.Split(set.Interfaces, ","),
		XDPMode:    set.XDPMode,
		PinPath:    set.PinPath,
		OnExit:     set.OnExit,
		// DropMalformed is static policy that lives in kapkan_cfg rather than
		// in a map, so it rides on Options and is re-stamped on reload.
		DropMalformed: d.DropMalformed,
		DryRun:        dryRun,
		Limits: Limits{
			MaxDynamicRules:     set.MaxDynamicRules,
			MaxStaticRules:      set.MaxStaticRules,
			MaxRatelimitSources: set.MaxRatelimitSources,
		},
		Policy: pol,
	}, nil
}

// PolicyFromConfig extracts just the hot-reloadable half, which is what
// Manager.Reload needs and what a config reload changes.
func PolicyFromConfig(cfg *config.Config) (StaticPolicy, error) {
	return policyFromBlock(cfg.Dataplane, cfg.WhitelistAddrs)
}

func policyFromBlock(d *config.Dataplane, protected []netip.Addr) (StaticPolicy, error) {
	if d == nil {
		return StaticPolicy{}, fmt.Errorf("dataplane: no dataplane block")
	}
	var pol StaticPolicy

	for i, s := range d.Allowlist {
		p, err := parsePrefixOrAddr(s)
		if err != nil {
			return StaticPolicy{}, fmt.Errorf("dataplane.allowlist[%d]: %w", i, err)
		}
		pol.Allow = append(pol.Allow, p)
	}

	// protected_whitelist is a list of bare addresses in config (it predates
	// the data plane and is used for "never ban this host"), so each becomes a
	// host route here.
	for _, a := range protected {
		pol.Protected = append(pol.Protected, netip.PrefixFrom(a, a.BitLen()))
	}

	for _, p := range d.RateLimitProfiles {
		pol.Profiles = append(pol.Profiles, NamedRate{Name: p.Name, PPS: p.PPS, Mbps: p.Mbps})
	}

	for _, r := range d.StaticRules {
		sr := StaticRule{Name: r.Name, Profile: r.Profile}
		if r.Match.Src != "" {
			p, err := parsePrefixOrAddr(r.Match.Src)
			if err != nil {
				return StaticPolicy{}, fmt.Errorf("dataplane.static_rules[%q].match.src: %w", r.Name, err)
			}
			sr.Src = p
		}
		switch r.Match.Proto {
		case "":
		case "tcp":
			sr.Proto = ptr(protoTCP)
		case "udp":
			sr.Proto = ptr(protoUDP)
		case "icmp":
			sr.Proto = ptr(protoICMP)
		case "icmp6":
			sr.Proto = ptr(protoICMPv6)
		default:
			return StaticPolicy{}, fmt.Errorf("dataplane.static_rules[%q]: unknown proto %q "+
				"(config.validate accepted it, so this package is out of step)", r.Name, r.Match.Proto)
		}
		// Config spells "any port" as 0 for these two, which is correct for a
		// port (port 0 is not usable) and is why they are plain uint16 there
		// and pointers here.
		if r.Match.SrcPort != 0 {
			sr.SrcPort = ptr(r.Match.SrcPort)
		}
		if r.Match.DstPort != 0 {
			sr.DstPort = ptr(r.Match.DstPort)
		}
		switch r.Match.Payload {
		case "":
		case config.StaticPayloadTLSClientHello:
			sr.MatchExt |= MatchTLSClientHello
		default:
			return StaticPolicy{}, fmt.Errorf("dataplane.static_rules[%q]: unknown payload %q "+
				"(config.validate accepted it, so this package is out of step)", r.Name, r.Match.Payload)
		}
		switch r.Action {
		case config.StaticActionPass:
			sr.Action = ActionPass
		case config.StaticActionDrop:
			sr.Action = ActionDrop
		case config.StaticActionRateLimit:
			sr.Action = ActionRateLimit
		default:
			return StaticPolicy{}, fmt.Errorf("dataplane.static_rules[%q]: unknown action %q "+
				"(config.validate accepted it, so this package is out of step)", r.Name, r.Action)
		}
		pol.Statics = append(pol.Statics, sr)
	}
	return pol, nil
}

// parsePrefixOrAddr accepts a CIDR or a bare address, mirroring config's own
// helper of the same name (which is unexported). Duplicated deliberately:
// exporting config's would widen a frozen surface, and a data-plane prefix that
// parses differently from a config prefix is caught by
// TestPolicyFromConfigMatchesValidate rather than by a rule that never fires.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func ptr[T any](v T) *T { return &v }

// restartRequired reports which of the two Options' fields cannot be changed
// under a running program, or "" when a reload is safe.
//
// This is the manager's own copy of the check config.Store.Reload already
// performs on DataplaneSettings. Both exist because they answer for different
// things: config refuses the whole reload for the whole daemon, while this
// refuses to pretend that a Manager holding 234 MiB of already-created maps can
// honour a new max_ratelimit_sources. A caller that bypassed config's check —
// a test, or a future API that reloads only the data plane — must still be
// refused, and shrinking a live LRU is not a thing the kernel offers at all.
func (o Options) restartRequired(next Options) string {
	var diffs []string
	if a, b := strings.Join(o.Interfaces, ","), strings.Join(next.Interfaces, ","); a != b {
		diffs = append(diffs, fmt.Sprintf("interfaces %q -> %q", a, b))
	}
	if o.XDPMode != next.XDPMode {
		diffs = append(diffs, fmt.Sprintf("xdp_mode %q -> %q", o.XDPMode, next.XDPMode))
	}
	if o.PinPath != next.PinPath {
		diffs = append(diffs, fmt.Sprintf("pin_path %q -> %q", o.PinPath, next.PinPath))
	}
	if o.Limits != next.Limits {
		diffs = append(diffs, fmt.Sprintf("limits %+v -> %+v", o.Limits, next.Limits))
	}
	return strings.Join(diffs, "; ")
}

// normalize fills the defaults and rejects what cannot be defaulted. Called by
// Open before anything touches the kernel, so a typo in a hand-built Options
// (in a test, or in a future API surface) fails the same way an operator's
// would.
func (o *Options) normalize() error {
	if len(o.Interfaces) == 0 || (len(o.Interfaces) == 1 && o.Interfaces[0] == "") {
		return fmt.Errorf("dataplane: no interfaces to attach to")
	}
	seen := make(map[string]struct{}, len(o.Interfaces))
	for _, n := range o.Interfaces {
		if n == "" {
			return fmt.Errorf("dataplane: empty interface name in %q", strings.Join(o.Interfaces, ","))
		}
		if _, dup := seen[n]; dup {
			return fmt.Errorf("dataplane: interface %q listed twice", n)
		}
		seen[n] = struct{}{}
	}
	switch o.XDPMode {
	case "":
		o.XDPMode = config.XDPModeAuto
	case config.XDPModeAuto, config.XDPModeNative, config.XDPModeGeneric:
	default:
		return fmt.Errorf("dataplane: xdp_mode must be %q, %q or %q, got %q",
			config.XDPModeAuto, config.XDPModeNative, config.XDPModeGeneric, o.XDPMode)
	}
	switch o.OnExit {
	case "":
		o.OnExit = config.OnExitKeep
	case config.OnExitKeep, config.OnExitDetach:
	default:
		return fmt.Errorf("dataplane: on_exit must be %q or %q, got %q",
			config.OnExitKeep, config.OnExitDetach, o.OnExit)
	}
	if !strings.HasPrefix(o.PinPath, "/") {
		return fmt.Errorf("dataplane: pin_path must be absolute, got %q", o.PinPath)
	}
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits()
	}
	if o.WatchInterval == 0 {
		o.WatchInterval = defaultWatchInterval
	}
	if o.BackoffMin <= 0 {
		o.BackoffMin = defaultBackoffMin
	}
	if o.BackoffMax <= 0 {
		o.BackoffMax = defaultBackoffMax
	}
	if o.BackoffMax < o.BackoffMin {
		o.BackoffMax = o.BackoffMin
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return nil
}

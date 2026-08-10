//go:build linux

package dataplane

// Independent end-to-end tests, kept from the S3 review.
//
// These deliberately share NO helper with the rest of the suite: their own
// bpffs mount, their own pin directories, their own packet builder, their own
// assertions. That is the whole value — a bug in a shared fixture cannot hide
// here, and every claim these make about the kernel was reproduced from
// scratch rather than inherited.
//
// TestIVFalsePinsRebuiltAlarm is a regression test for a real bug found this
// way: a cold start on a pre-created (or detach-emptied) pin directory used to
// fire the "your dynamic rules were lost" alarm, on the one signal that has to
// stay trustworthy.

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

/* -------------------------------------------------------------------------- */
/* my own environment                                                          */
/* -------------------------------------------------------------------------- */

// ivBpffs mounts a bpffs of my own at /run/ivbpf and returns it.
//
// Mounting one of my own is the point — these tests share no fixture with the
// rest of the suite — so that is still what is tried first. What I cannot do is
// insist on it: mount(2) needs CAP_SYS_ADMIN, and the CI job that runs this
// binary deliberately holds CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON and nothing
// else, where even the mkdir under /run fails. So KAPKAN_BPFFS, if the
// environment offers one, gets me a subdirectory of somebody else's mount —
// still my own pin directories, still my own assertions — and if there is
// neither, this is an environment that cannot run these tests and it says so
// through the shared gate rather than by failing.
func ivBpffs(t *testing.T) string {
	t.Helper()
	requireBPF(t)

	const root = "/run/ivbpf"
	if err := os.MkdirAll(root, 0o755); err == nil {
		var st syscall.Statfs_t
		if err := syscall.Statfs(root, &st); err == nil && uint32(st.Type) == 0xcafe4a11 {
			return root
		}
		if err := syscall.Mount("bpffs", root, "bpf", 0, ""); err == nil {
			return root
		}
	}

	if shared := os.Getenv("KAPKAN_BPFFS"); shared != "" {
		mine := filepath.Join(shared, "iv")
		if err := os.MkdirAll(mine, 0o700); err != nil {
			skipOrFail(t, "cannot mount a bpffs at %s and cannot make one under KAPKAN_BPFFS=%s: %v",
				root, shared, err)
		}
		if err := usableBpffs(mine); err != nil {
			skipOrFail(t, "cannot mount a bpffs at %s and KAPKAN_BPFFS=%s is unusable: %v",
				root, shared, err)
		}
		return mine
	}

	skipOrFail(t, "cannot mount a bpffs at %s and KAPKAN_BPFFS is unset; run `make dataplane-test`", root)
	return ""
}

// ivPinDir makes a fresh, correctly-owned pin dir under a bpffs.
func ivPinDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(ivBpffs(t), name)
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir pin dir: %v", err)
	}
	return dir
}

func ivQuietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ivOptions is my own Options builder. WatchInterval is negative so no watcher
// goroutine runs behind my assertions.
func ivOptions(pinDir string, lim Limits) Options {
	return Options{
		Interfaces:    []string{"lo"},
		XDPMode:       "generic",
		PinPath:       pinDir,
		OnExit:        "detach",
		Limits:        lim,
		Log:           ivQuietLog(),
		WatchInterval: -1,
	}
}

/* -------------------------------------------------------------------------- */
/* my own packet builder                                                       */
/* -------------------------------------------------------------------------- */

// ivUDPv4 builds Ethernet/IPv4/UDP by hand, so no framing helper is shared with
// the code under review.
func ivUDPv4(src, dst netip.Addr, sport, dport uint16) []byte {
	p := make([]byte, 0, 64)
	// Ethernet: dst, src, ethertype IPv4.
	p = append(p, 0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00)
	ip := make([]byte, 20)
	ip[0] = 0x45                             // v4, ihl 5
	binary.BigEndian.PutUint16(ip[2:], 20+8) // total length
	ip[8] = 64                               // ttl
	ip[9] = 17                               // UDP
	s4, d4 := src.As4(), dst.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:], ivCsum(ip)) // header checksum
	p = append(p, ip...)
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], 8)
	p = append(p, u...)
	// XDP test-run wants a frame the kernel will accept; pad to 60.
	for len(p) < 60 {
		p = append(p, 0)
	}
	return p
}

func ivCsum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

const (
	ivXDPDrop = 1
	ivXDPPass = 2
)

func ivVerdict(t *testing.T, m *Manager, pkt []byte) uint32 {
	t.Helper()
	ret, err := m.objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	return ret
}

/* -------------------------------------------------------------------------- */
/* ITEM 5 — the headline: does dataplane.limits actually size the maps?        */
/* -------------------------------------------------------------------------- */

// ivKernelMapSizes asks the KERNEL (BPF_OBJ_GET_INFO_BY_FD via Map.Info) what
// each map was created with. Not the spec, not the Manager's own bookkeeping.
func ivKernelMapSizes(t *testing.T, m *Manager) (map[string]uint32, map[string]uint64, uint64) {
	t.Helper()
	entries := map[string]uint32{}
	bytes := map[string]uint64{}
	var total uint64
	set := m.objs.MapSet()
	fields := mapFields(set)
	for _, name := range AllMaps {
		info, err := (*fields[name]).Info()
		if err != nil {
			t.Fatalf("Info(%s): %v", name, err)
		}
		entries[name] = info.MaxEntries
		b, _ := info.Memlock()
		bytes[name] = b
		total += b
	}
	return entries, bytes, total
}

func TestIVLimitsActuallySizeTheKernelMaps(t *testing.T) {
	small := Limits{MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 65536}

	// Phase A: the operator's small limits.
	mA, err := Open(ivOptions(ivPinDir(t, "iv-small"), small))
	if err != nil {
		t.Fatalf("Open(small): %v", err)
	}
	entA, bytA, totA := ivKernelMapSizes(t, mA)
	if err := mA.Close("detach"); err != nil {
		t.Fatalf("close A: %v", err)
	}

	// Phase B: the compiled-in defaults, same code path.
	mB, err := Open(ivOptions(ivPinDir(t, "iv-default"), DefaultLimits()))
	if err != nil {
		t.Fatalf("Open(default): %v", err)
	}
	entB, bytB, totB := ivKernelMapSizes(t, mB)
	if err := mB.Close("detach"); err != nil {
		t.Fatalf("close B: %v", err)
	}

	t.Logf("KERNEL-REPORTED max_entries, small limits vs defaults:")
	for _, n := range AllMaps {
		t.Logf("  %-20s %10d -> %10d entries   %12d -> %12d bytes",
			n, entB[n], entA[n], bytB[n], bytA[n])
	}
	t.Logf("TOTAL kernel memlock: defaults %d B (%.1f MiB)  small %d B (%.1f MiB)",
		totB, float64(totB)/(1<<20), totA, float64(totA)/(1<<20))

	// The claim: max_ratelimit_sources is honoured on the real load path.
	for _, n := range []string{MapRLSrc4, MapRLSrc6} {
		if entA[n] != 65536 {
			t.Errorf("DEBT (a) NOT PAID: %s created with %d entries, wanted 65536", n, entA[n])
		}
		if entB[n] != 1<<20 {
			t.Errorf("%s default is %d, expected 1<<20", n, entB[n])
		}
	}
	// max_dynamic_rules 256 / 8 rules per block = 32 blocks per generation.
	if want := uint32(32 * Generations); entA[MapPolicies] != want {
		t.Errorf("kapkan_policies %d, wanted %d", entA[MapPolicies], want)
	}
	// max_static_rules 32 x StaticExpansion 2 x 2 generations.
	if want := uint32(32 * StaticExpansion * Generations); entA[MapStatics] != want {
		t.Errorf("kapkan_statics %d, wanted %d", entA[MapStatics], want)
	}
	if want := uint32(256 + 32*StaticExpansion); entA[MapRuleStats] != want {
		t.Errorf("kapkan_rule_stats %d, wanted %d", entA[MapRuleStats], want)
	}
	// The maps that are contract, not policy, must NOT have moved.
	for _, n := range []string{MapCfg, MapProfiles, MapAllow4, MapAllow6, MapProtect4, MapProtect6, MapVictims4, MapVictims6, MapStats} {
		if entA[n] != entB[n] {
			t.Errorf("fixed-size map %s changed with limits: %d vs %d", n, entA[n], entB[n])
		}
	}
	if totA >= totB {
		t.Errorf("no memory was saved: small=%d default=%d", totA, totB)
	}
	t.Logf("SAVED %d bytes (%.1f MiB), %.1f%% of the stock footprint",
		totB-totA, float64(totB-totA)/(1<<20), 100*float64(totB-totA)/float64(totB))
}

/* -------------------------------------------------------------------------- */
/* ITEM 8 — adversarial: does a static reload really leave dynamic rules alone? */
/* -------------------------------------------------------------------------- */

// TestIVReloadDoesNotUnmitigate installs a dynamic DROP rule the way S4 is told
// to (through WithMaps, into the live generation), proves the kernel drops the
// packet, then reloads a DIFFERENT static policy and proves the same packet is
// still dropped. If mirrorPolicyBlocks were absent or wrong, the generation flip
// would move the datapath to a policy half nobody wrote and the packet would
// pass — i.e. a config reload would un-mitigate every live attack.
func TestIVReloadDoesNotUnmitigate(t *testing.T) {
	attacker := netip.MustParseAddr("203.0.113.7")
	victimNet := netip.MustParsePrefix("198.51.100.0/24")
	victimHost := netip.MustParseAddr("198.51.100.5")

	opts := ivOptions(ivPinDir(t, "iv-reload"), Limits{
		MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 4096,
	})
	opts.Policy = StaticPolicy{
		Profiles: []NamedRate{{Name: "slow", PPS: 100}},
	}
	m, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = m.Close("detach") }()

	pkt := ivUDPv4(attacker, victimHost, 40000, 53)

	// Baseline: nothing installed, the packet passes.
	if got := ivVerdict(t, m, pkt); got != ivXDPPass {
		t.Fatalf("baseline verdict %d, wanted XDP_PASS(%d)", got, ivXDPPass)
	}

	// Install the dynamic rule the way the hand-off says to.
	const policyID = 1
	if err := m.WithMaps(func(maps *Maps, gen uint32) error {
		rules, err := EncodeRules(RuleSpec{
			ID: 1, Action: ActionDrop, Src: netip.PrefixFrom(attacker, 32),
		})
		if err != nil {
			return err
		}
		if err := PutPolicy(maps, gen, policyID, rules); err != nil {
			return err
		}
		return AddVictim(maps, victimNet, policyID)
	}); err != nil {
		t.Fatalf("install dynamic rule: %v", err)
	}

	snap0, err := m.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if got := ivVerdict(t, m, pkt); got != ivXDPDrop {
		t.Fatalf("after install verdict %d, wanted XDP_DROP(%d) — the rule never took effect, "+
			"so the rest of this test would prove nothing", got, ivXDPDrop)
	}
	t.Logf("dynamic rule live in generation %d: packet is DROPPED", snap0.Generation)

	// Now reload a DIFFERENT static policy. This flips the generation.
	next := opts
	next.Policy = StaticPolicy{
		Profiles: []NamedRate{{Name: "slow", PPS: 100}},
		Statics: []StaticRule{{
			Name:   "drop-chargen",
			Action: ActionDrop,
			Src:    netip.MustParsePrefix("192.0.2.0/24"),
		}},
	}
	rep, err := m.Reload(next)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	snap1, err := m.Stats()
	if err != nil {
		t.Fatalf("stats after reload: %v", err)
	}
	if snap1.Generation == snap0.Generation {
		t.Fatalf("the generation did not flip (%d): this test cannot detect the bug it exists for",
			snap1.Generation)
	}
	t.Logf("reload flipped generation %d -> %d; report: %s", snap0.Generation, snap1.Generation, rep.Summary())

	if got := ivVerdict(t, m, pkt); got != ivXDPDrop {
		t.Fatalf("AFTER RELOAD verdict %d, wanted XDP_DROP(%d): a static-policy reload "+
			"un-mitigated a live attack", got, ivXDPDrop)
	}
	t.Logf("after the flip the same packet is STILL DROPPED")

	// And the new static rule really is live too, so the reload was not a no-op.
	chargen := ivUDPv4(netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("192.0.2.10"), 1, 2)
	if got := ivVerdict(t, m, chargen); got != ivXDPDrop {
		t.Errorf("the reloaded static rule is not enforcing: verdict %d", got)
	}
}

/* -------------------------------------------------------------------------- */
/* ITEM 7 — adoption, schema refusal, pin-directory mode (real chmod)          */
/* -------------------------------------------------------------------------- */

func TestIVAdoptionAndRefusals(t *testing.T) {
	dir := ivPinDir(t, "iv-adopt")
	lim := Limits{MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 4096}

	// --- 1. adopt a matching pinned set -------------------------------------
	o1 := ivOptions(dir, lim)
	o1.OnExit = "keep"
	m1, err := Open(o1)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	// Stamp something only the FIRST process could have written, so "adopted"
	// means "the same kernel objects", not "a fresh set that looks alike".
	const policyID = 3
	marker := netip.MustParsePrefix("198.51.100.0/24")
	if err := m1.WithMaps(func(maps *Maps, gen uint32) error {
		rules, err := EncodeRules(RuleSpec{ID: 77, Action: ActionDrop, Src: netip.MustParsePrefix("203.0.113.7/32")})
		if err != nil {
			return err
		}
		if err := PutPolicy(maps, gen, policyID, rules); err != nil {
			return err
		}
		return AddVictim(maps, marker, policyID)
	}); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	id1, err := m1.objs.KapkanPolicies.Info()
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	mapID1, _ := id1.ID()
	if err := m1.Close("keep"); err != nil {
		t.Fatalf("Close(keep): %v", err)
	}

	m2, err := Open(ivOptions(dir, lim))
	if err != nil {
		t.Fatalf("Open #2 (should adopt): %v", err)
	}
	if !m2.Health().Adopted {
		t.Errorf("second Open did not adopt the pinned set")
	}
	id2, err := m2.objs.KapkanPolicies.Info()
	if err != nil {
		t.Fatalf("info 2: %v", err)
	}
	mapID2, _ := id2.ID()
	if mapID1 != mapID2 {
		t.Errorf("adoption produced a DIFFERENT kernel map: id %d -> %d", mapID1, mapID2)
	} else {
		t.Logf("adopted: kapkan_policies is the same kernel object across the restart (map id %d)", mapID1)
	}
	// The dynamic rule the previous process installed must still be dropping.
	pkt := ivUDPv4(netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("198.51.100.5"), 1, 2)
	if got := ivVerdict(t, m2, pkt); got != ivXDPDrop {
		t.Errorf("adopted process lost the previous process's dynamic rule: verdict %d", got)
	} else {
		t.Logf("the previous process's dynamic rule survived the restart and still drops")
	}

	// --- 2. refuse on a schema-version mismatch ------------------------------
	if err := m2.WithMaps(func(maps *Maps, gen uint32) error {
		cfg, err := ReadConfig(maps)
		if err != nil {
			return err
		}
		cfg.MapSchemaVersion = MapSchemaVersion + 41
		return maps.KapkanCfg.Put(uint32(0), &cfg)
	}); err != nil {
		t.Fatalf("poison schema: %v", err)
	}
	if err := m2.Close("keep"); err != nil {
		t.Fatalf("close m2: %v", err)
	}
	m3, err := Open(ivOptions(dir, lim))
	if err != nil {
		t.Fatalf("Open #3: %v", err)
	}
	if m3.Health().Adopted {
		t.Errorf("adopted a pin set whose map_schema_version was %d, not %d",
			MapSchemaVersion+41, MapSchemaVersion)
	}
	rebuilt := false
	for _, c := range m3.Health().Conditions {
		if c.Kind == CondPinsRebuilt {
			rebuilt = true
			t.Logf("refusal surfaced: %s", c.Message)
		}
	}
	if !rebuilt {
		t.Errorf("no CondPinsRebuilt condition after a schema mismatch")
	}
	id3, _ := m3.objs.KapkanPolicies.Info()
	mapID3, _ := id3.ID()
	if mapID3 == mapID1 {
		t.Errorf("pins were NOT rebuilt: still kernel map id %d", mapID1)
	}
	if err := m3.Close("detach"); err != nil {
		t.Fatalf("close m3: %v", err)
	}

	// --- 3. refuse a world-writable pin directory (REAL chmod) ---------------
	bad := filepath.Join(ivBpffs(t), "iv-badmode")
	_ = os.RemoveAll(bad)
	if err := os.MkdirAll(bad, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(bad, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	st, err := os.Stat(bad)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	t.Logf("pin dir %s is really mode %#o on disk", bad, st.Mode().Perm())
	if _, err := Open(ivOptions(bad, lim)); err == nil {
		t.Errorf("SECURITY: started with a world-writable pin directory")
	} else {
		t.Logf("refused, as it must: %v", err)
	}
	_ = os.RemoveAll(bad)
}

/* -------------------------------------------------------------------------- */
/* ITEM 8b — on_exit semantics, checked from outside the Manager               */
/* -------------------------------------------------------------------------- */

func TestIVOnExitSemantics(t *testing.T) {
	lim := Limits{MaxDynamicRules: 128, MaxStaticRules: 16, MaxRatelimitSources: 4096}

	// keep: the pins survive and the program is still on the hook.
	dir := ivPinDir(t, "iv-onexit-keep")
	o := ivOptions(dir, lim)
	o.OnExit = "keep"
	m, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := m.Close(""); err != nil { // "" = use the configured mode
		t.Fatalf("Close(\"\"): %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if len(ents) == 0 {
		t.Errorf("on_exit=keep left an EMPTY pin dir; nothing to re-adopt")
	}
	t.Logf("on_exit=keep left %d pins: %v", len(ents), names)
	// The link pin must be there, i.e. the hook is still owned.
	linkPins := 0
	for _, n := range names {
		if isLinkPin(n) {
			linkPins++
		}
	}
	if linkPins == 0 {
		t.Errorf("on_exit=keep left no link pin: the XDP hook was released")
	}

	// Now detach, and prove the hook and the directory are actually free.
	o2 := ivOptions(dir, lim)
	m2, err := Open(o2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := m2.Close("detach"); err != nil {
		t.Fatalf("Close(detach): %v", err)
	}
	ents2, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir 2: %v", err)
	}
	if len(ents2) != 0 {
		var left []string
		for _, e := range ents2 {
			left = append(left, e.Name())
		}
		t.Errorf("on_exit=detach left pins behind: %v", left)
	} else {
		t.Logf("on_exit=detach emptied the pin dir")
	}
	// A fresh Open must now succeed without an EEXIST on the hook.
	m3, err := Open(ivOptions(ivPinDir(t, "iv-onexit-fresh"), lim))
	if err != nil {
		t.Fatalf("after detach a fresh attach failed (hook not released?): %v", err)
	}
	if m3.Health().Adopted {
		t.Errorf("a fresh pin dir reported adoption")
	}
	_ = m3.Close("detach")
}

/* -------------------------------------------------------------------------- */
/* ITEM 5b — restart-required, checked against config's own rule               */
/* -------------------------------------------------------------------------- */

func TestIVReloadRefusesLimitChange(t *testing.T) {
	lim := Limits{MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 4096}
	m, err := Open(ivOptions(ivPinDir(t, "iv-restart"), lim))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = m.Close("detach") }()

	next := ivOptions(m.opts.PinPath, Limits{
		MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 8192,
	})
	if _, err := m.Reload(next); err == nil {
		t.Errorf("Reload accepted a max_ratelimit_sources change; the maps cannot be resized in place")
	} else {
		t.Logf("Reload refused, as it must: %v", err)
	}
	// And the running maps are untouched.
	info, _ := m.objs.KapkanRlSrc4.Info()
	if info.MaxEntries != 4096 {
		t.Errorf("kapkan_rl_src4 is now %d entries", info.MaxEntries)
	}
}

/* -------------------------------------------------------------------------- */
/* sanity: the whole thing is not somehow attaching nowhere                    */
/* -------------------------------------------------------------------------- */

func TestIVReallyAttaches(t *testing.T) {
	m, err := Open(ivOptions(ivPinDir(t, "iv-attach"), DefaultLimits()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = m.Close("detach") }()
	h := m.Health()
	if len(h.Interfaces) != 1 || !h.Interfaces[0].Attached {
		t.Fatalf("not attached: %+v", h)
	}
	t.Logf("attached: %s ifindex %d mode %s; health: %s",
		h.Interfaces[0].Name, h.Interfaces[0].Index, h.Interfaces[0].Mode, h.Summary())
	if h.Degraded {
		t.Errorf("degraded with one interface attached")
	}
	_ = fmt.Sprint(time.Now())
}

/* -------------------------------------------------------------------------- */
/* FINDING: a cold start on an EXISTING but EMPTY pin dir cries "rules lost"   */
/* -------------------------------------------------------------------------- */

func TestIVFalsePinsRebuiltAlarm(t *testing.T) {
	lim := Limits{MaxDynamicRules: 128, MaxStaticRules: 16, MaxRatelimitSources: 4096}

	// Case 1: the operator (or systemd ExecStartPre, or a package postinst)
	// pre-created the pin directory. Nothing has ever run here.
	dir := filepath.Join(ivBpffs(t), "iv-virgin")
	_ = os.RemoveAll(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("precondition: dir is not empty")
	}
	var buf ivBuf
	o := ivOptions(dir, lim)
	o.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	h := m.Health()
	_ = m.Close("detach")
	for _, c := range h.Conditions {
		if c.Kind == CondPinsRebuilt {
			t.Errorf("FIRST-EVER START on an empty pre-created pin dir raised %s: %q",
				c.Kind, c.Message)
		}
	}
	if buf.s != "" {
		t.Errorf("FIRST-EVER START logged at WARN:\n%s", buf.s)
	}
	t.Logf("health summary on a virgin start: %s", h.Summary())

	// Case 2: a clean shutdown under on_exit: detach, then a restart. The dir
	// survives, empty, so the next start takes the same path.
	dir2 := ivPinDir(t, "iv-cycle")
	o2 := ivOptions(dir2, lim) // OnExit is already "detach"
	m2, err := Open(o2)
	if err != nil {
		t.Fatalf("Open cycle #1: %v", err)
	}
	if err := m2.Close(""); err != nil {
		t.Fatalf("close: %v", err)
	}
	if e, _ := os.ReadDir(dir2); len(e) != 0 {
		t.Fatalf("precondition: detach did not empty the dir")
	}
	var buf2 ivBuf
	o3 := ivOptions(dir2, lim)
	o3.Log = slog.New(slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m3, err := Open(o3)
	if err != nil {
		t.Fatalf("Open cycle #2: %v", err)
	}
	h3 := m3.Health()
	_ = m3.Close("detach")
	for _, c := range h3.Conditions {
		if c.Kind == CondPinsRebuilt {
			t.Errorf("RESTART AFTER A CLEAN on_exit=detach SHUTDOWN raised %s: %q",
				c.Kind, c.Message)
		}
	}
	if buf2.s != "" {
		t.Errorf("RESTART AFTER on_exit=detach logged at WARN:\n%s", buf2.s)
	}
}

type ivBuf struct{ s string }

func (b *ivBuf) Write(p []byte) (int, error) { b.s += string(p); return len(p), nil }

// TestIVForeignOwnedPinDir is the attack the mode check exists for. /sys/fs/bpf
// is drwxrwxrwt on a real box, so an unprivileged local user can mkdir the pin
// dir before kapkan ever starts, mode 0700 and owned by THEM, and pre-create a
// program for a root process to adopt. Mode alone would pass; ownership is what
// stops it.
func TestIVForeignOwnedPinDir(t *testing.T) {
	dir := filepath.Join(ivBpffs(t), "iv-foreign")
	_ = os.RemoveAll(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// uid 65534 = nobody. Mode stays a blameless 0700.
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skipf("cannot chown on this fs: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	t.Logf("pin dir is uid %d mode %#o; this process is euid %d",
		fi.Sys().(*syscall.Stat_t).Uid, fi.Mode().Perm(), os.Geteuid())
	if _, err := Open(ivOptions(dir, DefaultLimits())); err == nil {
		t.Errorf("SECURITY: adopted from a pin directory owned by another user")
	} else {
		t.Logf("refused: %v", err)
	}
	_ = os.RemoveAll(dir)
}

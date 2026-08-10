//go:build linux

package dataplane

// Manager tests against a real kernel.
//
// Everything here needs a live bpffs, a loadable XDP program and an interface to
// attach to, which is why `make dataplane-test` exists: on the macOS development
// host the test binary is cross-compiled and run in a privileged container. The
// helpers below mount bpffs themselves rather than assuming it, because a bare
// container does not have one.
//
// TWO INTERFACES ARE USED, AND THE CHOICE MATTERS.
//
//	lo   has no ndo_bpf, so a native (driver-mode) attach is REFUSED by the
//	     kernel. That is what makes it the right device for testing xdp_mode:
//	     native must fail loudly and xdp_mode: auto must fall back and say so.
//	veth DOES support native XDP, so it is the right device for proving that auto
//	     picks native when it can — and it can be deleted and recreated, which is
//	     the only honest way to test the interface-flap watcher.

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/kapkan-io/kapkan/internal/config"
)

/* --------------------------------------------------------------- harness */

// testLogger routes the manager's narration into the test log, so a failure
// comes with the lifecycle story that produced it. That narration is a
// deliverable in its own right — an operator reads these exact lines when a data
// plane rebuilds its pins or falls back to generic mode — so seeing it in `-v`
// output is how it stays worth reading.
func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

var bpffsOnce struct {
	sync.Once
	root string
	err  error
}

// bpffsRoot returns a bpffs this process can create pins in, mounting one at
// /sys/fs/bpf if it has to.
//
// Not unmounted afterwards: the mount is process-wide state shared by every test
// in the binary, and in the container it goes away with the container.
//
// KAPKAN_BPFFS names a mount to use instead, and exists for the CI job that runs
// this suite with three capabilities and no more. There, /sys/fs/bpf IS a bpffs
// — systemd mounts it — but it is root-owned mode 0700 and the job holds no
// CAP_DAC_OVERRIDE, so every pin directory failed with EACCES. Mounting a second
// bpffs and handing it to the test user is the same remedy the pcap block-rate
// suite already uses, and it is the same environment variable, deliberately:
// one knob for "where may this binary put its pins".
//
// The usableBpffs check is a real mkdir rather than a statfs magic comparison
// for exactly that reason — "it is a bpffs" and "I may write to it" are
// different questions and only the second one predicts what happens next.
func bpffsRoot(t *testing.T) string {
	t.Helper()
	bpffsOnce.Do(func() {
		if root := os.Getenv("KAPKAN_BPFFS"); root != "" {
			if err := usableBpffs(root); err != nil {
				bpffsOnce.err = fmt.Errorf("KAPKAN_BPFFS=%s: %w", root, err)
				return
			}
			bpffsOnce.root = root
			return
		}
		const root = "/sys/fs/bpf"
		if err := usableBpffs(root); err == nil {
			bpffsOnce.root = root
			return
		}
		if err := os.MkdirAll(root, 0o755); err != nil {
			bpffsOnce.err = fmt.Errorf("mkdir %s: %w", root, err)
			return
		}
		if err := syscall.Mount("bpffs", root, "bpf", 0, ""); err != nil {
			bpffsOnce.err = fmt.Errorf("mount bpffs at %s: %w", root, err)
			return
		}
		if err := usableBpffs(root); err != nil {
			bpffsOnce.err = err
			return
		}
		bpffsOnce.root = root
	})
	if bpffsOnce.err != nil {
		skipOrFail(t, "no writable bpffs available (%v); run `make dataplane-test` for the "+
			"privileged-container loop, or set KAPKAN_BPFFS to a bpffs this user owns",
			bpffsOnce.err)
	}
	return bpffsOnce.root
}

// pinDir returns a fresh, non-existent pin directory path under bpffs, and
// removes whatever is left in it afterwards.
func pinDir(t *testing.T) string {
	t.Helper()
	root := bpffsRoot(t)
	dir := filepath.Join(root, "kapkan-test-"+strings.ReplaceAll(t.Name(), "/", "_"))
	cleanupPinDir(dir)
	t.Cleanup(func() { cleanupPinDir(dir) })
	return dir
}

// cleanupPinDir empties and removes a pin directory. Links go first, through
// discardLinkPin, so the program is really detached before this returns.
//
// discardLinkPin AND NOT os.Remove, for the reason spelled out at that function:
// evicting a bpf_link's bpffs inode drops its last reference ASYNCHRONOUSLY,
// while closing its last fd is synchronous. This helper used to call
// os.Remove(pin), and because testOptions sets OnExit: keep, a test that attached
// to "lo" left a live link behind for the kernel to release whenever it got
// round to it. The NEXT test to attach to "lo" then raced that release and failed
// with:
//
//	attach XDP to lo (ifindex 1): create link: file exists — another XDP
//	program already owns this interface's hook
//
// Measured at 4 failures in 7 full runs of `make dataplane-test`, always on
// whichever test followed one that had used "lo", which is what made it look like
// a bug in the victim rather than in this cleanup. Note the production code got
// this right — see discardLinkPin's comment, written for exactly this race — so
// the defect was that the test helper had its own, older copy of the logic.
func cleanupPinDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if isLinkPin(e.Name()) {
			_ = discardLinkPin(filepath.Join(dir, e.Name()))
		}
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	_ = os.Remove(dir)
}

// testOptions is a Manager configuration with the watcher DISABLED, so every
// test drives reconciliation by hand with Reconcile() instead of sleeping.
//
// The privilege gate lives here as well as in mustOpen because several tests
// call Open directly — they are testing a REFUSAL, so they must not go through
// a helper that turns a failed Open into a skip. Every one of them still builds
// its Options here, and Open's own capability check runs before the refusal
// they are asserting on, so without this they failed with "missing capability:
// CAP_BPF, want ErrPinPathUnsafe". Gating the constructor catches them all
// without weakening a single assertion.
func testOptions(t *testing.T, dir string, ifaces ...string) Options {
	t.Helper()
	requireBPF(t)
	return Options{
		Interfaces:    ifaces,
		XDPMode:       config.XDPModeAuto,
		PinPath:       dir,
		OnExit:        config.OnExitKeep,
		Limits:        Limits{MaxDynamicRules: 64, MaxStaticRules: 8, MaxRatelimitSources: 1024},
		Log:           testLogger(t),
		WatchInterval: -1,
		BackoffMin:    time.Millisecond,
		BackoffMax:    2 * time.Millisecond,
	}
}

// mustOpen opens a Manager, skipping on the one failure that is an environment
// problem rather than a bug: no permission to touch bpf(2) at all.
// It also guarantees the Manager is closed when the test ends, which is a
// correctness requirement and not tidiness.
//
// Every test here shares ONE netdevice, "lo". testOptions sets OnExit: keep, so a
// Manager that is never closed keeps its bpf_link fd open, and an open fd is a
// live reference: the XDP hook on "lo" stays occupied no matter what happens to
// the bpffs pin. The next test to attach to "lo" then fails with
//
//	create link: file exists — another XDP program already owns this
//	interface's hook
//
// which reads as a bug in the victim. TestAdoptionRewritesFlags was the leaker
// (it deliberately closes its FIRST manager to test adoption and then has no
// reason to close the second), and the cost was 4 failures in 7 full runs of
// `make dataplane-test`, landing on whichever test happened to follow it.
//
// Registering the cleanup here rather than in each test is deliberate: the
// hazard belongs to Open, so the remedy should be impossible to forget. Close is
// idempotent (it returns nil once m.closed is set), so a test that closes its own
// manager — including one that closes with keep ON PURPOSE to prove the program
// survives — is unaffected. Cleanups run LIFO and pinDir's is registered first,
// so managers are always closed before their pin directory is removed.
func mustOpen(t *testing.T, opts Options) *Manager {
	t.Helper()
	requireBPF(t)
	m, err := Open(opts)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, ErrMissingCapability) {
			skipOrFail(t, "need CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON (%v); run `make dataplane-test`", err)
		}
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(config.OnExitDetach) })
	return m
}

// testProgram reaches into the manager for the loaded program so a test can drive
// it with BPF_PROG_TEST_RUN. Same package, test file only: the production API has
// no reason to hand out the program, and a caller that wants verdicts should be
// reading counters.
func (m *Manager) testProgram() *ebpf.Program {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objs.KapkanXdpFilter
}

// runMgr drives one packet through the manager's program and returns the
// verdict. (packetpath_linux_test.go already owns `run` for a bare object set.)
func runMgr(t *testing.T, m *Manager, pkt []byte) uint32 {
	t.Helper()
	ret, err := m.testProgram().Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	return ret
}

// hasIP reports whether busybox/iproute2 `ip` is available for veth juggling.
func hasIP(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ip")
	if err != nil {
		skipOrFail(t, "no `ip` command to create a veth (%v)", err)
	}
	return p
}

// makeVeth creates a veth pair and brings the near end up, returning its name.
func makeVeth(t *testing.T, name string) string {
	t.Helper()
	ip := hasIP(t)
	peer := name + "p"
	_ = exec.Command(ip, "link", "del", name).Run()
	if out, err := exec.Command(ip, "link", "add", name, "type", "veth", "peer", "name", peer).CombinedOutput(); err != nil {
		skipOrFail(t, "cannot create veth %s (%v): %s", name, err, out)
	}
	t.Cleanup(func() { _ = exec.Command(ip, "link", "del", name).Run() })
	if out, err := exec.Command(ip, "link", "set", name, "up").CombinedOutput(); err != nil {
		t.Fatalf("ip link set %s up: %v: %s", name, err, out)
	}
	return name
}

func delVeth(t *testing.T, name string) {
	t.Helper()
	if out, err := exec.Command(hasIP(t), "link", "del", name).CombinedOutput(); err != nil {
		t.Fatalf("ip link del %s: %v: %s", name, err, out)
	}
}

// ifIndex resolves an interface, failing the test when it is absent.
func ifIndex(t *testing.T, name string) int {
	t.Helper()
	idx, ok, err := resolveInterface(name)
	if err != nil || !ok {
		t.Fatalf("interface %s not found (%v)", name, err)
	}
	return idx
}

// xdpHookBusy reports whether ANYTHING is attached to an interface's XDP hook,
// by trying to attach a trivial program of our own: the kernel allows exactly one
// XDP program per device, so EBUSY means occupied and success means it was free.
//
// This is the kernel's own answer rather than ours, which is the point — the pin
// existing is this package's bookkeeping, and Close(detach) has to be checked
// against something else. (BPF_PROG_QUERY would be the obvious route and is not
// available: it returns EINVAL for the XDP attach type on this 6.12 kernel.)
//
// The probe program is `return XDP_PASS`, so even the window in which it is
// attached cannot drop a packet.
func xdpHookBusy(t *testing.T, iface string) bool {
	t.Helper()
	probe, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "kapkan_probe",
		Type:         ebpf.XDP,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, xdpPass), asm.Return()},
	})
	if err != nil {
		t.Fatalf("build the XDP probe program: %v", err)
	}
	defer func() { _ = probe.Close() }()

	for _, flags := range []link.XDPAttachFlags{link.XDPGenericMode, link.XDPDriverMode} {
		l, err := link.AttachXDP(link.XDPOptions{
			Program: probe, Interface: ifIndex(t, iface), Flags: flags,
		})
		if err == nil {
			_ = l.Close() // unpinned: closing detaches, leaving the hook free again
			return false
		}
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EEXIST) {
			return true
		}
		// EOPNOTSUPP for driver mode on lo: try the other flag.
		if !errors.Is(err, syscall.EOPNOTSUPP) && !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("probing the XDP hook on %s: %v", iface, err)
		}
	}
	t.Fatalf("neither generic nor native XDP could be probed on %s", iface)
	return false
}

// pinnedLinkIdentity returns the id and bound ifindex of the pinned attachment.
//
// The ID is what proves adoption really adopted: a bpf_link id is stable for the
// life of the object, so the same id before and after a restart means the SAME
// kernel object is still attached — not a fresh attach that happens to look
// identical. ifindex 0 is the kernel's way of saying the netdevice is gone.
func pinnedLinkIdentity(t *testing.T, dir, iface string) (link.ID, int) {
	t.Helper()
	lp, ok := findLinkPin(dir, iface)
	if !ok {
		t.Fatalf("no pinned link for %s in %s", iface, dir)
	}
	l, err := link.LoadPinnedLink(lp.path, nil)
	if err != nil {
		t.Fatalf("open the pinned link %s: %v", lp.path, err)
	}
	defer func() { _ = l.Close() }()
	info, err := l.Info()
	if err != nil {
		t.Fatalf("pinned link info: %v", err)
	}
	x := info.XDP()
	if x == nil {
		t.Fatalf("pinned link for %s is not an XDP link", iface)
	}
	return info.ID, int(x.Ifindex)
}

func condition(h Health, kind ConditionKind, iface string) (Condition, bool) {
	for _, c := range h.Conditions {
		if c.Kind == kind && c.Interface == iface {
			return c, true
		}
	}
	return Condition{}, false
}

func ifaceStatus(t *testing.T, h Health, name string) InterfaceStatus {
	t.Helper()
	for _, i := range h.Interfaces {
		if i.Name == name {
			return i
		}
	}
	t.Fatalf("no status for interface %q in %+v", name, h)
	return InterfaceStatus{}
}

/* ------------------------------------------------- limits, the headline */

// TestLimitsRewriteCreatedMapSizes is the kernel-side half of debt (a).
//
// It asserts the size of the map the KERNEL created, read back with
// BPF_OBJ_GET_INFO_BY_FD, not the size on the spec — the spec is what
// TestApplySizingRewritesTheSpec already covers, and a rewrite that never
// reached map_create would pass that test and still leave the operator paying for
// a million-entry LRU.
func TestLimitsRewriteCreatedMapSizes(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")
	opts.Limits = Limits{MaxDynamicRules: 256, MaxStaticRules: 32, MaxRatelimitSources: 65536}
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	snap, err := m.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	want := map[string]uint32{
		MapPolicies:  64,    // 2 generations x (256/8) blocks
		MapStatics:   128,   // 2 generations x (32 x 2 families)
		MapRLSrc4:    65536, // the number the operator actually wrote
		MapRLSrc6:    65536,
		MapRuleStats: 320, // 256 dynamic + 64 expanded statics
		// Untouched by design.
		MapStats:    uint32(StatMax),
		MapCfg:      1,
		MapProfiles: MaxProfiles,
		MapAllow4:   MaxPrefixes,
	}
	got := map[string]MapStatus{}
	for _, ms := range snap.Maps {
		got[ms.Name] = ms
	}
	for name, w := range want {
		if got[name].MaxEntries != w {
			t.Errorf("kernel created %s with max_entries %d, want %d",
				name, got[name].MaxEntries, w)
		}
	}

	// And the point of the exercise: the footprint. With stock limits the two
	// LRUs alone measured 243 MiB on a 14-CPU host; at 1/16 of the sources this
	// must be a small fraction of that.
	for _, ms := range snap.Maps {
		t.Logf("%-18s %-16s max_entries=%-8d bytes=%d", ms.Name, ms.Type, ms.MaxEntries, ms.Bytes)
	}
	t.Logf("total map footprint: %d bytes (%.1f MiB)", snap.MapBytes, float64(snap.MapBytes)/(1<<20))
	if snap.MapBytes > 64<<20 {
		t.Errorf("map footprint is %.1f MiB with max_ratelimit_sources=65536; "+
			"the limits rewrite is not reaching map_create", float64(snap.MapBytes)/(1<<20))
	}

	// The strides the datapath will use must be the ones the sizing computed, or
	// every generation index addresses the wrong slot.
	if snap.Sizing != m.Sizing() {
		t.Errorf("Stats sizing %+v != Manager sizing %+v", snap.Sizing, m.Sizing())
	}
	cfgGen, err := ReadConfig(m.Maps())
	if err != nil {
		t.Fatal(err)
	}
	if cfgGen.PolicyStride != 32 || cfgGen.StaticStride != 64 {
		t.Errorf("kapkan_cfg strides = policy %d, static %d; want 32 and 64",
			cfgGen.PolicyStride, cfgGen.StaticStride)
	}
	if cfgGen.MapSchemaVersion != MapSchemaVersion {
		t.Errorf("kapkan_cfg.map_schema_version = %d, want %d", cfgGen.MapSchemaVersion, MapSchemaVersion)
	}
}

// TestDefaultLimitsFootprint records the stock footprint, which is the number
// deploy/dataplane-operations.md §2 quotes and the number an operator sizes
// MemoryMax= against. It asserts only the shape (the LRUs dominate), because the
// absolute figure is a function of the host's CPU count.
func TestDefaultLimitsFootprint(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")
	opts.Limits = DefaultLimits()
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	snap, err := m.Stats()
	if err != nil {
		t.Fatal(err)
	}
	var lru uint64
	for _, ms := range snap.Maps {
		t.Logf("%-18s %-16s max_entries=%-8d bytes=%d", ms.Name, ms.Type, ms.MaxEntries, ms.Bytes)
		if ms.Name == MapRLSrc4 || ms.Name == MapRLSrc6 {
			lru += ms.Bytes
		}
	}
	t.Logf("stock footprint: %d bytes (%.1f MiB), of which the two token-bucket LRUs are %.1f%%",
		snap.MapBytes, float64(snap.MapBytes)/(1<<20), 100*float64(lru)/float64(snap.MapBytes))
	if snap.MapBytes == 0 {
		t.Fatal("no map footprint reported; the kernel's memlock estimate is unavailable")
	}
	if share := float64(lru) / float64(snap.MapBytes); share < 0.8 {
		t.Errorf("the token-bucket LRUs are only %.1f%% of the footprint; "+
			"deploy/dataplane-operations.md §2 says 94%% and the sizing advice depends on it",
			100*share)
	}
}

/* ------------------------------------------------------------- adoption */

// TestAdoptMatchingPinnedSet is the upgrade story: a second Open over the same
// pins re-adopts them, keeping the attachment and every dynamic rule.
//
// The proof is not "Adopted is true" — that is the manager's own opinion. It is a
// marker written into a map by the first process and read back by the second,
// plus the kernel still reporting exactly one program on the interface across the
// whole sequence.
func TestAdoptMatchingPinnedSet(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")

	first := mustOpen(t, opts)
	if first.Health().Adopted {
		t.Error("the first Open claims to have adopted pins that did not exist")
	}

	// A dynamic rule, installed the way a mitigator would: through WithMaps, so
	// it cannot race a generation flip.
	victim := mustPrefix(t, "203.0.113.9/32")
	rules, err := EncodeRules(RuleSpec{
		ID:     7,
		Action: ActionDrop,
		Src:    mustPrefix(t, "198.51.100.7/32"),
		Dst:    victim,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.WithMaps(func(maps *Maps, gen uint32) error {
		if err := PutPolicy(maps, gen, 0, rules); err != nil {
			return err
		}
		return AddVictim(maps, victim, 0)
	}); err != nil {
		t.Fatalf("install a dynamic rule: %v", err)
	}

	// It drops, before the restart.
	pkt := cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(1234, 80, 0x02))
	if got := runMgr(t, first, pkt); got != xdpDrop {
		t.Fatalf("before restart: verdict = %s, want XDP_DROP", verdictName(got))
	}
	if !xdpHookBusy(t, "lo") {
		t.Fatal("nothing is attached to lo's XDP hook while the manager is running")
	}
	idBefore, idxBefore := pinnedLinkIdentity(t, dir, "lo")

	// The process goes away with on_exit: keep — the pins hold everything.
	if err := first.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close(keep): %v", err)
	}
	if !xdpHookBusy(t, "lo") {
		t.Fatal("lo's XDP hook is free after Close(keep) — keep must leave the program attached")
	}

	second := mustOpen(t, opts)
	defer func() { _ = second.Close(config.OnExitDetach) }()
	h := second.Health()
	if !h.Adopted {
		t.Errorf("the second Open did not adopt the pinned data plane: %s", h.Summary())
	}
	if _, found := condition(h, CondPinsRebuilt, ""); found {
		t.Errorf("pins were rebuilt when they should have been adopted: %s", h.Summary())
	}
	if h.Degraded {
		t.Errorf("adopted but degraded: %s", h.Summary())
	}
	// The dynamic rule survived — including across the generation flip that
	// re-installing static policy over an adopted set performs.
	if got := runMgr(t, second, pkt); got != xdpDrop {
		t.Errorf("after adoption: verdict = %s, want XDP_DROP; the dynamic rule was lost "+
			"(check mirrorPolicyBlocks)", verdictName(got))
	}
	// The SAME bpf_link object, not a fresh attach that looks the same: a link id
	// is stable for the life of the object, so an equal id across the restart is
	// proof the attachment was never broken.
	idAfter, idxAfter := pinnedLinkIdentity(t, dir, "lo")
	if idAfter != idBefore {
		t.Errorf("bpf_link id changed from %d to %d across the restart: the pinned attachment "+
			"was re-created rather than adopted, which means lo was briefly unfiltered",
			idBefore, idAfter)
	}
	if idxAfter != idxBefore || idxAfter == 0 {
		t.Errorf("pinned link ifindex went from %d to %d", idxBefore, idxAfter)
	}
	t.Logf("adopted the same bpf_link (id %d, ifindex %d): %s", idAfter, idxAfter, h.Summary())
}

// TestRefuseAdoptOnSchemaMismatch is the whole reason map_schema_version exists.
//
// A new binary whose object changed a struct must not attach to the old maps: the
// names and sizes would still match and every field past the change would be read
// at the wrong offset. Bumping the stamped version is the cheapest faithful
// simulation of that, and it exercises exactly the branch a real bump would.
func TestRefuseAdoptOnSchemaMismatch(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")

	first := mustOpen(t, opts)
	if err := first.WithMaps(func(maps *Maps, gen uint32) error {
		// A dynamic rule, so the test can also show it was LOST — which is the
		// cost of a rebuild and the reason the refusal is logged at WARN.
		rules, err := EncodeRules(RuleSpec{ID: 7, Action: ActionDrop,
			Src: mustPrefix(t, "198.51.100.7/32"), Dst: mustPrefix(t, "203.0.113.9/32")})
		if err != nil {
			return err
		}
		if err := PutPolicy(maps, gen, 0, rules); err != nil {
			return err
		}
		return AddVictim(maps, mustPrefix(t, "203.0.113.9/32"), 0)
	}); err != nil {
		t.Fatal(err)
	}
	pkt := cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(1234, 80, 0x02))
	if got := runMgr(t, first, pkt); got != xdpDrop {
		t.Fatalf("verdict = %s, want XDP_DROP", verdictName(got))
	}
	if err := first.Close(config.OnExitKeep); err != nil {
		t.Fatal(err)
	}

	// Rewrite the stamped schema version through the pin, as a differently-built
	// binary's pins would look.
	cfgMap, err := ebpf.LoadPinnedMap(mapPin(dir, MapCfg), nil)
	if err != nil {
		t.Fatalf("open pinned kapkan_cfg: %v", err)
	}
	var cfg Config
	if err := cfgMap.Lookup(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.MapSchemaVersion = MapSchemaVersion + 1
	if err := cfgMap.Put(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	_ = cfgMap.Close()

	second := mustOpen(t, opts)
	defer func() { _ = second.Close(config.OnExitDetach) }()
	h := second.Health()
	if h.Adopted {
		t.Fatal("adopted a pinned set stamped with a schema version this binary does not speak")
	}
	c, found := condition(h, CondPinsRebuilt, "")
	if !found {
		t.Fatalf("no pins_rebuilt condition after a refusal: %s", h.Summary())
	}
	if !strings.Contains(c.Message, "map_schema_version") {
		t.Errorf("the pins_rebuilt condition does not name the reason: %q", c.Message)
	}
	t.Logf("refused and rebuilt: %s", c.Message)

	// The rebuild really did replace the maps: the previous process's dynamic
	// rule is gone, which is the documented cost.
	if got := runMgr(t, second, pkt); got != xdpPass {
		t.Errorf("verdict = %s after a rebuild, want XDP_PASS: the old maps are still in use",
			verdictName(got))
	}
	if !xdpHookBusy(t, "lo") {
		t.Error("lo's XDP hook is free after a rebuild; the new program did not attach")
	}
}

// TestRefuseAdoptOnChangedLimits: the limits are restart-required, and a restart
// is exactly when adoption happens. Adopting the old maps would mean the operator
// restarted to apply a new max_ratelimit_sources and silently kept the old one.
func TestRefuseAdoptOnChangedLimits(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")
	first := mustOpen(t, opts)
	if err := first.Close(config.OnExitKeep); err != nil {
		t.Fatal(err)
	}

	opts.Limits.MaxRatelimitSources = 2048
	second := mustOpen(t, opts)
	defer func() { _ = second.Close(config.OnExitDetach) }()
	h := second.Health()
	if h.Adopted {
		t.Fatal("adopted maps sized for the previous limits")
	}
	c, _ := condition(h, CondPinsRebuilt, "")
	if !strings.Contains(c.Message, "MaxEntries") && !strings.Contains(c.Message, "incompatible") {
		t.Errorf("the refusal does not name the size mismatch: %q", c.Message)
	}
	t.Logf("refused and rebuilt: %s", c.Message)

	snap, err := second.Stats()
	if err != nil {
		t.Fatal(err)
	}
	for _, ms := range snap.Maps {
		if ms.Name == MapRLSrc4 && ms.MaxEntries != 2048 {
			t.Errorf("%s max_entries = %d after the restart, want the new limit 2048",
				ms.Name, ms.MaxEntries)
		}
	}
}

// TestRefuseAdoptOnValueSizeMismatch substitutes a pinned map with one of the
// right name and the wrong value size — the shape a struct that grew a field
// leaves behind.
func TestRefuseAdoptOnValueSizeMismatch(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")
	first := mustOpen(t, opts)
	if err := first.Close(config.OnExitKeep); err != nil {
		t.Fatal(err)
	}

	// Replace kapkan_profiles with a map whose value is one byte longer.
	if err := os.Remove(mapPin(dir, MapProfiles)); err != nil {
		t.Fatal(err)
	}
	wrong, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "kapkan_profiles",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  64 + 8, // struct kapkan_profile is 64 bytes
		MaxEntries: MaxProfiles,
	})
	if err != nil {
		t.Fatalf("create the substitute map: %v", err)
	}
	if err := wrong.Pin(mapPin(dir, MapProfiles)); err != nil {
		t.Fatal(err)
	}
	_ = wrong.Close()

	second := mustOpen(t, opts)
	defer func() { _ = second.Close(config.OnExitDetach) }()
	h := second.Health()
	if h.Adopted {
		t.Fatal("adopted a map set with a wrong value size — every field past the change " +
			"would be read at the wrong offset")
	}
	c, _ := condition(h, CondPinsRebuilt, "")
	if !strings.Contains(c.Message, "ValueSize") {
		t.Errorf("the refusal does not name the value size: %q", c.Message)
	}
	t.Logf("refused and rebuilt: %s", c.Message)
}

// TestRefusePinDirBadMode is the security half. A pin directory a local user can
// write is one in which they can pre-create a program this process would adopt —
// an XDP program of their choosing on the operator's uplink. It must be a refusal
// to start, not a fall back to rebuilding: falling back would let an
// unprivileged user drop every active mitigation on demand.
func TestRefusePinDirBadMode(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")
	m := mustOpen(t, opts)
	if err := m.Close(config.OnExitKeep); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []os.FileMode{0o777, 0o770, 0o702} {
		t.Run(fmt.Sprintf("mode_%o", mode), func(t *testing.T) {
			if err := os.Chmod(dir, mode); err != nil {
				t.Skipf("cannot chmod on this bpffs: %v", err)
			}
			defer func() { _ = os.Chmod(dir, 0o700) }()

			got, err := Open(opts)
			if err == nil {
				_ = got.Close(config.OnExitDetach)
				t.Fatalf("Open accepted a pin directory with mode %o", mode)
			}
			if !errors.Is(err, ErrPinPathUnsafe) {
				t.Fatalf("Open failed with %v, want ErrPinPathUnsafe", err)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// TestRefusePinPathNotBPFFS: an ordinary directory cannot hold pins, and the
// most common way to get one is a missing bpffs mount or a systemd unit with
// ProtectKernelTunables=yes.
func TestRefusePinPathNotBPFFS(t *testing.T) {
	opts := testOptions(t, filepath.Join(t.TempDir(), "kapkan"), "lo")
	m, err := Open(opts)
	if err == nil {
		_ = m.Close(config.OnExitDetach)
		t.Fatal("Open accepted a pin path that is not on a bpffs")
	}
	if !errors.Is(err, ErrPinPathUnsafe) {
		t.Fatalf("Open failed with %v, want ErrPinPathUnsafe", err)
	}
	t.Logf("refused: %v", err)
}

/* --------------------------------------------------------- attach modes */

// TestXDPModes covers all three settings on both kinds of device, which is the
// only way to see that "auto" records what it chose.
func TestXDPModes(t *testing.T) {
	// lo has no ndo_bpf: native must fail, auto must fall back, generic works.
	t.Run("lo/native refuses", func(t *testing.T) {
		opts := testOptions(t, pinDir(t), "lo")
		opts.XDPMode = config.XDPModeNative
		m, err := Open(opts)
		if err == nil {
			_ = m.Close(config.OnExitDetach)
			t.Fatal("native mode attached to lo, which has no driver XDP support")
		}
		if !strings.Contains(err.Error(), "native") {
			t.Errorf("the error does not mention the mode: %v", err)
		}
		t.Logf("refused as it should: %v", err)
	})

	t.Run("lo/auto falls back and says so", func(t *testing.T) {
		m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
		defer func() { _ = m.Close(config.OnExitDetach) }()
		h := m.Health()
		st := ifaceStatus(t, h, "lo")
		if st.Mode != config.XDPModeGeneric {
			t.Errorf("mode = %q on lo under auto, want generic", st.Mode)
		}
		if !st.Attached {
			t.Errorf("not attached: %s", h.Summary())
		}
		if h.Degraded {
			t.Errorf("a generic-mode attachment is not degradation: %s", h.Summary())
		}
		c, found := condition(h, CondModeDowngraded, "lo")
		if !found {
			t.Fatalf("auto fell back to generic without recording it: %s", h.Summary())
		}
		t.Logf("recorded: %s", c.Message)
		// The mode is recorded in the pin name, because a bpf_link reports only
		// its ifindex and an adopting process has no other way to learn it.
		if lp, ok := findLinkPin(m.opts.PinPath, "lo"); !ok || lp.mode != config.XDPModeGeneric {
			t.Errorf("link pin does not record the generic mode: %+v (found=%v)", lp, ok)
		}
	})

	t.Run("lo/generic forced", func(t *testing.T) {
		opts := testOptions(t, pinDir(t), "lo")
		opts.XDPMode = config.XDPModeGeneric
		m := mustOpen(t, opts)
		defer func() { _ = m.Close(config.OnExitDetach) }()
		st := ifaceStatus(t, m.Health(), "lo")
		if st.Mode != config.XDPModeGeneric || !st.Attached {
			t.Errorf("status = %+v", st)
		}
		// Under an explicit generic there is nothing to warn about: the operator
		// asked for it.
		if _, found := condition(m.Health(), CondModeDowngraded, "lo"); found {
			t.Error("an explicitly configured generic mode was reported as a downgrade")
		}
	})

	// A veth DOES support native XDP, so auto must pick it.
	t.Run("veth/auto picks native", func(t *testing.T) {
		iface := makeVeth(t, "kapv0")
		m := mustOpen(t, testOptions(t, pinDir(t), iface))
		defer func() { _ = m.Close(config.OnExitDetach) }()
		st := ifaceStatus(t, m.Health(), iface)
		if st.Mode != config.XDPModeNative {
			t.Errorf("mode = %q on a veth under auto, want native", st.Mode)
		}
		if !st.Attached || st.Index != ifIndex(t, iface) {
			t.Errorf("status = %+v, ifindex should be %d", st, ifIndex(t, iface))
		}
		if _, found := condition(m.Health(), CondModeDowngraded, iface); found {
			t.Error("a native attachment was reported as a downgrade")
		}
		if !xdpHookBusy(t, iface) {
			t.Errorf("nothing is attached to %s's XDP hook", iface)
		}
		if _, idx := pinnedLinkIdentity(t, m.opts.PinPath, iface); idx != st.Index {
			t.Errorf("the pinned link is on ifindex %d, the manager reports %d", idx, st.Index)
		}
		t.Logf("real native attach on %s (ifindex %d)", iface, st.Index)
	})
}

// TestRestartWithChangedModeReAttaches: xdp_mode is restart-required, and a
// restart is how it is meant to be applied — so adopting the old attachment
// would hand the operator the mode they just changed away from, silently.
func TestRestartWithChangedModeReAttaches(t *testing.T) {
	// Separate pin directories per subtest: a refused Open legitimately discards
	// the pinned attachment on its way out, so sharing one would make the
	// adoption assertion depend on the refusal having run first.
	t.Run("an unchanged mode adopts", func(t *testing.T) {
		dir := pinDir(t)
		opts := testOptions(t, dir, "lo")
		opts.XDPMode = config.XDPModeGeneric
		first := mustOpen(t, opts)
		idBefore, _ := pinnedLinkIdentity(t, dir, "lo")
		if err := first.Close(config.OnExitKeep); err != nil {
			t.Fatal(err)
		}
		second := mustOpen(t, opts)
		defer func() { _ = second.Close(config.OnExitDetach) }()
		if !second.Health().Adopted {
			t.Error("did not adopt on a restart with an unchanged mode")
		}
		if idAfter, _ := pinnedLinkIdentity(t, dir, "lo"); idAfter != idBefore {
			t.Errorf("bpf_link id changed from %d to %d on a restart with the same mode",
				idBefore, idAfter)
		}
	})

	// An operator who changes xdp_mode and restarts did so to get the other mode.
	// Adopting the pinned attachment would hand them the old one and say nothing.
	// lo cannot do native, so the correct outcome is a loud failure — NOT a
	// silent generic attachment.
	t.Run("a changed mode is not adopted", func(t *testing.T) {
		dir := pinDir(t)
		opts := testOptions(t, dir, "lo")
		opts.XDPMode = config.XDPModeGeneric
		first := mustOpen(t, opts)
		if err := first.Close(config.OnExitKeep); err != nil {
			t.Fatal(err)
		}

		native := opts
		native.XDPMode = config.XDPModeNative
		m, err := Open(native)
		if err == nil {
			st := ifaceStatus(t, m.Health(), "lo")
			_ = m.Close(config.OnExitDetach)
			t.Fatalf("Open succeeded with xdp_mode: native on lo, reporting mode %q — "+
				"it adopted the generic attachment that was already pinned", st.Mode)
		}
		// And specifically NOT "file exists": discarding the old attachment has to
		// leave the hook free, or the diagnosis blames the wrong thing entirely.
		if strings.Contains(err.Error(), "file exists") || strings.Contains(err.Error(), "already owns") {
			t.Errorf("the fresh attach raced the previous link's release:\n%v", err)
		}
		if !strings.Contains(err.Error(), "no native XDP support") {
			t.Errorf("the error does not name the real reason:\n%v", err)
		}
		t.Logf("refused: %v", err)
	})

	// The same discard path, but with a mode the device CAN do: a veth pinned
	// generic and restarted as native must end up native.
	t.Run("a changed mode the device supports is applied", func(t *testing.T) {
		iface := makeVeth(t, "kapv2")
		dir := pinDir(t)
		opts := testOptions(t, dir, iface)
		opts.XDPMode = config.XDPModeGeneric
		first := mustOpen(t, opts)
		if got := ifaceStatus(t, first.Health(), iface).Mode; got != config.XDPModeGeneric {
			t.Fatalf("mode = %q, want generic", got)
		}
		if err := first.Close(config.OnExitKeep); err != nil {
			t.Fatal(err)
		}

		native := opts
		native.XDPMode = config.XDPModeNative
		second := mustOpen(t, native)
		defer func() { _ = second.Close(config.OnExitDetach) }()
		st := ifaceStatus(t, second.Health(), iface)
		if st.Mode != config.XDPModeNative || !st.Attached {
			t.Fatalf("after restarting with xdp_mode: native, status = %+v", st)
		}
		if lp, ok := findLinkPin(dir, iface); !ok || lp.mode != config.XDPModeNative {
			t.Errorf("the pin still records mode %v (found=%v)", lp.mode, ok)
		}
		t.Logf("re-attached %s from generic to native across a restart", iface)
	})
}

// TestPartialAttachIsDegradedNotFatal: eth0 being protected must not depend on
// eth1 existing. And a data plane attached to NOTHING must refuse to start,
// because that state is indistinguishable from disabled.
func TestPartialAttachIsDegradedNotFatal(t *testing.T) {
	t.Run("one of two", func(t *testing.T) {
		m := mustOpen(t, testOptions(t, pinDir(t), "lo", "kapkan-absent0"))
		defer func() { _ = m.Close(config.OnExitDetach) }()
		h := m.Health()
		if !h.Degraded {
			t.Errorf("a missing interface is not reported as degraded: %s", h.Summary())
		}
		if !ifaceStatus(t, h, "lo").Attached {
			t.Errorf("lo was not attached because another interface was missing: %s", h.Summary())
		}
		if _, found := condition(h, CondInterfaceMissing, "kapkan-absent0"); !found {
			t.Errorf("no interface_missing condition: %s", h.Summary())
		}
		t.Logf("degraded as it should be: %s", h.Summary())
	})

	t.Run("none at all", func(t *testing.T) {
		m, err := Open(testOptions(t, pinDir(t), "kapkan-absent0", "kapkan-absent1"))
		if err == nil {
			_ = m.Close(config.OnExitDetach)
			t.Fatal("Open succeeded with no interface attached; that state is " +
				"indistinguishable from a disabled data plane")
		}
		t.Logf("refused: %v", err)
	})
}

/* ------------------------------------------------------- interface flap */

// TestInterfaceFlapReattaches is the watcher's reason to exist. A NIC going away
// silently detaches the XDP program and the kernel does not tell us: an
// unregistered netdevice leaves the bpf_link reporting ifindex 0.
//
// Reconcile() is called directly rather than waiting for the ticker, so the test
// is deterministic; the ticker only decides when Reconcile runs in production.
func TestInterfaceFlapReattaches(t *testing.T) {
	iface := makeVeth(t, "kapv1")
	m := mustOpen(t, testOptions(t, pinDir(t), iface))
	defer func() { _ = m.Close(config.OnExitDetach) }()

	before := ifaceStatus(t, m.Health(), iface)
	if !before.Attached {
		t.Fatalf("not attached to start with: %+v", before)
	}
	t.Logf("attached: ifindex %d mode %s", before.Index, before.Mode)

	// The NIC goes away.
	delVeth(t, iface)
	m.Reconcile()
	h := m.Health()
	if !h.Degraded {
		t.Errorf("the data plane is not degraded after its interface was deleted: %s", h.Summary())
	}
	if ifaceStatus(t, h, iface).Attached {
		t.Errorf("still claims to be attached to a deleted interface: %s", h.Summary())
	}
	if _, found := condition(h, CondInterfaceMissing, iface); !found {
		t.Errorf("no interface_missing condition: %s", h.Summary())
	}
	t.Logf("loss detected: %s", h.Summary())

	// Persistent failure must be a condition and a backoff, never a crash and
	// never a silent no-op. Several passes with the interface still gone.
	for i := 0; i < 3; i++ {
		time.Sleep(3 * time.Millisecond) // clear the (millisecond) backoff
		m.Reconcile()
	}
	h = m.Health()
	st := ifaceStatus(t, h, iface)
	if st.Attempts < 2 {
		t.Errorf("attach attempts = %d after several passes, want them counted", st.Attempts)
	}
	if st.LastError == "" {
		t.Error("no last_error recorded for a persistently failing interface")
	}
	t.Logf("persistent failure surfaced: attempts=%d err=%q", st.Attempts, st.LastError)

	// And it comes back — under the same name, with a NEW ifindex, which is
	// exactly the case a link that merely "looks attached" would get wrong.
	makeVeth(t, iface)
	newIndex := ifIndex(t, iface)
	time.Sleep(3 * time.Millisecond)
	m.Reconcile()

	h = m.Health()
	st = ifaceStatus(t, h, iface)
	if !st.Attached {
		t.Fatalf("not re-attached after the interface came back: %s (last_error %q)",
			h.Summary(), st.LastError)
	}
	if st.Index != newIndex {
		t.Errorf("re-attached to ifindex %d, the interface is now %d", st.Index, newIndex)
	}
	if h.Degraded {
		t.Errorf("still degraded after a successful re-attach: %s", h.Summary())
	}
	if !xdpHookBusy(t, iface) {
		t.Errorf("nothing is attached to %s's XDP hook after the re-attach", iface)
	}
	if _, idx := pinnedLinkIdentity(t, m.opts.PinPath, iface); idx != newIndex {
		t.Errorf("the pinned link is on ifindex %d, the interface is now %d", idx, newIndex)
	}
	if st.Attempts != 0 {
		t.Errorf("attach attempts = %d after success, want them reset", st.Attempts)
	}
	if _, found := condition(h, CondUnattached, iface); found {
		t.Error("the unattached condition was not cleared after a successful re-attach")
	}
	t.Logf("re-attached to the new ifindex %d: %s", newIndex, h.Summary())
}

/* -------------------------------------------------------------- reload */

// dropChargen is a static rule with no source prefix, which is the interesting
// case: it has no address family, so it must compile to one kernel rule per
// family or it would silently protect only IPv4.
func dropChargen() StaticRule {
	return StaticRule{
		Name: "drop-chargen", Action: ActionDrop,
		Proto: ptr(protoUDP), SrcPort: ptr(uint16(19)),
	}
}

func chargenV4() []byte {
	return cat(eth(etherTypeIPv4), ipv4(17, 0, 8), udp(19, 53, 0))
}

func chargenV6() []byte {
	return cat(eth(etherTypeIPv6), ipv6(17, 8), udp(19, 53, 0))
}

// TestStaticPolicyBothFamilies proves StaticExpansion is not a theory: one config
// rule, both families dropped.
func TestStaticPolicyBothFamilies(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.Policy.Statics = []StaticRule{dropChargen()}
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	for name, pkt := range map[string][]byte{"ipv4": chargenV4(), "ipv6": chargenV6()} {
		if got := runMgr(t, m, pkt); got != xdpDrop {
			t.Errorf("%s: verdict = %s, want XDP_DROP — a config rule with no match.src "+
				"must cover both families", name, verdictName(got))
		}
	}
	cfg, err := ReadConfig(m.Maps())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StaticCount != StaticExpansion {
		t.Errorf("static_count = %d, want %d (one config rule, one kernel rule per family)",
			cfg.StaticCount, StaticExpansion)
	}
	// An icmp rule is family-pinned by its protocol number, so it must NOT be
	// doubled.
	opts2 := opts
	opts2.Policy.Statics = []StaticRule{{Name: "icmp", Action: ActionDrop, Proto: ptr(protoICMP)}}
	c, err := compilePolicy(opts2.Policy, m.Sizing(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.rules) != 1 {
		t.Errorf("an icmp rule compiled to %d kernel rules, want 1 (icmp is IPv4-only)", len(c.rules))
	}
}

// TestReloadFlipsGenerationsWithoutLoss is the lossless-swap proof.
//
// A goroutine drives BPF_PROG_TEST_RUN in a tight loop while Reload publishes a
// new static rule set that still drops the same packet. Every verdict observed
// must be XDP_DROP: a packet that saw a half-built rule set, or the wrong half of
// the double buffer, would show up as a pass. Before/after generation numbers
// prove the flip really happened rather than the test observing a no-op.
func TestReloadFlipsGenerationsWithoutLoss(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.Policy.Statics = []StaticRule{dropChargen()}
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	pkt := chargenV4()
	if got := runMgr(t, m, pkt); got != xdpDrop {
		t.Fatalf("before the reload: verdict = %s, want XDP_DROP", verdictName(got))
	}
	genBefore, err := ReadConfig(m.Maps())
	if err != nil {
		t.Fatal(err)
	}

	// A driver goroutine hammers the program while the flips happen. `started`
	// exists because without it the reload loop can finish before the goroutine
	// is scheduled at all, and the test would pass having proved nothing.
	prog := m.testProgram()
	stop := make(chan struct{})
	done := make(chan struct{})
	started := make(chan struct{})
	var runs, passes atomic.Int64
	var runErr atomic.Pointer[error]
	go func() {
		defer close(done)
		first := true
		for {
			ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
			if err != nil {
				runErr.Store(&err)
				if first {
					close(started)
				}
				return
			}
			runs.Add(1)
			if ret != xdpDrop {
				passes.Add(1)
			}
			if first {
				first = false
				close(started)
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	<-started

	// Several reloads, each publishing a different rule set that still drops the
	// probe packet. Doing it repeatedly, with the driver running throughout, is
	// what makes the window a flip opens likely to be hit if there is one.
	// Keep flipping until the driver has demonstrably raced them, rather than
	// for a fixed number of iterations.
	//
	// The window in which a flip can be observed IS the reload work, so it
	// shrinks on a fast machine by exactly the factor that speeds the driver up.
	// A fixed 8 flips plus an absolute "at least 100 runs" guard therefore
	// calibrates itself to whatever host it was written on: measured 73 runs on
	// a KVM-backed CI runner against >100 under TCG locally, which made the
	// matrix red on a different kernel each run for reasons that had nothing to
	// do with the kernel. Looping until both conditions hold keeps the guard's
	// intent — proof that the driver really overlapped the swaps — without
	// asserting anything about how fast the machine is.
	const minFlips, minRuns = 8, 100
	next := opts
	publishedGens := map[uint32]int{}
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; ; i++ {
		next.Policy.Statics = []StaticRule{
			dropChargen(),
			{Name: fmt.Sprintf("filler-%d", i), Action: ActionDrop,
				Proto: ptr(protoUDP), SrcPort: ptr(uint16(1000 + i))},
		}
		rep, err := m.Reload(next)
		if err != nil {
			t.Fatalf("Reload %d: %v", i, err)
		}
		if rep.StaticRules != 4 { // two config rules x two families
			t.Errorf("reload %d installed %d kernel rules, want 4", i, rep.StaticRules)
		}
		publishedGens[rep.Generation]++
		if i+1 >= minFlips && runs.Load() >= minRuns {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %d flips the concurrent driver had only managed %d runs (want %d); "+
				"it is not keeping up, which means this test is no longer proving the swap is "+
				"lossless under load", i+1, runs.Load(), minRuns)
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	<-done

	if e := runErr.Load(); e != nil {
		t.Fatalf("the concurrent driver stopped after %d runs: %v", runs.Load(), *e)
	}
	if runs.Load() < minRuns {
		t.Fatalf("the concurrent driver only managed %d runs; too few to have overlapped the flips",
			runs.Load())
	}
	if passes.Load() != 0 {
		t.Errorf("%d of %d packets were PASSED during 8 generation flips; the swap is not lossless",
			passes.Load(), runs.Load())
	}
	genAfter, err := ReadConfig(m.Maps())
	if err != nil {
		t.Fatal(err)
	}
	// Eight reloads alternate 0,1,0,1,... and land back where they started, so the
	// before/after generation is deliberately NOT the assertion — what matters is
	// that both halves were genuinely published, i.e. the driver really did read
	// across flips rather than through a no-op.
	if len(publishedGens) != Generations {
		t.Errorf("reloads published generations %v; expected all %d halves to be used, "+
			"so this test did not exercise a flip", publishedGens, Generations)
	}
	t.Logf("%d packets driven across 8 flips (generations published: %v, %d -> %d), zero passes",
		runs.Load(), publishedGens, genBefore.Generation, genAfter.Generation)
}

// TestReloadPreservesDynamicRules is the regression test for the trap in
// mirrorPolicyBlocks: kapkan_policies shares the generation counter with
// kapkan_statics, so a static-policy reload flips the datapath to a half of the
// policy map that the mitigator never wrote. Without the mirror, an operator
// fixing a typo in an allowlist entry would un-mitigate every live attack.
func TestReloadPreservesDynamicRules(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	victim := mustPrefix(t, "203.0.113.9/32")
	rules, err := EncodeRules(RuleSpec{ID: 11, Action: ActionDrop,
		Src: mustPrefix(t, "198.51.100.7/32"), Dst: victim})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WithMaps(func(maps *Maps, gen uint32) error {
		if err := PutPolicy(maps, gen, 0, rules); err != nil {
			return err
		}
		return AddVictim(maps, victim, 0)
	}); err != nil {
		t.Fatal(err)
	}

	pkt := cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(1234, 80, 0x02))
	if got := runMgr(t, m, pkt); got != xdpDrop {
		t.Fatalf("the dynamic rule does not drop: verdict = %s", verdictName(got))
	}

	next := opts
	next.Policy.Statics = []StaticRule{dropChargen()}
	rep, err := m.Reload(next)
	if err != nil {
		t.Fatal(err)
	}
	if rep.MirroredPolicyBlocks != 1 {
		t.Errorf("reload mirrored %d occupied policy blocks, want 1", rep.MirroredPolicyBlocks)
	}
	if got := runMgr(t, m, pkt); got != xdpDrop {
		t.Errorf("after a static-policy reload the dynamic rule stopped dropping "+
			"(verdict %s): the generation flip lost it", verdictName(got))
	}
	t.Logf("reload: %s", rep.Summary())
}

// TestReloadRejectsRestartRequiredChanges: the Manager refuses what it cannot
// honour, independently of config.Store.Reload also refusing the file (which
// TestRestartRequiredMatchesConfigsRule checks). There is no bpf(2) call that
// resizes a map and an LRU cannot shrink.
func TestReloadRejectsRestartRequiredChanges(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	for name, mutate := range map[string]func(o *Options){
		"limits shrunk":  func(o *Options) { o.Limits.MaxRatelimitSources = 128 },
		"limits grown":   func(o *Options) { o.Limits.MaxRatelimitSources = 4096 },
		"interface list": func(o *Options) { o.Interfaces = []string{"lo", "kapkan-absent0"} },
		"xdp mode":       func(o *Options) { o.XDPMode = config.XDPModeGeneric },
		"pin path":       func(o *Options) { o.PinPath = o.PinPath + "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			next := opts
			mutate(&next)
			_, err := m.Reload(next)
			if !errors.Is(err, ErrRestartRequired) {
				t.Fatalf("Reload returned %v, want ErrRestartRequired", err)
			}
			t.Logf("refused: %v", err)
		})
	}

	// And the static policy still reloads afterwards: a rejected reload must not
	// leave the manager wedged.
	next := opts
	next.Policy.Statics = []StaticRule{dropChargen()}
	if _, err := m.Reload(next); err != nil {
		t.Fatalf("a legitimate reload after the refusals failed: %v", err)
	}
	if got := runMgr(t, m, chargenV4()); got != xdpDrop {
		t.Errorf("verdict = %s, want XDP_DROP", verdictName(got))
	}
}

/* --------------------------------------------- allowlist reconciliation */

// TestAllowlistReconciliation covers both of the cases config cannot see, plus
// the trie diff that keeps a prefix present across a reload that retains it.
func TestAllowlistReconciliation(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	// A static drop aimed at one source, which an allowlist entry will shadow.
	opts.Policy.Statics = []StaticRule{{
		Name: "drop-that-host", Action: ActionDrop,
		Src: mustPrefix(t, "198.51.100.7/32"), Proto: ptr(protoUDP), SrcPort: ptr(uint16(19)),
	}}
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	pkt := chargenV4() // src 198.51.100.7
	if got := runMgr(t, m, pkt); got != xdpDrop {
		t.Fatalf("the static rule does not drop: verdict = %s", verdictName(got))
	}

	// A dynamic rule dropping the same source, so the reload can report that a
	// LIVE mitigation just stopped taking effect.
	victim := mustPrefix(t, "203.0.113.9/32")
	rules, err := EncodeRules(RuleSpec{ID: 21, Action: ActionDrop,
		Src: mustPrefix(t, "198.51.100.7/32"), Dst: victim})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WithMaps(func(maps *Maps, gen uint32) error {
		if err := PutPolicy(maps, gen, 0, rules); err != nil {
			return err
		}
		return AddVictim(maps, victim, 0)
	}); err != nil {
		t.Fatal(err)
	}

	// Now allowlist the /24 that contains it.
	next := opts
	next.Policy.Allow = []netip.Prefix{
		mustPrefix(t, "198.51.100.0/24"),
		mustPrefix(t, "192.0.2.0/24"),
	}
	rep, err := m.Reload(next)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reload: %s", rep.Summary())

	if len(rep.AllowAdded) != 2 {
		t.Errorf("allow_added = %v, want both prefixes", rep.AllowAdded)
	}
	if len(rep.ShadowedStatics) != 1 || !strings.Contains(rep.ShadowedStatics[0], "drop-that-host") {
		t.Errorf("shadowed_statics = %v, want the static rule named", rep.ShadowedStatics)
	}
	if rep.ShadowedDynamicRules != 1 {
		t.Errorf("shadowed_dynamic_rules = %d, want 1", rep.ShadowedDynamicRules)
	}
	if _, found := condition(m.Health(), CondPolicyShadowed, ""); !found {
		t.Error("no policy_shadowed condition after a rule was shadowed")
	}
	// And the kernel agrees: precedence 1 admits the packet both rules wanted
	// dropped.
	if got := runMgr(t, m, pkt); got != xdpPass {
		t.Errorf("verdict = %s after allowlisting the source, want XDP_PASS", verdictName(got))
	}
	if p, _ := readStatMap(t, m, StatPassAllowSrc); p == 0 {
		t.Error("pass_allow_src did not move; the packet passed for some other reason")
	}

	// Remove one prefix and keep the other. The kept one must never have been
	// absent (adds happen before removes), and the removed one must be gone.
	next2 := next
	next2.Policy.Allow = []netip.Prefix{mustPrefix(t, "198.51.100.0/24")}
	rep2, err := m.Reload(next2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.AllowAdded) != 0 || len(rep2.AllowRemoved) != 1 ||
		rep2.AllowRemoved[0] != "192.0.2.0/24" {
		t.Errorf("second reload: added=%v removed=%v, want only 192.0.2.0/24 removed",
			rep2.AllowAdded, rep2.AllowRemoved)
	}
	have, err := trieEntries(m.Maps().KapkanAllow4, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(have) != 1 || have[0].String() != "198.51.100.0/24" {
		t.Errorf("kapkan_allow4 holds %v, want only 198.51.100.0/24", have)
	}

	// Dropping the allowlist entirely restores the drop — the reconciliation is
	// a real diff in both directions, not an append-only list.
	next3 := next2
	next3.Policy.Allow = nil
	if _, err := m.Reload(next3); err != nil {
		t.Fatal(err)
	}
	if got := runMgr(t, m, pkt); got != xdpDrop {
		t.Errorf("verdict = %s after the allowlist was emptied, want XDP_DROP again",
			verdictName(got))
	}
	if _, found := condition(m.Health(), CondPolicyShadowed, ""); found {
		t.Error("the policy_shadowed condition was not cleared once the allowlist was emptied")
	}
}

// readStatMap sums one counter through the manager's map set.
func readStatMap(t *testing.T, m *Manager, s Stat) (uint64, uint64) {
	t.Helper()
	c, err := ReadStat(m.Maps(), s)
	if err != nil {
		t.Fatal(err)
	}
	return c.Pkts, c.Bytes
}

// TestProfilesLiveAndDieWithTheConfig: an id keeps its meaning across a reload
// (so reordering the config cannot silently reassign every rate), and a profile
// the config no longer declares is retired to "caps nothing", which admits.
func TestProfilesLiveAndDieWithTheConfig(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.Policy.Profiles = []NamedRate{{Name: "slow", PPS: 10}, {Name: "fat", Mbps: 100}}
	opts.Policy.Statics = []StaticRule{
		{Name: "cap", Action: ActionRateLimit, Profile: "fat", Proto: ptr(protoUDP)},
	}
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	slowID, ok := m.ProfileID("slow")
	if !ok {
		t.Fatal("profile \"slow\" has no id")
	}
	fatID, _ := m.ProfileID("fat")
	t.Logf("profile ids: slow=%d fat=%d", slowID, fatID)

	// Reorder the config. The ids must not move: a rule in the outgoing
	// generation would otherwise read the other profile's numbers in the window
	// before the flip.
	next := opts
	next.Policy.Profiles = []NamedRate{{Name: "fat", Mbps: 100}, {Name: "slow", PPS: 10}}
	if _, err := m.Reload(next); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ProfileID("slow"); got != slowID {
		t.Errorf("profile \"slow\" moved from id %d to %d when the config was reordered", slowID, got)
	}
	if got, _ := m.ProfileID("fat"); got != fatID {
		t.Errorf("profile \"fat\" moved from id %d to %d when the config was reordered", fatID, got)
	}

	// Drop "slow" from the config. Its slot must be retired to a profile that
	// caps neither packets nor bytes, which the datapath admits on — failing open,
	// per the charter.
	next2 := next
	next2.Policy.Profiles = []NamedRate{{Name: "fat", Mbps: 100}}
	if _, err := m.Reload(next2); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.ProfileID("slow"); ok {
		t.Error("profile \"slow\" is still known after the config dropped it")
	}
	var prof Profile
	if err := m.Maps().KapkanProfiles.Lookup(slowID, &prof); err != nil {
		t.Fatal(err)
	}
	if prof.RatePps != 0 || prof.RateBps != 0 {
		t.Errorf("retired profile %d still caps traffic: %+v", slowID, prof)
	}
	t.Logf("profile %d retired to a no-cap entry, which the datapath admits on", slowID)
}

/* --------------------------------------------------------------- close */

// TestCloseKeepVsDetach is the on_exit contract, checked against the kernel's own
// view of what is attached rather than against our pins.
func TestCloseKeepVsDetach(t *testing.T) {
	t.Run("keep leaves it enforcing", func(t *testing.T) {
		dir := pinDir(t)
		opts := testOptions(t, dir, "lo")
		opts.Policy.Statics = []StaticRule{dropChargen()}
		m := mustOpen(t, opts)
		if err := m.Close(config.OnExitKeep); err != nil {
			t.Fatalf("Close(keep): %v", err)
		}
		if !xdpHookBusy(t, "lo") {
			t.Error("lo's XDP hook is free after Close(keep)")
		}
		if _, ok := findLinkPin(dir, "lo"); !ok {
			t.Error("the link pin is gone after Close(keep)")
		}
		for _, name := range append([]string{progPinName}, AllMaps...) {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Errorf("pin %q is gone after Close(keep): %v", name, err)
			}
		}
		// Static policy is still enforced with no userspace at all: the pinned
		// program keeps running. Prove it by driving the PINNED program.
		prog, err := ebpf.LoadPinnedProgram(progPin(dir), nil)
		if err != nil {
			t.Fatalf("open the pinned program: %v", err)
		}
		defer func() { _ = prog.Close() }()
		ret, err := prog.Run(&ebpf.RunOptions{Data: chargenV4()})
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpDrop {
			t.Errorf("the pinned program returns %s after Close(keep), want XDP_DROP — "+
				"static policy must keep enforcing with no userspace", verdictName(ret))
		}

		// Clean up for real, through a second manager that adopts it.
		m2 := mustOpen(t, opts)
		if err := m2.Close(config.OnExitDetach); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("detach removes everything", func(t *testing.T) {
		dir := pinDir(t)
		opts := testOptions(t, dir, "lo")
		m := mustOpen(t, opts)
		if !xdpHookBusy(t, "lo") {
			t.Fatal("nothing is attached to lo's XDP hook while the manager is running")
		}
		if err := m.Close(config.OnExitDetach); err != nil {
			t.Fatalf("Close(detach): %v", err)
		}
		if xdpHookBusy(t, "lo") {
			t.Error("something is still attached to lo's XDP hook after Close(detach)")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read pin dir: %v", err)
		}
		if len(entries) != 0 {
			names := make([]string, len(entries))
			for i, e := range entries {
				names[i] = e.Name()
			}
			t.Errorf("pins left after Close(detach): %v", names)
		}
	})

	t.Run("close is idempotent and later calls are refused", func(t *testing.T) {
		m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
		if err := m.Close(config.OnExitDetach); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(config.OnExitDetach); err != nil {
			t.Errorf("the second Close returned %v, want nil", err)
		}
		if _, err := m.Stats(); !errors.Is(err, ErrClosed) {
			t.Errorf("Stats after Close returned %v, want ErrClosed", err)
		}
		if _, err := m.Reload(testOptions(t, "/sys/fs/bpf/x", "lo")); err == nil {
			t.Error("Reload after Close succeeded")
		}
		if m.Maps() != nil {
			t.Error("Maps() after Close is non-nil; those are closed file descriptors")
		}
		if err := m.WithMaps(func(*Maps, uint32) error { return nil }); !errors.Is(err, ErrClosed) {
			t.Errorf("WithMaps after Close returned %v, want ErrClosed", err)
		}
	})

	t.Run("an invalid on_exit is refused", func(t *testing.T) {
		m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
		defer func() { _ = m.Close(config.OnExitDetach) }()
		if err := m.Close("burn"); err == nil {
			t.Fatal("Close accepted an unknown on_exit mode")
		}
	})
}

// TestWatcherRunsAndStops exercises the real ticker path once, since every other
// test disables it — a watcher that panicked or deadlocked on its first tick
// would otherwise never be noticed here.
func TestWatcherRunsAndStops(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.WatchInterval = 5 * time.Millisecond
	m := mustOpen(t, opts)
	time.Sleep(40 * time.Millisecond) // several ticks
	if h := m.Health(); h.Degraded {
		t.Errorf("the watcher marked a healthy attachment degraded: %s", h.Summary())
	}
	// Close must not wait for a tick, and must join the goroutine.
	start := time.Now()
	if err := m.Close(config.OnExitDetach); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close took %v; it should not wait on the watcher's ticker", d)
	}
}

/* ------------------------------------------------------------- probes */

func TestKernelVersionParsing(t *testing.T) {
	// The real host, whatever it is, must parse and be at or above the floor —
	// otherwise none of the tests above could have run.
	major, minor, raw, err := kernelVersion()
	if err != nil {
		t.Fatalf("kernelVersion: %v", err)
	}
	t.Logf("running kernel %s, parsed as %d.%d (floor %d.%d)",
		raw, major, minor, minKernelMajor, minKernelMinor)
	if _, err := checkKernel(); err != nil {
		t.Errorf("checkKernel rejected the kernel these tests are running on: %v", err)
	}
	for in, want := range map[string]string{
		"6.12.76-linuxkit":  "6.12",
		"5.15.0-91-generic": "5.15",
		"6.1.0-rc4+":        "6.1",
		"5.10.221":          "5.10",
	} {
		gotMajor, gotMinor := 0, 0
		f := strings.SplitN(in, ".", 3)
		gotMajor = atoiOrZero(leadingDigits(f[0]))
		gotMinor = atoiOrZero(leadingDigits(f[1]))
		if got := fmt.Sprintf("%d.%d", gotMajor, gotMinor); got != want {
			t.Errorf("parse %q = %s, want %s", in, got, want)
		}
	}
}

func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// TestCapabilityProbeAgreesWithReality: the capability check must not refuse a
// process that can in fact load the program, and must not accept one that
// cannot. Under `make dataplane-test` the container is privileged, so the only
// assertion available is the positive one — which is still worth making, because
// a check that refused everything would pass every negative test.
func TestCapabilityProbeAgreesWithReality(t *testing.T) {
	caps, err := effectiveCaps()
	if err != nil {
		t.Skipf("cannot read /proc/self/status: %v", err)
	}
	t.Logf("CapEff = %#016x", caps)
	probeErr := checkCapabilities()

	// Ground truth: can we actually load the program?
	_, verified, loadErr := probeLoad()
	switch {
	case loadErr == nil && probeErr != nil:
		t.Errorf("the capability check refused a process that CAN load the program:\n%v", probeErr)
	case loadErr != nil && probeErr == nil && errors.Is(loadErr, syscall.EPERM):
		t.Errorf("the capability check accepted a process that cannot load the program: %v", loadErr)
	case loadErr != nil:
		// Through skipOrFail, not a plain Skipf. This is the test that stops the
		// gate marking its own homework, so on an enforcement run — the CI bpf
		// job, make dataplane-test, the kernel matrix — it has to be a failure
		// rather than a quiet skip. Otherwise a job whose program loading broke
		// would lose the one check that would have noticed the gate was lying.
		skipOrFail(t, "cannot load the program here (%v); capability check said: %v", loadErr, probeErr)
	}
	t.Logf("program loads, verifier processed %d insns; capability check agrees", verified)
}

// TestStatsSnapshot checks the shape of what /api and the console will render.
func TestStatsSnapshot(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.Policy.Statics = []StaticRule{dropChargen()}
	m := mustOpen(t, opts)
	defer func() { _ = m.Close(config.OnExitDetach) }()

	if got := runMgr(t, m, chargenV4()); got != xdpDrop {
		t.Fatalf("verdict = %s", verdictName(got))
	}
	snap, err := m.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Verdicts[StatDropStatic.String()].Pkts != 1 {
		t.Errorf("verdicts[%s] = %+v, want 1 packet",
			StatDropStatic, snap.Verdicts[StatDropStatic.String()])
	}
	if len(snap.Verdicts) != int(StatMax) {
		t.Errorf("verdicts has %d entries, want %d", len(snap.Verdicts), StatMax)
	}
	if len(snap.Maps) != len(AllMaps) {
		t.Errorf("maps has %d entries, want %d", len(snap.Maps), len(AllMaps))
	}
	if snap.SchemaVersion != MapSchemaVersion {
		t.Errorf("schema version = %d, want %d", snap.SchemaVersion, MapSchemaVersion)
	}
	if snap.StaticCount != StaticExpansion {
		t.Errorf("static_rules = %d, want %d", snap.StaticCount, StaticExpansion)
	}
	if !snap.Health.Enabled || snap.Health.Degraded {
		t.Errorf("health = %s", snap.Health.Summary())
	}
	// The map list is sorted by cost, which is what makes it useful in a console:
	// the two LRUs come first and are what an operator should tune.
	t.Logf("largest map: %s (%d bytes)", snap.Maps[0].Name, snap.Maps[0].Bytes)
}

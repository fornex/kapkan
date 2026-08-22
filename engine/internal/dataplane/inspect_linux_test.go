//go:build linux

package dataplane

// InspectPins against a real kernel: every state the command can report, and the
// three proofs that it does not mutate anything.
//
// Run with `make dataplane-test` (cross-compile, then a privileged container).
// The helpers — bpffsRoot, pinDir, testOptions, mustOpen, makeVeth — are shared
// with manager_linux_test.go; see the harness note at the top of that file for
// why "lo" and a veth are the two devices used.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/kapkan-io/kapkan/internal/config"
)

// TestCfgSchemaVersionOffset gates the constant that lets a skew be diagnosed at
// all. The whole schema-skew path depends on being able to read the version out
// of a layout the Go struct no longer describes, which only works while
// map_schema_version stays where it is.
func TestCfgSchemaVersionOffset(t *testing.T) {
	if got := unsafe.Offsetof(Config{}.MapSchemaVersion); got != cfgSchemaVersionOffset {
		t.Fatalf("map_schema_version is at offset %d, cfgSchemaVersionOffset says %d. "+
			"That constant is how `kapkan dataplane status` reads the version of a layout it cannot "+
			"decode; moving the field breaks skew detection, which is the one case where the tool has "+
			"to work against a stranger's data.", got, cfgSchemaVersionOffset)
	}
	if got := unsafe.Offsetof(Config{}.Generation); got != 0 {
		t.Fatalf("generation is at offset %d, want 0", got)
	}
}

/* ------------------------------------------------------------ the states */

// TestInspectNoPinPath is the "the feature never ran here" case, which is the
// state on every host with dataplane.enabled: false and after every clean
// shutdown under on_exit: detach.
func TestInspectNoPinPath(t *testing.T) {
	dir := filepath.Join(bpffsRoot(t), "kapkan-absent-"+t.Name())
	_ = os.Remove(dir)

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins on an absent directory returned an error: %v", err)
	}
	if ins.State != StateNoPinPath {
		t.Errorf("state = %s, want %s (reason: %s)", ins.State, StateNoPinPath, ins.Reason)
	}
	if ins.Program != nil || ins.Live != nil || len(ins.Maps) != 0 {
		t.Error("an absent pin directory reported program/maps/contents")
	}
	// The reason has to say what to check, not just what is missing.
	for _, want := range []string{"never run", "on_exit: detach", "dataplane.enabled"} {
		if !strings.Contains(ins.Reason, want) {
			t.Errorf("reason does not mention %q: %s", want, ins.Reason)
		}
	}
}

// TestInspectNotBPFFS is the single most likely misconfiguration: a pin_path
// that is an ordinary directory because nobody mounted bpffs (or because the
// systemd unit sets ProtectKernelTunables=yes, which mounts /sys/fs/bpf
// read-only).
func TestInspectNotBPFFS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kapkan")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins on a non-bpffs directory returned an error: %v", err)
	}
	if ins.State != StateNotBPFFS {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateNotBPFFS, ins.Reason)
	}
	if !strings.Contains(ins.Reason, "mount -t bpf") {
		t.Errorf("reason does not name the mount command: %s", ins.Reason)
	}

	// And the same for a path that does not exist on a filesystem that is not a
	// bpffs — "the directory is missing" would be true and useless here.
	ins, err = InspectPins(filepath.Join(dir, "deeper"))
	if err != nil {
		t.Fatal(err)
	}
	if ins.State != StateNotBPFFS {
		t.Errorf("absent path under a non-bpffs: state = %s, want %s", ins.State, StateNotBPFFS)
	}
}

// TestInspectNoProgram: the directory exists and is empty. Distinct from
// StateNoPinPath because the directory being there is exactly what makes an
// operator believe something is running.
func TestInspectNoProgram(t *testing.T) {
	dir := pinDir(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if ins.State != StateNoProgram {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateNoProgram, ins.Reason)
	}
	if !strings.Contains(ins.Reason, "RuntimeDirectory") {
		t.Errorf("reason does not explain who leaves an empty directory behind: %s", ins.Reason)
	}
}

// TestInspectEnforcing runs against a live, attached data plane — the case the
// command is normally used to confirm.
func TestInspectEnforcing(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins0")
	m := mustOpen(t, testOptions(t, dir, iface))

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if ins.State != StateEnforcing {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateEnforcing, ins.Reason)
	}
	if !ins.State.Enforcing() {
		t.Error("Enforcing() = false for StateEnforcing")
	}

	// The attachment, read back out of the link pin with no help from the
	// Manager: this is the daemon-stopped code path exercised while it runs.
	if len(ins.Attachments) != 1 {
		t.Fatalf("attachments = %+v, want exactly one", ins.Attachments)
	}
	a := ins.Attachments[0]
	if a.Interface != iface || !a.Live || a.Ifindex == 0 || a.Ifindex != a.CurrentIfindex {
		t.Errorf("attachment = %+v", a)
	}
	if a.Mode != config.XDPModeNative {
		t.Errorf("mode = %q; a veth supports native XDP, so auto should have picked it", a.Mode)
	}

	// Everything the CLI prints must actually be there.
	if ins.Program == nil || ins.Program.Tag == "" {
		t.Errorf("program = %+v, want a tag", ins.Program)
	}
	if ins.Kernel == "" {
		t.Error("no kernel version")
	}
	if got, want := len(ins.Maps), len(AllMaps); got != want {
		t.Errorf("described %d maps, the contract names %d", got, want)
	}
	if ins.MapBytes == 0 {
		t.Error("total map bytes = 0")
	}
	if ins.Live == nil {
		t.Fatal("no live state for an intact pin set")
	}
	if ins.Live.SchemaVersion != MapSchemaVersion {
		t.Errorf("schema = %d, want %d", ins.Live.SchemaVersion, MapSchemaVersion)
	}
	if ins.Live.PolicyStride == 0 || ins.Live.StaticStride == 0 {
		t.Errorf("strides = %d/%d, want the sizing from the limits",
			ins.Live.PolicyStride, ins.Live.StaticStride)
	}

	// The read-only view and the Manager's own Snapshot must agree, or one of
	// them is lying. This is the strongest single assertion in the file: the two
	// read the same maps by completely different routes.
	snap, err := m.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if ins.Live.Generation != snap.Generation {
		t.Errorf("generation: inspection %d, Stats %d", ins.Live.Generation, snap.Generation)
	}
	if ins.Live.StaticRules != snap.StaticCount {
		t.Errorf("static rules: inspection %d, Stats %d", ins.Live.StaticRules, snap.StaticCount)
	}
	if ins.Live.SchemaVersion != snap.SchemaVersion {
		t.Errorf("schema: inspection %d, Stats %d", ins.Live.SchemaVersion, snap.SchemaVersion)
	}
	if ins.MapBytes != snap.MapBytes {
		t.Errorf("map bytes: inspection %d, Stats %d", ins.MapBytes, snap.MapBytes)
	}
	insNames, snapNames := mapNamesOf(ins.Maps), make([]string, 0, len(snap.Maps))
	for _, s := range snap.Maps {
		snapNames = append(snapNames, s.Name)
	}
	sort.Strings(snapNames)
	if !reflect.DeepEqual(insNames, snapNames) {
		t.Errorf("map sets differ:\n  inspection %v\n  Stats      %v", insNames, snapNames)
	}

	// Array maps report no fill; keyed maps do.
	for _, m := range ins.Maps {
		switch m.Name {
		case MapCfg, MapStats, MapPolicies, MapStatics:
			if m.Entries >= 0 {
				t.Errorf("%s is an array and reported %d entries", m.Name, m.Entries)
			}
		case MapAllow4, MapRLSrc4, MapRuleStats:
			if m.Entries < 0 {
				t.Errorf("%s is keyed and reported no entry count", m.Name)
			}
		}
	}
}

// TestInspectDetachedWithTheDaemonStopped is the primary use case: kapkan is
// gone, on_exit: keep left the program pinned, and the operator wants to know
// whether the kernel is still filtering. Here it is not, because the manager was
// closed with detach-the-link semantics simulated by deleting the netdevice.
func TestInspectDetachedWithTheDaemonStopped(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins1")
	m, err := Open(testOptions(t, dir, iface))
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Open: %v", err)
	}
	// on_exit: keep — the pins and the attachment survive the process. This is
	// what an upgrade restart looks like from the kernel's side.
	if err := m.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Still enforcing with no userspace at all: that is the whole point of keep.
	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins after Close(keep): %v", err)
	}
	if ins.State != StateEnforcing {
		t.Fatalf("after Close(keep) state = %s, want still %s (reason: %s)",
			ins.State, StateEnforcing, ins.Reason)
	}
	if ins.Live == nil || ins.Live.SchemaVersion != MapSchemaVersion {
		t.Errorf("contents unreadable with the daemon stopped: %+v", ins.Live)
	}

	// Now take the netdevice away. The bpf_link stays pinned and reports
	// ifindex 0, which is the kernel's own way of saying the device is gone —
	// and the interface is no longer being filtered.
	delVeth(t, iface)
	ins, err = InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins after the netdevice went away: %v", err)
	}
	if ins.State != StateDetached {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateDetached, ins.Reason)
	}
	if len(ins.Attachments) != 1 || ins.Attachments[0].Live {
		t.Errorf("attachments = %+v, want one dead entry", ins.Attachments)
	}
	if ins.Attachments[0].Ifindex != 0 {
		t.Errorf("dead link reports ifindex %d, want 0", ins.Attachments[0].Ifindex)
	}
	// The maps are intact, so the policy is intact, and the message must say so
	// rather than implying everything is lost.
	if ins.Live == nil {
		t.Error("a detached data plane reported no contents; the maps are still there")
	}
	if !strings.Contains(ins.Reason, "intact") {
		t.Errorf("reason does not say the policy survived: %s", ins.Reason)
	}
}

// TestInspectTorn: a program pin with maps missing. A previous process died
// between pinning the program and pinning its maps.
func TestInspectTorn(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins2")
	m := mustOpen(t, testOptions(t, dir, iface))
	if err := m.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Tear it: unpin two maps but leave the program. The maps stay alive (the
	// program holds them), so this is exactly the shape of a half-pinned set.
	for _, name := range []string{MapStats, MapVictims6} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins on a torn set: %v", err)
	}
	if ins.State != StateTorn {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateTorn, ins.Reason)
	}
	want := []string{MapStats, MapVictims6}
	sort.Strings(want)
	got := append([]string(nil), ins.MissingMaps...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("missing maps = %v, want %v", got, want)
	}
	if !strings.Contains(ins.Reason, "Restart kapkan") {
		t.Errorf("reason does not name the fix: %s", ins.Reason)
	}
	// The attachment is still reported: a torn pin set does not stop the kernel
	// from filtering, and that is the first thing an operator needs to know.
	if len(ins.Attachments) != 1 || !ins.Attachments[0].Live {
		t.Errorf("attachments = %+v, want the live attachment reported anyway", ins.Attachments)
	}
}

// TestInspectSchemaSkew poisons map_schema_version, which is what a binary/pin
// version skew looks like from the reader's side.
//
// It writes through the MANAGER's own map handle, not through the inspection's:
// the inspection cannot write, which is the property under test everywhere else
// in this file.
func TestInspectSchemaSkew(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins3")
	m := mustOpen(t, testOptions(t, dir, iface))

	maps := m.Maps()
	cfg, err := ReadConfig(maps)
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	cfg.MapSchemaVersion = MapSchemaVersion + 41
	if err := maps.KapkanCfg.Put(uint32(0), &cfg); err != nil {
		t.Fatalf("poison kapkan_cfg: %v", err)
	}

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins on a skewed set: %v", err)
	}
	if ins.State != StateSchemaSkew {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateSchemaSkew, ins.Reason)
	}
	// The contents must NOT be reported: decoding them would mean reading every
	// field at an offset the pinned layout does not have.
	if ins.Live != nil {
		t.Error("a skewed pin set reported decoded contents")
	}
	// But the maps and the attachment must be, because their metadata is not
	// schema-dependent.
	if len(ins.Maps) != len(AllMaps) || len(ins.Attachments) != 1 {
		t.Errorf("skew hid the schema-independent facts: %d maps, %d attachments",
			len(ins.Maps), len(ins.Attachments))
	}
	if !strings.Contains(ins.Reason, "RESTART KAPKAN") {
		t.Errorf("reason does not name the fix: %s", ins.Reason)
	}
	// Both versions must appear: the poisoned one on the pin and the one this
	// binary speaks. Derived from MapSchemaVersion so the assertion does not
	// drift when the schema is bumped (as E2 did, 1 -> 2).
	poisoned := fmt.Sprintf("%d", MapSchemaVersion+41)
	binary := fmt.Sprintf("%d", MapSchemaVersion)
	if !strings.Contains(ins.Reason, poisoned) || !strings.Contains(ins.Reason, binary) {
		t.Errorf("reason does not name both versions (poisoned %s, binary %s): %s",
			poisoned, binary, ins.Reason)
	}
}

// TestInspectGenericModeIsReported: generic is a silent fallback that costs
// roughly an order of magnitude of capacity, so it has to survive into the
// report. "lo" has no ndo_bpf, so auto falls back there.
func TestInspectGenericModeIsReported(t *testing.T) {
	dir := pinDir(t)
	m := mustOpen(t, testOptions(t, dir, "lo"))
	_ = m

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if len(ins.Attachments) != 1 || ins.Attachments[0].Mode != config.XDPModeGeneric {
		t.Fatalf("attachments = %+v, want one generic-mode entry (lo has no native XDP)", ins.Attachments)
	}
	var found bool
	for _, w := range ins.Warnings {
		if strings.Contains(w, "GENERIC") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning about the generic path: %v", ins.Warnings)
	}
}

// TestInspectReportsUnknownPins: pin_path may be a shared bpffs directory, so
// entries this build does not recognise are reported and never touched.
func TestInspectReportsUnknownPins(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins4")
	m := mustOpen(t, testOptions(t, dir, iface))

	// A pin that is not ours: another tool's map, pinned next to kapkan's.
	other, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatalf("create a foreign map: %v", err)
	}
	defer func() { _ = other.Close() }()
	foreign := filepath.Join(dir, "somebody_elses_map")
	if err := other.Pin(foreign); err != nil {
		t.Fatalf("pin the foreign map: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(foreign) })
	_ = m

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if ins.State != StateEnforcing {
		t.Errorf("a foreign pin changed the verdict: %s", ins.State)
	}
	if !reflect.DeepEqual(ins.UnknownPins, []string{"somebody_elses_map"}) {
		t.Errorf("unknown pins = %v", ins.UnknownPins)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("the foreign pin was disturbed: %v", err)
	}
}

/* ------------------------------------------------ the read-only guarantee */

// TestInspectMapFDsAreReadOnlyToTheKernel is the runtime half of the read-only
// guarantee, and the one that does not depend on anybody's discipline: a map
// opened the way InspectPins opens it cannot be written THROUGH THAT FD, because
// BPF_F_RDONLY is on the file description and map_get_sys_perms() refuses.
func TestInspectMapFDsAreReadOnlyToTheKernel(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins5")
	_ = mustOpen(t, testOptions(t, dir, iface))

	ro, err := ebpf.LoadPinnedMap(mapPin(dir, MapCfg), readOnly())
	if err != nil {
		t.Fatalf("open %s read-only: %v", MapCfg, err)
	}
	defer func() { _ = ro.Close() }()

	// Reading works.
	var cfg Config
	if err := ro.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("read through a read-only fd: %v", err)
	}
	if cfg.MapSchemaVersion != MapSchemaVersion {
		t.Fatalf("read the wrong thing: schema %d", cfg.MapSchemaVersion)
	}
	// Writing does not, and the kernel is the one saying no.
	if err := ro.Put(uint32(0), &cfg); err == nil {
		t.Fatal("wrote through a read-only fd: BPF_F_RDONLY is not in force, and the whole " +
			"read-only guarantee of `kapkan dataplane status` rests on it")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Errorf("write through a read-only fd failed with %v, want a permission error", err)
	}
	if err := ro.Delete(uint32(0)); err == nil {
		t.Fatal("deleted through a read-only fd")
	}

	// And the counter map, which is PERCPU: a read-only percpu fd must still be
	// readable, because that is where the verdict counters come from.
	roStats, err := ebpf.LoadPinnedMap(mapPin(dir, MapStats), readOnly())
	if err != nil {
		t.Fatalf("open %s read-only: %v", MapStats, err)
	}
	defer func() { _ = roStats.Close() }()
	var per []Counter
	if err := roStats.Lookup(uint32(StatPassDefault), &per); err != nil {
		t.Fatalf("read a percpu counter through a read-only fd: %v", err)
	}
	if len(per) == 0 {
		t.Error("percpu read returned no per-CPU values")
	}
}

// TestInspectPinsChangesNothing is the observational half: fingerprint the whole
// pin directory, inspect it a hundred times, and require the fingerprint to be
// identical. It would catch a mutation this file's author did not think to
// forbid, including one inside a helper InspectPins calls.
func TestInspectPinsChangesNothing(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins6")
	m := mustOpen(t, testOptions(t, dir, iface))

	// Give it some state worth losing: a dynamic rule in the live generation and
	// a victim pointing at it, which is what a rebuild would destroy.
	if err := m.WithMaps(func(maps *Maps, gen uint32) error {
		rules, err := EncodeRules(RuleSpec{ID: 1, Action: ActionDrop, ExpiresAt: 1 << 62})
		if err != nil {
			return err
		}
		if err := PutPolicy(maps, gen, 0, rules); err != nil {
			return err
		}
		return AddVictim(maps, mustPrefix(t, "198.51.100.0/24"), 0)
	}); err != nil {
		t.Fatalf("install a dynamic rule: %v", err)
	}

	before := fingerprintPins(t, dir)
	for i := 0; i < 100; i++ {
		ins, err := InspectPins(dir)
		if err != nil {
			t.Fatalf("InspectPins #%d: %v", i, err)
		}
		if ins.State != StateEnforcing {
			t.Fatalf("InspectPins #%d changed the verdict to %s", i, ins.State)
		}
		if ins.Live.DynamicRules != 1 {
			t.Fatalf("InspectPins #%d saw %d dynamic rules, want 1", i, ins.Live.DynamicRules)
		}
	}
	after := fingerprintPins(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("InspectPins changed the pinned state.\n  before %v\n  after  %v", before, after)
	}

	// And the Manager is still usable afterwards — an inspection that stole the
	// XDP hook or closed something would show up here.
	if _, err := m.Stats(); err != nil {
		t.Errorf("the Manager broke after being inspected: %v", err)
	}
	h := m.Health()
	if h.Degraded {
		t.Errorf("the Manager went degraded after being inspected: %s", h.Summary())
	}
}

// fingerprintPins captures everything about the pin directory that an accidental
// write could change: the entry list, every map's shape, kapkan_cfg's bytes, the
// counter block, and the occupied policy blocks.
func fingerprintPins(t *testing.T, dir string) []string {
	t.Helper()
	var out []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read pin dir: %v", err)
	}
	for _, e := range entries {
		out = append(out, "entry:"+e.Name())
	}

	var objs Objects
	fields := mapFields(objs.MapSet())
	for _, name := range AllMaps {
		mp, err := ebpf.LoadPinnedMap(mapPin(dir, name), readOnly())
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer func() { _ = mp.Close() }()
		*fields[name] = mp
		info, err := mp.Info()
		if err != nil {
			t.Fatalf("info %s: %v", name, err)
		}
		bytes, _ := info.Memlock()
		out = append(out, fmt.Sprintf("map:%s type=%v max=%d key=%d val=%d bytes=%d",
			name, info.Type, info.MaxEntries, info.KeySize, info.ValueSize, bytes))
	}

	raw, err := objs.MapSet().KapkanCfg.LookupBytes(uint32(0))
	if err != nil {
		t.Fatalf("read kapkan_cfg: %v", err)
	}
	out = append(out, "cfg:"+fmt.Sprintf("%x", raw))

	counters, err := ReadStats(objs.MapSet())
	if err != nil {
		t.Fatalf("read stats: %v", err)
	}
	for s := Stat(0); s < StatMax; s++ {
		out = append(out, fmt.Sprintf("stat:%s=%d/%d", s, counters[s].Pkts, counters[s].Bytes))
	}

	cfg, err := ReadConfig(objs.MapSet())
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	stride := PolicyStride(objs.MapSet())
	for i := uint32(0); i < stride; i++ {
		var b PolicyBlock
		if err := objs.MapSet().KapkanPolicies.Lookup(cfg.Generation*stride+i, &b); err != nil {
			t.Fatalf("read policy block %d: %v", i, err)
		}
		if b.N_rules == 0 {
			continue
		}
		out = append(out, fmt.Sprintf("policy:%d n=%d %+v", i, b.N_rules, b.Rules[0]))
	}

	sort.Strings(out)
	return out
}

func mapNamesOf(maps []InspectedMap) []string {
	out := make([]string, 0, len(maps))
	for _, m := range maps {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// TestInspectAttachUnknownWhenALinkPinIsUnreadable is the regression test for
// the worst output this command could produce, and it was a real bug rather than
// a hypothesis.
//
// The kernel refuses BPF_OBJ_GET on a LINK unless the fd is opened O_RDWR (see
// readOnly()), so reading a link pin needs WRITE permission on its inode while
// reading a map pin needs only read. kapkan pins at 0600, so an unprivileged
// operator running `kapkan dataplane status` against a live, filtering data plane
// got every map and no attachment — and the state machine called that "detached"
// and printed NOT ENFORCING.
//
// This reproduces the same shape without needing a second uid: replace the link
// pin with a map pin, so opening it as a link fails. The state must be
// attach_unknown, never detached.
func TestInspectAttachUnknownWhenALinkPinIsUnreadable(t *testing.T) {
	dir := pinDir(t)
	iface := makeVeth(t, "kpkins7")
	m := mustOpen(t, testOptions(t, dir, iface))
	if err := m.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lp, ok := findLinkPin(dir, iface)
	if !ok {
		t.Fatal("no link pin to break")
	}
	if err := os.Remove(lp.path); err != nil {
		t.Fatal(err)
	}
	decoy, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatalf("create the decoy: %v", err)
	}
	defer func() { _ = decoy.Close() }()
	if err := decoy.Pin(lp.path); err != nil {
		t.Fatalf("pin the decoy at %s: %v", lp.path, err)
	}
	t.Cleanup(func() { _ = os.Remove(lp.path) })

	ins, err := InspectPins(dir)
	if err != nil {
		t.Fatalf("InspectPins: %v", err)
	}
	if ins.State == StateDetached {
		t.Fatal("an unreadable link pin was reported as `detached`, i.e. NOT ENFORCING, " +
			"about a data plane whose attachment state is simply unknown")
	}
	if ins.State != StateAttachUnknown {
		t.Fatalf("state = %s, want %s (reason: %s)", ins.State, StateAttachUnknown, ins.Reason)
	}
	if !strings.Contains(ins.Reason, "UNKNOWN") || !strings.Contains(ins.Reason, "not known to be false") {
		t.Errorf("reason does not distinguish unknown from false: %s", ins.Reason)
	}
	if len(ins.Attachments) != 1 || ins.Attachments[0].Error == "" {
		t.Errorf("attachments = %+v, want one entry carrying the read error", ins.Attachments)
	}
	// The maps still read, because their pins are fine.
	if ins.Live == nil {
		t.Error("the map contents were not reported; only the link pin was broken")
	}
}

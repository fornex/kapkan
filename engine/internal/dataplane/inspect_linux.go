//go:build linux

package dataplane

// The read-only reader. See inspect.go for why it exists.
//
// THE ONE NON-NEGOTIABLE PROPERTY OF THIS FILE: it never mutates anything. Not
// the pins, not the maps, not the attachments, not the filesystem. That is
// enforced three ways, deliberately overlapping, because "we were careful" is
// not an enforcement mechanism:
//
//  1. THE KERNEL. Every map is opened with ebpf.LoadPinOptions{ReadOnly: true},
//     which sets BPF_F_RDONLY on the file description. The kernel then refuses
//     BPF_MAP_UPDATE_ELEM and BPF_MAP_DELETE_ELEM through that fd with EPERM —
//     see map_get_sys_perms() in kernel/bpf/syscall.c. A bug in this file that
//     tried to write would fail, not succeed quietly.
//     TestInspectMapFDsAreReadOnlyToTheKernel proves it against a real kernel.
//
//  2. THE SOURCE. TestInspectIsStructurallyReadOnly greps this file for the
//     mutating vocabulary — Put, Delete, Pin, Unpin, os.Remove, os.Mkdir,
//     LoadAndAssign, NewCollection, AttachXDP — and fails if any appears. That
//     is what keeps a future edit from reaching for Manager.Open() because it
//     needed one more field.
//
//  3. THE OBSERVED STATE. TestInspectPinsChangesNothing fingerprints the whole
//     pin directory (entries, map info, kapkan_cfg, counters) around a hundred
//     InspectPins calls and fails on any difference.
//
// The functions in maps_linux.go that this file calls — ReadStats, ReadConfig —
// are pure Lookups, and they are reached through map handles that the kernel
// has already marked read-only, so (1) covers them too.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// readOnly is the only options value this file ever opens a pinned object with.
// It is a function rather than a package var so no caller can reach in and flip
// the field; the cost is one 16-byte allocation per open.
//
// What it buys differs by object, and the difference is worth stating precisely
// rather than claiming the strong version everywhere:
//
//   - MAPS get real, kernel-side enforcement. bpf_map_new_fd() takes the file
//     flags, so BPF_F_RDONLY lands on the file description and every subsequent
//     BPF_MAP_UPDATE_ELEM/DELETE_ELEM through that fd is refused with EPERM by
//     map_get_sys_perms(). This is the guarantee the whole command rests on.
//   - PROGRAMS get the narrowed inode access mode only: bpf_obj_do_get passes
//     ACC_MODE(flags) to inode_permission, but bpf_prog_new_fd takes no flags.
//     There is no update operation on a program fd, so there is nothing more to
//     take away.
//   - LINKS cannot be opened this way AT ALL, which is measured and not
//     theoretical: bpf_obj_do_get refuses a link whose file flags are anything
//     but O_RDWR, so BPF_OBJ_GET returns EINVAL and cilium/ebpf reports
//     "load pinned link: invalid argument". Link pins are therefore opened with
//     nil options — see inspectLinks, which is the one exception and says so.
//     The mutating link operation is BPF_LINK_UPDATE, which the source scan
//     forbids by name.
func readOnly() *ebpf.LoadPinOptions { return &ebpf.LoadPinOptions{ReadOnly: true} }

// inspectEntryBudget bounds the key walk used to count a hash/LRU/trie map's
// occupancy. Iteration costs one syscall per key present (not per max_entries),
// so an idle box pays almost nothing and a box with a million live token buckets
// pays about a second — which is exactly the box where an operator does not want
// their diagnostic to stall. Past the budget the count is reported as a floor.
const inspectEntryBudget = 100_000

// cfgSchemaVersionOffset is the byte offset of map_schema_version inside
// struct kapkan_config.
//
// It is a constant rather than an unsafe.Offsetof because the whole point of
// reading it is to survive a layout the Go struct no longer describes: on a
// schema skew, Lookup into a Config value fails outright on the value size, so
// the version has to come out of the raw bytes. The first two fields of
// kapkan_config are u32 generation and u32 map_schema_version, and their order
// is frozen for exactly this reason — a diagnostic must be able to read the
// version number of a layout it does not understand.
// TestCfgSchemaVersionOffset gates it against the generated struct.
const cfgSchemaVersionOffset = 4

// InspectPins reads an existing pinned data plane and reports what it finds,
// without touching it.
//
// It returns an error ONLY when the state could not be determined — permission
// denied, or an I/O failure that is not "absent". Every way for the data plane to
// be missing, detached, torn or skewed is an InspectState with a Reason, because
// those are answers, not failures, and a caller must be able to tell "there is no
// data plane here" from "I could not look".
func InspectPins(dir string) (Inspection, error) {
	ins := Inspection{PinPath: dir, BinarySchemaVersion: MapSchemaVersion}
	if _, _, raw, err := kernelVersion(); err == nil {
		ins.Kernel = raw
	}

	// 1. Does the directory exist, and is it a directory on a bpffs?
	//
	// The bpffs question is asked in both branches but phrased once: an absent
	// pin path on a mounted bpffs means "the feature never ran here", while an
	// absent pin path with no bpffs anywhere above it means the operator (or
	// their systemd unit) never mounted one, and no amount of restarting kapkan
	// will change that.
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if bpfErr := checkBPFFS(dir); bpfErr != nil {
			return notBPFFS(ins, bpfErr), nil
		}
		ins.State = StateNoPinPath
		ins.Reason = fmt.Sprintf("%s does not exist: the XDP data plane has never run on this host, "+
			"or it exited with on_exit: detach. If you expected it to be running, check that "+
			"dataplane.enabled is true and that the pin path below is the one in your config.", dir)
		return ins, nil
	case errors.Is(err, os.ErrPermission):
		return ins, permissionError(dir, err)
	case err != nil:
		return ins, fmt.Errorf("dataplane: stat pin directory %s: %w", dir, err)
	}
	if bpfErr := checkBPFFS(dir); bpfErr != nil {
		return notBPFFS(ins, bpfErr), nil
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		ins.State = StateNotBPFFS
		ins.Reason = fmt.Sprintf("%s is not a directory. dataplane.pin_path must name a directory "+
			"on a bpffs; remove whatever is at that path, or point pin_path somewhere else.", dir)
		return ins, nil
	}
	// A mode the daemon would refuse to start on. Read-only, so this is a
	// warning and not a refusal — but the operator is going to hit it the next
	// time they restart, and finding out now beats finding out then.
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		ins.Warnings = append(ins.Warnings, fmt.Sprintf(
			"%s is mode %#o: group or other can write it, so a local user could pre-create pins "+
				"for the daemon to adopt. The daemon REFUSES TO START in this state. Fix: chmod 0700 %s",
			dir, perm, dir))
	}

	// 2. What is in it?
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return ins, permissionError(dir, err)
		}
		return ins, fmt.Errorf("dataplane: read pin directory %s: %w", dir, err)
	}
	known := map[string]bool{progPinName: true}
	for _, n := range AllMaps {
		known[n] = true
	}
	var links []linkPinInfo
	present := map[string]bool{}
	for _, e := range entries {
		switch name := e.Name(); {
		case isLinkPin(name):
			if lp, ok := parseLinkPin(dir, name); ok {
				links = append(links, lp)
			} else {
				ins.UnknownPins = append(ins.UnknownPins, name)
			}
		case known[name]:
			present[name] = true
		default:
			ins.UnknownPins = append(ins.UnknownPins, name)
		}
	}
	sort.Strings(ins.UnknownPins)
	sort.Slice(links, func(i, j int) bool { return links[i].iface < links[j].iface })

	// Attachments are read before the maps, so that a torn or skewed pin set
	// still reports what the kernel is filtering with. That is the field an
	// operator needs first and the one least affected by anything else's state.
	ins.Attachments = inspectLinks(links)
	unreadableLinks := 0
	for _, a := range ins.Attachments {
		switch {
		case a.Error != "":
			unreadableLinks++
			hint := ""
			if a.Permission {
				// Measured, not guessed: bpf_obj_do_get refuses a LINK unless the
				// file flags are exactly O_RDWR, so opening a link pin needs write
				// permission on its inode where a map pin needs only read. kapkan
				// pins at 0600, so this is what every non-root reader sees.
				hint = ". Reading a link pin needs WRITE permission on it — the kernel refuses " +
					"BPF_OBJ_GET on a link unless the fd is opened O_RDWR — and kapkan's pins are " +
					"mode 0600. Re-run as the user the daemon runs as (usually: sudo kapkan dataplane status)"
			}
			ins.Warnings = append(ins.Warnings, fmt.Sprintf(
				"the link pin for %s could not be read (%s), so this interface's attachment state is "+
					"unknown%s", a.Interface, a.Error, hint))
		case !a.Live && a.Ifindex == 0:
			ins.Warnings = append(ins.Warnings, fmt.Sprintf(
				"%s has a pinned XDP attachment whose netdevice is gone, so it is NOT being filtered. "+
					"A running daemon re-attaches within its watch interval; a stopped one does not.",
				a.Interface))
		case !a.Live:
			ins.Warnings = append(ins.Warnings, fmt.Sprintf(
				"the pinned attachment for %s is on ifindex %d but %s is now ifindex %d — the NIC was "+
					"replaced or renamed and this attachment is filtering something else, or nothing",
				a.Interface, a.Ifindex, a.Interface, a.CurrentIfindex))
		case a.Mode == "generic":
			ins.Warnings = append(ins.Warnings, fmt.Sprintf(
				"%s is attached in GENERIC (skb) mode, not native: the program runs after the kernel has "+
					"allocated an skb, which costs roughly an order of magnitude of capacity. Either the "+
					"driver has no native XDP support or xdp_mode: generic is configured.", a.Interface))
		}
	}

	// 3. Is there a program?
	if !present[progPinName] {
		ins.State = StateNoProgram
		ins.Reason = fmt.Sprintf("%s exists but holds no program pin: nothing has ever been attached "+
			"through it. An empty pin directory is left behind by systemd's RuntimeDirectory=, by a "+
			"package postinstall, and by a clean shutdown under on_exit: detach — so this is the normal "+
			"state for a host where the data plane is off, not evidence that something crashed.", dir)
		return ins, nil
	}
	prog, err := ebpf.LoadPinnedProgram(progPin(dir), readOnly())
	if err != nil {
		if isPermission(err) {
			return ins, permissionError(progPin(dir), err)
		}
		return ins, fmt.Errorf("dataplane: open pinned program %s: %w", progPin(dir), err)
	}
	defer func() { _ = prog.Close() }()
	ins.Program = &PinnedProgram{Type: prog.Type().String()}
	if info, ierr := prog.Info(); ierr == nil {
		ins.Program.Name = info.Name
		ins.Program.Tag = info.Tag
		ins.Program.VerifiedInstructions, _ = info.VerifiedInstructions()
	}

	// 4. Is the map set complete?
	for _, name := range AllMaps {
		if !present[name] {
			ins.MissingMaps = append(ins.MissingMaps, name)
		}
	}
	if len(ins.MissingMaps) > 0 {
		ins.State = StateTorn
		ins.Reason = fmt.Sprintf("the pin set is TORN: a program is pinned but %d of its %d maps are "+
			"missing (%s). A previous process died between pinning the program and pinning its maps. "+
			"Restart kapkan — the manager tears a torn set down and rebuilds it. Dynamic rules from the "+
			"previous process are already gone; static policy comes from the config file and is not.",
			len(ins.MissingMaps), len(AllMaps), strings.Join(ins.MissingMaps, ", "))
		return ins, nil
	}

	// 5. Open every map read-only and describe it.
	var objs Objects
	if err := checkMapFields(objs.MapSet()); err != nil {
		return ins, err
	}
	fields := mapFields(objs.MapSet())
	opened := make([]*ebpf.Map, 0, len(AllMaps))
	defer func() {
		for _, m := range opened {
			_ = m.Close()
		}
	}()
	for _, name := range AllMaps {
		m, err := ebpf.LoadPinnedMap(mapPin(dir, name), readOnly())
		if err != nil {
			if isPermission(err) {
				return ins, permissionError(mapPin(dir, name), err)
			}
			return ins, fmt.Errorf("dataplane: open pinned map %s: %w", name, err)
		}
		opened = append(opened, m)
		*fields[name] = m
		desc := describeMap(name, m)
		ins.Maps = append(ins.Maps, desc)
		ins.MapBytes += desc.Bytes
	}
	sort.Slice(ins.Maps, func(i, j int) bool { return ins.Maps[i].Bytes > ins.Maps[j].Bytes })

	// 6. Is the pinned layout one this binary can decode?
	//
	// Read the version out of the RAW bytes. A skew is precisely the case where
	// the Go struct does not describe the map's value, so decoding into it would
	// either fail on the size or — worse, for a same-size change — succeed and
	// report every field from the wrong offset.
	schema, err := readSchemaVersion(objs.MapSet().KapkanCfg)
	if err != nil {
		if isPermission(err) {
			return ins, permissionError(mapPin(dir, MapCfg), err)
		}
		return ins, fmt.Errorf("dataplane: read pinned %s: %w", MapCfg, err)
	}
	if schema != MapSchemaVersion {
		ins.State = StateSchemaSkew
		ins.Reason = fmt.Sprintf("SCHEMA SKEW: the pinned maps are map_schema_version %d and this "+
			"binary speaks %d, so their contents cannot be decoded — every field after the change "+
			"would be read at the wrong offset. This is a binary/pin version skew, normally left by an "+
			"upgrade that has not restarted yet. RESTART KAPKAN: the manager refuses to adopt a skewed "+
			"pin set, tears it down and rebuilds it. Dynamic rules from the old process are lost in that "+
			"rebuild; static policy is not, it comes from the config file.", schema, MapSchemaVersion)
		return ins, nil
	}

	// 7. Contents.
	live, err := readLiveState(objs.MapSet(), schema)
	if err != nil {
		return ins, err
	}
	ins.Live = live
	if live.DryRun {
		ins.Warnings = append(ins.Warnings, "DRY-RUN is set in kapkan_cfg: the datapath is rewriting "+
			"every drop verdict into a pass, so nothing is actually being dropped. This is what the "+
			"kernel is doing, regardless of what the config file now says — set dry_run: false and "+
			"reload to arm it.")
	}
	if live.ExpiredDynamicRules > 0 && live.ExpiredDynamicRules == live.DynamicRules {
		ins.Warnings = append(ins.Warnings, fmt.Sprintf(
			"all %d dynamic rules in the live generation are past their in-kernel expiry, so the "+
				"datapath treats them as absent. That is the fail-safe for a dead userspace: rules age "+
				"out rather than leaving a customer blackholed. If kapkan is running, it should have "+
				"reaped them.", live.ExpiredDynamicRules))
	}

	// 8. The verdict.
	for _, a := range ins.Attachments {
		if a.Live {
			ins.State = StateEnforcing
			ins.Reason = "the program is attached and filtering."
			return ins, nil
		}
	}
	// Nothing is live. Before calling that "detached", check whether we were
	// actually able to LOOK: an unreadable link pin means the answer is unknown,
	// and reporting NOT ENFORCING about a box that is enforcing would be the
	// worst single output this command could produce.
	if unreadableLinks > 0 && unreadableLinks == len(ins.Attachments) {
		ins.State = StateAttachUnknown
		ins.Reason = fmt.Sprintf("the program and all %d maps read correctly, but NONE of the %d "+
			"pinned attachments could be read, so whether packets are being filtered is UNKNOWN — "+
			"not known to be false. See the warnings below for why; if they say permission denied, "+
			"re-run as the user the daemon runs as (usually root).", len(AllMaps), len(ins.Attachments))
		return ins, nil
	}

	ins.State = StateDetached
	switch len(ins.Attachments) {
	case 0:
		ins.Reason = fmt.Sprintf("the program and all %d maps are pinned and intact, but nothing is "+
			"attached: there is no link pin in %s, so no packet reaches the filter. Policy is preserved "+
			"and will take effect the moment something attaches. Start kapkan (systemctl start kapkan) "+
			"to attach it.", len(AllMaps), dir)
	default:
		ins.Reason = fmt.Sprintf("the program and all %d maps are pinned and intact, but not one of the "+
			"%d pinned attachments is bound to a live netdevice, so no packet reaches the filter. "+
			"Check that the configured interfaces exist (ip link), then restart kapkan.",
			len(AllMaps), len(ins.Attachments))
	}
	return ins, nil
}

// notBPFFS fills in the bpffs failure, reusing checkBPFFS's message — which
// already names the mount command and the systemd option that causes it.
func notBPFFS(ins Inspection, err error) Inspection {
	ins.State = StateNotBPFFS
	ins.Reason = strings.TrimPrefix(err.Error(), ErrPinPathUnsafe.Error()+": ")
	return ins
}

// isPermission recognises both spellings this path can produce: EACCES from the
// bpffs inode check (wrong uid) and EPERM from the kernel's bpf_capable() gate
// (no CAP_BPF with unprivileged_bpf_disabled set). syscall.Errno maps both onto
// os.ErrPermission, so one test covers them; they are named here because the two
// have different remedies and permissionError has to describe both.
func isPermission(err error) bool { return errors.Is(err, os.ErrPermission) }

// permissionError is the message an operator gets when they ran this as the
// wrong user. It names the three independent gates, because they have three
// different fixes and only one of them is about capabilities at all.
//
// The claim that no capability is needed for the map reads is measured, not
// inferred: on kernel 6.12 with unprivileged_bpf_disabled=0, uid 1000 with
// CapEff and CapBnd both 0x0 produced the complete report from a
// world-readable pin set. What that run could NOT read was the link pins, which
// is gate 3 and is a permission on the inode rather than a capability.
func permissionError(path string, err error) error {
	return fmt.Errorf("cannot read %s: %w\n\n"+
		"Reading pinned maps is far cheaper than creating them. There are three gates, and only\n"+
		"one of them is about capabilities:\n"+
		"  1. The pin directory is mode 0700, owned by the uid the daemon runs as (root in the\n"+
		"     shipped systemd unit). That is the usual answer: run `sudo kapkan dataplane status`.\n"+
		"  2. If kernel.unprivileged_bpf_disabled is non-zero — the default on Debian and Ubuntu —\n"+
		"     bpf(2) needs CAP_BPF even to open an existing pin. With it zero, reading the maps\n"+
		"     needs no capability at all.\n"+
		"     Grant it for one command with: setpriv --ambient-caps=+cap_bpf kapkan dataplane status\n"+
		"  3. Link pins need WRITE permission, not just read: the kernel refuses BPF_OBJ_GET on a\n"+
		"     bpf_link unless the fd is opened O_RDWR. So even a reader who can see every map\n"+
		"     cannot see the attachments unless it is the owning uid.\n"+
		"NEITHER CAP_NET_ADMIN NOR CAP_PERFMON is needed here — those are for loading and attaching\n"+
		"the program, not for reading its maps. See engine/deploy/dataplane-operations.md.",
		path, err)
}

// inspectLinks reads back each link pin: the mode from its name, the ifindex
// from the kernel, and whether the two still describe a live attachment.
func inspectLinks(pins []linkPinInfo) []Attachment {
	out := make([]Attachment, 0, len(pins))
	for _, lp := range pins {
		a := Attachment{Interface: lp.iface, Mode: lp.mode}
		if ifi, err := net.InterfaceByName(lp.iface); err == nil {
			a.CurrentIfindex = ifi.Index
		}
		// nil, not readOnly(): the kernel rejects BPF_OBJ_GET on a LINK with any
		// file flags other than O_RDWR, so asking for a read-only link fd fails
		// with EINVAL. See readOnly(). The link is only ever asked for its
		// Info(); nothing here can update it.
		l, err := link.LoadPinnedLink(lp.path, nil)
		if err != nil {
			a.Error, a.Permission = err.Error(), isPermission(err)
			out = append(out, a)
			continue
		}
		info, err := l.Info()
		_ = l.Close()
		if err != nil {
			a.Error, a.Permission = err.Error(), isPermission(err)
			out = append(out, a)
			continue
		}
		x := info.XDP()
		if x == nil {
			a.Error = fmt.Sprintf("pinned link is not an XDP link (type %v)", info.Type)
			out = append(out, a)
			continue
		}
		// ifindex 0 is the kernel's own answer for "the netdevice this link
		// pointed at is gone" — see adoptLink, which makes the same comparison
		// for the same reason.
		a.Ifindex = int(x.Ifindex)
		a.Live = a.Ifindex != 0 && a.Ifindex == a.CurrentIfindex
		out = append(out, a)
	}
	return out
}

// describeMap reports one map's shape, cost and occupancy.
func describeMap(name string, m *ebpf.Map) InspectedMap {
	out := InspectedMap{
		MapStatus: MapStatus{Name: name, Type: m.Type().String(), MaxEntries: m.MaxEntries()},
	}
	if info, err := m.Info(); err == nil {
		out.Type = info.Type.String()
		out.MaxEntries = info.MaxEntries
		out.Bytes, _ = info.Memlock()
	}
	out.Entries, out.Capped = countEntries(m)
	return out
}

// countEntries walks a map's keys.
//
// ARRAY maps are skipped: every slot of an array exists from the moment it is
// created, so a key count would just restate max_entries and imply an occupancy
// that does not exist. What is actually occupied in kapkan_statics and
// kapkan_policies is reported instead from kapkan_cfg and the policy blocks.
//
// For everything else the walk costs one syscall per key PRESENT, so an idle map
// is nearly free. Iterating an LRU that the datapath is concurrently evicting
// can miss or repeat keys — this is an occupancy estimate and is labelled as one.
func countEntries(m *ebpf.Map) (n int64, capped bool) {
	switch m.Type() {
	case ebpf.Array, ebpf.PerCPUArray, ebpf.ProgramArray:
		return -1, false
	}
	// prev is `any` and starts nil on purpose: NextKeyBytes tests its argument
	// against a nil INTERFACE to mean "start from the first key", and a typed
	// nil []byte would not be nil there — it would be marshalled as a key and
	// rejected on its length.
	var prev any
	for n < inspectEntryBudget {
		next, err := m.NextKeyBytes(prev)
		if err != nil || next == nil {
			return n, false
		}
		n++
		prev = next
	}
	return n, true
}

// readSchemaVersion pulls map_schema_version out of kapkan_cfg[0] as raw bytes.
// See cfgSchemaVersionOffset for why it does not decode the struct.
func readSchemaVersion(cfg *ebpf.Map) (uint32, error) {
	raw, err := cfg.LookupBytes(uint32(0))
	if err != nil {
		return 0, err
	}
	if len(raw) < cfgSchemaVersionOffset+4 {
		return 0, fmt.Errorf("kapkan_cfg[0] is %d bytes, too short to hold a schema version", len(raw))
	}
	return binary.LittleEndian.Uint32(raw[cfgSchemaVersionOffset:]), nil
}

// readLiveState decodes the map contents. Only called once the schema version
// has been confirmed to match, so the generated structs really do describe what
// is in the kernel.
func readLiveState(maps *Maps, schema uint32) (*LiveState, error) {
	cfg, err := ReadConfig(maps)
	if err != nil {
		return nil, fmt.Errorf("dataplane: read pinned kapkan_cfg: %w", err)
	}
	live := &LiveState{
		SchemaVersion: schema,
		Generation:    cfg.Generation,
		PolicyStride:  cfg.PolicyStride,
		StaticStride:  cfg.StaticStride,
		StaticRules:   cfg.StaticCount,
		DryRun:        cfg.DryRun != 0,
		DropMalformed: cfg.DropMalformed != 0,
	}
	if cfg.Generation >= Generations {
		return nil, fmt.Errorf("dataplane: pinned generation is %d, out of range [0,%d) — "+
			"the pin set is corrupt; restart kapkan to rebuild it", cfg.Generation, Generations)
	}

	blocks, err := readPolicyBlocks(maps, cfg.Generation)
	if err != nil {
		return nil, err
	}
	live.PolicyBlocks, live.DynamicRules, live.ExpiredDynamicRules = dynamicRuleTotals(blocks, bootTimeNs())

	counters, err := ReadStats(maps)
	if err != nil {
		return nil, fmt.Errorf("dataplane: read pinned kapkan_stats: %w", err)
	}
	live.Terminal, live.Observation, live.TerminalTotal = splitCounters(counters)
	return live, nil
}

// readPolicyBlocks reads one generation's half of kapkan_policies. Bounded by
// the same budget as the key walk: the stride is the operator's dynamic-rule
// limit divided by the block size, which is 512 blocks at the default limit but
// is theirs to raise.
func readPolicyBlocks(maps *Maps, gen uint32) ([]PolicyBlock, error) {
	stride := PolicyStride(maps)
	n := stride
	if n > inspectEntryBudget {
		n = inspectEntryBudget
	}
	out := make([]PolicyBlock, 0, n)
	for i := uint32(0); i < n; i++ {
		var b PolicyBlock
		if err := maps.KapkanPolicies.Lookup(gen*stride+i, &b); err != nil {
			return nil, fmt.Errorf("dataplane: read policy block %d in generation %d: %w", i, gen, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// bootTimeNs reads CLOCK_BOOTTIME in nanoseconds from /proc/uptime, which is the
// clock the datapath's rule deadlines are on (bpf_ktime_get_boot_ns). Returns 0
// when it cannot be read, and dynamicRuleTotals then declines to call anything
// expired rather than guessing.
//
// /proc rather than clock_gettime(2) because reading two integers is not worth
// promoting golang.org/x/sys from an indirect dependency to a direct one — the
// same trade probe_linux.go makes for the kernel version.
func bootTimeNs() uint64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f, _, ok := strings.Cut(strings.TrimSpace(string(b)), " ")
	if !ok {
		f = strings.TrimSpace(string(b))
	}
	secs, err := strconv.ParseFloat(f, 64)
	if err != nil || secs <= 0 {
		return 0
	}
	return uint64(secs * 1e9)
}

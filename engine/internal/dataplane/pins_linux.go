//go:build linux

package dataplane

// Pins: how policy survives a restart, and the rules for when it may not.
//
// The pin directory holds one file per map, one for the program, and one per
// attached interface for the bpf_link. A new process that finds them can ADOPT
// them, which is what makes an in-place upgrade non-disruptive: the XDP program
// stays attached across the exec, the token buckets keep their state, and the
// mitigator's dynamic rules — which have in-kernel expiry and are the only
// thing here that cannot be rebuilt from the config file — are still in force.
//
// ADOPTION IS THE DANGEROUS PART, in two different ways, and each has a rule.
//
//  1. A new binary whose object changed a struct must NOT attach to the old
//     maps. The maps would still be there, still the right names, still the
//     right sizes — and every field after the changed one would be read at the
//     wrong offset. That is not a crash, it is a rule matching traffic nobody
//     named. So adoption requires all four of: the schema version stamped in
//     kapkan_cfg, every map's type/key/value/flags/max_entries, the program's
//     kernel tag, and the full map set being present. Any mismatch tears the
//     pins down and rebuilds, LOUDLY — dynamic rules are lost, which is a real
//     cost, and the operator is told so rather than left to notice.
//
//  2. A pin directory a local user can write is a pin directory in which they
//     can pre-create a program and maps for this process to adopt — an XDP
//     program of their choosing, running on the operator's uplink, installed by
//     a privileged process that believed it was resuming its own work. So the
//     directory's ownership and mode are checked BEFORE anything in it is
//     opened, and a bad mode is a refusal to start, not a fall-back to
//     rebuilding. Falling back would be worse than useless: it would mean an
//     unprivileged user could force a rebuild (and drop every active dynamic
//     rule) at will.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/kapkan-io/kapkan/internal/config"
)

// Pin file names inside the pin directory. The map pins use the map names,
// which are contract (see contract.go), so renaming a map orphans an operator's
// pins across an upgrade — deliberately, because a renamed map is exactly the
// kind of change that must not be adopted.
const (
	progPinName = "prog"
	// linkPinPrefix starts every link pin. The rest of the name is the ATTACH
	// MODE and then the interface name: "link_native_eth0".
	//
	// The mode is in the file name because there is nowhere else to put it. An
	// adopted bpf_link reports only its ifindex — bpf_link_info for XDP carries
	// nothing else, and BPF_PROG_QUERY does not return the attach flags — so a
	// process that re-adopts a pinned attachment cannot otherwise tell whether
	// it is on the driver path or the ten-times-slower skb one. Losing that
	// across a restart would mean an operator on xdp_mode: auto has no way to
	// find out which they got. bpffs holds no metadata but the name, so the name
	// carries it.
	//
	// Parsing is unambiguous because the mode set is closed and the mode comes
	// FIRST: an interface name may contain '_' but "link_native_" and
	// "link_generic_" are fixed prefixes.
	linkPinPrefix = "link_"
)

func progPin(dir string) string      { return filepath.Join(dir, progPinName) }
func mapPin(dir, name string) string { return filepath.Join(dir, name) }

// linkPin is the pin path for an attachment, encoding the mode in force.
func linkPin(dir, iface, mode string) string {
	return filepath.Join(dir, linkPinPrefix+mode+"_"+iface)
}

func isLinkPin(base string) bool { return strings.HasPrefix(base, linkPinPrefix) }

// linkPinInfo is one parsed link pin.
type linkPinInfo struct {
	path  string
	iface string
	mode  string
}

// parseLinkPin splits a link pin's base name into mode and interface. An
// unparseable name (an older layout, or a hand-created file) is reported as not
// ok, and the caller treats it as an entry it does not recognise rather than
// guessing what it attaches.
func parseLinkPin(dir, base string) (linkPinInfo, bool) {
	rest, ok := strings.CutPrefix(base, linkPinPrefix)
	if !ok {
		return linkPinInfo{}, false
	}
	for _, mode := range []string{config.XDPModeNative, config.XDPModeGeneric} {
		if iface, ok := strings.CutPrefix(rest, mode+"_"); ok && iface != "" {
			return linkPinInfo{path: filepath.Join(dir, base), iface: iface, mode: mode}, true
		}
	}
	return linkPinInfo{}, false
}

// removePin unlinks a pin.
func removePin(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dataplane: unpin %s: %w", path, err)
	}
	return nil
}

// discardLinkPin detaches a pinned XDP attachment and waits for the kernel to
// actually let go of the hook.
//
// UNLINKING THE PIN IS NOT ENOUGH, and the difference is a real bug rather than
// a theoretical one. Dropping a bpf_link's last reference by evicting its bpffs
// inode is DEFERRED — the kernel schedules the release — while dropping it by
// closing the last file descriptor is synchronous (bpf_link_release calls
// bpf_link_put_direct). So `os.Remove(pin)` immediately followed by a fresh
// attach races the release and fails with EEXIST: "another XDP program already
// owns this interface's hook", the previous one, on its way out.
//
// Measured: that is exactly what a restart with a changed xdp_mode hit before
// this function existed. Opening the pin, unpinning it, and closing the fd
// leaves the hook free the moment this returns.
func discardLinkPin(path string) error {
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		// Not a link, or already gone: fall back to a plain unlink so a stray
		// file cannot wedge startup.
		return removePin(path)
	}
	if uerr := l.Unpin(); uerr != nil {
		_ = l.Close()
		return fmt.Errorf("dataplane: unpin %s: %w", path, uerr)
	}
	// The last reference. Closing it is what synchronously detaches.
	if cerr := l.Close(); cerr != nil {
		return fmt.Errorf("dataplane: detach %s: %w", path, cerr)
	}
	return nil
}

// mapFields is the single place that pairs a contract map name with its field
// in the generated Maps struct. Everything that iterates the map set — pinning,
// adoption, per-map statistics — goes through it, so a map added in C is a
// compile error here (the generated struct grows a field) and a length
// assertion catches the reverse.
func mapFields(m *Maps) map[string]**ebpf.Map {
	return map[string]**ebpf.Map{
		MapAllow4:    &m.KapkanAllow4,
		MapAllow6:    &m.KapkanAllow6,
		MapProtect4:  &m.KapkanProtect4,
		MapProtect6:  &m.KapkanProtect6,
		MapVictims4:  &m.KapkanVictims4,
		MapVictims6:  &m.KapkanVictims6,
		MapPolicies:  &m.KapkanPolicies,
		MapStatics:   &m.KapkanStatics,
		MapRLSrc4:    &m.KapkanRlSrc4,
		MapRLSrc6:    &m.KapkanRlSrc6,
		MapProfiles:  &m.KapkanProfiles,
		MapCfg:       &m.KapkanCfg,
		MapStats:     &m.KapkanStats,
		MapRuleStats: &m.KapkanRuleStats,
		MapFPEvents:  &m.KapkanFpEvents,
		MapFPSampler: &m.KapkanFpSampler,
	}
}

// checkMapFields asserts mapFields covers exactly AllMaps. Called on every
// path that uses it, because the cost is a map length comparison and the
// failure it prevents is a nil *ebpf.Map dereference on the first rule install.
func checkMapFields(m *Maps) error {
	f := mapFields(m)
	if len(f) != len(AllMaps) {
		return fmt.Errorf("dataplane: mapFields covers %d maps, AllMaps names %d", len(f), len(AllMaps))
	}
	for _, n := range AllMaps {
		if _, ok := f[n]; !ok {
			return fmt.Errorf("dataplane: mapFields does not cover map %q", n)
		}
	}
	return nil
}

/* ========================================================================= */
/* Pin directory safety                                                       */
/* ========================================================================= */

// ensurePinDir creates the pin directory if needed and verifies it is safe to
// adopt from. It returns whether the directory already existed, which is the
// only signal the caller needs to decide whether to look for pins at all.
//
// Mode 0700: the pins are this process's private state. Nothing else has a
// reason to read them, and something else being able to WRITE them is the
// attack in the file header.
func ensurePinDir(dir string) (existed bool, err error) {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := checkParentDirSafe(dir); err != nil {
			return false, err
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return false, fmt.Errorf("dataplane: create pin directory %s: %w", dir, err)
		}
		return false, nil
	case err != nil:
		return false, fmt.Errorf("dataplane: stat pin directory %s: %w", dir, err)
	}
	// Lstat, not Stat: a symlink here would let the mode check apply to one
	// directory and the pins be created in another. bpffs does not support
	// symlinks, so this can only fire when pin_path is not where it claims.
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: %s is a symlink", ErrPinPathUnsafe, dir)
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%w: %s is not a directory", ErrPinPathUnsafe, dir)
	}
	if err := checkDirOwnerMode(dir, fi); err != nil {
		return false, err
	}
	if err := checkParentDirSafe(dir); err != nil {
		return false, err
	}
	return true, nil
}

// checkDirOwnerMode refuses a directory this process does not own, or that
// group or other can write.
func checkDirOwnerMode(dir string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read ownership of %s", ErrPinPathUnsafe, dir)
	}
	euid := os.Geteuid()
	if int(st.Uid) != euid {
		return fmt.Errorf("%w: %s is owned by uid %d, this process is uid %d. "+
			"A pin directory owned by someone else is a directory whose contents this process "+
			"would adopt — an XDP program of their choosing on your uplink. "+
			"Fix with: chown %d %s", ErrPinPathUnsafe, dir, st.Uid, euid, euid, dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is mode %#o; group/other write lets a local user pre-create "+
			"pins that this process would adopt. Fix with: chmod 0700 %s",
			ErrPinPathUnsafe, dir, perm, dir)
	}
	return nil
}

// checkParentDirSafe refuses a parent directory that group or other can write
// without the sticky bit, because a writable parent means the pin directory can
// be renamed out of the way and replaced wholesale — which defeats the check on
// the directory itself.
//
// The sticky-bit exemption is what makes a /tmp-like layout tolerable: with it
// set, only the owner can rename or remove an entry.
func checkParentDirSafe(dir string) error {
	parent := parentDir(dir)
	fi, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("%w: stat parent %s: %v", ErrPinPathUnsafe, parent, err)
	}
	perm := fi.Mode().Perm()
	if perm&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%w: parent directory %s is mode %#o with no sticky bit, so %s can be "+
			"replaced by a local user. Fix with: chmod 0755 %s", ErrPinPathUnsafe, parent, perm, dir, parent)
	}
	return nil
}

/* ========================================================================= */
/* Adoption                                                                   */
/* ========================================================================= */

// adoptResult is the outcome of looking at an existing pin set.
type adoptResult struct {
	// Objs is the adopted program and map set, nil when adoption was refused.
	Objs *Objects
	// Reason explains a refusal, in a form that goes straight into a log line.
	// Empty on success.
	Reason string
	// ColdStart distinguishes "there was no data plane here" from "there was
	// one and we rejected it". Both end in a rebuild, but only the second one
	// costs an operator anything.
	//
	// The distinction is load-bearing because the pin DIRECTORY existing tells
	// you nothing: systemd's RuntimeDirectory=, a postinstall script, or an
	// operator following our own "mount bpffs" error message all leave an empty
	// directory behind, and so does every clean shutdown under on_exit: detach.
	// Treating those as a rejection fires the rules-were-lost alarm on a
	// perfectly healthy first boot, which teaches operators to ignore the one
	// signal that is supposed to mean they really did lose their rules.
	ColdStart bool
}

// tryAdopt inspects the pins in dir and adopts them if — and only if — they are
// the same program over the same map layouts at the same sizes.
//
// spec must already have been through applySizing, so the max_entries compared
// below are the ones THIS process would create. That makes a limits change
// (which config declares restart-required) an adoption refusal rather than a
// silent continuation with the old sizes: the operator restarted precisely
// because they wanted the new number.
//
// wantTag is the kernel tag of the program this binary loads, obtained by
// actually loading it — see probeLoad. Comparing against a tag computed from
// the ELF would not work: kapkan_xdp.c uses global (non-inlined) functions, so
// the CollectionSpec's instruction stream for kapkan_xdp_filter does not yet
// include its callees, while the kernel's tag covers the linked whole.
//
// A returned error means something went wrong that the caller should not paper
// over. A non-empty Reason with no error means "these pins are not ours,
// rebuild".
func tryAdopt(dir string, spec *ebpf.CollectionSpec, wantTag string) (adoptResult, error) {
	// Every pin must be present. A partial set is a previous process that died
	// mid-setup; there is nothing to preserve and nothing to trust.
	// The program pin is the one that decides which kind of "not adoptable"
	// this is. Without it nothing was ever attached through these pins, so no
	// packet was ever filtered and no dynamic rule can have been lost — that is
	// a cold start, however many stray map pins are lying around next to it.
	if _, err := os.Stat(progPin(dir)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return adoptResult{ColdStart: true, Reason: "no program pin: nothing was attached here before"}, nil
		}
		return adoptResult{}, fmt.Errorf("dataplane: stat pin %s: %w", progPinName, err)
	}
	// A program pin with maps missing under it is different: something did run
	// here and its pin set is torn. Still nothing to preserve, but worth saying
	// out loud, because it means a previous process died between pinning the
	// program and pinning its maps.
	for _, name := range AllMaps {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return adoptResult{Reason: fmt.Sprintf("pin %q is missing (incomplete pin set)", name)}, nil
			}
			return adoptResult{}, fmt.Errorf("dataplane: stat pin %s: %w", name, err)
		}
	}

	prog, err := ebpf.LoadPinnedProgram(progPin(dir), nil)
	if err != nil {
		return adoptResult{}, fmt.Errorf("dataplane: open pinned program %s: %w", progPin(dir), err)
	}
	// From here on every early return must close what has been opened, or a
	// rebuild leaks the old program's fd and the old maps' 235 MiB stay charged
	// to this process for its whole life.
	opened := []interface{ Close() error }{prog}
	closeAll := func() {
		for _, c := range opened {
			_ = c.Close()
		}
	}

	if prog.Type() != ebpf.XDP {
		closeAll()
		return adoptResult{Reason: fmt.Sprintf("pinned program is type %v, not XDP", prog.Type())}, nil
	}
	info, err := prog.Info()
	if err != nil {
		closeAll()
		return adoptResult{}, fmt.Errorf("dataplane: pinned program info: %w", err)
	}
	if info.Tag != wantTag {
		closeAll()
		return adoptResult{Reason: fmt.Sprintf(
			"pinned program tag %s is not this binary's %s (the BPF object changed)",
			info.Tag, wantTag)}, nil
	}

	var objs Objects
	if err := checkMapFields(objs.MapSet()); err != nil {
		closeAll()
		return adoptResult{}, err
	}
	fields := mapFields(objs.MapSet())
	for _, name := range AllMaps {
		m, err := ebpf.LoadPinnedMap(mapPin(dir, name), nil)
		if err != nil {
			closeAll()
			return adoptResult{}, fmt.Errorf("dataplane: open pinned map %s: %w", name, err)
		}
		opened = append(opened, m)
		// The full structural comparison: type, key size, value size,
		// max_entries and flags. Value size is what catches a struct that grew
		// a field; max_entries is what catches changed limits.
		if err := spec.Maps[name].Compatible(m); err != nil {
			closeAll()
			return adoptResult{Reason: fmt.Sprintf("pinned map %q is incompatible: %v", name, err)}, nil
		}
		*fields[name] = m
	}
	objs.KapkanXdpFilter = prog

	// The schema version the previous process stamped. Redundant with the map
	// comparisons for any change that moves a field's offset or a struct's
	// size, and NOT redundant for one that does not — swapping two same-sized
	// fields, or renumbering an enum. Which is exactly why it exists.
	cfg, err := ReadConfig(objs.MapSet())
	if err != nil {
		closeAll()
		return adoptResult{}, fmt.Errorf("dataplane: read pinned kapkan_cfg: %w", err)
	}
	if cfg.MapSchemaVersion != MapSchemaVersion {
		closeAll()
		return adoptResult{Reason: fmt.Sprintf("pinned map_schema_version is %d, this binary speaks %d",
			cfg.MapSchemaVersion, MapSchemaVersion)}, nil
	}
	if cfg.Generation >= Generations {
		closeAll()
		return adoptResult{Reason: fmt.Sprintf("pinned generation is %d, out of range [0,%d)",
			cfg.Generation, Generations)}, nil
	}

	return adoptResult{Objs: &objs}, nil
}

// pinObjects pins a freshly created program and map set, all or nothing. A
// half-pinned set is worse than none: the next start would find a partial set,
// refuse to adopt it, and have to tear it down anyway — but in between, an
// operator looking at the directory would see something that appears to be
// live state.
func pinObjects(dir string, objs *Objects) error {
	if err := checkMapFields(objs.MapSet()); err != nil {
		return err
	}
	var done []string
	rollback := func() {
		for _, p := range done {
			_ = os.Remove(p)
		}
	}
	for _, name := range AllMaps {
		p := mapPin(dir, name)
		if err := (*mapFields(objs.MapSet())[name]).Pin(p); err != nil {
			rollback()
			return fmt.Errorf("dataplane: pin map %s at %s: %w", name, p, err)
		}
		done = append(done, p)
	}
	if err := objs.KapkanXdpFilter.Pin(progPin(dir)); err != nil {
		rollback()
		return fmt.Errorf("dataplane: pin program at %s: %w", progPin(dir), err)
	}
	return nil
}

// removeOurPins unlinks every pin this package knows the name of, links first.
//
// Unlinking a bpffs pin drops a reference; for a link that means the XDP
// program is detached, which is why the order matters — detach before the
// program and maps lose their last pin, so the datapath never runs against maps
// that are being freed.
//
// It deliberately does NOT empty the directory. pin_path could be a shared
// bpffs directory (an operator can set it to anything absolute), and removing
// entries this package did not create would be removing another tool's state.
// Only names derived from the contract are touched, and unknown entries are
// returned so the caller can say something about them.
func removeOurPins(dir string) (removed, unknown []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("dataplane: read pin directory %s: %w", dir, err)
	}
	known := map[string]bool{progPinName: true}
	for _, n := range AllMaps {
		known[n] = true
	}

	// Two passes: links first (detach), then program and maps.
	var second []string
	for _, e := range entries {
		switch {
		case isLinkPin(e.Name()):
			p := filepath.Join(dir, e.Name())
			// discardLinkPin, not os.Remove: the hook has to be free before the
			// caller attaches its replacement. See that function.
			if rmErr := discardLinkPin(p); rmErr != nil {
				return removed, unknown, rmErr
			}
			removed = append(removed, e.Name())
		case known[e.Name()]:
			second = append(second, e.Name())
		default:
			unknown = append(unknown, e.Name())
		}
	}
	for _, name := range second {
		p := filepath.Join(dir, name)
		if rmErr := os.Remove(p); rmErr != nil {
			return removed, unknown, fmt.Errorf("dataplane: unpin %s: %w", p, rmErr)
		}
		removed = append(removed, name)
	}
	sort.Strings(removed)
	sort.Strings(unknown)
	return removed, unknown, nil
}

// pinnedLinkPins lists every parseable link pin in dir, sorted by interface.
func pinnedLinkPins(dir string) ([]linkPinInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("dataplane: read pin directory %s: %w", dir, err)
	}
	var out []linkPinInfo
	for _, e := range entries {
		if lp, ok := parseLinkPin(dir, e.Name()); ok {
			out = append(out, lp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].iface < out[j].iface })
	return out, nil
}

// findLinkPin returns the pinned link for one interface, in whichever mode it
// was attached.
func findLinkPin(dir, iface string) (linkPinInfo, bool) {
	for _, mode := range []string{config.XDPModeNative, config.XDPModeGeneric} {
		p := linkPin(dir, iface, mode)
		if _, err := os.Stat(p); err == nil {
			return linkPinInfo{path: p, iface: iface, mode: mode}, true
		}
	}
	return linkPinInfo{}, false
}

// adoptLink re-opens the pinned link for iface and reports whether it is still
// bound to the interface that now carries that name.
//
// The ifindex comparison is the point. A veth that flapped, or a NIC that was
// renamed, comes back with a NEW ifindex, and a pinned link still pointing at
// the old one is defunct — the kernel reports ifindex 0 once the netdevice is
// unregistered. Adopting such a link would leave the interface unfiltered while
// every status field said "attached".
func adoptLink(dir, iface, mode string, wantIndex int) (link.Link, int, error) {
	l, err := link.LoadPinnedLink(linkPin(dir, iface, mode), nil)
	if err != nil {
		return nil, 0, err
	}
	info, err := l.Info()
	if err != nil {
		_ = l.Close()
		return nil, 0, fmt.Errorf("link info: %w", err)
	}
	x := info.XDP()
	if x == nil {
		_ = l.Close()
		return nil, 0, fmt.Errorf("pinned link is not an XDP link (type %v)", info.Type)
	}
	got := int(x.Ifindex)
	if got != wantIndex {
		_ = l.Close()
		// ifindex 0 is the kernel's own way of saying "the netdevice this link
		// pointed at is gone".
		return nil, got, fmt.Errorf("pinned link is on ifindex %d, %s is now ifindex %d", got, iface, wantIndex)
	}
	return l, got, nil
}

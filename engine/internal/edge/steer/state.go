package steer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DirName is the steering directory under state_dir.
	DirName = "steering"
	// NewNodeReason is the new-node drain's reason: DrainFor reports the
	// new_node marker with it, whatever the file says, and Step reports a
	// drain carrying it as ReasonNewNode.
	NewNodeReason = "new_node"

	stateFileName   = "state.json"
	drainFileName   = "drain"
	newNodeFileName = "new_node"
	stateVersion    = 1

	// storeMaxFile bounds what is read of any file here. Ours are a few
	// hundred bytes; the bound is for a drain file someone filled by mistake,
	// which then reads as a drain that does not parse — never as a process
	// out of memory.
	storeMaxFile = 1 << 20
)

// Store is state_dir/steering. Each file in it has one author:
//
//   - state.json — every target's Saved record — is the daemon's (Birth,
//     Save);
//   - new_node — the node's pending first entry (D7), a drain of every
//     target — is created by Birth alone and removed by LiftNewNode alone:
//     the daemon's once the first entry is done, or the operator's
//     `-s undrain -force` (E7.2);
//   - drain (the node) and drain.<addr> (one VIP) are the operator's: E7.2's
//     `-s drain|undrain`, or an `rm` or a `touch` by hand — a drain file's
//     existence is the command, its content only explains it. SetDrain names
//     a VIP's file by the address's canonical text; a hand may spell the
//     address any way netip reads it (2001:DB8::10, 2001:0db8::10,
//     ::ffff:192.0.2.10), and every spelling drains that VIP. The daemon
//     writes none of these.
//
// So the operator's drain and the first entry never stand in for each other:
// draining a new node and undraining it leaves it drained, new_node, and the
// first entry lifting leaves the operator's drain in force.
//
// Every write is atomic: a temporary file in the directory, fsync, rename,
// directory fsync — so a crash leaves the old file or the new one, and a
// reader on the tick never sees half of one. The directory is created on the
// first write, 0755 whatever the writer's umask, and the files are 0644:
// nothing here is secret, and an unprivileged `-steer` (E7.2) must see every
// drain.
type Store struct {
	// Dir is state_dir/steering, absolute.
	Dir string
}

// NewStore is the Store under a node's state_dir.
func NewStore(stateDir string) Store { return Store{Dir: filepath.Join(stateDir, DirName)} }

// StateFile is state.json.
type StateFile struct {
	Version int `json:"version"`
	// Born is when Birth wrote the file: when this node, or this state_dir,
	// first testified.
	Born time.Time `json:"born"`
	// Targets are the automata's records by target key (NodeKey, or a VIP's
	// canonical text). A key no target has any more is dropped at the next
	// Save by whoever builds the file; it is harmless meanwhile.
	Targets map[string]Saved `json:"targets,omitempty"`
}

// Load reads state.json. A missing file — a new node, or a wiped state_dir —
// is reported as born, with an empty StateFile: the caller runs Birth. Any
// other failure, an unparseable file included, is an error and NOT a birth:
// a corrupt file must not drain a node, let alone a fleet; the caller goes on
// with an empty StateFile. Every Until is capped at now+maxHold — the
// configured HoldDownMax, so a lowered max takes effect at the next start —
// and every negative Level is 0.
//
// maxHold is taken as DefaultHoldDownMax when zero or negative and as
// HoldDownCeiling when above it, as Config takes a hold-down: a caller that
// passes an unchecked value still cannot keep a node out longer than any
// configuration could. The file's version is written, not enforced: what a
// newer binary left is read for the fields this one knows, and the worst a
// misread can do is move a hold-down within that cap.
func (s Store) Load(now time.Time, maxHold time.Duration) (f StateFile, born bool, err error) {
	path := filepath.Join(s.Dir, stateFileName)
	raw, err := storeReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return StateFile{}, true, nil
	}
	if err != nil {
		return StateFile{}, false, fmt.Errorf("steer: %w", err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return StateFile{}, false, fmt.Errorf("steer: %s: %w", path, err)
	}
	if maxHold <= 0 {
		maxHold = DefaultHoldDownMax
	}
	limit := now.Add(min(maxHold, HoldDownCeiling))
	for key, saved := range f.Targets {
		if saved.Until.After(limit) {
			saved.Until = limit
		}
		saved.Level = max(saved.Level, 0)
		f.Targets[key] = saved
	}
	return f, false, nil
}

// Save writes state.json atomically, with Version set.
func (s Store) Save(f StateFile) error {
	f.Version = stateVersion
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("steer: %w", err)
	}
	return storeWrite(filepath.Join(s.Dir, stateFileName), append(raw, '\n'))
}

// Birth arms the new-node drain (D7) — writes the new_node marker — and a
// fresh state.json, in that order: a crash between the two leaves state.json
// missing, and the next start is born again. A marker already there, left by
// a Birth that crashed before its state.json, is kept with its Since. The
// operator's drain files are neither read nor written: one there before the
// first start stays in force beside the first entry, and lifting it leaves
// the node drained, new_node. Until Birth has succeeded, the caller holds the
// node drained with NewNodeReason in memory (E7.2): DrainFor reads the files
// only.
func (s Store) Birth(now time.Time) (StateFile, error) {
	path := filepath.Join(s.Dir, newNodeFileName)
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := storeWriteDrain(path, Drain{Reason: NewNodeReason, Since: now}); err != nil {
			return StateFile{}, err
		}
	case err != nil:
		return StateFile{}, fmt.Errorf("steer: %w", err)
	}
	f := StateFile{Version: stateVersion, Born: now}
	if err := s.Save(f); err != nil {
		return StateFile{}, err
	}
	return f, nil
}

// Drain is a drain file's content, JSON. An empty or unparseable file is
// still a drain — its existence is the operator's command — with Reason ""
// (reported as ReasonDrained) and Since the file's modification time.
type Drain struct {
	// Reason is free text: the operator's -reason, or NewNodeReason.
	Reason string `json:"reason,omitempty"`
	// Since is when the drain was set.
	Since time.Time `json:"since"`
}

// DrainFor reports the drain in force for a target key, and whether one is:
// TriYes when a drain file applies, TriNo when every file that could is known
// to be absent, TriUnknown otherwise. E7.2 makes TriYes alone
// Triggers.Drained, and anything but TriUnknown Gates.DrainKnown: an unknown
// drain takes no address out and lets none in, so it never lifts a drain that
// stands. The files, by precedence:
//
//   - drain, the operator's drain of the node, for every key;
//   - drain.<addr>, the operator's drain of one VIP, for that VIP's key: the
//     canonical name first, then every other spelling of the address;
//   - new_node, the first entry, for every key, with Reason NewNodeReason.
//
// The first one known to exist wins: a drain that is known is a drain,
// whatever else could not be looked at. err is for the report
// (Report.DrainErr) and decides nothing: it says which file could not be
// looked at or parsed, that the key is no target's, and which other names in
// the directory begin "drain" but spell no address — a hand-made drain that
// drains nothing, named on every target's report rather than ignored.
func (s Store) DrainFor(key string) (Drain, Tri, error) {
	names, listErr := storeDrainNames(s.Dir)
	reads := []drainRead{storeReadDrain(filepath.Join(s.Dir, drainFileName))}
	var notes []error
	if key == NodeKey {
		notes = append(notes, listErr) // the node has one drain file: what the listing missed is no drain of its
	} else {
		reads = append(reads, s.vipDrainReads(key, names, listErr)...)
	}
	first := storeReadDrain(filepath.Join(s.Dir, newNodeFileName))
	if first.tri == TriYes {
		first.d.Reason = NewNodeReason
	}
	reads = append(reads, first)
	for _, name := range names {
		if _, ok := drainNameKey(name); !ok {
			notes = append(notes, fmt.Errorf("steer: %s spells no address, so it drains nothing", filepath.Join(s.Dir, name)))
		}
	}
	d, tri, err := drainFold(reads)
	return d, tri, errors.Join(append([]error{err}, notes...)...)
}

// FirstEntryPending reports whether the node's first entry is still pending —
// the new_node marker exists — whatever drain of the operator's lies over it:
// E7.2 runs the Joiner while it is TriYes, and its `-s undrain` refuses
// without -force while it is anything but TriNo.
func (s Store) FirstEntryPending() (Tri, error) {
	_, tri, err := storeLstat(filepath.Join(s.Dir, newNodeFileName))
	return tri, err
}

// SetDrain writes the operator's drain file for key (NodeKey for the
// node-wide one) atomically, replacing any there: E7.2's
// `-s drain [-vip] [-reason]`. It never touches the first entry.
func (s Store) SetDrain(key string, d Drain) error {
	path, err := s.drainPath(key)
	if err != nil {
		return err
	}
	return storeWriteDrain(path, d)
}

// Undrain lifts the operator's drain of key: it removes drain (NodeKey), or
// every file that drains the VIP — drain.<key> and any other spelling of its
// address. An absent one is not an error. It never touches the first entry:
// the new-node drain lifts by LiftNewNode alone, so a plain undrain of a new
// node leaves it drained, new_node — E7.2's `-s undrain` then reports the
// first entry's progress and lifts it only with -force.
func (s Store) Undrain(key string) error {
	path, err := s.drainPath(key)
	if err != nil {
		return err
	}
	paths, errs := []string{path}, []error(nil)
	if key != NodeKey {
		names, err := storeDrainNames(s.Dir)
		errs = append(errs, err) // a spelling the listing missed may still drain
		for _, name := range drainAliases(key, names) {
			paths = append(paths, filepath.Join(s.Dir, name))
		}
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("steer: %w", err))
		}
	}
	// A removal lost to a crash would bring the drain back.
	storeSyncDir(s.Dir)
	return errors.Join(errs...)
}

// LiftNewNode removes the new_node marker and reports whether it did: the
// first entry lifting itself once FirstEntry.Done, or the operator's
// `-s undrain -force` (E7.2), the bootstrap of a new VIP's first node. It
// never touches the operator's drain files: a drain the operator set over a
// new node, or before its first start, stays in force until the operator
// lifts it. It refuses while state.json is missing: the next start would be
// born again and arm the drain anew, so a lift then would not hold.
func (s Store) LiftNewNode() (lifted bool, err error) {
	if _, err := os.Lstat(filepath.Join(s.Dir, stateFileName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, errors.New("steer: state.json is missing, so the node is not born yet; the new-node drain stays")
		}
		return false, fmt.Errorf("steer: %w", err)
	}
	if err := os.Remove(filepath.Join(s.Dir, newNodeFileName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("steer: %w", err)
	}
	storeSyncDir(s.Dir)
	return true, nil
}

// drainPath is the operator's drain file for key under the name SetDrain
// writes: "drain" for NodeKey, "drain.<key>" for a VIP's key — exactly what
// VIPTarget makes of an address: its canonical text, unmapped, without a
// zone. Anything else is refused, so the API keeps one file per address, and
// a key never names a path outside Dir nor another file in it: a zone is free
// text, and "fe80::1%../../x" would climb out.
func (s Store) drainPath(key string) (string, error) {
	if key == NodeKey {
		return filepath.Join(s.Dir, drainFileName), nil
	}
	addr, err := netip.ParseAddr(key)
	if err != nil || addr.Zone() != "" || VIPTarget(addr).Key != key {
		return "", fmt.Errorf("steer: drain key %q is neither %q nor a VIP's key (its address in canonical form, unmapped, without a zone)", key, NodeKey)
	}
	return filepath.Join(s.Dir, drainFileName+"."+key), nil
}

// vipDrainReads reads the operator's drain files of a VIP's key: drain.<key>,
// then each other name that spells the same address. A key that is no VIP's,
// or a directory that could not be listed, leaves the drain unknown.
func (s Store) vipDrainReads(key string, names []string, listErr error) []drainRead {
	path, err := s.drainPath(key)
	if err != nil {
		return []drainRead{{tri: TriUnknown, err: err}}
	}
	reads := []drainRead{storeReadDrain(path)}
	if listErr != nil {
		reads = append(reads, drainRead{tri: TriUnknown, err: listErr})
	}
	for _, name := range drainAliases(key, names) {
		reads = append(reads, storeReadDrain(filepath.Join(s.Dir, name)))
	}
	return reads
}

// drainAliases are the names that spell key's address other than
// drain.<key> itself.
func drainAliases(key string, names []string) []string {
	var aliases []string
	for _, name := range names {
		if k, ok := drainNameKey(name); ok && k == key && name != drainFileName+"."+key {
			aliases = append(aliases, name)
		}
	}
	return aliases
}

// drainNameKey is the key of the VIP a drain.<text> name drains: VIPTarget's,
// for the address text spells in any form netip reads. ok is false for any
// other name: it spells no address.
func drainNameKey(name string) (key string, ok bool) {
	text, found := strings.CutPrefix(name, drainFileName+".")
	if !found {
		return "", false
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return "", false
	}
	return VIPTarget(addr).Key, true
}

// drainRead is what one drain file says: whether it exists, its content, and
// why either could not be told — for the report.
type drainRead struct {
	d   Drain
	tri Tri
	err error
}

// drainFold is DrainFor's answer from its files' reads, in precedence order:
// the first TriYes wins, whatever could not be looked at before or after it;
// TriNo needs every read TriNo; anything else — a zero drainRead included —
// is TriUnknown. Every error goes to the report.
func drainFold(reads []drainRead) (Drain, Tri, error) {
	var d Drain
	tri, errs := TriNo, make([]error, 0, len(reads))
	for _, r := range reads {
		errs = append(errs, r.err)
		switch {
		case tri == TriYes:
		case r.tri == TriYes:
			d, tri = r.d, TriYes
		case r.tri != TriNo:
			tri = TriUnknown
		}
	}
	return d, tri, errors.Join(errs...)
}

// storeReadDrain reads one drain file. Its existence is the drain and its
// content only explains it, so an empty file — a `touch` — or one that cannot
// be read or parsed (a directory, a symlink to nothing) still drains, dated
// by its modification time, with the error beside it for the report. A file
// whose existence cannot be established is TriUnknown.
func storeReadDrain(path string) drainRead {
	fi, tri, err := storeLstat(path)
	if tri != TriYes {
		return drainRead{tri: tri, err: err}
	}
	var d Drain
	raw, err := storeReadFile(path)
	switch {
	case err != nil:
		err = fmt.Errorf("steer: %w", err)
	case len(bytes.TrimSpace(raw)) == 0:
		// A `touch`: a drain with nothing to say about itself.
	default:
		if perr := json.Unmarshal(raw, &d); perr != nil {
			d, err = Drain{}, fmt.Errorf("steer: %s: %w", path, perr)
		}
	}
	if d.Since.IsZero() {
		d.Since = fi.ModTime()
	}
	return drainRead{d: d, tri: TriYes, err: err}
}

// storeLstat reports whether path exists, not following a final symlink:
// TriNo only for fs.ErrNotExist, TriUnknown with the error for any other
// failure.
func storeLstat(path string) (fs.FileInfo, Tri, error) {
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		return fi, TriYes, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, TriNo, nil
	}
	return nil, TriUnknown, fmt.Errorf("steer: %w", err)
}

// storeDrainNames lists the names in dir that begin "drain", the node's own
// drain file aside: the drain files of single VIPs, under any spelling, and
// mistakes (drain.192.0.2.010, drain_192.0.2.10, drain~). A dir that does not
// exist lists none. On an error it returns what was listed before it.
func storeDrainNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	var names []string
	for _, e := range entries {
		if name := e.Name(); strings.HasPrefix(name, drainFileName) && name != drainFileName {
			names = append(names, name)
		}
	}
	if err != nil {
		return names, fmt.Errorf("steer: %w", err)
	}
	return names, nil
}

// storeReadFile reads at most storeMaxFile bytes of path; a longer file comes
// back cut, and fails to parse.
func storeReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	return io.ReadAll(io.LimitReader(f, storeMaxFile))
}

// storeWriteDrain writes a drain file atomically.
func storeWriteDrain(path string, d Drain) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("steer: %w", err)
	}
	return storeWrite(path, append(raw, '\n'))
}

// storeWrite replaces path with data atomically. The temporary file is
// uniquely named, because the daemon and an operator's command may write
// into the directory at the same moment and must never share one; it is
// synced before the rename and the directory after it, so a crash leaves the
// old file or the new one, never an empty one in its place.
func storeWrite(path string, data []byte) error {
	dir, name := filepath.Split(path)
	dir = filepath.Clean(dir) // Split leaves a trailing separator: storeMkdir needs the name
	if err := storeMkdir(dir); err != nil {
		return fmt.Errorf("steer: %w", err)
	}
	f, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("steer: %w", err)
	}
	if err := storeFill(f, data); err != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("steer: write %s: %w", path, err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("steer: %w", err)
	}
	storeSyncDir(dir)
	return nil
}

// storeMkdir creates dir, the steering directory, 0755 whatever the writer's
// umask, as storeFill makes the files 0644: the first writer may be an
// operator's `sudo kapkan edge -s drain` under a hardened umask (027, 077),
// and a directory left 0750 or 0700 would hide every drain from a `-steer`
// running as the speaker's own user (E7.2), which would then answer announce
// for a drained node. A directory already there keeps its mode, and state_dir
// above it is systemd's (StateDirectoryMode).
func storeMkdir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	err := os.Mkdir(dir, 0o755)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.Chmod(dir, 0o755) // mkdir applied the umask; chmod does not
}

// storeFill writes data into a fresh temporary file, opens it to every reader
// (CreateTemp makes it 0600; an operator's tools read these files, and none
// is secret), syncs it and closes it.
func storeFill(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// storeSyncDir makes a rename or a removal durable. Best-effort, as in
// internal/edge/apply: some filesystems refuse fsync on a directory, and the
// file itself was synced already.
func storeSyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

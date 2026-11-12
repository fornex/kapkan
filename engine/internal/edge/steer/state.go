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
	"time"
)

const (
	// DirName is the steering directory under state_dir.
	DirName = "steering"
	// NewNodeReason is the drain reason Birth writes and LiftNewNode looks for;
	// a drain carrying it is reported as ReasonNewNode.
	NewNodeReason = "new_node"

	stateFileName = "state.json"
	drainFileName = "drain"
	stateVersion  = 1

	// storeMaxFile bounds what is read of any file here. Ours are a few
	// hundred bytes; the bound is for a drain file someone filled by mistake,
	// which then reads as a drain that does not parse — never as a process
	// out of memory.
	storeMaxFile = 1 << 20
)

// Store is state_dir/steering. Two writers share it, and never a file:
//
//   - state.json — every target's Saved record — is written by the daemon
//     alone (Birth, Save);
//   - drain (the node) and drain.<key> (one VIP) are written by the operator:
//     E7.2's `-s drain|undrain`, or an `rm` or a `touch` by hand — a drain
//     file's existence is the command, its content only explains it. The
//     daemon writes one in exactly two places: Birth arms the new-node
//     drain, LiftNewNode lifts it.
//
// Every write is atomic: a temporary file in the directory, fsync, rename,
// directory fsync — so a crash leaves the old file or the new one, and a
// reader on the tick never sees half of one. The directory is created on the
// first write (0755; the files are 0644 — nothing here is secret).
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

// Birth arms the new-node drain (D7) and writes a fresh state.json, in that
// order: a crash between the two leaves state.json missing, and the next start
// is born again. A node-wide drain file already there is kept as it is — an
// operator's drain is never weakened into one that lifts by itself. Until
// Birth has succeeded, the caller holds the node drained with NewNodeReason
// in memory (E7.2): DrainFor reads drain files only.
//
// An operator's drain written between Birth's look and its write is replaced
// by the new-node one. That window is one system call wide, at a node's first
// start; closing it would take a lock the operator's `touch` cannot share.
func (s Store) Birth(now time.Time) (StateFile, error) {
	_, err := os.Lstat(filepath.Join(s.Dir, drainFileName))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := s.SetDrain(NodeKey, Drain{Reason: NewNodeReason, Since: now}); err != nil {
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

// DrainFor reports the drain in force for a target key: the node-wide file
// first, then drain.<key> (the node target has only the node-wide one). ok is
// whether one exists — Triggers.Drained. err is for the report only: beside
// ok=true it says the content could not be parsed; beside ok=false it says
// existence could not be established (anything but fs.ErrNotExist), which is
// unknown, and unknown is not a drain.
//
// A node-wide file that cannot be looked at does not hide a VIP's own drain
// file that can: a drain that is known is a drain.
func (s Store) DrainFor(key string) (d Drain, ok bool, err error) {
	d, ok, nodeErr := storeReadDrain(filepath.Join(s.Dir, drainFileName))
	if ok || key == NodeKey {
		return d, ok, nodeErr
	}
	path, err := s.drainPath(key)
	if err != nil {
		return Drain{}, false, errors.Join(nodeErr, err)
	}
	if d, ok, err = storeReadDrain(path); ok {
		return d, true, err
	}
	return Drain{}, false, errors.Join(nodeErr, err)
}

// SetDrain writes the drain file for key (NodeKey for the node-wide one)
// atomically, replacing any there: E7.2's `-s drain [-vip] [-reason]`.
func (s Store) SetDrain(key string, d Drain) error {
	path, err := s.drainPath(key)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("steer: %w", err)
	}
	return storeWrite(path, append(raw, '\n'))
}

// Undrain removes the drain file for key; an absent one is not an error. It
// does not look at the reason: refusing to lift a new-node drain without
// -force is the command's business (E7.2).
func (s Store) Undrain(key string) error {
	path, err := s.drainPath(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("steer: %w", err)
	}
	// A removal lost to a crash would bring the drain back.
	storeSyncDir(s.Dir)
	return nil
}

// LiftNewNode removes the node-wide drain file if, and only if, it still
// carries NewNodeReason, and reports whether it did — the new-node drain
// lifting itself once FirstEntry.Done. An operator's drain written over it
// meanwhile stays. It refuses while state.json is missing: lifting before
// Birth succeeded would let the next start be born again with nothing to
// show.
//
// A file that cannot be read or parsed is not known to be the new-node drain,
// so it stays. The check and the removal are two system calls, and an
// operator's drain written between them is removed with the new-node one: a
// race one read wide, against a command the operator can repeat — not worth a
// lock their `touch` could not take.
func (s Store) LiftNewNode() (lifted bool, err error) {
	if _, err := os.Lstat(filepath.Join(s.Dir, stateFileName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, errors.New("steer: state.json is missing, so the node is not born yet; the new-node drain stays")
		}
		return false, fmt.Errorf("steer: %w", err)
	}
	path := filepath.Join(s.Dir, drainFileName)
	raw, err := storeReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("steer: %w", err)
	}
	var d Drain
	if json.Unmarshal(raw, &d) != nil || d.Reason != NewNodeReason {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("steer: %w", err)
	}
	storeSyncDir(s.Dir)
	return true, nil
}

// drainPath is the drain file for key: "drain" for NodeKey, "drain.<key>" for
// a VIP's canonical text. Anything else is refused, so a key never names a
// path outside Dir.
func (s Store) drainPath(key string) (string, error) {
	if key == NodeKey {
		return filepath.Join(s.Dir, drainFileName), nil
	}
	addr, err := netip.ParseAddr(key)
	if err != nil || addr.String() != key {
		return "", fmt.Errorf("steer: drain key %q is neither %q nor an address in canonical form", key, NodeKey)
	}
	return filepath.Join(s.Dir, drainFileName+"."+key), nil
}

// storeReadDrain reads one drain file. Its existence is the drain and its
// content only explains it, so an empty file — a `touch` — or one that cannot
// be read or parsed still drains, dated by its modification time, with the
// error beside it for the report. A file whose existence cannot be
// established is unknown, and unknown is not a drain.
func storeReadDrain(path string) (Drain, bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Drain{}, false, nil
	}
	if err != nil {
		return Drain{}, false, fmt.Errorf("steer: %w", err)
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
	return d, true, err
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

// storeWrite replaces path with data atomically. The temporary file is
// uniquely named, because the daemon and an operator's command may write
// into the directory at the same moment and must never share one; it is
// synced before the rename and the directory after it, so a crash leaves the
// old file or the new one, never an empty one in its place.
func storeWrite(path string, data []byte) error {
	dir, name := filepath.Split(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
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

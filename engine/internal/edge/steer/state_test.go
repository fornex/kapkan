package steer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// storeT0 is the store tests' clock: a plain UTC wall time, which JSON
// carries exactly.
var storeT0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

const storeVIP = "192.0.2.10"

// storeNew is a Store under a fresh state_dir; its steering directory does
// not exist yet, as on a new node.
func storeNew(t *testing.T) Store {
	t.Helper()
	return NewStore(t.TempDir())
}

// storeRaw puts raw bytes at name in the store's directory, as an editor, a
// `touch` or a crash would leave them, and dates the file mtime.
func storeRaw(t *testing.T, s Store, name, raw string, mtime time.Time) {
	t.Helper()
	path := filepath.Join(s.Dir, name)
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// storeTemporaries lists what writes left behind in the store's directory.
func storeTemporaries(t *testing.T, s Store) []string {
	t.Helper()
	var left []string
	for _, name := range storeNames(t, s) {
		if strings.HasSuffix(name, ".tmp") {
			left = append(left, name)
		}
	}
	return left
}

// storeNames lists the store's directory.
func storeNames(t *testing.T, s Store) []string {
	t.Helper()
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// storeTree is every path under root, relative: each file with its content,
// each directory as "/" — what any write or removal under root changes. A
// root that does not exist is an empty tree.
func storeTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		switch {
		case path == root && errors.Is(err, fs.ErrNotExist):
			return filepath.SkipAll
		case err != nil:
			return err
		case path == root:
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if e.IsDir() {
			tree[rel] = "/"
			return nil
		}
		raw, err := os.ReadFile(path)
		tree[rel] = string(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// storeModes checks the permission bits of the paths under dir ("." for dir
// itself).
func storeModes(t *testing.T, dir string, want map[string]fs.FileMode) {
	t.Helper()
	for name, mode := range want {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := fi.Mode().Perm(); got != mode {
			t.Errorf("%s is %#o, want %#o: the operator's tools, and an unprivileged -steer, read it", name, got, mode)
		}
	}
}

func storeMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func storeJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	storeMust(t, err)
	return string(b)
}

// storeInputs is one tick's Inputs as E7.2 wires the store into them: the
// drain files' answer for key is the Drained trigger (TriYes alone) and the
// drain gate (anything but TriUnknown); every other gate is open, probe is
// the probe's class, and DrainFor's error is the report's.
func storeInputs(s Store, key string, probe Class) Inputs {
	d, tri, err := s.DrainFor(key)
	g := autoOpen
	g.DrainKnown = tri != TriUnknown
	in := Inputs{Triggers: Triggers{Drained: tri == TriYes}, Drain: d, Probe: probe, Gates: g}
	if err != nil {
		in.Report.DrainErr = err.Error()
	}
	return in
}

// TestStoreBornOnlyWithoutStateJSON: a node is born — drained, new_node —
// when state.json is missing, and in no other case. A file that is present
// and unreadable, empty or corrupt is an error, never a birth: a disk problem
// on every node must not drain the fleet.
func TestStoreBornOnlyWithoutStateJSON(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, s Store)
		born    bool
		err     bool
	}{
		{"a fresh state_dir", func(*testing.T, Store) {}, true, false},
		{"an empty steering directory", func(t *testing.T, s Store) { storeMust(t, os.MkdirAll(s.Dir, 0o755)) }, true, false},
		{"only a VIP's drain", func(t *testing.T, s Store) {
			storeMust(t, s.SetDrain(storeVIP, Drain{Reason: "maintenance", Since: storeT0}))
		}, true, false},
		{"only the operator's node drain", func(t *testing.T, s Store) {
			storeMust(t, s.SetDrain(NodeKey, Drain{Reason: "maintenance", Since: storeT0}))
		}, true, false},
		{"only the first entry: a Birth that crashed", func(t *testing.T, s Store) {
			storeRaw(t, s, newNodeFileName, storeJSON(t, Drain{Reason: NewNodeReason, Since: storeT0}), storeT0)
		}, true, false},
		{"a state.json with nothing in it", func(t *testing.T, s Store) { storeRaw(t, s, "state.json", "{}\n", storeT0) }, false, false},
		{"a state.json from a newer binary", func(t *testing.T, s Store) {
			storeRaw(t, s, "state.json", `{"version":9,"born":"2026-01-01T00:00:00Z","shape":"new"}`, storeT0)
		}, false, false},
		{"an empty state.json", func(t *testing.T, s Store) { storeRaw(t, s, "state.json", "", storeT0) }, false, true},
		{"a cut state.json", func(t *testing.T, s Store) { storeRaw(t, s, "state.json", `{"version":1,"targets":{"node":`, storeT0) }, false, true},
		{"a corrupt state.json", func(t *testing.T, s Store) { storeRaw(t, s, "state.json", "\x00\x00\x00", storeT0) }, false, true},
		{"a state.json that is a directory", func(t *testing.T, s Store) {
			storeMust(t, os.MkdirAll(filepath.Join(s.Dir, "state.json"), 0o755))
		}, false, true},
		{"a steering path that is a file", func(t *testing.T, s Store) {
			storeMust(t, os.WriteFile(s.Dir, []byte("not a directory"), 0o644))
		}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			tc.prepare(t, s)
			f, born, err := s.Load(storeT0, DefaultHoldDownMax)
			if born != tc.born || (err != nil) != tc.err {
				t.Fatalf("Load = (%+v, born %v, %v), want born %v, error %v", f, born, err, tc.born, tc.err)
			}
			if (born || err != nil) && !reflect.DeepEqual(f, StateFile{}) {
				t.Fatalf("Load = %+v beside born %v, %v: want an empty StateFile", f, born, err)
			}
		})
	}
}

// TestStoreBirthArmsTheNewNodeDrain: Birth writes the new_node marker — a
// drain of every target, VIPs included — and state.json, 0644 in a 0755
// directory, and writes no file of the operator's; the next Load is no birth.
func TestStoreBirthArmsTheNewNodeDrain(t *testing.T) {
	s := storeNew(t)
	f, err := s.Birth(storeT0)
	if err != nil || f.Version != stateVersion || !f.Born.Equal(storeT0) || len(f.Targets) != 0 {
		t.Fatalf("Birth = (%+v, %v), want version %d, born %v", f, err, stateVersion, storeT0)
	}
	for _, key := range []string{NodeKey, storeVIP, "2001:db8::10"} {
		d, tri, err := s.DrainFor(key)
		if tri != TriYes || err != nil || d.Reason != NewNodeReason || !d.Since.Equal(storeT0) {
			t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want the new-node drain since %v", key, d, tri, err, storeT0)
		}
	}
	if pending, err := s.FirstEntryPending(); pending != TriYes || err != nil {
		t.Fatalf("FirstEntryPending after Birth = (%v, %v), want yes", pending, err)
	}
	g, born, err := s.Load(storeT0.Add(time.Hour), DefaultHoldDownMax)
	if born || err != nil || !g.Born.Equal(storeT0) || g.Version != stateVersion {
		t.Fatalf("Load after Birth = (%+v, born %v, %v), want the born record", g, born, err)
	}
	if names := storeNames(t, s); !reflect.DeepEqual(names, []string{newNodeFileName, stateFileName}) {
		t.Fatalf("Birth wrote %v, want only %s and %s: the drain files are the operator's", names, newNodeFileName, stateFileName)
	}
	storeModes(t, s.Dir, map[string]fs.FileMode{".": 0o755, newNodeFileName: 0o644, stateFileName: 0o644})
}

// TestStoreOperatorDrainAndFirstEntryStandApart: the operator's drain and the
// first entry are two files, so neither stands in for the other. A node its
// operator drained before its first start, or over its pending first entry,
// reports the operator's drain; a plain undrain then leaves it drained,
// new_node — the first-entry gate holds against any streak of ok probes —
// until LiftNewNode, which leaves it undrained.
func TestStoreOperatorDrainAndFirstEntryStandApart(t *testing.T) {
	cfg := DefaultConfig()
	maint := Drain{Reason: "fleet maintenance", Since: storeT0.Add(-time.Hour)}
	for _, before := range []bool{true, false} {
		name := "drained over the first entry"
		if before {
			name = "drained before the first start"
		}
		t.Run(name, func(t *testing.T) {
			s := storeNew(t)
			if before {
				storeMust(t, s.SetDrain(NodeKey, maint))
				if _, born, err := s.Load(storeT0, cfg.HoldDownMax); !born || err != nil {
					t.Fatalf("a drained new node: Load = (born %v, %v), want born", born, err)
				}
			}
			_, err := s.Birth(storeT0)
			storeMust(t, err)
			if !before {
				storeMust(t, s.SetDrain(NodeKey, maint))
			}
			for _, key := range []string{NodeKey, storeVIP} {
				if d, tri, err := s.DrainFor(key); tri != TriYes || err != nil || d.Reason != maint.Reason || !d.Since.Equal(maint.Since) {
					t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want the operator's %+v", key, d, tri, err, maint)
				}
			}
			if pending, err := s.FirstEntryPending(); pending != TriYes || err != nil {
				t.Fatalf("FirstEntryPending under the operator's drain = (%v, %v), want yes", pending, err)
			}

			storeMust(t, s.Undrain(NodeKey))
			a := NewAutomaton(cfg, Saved{})
			now := storeT0
			for i := range 3 * cfg.RecoverAfter {
				in := storeInputs(s, storeVIP, ClassOK)
				if v := a.Step(in, now); v.State != StateDrain || v.Reason != ReasonNewNode || in.Report.DrainErr != "" {
					t.Fatalf("ok %d after the operator's undrain: %+v (%s), want drain/new_node", i+1, v, in.Report.DrainErr)
				}
				now = now.Add(cfg.Interval)
			}
			if d, tri, err := s.DrainFor(storeVIP); tri != TriYes || err != nil || d.Reason != NewNodeReason || !d.Since.Equal(storeT0) {
				t.Fatalf("after the operator's undrain: DrainFor = (%+v, %v, %v), want the first entry since %v", d, tri, err, storeT0)
			}

			if lifted, err := s.LiftNewNode(); !lifted || err != nil {
				t.Fatalf("LiftNewNode = (%v, %v), want lifted", lifted, err)
			}
			if _, tri, err := s.DrainFor(storeVIP); tri != TriNo || err != nil {
				t.Fatalf("after LiftNewNode: DrainFor = (%v, %v), want no drain", tri, err)
			}
			if pending, err := s.FirstEntryPending(); pending != TriNo || err != nil {
				t.Fatalf("after LiftNewNode: FirstEntryPending = (%v, %v), want no", pending, err)
			}
		})
	}
}

// TestStoreBirthWritesTheMarkerFirst: when state.json cannot be written, the
// first entry is already armed — the crash between the two leaves a node that
// is drained and born again at the next start, never one that is in without
// its first entry. The second Birth keeps the marker it finds, and its Since.
func TestStoreBirthWritesTheMarkerFirst(t *testing.T) {
	s := storeNew(t)
	blocker := filepath.Join(s.Dir, stateFileName, "x") // a non-empty directory holds the name
	storeMust(t, os.MkdirAll(blocker, 0o755))
	if _, err := s.Birth(storeT0); err == nil {
		t.Fatal("Birth wrote state.json over a directory")
	}
	if d, tri, err := s.DrainFor(NodeKey); tri != TriYes || err != nil || d.Reason != NewNodeReason {
		t.Fatalf("after a failed Birth: DrainFor = (%+v, %v, %v), want the new-node drain armed", d, tri, err)
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("a failed write left %v behind", left)
	}

	storeMust(t, os.RemoveAll(filepath.Join(s.Dir, stateFileName)))
	if _, born, err := s.Load(storeT0.Add(time.Minute), DefaultHoldDownMax); !born || err != nil {
		t.Fatalf("the next start: Load = (born %v, %v), want born again", born, err)
	}
	if _, err := s.Birth(storeT0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := s.DrainFor(NodeKey); !d.Since.Equal(storeT0) {
		t.Fatalf("the second Birth rewrote the marker: since %v, want %v", d.Since, storeT0)
	}
}

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	s := storeNew(t)
	until := storeT0.Add(15 * time.Second)
	f := StateFile{Born: storeT0, Targets: map[string]Saved{storeVIP: {Level: 2, Until: until}, NodeKey: {}}}
	storeMust(t, s.Save(f))
	g, born, err := s.Load(storeT0, DefaultHoldDownMax)
	if born || err != nil || g.Version != stateVersion || !g.Born.Equal(storeT0) || len(g.Targets) != 2 ||
		!g.Targets[storeVIP].Equal(f.Targets[storeVIP]) || !g.Targets[NodeKey].Equal(Saved{}) {
		t.Fatalf("Load = (%+v, born %v, %v), want %+v at version %d", g, born, err, f, stateVersion)
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir, stateFileName))
	storeMust(t, err)
	for _, want := range []string{`"version": 1`, `"born": "2026-11-12T10:00:00Z"`, `"level": 2`, `"until": "2026-11-12T10:00:15Z"`, `"node": {}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("state.json lacks %s:\n%s", want, raw)
		}
	}
}

// TestStoreLoadCapsTheHoldDown: a hold-down's end is capped at now+max on
// load — a clock jump or a hand-edited file keeps no node out past the
// configured max, and a lowered max takes effect at the next start.
func TestStoreLoadCapsTheHoldDown(t *testing.T) {
	s := storeNew(t)
	past := storeT0.Add(-5 * time.Minute)
	storeMust(t, s.Save(StateFile{Born: storeT0, Targets: map[string]Saved{
		"192.0.2.1": {Level: 3, Until: storeT0.Add(time.Hour)},
		"192.0.2.2": {Level: 1, Until: past},
		"192.0.2.3": {Level: 1, Until: storeT0.Add(30 * time.Second)},
		"192.0.2.4": {Level: -4},
		NodeKey:     {},
	}}))
	sec := time.Second
	tests := []struct {
		name    string
		maxHold time.Duration
		want    map[string]Saved
	}{
		{"max 60 s", 60 * sec, map[string]Saved{
			"192.0.2.1": {Level: 3, Until: storeT0.Add(60 * sec)}, "192.0.2.2": {Level: 1, Until: past},
			"192.0.2.3": {Level: 1, Until: storeT0.Add(30 * sec)}, "192.0.2.4": {}, NodeKey: {}}},
		{"a lowered max", 20 * sec, map[string]Saved{
			"192.0.2.1": {Level: 3, Until: storeT0.Add(20 * sec)}, "192.0.2.2": {Level: 1, Until: past},
			"192.0.2.3": {Level: 1, Until: storeT0.Add(20 * sec)}, "192.0.2.4": {}, NodeKey: {}}},
		{"no max is the default", 0, map[string]Saved{
			"192.0.2.1": {Level: 3, Until: storeT0.Add(DefaultHoldDownMax)}, "192.0.2.2": {Level: 1, Until: past},
			"192.0.2.3": {Level: 1, Until: storeT0.Add(30 * sec)}, "192.0.2.4": {}, NodeKey: {}}},
		{"no max beyond the ceiling", time.Hour, map[string]Saved{
			"192.0.2.1": {Level: 3, Until: storeT0.Add(HoldDownCeiling)}, "192.0.2.2": {Level: 1, Until: past},
			"192.0.2.3": {Level: 1, Until: storeT0.Add(30 * sec)}, "192.0.2.4": {}, NodeKey: {}}},
	}
	for _, tc := range tests {
		f, born, err := s.Load(storeT0, tc.maxHold)
		if born || err != nil || len(f.Targets) != len(tc.want) {
			t.Fatalf("%s: Load = (%+v, born %v, %v)", tc.name, f, born, err)
		}
		for key, want := range tc.want {
			if got := f.Targets[key]; !got.Equal(want) {
				t.Errorf("%s: %s loaded as %+v, want %+v", tc.name, key, got, want)
			}
		}
	}
}

// TestStoreRestartKeepsTheDrainAndTheHoldDown is the restart end to end: a
// target flaps, the daemon saves its ladder and dies; a new process on the
// same state_dir loads it and still holds the join until the saved end,
// showing that end as RejoinAt — and an operator's drain is still a drain.
func TestStoreRestartKeepsTheDrainAndTheHoldDown(t *testing.T) {
	stateDir := t.TempDir()
	cfg := DefaultConfig()
	const other = "192.0.2.20"

	s := NewStore(stateDir)
	f, err := s.Birth(storeT0)
	storeMust(t, err)
	if lifted, err := s.LiftNewNode(); !lifted || err != nil {
		t.Fatalf("LiftNewNode = (%v, %v)", lifted, err)
	}
	storeMust(t, s.SetDrain(other, Drain{Reason: "maintenance", Since: storeT0}))
	a := NewAutomaton(cfg, f.Targets[storeVIP])
	_, at := autoRun(a, storeT0, autoOK(10))
	w, _ := autoFlap(t, a, at)
	f.Targets = map[string]Saved{storeVIP: a.Saved()}
	storeMust(t, s.Save(f))

	restart := w.At.Add(3 * time.Second)
	s2 := NewStore(stateDir)
	g, born, err := s2.Load(restart, cfg.HoldDownMax)
	if born || err != nil || !g.Targets[storeVIP].Equal(Saved{Level: 1, Until: w.RejoinAt}) {
		t.Fatalf("after the restart: Load = (%+v, born %v, %v), want level 1 until %v", g, born, err, w.RejoinAt)
	}
	d, tri, err := s2.DrainFor(other)
	if tri != TriYes || err != nil || d.Reason != "maintenance" {
		t.Fatalf("after the restart: DrainFor(%s) = (%+v, %v, %v), want the operator's drain", other, d, tri, err)
	}
	if v := NewAutomaton(cfg, g.Targets[other]).Step(Inputs{Triggers: Triggers{Drained: tri == TriYes}, Drain: d}, restart); v.State != StateDrain {
		t.Fatalf("a drained target after the restart: %+v, want drain", v)
	}
	if _, tri, err := s2.DrainFor(storeVIP); tri != TriNo || err != nil {
		t.Fatalf("%s after the restart: (%v, %v); nobody drained it", storeVIP, tri, err)
	}

	// Ok every half second: the streak is full before the saved end, and
	// the saved end still holds the join.
	b := NewAutomaton(cfg, g.Targets[storeVIP])
	for now := restart; ; now = now.Add(500 * time.Millisecond) {
		v := b.Step(autoTick('O'), now)
		if now.Before(w.RejoinAt) {
			if v.State == StateAnnounce || !v.RejoinAt.Equal(w.RejoinAt) {
				t.Fatalf("%v after the restart: %+v, want held until the saved %v", now.Sub(restart), v, w.RejoinAt)
			}
			continue
		}
		if v.State != StateAnnounce || !v.Since.Equal(w.RejoinAt) {
			t.Fatalf("at the saved end: %+v, want the join", v)
		}
		break
	}
}

// TestStoreWipedStateDirReArmsTheNewNodeDrain: once lifted, the new-node drain
// stays lifted across restarts; a wiped steering directory or state_dir arms
// it again, as on a new node.
func TestStoreWipedStateDirReArmsTheNewNodeDrain(t *testing.T) {
	for _, wipe := range []string{"steering", "state_dir"} {
		t.Run(wipe, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			s := NewStore(stateDir)
			_, err := s.Birth(storeT0)
			storeMust(t, err)
			if lifted, err := s.LiftNewNode(); !lifted || err != nil {
				t.Fatalf("LiftNewNode = (%v, %v)", lifted, err)
			}
			if _, born, err := s.Load(storeT0.Add(time.Minute), DefaultHoldDownMax); born || err != nil {
				t.Fatalf("a restart after the lift: born %v, %v; want neither", born, err)
			}
			if _, tri, err := s.DrainFor(NodeKey); tri != TriNo || err != nil {
				t.Fatalf("the lifted drain came back on a restart: (%v, %v)", tri, err)
			}

			dir := s.Dir
			if wipe == "state_dir" {
				dir = stateDir
			}
			storeMust(t, os.RemoveAll(dir))
			later := storeT0.Add(time.Hour)
			if _, born, err := s.Load(later, DefaultHoldDownMax); !born || err != nil {
				t.Fatalf("after wiping %s: born %v, %v; want born", wipe, born, err)
			}
			_, err = s.Birth(later)
			storeMust(t, err)
			if d, tri, err := s.DrainFor(storeVIP); tri != TriYes || err != nil || d.Reason != NewNodeReason || !d.Since.Equal(later) {
				t.Fatalf("after wiping %s: DrainFor = (%+v, %v, %v), want the new-node drain again", wipe, d, tri, err)
			}
		})
	}
}

// TestStoreDrainFor: a drain file's existence is the drain; its content only
// explains it. The operator's node drain comes first, then the VIP's own,
// then the first entry, whose reason is new_node whatever its file says.
func TestStoreDrainFor(t *testing.T) {
	maint := Drain{Reason: "maintenance", Since: storeT0}
	vip := Drain{Reason: "the VIP's", Since: storeT0.Add(time.Second)}
	fresh := Drain{Reason: NewNodeReason, Since: storeT0.Add(time.Minute)}
	mtime := storeT0.Add(-time.Hour)
	const dir = "<dir>"
	tests := []struct {
		name  string
		files map[string]string // name → content; dir makes a directory
		key   string
		want  Drain
		tri   Tri
		err   bool
	}{
		{"none", nil, storeVIP, Drain{}, TriNo, false},
		{"none, for the node", nil, NodeKey, Drain{}, TriNo, false},
		{"the node's", map[string]string{"drain": storeJSON(t, maint)}, storeVIP, maint, TriYes, false},
		{"the node's, for the node", map[string]string{"drain": storeJSON(t, maint)}, NodeKey, maint, TriYes, false},
		{"the VIP's", map[string]string{"drain.192.0.2.10": storeJSON(t, maint)}, storeVIP, maint, TriYes, false},
		{"an IPv6 VIP's", map[string]string{"drain.2001:db8::10": storeJSON(t, maint)}, "2001:db8::10", maint, TriYes, false},
		{"another VIP's", map[string]string{"drain.192.0.2.20": storeJSON(t, maint)}, storeVIP, Drain{}, TriNo, false},
		{"a VIP's is not the node's", map[string]string{"drain.192.0.2.10": storeJSON(t, maint)}, NodeKey, Drain{}, TriNo, false},
		{"the node's wins", map[string]string{"drain": storeJSON(t, maint), "drain.192.0.2.10": storeJSON(t, vip)}, storeVIP, maint, TriYes, false},
		{"the first entry", map[string]string{"new_node": storeJSON(t, fresh)}, storeVIP, fresh, TriYes, false},
		{"the first entry, for the node", map[string]string{"new_node": storeJSON(t, fresh)}, NodeKey, fresh, TriYes, false},
		{"the first entry, whatever its file says", map[string]string{"new_node": `{"reason":"maintenance"}`}, storeVIP, Drain{Reason: NewNodeReason, Since: mtime}, TriYes, false},
		{"the first entry, touched", map[string]string{"new_node": ""}, NodeKey, Drain{Reason: NewNodeReason, Since: mtime}, TriYes, false},
		{"the node's over the first entry", map[string]string{"drain": storeJSON(t, maint), "new_node": storeJSON(t, fresh)}, storeVIP, maint, TriYes, false},
		{"the VIP's over the first entry", map[string]string{"drain.192.0.2.10": storeJSON(t, vip), "new_node": storeJSON(t, fresh)}, storeVIP, vip, TriYes, false},
		{"another VIP's beside the first entry", map[string]string{"drain.192.0.2.20": storeJSON(t, vip), "new_node": storeJSON(t, fresh)}, storeVIP, fresh, TriYes, false},
		{"a touch", map[string]string{"drain": ""}, storeVIP, Drain{Since: mtime}, TriYes, false},
		{"whitespace", map[string]string{"drain": " \n"}, storeVIP, Drain{Since: mtime}, TriYes, false},
		{"JSON without a date", map[string]string{"drain": `{"reason":"disk swap"}`}, storeVIP, Drain{Reason: "disk swap", Since: mtime}, TriYes, false},
		{"prose", map[string]string{"drain.192.0.2.10": "maintenance until friday"}, storeVIP, Drain{Since: mtime}, TriYes, true},
		{"half a JSON", map[string]string{"drain": `{"reason":"x","since":`}, storeVIP, Drain{Since: mtime}, TriYes, true},
		{"a directory", map[string]string{"drain": dir}, storeVIP, Drain{Since: mtime}, TriYes, true},
		{"prose beside the drain in force is reported", map[string]string{"drain": storeJSON(t, maint), "drain.192.0.2.10": "until friday"}, storeVIP, maint, TriYes, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			for name, content := range tc.files {
				if content == dir {
					path := filepath.Join(s.Dir, name)
					storeMust(t, os.MkdirAll(path, 0o755))
					storeMust(t, os.Chtimes(path, mtime, mtime))
					continue
				}
				storeRaw(t, s, name, content, mtime)
			}
			d, tri, err := s.DrainFor(tc.key)
			if tri != tc.tri || (err != nil) != tc.err || d.Reason != tc.want.Reason || !d.Since.Equal(tc.want.Since) {
				t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want (%+v, %v, error %v)", tc.key, d, tri, err, tc.want, tc.tri, tc.err)
			}
		})
	}
}

// TestStoreDrainFold: the first drain file known to exist wins, whatever
// could not be looked at before or after it; no drain needs every file known
// absent; anything else is unknown — a read nobody made included. Every error
// is kept for the report.
func TestStoreDrainFold(t *testing.T) {
	node, vip, first := Drain{Reason: "node"}, Drain{Reason: "vip"}, Drain{Reason: NewNodeReason}
	errA, errB := errors.New("a"), errors.New("b")
	yes := func(d Drain, err error) drainRead { return drainRead{d: d, tri: TriYes, err: err} }
	unknown := func(err error) drainRead { return drainRead{tri: TriUnknown, err: err} }
	no := drainRead{tri: TriNo}
	tests := []struct {
		name  string
		reads []drainRead // the node's, the VIP's, the first entry
		want  Drain
		tri   Tri
		errs  []error
	}{
		{"every file absent", []drainRead{no, no, no}, Drain{}, TriNo, nil},
		{"the node's wins", []drainRead{yes(node, nil), yes(vip, nil), yes(first, nil)}, node, TriYes, nil},
		{"the VIP's over the first entry", []drainRead{no, yes(vip, nil), yes(first, nil)}, vip, TriYes, nil},
		{"the node's unknown, the VIP's present", []drainRead{unknown(errA), yes(vip, nil), no}, vip, TriYes, []error{errA}},
		{"the node's unknown, the VIP's absent", []drainRead{unknown(errA), no, no}, Drain{}, TriUnknown, []error{errA}},
		{"the VIP's unknown, the first entry pending", []drainRead{no, unknown(errA), yes(first, nil)}, first, TriYes, []error{errA}},
		{"only the first entry unknown", []drainRead{no, no, unknown(errA)}, Drain{}, TriUnknown, []error{errA}},
		{"a drain that does not parse, an unknown after it", []drainRead{yes(node, errB), unknown(errA), no}, node, TriYes, []error{errB, errA}},
		{"a read nobody made", []drainRead{no, {}, no}, Drain{}, TriUnknown, nil},
	}
	for _, tc := range tests {
		d, tri, err := drainFold(tc.reads)
		if d != tc.want || tri != tc.tri || (err != nil) != (len(tc.errs) > 0) {
			t.Errorf("%s: drainFold = (%+v, %v, %v), want (%+v, %v, %v)", tc.name, d, tri, err, tc.want, tc.tri, tc.errs)
		}
		for _, e := range tc.errs {
			if !errors.Is(err, e) {
				t.Errorf("%s: %v lost %v", tc.name, err, e)
			}
		}
	}
}

// TestStoreDrainForUnknown: when the drain files' existence cannot be
// established, the answer is TriUnknown with the error for the report — not
// a drain, so nothing is taken out, and not the absence of one, so it holds a
// join (Gates.DrainKnown). FirstEntryPending says the same.
func TestStoreDrainForUnknown(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, s Store)
	}{
		{"a steering path that is a file", func(t *testing.T, s Store) {
			storeMust(t, os.WriteFile(s.Dir, []byte("not a directory"), 0o644))
		}},
		{"a steering path that is a symlink loop", func(t *testing.T, s Store) {
			storeMust(t, os.Symlink(DirName, s.Dir))
		}},
		{"a steering directory nobody may search, with every drain in it", func(t *testing.T, s Store) {
			if os.Geteuid() == 0 {
				t.Skip("root searches any directory")
			}
			_, err := s.Birth(storeT0)
			storeMust(t, err)
			for _, key := range []string{NodeKey, storeVIP, "2001:db8::10"} {
				storeMust(t, s.SetDrain(key, Drain{Reason: "maintenance", Since: storeT0}))
			}
			storeMust(t, os.Chmod(s.Dir, 0))
			t.Cleanup(func() { _ = os.Chmod(s.Dir, 0o755) })
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			tc.prepare(t, s)
			for _, key := range []string{NodeKey, storeVIP, "2001:db8::10"} {
				if d, tri, err := s.DrainFor(key); tri != TriUnknown || err == nil || d != (Drain{}) {
					t.Errorf("DrainFor(%s) = (%+v, %v, %v), want unknown, with an error", key, d, tri, err)
				}
			}
			if pending, err := s.FirstEntryPending(); pending != TriUnknown || err == nil {
				t.Errorf("FirstEntryPending = (%v, %v), want unknown, with an error", pending, err)
			}
		})
	}
}

// TestStoreDrainForDanglingSymlink: a drain file that is a symlink to nothing
// exists all the same — only the operator makes one — so it drains, dated by
// the link, with the failed read for the report. The new_node marker too.
func TestStoreDrainForDanglingSymlink(t *testing.T) {
	for _, tc := range []struct{ name, key, reason string }{
		{drainFileName, storeVIP, ""},
		{drainFileName + "." + storeVIP, storeVIP, ""},
		{newNodeFileName, NodeKey, NewNodeReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			storeMust(t, os.MkdirAll(s.Dir, 0o755))
			link := filepath.Join(s.Dir, tc.name)
			storeMust(t, os.Symlink(filepath.Join(s.Dir, "nowhere"), link))
			fi, err := os.Lstat(link)
			storeMust(t, err)
			if d, tri, err := s.DrainFor(tc.key); tri != TriYes || err == nil || d.Reason != tc.reason || !d.Since.Equal(fi.ModTime()) {
				t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want a drain since the link's %v, with an error", tc.key, d, tri, err, fi.ModTime())
			}
		})
	}
}

// TestStoreDrainForHandSpellings: a drain made by hand may spell its VIP's
// address any way netip reads it — upper case, leading zeros, every group,
// the IPv4-mapped form, a zone — and drains that VIP and no other target;
// Undrain lifts every spelling at once. (macOS's file system ignores case, so
// only Linux tells the upper-case rows from the canonical name.)
func TestStoreDrainForHandSpellings(t *testing.T) {
	const v6 = "2001:db8::10"
	mtime := storeT0.Add(-time.Hour)
	for _, tc := range []struct{ name, key string }{
		{"drain.2001:DB8::10", v6},
		{"drain.2001:0db8::10", v6},
		{"drain.2001:0DB8::0010", v6},
		{"drain.2001:db8:0:0:0:0:0:10", v6},
		{"drain.2001:0db8:0000:0000:0000:0000:0000:0010", v6},
		{"drain.2001:db8::10%eth0", v6},
		{"drain.::ffff:192.0.2.10", storeVIP},
		{"drain.::FFFF:192.0.2.10", storeVIP},
		{"drain.::ffff:c000:20a", storeVIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			storeRaw(t, s, tc.name, "", mtime)
			if d, tri, err := s.DrainFor(tc.key); tri != TriYes || err != nil || d.Reason != "" || !d.Since.Equal(mtime) {
				t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want the hand-made drain since %v", tc.key, d, tri, err, mtime)
			}
			for _, other := range []string{NodeKey, "2001:db8::11", "192.0.2.11"} {
				if _, tri, err := s.DrainFor(other); tri != TriNo || err != nil {
					t.Fatalf("DrainFor(%s) = (%v, %v), want no drain: %s is %s's", other, tri, err, tc.name, tc.key)
				}
			}
			storeMust(t, s.Undrain(tc.key))
			if _, tri, err := s.DrainFor(tc.key); tri != TriNo || err != nil {
				t.Fatalf("after Undrain(%s): DrainFor = (%v, %v), want no drain", tc.key, tri, err)
			}
			if left := storeNames(t, s); len(left) != 0 {
				t.Fatalf("Undrain(%s) left %v", tc.key, left)
			}
		})
	}

	t.Run("the canonical file beside a hand-made one", func(t *testing.T) {
		s := storeNew(t)
		storeMust(t, s.SetDrain(v6, Drain{Reason: "maintenance", Since: storeT0}))
		storeRaw(t, s, "drain.2001:0db8::10", "", mtime)
		if d, tri, err := s.DrainFor(v6); tri != TriYes || err != nil || d.Reason != "maintenance" {
			t.Fatalf("DrainFor = (%+v, %v, %v), want the canonical file's drain", d, tri, err)
		}
		storeMust(t, s.Undrain(v6))
		if _, tri, err := s.DrainFor(v6); tri != TriNo || err != nil {
			t.Fatalf("after one Undrain: DrainFor = (%v, %v), want every spelling lifted", tri, err)
		}
		if left := storeNames(t, s); len(left) != 0 {
			t.Fatalf("Undrain left %v", left)
		}
	})
}

// TestStoreDrainForNamesStrays: a name beginning "drain" that spells no
// address drains nothing — nobody can tell which VIP it meant — and is never
// ignored silently: every DrainFor names it for the report, and Undrain
// leaves it. What does not begin "drain" — a writer's temporary, an
// operator's notes — is neither a drain nor a stray.
func TestStoreDrainForNamesStrays(t *testing.T) {
	for _, name := range []string{"drain.node", "drain.192.0.2.010", "drain.2001:db8::10.bak", "drain.192.0.2.10~", "drain.", "drain_192.0.2.10", "drain~"} {
		t.Run(name, func(t *testing.T) {
			s := storeNew(t)
			storeRaw(t, s, name, "", storeT0)
			for _, key := range []string{NodeKey, storeVIP, "2001:db8::10"} {
				if _, tri, err := s.DrainFor(key); tri != TriNo || err == nil || !strings.Contains(err.Error(), filepath.Join(s.Dir, name)) {
					t.Fatalf("DrainFor(%s) beside %s = (%v, %v), want no drain, naming it", key, name, tri, err)
				}
			}
			storeMust(t, s.Undrain(storeVIP))
			storeMust(t, s.Undrain(NodeKey))
			if left := storeNames(t, s); !reflect.DeepEqual(left, []string{name}) {
				t.Fatalf("after Undrain: %v left, want %s alone", left, name)
			}
		})
	}
	for _, name := range []string{".drain.192.0.2.10.123.tmp", "notes", "xdrain.192.0.2.10"} {
		t.Run(name, func(t *testing.T) {
			s := storeNew(t)
			storeRaw(t, s, name, "", storeT0)
			for _, key := range []string{NodeKey, storeVIP} {
				if _, tri, err := s.DrainFor(key); tri != TriNo || err != nil {
					t.Fatalf("DrainFor(%s) beside %s = (%v, %v), want no drain and nothing to report", key, name, tri, err)
				}
			}
		})
	}
}

func TestStoreSetDrainAndUndrain(t *testing.T) {
	s := storeNew(t)
	for _, key := range []string{NodeKey, storeVIP, "2001:db8::10"} {
		want := Drain{Reason: "maintenance of " + key, Since: storeT0}
		storeMust(t, s.SetDrain(key, want))
		if d, tri, err := s.DrainFor(key); tri != TriYes || err != nil || d.Reason != want.Reason || !d.Since.Equal(want.Since) {
			t.Fatalf("after SetDrain(%s): DrainFor = (%+v, %v, %v), want %+v", key, d, tri, err, want)
		}
		storeMust(t, s.Undrain(key))
		if _, tri, err := s.DrainFor(key); tri != TriNo || err != nil {
			t.Fatalf("after Undrain(%s): DrainFor = (%v, %v), want no drain", key, tri, err)
		}
		if err := s.Undrain(key); err != nil {
			t.Fatalf("Undrain(%s) of no drain = %v, want nil", key, err)
		}
	}

	storeMust(t, s.SetDrain(storeVIP, Drain{Reason: "first", Since: storeT0}))
	storeMust(t, s.SetDrain(storeVIP, Drain{Reason: "second", Since: storeT0.Add(time.Minute)}))
	if d, _, _ := s.DrainFor(storeVIP); d.Reason != "second" {
		t.Fatalf("SetDrain over a drain: reason %q, want the second", d.Reason)
	}
	storeMust(t, s.Undrain(storeVIP))

	// A drain of the operator's is the operator's whatever its reason says:
	// Undrain lifts one that reads new_node. The first entry itself it never
	// lifts — that is LiftNewNode's alone.
	storeMust(t, s.SetDrain(NodeKey, Drain{Reason: NewNodeReason, Since: storeT0}))
	storeMust(t, s.Undrain(NodeKey))
	if _, tri, _ := s.DrainFor(NodeKey); tri != TriNo {
		t.Fatalf("Undrain left the operator's drain that reads %s: %v", NewNodeReason, tri)
	}
	_, err := s.Birth(storeT0)
	storeMust(t, err)
	for _, key := range []string{NodeKey, storeVIP} {
		storeMust(t, s.Undrain(key))
		if d, tri, _ := s.DrainFor(key); tri != TriYes || d.Reason != NewNodeReason {
			t.Fatalf("Undrain(%s) lifted the first entry: (%+v, %v)", key, d, tri)
		}
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("writes left %v behind", left)
	}
}

// TestStoreRefusesKeysThatAreNotTargets: a drain key is NodeKey or what
// VIPTarget makes of an address — its canonical text, unmapped, without a
// zone — so the API keeps one file per address, and no key names a file
// outside the directory or another file in it: a zone is free text, and
// "fe80::1%../../x" would climb out. A refused key writes, removes and drains
// nothing; a target's key is accepted, whatever address it was made from.
func TestStoreRefusesKeysThatAreNotTargets(t *testing.T) {
	refused := []string{
		"", "../escape", "x/y", "drain", "nodes", "new_node", "state.json",
		"192.0.2.010", "2001:DB8::10", "2001:0db8::10", "192.0.2.10/32", " 192.0.2.10",
		"::ffff:192.0.2.10", "::ffff:192.0.2.10%eth0", "fe80::1%eth0", "2001:db8::10%eth0", "2001:db8::10%a/b",
		"fe80::1%../../../escaped", "2001:db8::10%../../drain", "2001:db8::10%../../new_node", "2001:db8::10%../../state.json",
	}
	root := t.TempDir()
	s := NewStore(filepath.Join(root, "a", "b", "state")) // deep enough that no ".." above leaves root
	try := func(t *testing.T, want Tri) {
		t.Helper()
		for _, key := range refused {
			if err := s.SetDrain(key, Drain{Reason: "refused", Since: storeT0}); err == nil {
				t.Errorf("SetDrain(%q) = nil, want a refusal", key)
			}
			if err := s.Undrain(key); err == nil {
				t.Errorf("Undrain(%q) = nil, want a refusal", key)
			}
			if _, tri, err := s.DrainFor(key); tri != want || err == nil {
				t.Errorf("DrainFor(%q) = (%v, %v), want %v, with an error", key, tri, err, want)
			}
		}
	}

	t.Run("on a new node", func(t *testing.T) {
		try(t, TriUnknown) // a key that is no target's cannot be said to be undrained
		if tree := storeTree(t, root); len(tree) != 0 {
			t.Fatalf("refused keys wrote %v", tree)
		}
	})
	t.Run("beside the node's files", func(t *testing.T) {
		_, err := s.Birth(storeT0)
		storeMust(t, err)
		storeMust(t, s.SetDrain(NodeKey, Drain{Reason: "maintenance", Since: storeT0}))
		before := storeTree(t, root)
		try(t, TriYes) // the node's own drain covers every target, whatever key asks
		if after := storeTree(t, root); !reflect.DeepEqual(after, before) {
			t.Fatalf("refused keys changed the tree from %v to %v", before, after)
		}
	})
	t.Run("a target's key", func(t *testing.T) {
		s := storeNew(t)
		for _, text := range []string{"192.0.2.10", "::ffff:192.0.2.10", "::ffff:192.0.2.10%eth0", "2001:db8::10", "2001:DB8:0:0::10", "2001:db8::10%eth0"} {
			key := VIPTarget(netip.MustParseAddr(text)).Key
			want := Drain{Reason: "maintenance of " + text, Since: storeT0}
			if err := s.SetDrain(key, want); err != nil {
				t.Errorf("SetDrain(VIPTarget(%s).Key = %q) = %v, want it accepted", text, key, err)
				continue
			}
			if _, err := os.Lstat(filepath.Join(s.Dir, drainFileName+"."+key)); err != nil {
				t.Errorf("SetDrain(%q) wrote no %s.%s: %v", key, drainFileName, key, err)
			}
			if d, tri, err := s.DrainFor(key); tri != TriYes || err != nil || d.Reason != want.Reason {
				t.Errorf("DrainFor(%q) = (%+v, %v, %v), want %+v", key, d, tri, err, want)
			}
			storeMust(t, s.Undrain(key))
			if _, tri, err := s.DrainFor(key); tri != TriNo || err != nil {
				t.Errorf("after Undrain(%q): DrainFor = (%v, %v), want no drain", key, tri, err)
			}
		}
	})
}

// TestStoreLiftNewNode: lifting the first entry — the Joiner's lift, or
// `-s undrain -force` — removes new_node and nothing else: the operator's
// drains, set before the first start, over the first entry or beside it,
// stand as they were. It refuses before Birth has written state.json.
func TestStoreLiftNewNode(t *testing.T) {
	maint := Drain{Reason: "maintenance", Since: storeT0}
	birth := func(t *testing.T, s Store) {
		_, err := s.Birth(storeT0)
		storeMust(t, err)
	}
	tests := []struct {
		name    string
		prepare func(t *testing.T, s Store)
		lifted  bool
		err     bool
		drained Tri    // DrainFor(NodeKey), after
		reason  string // its reason
	}{
		{"the first entry", birth, true, false, TriNo, ""},
		{"before Birth: no state.json", func(t *testing.T, s Store) {
			storeRaw(t, s, newNodeFileName, storeJSON(t, Drain{Reason: NewNodeReason, Since: storeT0}), storeT0)
		}, false, true, TriYes, NewNodeReason},
		{"after a plain undrain", func(t *testing.T, s Store) { birth(t, s); storeMust(t, s.Undrain(NodeKey)) }, true, false, TriNo, ""},
		{"under the operator's drain from before Birth", func(t *testing.T, s Store) {
			storeMust(t, s.SetDrain(NodeKey, maint))
			birth(t, s)
		}, true, false, TriYes, maint.Reason},
		{"under the operator's drain set over it", func(t *testing.T, s Store) {
			birth(t, s)
			storeMust(t, s.SetDrain(NodeKey, maint))
		}, true, false, TriYes, maint.Reason},
		{"beside a touch", func(t *testing.T, s Store) { birth(t, s); storeRaw(t, s, drainFileName, "", storeT0) }, true, false, TriYes, ""},
		{"beside the operator's prose naming its reason", func(t *testing.T, s Store) {
			birth(t, s)
			storeRaw(t, s, drainFileName, NewNodeReason, storeT0)
		}, true, false, TriYes, ""},
		{"beside a VIP's drain", func(t *testing.T, s Store) { birth(t, s); storeMust(t, s.SetDrain(storeVIP, maint)) }, true, false, TriNo, ""},
		{"lifted already", func(t *testing.T, s Store) {
			birth(t, s)
			if _, err := s.LiftNewNode(); err != nil {
				t.Fatal(err)
			}
		}, false, false, TriNo, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			tc.prepare(t, s)
			before := storeTree(t, s.Dir)
			lifted, err := s.LiftNewNode()
			if lifted != tc.lifted || (err != nil) != tc.err {
				t.Fatalf("LiftNewNode = (%v, %v), want (%v, error %v)", lifted, err, tc.lifted, tc.err)
			}
			if lifted {
				delete(before, newNodeFileName)
			}
			if after := storeTree(t, s.Dir); !reflect.DeepEqual(after, before) {
				t.Fatalf("LiftNewNode left %v, want %v: new_node gone when lifted, nothing else touched", after, before)
			}
			if d, tri, _ := s.DrainFor(NodeKey); tri != tc.drained || d.Reason != tc.reason {
				t.Fatalf("after LiftNewNode: DrainFor = (%+v, %v), want %v, reason %q", d, tri, tc.drained, tc.reason)
			}
			if lifted, err := s.LiftNewNode(); lifted || (err != nil) != tc.err {
				t.Fatalf("LiftNewNode again = (%v, %v), want nothing more to lift", lifted, err)
			}
		})
	}
}

// TestStoreNewNodeDrainLiftsOnceEveryZoneHasHandshaken is D7 end to end, from
// the join-handshake facts (FirstEntry, as Joiner.Check reports them) to the
// verdict: a new node is born drained and stays drained while it serves,
// until every zone with a :443 server in the live render has passed its one
// handshake; then the drain lifts itself, the target joins on a full streak
// with no hold-down, and a restart does not drain it again.
func TestStoreNewNodeDrainLiftsOnceEveryZoneHasHandshaken(t *testing.T) {
	s := storeNew(t)
	cfg := DefaultConfig()
	f, born, err := s.Load(storeT0, cfg.HoldDownMax)
	if !born || err != nil {
		t.Fatalf("a new node: Load = (born %v, %v), want born", born, err)
	}
	f, err = s.Birth(storeT0)
	storeMust(t, err)
	a := NewAutomaton(cfg, f.Targets[storeVIP])
	now := storeT0
	step := func() Verdict {
		t.Helper()
		in := storeInputs(s, storeVIP, ClassOK)
		if in.Report.DrainErr != "" {
			t.Fatal(in.Report.DrainErr)
		}
		v := a.Step(in, now)
		now = now.Add(time.Second)
		return v
	}

	for _, facts := range []FirstEntry{
		{}, // the document names no zone yet
		{Zones: 2, Missing: []string{"a.example", "b.example"}},
		{Zones: 2, Ready: 1, Missing: []string{"b.example"}},
	} {
		if facts.Done() {
			t.Fatalf("%+v is Done", facts)
		}
		for range 12 { // the box answers TLS all along; the drain holds anyway
			if v := step(); v.State != StateDrain || v.Reason != ReasonNewNode || !v.Since.Equal(storeT0) {
				t.Fatalf("%+v: verdict %+v, want drain/new_node since %v", facts, v, storeT0)
			}
		}
	}

	if facts := (FirstEntry{Zones: 2, Ready: 2}); !facts.Done() {
		t.Fatalf("%+v is not Done", facts)
	}
	if lifted, err := s.LiftNewNode(); !lifted || err != nil {
		t.Fatalf("every zone handshaken: LiftNewNode = (%v, %v), want lifted", lifted, err)
	}
	lift := now
	for i := 1; i <= cfg.RecoverAfter; i++ {
		v := step()
		switch {
		case i == 1 && (v.State != StateUnknown || v.Reason != ReasonStarting || !v.Since.Equal(lift)):
			t.Fatalf("the tick after the lift: %+v, want unknown/starting", v)
		case i < cfg.RecoverAfter && v.State != StateUnknown:
			t.Fatalf("ok %d after the lift: %+v, want unknown until a full streak", i, v)
		case i == cfg.RecoverAfter && (v.State != StateAnnounce || !v.RejoinAt.IsZero()):
			t.Fatalf("ok %d after the lift: %+v, want the join, with no hold-down", i, v)
		}
	}
	if _, born, err := s.Load(now, cfg.HoldDownMax); born || err != nil {
		t.Fatalf("a restart after the lift: Load = (born %v, %v), want neither", born, err)
	}
	if _, tri, err := s.DrainFor(storeVIP); tri != TriNo || err != nil {
		t.Fatalf("the new-node drain came back: (%v, %v)", tri, err)
	}
}

// TestStoreUnknownDrainHoldsTheJoin is I3 for the drain, from the disk to the
// verdict: while the drain files cannot be looked at, a drained target is not
// let in — its streak fills and the drain gate holds it — a restarted one
// does not join, and an announced one stays in, warned; once the files read
// again, the drain stands where it stood. The steering path is made a symlink
// loop, which no privilege reads through.
func TestStoreUnknownDrainHoldsTheJoin(t *testing.T) {
	cfg := DefaultConfig()
	const other = "192.0.2.20"
	s := storeNew(t)
	_, err := s.Birth(storeT0)
	storeMust(t, err)
	if lifted, err := s.LiftNewNode(); !lifted || err != nil {
		t.Fatalf("LiftNewNode = (%v, %v)", lifted, err)
	}
	storeMust(t, s.SetDrain(storeVIP, Drain{Reason: "maintenance", Since: storeT0}))

	drained, announced := NewAutomaton(cfg, Saved{}), NewAutomaton(cfg, Saved{})
	now := storeT0
	tick := func(a *Automaton, key string) Verdict { return a.Step(storeInputs(s, key, ClassOK), now) }
	var v, w Verdict
	for range cfg.RecoverAfter {
		v, w = tick(drained, storeVIP), tick(announced, other)
		now = now.Add(cfg.Interval)
	}
	if v.State != StateDrain || w.State != StateAnnounce {
		t.Fatalf("before: %s %+v, %s %+v; want drain and announce", storeVIP, v, other, w)
	}

	kept := s.Dir + ".kept"
	storeMust(t, os.Rename(s.Dir, kept))
	storeMust(t, os.Symlink(DirName, s.Dir))
	for _, key := range []string{storeVIP, other} {
		if _, tri, err := s.DrainFor(key); tri != TriUnknown || err == nil {
			t.Fatalf("DrainFor(%s) through a symlink loop = (%v, %v), want unknown, with an error", key, tri, err)
		}
	}
	restarted := NewAutomaton(cfg, Saved{})
	for i := range 3 * cfg.RecoverAfter {
		for _, x := range []struct {
			name string
			a    *Automaton
			key  string
			want State
		}{
			{"the drained target", drained, storeVIP, StateUnknown},
			{"a restarted one", restarted, storeVIP, StateUnknown},
			{"the announced one", announced, other, StateAnnounce},
		} {
			if v := tick(x.a, x.key); v.State != x.want || v.Warning != ReasonDrainUnknown {
				t.Fatalf("ok %d with the drain unknown: %s is %+v, want %v, warned %s", i+1, x.name, v, x.want, ReasonDrainUnknown)
			}
		}
		now = now.Add(cfg.Interval)
	}

	storeMust(t, os.Remove(s.Dir))
	storeMust(t, os.Rename(kept, s.Dir))
	if v := tick(drained, storeVIP); v.State != StateDrain || v.Reason != ReasonDrained {
		t.Fatalf("the files read again: %+v, want the drain where it stood", v)
	}
	now = now.Add(cfg.Interval)
	storeMust(t, s.Undrain(storeVIP))
	for i := 1; i <= cfg.RecoverAfter; i++ {
		want := StateUnknown
		if i == cfg.RecoverAfter {
			want = StateAnnounce
		}
		if v := tick(drained, storeVIP); v.State != want {
			t.Fatalf("ok %d after the undrain: %+v, want %v", i, v, want)
		}
		now = now.Add(cfg.Interval)
	}
}

// TestStoreWritesAtomically: readers on the tick never see half a state.json
// while it is rewritten — every read parses, and is one of the versions
// written — and nothing is left behind.
func TestStoreWritesAtomically(t *testing.T) {
	s := storeNew(t)
	versions := []StateFile{storeTargets(1), storeTargets(3000)}
	storeMust(t, s.Save(versions[0]))

	stop := make(chan struct{})
	bad := make(chan string, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				f, born, err := s.Load(storeT0, DefaultHoldDownMax)
				if n := len(f.Targets); err != nil || born || (n != 1 && n != 3000) {
					bad <- fmt.Sprintf("a read during the writes: %d targets, born %v, %v", n, born, err)
					return
				}
			}
		}()
	}
	for i := range 30 {
		if err := s.Save(versions[i%2]); err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("writes left %v behind", left)
	}
}

// storeTargets is a StateFile with n targets.
func storeTargets(n int) StateFile {
	f := StateFile{Born: storeT0, Targets: make(map[string]Saved, n)}
	for i := range n {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		f.Targets[addr.String()] = Saved{Level: 1, Until: storeT0.Add(time.Second)}
	}
	return f
}

// TestStoreWritersNeverShareATemporary: the daemon and an operator's commands
// write into the directory at once; every write lands, and every file reads
// whole afterwards.
func TestStoreWritersNeverShareATemporary(t *testing.T) {
	s := storeNew(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 10 {
				var err error
				switch g % 3 {
				case 0:
					err = s.Save(StateFile{Born: storeT0, Targets: map[string]Saved{storeVIP: {Level: i}}})
				case 1:
					err = s.SetDrain(NodeKey, Drain{Reason: fmt.Sprintf("writer %d, write %d", g, i), Since: storeT0})
				default:
					err = s.SetDrain(storeVIP, Drain{Reason: fmt.Sprintf("writer %d, write %d", g, i), Since: storeT0})
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if _, born, err := s.Load(storeT0, DefaultHoldDownMax); born || err != nil {
		t.Fatalf("Load after the writers = (born %v, %v)", born, err)
	}
	for _, key := range []string{NodeKey, storeVIP} {
		if d, tri, err := s.DrainFor(key); tri != TriYes || err != nil || !strings.HasPrefix(d.Reason, "writer ") {
			t.Fatalf("DrainFor(%s) after the writers = (%+v, %v, %v)", key, d, tri, err)
		}
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("writes left %v behind", left)
	}
}

// TestStoreReadsAtMostAMegabyte: no file here is read past storeMaxFile
// bytes. A drain file someone filled by mistake is still a drain, read in
// part; an oversized state.json is an error, not a birth. Every payload is
// valid JSON whole, so only the cut can make it fail: the same drain parses
// at exactly the bound and does not one byte past it.
func TestStoreReadsAtMostAMegabyte(t *testing.T) {
	const head, tail = `{"reason":"`, `"}`
	fill := storeMaxFile - len(head) - len(tail)
	s := storeNew(t)

	storeRaw(t, s, drainFileName, head+strings.Repeat("a", fill)+tail, storeT0)
	if d, tri, err := s.DrainFor(NodeKey); tri != TriYes || err != nil || len(d.Reason) != fill {
		t.Fatalf("a drain file of exactly the bound: (%d-byte reason, %v, %v), want it read whole", len(d.Reason), tri, err)
	}
	storeRaw(t, s, drainFileName, head+strings.Repeat("a", fill+1)+tail, storeT0)
	if raw, err := storeReadFile(filepath.Join(s.Dir, drainFileName)); err != nil || len(raw) != storeMaxFile {
		t.Fatalf("a file one byte past the bound: %d bytes read, %v; want %d", len(raw), err, storeMaxFile)
	}
	if d, tri, err := s.DrainFor(NodeKey); tri != TriYes || err == nil || d.Reason != "" || !d.Since.Equal(storeT0) {
		t.Fatalf("a drain file one byte past the bound: (%d-byte reason, since %v, %v, %v), want drained, cut, dated by its mtime, with an error",
			len(d.Reason), d.Since, tri, err)
	}
	storeRaw(t, s, stateFileName, `{"version":1,"born":"2026-11-12T10:00:00Z","pad":"`+strings.Repeat("a", storeMaxFile)+`"}`, storeT0)
	if f, born, err := s.Load(storeT0, DefaultHoldDownMax); born || err == nil || !reflect.DeepEqual(f, StateFile{}) {
		t.Fatalf("a state.json past the bound: (born at %v, born %v, %v), want an error and no birth", f.Born, born, err)
	}
}

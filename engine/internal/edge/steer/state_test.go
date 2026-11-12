package steer

import (
	"encoding/json"
	"fmt"
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
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			left = append(left, e.Name())
		}
	}
	return left
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

// TestStoreBirthArmsTheNewNodeDrain: Birth writes the node-wide new-node drain
// — which covers every VIP — and state.json, and the next Load is no birth.
func TestStoreBirthArmsTheNewNodeDrain(t *testing.T) {
	s := storeNew(t)
	f, err := s.Birth(storeT0)
	if err != nil || f.Version != stateVersion || !f.Born.Equal(storeT0) || len(f.Targets) != 0 {
		t.Fatalf("Birth = (%+v, %v), want version %d, born %v", f, err, stateVersion, storeT0)
	}
	for _, key := range []string{NodeKey, storeVIP} {
		d, ok, err := s.DrainFor(key)
		if !ok || err != nil || d.Reason != NewNodeReason || !d.Since.Equal(storeT0) {
			t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want the new-node drain since %v", key, d, ok, err, storeT0)
		}
	}
	g, born, err := s.Load(storeT0.Add(time.Hour), DefaultHoldDownMax)
	if born || err != nil || !g.Born.Equal(storeT0) || g.Version != stateVersion {
		t.Fatalf("Load after Birth = (%+v, born %v, %v), want the born record", g, born, err)
	}
	for _, name := range []string{drainFileName, stateFileName} {
		fi, err := os.Stat(filepath.Join(s.Dir, name))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s: %v, %v; want mode 0644 — the operator's tools read it", name, fi, err)
		}
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("Birth left %v behind", left)
	}
}

// TestStoreBirthKeepsAnOperatorDrain: an operator's node-wide drain, there
// before the first start, is never replaced by one that lifts by itself.
func TestStoreBirthKeepsAnOperatorDrain(t *testing.T) {
	s := storeNew(t)
	op := Drain{Reason: "maintenance", Since: storeT0.Add(-time.Hour)}
	storeMust(t, s.SetDrain(NodeKey, op))
	if _, err := s.Birth(storeT0); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := s.DrainFor(storeVIP); !ok || err != nil || d.Reason != op.Reason || !d.Since.Equal(op.Since) {
		t.Fatalf("DrainFor after Birth = (%+v, %v, %v), want the operator's %+v", d, ok, err, op)
	}
	if lifted, err := s.LiftNewNode(); lifted || err != nil {
		t.Fatalf("LiftNewNode over an operator's drain = (%v, %v), want (false, nil)", lifted, err)
	}
	if _, ok, _ := s.DrainFor(NodeKey); !ok {
		t.Fatal("the operator's drain is gone")
	}
}

// TestStoreBirthWritesTheDrainFirst: when state.json cannot be written, the
// drain is already armed — the crash between the two leaves a node that is
// drained and born again at the next start, never one that is in without
// its first entry. The second Birth keeps the drain it finds.
func TestStoreBirthWritesTheDrainFirst(t *testing.T) {
	s := storeNew(t)
	blocker := filepath.Join(s.Dir, stateFileName, "x") // a non-empty directory holds the name
	storeMust(t, os.MkdirAll(blocker, 0o755))
	if _, err := s.Birth(storeT0); err == nil {
		t.Fatal("Birth wrote state.json over a directory")
	}
	if d, ok, err := s.DrainFor(NodeKey); !ok || err != nil || d.Reason != NewNodeReason {
		t.Fatalf("after a failed Birth: DrainFor = (%+v, %v, %v), want the new-node drain armed", d, ok, err)
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
		t.Fatalf("the second Birth rewrote the drain: since %v, want %v", d.Since, storeT0)
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
	d, drained, err := s2.DrainFor(other)
	if !drained || err != nil || d.Reason != "maintenance" {
		t.Fatalf("after the restart: DrainFor(%s) = (%+v, %v, %v), want the operator's drain", other, d, drained, err)
	}
	if v := NewAutomaton(cfg, g.Targets[other]).Step(Inputs{Triggers: Triggers{Drained: drained}, Drain: d}, restart); v.State != StateDrain {
		t.Fatalf("a drained target after the restart: %+v, want drain", v)
	}
	if _, drained, _ := s2.DrainFor(storeVIP); drained {
		t.Fatalf("%s is drained after the restart; nobody drained it", storeVIP)
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
			if _, drained, _ := s.DrainFor(NodeKey); drained {
				t.Fatal("the lifted drain came back on a restart")
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
			if d, drained, err := s.DrainFor(storeVIP); !drained || err != nil || d.Reason != NewNodeReason || !d.Since.Equal(later) {
				t.Fatalf("after wiping %s: DrainFor = (%+v, %v, %v), want the new-node drain again", wipe, d, drained, err)
			}
		})
	}
}

// TestStoreDrainFor: a drain file's existence is the drain; its content only
// explains it.
func TestStoreDrainFor(t *testing.T) {
	maint := Drain{Reason: "maintenance", Since: storeT0}
	fresh := Drain{Reason: NewNodeReason, Since: storeT0.Add(time.Minute)}
	mtime := storeT0.Add(-time.Hour)
	const dir = "<dir>"
	tests := []struct {
		name    string
		files   map[string]string // name → content; dir makes a directory
		key     string
		want    Drain
		ok, err bool
	}{
		{"none", nil, storeVIP, Drain{}, false, false},
		{"the node's", map[string]string{"drain": storeJSON(t, maint)}, storeVIP, maint, true, false},
		{"the node's, for the node", map[string]string{"drain": storeJSON(t, maint)}, NodeKey, maint, true, false},
		{"the VIP's", map[string]string{"drain.192.0.2.10": storeJSON(t, maint)}, storeVIP, maint, true, false},
		{"an IPv6 VIP's", map[string]string{"drain.2001:db8::10": storeJSON(t, maint)}, "2001:db8::10", maint, true, false},
		{"another VIP's", map[string]string{"drain.192.0.2.20": storeJSON(t, maint)}, storeVIP, Drain{}, false, false},
		{"a VIP's is not the node's", map[string]string{"drain.192.0.2.10": storeJSON(t, maint)}, NodeKey, Drain{}, false, false},
		{"the node's wins", map[string]string{"drain": storeJSON(t, fresh), "drain.192.0.2.10": storeJSON(t, maint)}, storeVIP, fresh, true, false},
		{"a touch", map[string]string{"drain": ""}, storeVIP, Drain{Since: mtime}, true, false},
		{"whitespace", map[string]string{"drain": " \n"}, storeVIP, Drain{Since: mtime}, true, false},
		{"JSON without a date", map[string]string{"drain": `{"reason":"disk swap"}`}, storeVIP, Drain{Reason: "disk swap", Since: mtime}, true, false},
		{"prose", map[string]string{"drain.192.0.2.10": "maintenance until friday"}, storeVIP, Drain{Since: mtime}, true, true},
		{"half a JSON", map[string]string{"drain": `{"reason":"x","since":`}, storeVIP, Drain{Since: mtime}, true, true},
		{"a directory", map[string]string{"drain": dir}, storeVIP, Drain{Since: mtime}, true, true},
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
			d, ok, err := s.DrainFor(tc.key)
			if ok != tc.ok || (err != nil) != tc.err || d.Reason != tc.want.Reason || !d.Since.Equal(tc.want.Since) {
				t.Fatalf("DrainFor(%s) = (%+v, %v, %v), want (%+v, %v, error %v)", tc.key, d, ok, err, tc.want, tc.ok, tc.err)
			}
		})
	}
}

// TestStoreDrainForUnknownIsNoDrain: when existence cannot be established the
// answer is unknown — not drained, with the error for the report.
func TestStoreDrainForUnknownIsNoDrain(t *testing.T) {
	s := storeNew(t)
	storeMust(t, os.WriteFile(s.Dir, []byte("not a directory"), 0o644))
	for _, key := range []string{NodeKey, storeVIP} {
		if d, ok, err := s.DrainFor(key); ok || err == nil || d != (Drain{}) {
			t.Errorf("DrainFor(%s) over an unreadable directory = (%+v, %v, %v), want not drained, with an error", key, d, ok, err)
		}
	}
}

func TestStoreSetDrainAndUndrain(t *testing.T) {
	s := storeNew(t)
	for _, key := range []string{NodeKey, storeVIP, "2001:db8::10"} {
		want := Drain{Reason: "maintenance of " + key, Since: storeT0}
		storeMust(t, s.SetDrain(key, want))
		if d, ok, err := s.DrainFor(key); !ok || err != nil || d.Reason != want.Reason || !d.Since.Equal(want.Since) {
			t.Fatalf("after SetDrain(%s): DrainFor = (%+v, %v, %v), want %+v", key, d, ok, err, want)
		}
		storeMust(t, s.Undrain(key))
		if _, ok, err := s.DrainFor(key); ok || err != nil {
			t.Fatalf("after Undrain(%s): DrainFor = (%v, %v), want not drained", key, ok, err)
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
	// Undrain lifts any drain, the new-node one included: refusing that
	// without -force is the command's business.
	storeMust(t, s.SetDrain(NodeKey, Drain{Reason: NewNodeReason, Since: storeT0}))
	storeMust(t, s.Undrain(NodeKey))
	if _, ok, _ := s.DrainFor(NodeKey); ok {
		t.Fatal("Undrain left the new-node drain")
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("writes left %v behind", left)
	}
}

// TestStoreRefusesKeysThatAreNotTargets: a drain key is NodeKey or a VIP's
// canonical text, so no key names a file outside the directory or a second
// file for one address.
func TestStoreRefusesKeysThatAreNotTargets(t *testing.T) {
	stateDir := t.TempDir()
	s := NewStore(stateDir)
	for _, key := range []string{"", "../escape", "x/y", "drain", "nodes", "192.0.2.010", "2001:DB8::10", "192.0.2.10/32", " 192.0.2.10"} {
		if err := s.SetDrain(key, Drain{Reason: "maintenance", Since: storeT0}); err == nil {
			t.Errorf("SetDrain(%q) = nil, want a refusal", key)
		}
		if err := s.Undrain(key); err == nil {
			t.Errorf("Undrain(%q) = nil, want a refusal", key)
		}
		if _, ok, err := s.DrainFor(key); ok || err == nil {
			t.Errorf("DrainFor(%q) = (%v, %v), want not drained, with an error", key, ok, err)
		}
	}
	if entries, _ := os.ReadDir(stateDir); len(entries) != 0 {
		t.Fatalf("refused keys wrote %v", entries)
	}
	// The node's own drain covers every target, whatever key asks.
	storeMust(t, s.SetDrain(NodeKey, Drain{Reason: "maintenance", Since: storeT0}))
	if d, ok, err := s.DrainFor("../escape"); !ok || err != nil || d.Reason != "maintenance" {
		t.Fatalf("DrainFor of a bad key under the node's drain = (%+v, %v, %v), want the node's drain", d, ok, err)
	}
}

// TestStoreLiftNewNode: only the new-node drain lifts itself, and only once
// the node is born.
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
		drained bool // after
	}{
		{"the new-node drain", birth, true, false, false},
		{"before Birth: no state.json", func(t *testing.T, s Store) {
			storeMust(t, s.SetDrain(NodeKey, Drain{Reason: NewNodeReason, Since: storeT0}))
		}, false, true, true},
		{"no drain", func(t *testing.T, s Store) { birth(t, s); storeMust(t, s.Undrain(NodeKey)) }, false, false, false},
		{"the operator's drain", func(t *testing.T, s Store) { storeMust(t, s.SetDrain(NodeKey, maint)); birth(t, s) }, false, false, true},
		{"the operator's drain over the new-node one", func(t *testing.T, s Store) { birth(t, s); storeMust(t, s.SetDrain(NodeKey, maint)) }, false, false, true},
		{"a touch over the new-node one", func(t *testing.T, s Store) { birth(t, s); storeRaw(t, s, drainFileName, "", storeT0) }, false, false, true},
		{"prose naming the reason", func(t *testing.T, s Store) { birth(t, s); storeRaw(t, s, drainFileName, NewNodeReason, storeT0) }, false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := storeNew(t)
			tc.prepare(t, s)
			lifted, err := s.LiftNewNode()
			if lifted != tc.lifted || (err != nil) != tc.err {
				t.Fatalf("LiftNewNode = (%v, %v), want (%v, error %v)", lifted, err, tc.lifted, tc.err)
			}
			if _, drained, _ := s.DrainFor(NodeKey); drained != tc.drained {
				t.Fatalf("after LiftNewNode: drained %v, want %v", drained, tc.drained)
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
		d, drained, err := s.DrainFor(storeVIP)
		storeMust(t, err)
		v := a.Step(Inputs{Triggers: Triggers{Drained: drained}, Drain: d, Probe: ClassOK, Gates: autoOpen}, now)
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
	if _, drained, _ := s.DrainFor(storeVIP); drained {
		t.Fatal("the new-node drain came back")
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
		if d, ok, err := s.DrainFor(key); !ok || err != nil || !strings.HasPrefix(d.Reason, "writer ") {
			t.Fatalf("DrainFor(%s) after the writers = (%+v, %v, %v)", key, d, ok, err)
		}
	}
	if left := storeTemporaries(t, s); len(left) != 0 {
		t.Fatalf("writes left %v behind", left)
	}
}

// TestStoreReadsAtMostAMegabyte: a drain file someone filled by mistake is
// still a drain, read in part; an oversized state.json is an error, not a
// birth.
func TestStoreReadsAtMostAMegabyte(t *testing.T) {
	s := storeNew(t)
	huge := strings.Repeat("x", 2*storeMaxFile)
	storeRaw(t, s, drainFileName, huge, storeT0)
	if _, ok, err := s.DrainFor(NodeKey); !ok || err == nil {
		t.Fatalf("an oversized drain file: (%v, %v), want drained, with an error", ok, err)
	}
	storeRaw(t, s, stateFileName, `{"version":1,"born":"`+huge+`"}`, storeT0)
	if _, born, err := s.Load(storeT0, DefaultHoldDownMax); born || err == nil {
		t.Fatalf("an oversized state.json: born %v, %v; want an error and no birth", born, err)
	}
}

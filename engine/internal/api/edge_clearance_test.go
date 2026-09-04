package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// clearanceNow is a fixed instant in the middle of a UTC day.
var clearanceNow = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func testKeyring(t *testing.T, path string) *clearanceKeyring {
	t.Helper()
	return testKeyringLogging(t, path, io.Discard)
}

// testKeyringLogging is testKeyring with the keyring's log captured in w.
func testKeyringLogging(t *testing.T, path string, w io.Writer) *clearanceKeyring {
	t.Helper()
	k := newClearanceKeyring(slog.New(slog.NewTextHandler(w, nil)))
	k.setPath(path)
	return k
}

func twoZones() edgedoc.Doc {
	d := edgedoc.Empty()
	d.Zones = append(d.Zones,
		edgedoc.Zone{Name: "a.example", Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}},
		edgedoc.Zone{Name: "b.example", Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}},
	)
	return d
}

// zoneSecret is zone a's first key secret after a fill — the thing a restart
// or a reload must never change by accident.
func zoneSecret(t *testing.T, k *clearanceKeyring, now time.Time) (string, edgedoc.Doc) {
	t.Helper()
	d := twoZones()
	k.fill(&d, now)
	if len(d.Zones[0].ClearanceKeys) == 0 {
		t.Fatal("no clearance keys after fill")
	}
	return d.Zones[0].ClearanceKeys[0].Secret, d
}

// TestClearanceFillIsDeterministicPerEpoch pins what makes the document's
// ETag honest: within one epoch two fills yield the same bytes, every zone
// gets its own key derived from the one master, and the key's window is the
// epoch's UTC day plus a day of grace.
func TestClearanceFillIsDeterministicPerEpoch(t *testing.T) {
	k := testKeyring(t, "")
	d1, d2 := twoZones(), twoZones()
	k.fill(&d1, clearanceNow)
	k.fill(&d2, clearanceNow.Add(11*time.Hour))
	b1, _ := json.Marshal(d1)
	b2, _ := json.Marshal(d2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("two fills in one epoch differ:\n%s\n%s", b1, b2)
	}
	if len(d1.Zones[0].ClearanceKeys) != 1 || len(d1.Zones[1].ClearanceKeys) != 1 {
		t.Fatalf("keys per zone: %+v", d1.Zones)
	}
	ka, kb := d1.Zones[0].ClearanceKeys[0], d1.Zones[1].ClearanceKeys[0]
	if ka.ID != "c20260904" || kb.ID != ka.ID {
		t.Fatalf("epoch id: %q %q", ka.ID, kb.ID)
	}
	if ka.Secret == kb.Secret {
		t.Fatal("two zones share a secret")
	}
	if !ka.NotBefore.Equal(time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)) || !ka.NotAfter.Equal(time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("window: %v..%v", ka.NotBefore, ka.NotAfter)
	}
	keys := clearanceKeysFor(&d1, "a.example")
	if len(keys) != 1 || len(keys[0].Secret) != clearance.SecretLen {
		t.Fatalf("decoded keys: %+v", keys)
	}
	tok, err := clearance.Issue(keys[0], "a.example", "203.0.113.4", clearance.KindPoW, clearanceNow.Add(time.Hour), clearanceNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := clearance.Verify(keys, "a.example", "203.0.113.4", tok, clearanceNow); !ok {
		t.Fatal("a token under the document's key does not verify")
	}
	if _, ok := clearance.Verify(clearanceKeysFor(&d1, "b.example"), "a.example", "203.0.113.4", tok, clearanceNow); ok {
		t.Fatal("zone b's key verified zone a's token")
	}
}

// TestClearanceRotation pins the epoch machinery: a new UTC day adds a key
// and notifies exactly once, the previous key stays a further day, and a
// third day drops it. untilNextChange points a parked poll at midnight.
func TestClearanceRotation(t *testing.T) {
	k := testKeyring(t, "")
	d := twoZones()
	k.fill(&d, clearanceNow)
	ch := k.Changed()
	select {
	case <-ch:
		t.Fatal("Changed fired with no rotation")
	default:
	}
	if got := k.untilNextChange(clearanceNow); got != 12*time.Hour {
		t.Fatalf("untilNextChange = %v, want 12h", got)
	}
	// Same epoch, later: nothing moves.
	k.fill(&d, clearanceNow.Add(11*time.Hour+59*time.Minute))
	select {
	case <-ch:
		t.Fatal("Changed fired inside the epoch")
	default:
	}
	// Next day: the new key joins, the old one stays, one notification.
	day2 := clearanceNow.Add(24 * time.Hour)
	k.fill(&d, day2)
	select {
	case <-ch:
	default:
		t.Fatal("Changed did not fire on the rotation")
	}
	ids := func() []string {
		var out []string
		for _, ck := range d.Zones[0].ClearanceKeys {
			out = append(out, ck.ID)
		}
		return out
	}
	if got := strings.Join(ids(), ","); got != "c20260904,c20260905" {
		t.Fatalf("keys after day 2: %s", got)
	}
	ch = k.Changed()
	k.fill(&d, day2.Add(time.Hour))
	select {
	case <-ch:
		t.Fatal("Changed fired again inside day 2")
	default:
	}
	// Day 3: the first key's 48 h are up.
	k.fill(&d, clearanceNow.Add(48*time.Hour))
	if got := strings.Join(ids(), ","); got != "c20260905,c20260906" {
		t.Fatalf("keys after day 3: %s", got)
	}
	select {
	case <-ch:
	default:
		t.Fatal("Changed did not fire when a key expired")
	}
	// Both live keys verify a token issued under the older one.
	keys := clearanceKeysFor(&d, "a.example")
	at := clearanceNow.Add(48*time.Hour + time.Minute)
	tok, err := clearance.Issue(keys[0], "a.example", "s", clearance.KindPoW, at.Add(time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := clearance.Verify(keys, "a.example", "s", tok, at); !ok {
		t.Fatal("previous-epoch key refused")
	}
}

// TestClearanceStateFileRoundTrip pins persistence: a keyring with a state
// file writes it 0600 at the first fill, a fresh keyring on the same path
// derives the same secrets (a restart does not re-key the fleet), the file
// holds masters and never a derived zone key, and no path means no file.
func TestClearanceStateFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge-state.json")
	k1 := testKeyring(t, path)
	s1, d1 := zoneSecret(t, k1, clearanceNow)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %o, want 600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"c20260904"`) || !strings.Contains(string(raw), `"kind": "kapkan-edge-clearance"`) || strings.Contains(string(raw), s1) {
		t.Fatalf("state file content: %s", raw)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left after a save: %v", entries)
	}
	k2 := testKeyring(t, path)
	s2, d2 := zoneSecret(t, k2, clearanceNow.Add(time.Hour))
	b1, _ := json.Marshal(d1)
	b2, _ := json.Marshal(d2)
	if s1 != s2 || !bytes.Equal(b1, b2) {
		t.Fatalf("keys differ after a restart:\n%s\n%s", b1, b2)
	}
	k4 := testKeyring(t, "")
	zoneSecret(t, k4, clearanceNow)
	entries, _ = os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a keyring without a path wrote files: %v", entries)
	}
}

// TestClearanceStateFileNeverClobbersAForeignFile pins the guard behind a
// mistyped path: content that is not a clearance state — an operator's YAML,
// the ban state or a node's document cache (both JSON carrying a bare
// "version": 1 of their own) — is left untouched and the keyring runs in
// memory; the empty husk a crash can leave behind is ours to overwrite.
func TestClearanceStateFileNeverClobbersAForeignFile(t *testing.T) {
	dir := t.TempDir()
	foreign := map[string]string{
		"zones.yaml":  "zones:\n  - name: a.example\n",
		"bans.json":   `{"version": 1, "saved_at": "2026-09-04T00:00:00Z", "host_bans": [{"ip": "203.0.113.9"}]}`,
		"zones.json":  `{"version":1,"zones":[{"name":"a.example"}],"acme_challenges":[],"issuance_grants":[]}`,
		"noname.json": `{"version": 1, "masters": []}`,
	}
	for name, body := range foreign {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		k := testKeyring(t, path)
		s, _ := zoneSecret(t, k, clearanceNow)
		if s == "" {
			t.Fatalf("%s: no keys in memory-only mode", name)
		}
		// Next day's rotation must not touch it either.
		zoneSecret(t, k, clearanceNow.Add(24*time.Hour))
		raw, _ := os.ReadFile(path)
		if string(raw) != body {
			t.Fatalf("%s: a foreign file was overwritten: %s", name, raw)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != len(foreign) {
		t.Fatalf("temp files left beside foreign files: %v", entries)
	}

	husk := filepath.Join(dir, "edge-state.json")
	if err := os.WriteFile(husk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	k2 := testKeyring(t, husk)
	zoneSecret(t, k2, clearanceNow)
	raw, _ := os.ReadFile(husk)
	if !json.Valid(raw) || !strings.Contains(string(raw), `"c20260904"`) {
		t.Fatalf("an empty husk was not replaced by the state: %q", raw)
	}
}

// TestClearanceSetPathPersistsAtOnceAndMerges pins the reload cases: a path
// adopted while memory already holds a master is written immediately, not at
// the next midnight; a file holding an older master is merged, memory
// winning on a duplicate ID (nodes hold those keys), and the file gains what
// it lacked.
func TestClearanceSetPathPersistsAtOnceAndMerges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge-state.json")
	// Memory-only brain, then edge.state_file appears on a reload mid-day.
	k := testKeyring(t, "")
	before, _ := zoneSecret(t, k, clearanceNow)
	k.setPath(path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not written when the path was adopted: %v", err)
	}
	after, _ := zoneSecret(t, k, clearanceNow.Add(time.Minute))
	if after != before {
		t.Fatal("adopting a path changed the live key")
	}
	restarted := testKeyring(t, path)
	if s, _ := zoneSecret(t, restarted, clearanceNow.Add(2*time.Minute)); s != before {
		t.Fatal("a restart after the reload re-keyed the fleet")
	}

	// A file from an earlier install holds yesterday's master and a
	// different (stale) master under today's ID: memory keeps its own.
	stale := filepath.Join(dir, "stale.json")
	old, _ := clearance.NewSecret()
	other, _ := clearance.NewSecret()
	st := clearanceState{Kind: clearanceStateKind, Version: clearanceStateVersion, Masters: []clearanceMaster{
		{ID: "c20260903", Master: old, NotBefore: clearanceNow.Add(-36 * time.Hour), NotAfter: clearanceNow.Add(12 * time.Hour)},
		{ID: "c20260904", Master: other, NotBefore: clearanceNow.Add(-12 * time.Hour), NotAfter: clearanceNow.Add(36 * time.Hour)},
	}}
	raw, _ := json.Marshal(st)
	if err := os.WriteFile(stale, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	k2 := testKeyring(t, "")
	live, _ := zoneSecret(t, k2, clearanceNow)
	k2.setPath(stale)
	merged, d := zoneSecret(t, k2, clearanceNow)
	ids := []string{}
	for _, ck := range d.Zones[0].ClearanceKeys {
		ids = append(ids, ck.ID)
	}
	if strings.Join(ids, ",") != "c20260903,c20260904" {
		t.Fatalf("merged ids: %v", ids)
	}
	if merged == live {
		// The first key is now yesterday's; today's must still be memory's.
		t.Fatal("ordering: yesterday's key should come first")
	}
	if d.Zones[0].ClearanceKeys[1].Secret != live {
		t.Fatal("the file's stale master replaced the live one nodes already hold")
	}
	var back clearanceState
	raw, _ = os.ReadFile(stale)
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Masters) != 2 || bytes.Equal(back.Masters[1].Master, other) {
		t.Fatalf("file after merge: %s (%v)", raw, err)
	}
}

// TestClearanceSaveFailureIsRetried pins the dirty flag: a save that fails
// (the state directory does not exist yet) is retried on the next snapshot
// — logged once for the streak, not once per poll — and succeeds once the
// operator fixes the directory, no midnight needed; recovery is logged once.
func TestClearanceSaveFailureIsRetried(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	path := filepath.Join(dir, "edge-state.json")
	var logs bytes.Buffer
	k := testKeyringLogging(t, path, &logs)
	s, _ := zoneSecret(t, k, clearanceNow)
	zoneSecret(t, k, clearanceNow.Add(time.Minute))
	zoneSecret(t, k, clearanceNow.Add(2*time.Minute))
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a file appeared in a missing directory")
	}
	if n := strings.Count(logs.String(), "level=ERROR"); n != 1 {
		t.Fatalf("errors logged for one failure streak = %d, want 1:\n%s", n, logs.String())
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	zoneSecret(t, k, clearanceNow.Add(3*time.Minute))
	zoneSecret(t, k, clearanceNow.Add(4*time.Minute))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("save not retried after the directory appeared: %v", err)
	}
	if n := strings.Count(logs.String(), "clearance keys persisted"); n != 1 {
		t.Fatalf("recovery logged %d times, want 1:\n%s", n, logs.String())
	}
	if got, _ := zoneSecret(t, testKeyring(t, path), clearanceNow.Add(5*time.Minute)); got != s {
		t.Fatal("the retried save persisted a different master")
	}
}

// TestEdgeZonesCarriesClearanceKeys pins the wire: the served document has
// one live key per zone, per-zone distinct, and a poll PARKED on the current
// ETag wakes when the keyring rotates — well before the hold deadline, so
// the wake is the keyring's notification, not the timer.
func TestEdgeZonesCarriesClearanceKeys(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesTwo)
	s := testServer(t, store)
	s.rulesHold = 10 * time.Second
	h := s.Handler()

	rec := getZones(h, "", "agent-secret", "e1")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET zones = %d: %s", rec.Code, rec.Body)
	}
	etag := rec.Header().Get("ETag")
	doc, err := edgedoc.Decode(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Zones) != 2 {
		t.Fatalf("zones: %d", len(doc.Zones))
	}
	for _, z := range doc.Zones {
		if len(z.ClearanceKeys) != 1 {
			t.Fatalf("zone %s keys: %+v", z.Name, z.ClearanceKeys)
		}
	}
	if doc.Zones[0].ClearanceKeys[0].Secret == doc.Zones[1].ClearanceKeys[0].Secret {
		t.Fatal("zones share a clearance secret on the wire")
	}
	// The same document again: the same ETag, not a new one.
	rec = getZones(h, "", "agent-secret", "e1")
	if rec.Header().Get("ETag") != etag {
		t.Fatalf("ETag moved without news: %s -> %s", etag, rec.Header().Get("ETag"))
	}

	// Park a poll on the current ETag — provably parked, the hold gate counts
	// it — then rotate the keyring from outside, as the day boundary would.
	type result struct {
		code int
		etag string
		body []byte
		took time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		r := getZones(h, etag, "agent-secret", "e1")
		done <- result{code: r.Code, etag: r.Header().Get("ETag"), body: r.Body.Bytes(), took: time.Since(start)}
	}()
	waitEdgeHolds(t, s, 1)
	scratch := edgedoc.Empty()
	s.edgeClearance.fill(&scratch, time.Now().Add(clearanceEpoch))
	select {
	case res := <-done:
		if res.code != http.StatusOK || res.etag == etag {
			t.Fatalf("woken poll: %d etag %s (was %s)", res.code, res.etag, etag)
		}
		if res.took > s.rulesHold/2 {
			t.Fatalf("poll answered after %v: that is the deadline, not the rotation", res.took)
		}
		doc, err := edgedoc.Decode(res.body)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Zones[0].ClearanceKeys) != 2 {
			t.Fatalf("keys after rotation: %+v", doc.Zones[0].ClearanceKeys)
		}
	case <-time.After(s.rulesHold + 2*time.Second):
		// Longer than the hold, so a deadline-driven answer reaches the
		// branch above and fails the `took` check instead of timing out here.
		t.Fatal("parked poll did not wake on the rotation")
	}
}

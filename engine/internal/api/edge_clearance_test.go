package api

import (
	"bytes"
	"encoding/json"
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
	k := newClearanceKeyring(nil)
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
// file writes it 0600 on rotation, a fresh keyring on the same path derives
// the same secrets (a restart does not re-key the fleet), a corrupt file
// yields fresh keys instead of a crash, and no path means no file.
func TestClearanceStateFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge-state.json")
	k1 := testKeyring(t, path)
	d1 := twoZones()
	k1.fill(&d1, clearanceNow)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %o, want 600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"c20260904"`) || strings.Contains(string(raw), d1.Zones[0].ClearanceKeys[0].Secret) {
		// The file holds masters, never a derived zone key.
		t.Fatalf("state file content: %s", raw)
	}
	k2 := testKeyring(t, path)
	d2 := twoZones()
	k2.fill(&d2, clearanceNow.Add(time.Hour))
	b1, _ := json.Marshal(d1)
	b2, _ := json.Marshal(d2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("keys differ after a restart:\n%s\n%s", b1, b2)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	k3 := testKeyring(t, path)
	d3 := twoZones()
	k3.fill(&d3, clearanceNow)
	if len(d3.Zones[0].ClearanceKeys) != 1 || d3.Zones[0].ClearanceKeys[0].Secret == d1.Zones[0].ClearanceKeys[0].Secret {
		t.Fatalf("corrupt state file did not yield fresh keys: %+v", d3.Zones[0].ClearanceKeys)
	}
	raw, _ = os.ReadFile(path)
	if !json.Valid(raw) {
		t.Fatal("the corrupt file was not rewritten on the next rotation")
	}
	k4 := testKeyring(t, "")
	d4 := twoZones()
	k4.fill(&d4, clearanceNow)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a keyring without a path wrote files: %v", entries)
	}
}

// TestEdgeZonesCarriesClearanceKeys pins the wire: the served document has
// one live key per zone, per-zone distinct, and a parked hold wakes when the
// keyring rotates — the ETag moves once.
func TestEdgeZonesCarriesClearanceKeys(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesTwo)
	s := testServer(t, store)
	s.rulesHold = 5 * time.Second
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
	// The same document again: a 304-style hold, not a new ETag.
	rec = getZones(h, "", "agent-secret", "e1")
	if rec.Header().Get("ETag") != etag {
		t.Fatalf("ETag moved without news: %s -> %s", etag, rec.Header().Get("ETag"))
	}

	// Park a poll on the current ETag, then rotate the keyring from outside
	// (as the day boundary would): the hold must wake with the new document.
	done := make(chan *zonesResult, 1)
	go func() {
		r := getZones(h, etag, "agent-secret", "e1")
		done <- &zonesResult{code: r.Code, etag: r.Header().Get("ETag"), body: r.Body.Bytes()}
	}()
	time.Sleep(100 * time.Millisecond)
	tomorrow := time.Now().Add(clearanceEpoch)
	scratch := edgedoc.Empty()
	s.edgeClearance.fill(&scratch, tomorrow)
	select {
	case res := <-done:
		if res.code != http.StatusOK || res.etag == etag {
			t.Fatalf("woken poll: %d etag %s (was %s)", res.code, res.etag, etag)
		}
		doc, err := edgedoc.Decode(res.body)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Zones[0].ClearanceKeys) != 2 {
			t.Fatalf("keys after rotation: %+v", doc.Zones[0].ClearanceKeys)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked poll did not wake on the rotation")
	}
}

type zonesResult struct {
	code int
	etag string
	body []byte
}

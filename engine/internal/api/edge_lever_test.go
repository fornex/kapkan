package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

func lever(h http.Handler, method, zone, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1/edge/zones/"+zone+"/challenge", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func zonesDoc(t *testing.T, h http.Handler) (EdgeDoc, string) {
	t.Helper()
	rec := getZones(h, "", "op-secret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET zones = %d", rec.Code)
	}
	var doc EdgeDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc, rec.Header().Get("ETag")
}

// TestEdgeChallengeLever pins the operator's lever: who may pull it, what it
// refuses, that a pull lands in the zones document with a new ETag and wakes
// a parked poll, that the response says where it bites, and that clearing —
// by DELETE or by mode off — puts the document back.
func TestEdgeChallengeLever(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	aw := &fakeAuditWriter{}
	s.SetAuditWriter(aw)
	h := s.Handler()
	set := `{"mode":"manual","ttl_seconds":600,"reason":"incident 42"}`
	// The node has reported (in dry-run) but not polled yet: the lever's
	// response must say so.
	if rec := postEdgeReport(h, "e1", `{"version":"1.8.0","dry_run":true}`, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d", rec.Code)
	}

	if rec := lever(h, http.MethodPost, "a.example", set, "scoped-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped operator = %d, want 403", rec.Code)
	}
	if rec := lever(h, http.MethodPost, "a.example", set, "agent-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("agent = %d, want 403", rec.Code)
	}
	if rec := lever(h, http.MethodPost, "nobody.example", set, "op-secret"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown zone = %d, want 404", rec.Code)
	}
	for name, body := range map[string]string{
		"bad mode":      `{"mode":"sometimes","ttl_seconds":600}`,
		"ttl too short": `{"mode":"manual","ttl_seconds":30}`,
		"ttl too long":  `{"mode":"auto","ttl_seconds":90000}`,
		"no ttl":        `{"mode":"manual"}`,
		"control char":  `{"mode":"manual","ttl_seconds":600,"reason":"a\u0007b"}`,
		"unknown key":   `{"mode":"manual","ttl_seconds":600,"until":"never"}`,
		"not json":      `{mode`,
	} {
		if rec := lever(h, http.MethodPost, "a.example", body, "op-secret"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400: %s", name, rec.Code, rec.Body)
		}
	}
	// A reason is 200 CHARACTERS, not bytes.
	if rec := lever(h, http.MethodPost, "a.example", `{"mode":"manual","ttl_seconds":600,"reason":"`+strings.Repeat("д", 150)+`"}`, "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("a 150-character Cyrillic reason = %d: %s", rec.Code, rec.Body)
	}
	if rec := lever(h, http.MethodPost, "a.example", `{"mode":"off"}`, "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("clear after the long reason = %d", rec.Code)
	}
	if len(aw.rows) != 2 || aw.rows[0].Action != "edge_challenge" || aw.rows[0].Result != "set" || aw.rows[1].Result != "cleared" {
		t.Fatalf("audit rows so far: %+v", aw.rows)
	}
	aw.rows = nil

	before, etag0 := zonesDoc(t, h)
	if before.Zones[0].ChallengeOverride != nil {
		t.Fatal("an override before any pull")
	}
	// A parked poll wakes when the lever is pulled — parked for real first.
	woke := make(chan *httptest.ResponseRecorder, 1)
	go func() { woke <- getZones(h, etag0, "agent-secret", "e1") }()
	waitEdgeHolds(t, s, 1)

	rec := lever(h, http.MethodPost, "a.example", set, "op-secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("set = %d: %s", rec.Code, rec.Body)
	}
	var resp EdgeChallengeLeverResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Zone != "a.example" || resp.Mode != edgedoc.ChallengeManual || resp.Until == nil || resp.Reason != "incident 42" || resp.FileMode != edgedoc.ChallengeOff || !resp.RungWatchOnly || resp.ZoneWatchOnly {
		t.Fatalf("set response: %+v", resp)
	}
	// Where the lever bites: e1 is alive (its poll is parked) and has said it
	// is in dry-run — the operator sees the lever would only preview there.
	if len(resp.Nodes) != 1 || resp.Nodes[0].Name != "e1" || !resp.Nodes[0].Alive || resp.Nodes[0].DryRun == nil || !*resp.Nodes[0].DryRun {
		t.Fatalf("nodes in the response: %+v", resp.Nodes)
	}
	if len(aw.rows) != 1 || aw.rows[0].Action != "edge_challenge" || aw.rows[0].Result != "set" || aw.rows[0].Target != "a.example" || aw.rows[0].TargetType != "zone" || !strings.Contains(aw.rows[0].Reason, "manual until ") || !strings.Contains(aw.rows[0].Reason, "incident 42") {
		t.Fatalf("audit row for the set: %+v", aw.rows)
	}
	// The zone status shows the lever even though no node has reported the
	// zone: it is brain state.
	if st, code := getEdgeZonesStatus(h, "op-secret"); code != http.StatusOK || len(st.Zones) != 1 || st.Zones[0].Zone != "a.example" || st.Zones[0].Override == nil || st.Zones[0].Override.Mode != edgedoc.ChallengeManual {
		t.Fatalf("zone status with the lever pulled: %d %+v", code, st)
	}
	if d := time.Until(*resp.Until); d < 9*time.Minute || d > 10*time.Minute {
		t.Fatalf("until = %v from now, want ~10 min", d)
	}
	select {
	case r := <-woke:
		if r.Code != http.StatusOK || r.Header().Get("ETag") == etag0 {
			t.Fatalf("the parked poll woke with %d %q", r.Code, r.Header().Get("ETag"))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the parked poll was not woken by the lever")
	}
	after, etag1 := zonesDoc(t, h)
	o := after.Zones[0].ChallengeOverride
	if etag1 == etag0 || o == nil || o.Mode != edgedoc.ChallengeManual || o.Reason != "incident 42" || !o.Until.Equal(*resp.Until) {
		t.Fatalf("document after the pull: etag=%q override=%+v", etag1, o)
	}
	if after.Zones[0].EffectiveChallenge(time.Now()) != edgedoc.ChallengeManual {
		t.Fatal("effective mode is not the override's")
	}
	// Pulling again replaces (a longer hold, another mode); the ETag moves.
	if rec := lever(h, http.MethodPost, "a.example", `{"mode":"auto","ttl_seconds":3600}`, "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("replace = %d", rec.Code)
	}
	again, etag2 := zonesDoc(t, h)
	if etag2 == etag1 || again.Zones[0].ChallengeOverride.Mode != edgedoc.ChallengeAuto {
		t.Fatalf("document after the second pull: %q %+v", etag2, again.Zones[0].ChallengeOverride)
	}
	// DELETE clears: the document is what it was, byte for byte, and the
	// clear is audited.
	if rec := lever(h, http.MethodDelete, "a.example", "", "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	cleared, etag3 := zonesDoc(t, h)
	if etag3 != etag0 || cleared.Zones[0].ChallengeOverride != nil {
		t.Fatalf("document after the clear: %q %+v", etag3, cleared.Zones[0].ChallengeOverride)
	}
	if last := aw.rows[len(aw.rows)-1]; last.Action != "edge_challenge" || last.Result != "cleared" || last.Target != "a.example" {
		t.Fatalf("audit row for the clear: %+v", last)
	}
	// So does mode off.
	lever(h, http.MethodPost, "a.example", set, "op-secret")
	if rec := lever(h, http.MethodPost, "a.example", `{"mode":"off","reason":"false alarm"}`, "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("off = %d: %s", rec.Code, rec.Body)
	}
	if _, etag4 := zonesDoc(t, h); etag4 != etag0 {
		t.Fatalf("document after mode off: %q, want %q", etag4, etag0)
	}
}

// TestEdgeChallengeLeverRefusesANoneZone pins that the lever is refused for
// a zone the decision service never sees.
func TestEdgeChallengeLeverRefusesANoneZone(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne+"    policy: {mode: none}\n")
	s := testServer(t, store)
	h := s.Handler()
	if rec := lever(h, http.MethodPost, "a.example", `{"mode":"manual","ttl_seconds":600}`, "op-secret"); rec.Code != http.StatusConflict {
		t.Fatalf("lever on a mode:none zone = %d, want 409: %s", rec.Code, rec.Body)
	}
}

// TestChallengeLeverLapses pins the store: a lapsed override leaves the
// document at the first snapshot after its until, and a parked poll is told
// when to wake for it.
func TestChallengeLeverLapses(t *testing.T) {
	l := newChallengeLever()
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	l.set("a.example", edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeManual, Until: now.Add(time.Minute)})
	l.set("b.example", edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeAuto, Until: now.Add(time.Hour)})
	if d := l.untilNextChange(now); d != time.Minute {
		t.Fatalf("untilNextChange = %v, want 1m", d)
	}
	doc := edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{Name: "a.example"}, edgedoc.Zone{Name: "b.example"}, edgedoc.Zone{Name: "c.example"})
	l.fill(&doc, now.Add(30*time.Second))
	if doc.Zones[0].ChallengeOverride == nil || doc.Zones[1].ChallengeOverride == nil || doc.Zones[2].ChallengeOverride != nil {
		t.Fatalf("fill before the lapse: %+v", doc.Zones)
	}
	doc = edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{Name: "a.example"}, edgedoc.Zone{Name: "b.example"})
	l.fill(&doc, now.Add(2*time.Minute))
	if doc.Zones[0].ChallengeOverride != nil || doc.Zones[1].ChallengeOverride == nil {
		t.Fatalf("fill after the lapse: %+v", doc.Zones)
	}
	if _, ok := l.get("a.example", now.Add(2*time.Minute)); ok {
		t.Fatal("a lapsed override is still reported")
	}
	if d := l.untilNextChange(now.Add(2 * time.Minute)); d != 58*time.Minute {
		t.Fatalf("untilNextChange after the lapse = %v, want 58m", d)
	}
	if !l.clear("b.example", now) || l.clear("b.example", now) {
		t.Fatal("clear did not report the live override, or reported a second time")
	}
	if d := l.untilNextChange(now); d != maxLeverTTL {
		t.Fatalf("untilNextChange with nothing set = %v, want a day", d)
	}
}

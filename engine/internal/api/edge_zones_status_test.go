package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func getEdgeZonesStatus(h http.Handler, bearer string) (EdgeZonesStatusDoc, int) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/edge/zones/status", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var doc EdgeZonesStatusDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	return doc, rec.Code
}

// TestEdgeZonesStatus pins the endpoint: unscoped tokens only; only ALIVE
// nodes' reports count (a report is never presence); the report's zones come
// back merged with their would-be set.
func TestEdgeZonesStatus(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	h := s.Handler()

	if _, code := getEdgeZonesStatus(h, "scoped-secret"); code != http.StatusForbidden {
		t.Fatalf("scoped token = %d, want 403", code)
	}
	body := `{"version":"1.8.0","zones":[{"zone":"a.example","at":"2026-09-06T12:00:10Z","window_seconds":10,"rps":42.5,"requests":425,"decided":420,` +
		`"denied":30,"challenged":5,"would_challenge":12,"would_deny":3,"dry_run":true,` +
		`"challenge_active":{"reason":"zone-rps","until":"2026-09-06T12:05:00Z"},` +
		`"top_sources":[{"source":"203.0.113.9","rps":20,"requests":200,"state":"would-deny"},{"source":"203.0.113.10","rps":1,"requests":10,"state":"would-challenge"},{"source":"203.0.113.11","rps":1,"requests":10,"state":"allow"}]}]}`
	if rec := postEdgeReport(h, "e1", body, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d (%s)", rec.Code, rec.Body.String())
	}
	// Reported, never polled: not alive, so nothing is merged.
	if doc, code := getEdgeZonesStatus(h, "op-secret"); code != http.StatusOK || doc.NodesReporting != 0 || len(doc.Zones) != 0 {
		t.Fatalf("before a poll: %d %+v", code, doc)
	}
	// The zones poll is presence.
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	doc, code := getEdgeZonesStatus(h, "op-secret")
	if code != http.StatusOK || doc.NodesReporting != 1 || len(doc.Zones) != 1 {
		t.Fatalf("after the poll: %d %+v", code, doc)
	}
	z := doc.Zones[0]
	if z.Zone != "a.example" || z.Nodes != 1 || z.RPS != 42.5 || z.Requests != 425 || z.Challenged != 5 || z.WouldChallenge != 12 || z.WouldDeny != 3 {
		t.Fatalf("zone figures: %+v", z)
	}
	if len(z.WatchOnly) != 1 || z.WatchOnly[0] != "e1" || len(z.ChallengeActive) != 1 || z.ChallengeActive[0].Node != "e1" || z.ChallengeActive[0].Reason != "zone-rps" {
		t.Fatalf("watch-only / challenge: %+v", z)
	}
	if len(z.WouldBe) != 2 || z.WouldBe[0].Source != "203.0.113.9" || z.WouldBe[0].State != SourceStateWouldDeny || z.WouldBe[1].State != SourceStateWouldChallenge || z.WouldBe[0].Nodes[0] != "e1" {
		t.Fatalf("would-be set: %+v", z.WouldBe)
	}
}

// TestMergeEdgeZones pins the merge across nodes: sums, the union of the
// would-be set with the stronger state and every node that saw the source,
// deterministic order, the per-node bound, and nodes without zones not
// counted as reporting.
func TestMergeEdgeZones(t *testing.T) {
	until := time.Date(2026, 9, 6, 12, 5, 0, 0, time.UTC)
	src := func(ip, state string, n uint64) EdgeReportSource {
		return EdgeReportSource{Source: ip, Requests: n, State: state}
	}
	reports := map[string]EdgeReport{
		"e2": {Zones: []EdgeReportZone{
			{Zone: "b.example", RPS: 1, Requests: 10},
			{Zone: "a.example", RPS: 10, Requests: 100, WouldDeny: 4, TopSources: []EdgeReportSource{
				src("203.0.113.1", SourceStateWouldChallenge, 50), src("203.0.113.2", SourceStateWouldDeny, 40), src("203.0.113.3", SourceStateDenied, 30)}},
		}},
		"e1": {Zones: []EdgeReportZone{
			{Zone: "a.example", RPS: 5, Requests: 50, Challenged: 2, DryRun: true, ChallengeActive: &EdgeReportChallenge{Reason: "manual", Until: until}, TopSources: []EdgeReportSource{
				src("203.0.113.1", SourceStateWouldDeny, 20), src("203.0.113.4", SourceStateWouldChallenge, 5)}},
		}},
		"e3": {Version: "1.8.0"}, // alive, no zones: not reporting zones
	}
	doc := mergeEdgeZones(reports)
	if doc.NodesReporting != 2 || len(doc.Zones) != 2 || doc.Zones[0].Zone != "a.example" || doc.Zones[1].Zone != "b.example" {
		t.Fatalf("doc: %+v", doc)
	}
	a := doc.Zones[0]
	if a.Nodes != 2 || a.RPS != 15 || a.Requests != 150 || a.Challenged != 2 || a.WouldDeny != 4 {
		t.Fatalf("a sums: %+v", a)
	}
	if len(a.WatchOnly) != 1 || a.WatchOnly[0] != "e1" || len(a.ChallengeActive) != 1 || a.ChallengeActive[0].Node != "e1" || !a.ChallengeActive[0].Until.Equal(until) {
		t.Fatalf("a flags: %+v", a)
	}
	// .1 seen by both (would-challenge on e2, would-deny on e1 → would-deny,
	// 70 requests, nodes e1,e2); .2 by e2; .4 by e1; .3 is denied, not would-be.
	want := []EdgeZoneWouldBe{
		{Source: "203.0.113.1", State: SourceStateWouldDeny, Requests: 70, Nodes: []string{"e1", "e2"}},
		{Source: "203.0.113.2", State: SourceStateWouldDeny, Requests: 40, Nodes: []string{"e2"}},
		{Source: "203.0.113.4", State: SourceStateWouldChallenge, Requests: 5, Nodes: []string{"e1"}},
	}
	got, _ := json.Marshal(a.WouldBe)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("would-be:\n got %s\nwant %s", got, exp)
	}
	if b := doc.Zones[1]; b.Nodes != 1 || b.RPS != 1 || len(b.WouldBe) != 0 || len(b.WatchOnly) != 0 {
		t.Fatalf("b: %+v", b)
	}
	// The bound: one node names 25 would-be sources; 20 survive, 5 are counted.
	many := EdgeReport{Zones: []EdgeReportZone{{Zone: "c.example"}}}
	for i := 0; i < 25; i++ {
		many.Zones[0].TopSources = append(many.Zones[0].TopSources, src("198.51.100."+string(rune('0'+i/10))+string(rune('0'+i%10)), SourceStateWouldChallenge, uint64(100-i)))
	}
	c := mergeEdgeZones(map[string]EdgeReport{"e9": many}).Zones[0]
	if len(c.WouldBe) != wouldBePerNode || c.WouldBeTruncated != 5 || c.WouldBe[0].Requests != 100 {
		t.Fatalf("bound: %d kept, %d truncated, first %+v", len(c.WouldBe), c.WouldBeTruncated, c.WouldBe[0])
	}
}

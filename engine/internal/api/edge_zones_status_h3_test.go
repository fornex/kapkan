package api

import (
	"net/http"
	"strings"
	"testing"
)

// Through the handler: `enabled` is the zones file's word and shows for a zone
// that asks even before a node serves it; the nodes' lists and the h3 request
// sum join it once a report arrives.
func TestEdgeZonesStatusH3(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne+`    tls: {h3: true}
  - name: b.example
    origins: ["10.0.0.2:8080"]
`)
	s := testServer(t, store)
	h := s.Handler()
	body := `{"version":"1.9.0","terminator":{"kind":"nginx","version":"1.30.4","h3":{"state":"ready","module":true,"serving":["a.example"],"listening":true}},` +
		`"zones":[{"zone":"a.example","requests":40,"h3_requests":15},{"zone":"b.example","requests":3}]}`
	if rec := postEdgeReport(h, "e1", body, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	doc, code := getEdgeZonesStatus(h, "op-secret")
	if code != http.StatusOK || len(doc.Zones) != 2 {
		t.Fatalf("status: %d %+v", code, doc)
	}
	a, b := doc.Zones[0], doc.Zones[1]
	if a.Zone != "a.example" || a.H3 == nil || !a.H3.Enabled || strings.Join(a.H3.Serving, ",") != "e1" || len(a.H3.Unsupported) != 0 || a.H3.Requests != 15 {
		t.Fatalf("a.example h3 = %+v", a.H3)
	}
	if b.Zone != "b.example" || b.H3 != nil {
		t.Fatalf("b.example must carry no h3 section: %+v", b.H3)
	}
}

// `h3.enabled` is the zones file's word and must show even before any node
// serves the zone: a node that reports the zone but carries no terminator.h3
// (an older or no_module node), and a zone present only through a lever.
func TestEdgeZonesStatusH3EnabledBeforeServing(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne+`    tls: {h3: true}
  - name: lever-only.example
    origins: ["10.0.0.9:8080"]
    tls: {h3: true}
`)
	s := testServer(t, store)
	h := s.Handler()
	// e1 reports a.example in its zones section but has no terminator.h3 lists
	// and no h3_requests — the "enabled before any node serves it" case.
	body := `{"version":"1.9.0","terminator":{"kind":"nginx","version":"1.22.1"},"zones":[{"zone":"a.example","requests":9}]}`
	if rec := postEdgeReport(h, "e1", body, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	// A lever on the other h3 zone, which no node reports at all.
	lreq := `{"mode":"manual","ttl_seconds":600,"reason":"x"}`
	if rec := lever(h, http.MethodPost, "lever-only.example", lreq, "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("lever = %d (%s)", rec.Code, rec.Body.String())
	}
	doc, code := getEdgeZonesStatus(h, "op-secret")
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	byZone := map[string]EdgeZoneStatus{}
	for _, z := range doc.Zones {
		byZone[z.Zone] = z
	}
	a := byZone["a.example"]
	if a.H3 == nil || !a.H3.Enabled || len(a.H3.Serving) != 0 || len(a.H3.Unsupported) != 0 || a.H3.Requests != 0 {
		t.Fatalf("a.example enabled before serving: %+v", a.H3)
	}
	lv := byZone["lever-only.example"]
	if lv.Override == nil || lv.H3 == nil || !lv.H3.Enabled {
		t.Fatalf("lever-only zone must carry h3.enabled after the lever pass: h3=%+v override=%v", lv.H3, lv.Override)
	}
}

// The merged status names, per zone, the nodes serving it over QUIC and the
// nodes that degraded it to TCP, and sums the HTTP/3 requests; a zone no node
// speaks or asks h3 for carries no h3 section (the handler adds `enabled`
// from the zones file on top).
func TestMergeEdgeZonesH3(t *testing.T) {
	reports := map[string]EdgeReport{
		"e1": {
			Terminator: &EdgeReportTerminator{H3: &EdgeReportH3{State: H3StateReady, Serving: []string{"a.example", "c.example"}}},
			Zones:      []EdgeReportZone{{Zone: "a.example", Requests: 10, H3Requests: 4}, {Zone: "b.example", Requests: 3}},
		},
		"e2": {
			Terminator: &EdgeReportTerminator{H3: &EdgeReportH3{State: H3StateNoModule, Unsupported: []string{"a.example"}}},
			Zones:      []EdgeReportZone{{Zone: "a.example", Requests: 7}, {Zone: "b.example", Requests: 1}},
		},
		"e3": {
			// An older node: no terminator.h3 at all, no h3_requests.
			Terminator: &EdgeReportTerminator{Kind: "nginx"},
			Zones:      []EdgeReportZone{{Zone: "a.example", Requests: 2}},
		},
	}
	doc := mergeEdgeZones(reports)
	byZone := map[string]EdgeZoneStatus{}
	for _, z := range doc.Zones {
		byZone[z.Zone] = z
	}
	a := byZone["a.example"]
	if a.H3 == nil {
		t.Fatalf("a.example: no h3 section: %+v", a)
	}
	if strings.Join(a.H3.Serving, ",") != "e1" || strings.Join(a.H3.Unsupported, ",") != "e2" || a.H3.Requests != 4 || a.H3.Enabled {
		t.Errorf("a.example h3 = %+v", *a.H3)
	}
	if a.Requests != 19 || a.Nodes != 3 {
		t.Errorf("a.example totals unchanged by h3: requests %d nodes %d", a.Requests, a.Nodes)
	}
	if b := byZone["b.example"]; b.H3 != nil {
		t.Errorf("b.example: nobody speaks or asks h3, yet %+v", *b.H3)
	}
	// c.example is served over QUIC on e1 but reported in no zones section
	// (a mode: none zone): it has no status entry, and that is the documented
	// shape — the zones section lists deciding zones.
	if _, ok := byZone["c.example"]; ok {
		t.Error("c.example appeared without a zones-section entry")
	}
}

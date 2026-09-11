package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// Placement (E6.3): a node's document is the zones its scope covers; the
// fills, the ACME coordination, the status, the lever and the history follow
// it.
//
// The fixture: hostgroups edge-us, edge-eu and edge-asia (no node lists
// edge-asia); nodes e1 {edge-us}, e2 {edge-eu, global}; zones us.example
// (edge-us, tenant acme, h3), eu.example (edge-eu, h3), g.example (global),
// as.example (edge-asia — placed where no node reaches). Tokens a1 -> e1,
// a2 -> e2 (bound: a scope requires it), op (unscoped), av (a viewer scoped
// to acme).
const placementZones = `
zones:
  - name: us.example
    hostgroup: edge-us
    tenant: acme
    origins: ["10.0.0.1:8080"]
    tls: { h3: true }
  - name: eu.example
    hostgroup: edge-eu
    origins: ["10.0.0.2:8080"]
    tls: { h3: true }
  - name: g.example
    origins: ["10.0.0.3:8080"]
  - name: as.example
    hostgroup: edge-asia
    origins: ["10.0.0.4:8080"]
`

const placementTokens = "    - { name: a1, token_env: TEST_PL_A1, role: agent, node: e1 }\n" +
	"    - { name: a2, token_env: TEST_PL_A2, role: agent, node: e2 }\n" +
	"    - { name: op, token_env: TEST_PL_OP, role: operator }\n" +
	"    - { name: av, token_env: TEST_PL_AV, role: viewer, tenant: acme }\n"

const placementNodes = "    - name: e1\n      hostgroups: [edge-us]\n    - name: e2\n      hostgroups: [edge-eu, global]\n"

// placementConfig renders the fixture's kapkan.yaml over a zones file.
func placementConfig(zonesPath, tokens, nodes string) string {
	return apiYAML +
		"  tokens:\n" + tokens +
		"hostgroups:\n" +
		"  - name: edge-us\n    networks: [\"203.0.113.0/26\"]\n" +
		"  - name: edge-eu\n    networks: [\"203.0.113.64/26\"]\n" +
		"  - name: edge-asia\n    networks: [\"203.0.113.128/26\"]\n" +
		"edge:\n  zones_file: " + zonesPath + "\n  nodes:\n" + nodes
}

// placementStore builds the fixture; scoped=false leaves every node without
// a scope (the pre-E6.3 fleet) over the same zones file minus the labels.
// The kapkan.yaml sits beside the zones file (filepath.Dir(zonesPath)).
func placementStore(t *testing.T, scoped bool) (*config.Store, string) {
	t.Helper()
	t.Setenv("TEST_PL_A1", "a1-secret")
	t.Setenv("TEST_PL_A2", "a2-secret")
	t.Setenv("TEST_PL_OP", "op-secret")
	t.Setenv("TEST_PL_AV", "av-secret")
	dir := t.TempDir()
	zonesPath := filepath.Join(dir, "zones.yaml")
	zones, nodes := placementZones, placementNodes
	if !scoped {
		zones = strings.ReplaceAll(zones, "    hostgroup: edge-us\n", "")
		zones = strings.ReplaceAll(zones, "    hostgroup: edge-eu\n", "")
		zones = strings.ReplaceAll(zones, "    hostgroup: edge-asia\n", "")
		nodes = "    - name: e1\n    - name: e2\n"
	}
	if err := os.WriteFile(zonesPath, []byte(zones), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "kapkan.yaml")
	if err := os.WriteFile(cfgPath, []byte(placementConfig(zonesPath, placementTokens, nodes)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return config.NewStore(cfgPath, cfg), zonesPath
}

func docZones(t *testing.T, body string) []string {
	t.Helper()
	var doc EdgeDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	names := make([]string, 0, len(doc.Zones))
	for _, z := range doc.Zones {
		names = append(names, z.Name)
	}
	return names
}

// TestEdgePlacementGoldenWithoutScopes: a fleet that never set a scope or a
// label gets one document — the same bytes and ETag for every node and for
// the operator's bare GET — so E6.3 changes nothing for it.
func TestEdgePlacementGoldenWithoutScopes(t *testing.T) {
	store, _ := placementStore(t, false)
	h := testServer(t, store).Handler()
	e1 := getZones(h, "", "a1-secret", "e1")
	e2 := getZones(h, "", "a2-secret", "e2")
	op := getZones(h, "", "op-secret", "")
	if e1.Code != http.StatusOK || e2.Code != http.StatusOK || op.Code != http.StatusOK {
		t.Fatalf("polls: %d %d %d", e1.Code, e2.Code, op.Code)
	}
	if e1.Body.String() != e2.Body.String() || e1.Body.String() != op.Body.String() || e1.Header().Get("ETag") != e2.Header().Get("ETag") || e1.Header().Get("ETag") != op.Header().Get("ETag") {
		t.Fatalf("an unscoped fleet must get one document:\n%s\n%s\n%s", e1.Body.String(), e2.Body.String(), op.Body.String())
	}
	if got := docZones(t, op.Body.String()); strings.Join(got, ",") != "as.example,eu.example,g.example,us.example" {
		t.Fatalf("the whole file: %v", got)
	}
}

// TestEdgePlacementDocumentsPerNode: with scopes each node receives exactly
// the zones its scope covers, with its own stable ETag; the bare GET is the
// whole file; a node scoped to one group does not get the global zones and a
// node listing global does; a node name the configuration lacks gets nothing.
func TestEdgePlacementDocumentsPerNode(t *testing.T) {
	store, _ := placementStore(t, true)
	s := testServer(t, store)
	h := s.Handler()
	e1 := getZones(h, "", "a1-secret", "e1")
	e2 := getZones(h, "", "a2-secret", "e2")
	op := getZones(h, "", "op-secret", "")
	if got := docZones(t, e1.Body.String()); strings.Join(got, ",") != "us.example" {
		t.Fatalf("e1 [edge-us] document: %v, want us.example only (no global zone)", got)
	}
	if got := docZones(t, e2.Body.String()); strings.Join(got, ",") != "eu.example,g.example" {
		t.Fatalf("e2 [edge-eu, global] document: %v, want eu.example and g.example", got)
	}
	if got := docZones(t, op.Body.String()); strings.Join(got, ",") != "as.example,eu.example,g.example,us.example" {
		t.Fatalf("operator's bare GET: %v, want the whole file", got)
	}
	tags := map[string]bool{e1.Header().Get("ETag"): true, e2.Header().Get("ETag"): true, op.Header().Get("ETag"): true}
	if len(tags) != 3 {
		t.Fatalf("three different documents must carry three ETags: %v", tags)
	}
	if again := getZones(h, "", "a1-secret", "e1"); again.Header().Get("ETag") != e1.Header().Get("ETag") || again.Body.String() != e1.Body.String() {
		t.Fatal("a node's document is not stable across two polls")
	}
	// A hold on the node's own ETag holds (the whole file's ETag would be
	// "changed" for it and answer at once).
	if rec := getZones(h, op.Header().Get("ETag"), "a1-secret", "e1"); rec.Code != http.StatusOK || rec.Header().Get("ETag") != e1.Header().Get("ETag") {
		t.Fatalf("polling e1 with the operator's ETag = %d %s, want e1's document at once", rec.Code, rec.Header().Get("ETag"))
	}
	// The placement never enters the document.
	if strings.Contains(op.Body.String(), "hostgroup") || strings.Contains(op.Body.String(), "edge-us") {
		t.Fatalf("placement leaked into the document: %s", op.Body.String())
	}
	// A named node the configuration does not have serves nothing — the
	// snapshot is the empty document, never the whole file (fail-closed).
	body, _, err := s.edgeSnapshotFor("ghost")
	if err != nil {
		t.Fatal(err)
	}
	if got := docZones(t, string(body)); len(got) != 0 {
		t.Fatalf("an unconfigured node's snapshot carries zones: %v", got)
	}
}

// TestEdgePlacementHoldIsPerNode: two nodes parked on their own ETags; a
// challenge published for e2's zone wakes e2's hold at once and leaves e1's
// parked; e1's hold ends on the deadline with a 304 that names e1's own ETag.
func TestEdgePlacementHoldIsPerNode(t *testing.T) {
	store, _ := placementStore(t, true)
	s := testServer(t, store)
	s.rulesHold = 3 * time.Second // bounds the FAILURE mode and ends e1's hold
	h := s.Handler()
	e1 := getZones(h, "", "a1-secret", "e1")
	e2 := getZones(h, "", "a2-secret", "e2")
	done1 := make(chan *httptest.ResponseRecorder, 1)
	done2 := make(chan *httptest.ResponseRecorder, 1)
	go func() { done1 <- getZones(h, e1.Header().Get("ETag"), "a1-secret", "e1") }()
	go func() { done2 <- getZones(h, e2.Header().Get("ETag"), "a2-secret", "e2") }()
	waitEdgeHolds(t, s, 2)
	start := time.Now()
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/slot", `{"zone":"eu.example"}`, "a2-secret"); rec.Code != http.StatusOK {
		t.Fatalf("e2 slot = %d %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/challenges", challengeBody("eu.example", validToken, validKeyAuth), "a2-secret"); rec.Code/100 != 2 {
		t.Fatalf("e2 publish = %d %s", rec.Code, rec.Body.String())
	}
	select {
	case rec := <-done2:
		// The slot itself is news for e2 (its grant enters the document), so
		// the wake may carry the grant, the challenge, or both — either way
		// eu.example's coordination and a moved ETag.
		if elapsed := time.Since(start); elapsed > s.rulesHold/2 {
			t.Fatalf("e2's hold took %v to answer its zone's coordination; want a prompt wake", elapsed)
		}
		news := strings.Contains(rec.Body.String(), validKeyAuth) || strings.Contains(rec.Body.String(), `"zone":"eu.example","node":"e2"`)
		if rec.Code != http.StatusOK || rec.Header().Get("ETag") == e2.Header().Get("ETag") || !news {
			t.Fatalf("e2's woken hold = %d, etag %s: %s", rec.Code, rec.Header().Get("ETag"), rec.Body.String())
		}
	case <-time.After(s.rulesHold):
		t.Fatal("e2's hold did not wake for coordination on its own zone")
	}
	time.Sleep(200 * time.Millisecond)
	select {
	case rec := <-done1:
		t.Fatalf("e1's hold answered (%d) for another node's zone", rec.Code)
	default:
	}
	if heldEdgePolls(s) != 1 {
		t.Fatalf("edge holds = %d, want e1's alone", heldEdgePolls(s))
	}
	// The deadline: e1's document did not change, so a 304 naming e1's ETag —
	// not the whole file's.
	select {
	case rec := <-done1:
		if rec.Code != http.StatusNotModified || rec.Header().Get("ETag") != e1.Header().Get("ETag") {
			t.Fatalf("e1's hold ended with %d, etag %s; want 304 with e1's own ETag %s", rec.Code, rec.Header().Get("ETag"), e1.Header().Get("ETag"))
		}
	case <-time.After(2 * s.rulesHold):
		t.Fatal("e1's hold never ended")
	}
}

// TestEdgePlacementDecommissionedNodeHoldGetsNothing: a node cut out of the
// fleet by a reload while parked in its hold is answered 404, never a
// document — and a first poll by an unconfigured name is the same 404.
func TestEdgePlacementDecommissionedNodeHoldGetsNothing(t *testing.T) {
	store, zonesPath := placementStore(t, true)
	cfgPath := filepath.Join(filepath.Dir(zonesPath), "kapkan.yaml")
	s := testServer(t, store)
	s.rulesHold = 3 * time.Second
	h := s.Handler()
	e1 := getZones(h, "", "a1-secret", "e1")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- getZones(h, e1.Header().Get("ETag"), "a1-secret", "e1") }()
	waitEdgeHolds(t, s, 1)
	// The incident runbook's move: e1 and its token leave the configuration.
	tokens := strings.Replace(placementTokens, "    - { name: a1, token_env: TEST_PL_A1, role: agent, node: e1 }\n", "", 1)
	if err := os.WriteFile(cfgPath, []byte(placementConfig(zonesPath, tokens, "    - name: e2\n      hostgroups: [edge-eu, global]\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("Reload without e1: %v", err)
	}
	select {
	case rec := <-done:
		if rec.Code != http.StatusNotFound {
			t.Fatalf("the removed node's parked poll = %d %s, want 404", rec.Code, rec.Body.String())
		}
		for _, z := range []string{"us.example", "eu.example", "g.example", "as.example", "clearance_keys", "issuance_grants"} {
			if strings.Contains(rec.Body.String(), z) {
				t.Fatalf("the removed node's answer carries %q: %s", z, rec.Body.String())
			}
		}
	case <-time.After(s.rulesHold):
		t.Fatal("the removed node's hold was not answered by the reload")
	}
	// A fresh poll for the removed name (the operator's preview; a bound token
	// would be refused as another node first) is the same 404.
	if rec := getZones(h, "", "op-secret", "e1"); rec.Code != http.StatusNotFound {
		t.Fatalf("a fresh poll for the removed node = %d, want 404", rec.Code)
	}
}

// TestEdgePlacementFanOut: an ACME challenge published for e2's zone and a
// lever set on it reach e2's document and only e2's — e1's document and ETag
// do not move.
func TestEdgePlacementFanOut(t *testing.T) {
	store, _ := placementStore(t, true)
	s := testServer(t, store)
	h := s.Handler()
	e1Before := getZones(h, "", "a1-secret", "e1")
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/slot", `{"zone":"eu.example"}`, "a2-secret"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"granted":true`) {
		t.Fatalf("e2 slot for eu.example = %d %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/challenges", challengeBody("eu.example", validToken, validKeyAuth), "a2-secret"); rec.Code/100 != 2 {
		t.Fatalf("e2 publish = %d %s", rec.Code, rec.Body.String())
	}
	if rec := lever(h, http.MethodPost, "eu.example", `{"mode":"manual","ttl_seconds":600}`, "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("lever on eu.example = %d %s", rec.Code, rec.Body.String())
	}
	e2 := getZones(h, "", "a2-secret", "e2")
	if !strings.Contains(e2.Body.String(), validKeyAuth) || !strings.Contains(e2.Body.String(), "challenge_override") {
		t.Fatalf("e2's document lacks the challenge or the lever: %s", e2.Body.String())
	}
	e1After := getZones(h, "", "a1-secret", "e1")
	if e1After.Header().Get("ETag") != e1Before.Header().Get("ETag") || e1After.Body.String() != e1Before.Body.String() {
		t.Fatalf("e1's document moved for another node's zone:\n%s\n%s", e1Before.Body.String(), e1After.Body.String())
	}
	if strings.Contains(e1After.Body.String(), validKeyAuth) {
		t.Fatal("e1 received a challenge for a zone it does not serve")
	}
}

// TestEdgePlacementACMEOutsideScope: a node asking for the slot of, or
// publishing for, a zone its scope does not cover gets the byte-identical
// "unknown zone" a nonexistent zone gets.
func TestEdgePlacementACMEOutsideScope(t *testing.T) {
	store, _ := placementStore(t, true)
	h := testServer(t, store).Handler()
	unknown := postJSON(h, "/api/v1/edge/nodes/e1/acme/slot", `{"zone":"nope.example"}`, "a1-secret")
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("slot for a nonexistent zone = %d", unknown.Code)
	}
	for _, zone := range []string{"eu.example", "g.example", "as.example"} {
		if rec := postJSON(h, "/api/v1/edge/nodes/e1/acme/slot", `{"zone":"`+zone+`"}`, "a1-secret"); rec.Code != http.StatusNotFound || rec.Body.String() != unknown.Body.String() {
			t.Fatalf("e1 slot for %s (outside its scope) = %d %q, want the unknown-zone answer", zone, rec.Code, rec.Body.String())
		}
		if rec := postJSON(h, "/api/v1/edge/nodes/e1/acme/challenges", challengeBody(zone, validToken, validKeyAuth), "a1-secret"); rec.Code != http.StatusNotFound || rec.Body.String() != unknown.Body.String() {
			t.Fatalf("e1 publish for %s (outside its scope) = %d %q, want the unknown-zone answer", zone, rec.Code, rec.Body.String())
		}
	}
	if rec := postJSON(h, "/api/v1/edge/nodes/e1/acme/slot", `{"zone":"us.example"}`, "a1-secret"); rec.Code != http.StatusOK {
		t.Fatalf("e1 slot for its own zone = %d", rec.Code)
	}
}

// TestEdgePlacementStatusLeverInventory: the status carries each file zone's
// placement and flags an unserved one; a node's claims about a zone outside
// its scope — its window, its certificate, its QUIC listener — are stored but
// not merged; a tenant sees node names but not the operator's hostgroup; the
// lever lists the placement; the inventory shows each node's scope and
// placed zone count.
func TestEdgePlacementStatusLeverInventory(t *testing.T) {
	store, _ := placementStore(t, true)
	s := testServer(t, store)
	h := s.Handler()
	// e1 alive and reporting about its zone AND about eu.example and g.example,
	// which it does not serve; e2 never polls.
	if rec := getZones(h, "", "a1-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	report := `{"version":"1.8.0",` +
		`"terminator":{"kind":"nginx","version":"1.26.3","h3":{"state":"ready","module":true,"listening":true,"serving":["us.example","eu.example"],"unsupported":["g.example"]}},` +
		`"certs":[{"zone":"eu.example","not_after":"2026-12-01T00:00:00Z"}],"zones":[` +
		`{"zone":"us.example","rps":10,"requests":100},{"zone":"eu.example","rps":5,"requests":50}]}`
	if rec := postEdgeReport(h, "e1", report, "a1-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d %s", rec.Code, rec.Body.String())
	}
	st, code := getEdgeZonesStatus(h, "op-secret")
	if code != http.StatusOK || len(st.Zones) != 4 {
		t.Fatalf("status = %d %+v", code, st)
	}
	byName := map[string]EdgeZoneStatus{}
	for _, z := range st.Zones {
		byName[z.Zone] = z
	}
	us := byName["us.example"]
	if us.Nodes != 1 || us.Requests != 100 || us.Placement == nil || us.Placement.Hostgroup != "edge-us" || strings.Join(us.Placement.Nodes, ",") != "e1" || strings.Join(us.Placement.Alive, ",") != "e1" || us.Unserved || us.Tenant != "acme" {
		t.Fatalf("us.example: %+v (placement %+v)", us, us.Placement)
	}
	if us.H3 == nil || !us.H3.Enabled || strings.Join(us.H3.Serving, ",") != "e1" {
		t.Fatalf("us.example h3 (e1 serves it over QUIC): %+v", us.H3)
	}
	eu := byName["eu.example"]
	if eu.Nodes != 0 || eu.Requests != 0 || len(eu.Certs) != 0 || eu.Placement == nil || eu.Placement.Hostgroup != "edge-eu" || strings.Join(eu.Placement.Nodes, ",") != "e2" || len(eu.Placement.Alive) != 0 || !eu.Unserved {
		t.Fatalf("eu.example (e1's claim ignored; e2 not alive): %+v (placement %+v)", eu, eu.Placement)
	}
	if eu.H3 != nil && len(eu.H3.Serving) != 0 {
		t.Fatalf("eu.example h3.serving carries a node that does not serve the zone: %+v", eu.H3)
	}
	g := byName["g.example"]
	if g.Placement == nil || g.Placement.Hostgroup != config.GlobalGroup || strings.Join(g.Placement.Nodes, ",") != "e2" || !g.Unserved {
		t.Fatalf("g.example: %+v", g.Placement)
	}
	if g.H3 != nil && len(g.H3.Unsupported) != 0 {
		t.Fatalf("g.example h3.unsupported carries e1's claim about a zone it does not serve: %+v", g.H3)
	}
	as := byName["as.example"]
	if as.Placement == nil || as.Placement.Hostgroup != "edge-asia" || len(as.Placement.Nodes) != 0 || as.Unserved {
		t.Fatalf("as.example (no node reaches edge-asia): %+v unserved=%v", as.Placement, as.Unserved)
	}
	// The tenant's view: its zone, the nodes it is served on, no hostgroup.
	tst, code := getEdgeZonesStatus(h, "av-secret")
	if code != http.StatusOK || len(tst.Zones) != 1 || tst.Zones[0].Zone != "us.example" || tst.Zones[0].Tenant != "" {
		t.Fatalf("acme's status = %d %+v, want us.example alone without the tenant field", code, tst.Zones)
	}
	if pl := tst.Zones[0].Placement; pl == nil || pl.Hostgroup != "" || strings.Join(pl.Nodes, ",") != "e1" || strings.Join(pl.Alive, ",") != "e1" {
		t.Fatalf("acme's placement view = %+v, want the node names and no hostgroup", pl)
	}
	// The report itself is stored verbatim.
	inv, _ := getEdgeNodes(h, "op-secret")
	nodes := map[string]EdgeNodeStatus{}
	for _, n := range inv.Nodes {
		nodes[n.Name] = n
	}
	if nodes["e1"].Report == nil || len(nodes["e1"].Report.Zones) != 2 {
		t.Fatalf("e1's report not stored verbatim: %+v", nodes["e1"].Report)
	}
	if strings.Join(nodes["e1"].Hostgroups, ",") != "edge-us" || nodes["e1"].ZonesPlaced != 1 || strings.Join(nodes["e2"].Hostgroups, ",") != "edge-eu,global" || nodes["e2"].ZonesPlaced != 2 {
		t.Fatalf("inventory scopes: e1 %v/%d e2 %v/%d", nodes["e1"].Hostgroups, nodes["e1"].ZonesPlaced, nodes["e2"].Hostgroups, nodes["e2"].ZonesPlaced)
	}
	// The lever lists the zone's placement, not the fleet.
	rec := lever(h, http.MethodPost, "g.example", `{"mode":"manual","ttl_seconds":600}`, "op-secret")
	var resp EdgeChallengeLeverResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("lever on g.example = %d %s", rec.Code, rec.Body.String())
	}
	if len(resp.Nodes) != 1 || resp.Nodes[0].Name != "e2" || resp.Nodes[0].Alive {
		t.Fatalf("lever nodes for g.example = %+v, want e2 alone, not alive", resp.Nodes)
	}
	rec = lever(h, http.MethodPost, "us.example", `{"mode":"manual","ttl_seconds":600}`, "op-secret")
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Nodes) != 1 || resp.Nodes[0].Name != "e1" || !resp.Nodes[0].Alive {
		t.Fatalf("lever nodes for us.example = %+v, want e1 alone, alive", resp.Nodes)
	}
}

// TestEdgePlacementHistoryIgnoresClaimsOutsideScope: the history is the
// durable merge — a node's window, sources and certificate for a zone its
// scope does not cover are written nowhere and counted as outside_scope.
func TestEdgePlacementHistoryIgnoresClaimsOutsideScope(t *testing.T) {
	store, _ := placementStore(t, true)
	s := testServer(t, store)
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	h := s.Handler()
	before := dropped("outside_scope")
	at := time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339)
	win := func(zone, at string, n int) string {
		return fmt.Sprintf(`{"zone":%q,"at":%q,"window_seconds":10,"requests":%d,"decided":%d,"top_sources":[{"source":"203.0.113.9","requests":%d,"state":"would-deny"}]}`, zone, at, n, n, n)
	}
	if rec := postEdgeReport(h, "e1", `{"version":"1.8.0","zones":[`+win("us.example", at, 5)+","+win("eu.example", at, 7)+`]}`, "a1-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d %s", rec.Code, rec.Body.String())
	}
	if len(hw.windows) != 1 || hw.windows[0].Zone != "us.example" || len(hw.sources) != 1 || hw.sources[0].Zone != "us.example" {
		t.Fatalf("windows %+v sources %+v: want us.example only", hw.windows, hw.sources)
	}
	if got := dropped("outside_scope") - before; got != 1 {
		t.Fatalf("dropped{outside_scope} moved by %v, want 1 (eu.example's window)", got)
	}
	at2 := time.Now().UTC().Add(-4 * time.Second).Format(time.RFC3339)
	rep := `{"version":"1.8.0","certs":[{"zone":"eu.example","not_after":"2026-12-01T00:00:00Z"},{"zone":"us.example","not_after":"2026-12-01T00:00:00Z"}],` +
		`"zones":[` + win("us.example", at2, 6) + "," + win("eu.example", at2, 8) + `]}`
	if rec := postEdgeReport(h, "e1", rep, "a1-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("second report = %d", rec.Code)
	}
	for _, w := range hw.windows {
		if w.Zone != "us.example" {
			t.Fatalf("a window for %s was written by a node that does not serve it", w.Zone)
		}
	}
	if k := hw.kinds(); len(k) != 1 || k[0] != EventCertIssued+":us.example" {
		t.Fatalf("events = %v, want cert_issued for us.example alone (eu.example's certificate is outside e1's scope)", k)
	}
	if got := dropped("outside_scope") - before; got != 3 {
		t.Fatalf("dropped{outside_scope} moved by %v, want 3 (two windows, one certificate)", got)
	}
}

// TestEdgePlacementHoldFollowsTheBinding: a poll parked when a reload moves
// its token to another node, or removes the token, ends with the refusal a
// first poll would now get — 403 or 401 — promptly, never a document.
func TestEdgePlacementHoldFollowsTheBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tokens string
		want   int
	}{
		{"token rebound to another node", strings.Replace(placementTokens, "role: agent, node: e1", "role: agent, node: e2", 1), http.StatusForbidden},
		{"token removed", strings.Replace(placementTokens, "    - { name: a1, token_env: TEST_PL_A1, role: agent, node: e1 }\n", "", 1), http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, zonesPath := placementStore(t, true)
			cfgPath := filepath.Join(filepath.Dir(zonesPath), "kapkan.yaml")
			s := testServer(t, store)
			s.rulesHold = 3 * time.Second
			h := s.Handler()
			e1 := getZones(h, "", "a1-secret", "e1")
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- getZones(h, e1.Header().Get("ETag"), "a1-secret", "e1") }()
			waitEdgeHolds(t, s, 1)
			if err := os.WriteFile(cfgPath, []byte(placementConfig(zonesPath, tc.tokens, placementNodes)), 0o600); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			if _, err := store.Reload(); err != nil {
				t.Fatalf("Reload: %v", err)
			}
			select {
			case rec := <-done:
				if rec.Code != tc.want || strings.Contains(rec.Body.String(), "us.example") {
					t.Fatalf("the parked poll ended with %d %s, want %d and no document", rec.Code, rec.Body.String(), tc.want)
				}
				if elapsed := time.Since(start); elapsed > s.rulesHold/2 {
					t.Fatalf("the parked poll took %v to end after the reload; want the wake, not the deadline", elapsed)
				}
			case <-time.After(2 * s.rulesHold):
				t.Fatal("the parked poll did not end after the reload")
			}
		})
	}
}

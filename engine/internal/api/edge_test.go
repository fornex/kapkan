package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// The edge channel is the scrub channel's twin, so these tests mirror
// rules_test.go / nodes_test.go case for case, plus what is new here: the wake
// comes from a config reload, and presence lives in the api package.

const edgeZonesOne = `
zones:
  - name: a.example
    origins: ["10.0.0.1:8080"]
`

const edgeZonesTwo = edgeZonesOne + `  - name: b.example
    origins: ["10.0.0.2:8080"]
    policy: {mode: none}
`

// edgeStore builds a Store from real files — a kapkan.yaml (apiYAML plus an
// agent and an operator token and an edge block) referencing a zones.yaml — so
// the zones are LOADED (storeFromYAML uses Parse, which never reads them) and a
// test can rewrite the zones file and Reload. Requests must carry a bearer:
// configuring tokens ends open mode.
func edgeStore(t *testing.T, zonesYAML string) (store *config.Store, zonesPath string) {
	t.Helper()
	t.Setenv("TEST_EDGE_AGENT", "agent-secret")
	t.Setenv("TEST_EDGE_OP", "op-secret")
	dir := t.TempDir()
	zonesPath = filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zonesPath, []byte(zonesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "kapkan.yaml")
	yaml := apiYAML +
		"  tokens:\n" +
		"    - { name: agent, token_env: TEST_EDGE_AGENT, role: agent }\n" +
		"    - { name: op, token_env: TEST_EDGE_OP, role: operator }\n" +
		"\nedge:\n  zones_file: " + zonesPath + "\n  nodes:\n    - name: e1\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return config.NewStore(cfgPath, cfg), zonesPath
}

func getZones(h http.Handler, inm, bearer, node string) *httptest.ResponseRecorder {
	target := "/api/v1/edge/zones"
	if node != "" {
		target += "?node=" + node
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if inm != "" {
		r.Header.Set("If-None-Match", inm)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func postEdgeReport(h http.Handler, name, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/edge/nodes/"+name+"/report", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func getEdgeNodes(h http.Handler, bearer string) (EdgeNodesDoc, int) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/edge/nodes", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var doc EdgeNodesDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	return doc, rec.Code
}

func heldEdgePolls(s *Server) int {
	s.edgeHolds.mu.Lock()
	defer s.edgeHolds.mu.Unlock()
	return s.edgeHolds.held
}

func waitEdgeHolds(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for heldEdgePolls(s) != n {
		if time.Now().After(deadline) {
			t.Fatalf("edge holds = %d, want %d (timed out waiting)", heldEdgePolls(s), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestBuildEdgeDocIsDeterministicAndSorted: same zones in any order → identical
// bytes and ETag, zones sorted by name, and a nil zones file yields the empty
// document with every array present (never null).
func TestBuildEdgeDocIsDeterministicAndSorted(t *testing.T) {
	a, err := config.ParseZones([]byte(edgeZonesTwo))
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.ParseZones([]byte(`
zones:
  - name: b.example
    origins: ["10.0.0.2:8080"]
    policy: {mode: none}
  - name: a.example
    origins: ["10.0.0.1:8080"]
`))
	if err != nil {
		t.Fatal(err)
	}
	ba, ea, _ := edgeDocBytes(buildEdgeDoc(a))
	bb, eb, _ := edgeDocBytes(buildEdgeDoc(b))
	if string(ba) != string(bb) || ea != eb {
		t.Fatalf("doc bytes/ETag differ for the same zones in a different order:\n%s\n%s", ba, bb)
	}
	doc := buildEdgeDoc(b)
	if len(doc.Zones) != 2 || doc.Zones[0].Name != "a.example" || doc.Zones[1].Name != "b.example" {
		t.Errorf("zones not sorted by name: %+v", doc.Zones)
	}
	if doc.Zones[1].Policy.Mode != config.ZonePolicyNone || doc.Zones[0].Policy.Mode != config.ZonePolicyDecide {
		t.Errorf("policy modes not carried: %+v", doc.Zones)
	}
	if doc.Zones[0].Policy.FailureMode != config.ZoneFailOpen || doc.Zones[0].Policy.Challenge != config.ZoneChallengeOff || doc.Zones[0].TLS.MinVersion != config.ZoneTLS12 {
		t.Errorf("defaults not resolved in the document: %+v", doc.Zones[0])
	}

	empty, _, _ := edgeDocBytes(buildEdgeDoc(nil))
	for _, want := range []string{`"version":1`, `"zones":[]`, `"acme_challenges":[]`, `"issuance_grants":[]`} {
		if !strings.Contains(string(empty), want) {
			t.Errorf("empty doc %s lacks %s", empty, want)
		}
	}
	if strings.Contains(string(empty), "null") {
		t.Errorf("empty doc must never encode null arrays: %s", empty)
	}
}

func TestEdgeDocETagChangesWithContent(t *testing.T) {
	one, _ := config.ParseZones([]byte(edgeZonesOne))
	two, _ := config.ParseZones([]byte(edgeZonesTwo))
	_, e1, _ := edgeDocBytes(buildEdgeDoc(one))
	_, e2, _ := edgeDocBytes(buildEdgeDoc(two))
	if e1 == e2 {
		t.Fatal("ETag unchanged although a zone was added")
	}
	_, e1b, _ := edgeDocBytes(buildEdgeDoc(one))
	if e1 != e1b {
		t.Fatal("ETag not stable across two encodings of the same zones")
	}
}

func TestEdgeZonesServesDocument(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	h := s.Handler()

	rec := getZones(h, "", "agent-secret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the zones document")
	}
	var doc EdgeDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Version != edgeDocVersion || len(doc.Zones) != 1 || doc.Zones[0].Name != "a.example" {
		t.Fatalf("doc = %+v", doc)
	}
	if doc.Zones[0].Origins[0] != "10.0.0.1:8080" || doc.Zones[0].Policy.Mode != config.ZonePolicyDecide {
		t.Errorf("zone content = %+v", doc.Zones[0])
	}
	// The operator may curl what the agent sees.
	if rec := getZones(h, "", "op-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("operator GET = %d, want 200", rec.Code)
	}
	// A matching If-None-Match with nothing changed is a hold; with a short
	// budget it ends in 304 (covered separately) — here confirm a MISMATCH is
	// answered immediately.
	if rec := getZones(h, `"stale"`, "agent-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("mismatched If-None-Match = %d, want an immediate 200", rec.Code)
	}
}

// TestEdgeZonesLongPollWakesOnReload is the new thing about this channel: the
// held poll is released by a successful CONFIG RELOAD that changed the zones,
// via Store.Changed — not by the mitigator.
func TestEdgeZonesLongPollWakesOnReload(t *testing.T) {
	store, zonesPath := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	s.rulesHold = 3 * time.Second // bounds the FAILURE mode; a pass never waits this long
	h := s.Handler()

	etag := getZones(h, "", "agent-secret", "").Header().Get("ETag")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- getZones(h, etag, "agent-secret", "") }()
	waitEdgeHolds(t, s, 1)

	if err := os.WriteFile(zonesPath, []byte(edgeZonesTwo), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	rec := <-done
	if rec.Code != http.StatusOK {
		t.Fatalf("held poll = %d, want 200 after the zones reload", rec.Code)
	}
	var doc EdgeDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Zones) != 2 {
		t.Fatalf("woken doc = %+v, want both zones", doc)
	}
	if rec.Header().Get("ETag") == etag {
		t.Error("woken response carries the stale ETag")
	}
}

// TestEdgeZonesReloadWithoutZoneChangeKeepsHolding: a reload that did not alter
// the zones (Store.Changed fires on ANY successful reload) must not answer the
// poll with a spurious "changed" — the loop re-hashes and keeps holding.
func TestEdgeZonesReloadWithoutZoneChangeKeepsHolding(t *testing.T) {
	store, zonesPath := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	s.rulesHold = 300 * time.Millisecond
	h := s.Handler()

	etag := getZones(h, "", "agent-secret", "").Header().Get("ETag")
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- getZones(h, etag, "agent-secret", "") }()
	waitEdgeHolds(t, s, 1)

	// Same bytes, rewritten: a successful reload with an identical document.
	if err := os.WriteFile(zonesPath, []byte(edgeZonesOne), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	rec := <-done
	if rec.Code != http.StatusNotModified {
		t.Fatalf("poll after a no-op reload = %d, want 304 on the deadline (not a spurious 200)", rec.Code)
	}
}

func TestEdgeZonesHoldTimesOut(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	s.rulesHold = 50 * time.Millisecond
	h := s.Handler()

	etag := getZones(h, "", "agent-secret", "").Header().Get("ETag")
	rec := getZones(h, etag, "agent-secret", "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("timed-out hold = %d, want 304", rec.Code)
	}
	if got := rec.Header().Get("ETag"); got != etag {
		t.Errorf("304 ETag = %q, want %q", got, etag)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("304 Cache-Control = %q, want no-cache", got)
	}
	if heldEdgePolls(s) != 0 {
		t.Errorf("edge holds = %d after timeout, want 0 (leak)", heldEdgePolls(s))
	}
}

// TestEdgeZonesHoldCap: the edge channel has its own gate, so its per-token cap
// applies independently of the scrub channel's (zero scrub holds are consumed).
func TestEdgeZonesHoldCap(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	s.rulesHold = 2 * time.Second
	h := s.Handler()

	etag := getZones(h, "", "agent-secret", "").Header().Get("ETag")
	results := make(chan *httptest.ResponseRecorder, maxRuleHoldsPerToken)
	for i := 0; i < maxRuleHoldsPerToken; i++ {
		go func() { results <- getZones(h, etag, "agent-secret", "") }()
	}
	waitEdgeHolds(t, s, maxRuleHoldsPerToken)

	rec := getZones(h, etag, "agent-secret", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("hold beyond the per-token cap = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 lacks Retry-After")
	}
	if heldPolls(s) != 0 {
		t.Errorf("scrub holds = %d, want 0 — the edge channel must not consume the scrub gate", heldPolls(s))
	}
	// An instant (non-held) response is never counted against the cap.
	if rec := getZones(h, `"stale"`, "agent-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("instant response while capped = %d, want 200", rec.Code)
	}
	for i := 0; i < maxRuleHoldsPerToken; i++ {
		<-results // let the parked polls time out before the test ends
	}
}

// TestEdgeZonesNodeIdentity covers the three ?node= rules: a real credential is
// required, the name must be a configured edge node, and a sighting shows up as
// presence in the inventory — while a bare (node-less) poll records nothing.
func TestEdgeZonesNodeIdentity(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	h := s.Handler()

	if rec := getZones(h, "", "agent-secret", "nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown node = %d, want 404", rec.Code)
	}
	doc, code := getEdgeNodes(h, "op-secret")
	if code != http.StatusOK {
		t.Fatalf("GET /edge/nodes = %d, want 200", code)
	}
	if doc.NodesTotal != 1 || len(doc.Nodes) != 1 || doc.Nodes[0].Name != "e1" || doc.Nodes[0].Alive {
		t.Fatalf("inventory before any poll = %+v, want e1 configured and not alive", doc)
	}
	if doc.StaleAfterSeconds != 15 {
		t.Errorf("stale_after_seconds = %d, want the default 15", doc.StaleAfterSeconds)
	}

	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll as e1 = %d, want 200", rec.Code)
	}
	doc, _ = getEdgeNodes(h, "op-secret")
	if !doc.Nodes[0].Alive || doc.Nodes[0].LastSeen == "" {
		t.Errorf("inventory after a poll = %+v, want e1 alive with last_seen", doc.Nodes[0])
	}
	// The agent (rank 0) is denied the inventory, as in the scrub channel.
	if _, code := getEdgeNodes(h, "agent-secret"); code != http.StatusForbidden {
		t.Errorf("agent GET /edge/nodes = %d, want 403", code)
	}
}

// TestEdgeZonesNodeIdentityNeedsToken: in token-less open mode a node sighting
// is refused (the side-effectful GET sits outside the POST-only CSRF gate).
func TestEdgeZonesNodeIdentityNeedsToken(t *testing.T) {
	// Parse-only store: the zones file is never read, which is fine here — the
	// refusal happens before the document is built.
	s := testServer(t, storeFromYAML(t, apiYAML+"\nedge:\n  zones_file: /etc/kapkan/zones.yaml\n  nodes:\n    - name: e1\n"))
	h := s.Handler()
	rec := getZones(h, "", "", "e1")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("open-mode ?node= = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "requires an API token") {
		t.Errorf("body = %s, want the token requirement spelled out", rec.Body.String())
	}
	// Without ?node= the bare poll still works in open mode (an operator's curl).
	if rec := getZones(h, "", "", ""); rec.Code != http.StatusOK {
		t.Errorf("bare open-mode GET = %d, want 200", rec.Code)
	}
}

func TestEdgeNodeReport(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	h := s.Handler()

	if rec := postEdgeReport(h, "nope", `{}`, "agent-secret"); rec.Code != http.StatusNotFound {
		t.Errorf("report for unknown node = %d, want 404", rec.Code)
	}
	big := `{"version":"` + strings.Repeat("x", maxEdgeReportBytes) + `"}`
	if rec := postEdgeReport(h, "e1", big, "agent-secret"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized report = %d, want 413", rec.Code)
	}
	if rec := postEdgeReport(h, "e1", `{not json`, "agent-secret"); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed report = %d, want 400", rec.Code)
	}

	body := `{"version":"1.7.0","dry_run":true,"zones_etag":"\"abc\"",` +
		`"terminator":{"kind":"nginx","version":"1.22.1","generation":3,"test_ok":true},` +
		`"certs":[{"zone":"a.example","not_after":"2027-01-01T00:00:00Z","issuer":"pebble"}]}`
	if rec := postEdgeReport(h, "e1", body, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("valid report = %d (%s), want 204", rec.Code, rec.Body.String())
	}

	doc, _ := getEdgeNodes(h, "op-secret")
	n := doc.Nodes[0]
	if n.Report == nil || n.ReportedAt == "" {
		t.Fatalf("inventory lacks the report: %+v", n)
	}
	if n.Report.Version != "1.7.0" || !n.Report.DryRun || n.Report.Terminator == nil || n.Report.Terminator.Generation != 3 || !n.Report.Terminator.TestOK {
		t.Errorf("report not stored verbatim: %+v", n.Report)
	}
	if len(n.Report.Certs) != 1 || n.Report.Certs[0].Zone != "a.example" {
		t.Errorf("certs not stored: %+v", n.Report.Certs)
	}
	// A report is NEVER presence: the node has only reported, never polled.
	if n.Alive {
		t.Error("a self-report made the node alive; only the zones poll may")
	}
}

// TestEdgeReportCarriesNoKeyMaterial pins the contract that a report — written
// with the least-guarded token in the deployment — has no field that could ever
// carry a private key: no json key mentions key/private/secret/pem. (The zone
// document's key_authorization is the PUBLIC ACME token digest, and lives in
// EdgeDoc, not in the report.)
func TestEdgeReportCarriesNoKeyMaterial(t *testing.T) {
	var check func(t reflect.Type, path string)
	check = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			for _, bad := range []string{"key", "private", "secret", "pem"} {
				if strings.Contains(strings.ToLower(tag), bad) {
					t.Errorf("%s.%s has json key %q — a report must never carry key material", path, f.Name, tag)
				}
			}
			check(f.Type, path+"."+f.Name)
		}
	}
	check(reflect.TypeOf(EdgeReport{}), "EdgeReport")
}

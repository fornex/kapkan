package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// bindingOpts shapes the binding tests' kapkan.yaml (bindingYAML).
type bindingOpts struct {
	// unbound leaves every agent token without a node — the file a fleet has
	// before its migration; the document it yields must be byte-identical.
	unbound bool
	// twin adds a token sharing a1's secret: "bound" under another binding
	// (e2), "unbound" with none. Either is a reused secret, refused as ambiguous.
	twin string
	// edgeNodes is the edge fleet's size (at least e1 and e2).
	edgeNodes int
}

// bindingYAML is the brain of the binding tests: two edge nodes (e1, e2, more
// when asked), two scrub nodes (fra1, fra2) and the tokens: a1 bound to e1, a2
// to e2, s1 to fra1, a0 unbound (the grace case), op an unscoped operator.
// Secrets are the token names suffixed "-secret".
func bindingYAML(zonesPath string, o bindingOpts) string {
	node := func(n string) string {
		if o.unbound {
			return ""
		}
		return ", node: " + n
	}
	extra := ""
	switch o.twin {
	case "bound":
		extra = "    - { name: twin, token_env: TEST_BIND_TWIN, role: agent, node: e2 }\n"
	case "unbound":
		extra = "    - { name: twin, token_env: TEST_BIND_TWIN, role: agent }\n"
	}
	nodes := ""
	for i := 1; i <= max(2, o.edgeNodes); i++ {
		nodes += fmt.Sprintf("    - name: e%d\n", i)
	}
	return apiYAML +
		"  tokens:\n" +
		"    - { name: a0, token_env: TEST_BIND_A0, role: agent }\n" +
		"    - { name: a1, token_env: TEST_BIND_A1, role: agent" + node("e1") + " }\n" +
		"    - { name: a2, token_env: TEST_BIND_A2, role: agent" + node("e2") + " }\n" +
		"    - { name: s1, token_env: TEST_BIND_S1, role: agent" + node("fra1") + " }\n" +
		"    - { name: op, token_env: TEST_BIND_OP, role: operator }\n" + extra +
		"scrubbing:\n  next_hop: \"192.0.2.9\"\n  nodes:\n    - name: fra1\n      next_hop: \"192.0.2.10\"\n    - name: fra2\n      next_hop: \"192.0.2.11\"\n" +
		"edge:\n  zones_file: " + zonesPath + "\n  nodes:\n" + nodes
}

// bindingStoreWith loads bindingYAML from real files (the zones file is a
// second file Load follows) and returns the store with both paths, so a test
// can rewrite kapkan.yaml and Reload.
func bindingStoreWith(t *testing.T, o bindingOpts) (store *config.Store, cfgPath, zonesPath string) {
	t.Helper()
	for _, n := range []string{"A0", "A1", "A2", "S1", "OP"} {
		t.Setenv("TEST_BIND_"+n, strings.ToLower(n)+"-secret")
	}
	t.Setenv("TEST_BIND_TWIN", "a1-secret")
	dir := t.TempDir()
	zonesPath = filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zonesPath, []byte(edgeZonesOne), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "kapkan.yaml")
	if err := os.WriteFile(cfgPath, []byte(bindingYAML(zonesPath, o)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return config.NewStore(cfgPath, cfg), cfgPath, zonesPath
}

func bindingStore(t *testing.T) *config.Store {
	t.Helper()
	s, _, _ := bindingStoreWith(t, bindingOpts{})
	return s
}

func postJSON(h http.Handler, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func getWith(h http.Handler, path, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// slotHeld reports whether the coordinator holds a live grant for the zone.
func slotHeld(s *Server, zone string) bool {
	s.edgeIssuance.mu.Lock()
	defer s.edgeIssuance.mu.Unlock()
	_, held := s.edgeIssuance.grants[zone]
	return held
}

// A bound token acting as another node is refused on every node-identified
// route of the edge channel — and the refusal leaves NO trace: no presence, no
// stored report, no slot, no published challenge, no audit row. The body never
// names the bound node.
func TestNodeBindingRefusesAnotherNodeOnTheEdgeChannel(t *testing.T) {
	s := testServer(t, bindingStore(t))
	aw := &fakeAuditWriter{}
	s.SetStorageWriter(aw)
	h := s.Handler()

	// Poll as the other node.
	rec := getZones(h, "", "a1-secret", "e2")
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "e1") {
		t.Fatalf("a1 polling as e2 = %d %q, want 403 that does not name e1", rec.Code, rec.Body.String())
	}
	if last, holding := s.edgePresence.seen("e2"); !last.IsZero() || holding {
		t.Fatal("a refused poll stamped e2's presence")
	}
	// Report as the other node.
	if rec := postEdgeReport(h, "e2", `{"version":"x"}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 reporting as e2 = %d", rec.Code)
	}
	if _, _, ok := s.edgeReports.get("e2"); ok {
		t.Fatal("a refused report was stored")
	}
	// ACME slot as the other node: refused, and no grant exists afterwards.
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/slot", `{"zone":"a.example"}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 acquiring e2's slot = %d", rec.Code)
	}
	if slotHeld(s, "a.example") {
		t.Fatal("a refused slot request left a grant")
	}
	// A bound token that names no node is a misconfiguration, not a bare curl.
	if rec := getZones(h, "", "a1-secret", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 polling without ?node= = %d, want 403", rec.Code)
	}
	if len(aw.rows) != 0 {
		t.Fatalf("refusals wrote %d audit rows; a refusal is not an action", len(aw.rows))
	}

	// Its own node: everything works, and presence is stamped by the agent.
	if rec := getZones(h, "", "a1-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("a1 polling as e1 = %d", rec.Code)
	}
	if last, _ := s.edgePresence.seen("e1"); last.IsZero() {
		t.Fatal("a1's own poll did not stamp e1's presence")
	}
	if got := s.edgePresence.lastTokenOf("e1"); got != "a1" {
		t.Fatalf("last_token for e1 = %q, want a1", got)
	}
	if rec := postEdgeReport(h, "e1", `{"version":"x"}`, "a1-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("a1 reporting as e1 = %d", rec.Code)
	}
	rec = postJSON(h, "/api/v1/edge/nodes/e1/acme/slot", `{"zone":"a.example"}`, "a1-secret")
	var slot EdgeSlotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &slot); rec.Code != http.StatusOK || err != nil || !slot.Granted || slot.Holder != "" {
		t.Fatalf("a1 acquiring e1's slot = %d %s, want granted", rec.Code, rec.Body.String())
	}
	if rec := postJSON(h, "/api/v1/edge/nodes/e1/acme/slot", `{"zone":"a.example","release":true}`, "a1-secret"); rec.Code/100 != 2 {
		t.Fatalf("a1 releasing e1's slot = %d %s", rec.Code, rec.Body.String())
	}
	if slotHeld(s, "a.example") {
		t.Fatal("the released slot is still held")
	}

	// Publication: e2 holds the zone's slot (its own token), so a publish as e2
	// WOULD fan out — and a1 presenting e2 is still refused, with nothing in the
	// document; a2 then publishes and the fan-out is visible. This is what makes
	// the "publishes nothing" check bite: without the slot the publish would be
	// refused for want of it, whatever the token.
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/slot", `{"zone":"a.example"}`, "a2-secret"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"granted":true`) {
		t.Fatalf("a2 acquiring e2's slot = %d %s", rec.Code, rec.Body.String())
	}
	body := challengeBody("a.example", validToken, validKeyAuth)
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/challenges", body, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 publishing as e2 = %d", rec.Code)
	}
	if rec := getZones(h, "", "op-secret", ""); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), validKeyAuth) {
		t.Fatalf("document after the refused publish: %d, contains the key authorization: %v", rec.Code, strings.Contains(rec.Body.String(), validKeyAuth))
	}
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/challenges", body, "a2-secret"); rec.Code/100 != 2 {
		t.Fatalf("a2 publishing as e2 = %d %s", rec.Code, rec.Body.String())
	}
	if rec := getZones(h, "", "op-secret", ""); !strings.Contains(rec.Body.String(), validKeyAuth) {
		t.Fatalf("the slot holder's publish did not reach the document: %s", rec.Body.String())
	}
	if len(aw.rows) != 0 {
		t.Fatalf("node routes wrote %d audit rows", len(aw.rows))
	}
}

// The scrub channel is the edge channel's twin: the same helper, the same
// refusal on the rules poll and the report, before any side effect — a refused
// poll stamps no scrub presence (which would keep a victim's traffic diverted
// into a dead box), a refused report is not stored — and the operator's ?node=
// is a presence-free preview here too.
func TestNodeBindingRefusesAnotherNodeOnTheScrubChannel(t *testing.T) {
	s := testServer(t, bindingStore(t))
	aw := &fakeAuditWriter{}
	s.SetStorageWriter(aw)
	h := s.Handler()
	// s1 is bound to fra1: an edge name, no name, or the OTHER configured scrub
	// node are all refused.
	if rec := getWith(h, "/api/v1/dataplane/rules?node=e1", "s1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("s1 polling rules as e1 = %d", rec.Code)
	}
	if rec := getWith(h, "/api/v1/dataplane/rules", "s1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("s1 polling rules without ?node= = %d, want 403", rec.Code)
	}
	if rec := getWith(h, "/api/v1/dataplane/rules?node=fra2", "s1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("s1 polling rules as fra2 = %d, want 403", rec.Code)
	}
	if last, holding := s.mit.NodeSeen("fra2"); !last.IsZero() || holding {
		t.Fatal("a refused scrub poll stamped fra2's presence")
	}
	// The operator's preview of fra1 moves no liveness.
	if rec := getWith(h, "/api/v1/dataplane/rules?node=fra1", "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("operator preview of fra1 = %d", rec.Code)
	}
	if last, holding := s.mit.NodeSeen("fra1"); !last.IsZero() || holding {
		t.Fatal("an operator's ?node= preview stamped scrub presence")
	}
	// The node's own poll does.
	if rec := getWith(h, "/api/v1/dataplane/rules?node=fra1", "s1-secret"); rec.Code != http.StatusOK {
		t.Fatalf("s1 polling rules as fra1 = %d", rec.Code)
	}
	if last, _ := s.mit.NodeSeen("fra1"); last.IsZero() {
		t.Fatal("s1's own poll did not stamp fra1's presence")
	}
	// An edge-bound token reporting as a scrub node: refused, nothing stored.
	if rec := postJSON(h, "/api/v1/dataplane/nodes/fra1/report", `{"version":"x"}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 (edge-bound) reporting as scrub fra1 = %d", rec.Code)
	}
	if _, _, ok := s.nodeReports.get("fra1"); ok {
		t.Fatal("a refused scrub report was stored")
	}
	if rec := postJSON(h, "/api/v1/dataplane/nodes/fra1/report", `{}`, "s1-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("s1 reporting as fra1 = %d %s", rec.Code, rec.Body.String())
	}
	if len(aw.rows) != 0 {
		t.Fatalf("refusals wrote %d audit rows", len(aw.rows))
	}
}

// Presence is an agent's to stamp. An operator polling with ?node= gets the
// node's document (a preview) and moves no liveness; an unbound agent (grace)
// still stamps it and is named in the inventory.
func TestNodeBindingPresenceAndGrace(t *testing.T) {
	s := testServer(t, bindingStore(t))
	h := s.Handler()
	if rec := getZones(h, "", "op-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("operator preview of e1 = %d", rec.Code)
	}
	if last, holding := s.edgePresence.seen("e1"); !last.IsZero() || holding {
		t.Fatal("an operator's ?node= preview stamped presence")
	}
	// Unbound agent: today's behaviour, any node.
	for _, n := range []string{"e1", "e2"} {
		if rec := getZones(h, "", "a0-secret", n); rec.Code != http.StatusOK {
			t.Fatalf("unbound a0 polling as %s = %d", n, rec.Code)
		}
	}
	if got := s.edgePresence.lastTokenOf("e2"); got != "a0" {
		t.Fatalf("last_token for e2 = %q, want a0", got)
	}
	doc, code := getEdgeNodes(h, "op-secret")
	if code != http.StatusOK {
		t.Fatalf("inventory = %d", code)
	}
	if strings.Join(doc.UnboundAgentTokens, ",") != "a0" {
		t.Errorf("unbound_agent_tokens = %v, want [a0]", doc.UnboundAgentTokens)
	}
	byName := map[string]EdgeNodeStatus{}
	for _, n := range doc.Nodes {
		byName[n.Name] = n
	}
	if strings.Join(byName["e1"].Tokens, ",") != "a1" || byName["e1"].LastToken != "a0" {
		t.Errorf("e1 inventory = tokens %v last_token %q, want [a1] / a0", byName["e1"].Tokens, byName["e1"].LastToken)
	}
	if strings.Join(byName["e2"].Tokens, ",") != "a2" {
		t.Errorf("e2 inventory tokens = %v, want [a2]", byName["e2"].Tokens)
	}
}

// One secret behind two bindings — or behind a bound and an unbound entry, the
// migration mistake of reusing the shared token's value — is a reused secret:
// which node is this? Refused as ambiguous, like a role or tenant mismatch.
func TestNodeBindingAmbiguousSecretIsRefused(t *testing.T) {
	for _, twin := range []string{"bound", "unbound"} {
		store, _, _ := bindingStoreWith(t, bindingOpts{twin: twin})
		s := testServer(t, store)
		if rec := getZones(s.Handler(), "", "a1-secret", "e1"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("a secret shared by a1 (bound to e1) and a %s twin = %d, want 401", twin, rec.Code)
		}
	}
}

// Binding is a property of tokens, not of the document: on ONE brain, the
// document (bytes and ETag) is identical before and after every agent token is
// bound — so a fleet's migration reloads no node.
func TestNodeBindingDoesNotTouchTheDocument(t *testing.T) {
	store, cfgPath, zonesPath := bindingStoreWith(t, bindingOpts{unbound: true})
	s := testServer(t, store)
	h := s.Handler()
	before := getZones(h, "", "op-secret", "")
	if before.Code != http.StatusOK || before.Header().Get("ETag") == "" {
		t.Fatalf("document before binding: %d", before.Code)
	}
	if err := os.WriteFile(cfgPath, []byte(bindingYAML(zonesPath, bindingOpts{})), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload with bindings: %v", err)
	}
	// The reload took: the inventory shows the bindings.
	doc, _ := getEdgeNodes(h, "op-secret")
	bound := 0
	for _, n := range doc.Nodes {
		bound += len(n.Tokens)
	}
	if bound != 2 {
		t.Fatalf("inventory after the reload shows %d bound tokens, want 2: %+v", bound, doc.Nodes)
	}
	after := getZones(h, "", "op-secret", "")
	if after.Code != http.StatusOK || !bytes.Equal(before.Body.Bytes(), after.Body.Bytes()) || before.Header().Get("ETag") != after.Header().Get("ETag") {
		t.Fatalf("binding the tokens changed the document:\n%s\n%s", before.Body.String(), after.Body.String())
	}
}

// The refusal's log is rate-limited PER TOKEN — a leaked bound token varying
// the presented name gets one line a minute, not one per request, and the name
// it presents is logged truncated — while the counter counts every refusal by
// route.
func TestNodeBindingRefusalLogAndMetric(t *testing.T) {
	store := bindingStore(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	eng := engine.New(store, engine.WithLogger(log))
	mit, err := mitigate.New(store, log)
	if err != nil {
		t.Fatal(err)
	}
	s := New(store, eng, mit, log)
	h := s.Handler()
	zonesBefore := testutil.ToFloat64(metrics.APINodeBindingRefused.WithLabelValues("edge_zones"))
	reportBefore := testutil.ToFloat64(metrics.APINodeBindingRefused.WithLabelValues("edge_report"))

	long := strings.Repeat("x", 300)
	for _, presented := range []string{"e2", "e2", "e2", "", long, "e3", "e4"} {
		if rec := getZones(h, "", "a1-secret", presented); rec.Code != http.StatusForbidden {
			t.Fatalf("a1 presenting %q = %d, want 403", presented, rec.Code)
		}
	}
	if got := testutil.ToFloat64(metrics.APINodeBindingRefused.WithLabelValues("edge_zones")) - zonesBefore; got != 7 {
		t.Fatalf("edge_zones refusals counted = %v, want 7", got)
	}
	logged := buf.String()
	if n := strings.Count(logged, "node binding refused"); n != 1 {
		t.Fatalf("Warn lines = %d, want exactly one per token per minute:\n%s", n, logged)
	}
	if !strings.Contains(logged, "presented=e2") || !strings.Contains(logged, "reason=other_node") || !strings.Contains(logged, "token=a1") {
		t.Fatalf("the one Warn line lacks its attributes:\n%s", logged)
	}
	if strings.Contains(logged, long) {
		t.Fatalf("a presented name was logged untruncated:\n%s", logged)
	}
	// Another route, another counter; the log stays quiet within the minute.
	if rec := postEdgeReport(h, "e2", `{}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 reporting as e2 = %d", rec.Code)
	}
	if got := testutil.ToFloat64(metrics.APINodeBindingRefused.WithLabelValues("edge_report")) - reportBefore; got != 1 {
		t.Fatalf("edge_report refusals counted = %v, want 1", got)
	}
	if n := strings.Count(buf.String(), "node binding refused"); n != 1 {
		t.Fatalf("Warn lines after a second route = %d, want still 1", n)
	}
	// A different token gets its own line, and the nameless case says so.
	if rec := getWith(h, "/api/v1/dataplane/rules", "s1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("s1 bare poll = %d", rec.Code)
	}
	if !strings.Contains(buf.String(), "reason=no_node") || strings.Count(buf.String(), "node binding refused") != 2 {
		t.Fatalf("a second token's nameless refusal was not logged as such:\n%s", buf.String())
	}
	// The limiter's map is keyed by token: two entries, whatever was presented.
	s.bindingMu.Lock()
	entries := len(s.bindingWarned)
	s.bindingMu.Unlock()
	if entries != 2 {
		t.Fatalf("limiter entries = %d, want 2 (one per token)", entries)
	}
}

// The edge hold gate's total scales with the fleet — every node polls on its
// own token once bound — and stays at the floor for a small one.
func TestEdgeHoldTotalScalesWithTheFleet(t *testing.T) {
	total := func(s *Server) int {
		s.edgeHolds.mu.Lock()
		defer s.edgeHolds.mu.Unlock()
		return s.edgeHolds.total
	}
	small := testServer(t, bindingStore(t))
	if rec := getZones(small.Handler(), "", "op-secret", ""); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	if got := total(small); got != maxRuleHoldsTotal {
		t.Fatalf("hold total with two edge nodes = %d, want the floor %d", got, maxRuleHoldsTotal)
	}
	store, _, _ := bindingStoreWith(t, bindingOpts{edgeNodes: 5})
	big := testServer(t, store)
	if rec := getZones(big.Handler(), "", "op-secret", ""); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	if got := total(big); got != 10 {
		t.Fatalf("hold total with five edge nodes = %d, want 10", got)
	}
}

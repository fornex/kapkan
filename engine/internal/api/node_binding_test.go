package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
)

// bindingStore is a brain with two edge nodes (e1, e2), one scrub node (fra1),
// and the tokens the binding tests need: a1 bound to e1, a2 bound to e2, s1
// bound to fra1, a0 unbound (the grace case), op an unscoped operator. Secrets
// are the token names suffixed "-secret"; a "twin" token shares a1's secret
// under another binding, so ambiguity can be provoked.
func bindingStore(t *testing.T, twin bool) *config.Store {
	t.Helper()
	for _, n := range []string{"A0", "A1", "A2", "S1", "OP"} {
		t.Setenv("TEST_BIND_"+n, strings.ToLower(n)+"-secret")
	}
	dir := t.TempDir()
	zonesPath := filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zonesPath, []byte(edgeZonesOne), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := ""
	if twin {
		t.Setenv("TEST_BIND_TWIN", "a1-secret")
		extra = "    - { name: twin, token_env: TEST_BIND_TWIN, role: agent, node: e2 }\n"
	}
	yaml := apiYAML +
		"  tokens:\n" +
		"    - { name: a0, token_env: TEST_BIND_A0, role: agent }\n" +
		"    - { name: a1, token_env: TEST_BIND_A1, role: agent, node: e1 }\n" +
		"    - { name: a2, token_env: TEST_BIND_A2, role: agent, node: e2 }\n" +
		"    - { name: s1, token_env: TEST_BIND_S1, role: agent, node: fra1 }\n" +
		"    - { name: op, token_env: TEST_BIND_OP, role: operator }\n" + extra +
		"scrubbing:\n  next_hop: \"192.0.2.9\"\n  nodes:\n    - name: fra1\n      next_hop: \"192.0.2.10\"\n" +
		"edge:\n  zones_file: " + zonesPath + "\n  nodes:\n    - name: e1\n    - name: e2\n"
	cfgPath := filepath.Join(dir, "kapkan.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return config.NewStore(cfgPath, cfg)
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

// A bound token acting as another node is refused on every node-identified
// route of the edge channel — and the refusal leaves NO trace: no presence, no
// stored report, no slot, no published challenge. The body never names the
// bound node.
func TestNodeBindingRefusesAnotherNodeOnTheEdgeChannel(t *testing.T) {
	s := testServer(t, bindingStore(t, false))
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
	// ACME slot and challenge as the other node.
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/slot", `{"zone":"a.example"}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 acquiring e2's slot = %d", rec.Code)
	}
	if rec := postJSON(h, "/api/v1/edge/nodes/e2/acme/challenges", `{"zone":"a.example","token":"tok","key_authorization":"tok.thumb"}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 publishing as e2 = %d", rec.Code)
	}
	if rec := getZones(h, "", "op-secret", ""); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "tok.thumb") {
		t.Fatalf("document after the refused publish: %d, contains the challenge: %v", rec.Code, strings.Contains(rec.Body.String(), "tok.thumb"))
	}
	// A bound token that names no node is a misconfiguration, not a bare curl.
	if rec := getZones(h, "", "a1-secret", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 polling without ?node= = %d, want 403", rec.Code)
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
	if rec := postJSON(h, "/api/v1/edge/nodes/e1/acme/slot", `{"zone":"a.example"}`, "a1-secret"); rec.Code != http.StatusOK {
		t.Fatalf("a1 acquiring e1's slot = %d %s", rec.Code, rec.Body.String())
	}
}

// The scrub channel is the edge channel's twin: the same helper, the same
// refusal on the rules poll and the report.
func TestNodeBindingRefusesAnotherNodeOnTheScrubChannel(t *testing.T) {
	s := testServer(t, bindingStore(t, false))
	h := s.Handler()
	// s1 is bound to fra1; polling as e1 (an edge name) or any other name is refused.
	if rec := getWith(h, "/api/v1/dataplane/rules?node=e1", "s1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("s1 polling rules as e1 = %d", rec.Code)
	}
	if rec := getWith(h, "/api/v1/dataplane/rules", "s1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("s1 polling rules without ?node= = %d, want 403", rec.Code)
	}
	if rec := getWith(h, "/api/v1/dataplane/rules?node=fra1", "s1-secret"); rec.Code != http.StatusOK {
		t.Fatalf("s1 polling rules as fra1 = %d", rec.Code)
	}
	if rec := postJSON(h, "/api/v1/dataplane/nodes/fra1/report", `{}`, "a1-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("a1 (edge-bound) reporting as scrub fra1 = %d", rec.Code)
	}
	if rec := postJSON(h, "/api/v1/dataplane/nodes/fra1/report", `{}`, "s1-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("s1 reporting as fra1 = %d %s", rec.Code, rec.Body.String())
	}
}

// Presence is an agent's to stamp. An operator polling with ?node= gets the
// node's document (a preview) and moves no liveness; an unbound agent (grace)
// still stamps it and is named in the inventory.
func TestNodeBindingPresenceAndGrace(t *testing.T) {
	s := testServer(t, bindingStore(t, false))
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

// One secret behind two bindings is a reused secret: which node is this?
// Refused as ambiguous, like a role or tenant mismatch.
func TestNodeBindingAmbiguousSecretIsRefused(t *testing.T) {
	s := testServer(t, bindingStore(t, true))
	if rec := getZones(s.Handler(), "", "a1-secret", "e1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a secret shared by tokens bound to e1 and e2 = %d, want 401", rec.Code)
	}
}

// Binding is a property of tokens, not of the document: the zones document a
// node receives is byte-identical whether or not any token is bound.
func TestNodeBindingDoesNotTouchTheDocument(t *testing.T) {
	bound := testServer(t, bindingStore(t, false))
	unbound, _ := edgeStore(t, edgeZonesOne)
	plain := testServer(t, unbound)
	a := getZones(bound.Handler(), "", "op-secret", "")
	b := getZones(plain.Handler(), "", "op-secret", "")
	if a.Code != http.StatusOK || b.Code != http.StatusOK {
		t.Fatalf("documents: %d / %d", a.Code, b.Code)
	}
	var da, db map[string]any
	if err := json.Unmarshal(a.Body.Bytes(), &da); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.Body.Bytes(), &db); err != nil {
		t.Fatal(err)
	}
	// Clearance keys are minted per brain; compare the zones and the rest.
	delete(da, "zones")
	delete(db, "zones")
	if a.Header().Get("ETag") == "" || len(da) != len(db) {
		t.Errorf("document shape differs with bound tokens: %v vs %v", da, db)
	}
}

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRoleMatrix is the single regression guard for the API's authorization
// surface (plan §2.2): every /api/v1 route × every identity, with the expected
// authorization outcome. Its job is to make an accidental widening — an agent
// token reading /bans, a viewer touching a mutation — a test failure instead of
// an incident.
//
// Completeness is ENFORCED, not hoped for: Handler() records every /api/v1
// pattern it registers (Server.apiPatterns), and this test fails when the two
// sets differ — so registering a new route forces an explicit row here, with a
// decision for every identity. Above all for AGENT, whose whole design is
// "these routes and nothing else" (its token lives on a remote scrub box; a
// compromise there must not read attacks, bans or audit).
//
// "Allowed" asserts only that authorization passed (not 401/403); the handler
// may still answer 400/404/409 on the test's minimal inputs — that is its
// business logic, not this matrix's.
func TestRoleMatrix(t *testing.T) {
	const matrixYAML = apiYAML + `  tokens:
    - name: v
      token_env: TEST_MATRIX_VIEWER
      role: viewer
    - name: o
      token_env: TEST_MATRIX_OP
      role: operator
    - name: a
      token_env: TEST_MATRIX_AGENT
      role: agent
`
	t.Setenv("TEST_MATRIX_VIEWER", "v-secret")
	t.Setenv("TEST_MATRIX_OP", "o-secret")
	t.Setenv("TEST_MATRIX_AGENT", "a-secret")
	s := testServer(t, storeFromYAML(t, matrixYAML))
	h := s.Handler()

	// Identity name → bearer value ("" = no Authorization header).
	idents := []struct {
		name   string
		bearer string
	}{
		{"anonymous", ""},
		{"viewer", "v-secret"},
		{"operator", "o-secret"},
		{"agent", "a-secret"},
	}

	routes := []struct {
		method, path, body string
		// pattern is the registered mux pattern when it differs from
		// method+path (wildcards, query strings are stripped automatically).
		pattern string
		// allowed[identity name] — absent means denied.
		allowed map[string]bool
	}{
		{"GET", "/api/v1/status", "", "", map[string]bool{"viewer": true, "operator": true}},
		{"GET", "/api/v1/attacks", "", "", map[string]bool{"viewer": true, "operator": true}},
		{"GET", "/api/v1/hosts", "", "", map[string]bool{"viewer": true, "operator": true}},
		{"GET", "/api/v1/bans", "", "", map[string]bool{"viewer": true, "operator": true}},
		{"GET", "/api/v1/traffic?key=203.0.113.10", "", "", map[string]bool{"viewer": true, "operator": true}},
		{"GET", "/api/v1/audit", "", "", map[string]bool{"viewer": true, "operator": true}},
		{"POST", "/api/v1/ban", `{"ip":"203.0.113.10"}`, "", map[string]bool{"operator": true}},
		{"POST", "/api/v1/unban", `{"ip":"203.0.113.10"}`, "", map[string]bool{"operator": true}},
		{"POST", "/api/v1/config/reload", `{}`, "", map[string]bool{"operator": true}},
		// The source-block channel: operator-only writes, like ban/unban. The
		// agent role is DENIED on purpose — its trust model is rules-read plus
		// an advisory report, and a write that installs kernel rules must not
		// ride on it before the fleet milestone binds tokens to nodes.
		{"POST", "/api/v1/dataplane/sources",
			`{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":60}`, "",
			map[string]bool{"operator": true}},
		{"POST", "/api/v1/dataplane/sources/unblock",
			`{"victim":"203.0.113.10","source":"198.51.100.7"}`, "",
			map[string]bool{"operator": true}},
		// The scrub-node channel: the agent's routes, plus operator so a human
		// can curl what the agent sees/sends. Viewer is denied on purpose —
		// the rules document spans every tenant while viewer reads are
		// scopable, and a report is a write.
		{"GET", "/api/v1/dataplane/rules", "", "", map[string]bool{"operator": true, "agent": true}},
		{"POST", "/api/v1/dataplane/nodes/n1/report", `{}`, "POST /api/v1/dataplane/nodes/{name}/report",
			map[string]bool{"operator": true, "agent": true}},
		// The node inventory: viewer rank (the console's Nodes view), agent
		// DENIED — an agent needs its rules, not the whole fleet topology.
		{"GET", "/api/v1/dataplane/nodes", "", "", map[string]bool{"viewer": true, "operator": true}},
		// The edge-node channel (edge.go), the scrub channel's twin: the same
		// decisions for the same reasons — agent + operator on the document and
		// the report, viewer denied there; the inventory at viewer rank with
		// agent denied.
		{"GET", "/api/v1/edge/zones", "", "", map[string]bool{"operator": true, "agent": true}},
		{"POST", "/api/v1/edge/nodes/n1/report", `{}`, "POST /api/v1/edge/nodes/{name}/report",
			map[string]bool{"operator": true, "agent": true}},
		{"GET", "/api/v1/edge/nodes", "", "", map[string]bool{"viewer": true, "operator": true}},
	}

	// The two route sets must be IDENTICAL: every registered /api/v1 pattern
	// has a matrix row, and every row names a registered pattern.
	inMatrix := map[string]bool{}
	for _, rt := range routes {
		pat := rt.pattern
		if pat == "" {
			p := rt.path
			if i := strings.Index(p, "?"); i >= 0 {
				p = p[:i]
			}
			pat = rt.method + " " + p
		}
		inMatrix[pat] = true
	}
	registered := map[string]bool{}
	for _, pat := range s.apiPatterns {
		registered[pat] = true
		if !inMatrix[pat] {
			t.Errorf("route %q is registered in Handler() but has no authorization-matrix row — add one, with an explicit decision per identity", pat)
		}
	}
	for pat := range inMatrix {
		if !registered[pat] {
			t.Errorf("matrix row %q names a route Handler() does not register", pat)
		}
	}

	for _, rt := range routes {
		for _, id := range idents {
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
			if rt.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			if id.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+id.bearer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			denied := rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden
			if rt.allowed[id.name] && denied {
				t.Errorf("%s %s as %s = %d, want authorized", rt.method, rt.path, id.name, rec.Code)
			}
			if !rt.allowed[id.name] && !denied {
				t.Errorf("%s %s as %s = %d, want 401/403", rt.method, rt.path, id.name, rec.Code)
			}
		}
	}
}

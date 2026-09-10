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
	// n1 is an edge node so the bound identity has something to bind to; the
	// zones file is never read by Parse. The scrub routes below still name n1
	// — for them it is an unknown scrub node, which is business logic (404),
	// not authorization.
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
    - name: ab
      token_env: TEST_MATRIX_AGENT_BOUND
      role: agent
      node: n1
    - name: so
      token_env: TEST_MATRIX_SCOPED
      role: operator
      tenant: t1
hostgroups:
  - name: t1web
    tenant: t1
    networks: ["203.0.113.0/26"]
edge:
  zones_file: /etc/kapkan/zones.yaml
  nodes:
    - name: n1
`
	t.Setenv("TEST_MATRIX_VIEWER", "v-secret")
	t.Setenv("TEST_MATRIX_OP", "o-secret")
	t.Setenv("TEST_MATRIX_AGENT", "a-secret")
	t.Setenv("TEST_MATRIX_AGENT_BOUND", "ab-secret")
	t.Setenv("TEST_MATRIX_SCOPED", "so-secret")
	s := testServer(t, storeFromYAML(t, matrixYAML))
	h := s.Handler()

	// Identity name → bearer value ("" = no Authorization header). agent-bound
	// is an agent token bound to node n1 (E6.1): it reaches the agent's routes
	// only as n1, so the two bare polls (no ?node=) are DENIED for it while the
	// n1-named routes pass authorization. scoped is an operator scoped to
	// tenant t1, which owns 203.0.113.0/26 (so the 203.0.113.10 targets below
	// are its own): the tenant-scopable reads and writes pass, everything that
	// spans the deployment — reload, both node channels, both inventories — is
	// DENIED, and the two human-facing edge reads (the zone status and the
	// lever, E6.2) pass authorization; whether a zone is its own is the
	// handler's business (no zones file is loaded here, so the lever is 404).
	idents := []struct {
		name   string
		bearer string
	}{
		{"anonymous", ""},
		{"viewer", "v-secret"},
		{"operator", "o-secret"},
		{"agent", "a-secret"},
		{"agent-bound", "ab-secret"},
		{"scoped", "so-secret"},
	}

	routes := []struct {
		method, path, body string
		// pattern is the registered mux pattern when it differs from
		// method+path (wildcards, query strings are stripped automatically).
		pattern string
		// allowed[identity name] — absent means denied.
		allowed map[string]bool
	}{
		{"GET", "/api/v1/status", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/attacks", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/hosts", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/bans", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/traffic?key=203.0.113.10", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/audit", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"POST", "/api/v1/ban", `{"ip":"203.0.113.10"}`, "", map[string]bool{"operator": true, "scoped": true}},
		{"POST", "/api/v1/unban", `{"ip":"203.0.113.10"}`, "", map[string]bool{"operator": true, "scoped": true}},
		// A reload rewrites every tenant's policy and the token set: unscoped
		// operators only.
		{"POST", "/api/v1/config/reload", `{}`, "", map[string]bool{"operator": true}},
		// The source-block channel: operator-only writes, like ban/unban. The
		// agent role is DENIED on purpose — its trust model is rules-read plus
		// an advisory report, and a write that installs kernel rules must not
		// ride on it before the fleet milestone binds tokens to nodes.
		{"POST", "/api/v1/dataplane/sources",
			`{"victim":"203.0.113.10","source":"198.51.100.7","ttl_seconds":60}`, "",
			map[string]bool{"operator": true, "scoped": true}},
		{"POST", "/api/v1/dataplane/sources/unblock",
			`{"victim":"203.0.113.10","source":"198.51.100.7"}`, "",
			map[string]bool{"operator": true, "scoped": true}},
		// The scrub-node channel: the agent's routes, plus operator so a human
		// can curl what the agent sees/sends. Viewer is denied on purpose —
		// the rules document spans every tenant while viewer reads are
		// scopable, and a report is a write.
		// A bound agent polling without ?node= is refused (403): its binding
		// says which node it is, and a nameless poll from it is a
		// misconfiguration — so "agent-bound" is absent from the bare polls.
		{"GET", "/api/v1/dataplane/rules", "", "", map[string]bool{"operator": true, "agent": true}},
		{"POST", "/api/v1/dataplane/nodes/n1/report", `{}`, "POST /api/v1/dataplane/nodes/{name}/report",
			map[string]bool{"operator": true, "agent": true, "agent-bound": true}},
		// The node inventory: viewer rank (the console's Nodes view), agent
		// DENIED — an agent needs its rules, not the whole fleet topology.
		{"GET", "/api/v1/dataplane/nodes", "", "", map[string]bool{"viewer": true, "operator": true}},
		// The edge-node channel (edge.go), the scrub channel's twin: the same
		// decisions for the same reasons — agent + operator on the document and
		// the report, viewer denied there; the inventory at viewer rank with
		// agent denied.
		{"GET", "/api/v1/edge/zones", "", "", map[string]bool{"operator": true, "agent": true}},
		{"POST", "/api/v1/edge/nodes/n1/report", `{}`, "POST /api/v1/edge/nodes/{name}/report",
			map[string]bool{"operator": true, "agent": true, "agent-bound": true}},
		// ACME coordination: the node's own business, same rank as its report.
		{"POST", "/api/v1/edge/nodes/n1/acme/slot", `{"zone":"example.com"}`, "POST /api/v1/edge/nodes/{name}/acme/slot",
			map[string]bool{"operator": true, "agent": true, "agent-bound": true}},
		{"POST", "/api/v1/edge/nodes/n1/acme/challenges", `{"zone":"example.com","token":"tok","key_authorization":"tok.thumb"}`,
			"POST /api/v1/edge/nodes/{name}/acme/challenges", map[string]bool{"operator": true, "agent": true, "agent-bound": true}},
		{"GET", "/api/v1/edge/nodes", "", "", map[string]bool{"viewer": true, "operator": true}},
		// The two human-facing edge reads admit scoped tokens (E6.2): the
		// status shows a tenant its own zones, the lever acts on them only —
		// a foreign zone is the handler's 404, not an authorization refusal.
		{"GET", "/api/v1/edge/zones/status", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"POST", "/api/v1/edge/zones/a.example/challenge", `{"mode":"manual","ttl_seconds":600}`, "POST /api/v1/edge/zones/{name}/challenge", map[string]bool{"operator": true, "scoped": true}},
		{"DELETE", "/api/v1/edge/zones/a.example/challenge", "", "DELETE /api/v1/edge/zones/{name}/challenge", map[string]bool{"operator": true, "scoped": true}},
		// The edge history reads (edge_history_read.go, E6.6): viewer rank; a
		// scoped token reads its own zones' history — whether a zone is its own
		// is the handler's business, and with no querier here the history
		// answers available:false to anyone; the events name nodes and stay
		// unscoped, so the scoped identity is DENIED there.
		{"GET", "/api/v1/edge/history", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/edge/history/sources", "", "", map[string]bool{"viewer": true, "operator": true, "scoped": true}},
		{"GET", "/api/v1/edge/events", "", "", map[string]bool{"viewer": true, "operator": true}},
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

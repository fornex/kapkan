package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// nodesYAML is divertYAML plus a managed scrubbing node, so the report and
// poll-identity paths have a configured node to name.
const nodesYAML = apiYAML + `
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
`

func postReport(h http.Handler, node, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/dataplane/nodes/"+node+"/report", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestNodeReportIsStoredAndIsNotLiveness pins BOTH halves of the report
// contract: the report lands in the advisory store, and it does not move the
// node's liveness by a millisecond — a compromised agent token must not be
// able to keep a dead node "up" (attracting diverted traffic) by posting
// reports.
func TestNodeReportIsStoredAndIsNotLiveness(t *testing.T) {
	s := testServer(t, storeFromYAML(t, nodesYAML))
	h := s.Handler()

	rec := postReport(h, "fra1", `{"version":"1.5.0","xdp_mode":"native","load_mbps":123.5,"dry_run":true}`, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d (%s), want 204", rec.Code, rec.Body.String())
	}
	rep, at, ok := s.nodeReports.get("fra1")
	if !ok || rep.Version != "1.5.0" || rep.XDPMode != "native" || rep.LoadMbps != 123.5 || !rep.DryRun {
		t.Fatalf("stored report = %+v (ok=%v), want the posted claims", rep, ok)
	}
	if at.IsZero() {
		t.Error("stored report carries no timestamp")
	}
	// The invariant: a report is NEVER a liveness signal.
	if last, holding := s.mit.NodeSeen("fra1"); !last.IsZero() || holding {
		t.Fatalf("NodeSeen after a report = %v, %v — a report must not count as a poll", last, holding)
	}
	// Unknown JSON keys from a newer agent are tolerated (forward compat).
	if rec := postReport(h, "fra1", `{"version":"9.9.9","future_field":1}`, ""); rec.Code != http.StatusNoContent {
		t.Errorf("report with unknown keys = %d, want 204 (newer agents must not be rejected)", rec.Code)
	}
}

func TestNodeReportRejections(t *testing.T) {
	s := testServer(t, storeFromYAML(t, nodesYAML))
	h := s.Handler()

	if rec := postReport(h, "ghost", `{}`, ""); rec.Code != http.StatusNotFound {
		t.Errorf("report for an unconfigured node = %d, want 404 (the store must not be growable by token holders)", rec.Code)
	}
	if rec := postReport(h, "fra1", "{not json", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", rec.Code)
	}
	huge := `{"version":"` + strings.Repeat("x", maxNodeReportBytes) + `"}`
	if rec := postReport(h, "fra1", huge, ""); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized report = %d, want 413", rec.Code)
	}
}

// TestNodeReportScopedOperatorRefused: the node namespace is deployment-wide,
// so a tenant-scoped operator may not write into it — same rule as the rules
// feed.
func TestNodeReportScopedOperatorRefused(t *testing.T) {
	const yaml = apiYAML + `  tokens:
    - name: op-scoped
      token_env: TEST_NODES_OP_SCOPED
      role: operator
      tenant: acme
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
hostgroups:
  - name: acme-web
    networks: ["203.0.113.128/25"]
    tenant: acme
`
	t.Setenv("TEST_NODES_OP_SCOPED", "s-secret")
	s := testServer(t, storeFromYAML(t, yaml))
	if rec := postReport(s.Handler(), "fra1", `{}`, "s-secret"); rec.Code != http.StatusForbidden {
		t.Errorf("scoped operator report = %d, want 403", rec.Code)
	}
}

// TestNodesInventory: the Nodes-view document joins what the brain KNOWS
// (config, poll liveness, divert-ban counts) with what the node CLAIMS (its
// last report), and /status carries the count for every role.
func TestNodesInventory(t *testing.T) {
	s := testServer(t, storeFromYAML(t, nodesYAML))
	h := s.Handler()

	// The status scalar exists for everyone.
	rec := do(t, h, http.MethodGet, "/api/v1/status", "")
	var st map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st["nodes_total"] != float64(1) {
		t.Fatalf("status nodes_total = %v, want 1", st["nodes_total"])
	}

	// Inventory before any activity: configured, never seen, no report.
	rec = do(t, h, http.MethodGet, "/api/v1/dataplane/nodes", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET nodes = %d, want 200", rec.Code)
	}
	var doc NodesDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if doc.NodesTotal != 1 || len(doc.Nodes) != 1 || doc.StaleAfterSeconds != 15 {
		t.Fatalf("doc = %+v, want one node and the default stale_after", doc)
	}
	n := doc.Nodes[0]
	if n.Name != "fra1" || n.Alive || n.Holding || n.LastSeen != "" || n.Report != nil {
		t.Fatalf("pristine node = %+v, want never-seen fra1 with no report", n)
	}

	// A poll, a report and a divert ban later, the document reflects all three
	// — liveness from the poll, the claims under `report`, the ban count from
	// the mitigator.
	s.mit.NodePollStarted("fra1")
	s.mit.NodePollEnded("fra1")
	if rec := postReport(h, "fra1", `{"version":"1.5.0","load_mbps":250}`, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("report = %d", rec.Code)
	}
	if _, err := s.mit.ManualBan(mustAddr(t, "203.0.113.10")); err != nil {
		t.Fatalf("ManualBan: %v", err)
	}
	rec = do(t, h, http.MethodGet, "/api/v1/dataplane/nodes", "")
	doc = NodesDoc{}
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	n = doc.Nodes[0]
	if !n.Alive || n.LastSeen == "" {
		t.Errorf("after a poll: alive=%v last_seen=%q, want alive with a timestamp", n.Alive, n.LastSeen)
	}
	if n.Report == nil || n.Report.Version != "1.5.0" || n.Report.LoadMbps != 250 || n.ReportedAt == "" {
		t.Errorf("report on the doc = %+v (%q), want the posted claims", n.Report, n.ReportedAt)
	}
	if n.ActiveBans != 1 {
		t.Errorf("active_bans = %d, want the divert ban counted", n.ActiveBans)
	}
}

// TestNodesInventoryScopedRefused: the inventory is topology; a tenant-scoped
// token gets a 403, not a filtered lie (per-tenant filtering is the fleet
// milestone).
func TestNodesInventoryScopedRefused(t *testing.T) {
	const yaml = apiYAML + `  tokens:
    - name: v-scoped
      token_env: TEST_NODES_V_SCOPED
      role: viewer
      tenant: acme
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
hostgroups:
  - name: acme-web
    networks: ["203.0.113.128/25"]
    tenant: acme
`
	t.Setenv("TEST_NODES_V_SCOPED", "vs-secret")
	s := testServer(t, storeFromYAML(t, yaml))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/nodes", nil)
	r.Header.Set("Authorization", "Bearer vs-secret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped viewer inventory = %d, want 403", rec.Code)
	}
}

// TestRulesPollOpenModeCannotClaimIdentity: naming a node requires a real
// token. The ?node= sighting is the API's one side-effectful GET, outside the
// POST-only CSRF gate — in token-less open mode a browser on the operator's
// machine could otherwise forge a dead node's presence with a cross-origin
// <img> pointed at the localhost listener.
func TestRulesPollOpenModeCannotClaimIdentity(t *testing.T) {
	s := testServer(t, storeFromYAML(t, nodesYAML)) // no tokens: open mode
	h := s.Handler()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/rules?node=fra1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("open-mode poll with ?node= = %d, want 403", w.Code)
	}
	if last, holding := s.mit.NodeSeen("fra1"); !last.IsZero() || holding {
		t.Fatal("a refused identity claim must record nothing")
	}
	// The identity-less read still works in open mode.
	if rec := getRules(h, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("open-mode bare GET = %d, want 200", rec.Code)
	}
}

// TestRulesPollRecordsLiveness pins the other half of the liveness design: the
// rules poll IS the signal. A ?node= poll leaves a sighting; a held poll keeps
// the node marked as holding; an unknown name fails loudly.
func TestRulesPollRecordsLiveness(t *testing.T) {
	const yaml = apiYAML + `  tokens:
    - name: fra1-agent
      token_env: TEST_NODES_AGENT
      role: agent
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
`
	t.Setenv("TEST_NODES_AGENT", "a-secret")
	s := testServer(t, storeFromYAML(t, yaml))
	s.rulesHold = 3 * time.Second
	h := s.Handler()
	poll := func(query, inm string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/dataplane/rules"+query, nil)
		r.Header.Set("Authorization", "Bearer a-secret")
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Identity-less poll (an operator's curl): served, nothing recorded.
	if rec := poll("", ""); rec.Code != http.StatusOK {
		t.Fatalf("bare GET = %d, want 200", rec.Code)
	}
	if last, _ := s.mit.NodeSeen("fra1"); !last.IsZero() {
		t.Fatal("a poll without ?node= must not record liveness for anyone")
	}

	// Unknown node name: loud 404, so a typo'd controller.name cannot poll
	// diligently while the brain counts the node dead.
	if rec := poll("?node=ghost", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("poll as unknown node = %d, want 404", rec.Code)
	}

	// An immediate (non-held) poll leaves a sighting.
	w := poll("?node=fra1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("poll as fra1 = %d, want 200", w.Code)
	}
	last, holding := s.mit.NodeSeen("fra1")
	if last.IsZero() || holding {
		t.Fatalf("after a completed poll: NodeSeen = %v, %v; want a sighting and no open hold", last, holding)
	}
	var doc RuleDoc
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	etag := w.Header().Get("ETag")

	// A held poll marks the node as holding for its whole duration.
	done := make(chan struct{})
	go func() {
		defer close(done)
		poll("?node=fra1", etag)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, holding := s.mit.NodeSeen("fra1"); holding {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("held poll never marked the node as holding")
		}
		time.Sleep(time.Millisecond)
	}
	<-done
	if _, holding := s.mit.NodeSeen("fra1"); holding {
		t.Fatal("hold ended but the node is still marked as holding")
	}
}

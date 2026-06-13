package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/mitigate"

	"log/slog"
	"net/netip"
)

const apiYAML = `
listen:
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
notify: {}
api:
  listen: "127.0.0.1:8080"
`

func testServer(t *testing.T, store *config.Store) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	eng := engine.New(store, engine.WithLogger(log))
	mit, err := mitigate.New(store, log)
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	return New(store, eng, mit, log)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func storeFromYAML(t *testing.T, yaml string) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return config.NewStore("", cfg)
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	// Real clients (and the dashboard) POST JSON; the CSRF guard requires
	// it, so the default test request mirrors that.
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestStatusEndpoint(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	rec := do(t, s.Handler(), http.MethodGet, "/api/v1/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["dry_run"] != true {
		t.Errorf("dry_run = %v, want true", resp["dry_run"])
	}
}

func TestAttacksEndpoint(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	target := netip.MustParseAddr("203.0.113.50")
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Target: target, Metric: engine.MetricPPS,
		Rate: 200000, Threshold: 80000, At: time.Now(),
	}, nil)

	rec := do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Active []Attack `json:"active"`
		Recent []Attack `json:"recent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Active) != 1 || resp.Active[0].Target != target {
		t.Fatalf("active = %+v, want one attack on %v", resp.Active, target)
	}

	// End the attack: it must move to recent.
	s.RecordAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: target, At: time.Now()}, nil)
	rec = do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Active) != 0 {
		t.Errorf("active = %d, want 0 after end", len(resp.Active))
	}
	if len(resp.Recent) != 1 || resp.Recent[0].Active {
		t.Errorf("recent = %+v, want one inactive attack", resp.Recent)
	}
}

func TestRecentRingBounded(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	for i := 0; i < maxRecentAttacks+50; i++ {
		target := netip.AddrFrom4([4]byte{203, 0, 113, byte(i % 254)})
		s.RecordAttackStarted(engine.Event{Kind: engine.AttackStarted, Target: target, At: time.Now()}, nil)
		s.RecordAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: target, At: time.Now()}, nil)
	}
	s.mu.Lock()
	n := len(s.recent)
	s.mu.Unlock()
	if n != maxRecentAttacks {
		t.Errorf("recent ring size = %d, want %d", n, maxRecentAttacks)
	}
}

func TestManualBanEndpoint(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	h := s.Handler()

	// Valid ban (dry-run): active.
	rec := do(t, h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.50"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ban status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var ban mitigate.Ban
	if err := json.Unmarshal(rec.Body.Bytes(), &ban); err != nil {
		t.Fatal(err)
	}
	if ban.State != mitigate.BanActive {
		t.Errorf("ban state = %s, want active", ban.State)
	}

	// Whitelisted ban: rejected with 409.
	rec = do(t, h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.1"}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("whitelisted ban status = %d, want 409", rec.Code)
	}

	// Invalid IP: 400.
	rec = do(t, h, http.MethodPost, "/api/v1/ban", `{"ip":"not-an-ip"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ip status = %d, want 400", rec.Code)
	}

	// Malformed JSON: 400.
	rec = do(t, h, http.MethodPost, "/api/v1/ban", `{`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed json status = %d, want 400", rec.Code)
	}
}

func TestManualUnbanEndpoint(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	h := s.Handler()

	// Unban without an active ban: 404.
	rec := do(t, h, http.MethodPost, "/api/v1/unban", `{"ip":"203.0.113.60"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unban-unknown status = %d, want 404", rec.Code)
	}

	// Ban then unban: 200.
	do(t, h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.60"}`)
	rec = do(t, h, http.MethodPost, "/api/v1/unban", `{"ip":"203.0.113.60"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("unban status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestReloadEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte(apiYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewStore(path, cfg)
	s := testServer(t, store)
	h := s.Handler()

	// Change a threshold on disk and reload.
	updated := strings.Replace(apiYAML, "pps: 80000", "pps: 90000", 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, http.MethodPost, "/api/v1/config/reload", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reload status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if store.Get().Thresholds.PPS != 90000 {
		t.Errorf("reloaded PPS = %d, want 90000", store.Get().Thresholds.PPS)
	}

	// Break the file and reload: must 400 and keep previous config.
	if err := os.WriteFile(path, []byte("pps: 0"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec = do(t, h, http.MethodPost, "/api/v1/config/reload", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad reload status = %d, want 400", rec.Code)
	}
	if store.Get().Thresholds.PPS != 90000 {
		t.Error("failed reload changed live config")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	rec := do(t, s.Handler(), http.MethodGet, "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kapkan_") {
		t.Error("metrics output missing kapkan_ metrics")
	}
}

// TestGroupAttacksKeyedByName: simultaneous group-scoped attacks (which share
// the invalid target address) must be tracked independently, alongside host
// attacks, and end independently.
func TestGroupAttacksKeyedByName(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	now := time.Now()

	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeGroup, Group: "pool-a",
		Metric: engine.MetricPPS, Rate: 180000, Threshold: 150000, At: now,
	}, nil)
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeGroup, Group: "pool-b",
		Metric: engine.MetricMbps, Rate: 12000, Threshold: 10000, At: now,
	}, nil)
	target := netip.MustParseAddr("203.0.113.50")
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: target, Group: "web",
		Metric: engine.MetricPPS, Rate: 200000, Threshold: 80000, At: now,
	}, nil)

	rec := do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
	var resp struct {
		Active []Attack `json:"active"`
		Recent []Attack `json:"recent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Active) != 3 {
		t.Fatalf("active = %d, want 3 (two group + one host)", len(resp.Active))
	}

	// Ending pool-a must leave pool-b and the host attack active.
	s.RecordAttackEnded(engine.Event{
		Kind: engine.AttackEnded, Scope: engine.ScopeGroup, Group: "pool-a", At: now,
	}, nil)
	rec = do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Active) != 2 {
		t.Fatalf("active after ending pool-a = %d, want 2", len(resp.Active))
	}
	if len(resp.Recent) != 1 || resp.Recent[0].Group != "pool-a" || resp.Recent[0].Scope != engine.ScopeGroup {
		t.Fatalf("recent = %+v, want the ended pool-a group attack", resp.Recent)
	}
	for _, a := range resp.Active {
		if a.Scope == engine.ScopeGroup && a.Group == "pool-a" {
			t.Error("pool-a still active after its end event")
		}
	}
}

// TestInAndOutAttacksOnSameHostCoexist: per-direction keys keep both records.
func TestInAndOutAttacksOnSameHostCoexist(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	now := time.Now()
	target := netip.MustParseAddr("203.0.113.50")

	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: target,
		Direction: engine.DirIncoming, Metric: engine.MetricPPS, At: now,
	}, nil)
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: target,
		Direction: engine.DirOutgoing, Metric: engine.MetricPPS, At: now,
	}, nil)

	rec := do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
	var resp struct {
		Active []Attack `json:"active"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Active) != 2 {
		t.Fatalf("active = %d, want 2 (incoming + outgoing on one host)", len(resp.Active))
	}

	// Ending the outgoing attack leaves the incoming one active.
	s.RecordAttackEnded(engine.Event{
		Kind: engine.AttackEnded, Scope: engine.ScopeHost, Target: target,
		Direction: engine.DirOutgoing, At: now,
	}, nil)
	rec = do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Active) != 1 || resp.Active[0].Direction != engine.DirIncoming {
		t.Fatalf("active = %+v, want only the incoming attack", resp.Active)
	}
}

func TestHostsAndBansEndpoints(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	h := s.Handler()

	// Feed a flow so the engine actually tracks a host; the endpoint must
	// surface it (not just return an empty/null list).
	s.eng.Process(flow.Flow{
		SrcAddr:      netip.MustParseAddr("198.51.100.7"),
		DstAddr:      netip.MustParseAddr("203.0.113.20"),
		IPProto:      17,
		Bytes:        100,
		Packets:      1,
		SamplingRate: 1000,
	})

	rec := do(t, h, http.MethodGet, "/api/v1/hosts", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("hosts status = %d, want 200", rec.Code)
	}
	var hostsResp struct {
		Hosts []engine.HostStat `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &hostsResp); err != nil {
		t.Fatalf("hosts body: %v", err)
	}
	found := false
	for _, hst := range hostsResp.Hosts {
		if hst.Target.String() == "203.0.113.20" {
			found = true
		}
	}
	if !found {
		t.Errorf("hosts = %+v, want the tracked 203.0.113.20", hostsResp.Hosts)
	}

	// A manual ban then shows up in /bans.
	if rec := do(t, h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.66"}`); rec.Code != http.StatusOK {
		t.Fatalf("ban status = %d, want 200", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/v1/bans", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("bans status = %d, want 200", rec.Code)
	}
	var bansResp struct {
		Bans []mitigate.Ban `json:"bans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bansResp); err != nil {
		t.Fatalf("bans body: %v", err)
	}
	if len(bansResp.Bans) != 1 || bansResp.Bans[0].Target.String() != "203.0.113.66" {
		t.Errorf("bans = %+v, want one ban on 203.0.113.66", bansResp.Bans)
	}
}

func tokenYAML() string {
	return strings.Replace(apiYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  token_env: \"KAPKAN_TEST_API_TOKEN\"\n", 1)
}

// reqWith issues a request with optional bearer token and content type.
func reqWith(h http.Handler, method, path, body, bearer, ctype string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestBearerTokenGuard(t *testing.T) {
	t.Setenv("KAPKAN_TEST_API_TOKEN", "s3cr3t")
	s := testServer(t, storeFromYAML(t, tokenYAML()))
	h := s.Handler()

	// No token: 401 on the API.
	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	// Wrong token: 401.
	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "nope", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", rec.Code)
	}
	// Right token: 200.
	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "s3cr3t", ""); rec.Code != http.StatusOK {
		t.Errorf("right token: status = %d, want 200", rec.Code)
	}
	// Mutating endpoint guarded too.
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "", "application/json"); rec.Code != http.StatusUnauthorized {
		t.Errorf("ban without token: status = %d, want 401", rec.Code)
	}
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "s3cr3t", "application/json"); rec.Code != http.StatusOK {
		t.Errorf("ban with token: status = %d, want 200", rec.Code)
	}
	// /metrics and the dashboard stay open even with a token configured.
	if rec := reqWith(h, http.MethodGet, "/metrics", "", "", ""); rec.Code != http.StatusOK {
		t.Errorf("metrics: status = %d, want 200 (unguarded)", rec.Code)
	}
	if rec := reqWith(h, http.MethodGet, "/", "", "", ""); rec.Code != http.StatusOK {
		t.Errorf("dashboard: status = %d, want 200 (unguarded shell)", rec.Code)
	}

	// CSRF guard is enforced in token mode too: a valid token but a non-JSON
	// content type is still refused (415). This is the case that matters once
	// the listener is exposed beyond localhost.
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "s3cr3t", "text/plain"); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("ban with token but non-JSON: status = %d, want 415", rec.Code)
	}
	// Token is checked before content type: a request failing both (no token,
	// non-JSON) gets 401, not 415 — auth must not leak endpoint validity.
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "", "text/plain"); rec.Code != http.StatusUnauthorized {
		t.Errorf("ban failing both checks: status = %d, want 401 (token wins)", rec.Code)
	}
	// A raw token without the "Bearer " scheme must not authenticate.
	raw := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	raw.Header.Set("Authorization", "s3cr3t")
	rawRec := httptest.NewRecorder()
	h.ServeHTTP(rawRec, raw)
	if rawRec.Code != http.StatusUnauthorized {
		t.Errorf("raw token without Bearer scheme: status = %d, want 401", rawRec.Code)
	}
}

// TestEmptyConfiguredTokenFailsClosed: api.token_env is set but the env var
// is empty/unset — auth must fail closed (401), never accept an empty token.
func TestEmptyConfiguredTokenFailsClosed(t *testing.T) {
	t.Setenv("KAPKAN_TEST_API_TOKEN", "") // configured but blank
	s := testServer(t, storeFromYAML(t, tokenYAML()))
	h := s.Handler()

	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no auth header: status = %d, want 401", rec.Code)
	}
	// An explicit empty bearer must not match the empty configured secret.
	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("empty bearer: status = %d, want 401", rec.Code)
	}
	empty := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	empty.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, empty)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Bearer with empty token: status = %d, want 401", rec.Code)
	}
}

func TestCSRFContentTypeGuard(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML)) // no token
	h := s.Handler()
	// POST without application/json is refused even without auth — a
	// cross-site form (text/plain, form-encoded) cannot reach the action.
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "", ct)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("ban with content-type %q: status = %d, want 415", ct, rec.Code)
		}
	}
}

func TestDashboardServing(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	h := s.Handler()

	rec := reqWith(h, http.MethodGet, "/", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index content-type = %q, want text/html", ct)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("missing strict CSP, got %q", csp)
	}
	if !strings.Contains(rec.Body.String(), "Kapkan") {
		t.Error("index body does not look like the dashboard")
	}
	// Assets serve with their content type and hardening headers.
	for _, a := range []struct{ path, ctype string }{
		{"/app.js", "text/javascript"},
		{"/style.css", "text/css"},
	} {
		rec := reqWith(h, http.MethodGet, a.path, "", "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", a.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, a.ctype) {
			t.Errorf("%s content-type = %q, want %s", a.path, ct, a.ctype)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s missing X-Content-Type-Options: nosniff", a.path)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s missing strict CSP", a.path)
		}
	}

	// The explicit 3-file allowlist (not an http.FileServer) means only the
	// named routes exist: /index.html is NOT served (a FileServer would
	// serve or redirect to it), and unknown paths 404.
	if rec := reqWith(h, http.MethodGet, "/index.html", "", "", ""); rec.Code == http.StatusOK || rec.Code == http.StatusMovedPermanently {
		t.Errorf("/index.html status = %d, want not served (allowlist, not FileServer)", rec.Code)
	}
	if rec := reqWith(h, http.MethodGet, "/static/index.html", "", "", ""); rec.Code == http.StatusOK {
		t.Error("/static/index.html served; embed tree must not be exposed")
	}
	if rec := reqWith(h, http.MethodGet, "/nope.txt", "", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown asset status = %d, want 404", rec.Code)
	}

	// Disabled: index 404s but the API still works.
	disabled := strings.Replace(apiYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  dashboard: false\n", 1)
	s2 := testServer(t, storeFromYAML(t, disabled))
	h2 := s2.Handler()
	if rec := reqWith(h2, http.MethodGet, "/", "", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("disabled dashboard index = %d, want 404", rec.Code)
	}
	if rec := reqWith(h2, http.MethodGet, "/api/v1/status", "", "", ""); rec.Code != http.StatusOK {
		t.Errorf("api with dashboard disabled = %d, want 200", rec.Code)
	}
}

package api

import (
	"bytes"
	"context"
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
	"github.com/kapkan-io/kapkan/internal/storage"

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

type fakeQuerier struct {
	pts       []storage.TrafficPoint
	err       error
	gotKey    string
	auditRows []storage.AuditRow
	auditErr  error
	gotAudit  storage.AuditFilter
}

func (f *fakeQuerier) QueryTraffic(_ context.Context, key string, _, _ time.Time, _ int) ([]storage.TrafficPoint, error) {
	f.gotKey = key
	return f.pts, f.err
}

func (f *fakeQuerier) QueryAudit(_ context.Context, filter storage.AuditFilter) ([]storage.AuditRow, error) {
	f.gotAudit = filter
	return f.auditRows, f.auditErr
}

func TestTrafficEndpoint(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))

	// storage disabled (no querier) → available:false, never an error
	rec := do(t, s.Handler(), http.MethodGet, "/api/v1/traffic?key=203.0.113.10", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("nil-querier traffic = %d, want 200", rec.Code)
	}
	var off map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &off)
	if off["available"] != false {
		t.Errorf("available = %v, want false", off["available"])
	}

	// with a querier → points are returned and the key is forwarded
	fq := &fakeQuerier{pts: []storage.TrafficPoint{{TS: "2024-01-01 00:00:00", PPS: 123, Mbps: 4}}}
	s.SetQuerier(fq)
	rec = do(t, s.Handler(), http.MethodGet, "/api/v1/traffic?key=203.0.113.10&step=10", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("traffic = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var on struct {
		Available bool                   `json:"available"`
		Points    []storage.TrafficPoint `json:"points"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &on); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !on.Available || len(on.Points) != 1 || on.Points[0].PPS != 123 {
		t.Errorf("unexpected traffic body: %+v", on)
	}
	if fq.gotKey != "203.0.113.10" {
		t.Errorf("querier key = %q, want 203.0.113.10", fq.gotKey)
	}

	// invalid key → 400
	if rec := do(t, s.Handler(), http.MethodGet, "/api/v1/traffic?key=nope", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad key = %d, want 400", rec.Code)
	}
	// to before from → 400 (DoS-guard: no empty/inverted ranges)
	if rec := do(t, s.Handler(), http.MethodGet, "/api/v1/traffic?key=203.0.113.10&from=2024-01-02T00:00:00Z&to=2024-01-01T00:00:00Z", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("to<from = %d, want 400", rec.Code)
	}
	// range too large → 400 (DoS-guard: capped at 31 days)
	if rec := do(t, s.Handler(), http.MethodGet, "/api/v1/traffic?key=203.0.113.10&from=2000-01-01T00:00:00Z&to=2024-01-01T00:00:00Z", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized range = %d, want 400", rec.Code)
	}
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

func TestHealthzReflectsReadiness(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	h := s.Handler()
	// Unauthenticated and 503 until the daemon marks itself ready.
	if rec := do(t, h, http.MethodGet, "/healthz", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz before ready = %d, want 503", rec.Code)
	}
	s.SetReady()
	if rec := do(t, h, http.MethodGet, "/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz after ready = %d, want 200", rec.Code)
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

func TestAttackDryRunFallbackFromConfig(t *testing.T) {
	// When an attack is recorded with no ban (ban==nil) — e.g. mitigation is
	// disabled or the attack is group-scoped — Attack.DryRun must fall back to
	// the config's dry_run flag (the else-branch of RecordAttackStarted).
	record := func(t *testing.T, yaml string) Attack {
		t.Helper()
		s := testServer(t, storeFromYAML(t, yaml))
		s.RecordAttackStarted(engine.Event{
			Kind: engine.AttackStarted, Target: netip.MustParseAddr("203.0.113.50"),
			Metric: engine.MetricPPS, Rate: 200000, Threshold: 80000, At: time.Now(),
		}, nil)
		rec := do(t, s.Handler(), http.MethodGet, "/api/v1/attacks", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var resp struct {
			Active []Attack `json:"active"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Active) != 1 {
			t.Fatalf("active = %d, want 1", len(resp.Active))
		}
		return resp.Active[0]
	}

	// dry_run: true config → the fallback marks the unbanned attack dry-run.
	if a := record(t, "dry_run: true\n"+apiYAML); !a.DryRun {
		t.Errorf("DryRun = false, want true (dry_run: true config, ban=nil)")
	}
	// dry_run: false config → the fallback reflects the live (non-dry-run) flag.
	// (dry_run defaults to true when the key is absent — the safety default —
	// so this case must set it explicitly to exercise the false direction.)
	if a := record(t, "dry_run: false\n"+apiYAML); a.DryRun {
		t.Errorf("DryRun = true, want false (dry_run: false config, ban=nil)")
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

func apiTokensYAML() string {
	return strings.Replace(apiYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  tokens:\n"+
			"    - {name: ro, token_env: KAPKAN_TEST_RO, role: viewer}\n"+
			"    - {name: rw, token_env: KAPKAN_TEST_RW, role: operator}\n", 1)
}

// TestRoleBasedTokens: a viewer token may read but not mutate (403); an
// operator token may do both; an unknown token is 401 (not 403).
func TestRoleBasedTokens(t *testing.T) {
	t.Setenv("KAPKAN_TEST_RO", "view-secret")
	t.Setenv("KAPKAN_TEST_RW", "op-secret")
	s := testServer(t, storeFromYAML(t, apiTokensYAML()))
	h := s.Handler()

	// Viewer: read OK, write forbidden.
	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "view-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("viewer read: status = %d, want 200", rec.Code)
	}
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "view-secret", "application/json"); rec.Code != http.StatusForbidden {
		t.Errorf("viewer write: status = %d, want 403", rec.Code)
	}
	// Operator: read and write OK.
	if rec := reqWith(h, http.MethodGet, "/api/v1/bans", "", "op-secret", ""); rec.Code != http.StatusOK {
		t.Errorf("operator read: status = %d, want 200", rec.Code)
	}
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "op-secret", "application/json"); rec.Code != http.StatusOK {
		t.Errorf("operator write: status = %d, want 200", rec.Code)
	}
	// Unknown token: 401 (authentication failed, not a role problem).
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"203.0.113.9"}`, "bogus", "application/json"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown token write: status = %d, want 401", rec.Code)
	}
	// No token: 401.
	if rec := reqWith(h, http.MethodGet, "/api/v1/status", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token read: status = %d, want 401", rec.Code)
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

// TestDashboardCaching: assets carry Cache-Control: no-cache + a content-hash
// ETag, and honour conditional requests. This is what makes a redeployed
// binary's new console reach the browser instead of leaving a stale views.js
// running (the "I upgraded but the UI didn't change" trap).
func TestDashboardCaching(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	h := s.Handler()

	rec := reqWith(h, http.MethodGet, "/views.js", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("views.js status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("views.js missing ETag")
	}

	// Same ETag -> 304 with no body.
	r := httptest.NewRequest(http.MethodGet, "/views.js", nil)
	r.Header.Set("If-None-Match", etag)
	rec304 := httptest.NewRecorder()
	h.ServeHTTP(rec304, r)
	if rec304.Code != http.StatusNotModified {
		t.Errorf("conditional GET status = %d, want 304", rec304.Code)
	}
	if rec304.Body.Len() != 0 {
		t.Errorf("304 response wrote %d body bytes, want 0", rec304.Body.Len())
	}

	// Stale ETag -> full 200 with the asset.
	r2 := httptest.NewRequest(http.MethodGet, "/views.js", nil)
	r2.Header.Set("If-None-Match", `"deadbeefdeadbeefdeadbeefdeadbeef"`)
	rec200 := httptest.NewRecorder()
	h.ServeHTTP(rec200, r2)
	if rec200.Code != http.StatusOK {
		t.Errorf("stale conditional GET status = %d, want 200", rec200.Code)
	}
	if rec200.Body.Len() == 0 {
		t.Error("stale conditional GET returned empty body, want asset")
	}

	// Distinct assets hash to distinct ETags (no accidental shared constant).
	other := reqWith(h, http.MethodGet, "/app.js", "", "", "").Header().Get("ETag")
	if other == "" || other == etag {
		t.Errorf("app.js ETag = %q, views.js ETag = %q; want distinct non-empty", other, etag)
	}
}

func tenantAPIYAML() string {
	y := strings.Replace(apiYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  tokens:\n"+
			"    - {name: admin, token_env: K_ADMIN, role: operator}\n"+
			"    - {name: a-view, token_env: K_A, role: viewer, tenant: custA}\n"+
			"    - {name: b-op, token_env: K_B, role: operator, tenant: custB}\n", 1)
	return y + "hostgroups:\n" +
		"  - name: custA-web\n    tenant: custA\n    networks: [\"203.0.113.0/26\"]\n" +
		"  - name: custB-web\n    tenant: custB\n    networks: [\"203.0.113.64/26\"]\n"
}

func attackTargets(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var resp struct {
		Active []Attack `json:"active"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("attacks body: %v\n%s", err, body)
	}
	out := map[string]bool{}
	for _, a := range resp.Active {
		out[a.Target.String()] = true
	}
	return out
}

func banTargets(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var resp struct {
		Bans []mitigate.Ban `json:"bans"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("bans body: %v\n%s", err, body)
	}
	out := map[string]bool{}
	for _, b := range resp.Bans {
		out[b.Target.String()] = true
	}
	return out
}

// groupAttackNames returns the set of group names for the GROUP-scoped active
// attacks in an /attacks response. Group attacks share the invalid zero target,
// so (unlike attackTargets) they must be keyed by name, not address.
func groupAttackNames(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var resp struct {
		Active []Attack `json:"active"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("attacks body: %v\n%s", err, body)
	}
	out := map[string]bool{}
	for _, a := range resp.Active {
		if a.Scope == engine.ScopeGroup {
			out[a.Group] = true
		}
	}
	return out
}

// TestTenantScoping is the core cross-tenant isolation test: a scoped token
// sees and may mutate only its own tenant's data; an admin sees all.
func TestTenantScoping(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")
	s := testServer(t, storeFromYAML(t, tenantAPIYAML()))
	h := s.Handler()

	const aIP, bIP = "203.0.113.10", "203.0.113.70" // custA, custB
	s.RecordAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: netip.MustParseAddr(aIP), Group: "custA-web", At: time.Now()}, nil)
	s.RecordAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: netip.MustParseAddr(bIP), Group: "custB-web", At: time.Now()}, nil)
	if _, err := s.mit.ManualBan(netip.MustParseAddr(aIP)); err != nil { // dry-run virtual ban
		t.Fatal(err)
	}
	if _, err := s.mit.ManualBan(netip.MustParseAddr(bIP)); err != nil {
		t.Fatal(err)
	}

	// custA viewer sees only custA in attacks and bans.
	at := attackTargets(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "a-secret", "").Body.Bytes())
	if !at[aIP] || at[bIP] {
		t.Errorf("custA attacks = %v, want only %s", at, aIP)
	}
	bt := banTargets(t, reqWith(h, http.MethodGet, "/api/v1/bans", "", "a-secret", "").Body.Bytes())
	if !bt[aIP] || bt[bIP] {
		t.Errorf("custA bans = %v, want only %s", bt, aIP)
	}

	// custA status: only custA's hostgroup, and no global networks/thresholds.
	var st map[string]any
	_ = json.Unmarshal(reqWith(h, http.MethodGet, "/api/v1/status", "", "a-secret", "").Body.Bytes(), &st)
	if _, ok := st["networks"]; ok {
		t.Error("scoped status leaked global networks")
	}
	if _, ok := st["thresholds"]; ok {
		t.Error("scoped status leaked global thresholds")
	}
	if groups, _ := st["hostgroups"].([]any); len(groups) != 1 {
		t.Errorf("scoped status hostgroups = %v, want only custA-web", st["hostgroups"])
	}

	// admin sees both tenants and the global fields.
	at = attackTargets(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "admin-secret", "").Body.Bytes())
	if !at[aIP] || !at[bIP] {
		t.Errorf("admin attacks = %v, want both", at)
	}
	_ = json.Unmarshal(reqWith(h, http.MethodGet, "/api/v1/status", "", "admin-secret", "").Body.Bytes(), &st)
	if _, ok := st["networks"]; !ok {
		t.Error("admin status missing networks")
	}

	// Mutation scoping. A viewer cannot mutate at all (403).
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"`+aIP+`"}`, "a-secret", "application/json"); rec.Code != http.StatusForbidden {
		t.Errorf("custA viewer ban = %d, want 403", rec.Code)
	}
	// custB operator may ban within custB...
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"`+bIP+`"}`, "b-secret", "application/json"); rec.Code != http.StatusOK {
		t.Errorf("custB operator ban own = %d, want 200", rec.Code)
	}
	// ...but not a custA target (uniform 403, regardless of ban existence).
	if rec := reqWith(h, http.MethodPost, "/api/v1/unban", `{"ip":"`+aIP+`"}`, "b-secret", "application/json"); rec.Code != http.StatusForbidden {
		t.Errorf("custB operator unban custA = %d, want 403", rec.Code)
	}
	// A scoped operator cannot reload (admin-only).
	if rec := reqWith(h, http.MethodPost, "/api/v1/config/reload", "", "b-secret", "application/json"); rec.Code != http.StatusForbidden {
		t.Errorf("scoped operator reload = %d, want 403", rec.Code)
	}
	// admin passes the reload gate (in-memory test store has no file to re-read,
	// so the reload returns 400 — what matters is it is NOT blocked by 403).
	if rec := reqWith(h, http.MethodPost, "/api/v1/config/reload", "", "admin-secret", "application/json"); rec.Code == http.StatusForbidden {
		t.Errorf("admin reload = 403, want it to pass the admin gate")
	}
}

// TestTenantAmbiguousTokenFailsClosed: one bearer matching tokens of different
// scope (a reused secret) is refused, never silently widened — including when a
// HIGHER-rank operator token shares the secret (it must not clear the ambiguity
// and grant operator/admin).
func TestTenantAmbiguousTokenFailsClosed(t *testing.T) {
	t.Setenv("K_A", "shared")
	t.Setenv("K_B", "shared")     // same secret, different tenants — misconfig
	t.Setenv("K_ADMIN", "shared") // and a higher-rank operator, same secret
	y := strings.Replace(apiYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  tokens:\n"+
			"    - {name: a, token_env: K_A, role: viewer, tenant: custA}\n"+
			"    - {name: b, token_env: K_B, role: viewer, tenant: custB}\n"+
			"    - {name: admin, token_env: K_ADMIN, role: operator}\n", 1) +
		"hostgroups:\n  - name: ca\n    tenant: custA\n    networks: [\"203.0.113.0/26\"]\n" +
		"  - name: cb\n    tenant: custB\n    networks: [\"203.0.113.64/26\"]\n"
	s := testServer(t, storeFromYAML(t, y))
	// Read AND mutate must both fail closed: the operator-rank match must not
	// win once any ambiguity is present.
	if rec := reqWith(s.Handler(), http.MethodGet, "/api/v1/status", "", "shared", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("ambiguous token read = %d, want 401 (fail closed)", rec.Code)
	}
	if rec := reqWith(s.Handler(), http.MethodPost, "/api/v1/config/reload", "", "shared", "application/json"); rec.Code != http.StatusUnauthorized {
		t.Errorf("ambiguous token reload = %d, want 401 (must not resolve to operator)", rec.Code)
	}
}

// TestGlobalGroupNotLeakedToScopedToken: even when the global/fallback group is
// labeled with a tenant, a scoped token of that tenant must not receive the
// global group's deployment-wide config via /status.
func TestGlobalGroupNotLeakedToScopedToken(t *testing.T) {
	t.Setenv("K_A", "a-secret")
	y := strings.Replace(apiYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  tokens:\n"+
			"    - {name: a, token_env: K_A, role: viewer, tenant: custA}\n", 1) +
		"tenant: \"custA\"\n" + // label the GLOBAL group with custA
		"hostgroups:\n  - name: ca-web\n    tenant: custA\n    networks: [\"203.0.113.0/26\"]\n"
	s := testServer(t, storeFromYAML(t, y))
	var st map[string]any
	_ = json.Unmarshal(reqWith(s.Handler(), http.MethodGet, "/api/v1/status", "", "a-secret", "").Body.Bytes(), &st)
	groups, _ := st["hostgroups"].([]any)
	if len(groups) != 1 { // only ca-web — never the global group, despite its label
		t.Fatalf("scoped hostgroups = %v, want only ca-web (global group excluded)", st["hostgroups"])
	}
	if g, _ := groups[0].(map[string]any); g["name"] == config.GlobalGroup {
		t.Errorf("scoped token received the global group: %v", g)
	}
}

// fakeAuditWriter captures audit rows (the other Writer methods are no-ops).
// Handlers run synchronously inside ServeHTTP, so no locking is needed.
type fakeAuditWriter struct{ rows []storage.AuditRow }

func (f *fakeAuditWriter) WriteAttack(storage.AttackRow)     {}
func (f *fakeAuditWriter) WriteTraffic([]storage.TrafficRow) {}
func (f *fakeAuditWriter) WriteAudit(r storage.AuditRow)     { f.rows = append(f.rows, r) }
func (f *fakeAuditWriter) Start(context.Context)             {}
func (f *fakeAuditWriter) Stop()                             {}

// TestAuditEmittedOnMutations: ban/unban/reload each emit one audit record
// stamped with the operator's token name and tenant.
func TestAuditEmittedOnMutations(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")
	s := testServer(t, storeFromYAML(t, tenantAPIYAML()))
	aw := &fakeAuditWriter{}
	s.SetAuditWriter(aw)
	h := s.Handler()

	const bIP = "203.0.113.70" // custB
	if rec := reqWith(h, http.MethodPost, "/api/v1/ban", `{"ip":"`+bIP+`"}`, "b-secret", "application/json"); rec.Code != http.StatusOK {
		t.Fatalf("ban = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	reqWith(h, http.MethodPost, "/api/v1/unban", `{"ip":"`+bIP+`"}`, "b-secret", "application/json")
	reqWith(h, http.MethodPost, "/api/v1/config/reload", `{}`, "admin-secret", "application/json")

	if len(aw.rows) != 3 {
		t.Fatalf("audit rows = %d, want 3 (ban, unban, reload): %+v", len(aw.rows), aw.rows)
	}
	if b := aw.rows[0]; b.Action != "ban" || b.Operator != "b-op" || b.Tenant != "custB" || b.Target != bIP || b.Source != "api" || b.Result != "active" {
		t.Errorf("ban audit = %+v, want action=ban operator=b-op tenant=custB target=%s result=active", b, bIP)
	}
	if u := aw.rows[1]; u.Action != "unban" || u.Operator != "b-op" || u.Result != "withdrawn" {
		t.Errorf("unban audit = %+v, want action=unban operator=b-op result=withdrawn", u)
	}
	// Reload result depends on the store's path (empty in tests), so assert
	// identity/action/target only, not ok-vs-error.
	if r := aw.rows[2]; r.Action != "config_reload" || r.Operator != "admin" || r.TargetType != "global" {
		t.Errorf("reload audit = %+v, want action=config_reload operator=admin target_type=global", r)
	}
}

// TestAuditEndpointTenantScoping: the tenant filter is bound server-side from
// the caller; a scoped caller cannot widen it with a client param.
func TestAuditEndpointTenantScoping(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")
	s := testServer(t, storeFromYAML(t, tenantAPIYAML()))
	fq := &fakeQuerier{auditRows: []storage.AuditRow{{Action: "ban", Operator: "b-op", Tenant: "custB"}}}
	s.SetQuerier(fq)
	h := s.Handler()

	// Scoped viewer (custA) passing tenant=custB is ignored: server binds custA.
	if rec := reqWith(h, http.MethodGet, "/api/v1/audit?tenant=custB", "", "a-secret", ""); rec.Code != http.StatusOK {
		t.Fatalf("audit = %d, want 200", rec.Code)
	}
	if fq.gotAudit.Tenant != "custA" {
		t.Errorf("bound tenant = %q, want custA (client cannot widen scope)", fq.gotAudit.Tenant)
	}
	// Unscoped admin → no tenant filter (sees all).
	reqWith(h, http.MethodGet, "/api/v1/audit", "", "admin-secret", "")
	if fq.gotAudit.Tenant != "" {
		t.Errorf("admin bound tenant = %q, want empty (all tenants)", fq.gotAudit.Tenant)
	}
}

// TestAuditEndpointStorageDisabled: nil querier → available:false, not an error.
func TestAuditEndpointStorageDisabled(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	rec := do(t, s.Handler(), http.MethodGet, "/api/v1/audit", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d, want 200", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["available"] != false {
		t.Errorf("available = %v, want false", resp["available"])
	}
}

// TestAuditEndpointParamValidation: bad params 400; a valid action 200.
func TestAuditEndpointParamValidation(t *testing.T) {
	s := testServer(t, storeFromYAML(t, apiYAML))
	s.SetQuerier(&fakeQuerier{})
	h := s.Handler()
	for _, tc := range []struct {
		q    string
		want int
	}{
		{"action=bogus", http.StatusBadRequest},
		{"from=notatime", http.StatusBadRequest},
		{"target=notanip", http.StatusBadRequest},
		{"action=ban", http.StatusOK},
	} {
		if rec := do(t, h, http.MethodGet, "/api/v1/audit?"+tc.q, ""); rec.Code != tc.want {
			t.Errorf("audit?%s = %d, want %d", tc.q, rec.Code, tc.want)
		}
	}
}

// TestGroupAttackTenantScoping is the cross-tenant isolation test for the
// GROUP-scoped (total-group) attack path, which is gated by visibleGroupName
// (api.go) rather than by address. A total-group attack carries a group name
// but no single target address, so the scoped/admin filtering must match the
// group's owning tenant by name — not by GroupFor(addr). With two groups owned
// by DIFFERENT tenants (custA-web / custB-web from tenantAPIYAML), a scoped
// caller must see only its own tenant's group attack; an admin sees both.
func TestGroupAttackTenantScoping(t *testing.T) {
	t.Setenv("K_ADMIN", "admin-secret")
	t.Setenv("K_A", "a-secret")
	t.Setenv("K_B", "b-secret")
	s := testServer(t, storeFromYAML(t, tenantAPIYAML()))
	h := s.Handler()

	// One GROUP-scoped (total-group) attack per tenant-owned group. These have
	// no single target address; visibility is decided purely by group name →
	// owning tenant in visibleGroupName.
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeGroup, Group: "custA-web",
		Metric: engine.MetricPPS, Rate: 180000, Threshold: 150000, At: time.Now(),
	}, nil)
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeGroup, Group: "custB-web",
		Metric: engine.MetricMbps, Rate: 12000, Threshold: 10000, At: time.Now(),
	}, nil)

	// custA viewer: sees its own group attack, NOT custB's. The second clause
	// is what distinguishes "sees only own tenant" from "sees all" — without
	// the tenant gate this assertion fails.
	aSeen := groupAttackNames(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "a-secret", "").Body.Bytes())
	if !aSeen["custA-web"] || aSeen["custB-web"] {
		t.Errorf("custA viewer group attacks = %v, want only custA-web (custB-web must be hidden)", aSeen)
	}

	// custB operator: the mirror case — only custB's group attack.
	bSeen := groupAttackNames(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "b-secret", "").Body.Bytes())
	if !bSeen["custB-web"] || bSeen["custA-web"] {
		t.Errorf("custB operator group attacks = %v, want only custB-web (custA-web must be hidden)", bSeen)
	}

	// admin (unscoped): sees BOTH tenants' group attacks.
	adminSeen := groupAttackNames(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "admin-secret", "").Body.Bytes())
	if !adminSeen["custA-web"] || !adminSeen["custB-web"] {
		t.Errorf("admin group attacks = %v, want both custA-web and custB-web", adminSeen)
	}

	// A GROUP-scoped attack on an UNKNOWN group is hidden from any scoped
	// caller (visibleGroupName default-deny on no name match) but still visible
	// to the admin — so a refactor that fell back to "visible" on no match
	// would leak it.
	s.RecordAttackStarted(engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeGroup, Group: "no-such-group",
		Metric: engine.MetricPPS, Rate: 1, Threshold: 0, At: time.Now(),
	}, nil)
	if aSeen := groupAttackNames(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "a-secret", "").Body.Bytes()); aSeen["no-such-group"] {
		t.Errorf("custA viewer saw unknown-group attack %v, want default-deny", aSeen)
	}
	if adminSeen := groupAttackNames(t, reqWith(h, http.MethodGet, "/api/v1/attacks", "", "admin-secret", "").Body.Bytes()); !adminSeen["no-such-group"] {
		t.Errorf("admin missing unknown-group attack %v, want it visible", adminSeen)
	}
}

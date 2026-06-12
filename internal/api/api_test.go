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

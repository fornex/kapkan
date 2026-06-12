package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/mitigate"

	"log/slog"
	"net/netip"
)

func yamlWith(webhookURL string) string {
	return `
listen:
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
protected_whitelist: []
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
notify:
  telegram:
    token_env: "KAPKAN_TEST_TG_TOKEN"
    chat_id: "-100123"
  webhook:
    url: "` + webhookURL + `"
api:
  listen: "127.0.0.1:8080"
`
}

func storeFrom(t *testing.T, yaml string) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return config.NewStore("", cfg)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func sampleEvent() engine.Event {
	return engine.Event{
		Kind:      engine.AttackStarted,
		Target:    netip.MustParseAddr("203.0.113.50"),
		Metric:    engine.MetricPPS,
		Rate:      200000,
		Threshold: 80000,
		Rates:     engine.Rates{PPS: 200000, Mbps: 1200, FlowsPerSec: 40000},
		At:        time.Now(),
	}
}

type captured struct {
	path string
	body []byte
}

func TestWebhookNotification(t *testing.T) {
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{path: r.URL.Path, body: body}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(storeFrom(t, yamlWith(srv.URL)), discardLogger())
	ban := &mitigate.Ban{State: mitigate.BanActive, Route: "203.0.113.50/32 next-hop 192.0.2.1 community 65000:666", DryRun: true}
	n.NotifyAttackStarted(context.Background(), sampleEvent(), ban)

	select {
	case c := <-got:
		var p Payload
		if err := json.Unmarshal(c.body, &p); err != nil {
			t.Fatalf("unmarshal webhook body: %v", err)
		}
		if p.Event != "attack_started" {
			t.Errorf("event = %q, want attack_started", p.Event)
		}
		if p.Target != "203.0.113.50" {
			t.Errorf("target = %q, want 203.0.113.50", p.Target)
		}
		if p.Metric != "pps" || p.Rate != 200000 {
			t.Errorf("metric/rate = %q/%v, want pps/200000", p.Metric, p.Rate)
		}
		if p.BanState != "active" {
			t.Errorf("ban_state = %q, want active", p.BanState)
		}
		if !p.DryRun {
			t.Error("dry_run = false, want true")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called within timeout")
	}
}

func TestTelegramNotification(t *testing.T) {
	t.Setenv("KAPKAN_TEST_TG_TOKEN", "secret-token-123")
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{path: r.URL.Path, body: body}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// No webhook; only telegram, pointed at the fake server.
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	n.tgAPIBase = srv.URL
	n.NotifyAttackStarted(context.Background(), sampleEvent(), nil)

	select {
	case c := <-got:
		if !strings.Contains(c.path, "/botsecret-token-123/sendMessage") {
			t.Errorf("telegram path = %q, want it to contain the bot token and sendMessage", c.path)
		}
		var req map[string]any
		if err := json.Unmarshal(c.body, &req); err != nil {
			t.Fatalf("unmarshal telegram body: %v", err)
		}
		if req["chat_id"] != "-100123" {
			t.Errorf("chat_id = %v, want -100123", req["chat_id"])
		}
		text, _ := req["text"].(string)
		if !strings.Contains(text, "203.0.113.50") || !strings.Contains(text, "STARTED") {
			t.Errorf("telegram text missing target/verb: %q", text)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("telegram not called within timeout")
	}
}

func TestNoTokenNoTelegram(t *testing.T) {
	// Token env unset => telegram must not be attempted (no panic, no call).
	called := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(storeFrom(t, yamlWith("")), discardLogger())
	n.tgAPIBase = srv.URL
	n.NotifyAttackEnded(context.Background(), sampleEvent(), nil)

	select {
	case <-called:
		t.Fatal("telegram was called without a configured token")
	case <-time.After(300 * time.Millisecond):
		// expected: nothing sent
	}
}

func TestWebhookErrorRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	// Should not panic on a failing endpoint; just records the failure.
	n := New(storeFrom(t, yamlWith(srv.URL)), discardLogger())
	n.NotifyAttackStarted(context.Background(), sampleEvent(), nil)
	time.Sleep(200 * time.Millisecond)
}

// TestGroupEventPayload: group-scoped events name the hostgroup instead of a
// target address, in both the webhook payload and the Telegram text.
func TestGroupEventPayload(t *testing.T) {
	ev := engine.Event{
		Kind:      engine.AttackStarted,
		Scope:     engine.ScopeGroup,
		Group:     "pool",
		Metric:    engine.MetricPPS,
		Rate:      180000,
		Threshold: 150000,
		Rates:     engine.Rates{PPS: 180000, Mbps: 140, FlowsPerSec: 60000},
		At:        time.Now(),
	}
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	p := n.buildPayload("attack_started", ev, nil)

	if p.Scope != "group" || p.Group != "pool" {
		t.Errorf("scope/group = %q/%q, want group/pool", p.Scope, p.Group)
	}
	if p.Target != "" {
		t.Errorf("target = %q, want empty for a group event", p.Target)
	}

	text := formatTelegram(p)
	if !strings.Contains(text, "hostgroup <code>pool</code>") {
		t.Errorf("telegram text does not name the hostgroup:\n%s", text)
	}
}

// TestHostEventInGroupNamesGroup: per-host events from a named (non-global)
// group mention the group in the Telegram text.
func TestHostEventInGroupNamesGroup(t *testing.T) {
	ev := sampleEvent()
	ev.Scope = engine.ScopeHost
	ev.Group = "web"
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	text := formatTelegram(n.buildPayload("attack_started", ev, nil))
	if !strings.Contains(text, "Group: web") {
		t.Errorf("telegram text does not mention the hostgroup:\n%s", text)
	}

	ev.Group = "global"
	text = formatTelegram(n.buildPayload("attack_started", ev, nil))
	if strings.Contains(text, "Group:") {
		t.Errorf("telegram text must not mention the implicit global group:\n%s", text)
	}
}

// TestOutgoingEventFlagged: outgoing attacks are marked in the payload and
// loudly flagged in the Telegram text.
func TestOutgoingEventFlagged(t *testing.T) {
	ev := sampleEvent()
	ev.Scope = engine.ScopeHost
	ev.Direction = engine.DirOutgoing
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	p := n.buildPayload("attack_started", ev, nil)
	if p.Direction != "outgoing" {
		t.Errorf("payload direction = %q, want outgoing", p.Direction)
	}
	text := formatTelegram(p)
	if !strings.Contains(text, "OUTGOING") {
		t.Errorf("telegram text does not flag the outgoing direction:\n%s", text)
	}
}

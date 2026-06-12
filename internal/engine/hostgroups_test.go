package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// groupsYAML extends the base test config with one group per behavior under
// test: tighter per-host thresholds, ban disabled, and a total group.
const groupsYAML = baseYAML + `
hostgroups:
  - name: web
    networks:
      - "203.0.113.0/28"
    thresholds:
      pps: 10000
      mbps: 1000
      flows_per_sec: 35000
  - name: noban
    networks:
      - "203.0.113.16/28"
    ban: false
  - name: pool
    networks:
      - "203.0.113.32/28"
    calculation: total
    thresholds:
      pps: 150000
      mbps: 10000
      flows_per_sec: 1000000
`

func groupsStore(t *testing.T, yaml string) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return config.NewStore("", cfg)
}

// floodAt injects records*rate corrected pps at dst (1 packet, 100 bytes per
// sampled record).
func floodAt(e *Engine, dst string, records int, rate uint64) {
	for i := 0; i < records; i++ {
		e.Process(udpFlow(dst, 100, 1, rate))
	}
}

// TestGroupThresholdsApplied: a host inside a hostgroup is evaluated against
// the group's thresholds, while the same traffic level outside the group
// stays below the global thresholds and is not an attack.
func TestGroupThresholdsApplied(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 20000 corrected pps: above web's 10000, below the global 80000.
	floodAt(e, "203.0.113.5", 200, 100)   // in web (/28)
	floodAt(e, "203.0.113.100", 200, 100) // global fallback
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if want := netip.MustParseAddr("203.0.113.5"); ev.Target != want {
			t.Errorf("target = %v, want %v (the hostgroup member)", ev.Target, want)
		}
		if ev.Scope != ScopeHost {
			t.Errorf("scope = %q, want %q", ev.Scope, ScopeHost)
		}
		if ev.Group != "web" {
			t.Errorf("group = %q, want web", ev.Group)
		}
		if !ev.BanEnabled {
			t.Error("BanEnabled = false, want true for a default-policy group")
		}
		if ev.Threshold != 10000 {
			t.Errorf("threshold = %v, want the group's 10000", ev.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted for the hostgroup member")
	}

	// The global-group host at the same rate must not be flagged.
	select {
	case ev := <-events:
		t.Fatalf("unexpected second event for %v: same rate is below the global threshold", ev.Target)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestGroupBanDisabledPropagates: events from a ban:false group carry
// BanEnabled=false so mitigation refuses to act on them.
func TestGroupBanDisabledPropagates(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 200000 pps: above the inherited global 80000 threshold.
	floodAt(e, "203.0.113.20", 200, 1000)
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Group != "noban" {
			t.Errorf("group = %q, want noban", ev.Group)
		}
		if ev.BanEnabled {
			t.Error("BanEnabled = true, want false for a ban:false group")
		}
		if ev.Threshold != 80000 {
			t.Errorf("threshold = %v, want the inherited global 80000", ev.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted for the noban group member")
	}
}

// TestTotalGroupLifecycle: hosts of a calculation:total group are never
// flagged individually; their summed traffic drives a group-scoped attack
// that starts, persists, and ends with hysteresis like a host attack.
func TestTotalGroupLifecycle(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Three hosts at 60000 pps each: every host is below pool's 150000, the
	// 180000 sum is above it.
	flood := func() {
		floodAt(e, "203.0.113.33", 60, 1000)
		floodAt(e, "203.0.113.34", 60, 1000)
		floodAt(e, "203.0.113.35", 60, 1000)
	}
	flood()
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Scope != ScopeGroup {
			t.Fatalf("scope = %q, want %q", ev.Scope, ScopeGroup)
		}
		if ev.Group != "pool" {
			t.Errorf("group = %q, want pool", ev.Group)
		}
		if ev.Target.IsValid() {
			t.Errorf("target = %v, want invalid (group events have no single target)", ev.Target)
		}
		if ev.BanEnabled {
			t.Error("BanEnabled = true, want false: total groups never auto-ban")
		}
		if ev.Metric != MetricPPS {
			t.Errorf("metric = %v, want pps", ev.Metric)
		}
		if ev.Rate < 150000 {
			t.Errorf("rate = %v, want the summed rate above 150000", ev.Rate)
		}
	case <-time.After(time.Second):
		t.Fatal("no group AttackStarted")
	}

	// While the flood continues no further events are emitted.
	flood()
	runTick(e, clk)
	select {
	case ev := <-events:
		t.Fatalf("unexpected event mid-attack: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}

	// Traffic stops: the attack ends only after the 3s hysteresis.
	var ended *Event
	for i := 0; i < 10 && ended == nil; i++ {
		runTick(e, clk)
		select {
		case ev := <-events:
			ended = &ev
		case <-time.After(20 * time.Millisecond):
		}
	}
	if ended == nil {
		t.Fatal("group AttackEnded never emitted after traffic stopped")
	}
	if ended.Kind != AttackEnded || ended.Scope != ScopeGroup || ended.Group != "pool" {
		t.Fatalf("ended event = %+v, want group-scoped AttackEnded for pool", ended)
	}
	if ended.Threshold != 150000 {
		t.Errorf("ended threshold = %v, want the 150000 recorded at start", ended.Threshold)
	}
	if ended.StartedAt.IsZero() {
		t.Error("AttackEnded.StartedAt must be set")
	}
}

// TestTotalGroupRemovedByReloadEndsAttack: removing a total group mid-attack
// via hot reload closes the attack out with an end event instead of leaving
// it dangling.
func TestTotalGroupRemovedByReloadEndsAttack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kapkan.yaml")
	if err := os.WriteFile(path, []byte(groupsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	store := config.NewStore(path, cfg)

	clk := newMockClock()
	e := New(store, WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	floodAt(e, "203.0.113.33", 200, 1000) // 200000 pps > pool's 150000
	runTick(e, clk)
	select {
	case ev := <-events:
		if ev.Kind != AttackStarted || ev.Scope != ScopeGroup {
			t.Fatalf("event = %+v, want group AttackStarted", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("group attack not established")
	}

	// Drop the pool group from the config and hot-reload.
	v2 := strings.Replace(groupsYAML, `  - name: pool
    networks:
      - "203.0.113.32/28"
    calculation: total
    thresholds:
      pps: 150000
      mbps: 10000
      flows_per_sec: 1000000
`, "", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	runTick(e, clk)
	select {
	case ev := <-events:
		if ev.Kind != AttackEnded || ev.Scope != ScopeGroup || ev.Group != "pool" {
			t.Fatalf("event after reload = %+v, want group AttackEnded for pool", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no group AttackEnded after the group was removed via reload")
	}
	if _, ok := e.groups["pool"]; ok {
		t.Error("removed group's state must be dropped")
	}
}

// TestSnapshotCarriesGroup: the API snapshot names each host's owning group.
func TestSnapshotCarriesGroup(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))

	e.Process(udpFlow("203.0.113.5", 100, 1, 1))   // web
	e.Process(udpFlow("203.0.113.100", 100, 1, 1)) // global

	got := map[string]string{}
	for _, st := range e.Snapshot() {
		got[st.Target.String()] = st.Group
	}
	if got["203.0.113.5"] != "web" {
		t.Errorf(`snapshot group for 203.0.113.5 = %q, want "web"`, got["203.0.113.5"])
	}
	if got["203.0.113.100"] != config.GlobalGroup {
		t.Errorf(`snapshot group for 203.0.113.100 = %q, want %q`, got["203.0.113.100"], config.GlobalGroup)
	}
}

package app

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

func TestAttackRowMapping(t *testing.T) {
	at := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	ev := engine.Event{
		Kind:      engine.AttackStarted,
		Scope:     engine.ScopeHost,
		Target:    netip.MustParseAddr("203.0.113.20"),
		Group:     "web",
		Direction: engine.DirIncoming,
		Metric:    engine.MetricPPS,
		Rate:      200000,
		Threshold: 80000,
		Rates:     engine.Rates{PPS: 200000, Mbps: 749, FlowsPerSec: 40000},
		At:        at,
		Classification: &engine.Classification{
			Type: engine.AttackNTPAmplification, Confidence: 0.9, SrcPort: 123,
		},
		Sample: &engine.AttackSample{
			TopSources: []engine.Counter{{Key: "198.51.100.7"}, {Key: "198.51.100.8"}},
		},
	}
	ban := &mitigate.Ban{State: mitigate.BanActive, DryRun: true}

	r := attackRow(ev, ban)
	if r.EventTime != "2026-06-13 12:00:00" {
		t.Errorf("event_time = %q, want ClickHouse UTC literal", r.EventTime)
	}
	if r.Kind != "attack_started" || r.Scope != "host" || r.Target != "203.0.113.20" {
		t.Errorf("kind/scope/target = %q/%q/%q", r.Kind, r.Scope, r.Target)
	}
	if r.Group != "web" || r.Direction != "incoming" || r.Metric != "pps" {
		t.Errorf("group/direction/metric = %q/%q/%q", r.Group, r.Direction, r.Metric)
	}
	if r.AttackType != "ntp_amplification" {
		t.Errorf("attack_type = %q, want ntp_amplification", r.AttackType)
	}
	if r.TopSources != "198.51.100.7,198.51.100.8" {
		t.Errorf("top_sources = %q, want comma-joined sources", r.TopSources)
	}
	if r.BanState != "active" || r.DryRun != 1 {
		t.Errorf("ban_state/dry_run = %q/%d, want active/1", r.BanState, r.DryRun)
	}
	if r.Rate != 200000 || r.Threshold != 80000 || r.PPS != 200000 || r.FlowsPS != 40000 {
		t.Errorf("rate fields = %+v", r)
	}

	// Group-scoped event with no ban: target empty, dry_run from cfg path (0).
	grp := attackRow(engine.Event{
		Kind: engine.AttackEnded, Scope: engine.ScopeGroup, Group: "pool",
		Direction: engine.DirOutgoing, Metric: engine.MetricMbps, At: at,
	}, nil)
	if grp.Target != "" {
		t.Errorf("group event target = %q, want empty", grp.Target)
	}
	if grp.Kind != "attack_ended" || grp.Scope != "group" || grp.Group != "pool" {
		t.Errorf("group row = %+v", grp)
	}
	if grp.BanState != "" || grp.DryRun != 0 {
		t.Errorf("nil ban: ban_state/dry_run = %q/%d, want empty/0", grp.BanState, grp.DryRun)
	}
}

func TestTrafficRowMapping(t *testing.T) {
	h := engine.HostStat{
		Target:   netip.MustParseAddr("203.0.113.20"),
		Group:    "web",
		Rates:    engine.Rates{PPS: 12000, Mbps: 90, FlowsPerSec: 6000},
		InAttack: true,
		Baseline: &engine.Rates{PPS: 4000},
	}
	r := trafficRow(h, "2026-06-13 12:00:00")
	if r.Scope != "host" || r.Key != "203.0.113.20" || r.Group != "web" {
		t.Errorf("scope/key/group = %q/%q/%q", r.Scope, r.Key, r.Group)
	}
	if r.PPS != 12000 || r.Mbps != 90 || r.FlowsPS != 6000 {
		t.Errorf("rates = %+v", r)
	}
	if r.InAttack != 1 {
		t.Errorf("in_attack = %d, want 1", r.InAttack)
	}
	if r.BaselinePPS != 4000 {
		t.Errorf("baseline_pps = %v, want 4000", r.BaselinePPS)
	}

	// No baseline: field stays zero, no panic.
	r = trafficRow(engine.HostStat{Target: netip.MustParseAddr("203.0.113.21")}, "ts")
	if r.InAttack != 0 || r.BaselinePPS != 0 {
		t.Errorf("quiet host: in_attack/baseline = %d/%v, want 0/0", r.InAttack, r.BaselinePPS)
	}
}

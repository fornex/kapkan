package engine

import (
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
)

func floor() config.BaselineFloor {
	return config.BaselineFloor{PPS: 5000, Mbps: 50, FlowsPerSec: 2000}
}

// TestBuildReasonStatic: no baseline configured → static source, no baseline
// block, and the protocol shares reflect the windowed rates.
func TestBuildReasonStatic(t *testing.T) {
	r := Rates{PPS: 100000, UDPPPS: 95000, TCPSYNPPS: 3000}
	got := buildReason(MetricPPS, r, config.Thresholds{PPS: 80000}, nil, nil, 1000)
	if got.ThresholdSource != "static" {
		t.Errorf("source = %q, want static", got.ThresholdSource)
	}
	if got.Baseline != nil || got.BaselineConfigured {
		t.Errorf("static reason should carry no baseline: %+v", got)
	}
	if got.Shares.UDP != 0.95 || got.Shares.SYN != 0.03 {
		t.Errorf("shares = %+v, want udp 0.95 / syn 0.03", got.Shares)
	}
	if got.DominantShareGate != dominantShare {
		t.Errorf("gate = %v, want %v", got.DominantShareGate, dominantShare)
	}
}

// TestBuildReasonBaseline: a warmed-up baseline on a base-trio metric →
// baseline source with the learned normal, factor, floor and static ceiling.
func TestBuildReasonBaseline(t *testing.T) {
	b := &baselineState{pps: 40000, valid: true, firstSeen: 0}
	bc := &config.BaselineSettings{Factor: 3, WarmupSeconds: 600, Floor: floor()}
	// nowSec 700 > firstSeen 0 + warmup 600 → warmed up.
	got := buildReason(MetricPPS, Rates{PPS: 120000, UDPPPS: 120000}, config.Thresholds{PPS: 150000}, b, bc, 700)
	if got.ThresholdSource != "baseline" || got.Baseline == nil {
		t.Fatalf("reason = %+v, want baseline source with a baseline block", got)
	}
	if got.Baseline.Normal != 40000 || got.Baseline.Factor != 3 || got.Baseline.Floor != 5000 || got.Baseline.Ceiling != 150000 {
		t.Errorf("baseline = %+v, want normal 40000 / factor 3 / floor 5000 / ceiling 150000", got.Baseline)
	}
}

// TestBuildReasonWarmingUp: baseline configured but not warmed up → static
// threshold applied, with the warm-up state surfaced.
func TestBuildReasonWarmingUp(t *testing.T) {
	b := &baselineState{pps: 40000, valid: true, firstSeen: 100}
	bc := &config.BaselineSettings{Factor: 3, WarmupSeconds: 600, Floor: floor()}
	// nowSec 300, firstSeen 100 → 200s elapsed of 600 → 400s remaining.
	got := buildReason(MetricPPS, Rates{PPS: 100000}, config.Thresholds{PPS: 80000}, b, bc, 300)
	if got.ThresholdSource != "static" || got.Baseline != nil {
		t.Errorf("warming up should apply the static threshold: %+v", got)
	}
	if !got.BaselineConfigured || !got.WarmingUp || got.WarmupRemainingSeconds != 400 {
		t.Errorf("reason = %+v, want configured + warming up + 400s remaining", got)
	}
}

// TestBuildReasonPerProtocolStaysStatic: a per-protocol winning metric has no
// baseline even when the group's baseline is warmed — its threshold is static.
func TestBuildReasonPerProtocolStaysStatic(t *testing.T) {
	b := &baselineState{pps: 40000, valid: true, firstSeen: 0}
	bc := &config.BaselineSettings{Factor: 3, WarmupSeconds: 600, Floor: floor()}
	got := buildReason(MetricUDPPPS, Rates{PPS: 100000, UDPPPS: 90000}, config.Thresholds{PPS: 80000}, b, bc, 700)
	if got.ThresholdSource != "static" || got.Baseline != nil {
		t.Errorf("per-protocol metric should be static: %+v", got)
	}
	if !got.BaselineConfigured {
		t.Error("baseline is still configured (just not for this metric)")
	}
}

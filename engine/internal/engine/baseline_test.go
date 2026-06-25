package engine

import (
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// baselineSettings builds resolved settings without going through YAML.
func baselineSettings(factor float64, halfLife, warmup int, floorPPS uint64) *config.BaselineSettings {
	return &config.BaselineSettings{
		Factor:        factor,
		Alpha:         1 - math.Exp2(-1/float64(halfLife)),
		WarmupSeconds: warmup,
		Floor:         config.BaselineFloor{PPS: floorPPS, Mbps: 50, FlowsPerSec: 2000},
	}
}

func TestBaselineEWMAMath(t *testing.T) {
	bc := baselineSettings(3, 60, 0, 100)
	var b baselineState

	// First sample initializes.
	b.learn(Rates{PPS: 1000, Mbps: 8, FlowsPerSec: 500}, bc, 1000)
	if !b.valid || b.pps != 1000 {
		t.Fatalf("after init: %+v, want pps 1000", b)
	}

	// One half-life of a doubled sustained level moves each metric to
	// ~halfway. All three EWMAs must advance, not just pps.
	for s := int64(1); s <= 60; s++ {
		b.learn(Rates{PPS: 2000, Mbps: 16, FlowsPerSec: 1000}, bc, 1000+s)
	}
	if math.Abs(b.pps-1500) > 15 { // ~1% tolerance
		t.Errorf("pps after one half-life at 2x = %v, want ~1500", b.pps)
	}
	if math.Abs(b.mbps-12) > 0.12 {
		t.Errorf("mbps after one half-life at 2x = %v, want ~12", b.mbps)
	}
	if math.Abs(b.fps-750) > 7.5 {
		t.Errorf("fps after one half-life at 2x = %v, want ~750", b.fps)
	}
}

func TestBaselinePoisonResistance(t *testing.T) {
	bc := baselineSettings(3, 60, 0, 100)
	var b baselineState
	b.learn(Rates{PPS: 1000}, bc, 0)

	// An attacker pushing 100x traffic for one half-life: every sample is
	// clamped to baseline*factor, so the baseline grows at most as if the
	// input were 3x — far below the would-be 50500 of unclamped EWMA.
	for s := int64(1); s <= 60; s++ {
		b.learn(Rates{PPS: 100000}, bc, s)
	}
	unclampedHalfway := (1000.0 + 100000.0) / 2
	if b.pps >= unclampedHalfway/10 {
		t.Errorf("pps after poisoned half-life = %v; clamping failed (unclamped would be ~%v)", b.pps, unclampedHalfway)
	}
	// And it did grow toward the (clamped) 3x level, not stay frozen.
	if b.pps <= 1000 {
		t.Errorf("pps = %v, want growth above the initial 1000", b.pps)
	}
}

func TestEffectiveThresholds(t *testing.T) {
	static := config.Thresholds{PPS: 80000, Mbps: 1000, FlowsPerSec: 35000, UDPPPS: 40000}
	bc := baselineSettings(3, 3600, 600, 5000)

	var b baselineState
	// Not yet valid: static apply.
	if got := effectiveThresholds(static, &b, bc, 1000); got != static {
		t.Errorf("invalid baseline: thresholds = %+v, want static", got)
	}

	b.learn(Rates{PPS: 4000, Mbps: 100, FlowsPerSec: 3000}, bc, 1000)
	// Within warm-up: static still apply.
	if got := effectiveThresholds(static, &b, bc, 1100); got != static {
		t.Errorf("during warmup: thresholds = %+v, want static", got)
	}

	// Warmed up: pps tightens to baseline*3 = 12000; mbps to 300; fps to
	// 9000. Per-protocol limits untouched.
	got := effectiveThresholds(static, &b, bc, 1000+601)
	if got.PPS != 12000 || got.Mbps != 300 || got.FlowsPerSec != 9000 {
		t.Errorf("effective trio = %d/%d/%d, want 12000/300/9000", got.PPS, got.Mbps, got.FlowsPerSec)
	}
	if got.UDPPPS != 40000 {
		t.Errorf("per-protocol threshold changed: %d, want 40000", got.UDPPPS)
	}

	// Floor: a near-zero baseline cannot make detection hair-trigger.
	var quiet baselineState
	quiet.learn(Rates{PPS: 10, Mbps: 1, FlowsPerSec: 5}, bc, 1000)
	got = effectiveThresholds(static, &quiet, bc, 1000+601)
	if got.PPS != 5000 || got.Mbps != 50 || got.FlowsPerSec != 2000 {
		t.Errorf("floored trio = %d/%d/%d, want 5000/50/2000", got.PPS, got.Mbps, got.FlowsPerSec)
	}

	// Ceiling: a huge baseline cannot raise the bar above static.
	var fat baselineState
	fat.learn(Rates{PPS: 70000, Mbps: 900, FlowsPerSec: 30000}, bc, 1000)
	got = effectiveThresholds(static, &fat, bc, 1000+601)
	if got != static {
		t.Errorf("ceiling: thresholds = %+v, want static %+v", got, static)
	}
}

// baselineYAML enables baselines with zero warmup and a fast half-life so
// integration tests converge in simulated seconds.
const baselineYAML = baseYAML + `
baseline:
  factor: 3
  half_life_seconds: 10
  warmup_seconds: 5
  floor:
    pps: 5000
    mbps: 50
    flows_per_sec: 2000
`

// TestBaselineTriggersBelowStatic: traffic far below the static threshold
// but far above the host's learned normal is detected, with the effective
// (learned) threshold on the event.
func TestBaselineTriggersBelowStatic(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, baselineYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := "203.0.113.20"

	// Learn a ~10000 pps normal level past the 5s warmup.
	for s := 0; s < 8; s++ {
		floodAt(e, dst, 10, 1000) // 10000 pps
		runTick(e, clk)
	}
	expectQuiet(t, events)

	// Jump to 40000 pps: above baseline*3 (~30000) and the 5000 floor,
	// below the static 80000.
	floodAt(e, dst, 40, 1000)
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Metric != MetricPPS {
			t.Errorf("metric = %q, want pps", ev.Metric)
		}
		if ev.Threshold >= 80000 || ev.Threshold < 5000 {
			t.Errorf("threshold = %v, want the learned level in [5000, 80000)", ev.Threshold)
		}
		if ev.Rate < ev.Threshold {
			t.Errorf("rate %v below the effective threshold %v", ev.Rate, ev.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("no baseline-triggered AttackStarted")
	}
}

// TestBaselineStaticOnlyWithoutBlock: the same traffic jump without a
// baseline block stays silent (static thresholds only).
func TestBaselineStaticOnlyWithoutBlock(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1)) // no baseline block
	events := drain(e)
	dst := "203.0.113.20"

	for s := 0; s < 8; s++ {
		floodAt(e, dst, 8, 1000)
		runTick(e, clk)
	}
	floodAt(e, dst, 30, 1000) // 30000 pps/fps: below every static threshold
	runTick(e, clk)
	expectQuiet(t, events)
}

// TestBaselineFrozenDuringAttack: attack traffic does not train the
// baseline — after the attack ends the learned level is unchanged.
func TestBaselineFrozenDuringAttack(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, baselineYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := netip.MustParseAddr("203.0.113.20")

	for s := 0; s < 8; s++ {
		floodAt(e, dst.String(), 10, 1000)
		runTick(e, clk)
	}
	expectQuiet(t, events)
	sh := e.shardFor(dst)
	sh.mu.Lock()
	before := sh.hosts[dst].baselines[dirIn].pps
	sh.mu.Unlock()

	// Sustained attack at 40000 pps for several ticks.
	for s := 0; s < 5; s++ {
		floodAt(e, dst.String(), 40, 1000)
		runTick(e, clk)
	}

	sh.mu.Lock()
	after := sh.hosts[dst].baselines[dirIn].pps
	sh.mu.Unlock()
	// The clamped EWMA would have moved noticeably; frozen must stay put.
	if math.Abs(after-before) > before*0.01 {
		t.Errorf("baseline moved during attack: %v -> %v", before, after)
	}
}

// TestWarmupGatesBaseline: before warmup_seconds elapse the learned level
// does not gate detection even if traffic spikes above baseline*factor.
func TestWarmupGatesBaseline(t *testing.T) {
	yaml := strings.Replace(baselineYAML, "warmup_seconds: 5", "warmup_seconds: 600", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := "203.0.113.20"

	for s := 0; s < 3; s++ {
		floodAt(e, dst, 8, 1000)
		runTick(e, clk)
	}
	// 30000 pps: above baseline*3 (24000) but warmup (600s) has not
	// elapsed and it is below every static threshold — must stay quiet.
	floodAt(e, dst, 30, 1000)
	runTick(e, clk)
	expectQuiet(t, events)
}

// TestGroupTotalBaseline: total groups learn the summed level and detect a
// jump below their static total threshold.
func TestGroupTotalBaseline(t *testing.T) {
	yaml := groupsYAML + `
baseline:
  factor: 3
  half_life_seconds: 10
  warmup_seconds: 5
  floor:
    pps: 5000
    mbps: 50
    flows_per_sec: 2000
`
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Pool members at a combined ~12000 pps normal level past warmup.
	for s := 0; s < 8; s++ {
		floodAt(e, "203.0.113.33", 6, 1000)
		floodAt(e, "203.0.113.34", 6, 1000)
		runTick(e, clk)
	}
	expectQuiet(t, events)

	// Jump to 60000 pps combined: above baseline*3 (~36000) and the
	// floor, below pool's static 150000.
	floodAt(e, "203.0.113.33", 30, 1000)
	floodAt(e, "203.0.113.34", 30, 1000)
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Scope != ScopeGroup || ev.Group != "pool" {
			t.Fatalf("event = %+v, want pool group attack", ev)
		}
		if ev.Threshold >= 150000 {
			t.Errorf("threshold = %v, want the learned level below static 150000", ev.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("no baseline-triggered group AttackStarted")
	}
}

// TestEffectiveThresholdsEdgeClamps covers the floor>static misconfig (static
// ceiling must still win) and a non-finite factor (must collapse to static,
// never below the floor, on every architecture).
func TestEffectiveThresholdsEdgeClamps(t *testing.T) {
	var b baselineState
	b.learn(Rates{PPS: 1000, Mbps: 10, FlowsPerSec: 500}, baselineSettings(3, 60, 0, 100), 0)

	// floor above static: the static ceiling wins (safety rule).
	hiFloor := baselineSettings(3, 60, 0, 200000) // floor pps 200000 > static
	got := effectiveThresholds(config.Thresholds{PPS: 80000, Mbps: 1000, FlowsPerSec: 35000}, &b, hiFloor, 100)
	if got.PPS != 80000 {
		t.Errorf("floor>static: pps = %d, want the static ceiling 80000", got.PPS)
	}

	// NaN factor must not produce a 0 (arm64) or 1<<63 (amd64) effective
	// threshold; it collapses to static.
	nanBC := baselineSettings(math.NaN(), 60, 0, 5000)
	got = effectiveThresholds(config.Thresholds{PPS: 80000, Mbps: 1000, FlowsPerSec: 35000}, &b, nanBC, 100)
	if got.PPS != 80000 || got.Mbps != 1000 || got.FlowsPerSec != 35000 {
		t.Errorf("NaN factor: trio = %d/%d/%d, want static 80000/1000/35000", got.PPS, got.Mbps, got.FlowsPerSec)
	}
}

// TestBaselineNoLearnWithoutTraffic: a tracked host that sees no traffic in
// a direction never initializes that direction's baseline, so it stays on
// the static thresholds (no zero-baseline floor collapse).
func TestBaselineNoLearnWithoutTraffic(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, baselineYAML), WithClock(clk.Now), WithWindow(1))
	dst := netip.MustParseAddr("203.0.113.20")

	// Tiny incoming traffic keeps the host tracked, well past warmup, but
	// the outgoing direction never sees a packet.
	for s := 0; s < 10; s++ {
		floodAt(e, dst.String(), 1, 1) // 1 pps incoming, never an attack
		runTick(e, clk)
	}
	sh := e.shardFor(dst)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	hs := sh.hosts[dst]
	if hs == nil {
		t.Fatal("host evicted unexpectedly")
	}
	if hs.baselines[dirOut].valid {
		t.Error("outgoing baseline initialized despite zero outgoing traffic")
	}
}

// TestEmptyTotalGroupNoFalseAlert: a total group that is empty during warmup
// must not warm up on zero traffic and then false-alert when members arrive.
func TestEmptyTotalGroupNoFalseAlert(t *testing.T) {
	yaml := groupsYAML + `
baseline:
  factor: 3
  half_life_seconds: 10
  warmup_seconds: 5
  floor:
    pps: 5000
    mbps: 50
    flows_per_sec: 2000
`
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// Pool empty for well past the warmup.
	for s := 0; s < 10; s++ {
		runTick(e, clk)
	}
	// Members scale in at 20000 pps combined — below the 150000 static
	// total and a legitimate first burst, not an attack.
	for s := 0; s < 3; s++ {
		floodAt(e, "203.0.113.33", 10, 1000)
		floodAt(e, "203.0.113.34", 10, 1000)
		runTick(e, clk)
	}
	expectQuiet(t, events)
}

// TestBaselineFrozenInHysteresisTail: once an attack is active, traffic
// decaying through the hysteresis tail (below threshold but still inAttack)
// must not train the baseline.
func TestBaselineFrozenInHysteresisTail(t *testing.T) {
	// hysteresis 3s (baseYAML), 1s window so each tick is one second.
	clk := newMockClock()
	e := New(groupsStore(t, baselineYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := netip.MustParseAddr("203.0.113.20")

	// Warm up a ~10000 pps normal level.
	for s := 0; s < 8; s++ {
		floodAt(e, dst.String(), 10, 1000)
		runTick(e, clk)
	}
	expectQuiet(t, events)
	sh := e.shardFor(dst)
	sh.mu.Lock()
	learned := sh.hosts[dst].baselines[dirIn].pps
	sh.mu.Unlock()

	// Trigger an attack (40000 pps), then drop to a low-but-nonzero level
	// that sits in the hysteresis tail (below the frozen threshold).
	floodAt(e, dst.String(), 40, 1000)
	runTick(e, clk)
	if ev := <-events; ev.Kind != AttackStarted {
		t.Fatalf("event = %v, want AttackStarted", ev.Kind)
	}
	// One quiet-ish second below threshold while still inAttack: 8000 pps.
	floodAt(e, dst.String(), 8, 1000)
	runTick(e, clk)

	sh.mu.Lock()
	after := sh.hosts[dst].baselines[dirIn].pps
	sh.mu.Unlock()
	if math.Abs(after-learned) > learned*0.01 {
		t.Errorf("baseline moved during hysteresis tail: %v -> %v", learned, after)
	}
}

// TestOutgoingBaselineIndependent: outgoing baselines learn and gate
// separately from incoming.
func TestOutgoingBaselineIndependent(t *testing.T) {
	// directionsYAML has thresholds_outgoing pps 50000; add baselines.
	yaml := directionsYAML + `
baseline:
  factor: 3
  half_life_seconds: 10
  warmup_seconds: 5
  floor:
    pps: 2000
    mbps: 20
    flows_per_sec: 1000
`
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	src := "203.0.113.77"

	// Learn a ~6000 pps outgoing normal past warmup.
	for s := 0; s < 8; s++ {
		for i := 0; i < 6; i++ {
			e.Process(outboundFlow(src, 1000))
		}
		runTick(e, clk)
	}
	expectQuiet(t, events)

	// Jump outgoing to 25000 pps: above baseline*3 (~18000) and the 2000
	// floor, below the static outgoing 50000.
	for i := 0; i < 25; i++ {
		e.Process(outboundFlow(src, 1000))
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Direction != DirOutgoing {
			t.Fatalf("direction = %q, want outgoing", ev.Direction)
		}
		if ev.Threshold >= 50000 {
			t.Errorf("threshold = %v, want the learned outgoing level below static 50000", ev.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("no baseline-triggered outgoing AttackStarted")
	}
}

// TestPerGroupBaselineOverrideApplied: a hostgroup's own factor (not the
// global one) gates its hosts.
func TestPerGroupBaselineOverrideApplied(t *testing.T) {
	// Global factor 3; the web group (203.0.113.0/28) overrides to factor 10.
	yaml := groupsYAML + `
baseline:
  factor: 3
  half_life_seconds: 10
  warmup_seconds: 5
  floor:
    pps: 1000
    mbps: 10
    flows_per_sec: 500
`
	yaml = strings.Replace(yaml, "  - name: web\n    networks:\n      - \"203.0.113.0/28\"\n    thresholds:\n      pps: 10000\n      mbps: 1000\n      flows_per_sec: 35000\n",
		"  - name: web\n    networks:\n      - \"203.0.113.0/28\"\n    thresholds:\n      pps: 80000\n      mbps: 1000\n      flows_per_sec: 35000\n    baseline:\n      factor: 10\n      half_life_seconds: 10\n      warmup_seconds: 5\n      floor:\n        pps: 1000\n        mbps: 10\n        flows_per_sec: 500\n", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	dst := "203.0.113.5" // in web group

	// Learn ~3000 pps normal.
	for s := 0; s < 8; s++ {
		floodAt(e, dst, 3, 1000)
		runTick(e, clk)
	}
	// 25000 pps: above the global factor 3 level (~9000) but BELOW the
	// group's factor 10 level (~30000) — must stay quiet under the override.
	floodAt(e, dst, 25, 1000)
	runTick(e, clk)
	expectQuiet(t, events)

	// 70000 pps: above the group's factor-10 pps level (the quiet step above
	// also fed the baseline, lifting it) yet still below the 80000 static
	// ceiling — so a fire here proves the baseline-tightened pps threshold,
	// not the static one. (flows_per_sec is 0 for sFlow, so the trigger must
	// be pps.)
	floodAt(e, dst, 70, 1000)
	runTick(e, clk)
	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Metric != MetricPPS {
			t.Errorf("metric = %v, want pps", ev.Metric)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted above the group's factor-10 level")
	}
}

// TestEvictionDiscardsBaseline: a host that goes quiet is evicted with its
// baseline, and re-warms up on return (the learned level does not gate
// detection immediately).
func TestEvictionDiscardsBaseline(t *testing.T) {
	yaml := strings.Replace(baselineYAML, "warmup_seconds: 5", "warmup_seconds: 600", 1)
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	dst := netip.MustParseAddr("203.0.113.20")

	floodAt(e, dst.String(), 10, 1000)
	runTick(e, clk)
	if e.shardFor(dst).hosts[dst] == nil {
		t.Fatal("host not tracked after a flow")
	}

	// Go quiet well past the window: the host is evicted.
	clk.Advance(10 * time.Second)
	e.evalTick(clk.Now())
	if e.shardFor(dst).hosts[dst] != nil {
		t.Fatal("quiet host should have been evicted")
	}

	// On return it is a fresh state: baseline invalid, firstSeen reset, so
	// warm-up (600s) protects it with static thresholds again.
	floodAt(e, dst.String(), 10, 1000)
	runTick(e, clk)
	sh := e.shardFor(dst)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	hs := sh.hosts[dst]
	if hs == nil {
		t.Fatal("host not re-tracked on return")
	}
	if hs.baselines[dirIn].firstSeen != clk.Now().Unix() {
		t.Errorf("firstSeen = %d, want the return tick %d (re-warmup)", hs.baselines[dirIn].firstSeen, clk.Now().Unix())
	}
}

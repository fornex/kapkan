package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
)

// mockClock is a settable, monotonic-enough time source for deterministic
// simulated-time tests.
type mockClock struct {
	mu sync.Mutex
	t  time.Time
}

func newMockClock() *mockClock { return &mockClock{t: time.Unix(1_700_000_000, 0)} }

func (c *mockClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mockClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const baseYAML = `
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
  unban_hysteresis_seconds: 3
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

func testStore(t *testing.T) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(baseYAML))
	if err != nil {
		t.Fatalf("parse base config: %v", err)
	}
	return config.NewStore("", cfg)
}

func udpFlow(dst string, bytes, packets, rate uint64) flow.Flow {
	return flow.Flow{
		SrcAddr:      netip.MustParseAddr("198.51.100.50"),
		DstAddr:      netip.MustParseAddr(dst),
		IPProto:      17,
		SrcPort:      123,
		DstPort:      40000,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: rate,
		Wire:         flow.ProtoSFlow5,
	}
}

// drain collects events without blocking the test.
func drain(e *Engine) chan Event {
	out := make(chan Event, 64)
	go func() {
		for ev := range e.Events() {
			out <- ev
		}
	}()
	return out
}

func TestWindowedRateMath(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	dst := "203.0.113.7"

	// Inject a steady 100 sampled pps for 5 complete seconds, sampling
	// rate 10 => 1000 corrected pps; 1000 bytes/pkt => 1000*1000*8/1e6 =
	// 8 Mbps; flows = rate per record = 10/record * 100 records = 1000 fps.
	for s := 0; s < 5; s++ {
		for i := 0; i < 100; i++ {
			e.Process(udpFlow(dst, 1000, 1, 10))
		}
		clk.Advance(time.Second)
	}
	// Now evaluate at the second after the 5 filled seconds.
	hs := e.shardFor(netip.MustParseAddr(dst)).hosts[netip.MustParseAddr(dst)]
	rates, _, ok := e.windowedRates(hs, clk.Now().Unix())
	if !ok {
		t.Fatal("windowedRates ok = false, want true")
	}
	if rates.PPS != 1000 {
		t.Errorf("PPS = %v, want 1000", rates.PPS)
	}
	if rates.Mbps != 8 {
		t.Errorf("Mbps = %v, want 8", rates.Mbps)
	}
	if rates.FlowsPerSec != 1000 {
		t.Errorf("FlowsPerSec = %v, want 1000", rates.FlowsPerSec)
	}
}

func TestSamplingCorrection(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	dst := netip.MustParseAddr("203.0.113.8")

	// One flow per second for 5s, each 100 packets at sampling 1000.
	for s := 0; s < 5; s++ {
		e.Process(udpFlow(dst.String(), 64000, 100, 1000))
		clk.Advance(time.Second)
	}
	hs := e.shardFor(dst).hosts[dst]
	rates, _, _ := e.windowedRates(hs, clk.Now().Unix())
	// corrected pps per second = 100*1000 = 100000.
	if rates.PPS != 100000 {
		t.Errorf("PPS = %v, want 100000 (sampling-corrected)", rates.PPS)
	}
}

// runTick is a helper that advances the clock by one second and evaluates.
func runTick(e *Engine, clk *mockClock) {
	clk.Advance(time.Second)
	e.evalTick(clk.Now())
}

func TestAttackLifecycle(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	events := drain(e)
	dst := netip.MustParseAddr("203.0.113.20")

	// Flood: 200 records/sec, 1 pkt each, sampling 1000 => 200000 corrected
	// pps, well above the 80000 threshold. Inject for 3 seconds.
	inject := func() {
		for i := 0; i < 200; i++ {
			e.Process(udpFlow(dst.String(), 100, 1, 1000))
		}
	}
	inject()
	clk.Advance(time.Second)
	inject()
	clk.Advance(time.Second)
	inject()
	// At this point seconds [start, start+2] each have flood traffic.
	// Evaluate at start+3: window covers the 3 completed flood seconds.
	clk.Advance(time.Second)
	e.evalTick(clk.Now())

	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("first event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Target != dst {
			t.Errorf("target = %v, want %v", ev.Target, dst)
		}
		if ev.Metric != MetricPPS {
			t.Errorf("metric = %v, want pps", ev.Metric)
		}
		if ev.Rate <= ev.Threshold {
			t.Errorf("rate %v should exceed threshold %v", ev.Rate, ev.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted event within 3 simulated seconds")
	}

	// Traffic stops. The flood ages out of the 5s window over the next few
	// ticks; only then does the hysteresis (3s) countdown begin. The attack
	// must NOT end on the very first quiet tick (flood still dominates the
	// window), but must end once the window has drained and hysteresis has
	// elapsed.
	runTick(e, clk)
	select {
	case ev := <-events:
		t.Fatalf("premature %v on first quiet tick; flood still in window", ev.Kind)
	case <-time.After(50 * time.Millisecond):
	}

	var ended bool
	for i := 0; i < 12 && !ended; i++ {
		runTick(e, clk)
		select {
		case ev := <-events:
			if ev.Kind != AttackEnded {
				t.Fatalf("event = %v, want AttackEnded", ev.Kind)
			}
			if ev.StartedAt.IsZero() {
				t.Error("AttackEnded.StartedAt must be set")
			}
			if ev.Metric != MetricPPS {
				t.Errorf("AttackEnded.Metric = %v, want the original trigger pps", ev.Metric)
			}
			if ev.Threshold <= 0 {
				t.Error("AttackEnded.Threshold must carry the configured threshold")
			}
			ended = true
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !ended {
		t.Fatal("AttackEnded never emitted after traffic stopped")
	}
}

// TestHysteresisStateMachine isolates the unban hysteresis with a 1-second
// window, so each evaluated second maps cleanly to one tick. It inspects the
// host state directly: the attack must not end while below for less than
// hysteresis seconds, a resurge must reset the countdown (belowSince
// cleared), and the end must come only once traffic has stayed below for at
// least hysteresis seconds measured from the last time it dropped.
func TestHysteresisStateMachine(t *testing.T) {
	store := testStore(t)
	hysteresis := store.Get().Ban.UnbanHysteresis() // 3s
	clk := newMockClock()
	e := New(store, WithClock(clk.Now), WithWindow(1))
	dst := netip.MustParseAddr("203.0.113.21")
	hostOf := func() *hostState { return e.shardFor(dst).hosts[dst] }
	flood := func() {
		for i := 0; i < 200; i++ {
			e.Process(udpFlow(dst.String(), 100, 1, 1000))
		}
	}

	// Establish attack: flood second S, evaluate at S+1.
	flood()
	runTick(e, clk)
	hs := hostOf()
	if hs == nil || !hs.attacks[dirIn].inAttack {
		t.Fatal("attack not established")
	}

	// Two quiet ticks: below threshold, counting down, not yet ended.
	runTick(e, clk)
	if !hs.attacks[dirIn].inAttack {
		t.Fatal("ended too early on first quiet tick")
	}
	first := hs.attacks[dirIn].belowSince
	if first.IsZero() {
		t.Fatal("belowSince must be set on the first below-threshold tick")
	}
	runTick(e, clk)
	if !hs.attacks[dirIn].inAttack {
		t.Fatal("ended too early on second quiet tick")
	}
	if !hs.attacks[dirIn].belowSince.Equal(first) {
		t.Fatal("belowSince must not move while continuously below")
	}

	// Resurge: must clear the countdown.
	flood()
	runTick(e, clk)
	if !hs.attacks[dirIn].inAttack {
		t.Fatal("attack must remain active through a resurge")
	}
	if !hs.attacks[dirIn].belowSince.IsZero() {
		t.Fatal("resurge must reset the hysteresis countdown (belowSince cleared)")
	}

	// Go quiet again and run until the attack ends. The fresh countdown
	// starts at the next below tick; the end must be at least hysteresis
	// seconds after that, proving the earlier below-period did not count.
	runTick(e, clk)
	restart := hs.attacks[dirIn].belowSince
	if restart.IsZero() {
		t.Fatal("belowSince must be set again after going quiet post-resurge")
	}
	var endedAt time.Time
	for i := 0; i < 6 && hs.attacks[dirIn].inAttack; i++ {
		runTick(e, clk)
		if !hs.attacks[dirIn].inAttack {
			endedAt = clk.Now()
		}
	}
	if hs.attacks[dirIn].inAttack {
		t.Fatal("attack never ended after sustained quiet")
	}
	if d := endedAt.Sub(restart); d < hysteresis {
		t.Errorf("ended after %v below threshold, want >= %v (hysteresis)", d, hysteresis)
	}
}

func TestWhitelistNeverDetected(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	events := drain(e)
	wl := "203.0.113.1" // in protected_whitelist

	for s := 0; s < 6; s++ {
		for i := 0; i < 500; i++ {
			e.Process(udpFlow(wl, 1000, 10, 1000))
		}
		clk.Advance(time.Second)
		e.evalTick(clk.Now())
	}
	select {
	case ev := <-events:
		t.Fatalf("whitelisted host produced event %v; must never be detected", ev.Kind)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestOutOfNetworkIgnored(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	events := drain(e)
	out := "198.51.100.9" // not inside 203.0.113.0/24

	for s := 0; s < 6; s++ {
		for i := 0; i < 500; i++ {
			e.Process(udpFlow(out, 1000, 10, 1000))
		}
		clk.Advance(time.Second)
		e.evalTick(clk.Now())
	}
	// Host must not even be tracked.
	if hs := e.shardFor(netip.MustParseAddr(out)).hosts[netip.MustParseAddr(out)]; hs != nil {
		t.Error("out-of-network host was tracked; detection must be scoped to networks")
	}
	select {
	case ev := <-events:
		t.Fatalf("out-of-network host produced event %v", ev.Kind)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestReloadWhitelistEndsActiveAttack covers safety rule 5 across hot
// reload: whitelisting a host that is currently under attack must end the
// attack within one evaluation tick — emitting AttackEnded so mitigation
// withdraws the route — instead of leaving it dangling until the ban TTL.
func TestReloadWhitelistEndsActiveAttack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kapkan.yaml")
	if err := os.WriteFile(path, []byte(baseYAML), 0o600); err != nil {
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
	dst := netip.MustParseAddr("203.0.113.50")
	flood := func() {
		for i := 0; i < 200; i++ {
			e.Process(udpFlow(dst.String(), 100, 1, 1000))
		}
	}

	flood()
	runTick(e, clk)
	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("first event = %v, want AttackStarted", ev.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("attack not established")
	}

	// Whitelist the target on disk and hot-reload.
	v2 := strings.Replace(baseYAML, "  - \"203.0.113.1\"\n",
		"  - \"203.0.113.1\"\n  - \"203.0.113.50\"\n", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Keep flooding: traffic level must not matter for a whitelisted host.
	flood()
	runTick(e, clk)
	select {
	case ev := <-events:
		if ev.Kind != AttackEnded {
			t.Fatalf("event after whitelisting = %v, want AttackEnded", ev.Kind)
		}
		if ev.StartedAt.IsZero() {
			t.Error("AttackEnded.StartedAt must be set")
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackEnded after target was whitelisted via reload")
	}
	if hs := e.shardFor(dst).hosts[dst]; hs != nil && hs.attacks[dirIn].inAttack {
		t.Error("host must not remain flagged in-attack after whitelisting")
	}
}

func TestQuietHostEvicted(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	dst := netip.MustParseAddr("203.0.113.30")

	e.Process(udpFlow(dst.String(), 100, 1, 1)) // tiny, never an attack
	if hs := e.shardFor(dst).hosts[dst]; hs == nil {
		t.Fatal("host should be tracked after a flow")
	}
	// Advance well past the window with no traffic, evaluate.
	clk.Advance(10 * time.Second)
	e.evalTick(clk.Now())
	if hs := e.shardFor(dst).hosts[dst]; hs != nil {
		t.Error("quiet non-attacking host should have been evicted")
	}
}

func TestSnapshot(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	dst := netip.MustParseAddr("203.0.113.40")
	for s := 0; s < 5; s++ {
		e.Process(udpFlow(dst.String(), 1000, 1, 10))
		clk.Advance(time.Second)
	}
	snap := e.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("len(snapshot) = %d, want 1", len(snap))
	}
	if snap[0].Target != dst {
		t.Errorf("snapshot target = %v, want %v", snap[0].Target, dst)
	}
}

// waitEvent reads one event or fails after a short timeout.
func waitEvent(t *testing.T, events chan Event) Event {
	t.Helper()
	select {
	case ev := <-events:
		return ev
	case <-time.After(time.Second):
		t.Fatal("expected an event, got none")
		return Event{}
	}
}

// TestMbpsThresholdTrigger drives an attack that crosses only the Mbps
// threshold (pps and flows_per_sec stay below theirs), verifying the Mbps
// detection path end-to-end.
func TestMbpsThresholdTrigger(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	events := drain(e)
	dst := netip.MustParseAddr("203.0.113.70")
	// rate 20000, 1 pkt, 30000 bytes => 20000 pps (<80000), 20000 fps
	// (<35000), 4800 Mbps (>1000).
	inject := func() {
		e.Process(flow.Flow{
			SrcAddr: netip.MustParseAddr("198.51.100.5"), DstAddr: dst,
			IPProto: 17, Bytes: 30000, Packets: 1, SamplingRate: 20000, Wire: flow.ProtoSFlow5,
		})
	}
	for s := 0; s < 5; s++ {
		inject()
		clk.Advance(time.Second)
	}
	e.evalTick(clk.Now())
	ev := waitEvent(t, events)
	if ev.Kind != AttackStarted {
		t.Fatalf("kind = %v, want AttackStarted", ev.Kind)
	}
	if ev.Metric != MetricMbps {
		t.Errorf("metric = %v, want mbps (pps/flows are below their thresholds)", ev.Metric)
	}
}

// TestFlowsThresholdTrigger drives an attack that crosses only the
// flows_per_sec threshold.
func TestFlowsThresholdTrigger(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(5))
	events := drain(e)
	dst := netip.MustParseAddr("203.0.113.71")
	// 40 records/sec, rate 1000, 1 pkt, 64 bytes => 40000 pps (<80000),
	// 40000 fps (>35000), ~20 Mbps (<1000). Only flows_per_sec is crossed.
	inject := func() {
		for i := 0; i < 40; i++ {
			e.Process(flow.Flow{
				SrcAddr: netip.MustParseAddr("198.51.100.6"), DstAddr: dst,
				IPProto: 17, Bytes: 64, Packets: 1, SamplingRate: 1000, Wire: flow.ProtoSFlow5,
			})
		}
	}
	for s := 0; s < 5; s++ {
		inject()
		clk.Advance(time.Second)
	}
	e.evalTick(clk.Now())
	ev := waitEvent(t, events)
	if ev.Kind != AttackStarted {
		t.Fatalf("kind = %v, want AttackStarted", ev.Kind)
	}
	if ev.Metric != MetricFPS {
		t.Errorf("metric = %v, want flows_per_sec", ev.Metric)
	}
}

// ipv6Store returns a store whose protected networks include an IPv6 prefix.
func ipv6Store(t *testing.T) *config.Store {
	t.Helper()
	yaml := strings.Replace(baseYAML,
		"networks:\n  - \"203.0.113.0/24\"\n",
		"networks:\n  - \"203.0.113.0/24\"\n  - \"2001:db8::/32\"\n", 1)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse ipv6 config: %v", err)
	}
	return config.NewStore("", cfg)
}

// TestIPv6AttackDetected verifies an IPv6 destination inside a protected
// prefix is tracked and triggers detection just like IPv4.
func TestIPv6AttackDetected(t *testing.T) {
	clk := newMockClock()
	e := New(ipv6Store(t), WithClock(clk.Now), WithWindow(5))
	events := drain(e)
	dst := netip.MustParseAddr("2001:db8::dead")
	inject := func() {
		for i := 0; i < 200; i++ {
			e.Process(udpFlow(dst.String(), 100, 1, 1000)) // 200000 pps
		}
	}
	for s := 0; s < 3; s++ {
		inject()
		clk.Advance(time.Second)
	}
	e.evalTick(clk.Now())
	ev := waitEvent(t, events)
	if ev.Kind != AttackStarted {
		t.Fatalf("kind = %v, want AttackStarted", ev.Kind)
	}
	if ev.Target != dst {
		t.Errorf("target = %v, want %v", ev.Target, dst)
	}
}

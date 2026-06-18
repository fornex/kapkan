package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/flow"
)

// directionsYAML enables per-protocol incoming thresholds and outgoing
// detection. Total pps stays high (80000) so per-protocol triggers are
// observable below it.
const directionsYAML = `
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
  flows_per_sec: 1000000
  udp_pps: 20000
  tcp_syn_pps: 5000
  frag_pps: 3000
thresholds_outgoing:
  pps: 50000
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

func tcpFlow(dst string, flags uint8, rate uint64) flow.Flow {
	return flow.Flow{
		SrcAddr:      netip.MustParseAddr("198.51.100.50"),
		DstAddr:      netip.MustParseAddr(dst),
		IPProto:      6,
		TCPFlags:     flags,
		SrcPort:      443,
		DstPort:      40000,
		Bytes:        60,
		Packets:      1,
		SamplingRate: rate,
		Wire:         flow.ProtoSFlow5,
	}
}

func fragUDPFlow(dst string, rate uint64) flow.Flow {
	f := udpFlow(dst, 1400, 1, rate)
	f.Fragment = true
	return f
}

// outboundFlow originates at a protected host toward the outside world.
func outboundFlow(src string, rate uint64) flow.Flow {
	return flow.Flow{
		SrcAddr:      netip.MustParseAddr(src),
		DstAddr:      netip.MustParseAddr("198.51.100.9"),
		IPProto:      17,
		SrcPort:      40000,
		DstPort:      80,
		Bytes:        100,
		Packets:      1,
		SamplingRate: rate,
		Wire:         flow.ProtoSFlow5,
	}
}

func expectStart(t *testing.T, events chan Event, wantMetric Metric, wantDir Direction) Event {
	t.Helper()
	select {
	case ev := <-events:
		if ev.Kind != AttackStarted {
			t.Fatalf("event = %v, want AttackStarted", ev.Kind)
		}
		if ev.Metric != wantMetric {
			t.Fatalf("metric = %q, want %q", ev.Metric, wantMetric)
		}
		if ev.Direction != wantDir {
			t.Fatalf("direction = %q, want %q", ev.Direction, wantDir)
		}
		return ev
	case <-time.After(time.Second):
		t.Fatalf("no AttackStarted (want metric %q)", wantMetric)
		return Event{}
	}
}

func expectQuiet(t *testing.T, events chan Event) {
	t.Helper()
	select {
	case ev := <-events:
		t.Fatalf("unexpected event: kind=%v metric=%q direction=%q target=%v",
			ev.Kind, ev.Metric, ev.Direction, ev.Target)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestUDPThresholdTriggersBelowTotal: a UDP flood crossing udp_pps fires
// with the udp_pps metric even though total pps stays below the total limit.
func TestUDPThresholdTriggersBelowTotal(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 30000 pps UDP: above udp_pps 20000, below total 80000.
	floodAt(e, "203.0.113.7", 30, 1000)
	runTick(e, clk)

	ev := expectStart(t, events, MetricUDPPPS, DirIncoming)
	if ev.Threshold != 20000 {
		t.Errorf("threshold = %v, want 20000", ev.Threshold)
	}
	if ev.Rates.UDPPPS < 20000 {
		t.Errorf("rates.udp_pps = %v, want ~30000", ev.Rates.UDPPPS)
	}
}

// TestSYNClassification: pure SYNs count toward tcp_syn_pps; SYN-ACKs do not.
func TestSYNClassification(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 10000 pps of SYN-ACK (0x12): must NOT count as SYN flood.
	for i := 0; i < 10; i++ {
		e.Process(tcpFlow("203.0.113.8", 0x12, 1000))
	}
	runTick(e, clk)
	expectQuiet(t, events)

	// 10000 pps of pure SYN (0x02): above tcp_syn_pps 5000.
	for i := 0; i < 10; i++ {
		e.Process(tcpFlow("203.0.113.8", 0x02, 1000))
	}
	runTick(e, clk)
	ev := expectStart(t, events, MetricTCPSYNPPS, DirIncoming)
	if ev.Rates.TCPSYNPPS < 5000 {
		t.Errorf("rates.tcp_syn_pps = %v, want ~10000", ev.Rates.TCPSYNPPS)
	}
	if ev.Rates.TCPPPS < ev.Rates.TCPSYNPPS {
		t.Errorf("tcp_pps (%v) must include syn packets (%v)", ev.Rates.TCPPPS, ev.Rates.TCPSYNPPS)
	}
}

// TestFragmentThreshold: non-first fragments trip frag_pps.
func TestFragmentThreshold(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 5000 pps of fragments: above frag_pps 3000, below udp_pps 20000.
	for i := 0; i < 5; i++ {
		e.Process(fragUDPFlow("203.0.113.9", 1000))
	}
	runTick(e, clk)
	expectStart(t, events, MetricFragPPS, DirIncoming)
}

// TestOutgoingDetection: a protected host flooding outward is detected with
// direction=outgoing against thresholds_outgoing.
func TestOutgoingDetection(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 60000 pps outbound from a protected host: above outgoing pps 50000.
	src := "203.0.113.77"
	for i := 0; i < 60; i++ {
		e.Process(outboundFlow(src, 1000))
	}
	runTick(e, clk)

	ev := expectStart(t, events, MetricPPS, DirOutgoing)
	if ev.Target != netip.MustParseAddr(src) {
		t.Errorf("target = %v, want the attacking source %s", ev.Target, src)
	}
	if !ev.BanEnabled {
		t.Error("BanEnabled = false, want true (default policy)")
	}
	// Outgoing attacks are classified too — here a plain UDP flood the
	// compromised host originates.
	if ev.Classification == nil || ev.Classification.Type != AttackUDPFlood {
		t.Errorf("outgoing classification = %+v, want udp_flood", ev.Classification)
	}
}

// TestOutgoingDisabledCostsNothing: without thresholds_outgoing the engine
// does not even track sources.
func TestOutgoingDisabledCostsNothing(t *testing.T) {
	clk := newMockClock()
	e := New(testStore(t), WithClock(clk.Now), WithWindow(1)) // baseYAML: no outgoing
	events := drain(e)

	src := netip.MustParseAddr("203.0.113.77")
	for i := 0; i < 200; i++ {
		e.Process(outboundFlow(src.String(), 1000))
	}
	runTick(e, clk)
	expectQuiet(t, events)
	if e.shardFor(src).hosts[src] != nil {
		t.Error("source tracked despite outgoing detection being disabled")
	}
}

// TestSimultaneousInOutAttacks: one host can be under attack and attacking
// at the same time; both lifecycles run independently.
func TestSimultaneousInOutAttacks(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)
	host := "203.0.113.42"

	// Incoming UDP flood (30000 > udp_pps 20000) + outgoing flood
	// (60000 > outgoing pps 50000) in the same second.
	floodAt(e, host, 30, 1000)
	for i := 0; i < 60; i++ {
		e.Process(outboundFlow(host, 1000))
	}
	runTick(e, clk)

	got := map[Direction]Event{}
	for i := 0; i < 2; i++ {
		select {
		case ev := <-events:
			if ev.Kind != AttackStarted {
				t.Fatalf("event = %v, want AttackStarted", ev.Kind)
			}
			got[ev.Direction] = ev
		case <-time.After(time.Second):
			t.Fatalf("expected 2 AttackStarted events, got %d", len(got))
		}
	}
	if _, ok := got[DirIncoming]; !ok {
		t.Error("missing incoming attack event")
	}
	if _, ok := got[DirOutgoing]; !ok {
		t.Error("missing outgoing attack event")
	}

	// Both end after quiet + hysteresis, independently. Ticks drive the
	// simulated clock; the timed receive (instead of a non-blocking poll)
	// gives the drain goroutine time to forward events emitted by a tick,
	// otherwise an already-emitted AttackEnded can be missed.
	var ends int
	for i := 0; i < 12 && ends < 2; i++ {
		runTick(e, clk)
	recv:
		for ends < 2 {
			select {
			case ev := <-events:
				if ev.Kind != AttackEnded {
					t.Fatalf("event = %v, want AttackEnded", ev.Kind)
				}
				ends++
			case <-time.After(20 * time.Millisecond):
				break recv
			}
		}
	}
	if ends != 2 {
		t.Fatalf("AttackEnded events = %d, want 2 (one per direction)", ends)
	}
}

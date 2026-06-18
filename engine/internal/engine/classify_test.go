package engine

import (
	"math"
	"testing"
	"time"
)

// mkSample builds a sample whose only meaningful parts for classification
// are the untruncated total and the top source port.
func mkSample(srcPort string, packets, bytes uint64, protoKey string, protoPackets uint64) *AttackSample {
	return &AttackSample{
		TopSrcPorts:  []Counter{{Key: srcPort, Packets: packets, Bytes: bytes}},
		Protocols:    []Counter{{Key: protoKey, Packets: protoPackets}},
		TotalPackets: protoPackets,
	}
}

func TestClassifyVectors(t *testing.T) {
	tests := []struct {
		name     string
		rates    Rates
		sample   *AttackSample
		wantType AttackType
		wantPort uint16
		wantConf float64
	}{
		{
			name:  "ntp amplification",
			rates: Rates{PPS: 100000, UDPPPS: 95000},
			// 90% of sampled packets from port 123, avg 468 bytes.
			sample:   mkSample("123", 90000, 90000*468, "udp", 100000),
			wantType: AttackNTPAmplification,
			wantPort: 123,
			wantConf: 0.9, // port share, not the UDP share
		},
		{
			name:     "dns amplification",
			rates:    Rates{PPS: 100000, UDPPPS: 80000},
			sample:   mkSample("53", 70000, 70000*1200, "udp", 100000),
			wantType: AttackDNSAmplification,
			wantPort: 53,
			wantConf: 0.7,
		},
		{
			name:     "cldap amplification",
			rates:    Rates{PPS: 100000, UDPPPS: 80000},
			sample:   mkSample("389", 60000, 60000*1300, "udp", 100000),
			wantType: AttackCLDAPAmplification,
			wantPort: 389,
			wantConf: 0.6,
		},
		{
			name:     "ssdp amplification",
			rates:    Rates{PPS: 100000, UDPPPS: 70000},
			sample:   mkSample("1900", 55000, 55000*350, "udp", 100000),
			wantType: AttackSSDPAmplification,
			wantPort: 1900,
			wantConf: 0.55,
		},
		{
			name:     "chargen amplification",
			rates:    Rates{PPS: 100000, UDPPPS: 90000},
			sample:   mkSample("19", 80000, 80000*1000, "udp", 100000),
			wantType: AttackChargenAmplification,
			wantPort: 19,
			wantConf: 0.8,
		},
		{
			name:     "memcached amplification",
			rates:    Rates{PPS: 50000, UDPPPS: 49000},
			sample:   mkSample("11211", 40000, 40000*1400, "udp", 50000),
			wantType: AttackMemcachedAmplification,
			wantPort: 11211,
			wantConf: 0.8,
		},
		{
			name:  "small packets from service port are not amplification",
			rates: Rates{PPS: 100000, UDPPPS: 95000},
			// Port 53 dominant but request-sized packets (60B).
			sample:   mkSample("53", 90000, 90000*60, "udp", 100000),
			wantType: AttackUDPFlood,
			wantConf: 0.95,
		},
		{
			name:     "service port below dominance is plain udp flood",
			rates:    Rates{PPS: 100000, UDPPPS: 95000},
			sample:   mkSample("123", 30000, 30000*468, "udp", 100000),
			wantType: AttackUDPFlood,
			wantConf: 0.95,
		},
		{
			name: "fragmented amplification stays amplification",
			// UDP and fragments both dominant; the reflected-port signature
			// is more specific and is checked first.
			rates:    Rates{PPS: 100000, UDPPPS: 90000, FragPPS: 80000},
			sample:   mkSample("53", 85000, 85000*1200, "udp", 100000),
			wantType: AttackDNSAmplification,
			wantPort: 53,
			wantConf: 0.85,
		},
		{
			name:     "syn flood",
			rates:    Rates{PPS: 100000, TCPPPS: 98000, TCPSYNPPS: 95000},
			wantType: AttackSYNFlood,
			wantConf: 0.95, // the SYN share, not the broader TCP share
		},
		{
			name:     "fragment flood",
			rates:    Rates{PPS: 100000, UDPPPS: 40000, FragPPS: 80000},
			wantType: AttackFragmentFlood,
			wantConf: 0.8,
		},
		{
			name: "fragmented udp flood prefers fragment signature over udp",
			// Both dominant: fragments win (more specific than generic UDP).
			rates:    Rates{PPS: 100000, UDPPPS: 90000, FragPPS: 85000},
			wantType: AttackFragmentFlood,
			wantConf: 0.85,
		},
		{
			name: "fragmented icmp flood prefers fragment signature over icmp",
			// Fragments overlap their base protocol; frag is checked first.
			rates:    Rates{PPS: 100000, ICMPPPS: 85000, FragPPS: 80000},
			wantType: AttackFragmentFlood,
			wantConf: 0.8,
		},
		{
			name:     "icmp flood",
			rates:    Rates{PPS: 100000, ICMPPPS: 90000},
			wantType: AttackICMPFlood,
			wantConf: 0.9,
		},
		{
			name:     "udp flood without sample",
			rates:    Rates{PPS: 100000, UDPPPS: 90000},
			wantType: AttackUDPFlood,
			wantConf: 0.9,
		},
		{
			name:     "tcp ack flood",
			rates:    Rates{PPS: 100000, TCPPPS: 90000, TCPSYNPPS: 1000},
			wantType: AttackTCPFlood,
			wantConf: 0.9,
		},
		{
			name:     "nothing dominant is mixed with zero confidence",
			rates:    Rates{PPS: 100000, UDPPPS: 30000, TCPPPS: 30000, ICMPPPS: 30000},
			wantType: AttackMixed,
			wantConf: 0,
		},
		{
			name: "unknown protocol flood is mixed with zero confidence",
			// e.g. GRE/ESP: counted in the total class only — no signal at
			// all must not read as 100% confident.
			rates:    Rates{PPS: 100000},
			wantType: AttackMixed,
			wantConf: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.rates, tt.sample)
			if got == nil {
				t.Fatal("classify() = nil, want a classification")
			}
			if got.Type != tt.wantType {
				t.Fatalf("type = %q, want %q (confidence %v)", got.Type, tt.wantType, got.Confidence)
			}
			if got.SrcPort != tt.wantPort {
				t.Errorf("src_port = %d, want %d", got.SrcPort, tt.wantPort)
			}
			if math.Abs(got.Confidence-tt.wantConf) > 1e-9 {
				t.Errorf("confidence = %v, want %v", got.Confidence, tt.wantConf)
			}
		})
	}

	if got := classify(Rates{}, nil); got != nil {
		t.Errorf("classify(no traffic) = %+v, want nil", got)
	}
}

// TestClassificationOnEvents: end-to-end through the engine — an NTP
// amplification pattern lands on the start event as ntp_amplification, and
// a SYN flood as syn_flood.
func TestClassificationOnEvents(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, directionsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// NTP amplification at one host: src port 123, 468-byte responses,
	// 30000 pps (above udp_pps 20000).
	for i := 0; i < 30; i++ {
		f := attackerFlow("198.51.100.7", "203.0.113.10", 123, 1000)
		e.Process(f)
	}
	// Pure SYN flood at another host: 10000 pps (above tcp_syn_pps 5000).
	for i := 0; i < 10; i++ {
		e.Process(tcpFlow("203.0.113.11", 0x02, 1000))
	}
	runTick(e, clk)

	got := map[string]*Classification{}
	for i := 0; i < 2; i++ {
		select {
		case ev := <-events:
			if ev.Kind != AttackStarted {
				t.Fatalf("event = %v, want AttackStarted", ev.Kind)
			}
			got[ev.Target.String()] = ev.Classification
		case <-time.After(time.Second):
			t.Fatalf("expected 2 AttackStarted events, got %d", len(got))
		}
	}

	ntp := got["203.0.113.10"]
	if ntp == nil || ntp.Type != AttackNTPAmplification || ntp.SrcPort != 123 {
		t.Errorf("ntp classification = %+v, want ntp_amplification on port 123", ntp)
	}
	syn := got["203.0.113.11"]
	if syn == nil || syn.Type != AttackSYNFlood {
		t.Errorf("syn classification = %+v, want syn_flood", syn)
	}
}

// TestClassificationWithoutSample: with the traffic buffer disabled the
// classifier still types the flood from rates alone.
func TestClassificationWithoutSample(t *testing.T) {
	yaml := "samples:\n  enabled: false\n" + directionsYAML
	clk := newMockClock()
	e := New(groupsStore(t, yaml), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	for i := 0; i < 30; i++ {
		e.Process(udpFlow("203.0.113.10", 100, 1, 1000))
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Sample != nil {
			t.Error("sample present despite sampling disabled")
		}
		if ev.Classification == nil || ev.Classification.Type != AttackUDPFlood {
			t.Errorf("classification = %+v, want udp_flood from rates alone", ev.Classification)
		}
	case <-time.After(time.Second):
		t.Fatal("no AttackStarted")
	}
}

// TestGroupAttackClassified: total-group attacks carry a classification of
// the summed traffic.
func TestGroupAttackClassified(t *testing.T) {
	clk := newMockClock()
	e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(1))
	events := drain(e)

	// 180000 pps of NTP amplification spread over the pool members.
	for _, m := range []string{"203.0.113.33", "203.0.113.34", "203.0.113.35"} {
		for i := 0; i < 60; i++ {
			e.Process(attackerFlow("198.51.100.7", m, 123, 1000))
		}
	}
	runTick(e, clk)

	select {
	case ev := <-events:
		if ev.Scope != ScopeGroup {
			t.Fatalf("scope = %q, want group", ev.Scope)
		}
		if ev.Classification == nil || ev.Classification.Type != AttackNTPAmplification {
			t.Errorf("group classification = %+v, want ntp_amplification", ev.Classification)
		}
	case <-time.After(time.Second):
		t.Fatal("no group AttackStarted")
	}
}

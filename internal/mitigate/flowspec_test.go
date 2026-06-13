package mitigate

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
)

func cls(t engine.AttackType) *engine.Classification { return &engine.Classification{Type: t} }

func TestGenerateRulesVectors(t *testing.T) {
	v4 := netip.MustParseAddr("203.0.113.66")
	v6 := netip.MustParseAddr("2001:db8::42")

	tests := []struct {
		name   string
		target netip.Addr
		cls    *engine.Classification
		wantN  int
		check  func(t *testing.T, r FlowSpecRule)
	}{
		{
			name: "ntp amplification → udp src-port 123", target: v4, cls: cls(engine.AttackNTPAmplification), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 17 || r.SrcPort != 123 {
					t.Errorf("got proto/src-port %d/%d, want 17/123", r.Proto, r.SrcPort)
				}
			},
		},
		{
			name: "memcached → udp src-port 11211", target: v4, cls: cls(engine.AttackMemcachedAmplification), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 17 || r.SrcPort != 11211 {
					t.Errorf("got proto/src-port %d/%d, want 17/11211", r.Proto, r.SrcPort)
				}
			},
		},
		{
			name: "syn flood → tcp syn-flag", target: v4, cls: cls(engine.AttackSYNFlood), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 6 || r.TCPFlags != tcpSYN {
					t.Errorf("got proto/flags %d/0x%02x, want 6/0x02", r.Proto, r.TCPFlags)
				}
			},
		},
		{
			name: "fragment flood → fragment match", target: v4, cls: cls(engine.AttackFragmentFlood), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if !r.Fragment || r.Proto != 0 {
					t.Errorf("got fragment=%v proto=%d, want true/0", r.Fragment, r.Proto)
				}
			},
		},
		{
			name: "icmp flood v4 → proto 1", target: v4, cls: cls(engine.AttackICMPFlood), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 1 {
					t.Errorf("got proto %d, want 1 (icmp)", r.Proto)
				}
			},
		},
		{
			name: "icmp flood v6 → proto 58", target: v6, cls: cls(engine.AttackICMPFlood), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 58 {
					t.Errorf("got proto %d, want 58 (icmpv6)", r.Proto)
				}
			},
		},
		{
			name: "udp flood → proto 17", target: v4, cls: cls(engine.AttackUDPFlood), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 17 || r.SrcPort != 0 {
					t.Errorf("got proto/src-port %d/%d, want 17/any", r.Proto, r.SrcPort)
				}
			},
		},
		{
			name: "tcp flood → proto 6", target: v4, cls: cls(engine.AttackTCPFlood), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 6 || r.TCPFlags != 0 {
					t.Errorf("got proto/flags %d/0x%02x, want 6/any", r.Proto, r.TCPFlags)
				}
			},
		},
		{
			name: "mixed → destination-only", target: v4, cls: cls(engine.AttackMixed), wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 0 || r.SrcPort != 0 || r.Fragment {
					t.Errorf("mixed rule should be destination-only, got %+v", r)
				}
			},
		},
		{
			name: "nil classification → destination-only", target: v4, cls: nil, wantN: 1,
			check: func(t *testing.T, r FlowSpecRule) {
				if r.Proto != 0 {
					t.Errorf("nil cls rule should be destination-only, got %+v", r)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := generateRules(tt.target, engine.DirIncoming, tt.cls, nil, config.FlowSpecDiscard, 0)
			if len(rules) != tt.wantN {
				t.Fatalf("rule count = %d, want %d: %v", len(rules), tt.wantN, rules)
			}
			r := rules[0]
			// Destination is always the victim host prefix (/32 or /128).
			wantBits := 32
			if tt.target.Is6() {
				wantBits = 128
			}
			if r.Dst.Addr() != tt.target || r.Dst.Bits() != wantBits {
				t.Errorf("dst = %s, want %s/%d", r.Dst, tt.target, wantBits)
			}
			if r.Action != config.FlowSpecDiscard {
				t.Errorf("action = %q, want discard", r.Action)
			}
			tt.check(t, r)
		})
	}
}

func TestGenerateRulesRateLimit(t *testing.T) {
	rules := generateRules(netip.MustParseAddr("203.0.113.66"), engine.DirIncoming, cls(engine.AttackSYNFlood), nil,
		config.FlowSpecRateLimit, 12_500_000)
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
	if rules[0].Action != config.FlowSpecRateLimit || rules[0].RateBytes != 12_500_000 {
		t.Errorf("got %+v, want rate_limit at 12.5MB/s", rules[0])
	}
}

func TestGenerateRulesMixedWithSample(t *testing.T) {
	sample := &engine.AttackSample{TopSrcPorts: []engine.Counter{
		{Key: "123", Packets: 1000}, {Key: "53", Packets: 500}, {Key: "40000", Packets: 10},
	}}
	rules := generateRules(netip.MustParseAddr("203.0.113.66"), engine.DirIncoming, cls(engine.AttackMixed), sample,
		config.FlowSpecDiscard, 0)
	// destination-only + two known reflector ports (123, 53); 40000 ignored.
	if len(rules) != 3 {
		t.Fatalf("rule count = %d, want 3 (dst-only + 123 + 53): %v", len(rules), rules)
	}
	gotPorts := map[uint16]bool{}
	for _, r := range rules {
		gotPorts[r.SrcPort] = true
	}
	if !gotPorts[123] || !gotPorts[53] || gotPorts[40000] {
		t.Errorf("ports = %v, want 123 and 53 only (plus dst-only 0)", gotPorts)
	}
}

func TestGenerateRulesCapAndInvalid(t *testing.T) {
	if rules := generateRules(netip.Addr{}, engine.DirIncoming, cls(engine.AttackUDPFlood), nil, config.FlowSpecDiscard, 0); rules != nil {
		t.Errorf("invalid target produced rules: %v", rules)
	}
	// A flood of known reflector ports must still cap at maxRulesPerAttack.
	ports := make([]engine.Counter, 0, 20)
	for _, p := range []string{"123", "53", "389", "11211", "1900", "19"} {
		ports = append(ports, engine.Counter{Key: p})
	}
	sample := &engine.AttackSample{TopSrcPorts: append(ports, ports...)} // duplicates
	rules := generateRules(netip.MustParseAddr("203.0.113.66"), engine.DirIncoming, cls(engine.AttackMixed), sample, config.FlowSpecDiscard, 0)
	if len(rules) > maxRulesPerAttack {
		t.Errorf("rule count = %d, want <= %d", len(rules), maxRulesPerAttack)
	}
}

// TestGenerateRulesOutgoingAnchorsSource: an outgoing attack (compromised
// host) anchors the rule on the host as SOURCE, not destination, so the rule
// matches the outbound flood.
func TestGenerateRulesOutgoingAnchorsSource(t *testing.T) {
	host := netip.MustParseAddr("203.0.113.77")
	rules := generateRules(host, engine.DirOutgoing, cls(engine.AttackUDPFlood), nil, config.FlowSpecDiscard, 0)
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want 1", rules)
	}
	r := rules[0]
	if !r.Src.IsValid() || r.Src.Addr() != host || r.Src.Bits() != 32 {
		t.Errorf("src = %v, want %s/32", r.Src, host)
	}
	if r.Dst.IsValid() {
		t.Errorf("dst = %v, want unset for an outgoing rule", r.Dst)
	}
	if r.Proto != 17 {
		t.Errorf("proto = %d, want 17", r.Proto)
	}
	if !strings.HasPrefix(r.String(), "src 203.0.113.77/32") {
		t.Errorf("String() = %q, want it to start with the src anchor", r.String())
	}
}

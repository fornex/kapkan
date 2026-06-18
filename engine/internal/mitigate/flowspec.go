package mitigate

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
)

// maxRulesPerAttack caps the FlowSpec rules generated for one attack, per
// RFC-8955 deployment guidance and the project roadmap (a small, surgical
// rule set, not an explosion).
const maxRulesPerAttack = 8

// FlowSpecRule is a generated BGP FlowSpec rule: a match (the victim as
// destination for incoming attacks, or as source for outgoing ones, plus
// optional protocol/port/flag/fragment narrowing) and an action. Exactly
// one of Dst/Src anchors the rule on the victim; zero-valued fields mean
// "any". It is wire-agnostic; bgp.go encodes it.
type FlowSpecRule struct {
	Dst       netip.Prefix          `json:"dst,omitempty"`        // victim, for incoming attacks
	Src       netip.Prefix          `json:"src,omitempty"`        // victim-as-source, for outgoing attacks
	Proto     uint8                 `json:"proto,omitempty"`      // IP protocol; 0 = any
	SrcPort   uint16                `json:"src_port,omitempty"`   // 0 = any
	DstPort   uint16                `json:"dst_port,omitempty"`   // 0 = any
	TCPFlags  uint8                 `json:"tcp_flags,omitempty"`  // bitmask match (SYN also matches SYN-ACK); 0 = any
	Fragment  bool                  `json:"fragment,omitempty"`   // match any fragmented packet
	Action    config.FlowSpecAction `json:"action"`               // discard | rate_limit
	RateBytes float64               `json:"rate_bytes,omitempty"` // rate_limit ceiling, bytes/s
}

// anchor returns the victim prefix (Dst or Src, whichever is set) for the
// rule's String form.
func (r FlowSpecRule) anchor() (label string, p netip.Prefix) {
	if r.Src.IsValid() {
		return "src", r.Src
	}
	return "dst", r.Dst
}

// protoName renders an IP protocol number for the rule's String form.
func fsProtoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto/%d", p)
	}
}

// String renders the rule for logs, the API and the dashboard.
func (r FlowSpecRule) String() string {
	var b strings.Builder
	label, p := r.anchor()
	fmt.Fprintf(&b, "%s %s", label, p)
	if r.Proto != 0 {
		fmt.Fprintf(&b, " %s", fsProtoName(r.Proto))
	}
	if r.SrcPort != 0 {
		fmt.Fprintf(&b, " src-port %d", r.SrcPort)
	}
	if r.DstPort != 0 {
		fmt.Fprintf(&b, " dst-port %d", r.DstPort)
	}
	if r.TCPFlags != 0 {
		fmt.Fprintf(&b, " tcp-flags 0x%02x", r.TCPFlags)
	}
	if r.Fragment {
		b.WriteString(" fragment")
	}
	if r.Action == config.FlowSpecRateLimit {
		fmt.Fprintf(&b, " -> rate-limit %.0f bytes/s", r.RateBytes)
	} else {
		b.WriteString(" -> discard")
	}
	return b.String()
}

// tcpSYN is the pure-SYN flag bit (SYN set), matched as a bitmask.
const tcpSYN = 0x02

// reflectedPorts maps amplification attack types to the reflected UDP source
// port a FlowSpec rule should match.
var reflectedPorts = map[engine.AttackType]uint16{
	engine.AttackNTPAmplification:       123,
	engine.AttackDNSAmplification:       53,
	engine.AttackCLDAPAmplification:     389,
	engine.AttackMemcachedAmplification: 11211,
	engine.AttackSSDPAmplification:      1900,
	engine.AttackChargenAmplification:   19,
}

// generateRules derives a minimal FlowSpec rule set for an attack on target,
// from its direction, classification and flow sample. Every rule anchors on
// the victim host (a /32 or /128 — identical for IPv4 and IPv6): as the
// DESTINATION for an incoming attack, or as the SOURCE for an outgoing one
// (a compromised host's outbound flood), so the rule actually matches the
// offending traffic in either direction. The classification narrows
// protocol/port/flags so legitimate traffic is spared. With no usable signal
// it falls back to an anchor-only rule (equivalent to a blackhole, but
// expressed as FlowSpec).
func generateRules(target netip.Addr, dir engine.Direction, cls *engine.Classification, sample *engine.AttackSample, action config.FlowSpecAction, rateBytes float64) []FlowSpecRule {
	if !target.IsValid() {
		return nil
	}
	base := FlowSpecRule{Dst: hostPrefix(target), Action: action, RateBytes: rateBytes}
	if dir == engine.DirOutgoing {
		// The compromised host is the source of the flood; match on source.
		base = FlowSpecRule{Src: hostPrefix(target), Action: action, RateBytes: rateBytes}
	}

	var rules []FlowSpecRule
	add := func(mut func(*FlowSpecRule)) {
		if len(rules) >= maxRulesPerAttack {
			return
		}
		r := base
		mut(&r)
		rules = append(rules, r)
	}

	typ := engine.AttackType("")
	if cls != nil {
		typ = cls.Type
	}

	switch {
	case isAmplification(typ):
		// Match UDP from the reflected service source port: the single most
		// precise rule, sparing all other traffic to the victim.
		port := reflectedPorts[typ]
		add(func(r *FlowSpecRule) { r.Proto = 17; r.SrcPort = port })
	case typ == engine.AttackSYNFlood:
		// tcp-flags is an RFC 8955 bitmask match: it catches any segment with
		// the SYN bit set, SYN-ACK included. A discard rule therefore also
		// drops SYN-ACKs to the victim (its outbound-initiated connections);
		// rate_limit is the gentler choice for this vector.
		add(func(r *FlowSpecRule) { r.Proto = 6; r.TCPFlags = tcpSYN })
	case typ == engine.AttackFragmentFlood:
		add(func(r *FlowSpecRule) { r.Fragment = true })
	case typ == engine.AttackICMPFlood:
		proto := uint8(1)
		if target.Is6() {
			proto = 58 // ICMPv6
		}
		add(func(r *FlowSpecRule) { r.Proto = proto })
	case typ == engine.AttackUDPFlood:
		add(func(r *FlowSpecRule) { r.Proto = 17 })
	case typ == engine.AttackTCPFlood:
		add(func(r *FlowSpecRule) { r.Proto = 6 })
	default:
		// mixed / unknown: a destination-only rule. Add the dominant sampled
		// source ports as extra UDP rules when a sample is available, so a
		// multi-vector amplification still gets per-port precision.
		add(func(r *FlowSpecRule) {})
		for _, p := range dominantUDPPorts(sample) {
			add(func(r *FlowSpecRule) { r.Proto = 17; r.SrcPort = p })
		}
	}
	return rules
}

func isAmplification(t engine.AttackType) bool {
	_, ok := reflectedPorts[t]
	return ok
}

// dominantUDPPorts returns well-known reflector source ports present in the
// sample's top source ports, for the mixed-vector fallback.
func dominantUDPPorts(sample *engine.AttackSample) []uint16 {
	if sample == nil {
		return nil
	}
	known := map[uint16]bool{123: true, 53: true, 389: true, 11211: true, 1900: true, 19: true}
	var out []uint16
	for _, c := range sample.TopSrcPorts {
		var p uint16
		if _, err := fmt.Sscanf(c.Key, "%d", &p); err == nil && known[p] {
			out = append(out, p)
		}
	}
	return out
}

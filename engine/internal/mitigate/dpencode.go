package mitigate

// The SECOND encoder for FlowSpecRule.
//
// mitigate.FlowSpecRule is the frozen IR the detector produces: "this vector, to
// (or from) this victim, discard or cap". bgp.go turns it into an RFC 8955 NLRI
// for a peer to enforce; this file turns the same value into the match rules
// kapkan's own XDP program enforces. Two backends, one IR, and the whole point
// is that they select THE SAME PACKETS — a rule an operator sees in the API must
// mean one thing, not one thing per backend.
//
// TestEncodersAgree is what keeps that honest: it builds the FlowSpec NLRI and
// the kernel rule from the same FlowSpecRule and compares them component by
// component. It lives in dpencode_test.go and runs on every host, which is why
// this file has no build tag — the code that decides which packets get dropped
// must not be exercised only inside a privileged container.
//
// ==========================================================================
// THE MAPPING
// ==========================================================================
//
//	FlowSpecRule          RFC 8955 component        RuleSpec
//	--------------------------------------------------------------------
//	Dst (valid)           type 1  dst-prefix        Dst
//	Src (valid)           type 2  src-prefix        Src
//	Proto   != 0          type 3  =proto            Proto  (pointer set)
//	DstPort != 0          type 5  =port             DstPort
//	SrcPort != 0          type 6  =port             SrcPort
//	TCPFlags != 0         type 9  bitmask MATCH     MatchTCPFlags (flags==mask)
//	Fragment              type 12 bitmask IS-FRAG   Fragment
//	Action discard        traffic-rate 0            ActionDrop
//	Action rate_limit     traffic-rate RateBytes    ActionRateLimit + a profile
//	(family)              AFI (v4 NLRI vs v6)       IPv6, from the anchor prefix
//
// The "0 = any" convention on the left is a property of the FlowSpec WIRE
// FORMAT: a component that is absent matches anything, and gobgp is handed no
// component for a zero value. RuleSpec deliberately does not share it (protocol
// 0 is IPv6 hop-by-hop and TCP flags 0 is a NULL scan), so the conversion is
// exactly here, once, and the rest of the data plane keeps the distinction.
//
// ==========================================================================
// WHAT IT REFUSES, AND WHY REFUSING IS THE SAFE ANSWER
// ==========================================================================
// Every refusal below returns an error, which announceMethodLocked reports and
// the mitigator degrades to its configured fallback (a blackhole). That is
// louder and stricter than the alternative — installing a rule that means
// something slightly different from what the operator's ban record says.
//
//   - A rule with NEITHER prefix. On the wire that is a malformed NLRI and
//     flowSpecNLRI already rejects it. Here it would be a rule anchored on
//     nothing: "every IPv4 TCP packet on this box", which is a self-inflicted
//     outage. It cannot come from generateRules (every path sets an anchor),
//     which is exactly why it must be rejected rather than trusted.
//   - An unknown action. The zero FlowSpecAction is "", not discard.
//   - A rate that is not a finite, non-negative number of bytes per second.
//   - Two rules in one set asking for DIFFERENT rates. A policy block has one
//     profile per rule but the ban carries one rate; rather than pick, refuse.
//   - More rules than a policy block holds. generateRules is capped at
//     maxRulesPerAttack, which is RulesPerPolicy, so this is a guard against a
//     future divergence between the two constants, not a live case.
//
// Everything else that could go wrong — mismatched address families, an
// IPv4-mapped IPv6 prefix, flag bits outside the mask — is rejected one layer
// down by RuleSpec.Encode, which is where those checks already live.

import (
	"fmt"
	"math"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
)

// dataplaneRules compiles a ban's FlowSpec IR into the rule set the data-plane
// installer wants, with ttl becoming each rule's in-kernel deadline.
//
// ID, Profile and ExpiresAt are left zero on every spec: they are allocation
// against a live map set and belong to dataplane.Installer, which overwrites
// them. See dataplane.DynamicRules.
func dataplaneRules(rules []FlowSpecRule, ttl time.Duration) (dataplane.DynamicRules, error) {
	if len(rules) == 0 {
		return dataplane.DynamicRules{}, fmt.Errorf("dataplane: no rules were generated for this attack")
	}
	if len(rules) > dataplane.RulesPerPolicy {
		return dataplane.DynamicRules{}, fmt.Errorf(
			"dataplane: %d rules exceed the %d a policy block holds", len(rules), dataplane.RulesPerPolicy)
	}

	out := dataplane.DynamicRules{Specs: make([]dataplane.RuleSpec, 0, len(rules)), TTL: ttl}
	rateSet := false
	for i, r := range rules {
		spec, rate, err := dataplaneRule(r)
		if err != nil {
			return dataplane.DynamicRules{}, fmt.Errorf("rule %d of %d (%s): %w", i, len(rules), r, err)
		}
		if rateSet && rate != out.RateBytesPerSecond {
			// One ban, one interned profile. Two rates in one rule set would
			// need two, and choosing one would enforce a ceiling the operator
			// did not write on half the vector.
			return dataplane.DynamicRules{}, fmt.Errorf(
				"dataplane: rule set mixes rate-limit ceilings (%d and %d bytes/s); "+
					"a ban interns exactly one profile", out.RateBytesPerSecond, rate)
		}
		out.RateBytesPerSecond, rateSet = rate, true
		out.Specs = append(out.Specs, spec)
	}
	return out, nil
}

// dataplaneRule compiles one rule, returning the spec and the byte ceiling it
// needs (0 for a discard).
func dataplaneRule(r FlowSpecRule) (dataplane.RuleSpec, uint64, error) {
	if !r.Dst.IsValid() && !r.Src.IsValid() {
		return dataplane.RuleSpec{}, 0, fmt.Errorf(
			"has neither a destination nor a source prefix, so it would match every packet of its family")
	}

	action, rate, err := dataplaneAction(r)
	if err != nil {
		return dataplane.RuleSpec{}, 0, err
	}

	// The anchor decides the family. Dst first, matching flowSpecNLRI's own
	// choice, so a composite victim+attacker rule resolves the same way on both
	// paths (they must agree anyway — Encode rejects a mixed-family rule).
	anchor := r.Dst
	if !anchor.IsValid() {
		anchor = r.Src
	}

	spec := dataplane.RuleSpec{
		Action:   action,
		Src:      r.Src,
		Dst:      r.Dst,
		Fragment: r.Fragment,
		IPv6:     anchor.Addr().Is6(),
	}
	// "0 means any" on the wire becomes an explicit absent field here.
	if r.Proto != 0 {
		p := r.Proto
		spec.Proto = &p
	}
	if r.SrcPort != 0 {
		p := r.SrcPort
		spec.SrcPort = &p
	}
	if r.DstPort != 0 {
		p := r.DstPort
		spec.DstPort = &p
	}
	if r.TCPFlags != 0 {
		// RFC 8955 bitmask MATCH: every bit in the value must be set in the
		// packet. flags == mask is that predicate, and it is why a SYN rule
		// (0x02) also catches a SYN-ACK (0x12) on BOTH backends. A zero value
		// emits no type-9 component on the wire, so it must set no mask here:
		// MatchTCPFlags(0) would be a mask of 0, which the datapath reads as
		// "do not test flags" — the same thing — but going through the helper
		// for a zero would read as if the two cases were different.
		spec = spec.MatchTCPFlags(r.TCPFlags)
	}
	return spec, rate, nil
}

// dataplaneAction maps the FlowSpec action onto a kernel verdict and, for a
// rate limit, the byte ceiling to intern.
//
// rate_limit WITH A ZERO OR NEGATIVE RATE BECOMES A DROP, deliberately: the
// traffic-rate extended community bgp.go emits carries the rate as a float, and
// RFC 8955 defines rate 0 as discard, so a peer would drop it. Mapping it to
// ActionRateLimit with a profile that caps nothing would do the OPPOSITE here —
// the datapath admits when a profile has neither a packet nor a byte rate — and
// the same ban would discard upstream while passing locally.
func dataplaneAction(r FlowSpecRule) (dataplane.Action, uint64, error) {
	switch r.Action {
	case config.FlowSpecDiscard:
		return dataplane.ActionDrop, 0, nil
	case config.FlowSpecRateLimit:
		if math.IsNaN(r.RateBytes) || math.IsInf(r.RateBytes, 0) {
			return 0, 0, fmt.Errorf("rate_limit rate is not a finite number (%v)", r.RateBytes)
		}
		if r.RateBytes <= 0 {
			return dataplane.ActionDrop, 0, nil
		}
		if r.RateBytes >= math.MaxUint64 {
			return 0, 0, fmt.Errorf("rate_limit rate %v bytes/s is out of range", r.RateBytes)
		}
		return dataplane.ActionRateLimit, uint64(r.RateBytes), nil
	default:
		return 0, 0, fmt.Errorf("unknown flowspec action %q", r.Action)
	}
}

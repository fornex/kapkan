package dataplane

// Static rules that can never fire.
//
// This is the worst class of misconfiguration this package can hold, because it
// is INVISIBLE. Nothing errors, and the rule's entry in kapkan_rule_stats stays
// at zero — which is indistinguishable from a perfectly good rule whose traffic
// has not arrived. The operator believes a cap is in force; the kernel has never
// once evaluated it in a way that could take a packet.
//
// Two things can take a rule's packets before it is reached, and both are
// reported here:
//
//   - THE ALLOWLIST (precedence 1). It admits and stops evaluation before any
//     rule is looked at, so adding a /16 to it silently disables every static
//     drop aimed at a source inside that /16.
//
//   - AN EARLIER STATIC RULE (precedence 3, first match wins). If an earlier
//     rule's match set CONTAINS a later rule's, the scan stops at the earlier
//     one every time and the later rule is dead. The classic shape is a broad
//     cap followed by the narrower one the operator actually cared about:
//
//     - {name: cap_https, match: {proto: tcp, dst_port: 443}, action: ratelimit, ...}
//     - {name: cap_https_from_asn, match: {proto: tcp, dst_port: 443, src: 198.51.100.0/24}, ...}
//
// This file is untagged so the analysis runs — and is tested — on every host,
// including the macOS development host where nothing can be loaded into a
// kernel. Nothing here touches bpf(2); it is a property of the config alone.
//
// REPORTED, NOT REJECTED. The opposite is tempting and would be wrong. A dead
// rule enforces nothing, so refusing the config trades a defect that costs zero
// packets today for a daemon that will not start — on a box whose whole job is
// to be filtering when an attack lands. The same defect on the allowlist axis
// has been a warning for as long as that axis has existed, and rejecting a
// config Kapkan accepted yesterday is a MAJOR change by the changelog's own
// rule. So it is made loud instead of fatal: a WARN on every apply, a
// CondPolicyShadowed health condition that persists in /healthz, /api/v1/status
// and the console until the config is fixed, the
// kapkan_dataplane_shadowed_static_rules gauge to alert on, and a WARNING line
// out of `kapkan -check-config` before the file is ever deployed.

import (
	"fmt"
	"net/netip"
	"strings"
)

// ShadowedStatics names the config static rules that can never fire, and what
// takes their packets. The strings are operator-facing: they go into the reload
// report, the log line, the health condition and `kapkan -check-config`.
//
// Order is config order, which is the order the operator reads their file in.
func ShadowedStatics(pol StaticPolicy) []string {
	var out []string
	for i, sr := range pol.Statics {
		out = append(out, allowlistShadow(sr, pol.Allow)...)
		if s, ok := earlierRuleShadow(pol.Statics[:i], sr); ok {
			out = append(out, s)
		}
	}
	return out
}

// allowlistShadow reports sr as unreachable when the allowlist covers every
// source it matches.
//
// Only non-pass rules are reported on this axis: a pass rule the allowlist has
// already made redundant is harmless, because both verdicts admit the packet.
// That exemption does NOT hold for the earlier-rule axis below — see there.
func allowlistShadow(sr StaticRule, allow []netip.Prefix) []string {
	if sr.Action == ActionPass {
		return nil
	}
	var out []string
	for _, v6 := range familiesFor(sr) {
		target := sr.Src
		if !target.IsValid() {
			target = defaultRoute(v6)
		}
		for _, a := range allow {
			if covers(a, target) {
				out = append(out, fmt.Sprintf("%s (allowlist %s covers %s)", sr.Name, a, target))
				break
			}
		}
	}
	return out
}

// earlierRuleShadow reports sr as unreachable when rules earlier in the list
// already match every packet it selects, and names the rule (or rules) that do.
//
// EVERY action is reported here, unlike the allowlist axis. A dead pass rule is
// the most dangerous case on this one: an operator who writes a broad drop and
// then a narrow exemption below it has not exempted anything, and the traffic
// they meant to protect is being dropped right now.
//
// The verdict is per address family, because the datapath is family-strict and
// one config rule can compile to one kernel rule per family (see familiesFor).
// A rule is only dead when EVERY family it compiles to is taken — possibly by
// different earlier rules, which is why the covering names are collected rather
// than short-circuited on the first hit.
func earlierRuleShadow(earlier []StaticRule, sr StaticRule) (string, bool) {
	fams := familiesFor(sr)
	if len(fams) == 0 || len(earlier) == 0 {
		return "", false
	}
	var by []string
	for _, v6 := range fams {
		name, ok := coveringRule(earlier, sr, v6)
		if !ok {
			// This family is still reachable, so the rule can fire. Nothing to
			// report: a PARTIAL overlap is ordinary, correct policy.
			return "", false
		}
		if len(by) == 0 || by[len(by)-1] != name {
			by = append(by, name)
		}
	}
	if len(by) == 1 {
		return fmt.Sprintf("%s (rule %q already matches every packet it selects)", sr.Name, by[0]), true
	}
	// More than one name means the families were taken separately, which is
	// worth spelling out — neither rule alone would make this one dead.
	return fmt.Sprintf("%s (rules %s between them already match every packet it selects)",
		sr.Name, quoteJoin(by)), true
}

// coveringRule finds the first earlier rule that takes every packet sr selects
// in family v6. "First" matters: it is the one the datapath will actually stop
// at, so it is the one to name.
func coveringRule(earlier []StaticRule, sr StaticRule, v6 bool) (string, bool) {
	for _, e := range earlier {
		if !hasFamily(e, v6) {
			continue
		}
		if matchCovers(e, sr, v6) {
			return e.Name, true
		}
	}
	return "", false
}

// matchCovers reports whether every packet b matches, a matches too — i.e. a's
// match set contains b's.
//
// Each field is ANDed and an unset field means "any", so a covers b on a field
// when a leaves it unconstrained, or when both constrain it to the same value.
// Anything else (a narrower than b, or the two disjoint) is not coverage.
// Action and profile deliberately play no part: reachability is a question
// about the MATCH, and a rule that duplicates its predecessor's verdict is just
// as dead as one that contradicts it.
//
// v6 is the family the comparison is made in, and it is needed because "any
// source" is a different prefix in each: within v4, a rule with no match.src
// and a rule matching 0.0.0.0/0 select exactly the same packets.
func matchCovers(a, b StaticRule, v6 bool) bool {
	return coversField(a.Proto, b.Proto) &&
		coversField(a.SrcPort, b.SrcPort) &&
		coversField(a.DstPort, b.DstPort) &&
		coversSrc(a.Src, b.Src, v6)
}

// coversField is the "any, or the same value" test for the optional scalar
// match fields.
func coversField[T comparable](a, b *T) bool {
	return a == nil || (b != nil && *a == *b)
}

// coversSrc is the same test for the source prefix, where "the same value" is
// widened to containment: 10.0.0.0/8 covers 10.1.2.0/24, and an unset prefix
// (any source) covers everything in the family. An unset prefix on b is the
// family's default route, so a rule written as 0.0.0.0/0 covers a rule with no
// match.src for v4 — they select the same packets and the operator should not
// have to know which spelling the analysis prefers.
func coversSrc(a, b netip.Prefix, v6 bool) bool {
	if !a.IsValid() {
		return true
	}
	if !b.IsValid() {
		b = defaultRoute(v6)
	}
	return covers(a, b)
}

// hasFamily reports whether sr compiles to a kernel rule for family v6.
func hasFamily(sr StaticRule, v6 bool) bool {
	for _, f := range familiesFor(sr) {
		if f == v6 {
			return true
		}
	}
	return false
}

// familiesFor returns the address families a config static rule must be
// compiled for, as a slice of "is v6" flags whose index is the rule's family
// slot.
//
// The datapath tests a rule's family bit against the packet's unconditionally,
// so a rule that names no source prefix has no family of its own and needs one
// encoded rule per family. icmp and icmp6 are the exceptions: the protocol
// number pins the family, so they get one rule each and the other slot stays
// empty.
func familiesFor(sr StaticRule) []bool {
	if sr.Src.IsValid() {
		return []bool{sr.Src.Addr().Is6()}
	}
	if sr.Proto != nil {
		switch *sr.Proto {
		case protoICMP:
			return []bool{false}
		case protoICMPv6:
			return []bool{true}
		}
	}
	return []bool{false, true}
}

// covers reports whether allow entirely contains target, i.e. every address
// target can match is in allow. Same family, and allow no more specific.
func covers(allow, target netip.Prefix) bool {
	if !allow.IsValid() || !target.IsValid() {
		return false
	}
	if allow.Addr().Is4() != target.Addr().Is4() {
		return false
	}
	return allow.Bits() <= target.Bits() && allow.Contains(target.Masked().Addr())
}

// defaultRoute is the "any source" prefix for a family, which is what a static
// rule with no match.src effectively names.
func defaultRoute(v6 bool) netip.Prefix {
	if v6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0)
}

// quoteJoin renders rule names as "a" and "b" / "a", "b" and "c". Called only
// with at least two names.
func quoteJoin(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(q[:len(q)-1], ", ") + " and " + q[len(q)-1]
}

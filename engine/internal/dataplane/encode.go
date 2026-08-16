package dataplane

// The PURE half of the map interface: turning ordinary Go values into the
// layouts frozen in bpf/include/kapkan_maps.h. Nothing here touches a map, and
// nothing here needs bpf(2), so it builds and unit-tests on every host.
//
// WHY THIS IS A SEPARATE FILE FROM maps_linux.go. It used to live there, on the
// argument that splitting the encoders from the writers would put half of
// freeze point F6 in each file and invite drift. What changed is the caller:
// mitigate compiles its FlowSpecRule IR into RuleSpec (see
// internal/mitigate/dpencode.go), and that compiler has to be unit-testable on
// the macOS development host where the kernel side cannot even be loaded. A
// Linux-only RuleSpec would have forced the mitigator's encoder behind a build
// tag too, which means the one piece of this feature that decides WHICH PACKETS
// GET DROPPED would only ever be exercised by the container tests.
//
// The drift argument survives the split intact, because it never rested on file
// boundaries: THE STRUCT DEFINITIONS ARE STILL NOT HERE. Rule, Profile and the
// rest are the bpf2go-generated types in kapkanxdp_bpfel.go, derived from the
// object's BTF and aliased in bindings.go — a field added in C is a Go compile
// error on the next `make dataplane-sync`, in this file exactly as in the other.

import (
	"fmt"
	"math"
	"net/netip"
	"time"
)

/* ========================================================================= */
/* Rules                                                                      */
/* ========================================================================= */

// RuleSpec is one match rule in ordinary Go values, field-for-field the same
// predicate as mitigate.FlowSpecRule (which is frozen and cannot be edited, so
// this is the shape the encoder maps onto rather than the type itself — the
// data plane must not depend on the mitigation package).
//
// WHY POINTERS FOR proto/ports AND NOT "0 MEANS ANY". Zero is a legal value for
// several of these: protocol 0 is IPv6 hop-by-hop and TCP flags 0 is a NULL
// scan, which is precisely a thing an operator wants to match. The kernel
// spells "any" with an explicit KAPKAN_RF_*_ANY bit for the same reason, and
// this type keeps the distinction rather than losing it on the way in.
// FlowSpecRule's own "0 = any" convention is a property of the FlowSpec wire
// format; converting from it is the caller's job and is where that convention
// belongs.
type RuleSpec struct {
	// ID is the stable rule id, the key of kapkan_rule_stats.
	ID uint32
	// Action is pass, drop or ratelimit.
	Action Action
	// Profile indexes kapkan_profiles; only meaningful for ActionRateLimit.
	Profile uint32
	// ExpiresAt is a boot-clock deadline in nanoseconds, comparable with
	// bpf_ktime_get_boot_ns. 0 means "never expires" and is reserved for
	// static rules, which come from the config file and cannot be stranded by
	// a manager crash. AN EXPIRED RULE IS TREATED AS ABSENT: that is the
	// fail-safe that degrades a crashed userspace to a wire instead of leaving
	// a customer blackholed.
	ExpiresAt uint64

	// Src and Dst are the match prefixes. An invalid (zero) Prefix means
	// "any". Host bits are masked off; the datapath masks too, so this only
	// keeps the map contents readable.
	Src netip.Prefix
	Dst netip.Prefix

	// Proto, SrcPort and DstPort are nil for "any".
	Proto   *uint8
	SrcPort *uint16
	DstPort *uint16

	// TCPFlags and TCPFlagsMask together express the flag test:
	// (observed & TCPFlagsMask) == TCPFlags. A zero mask disables the test
	// entirely. Use MatchTCPFlags for RFC 8955 bitmask semantics.
	TCPFlags     uint8
	TCPFlagsMask uint8

	// Fragment restricts the rule to fragmented packets. Clear means the rule
	// is indifferent and matches fragments and whole datagrams alike, which
	// mirrors FlowSpec, where an absent type-12 component means "any".
	Fragment bool

	// MatchExt is the extended-predicate bitset (MatchTLSClientHello and, in
	// time, its siblings). Zero means "no extended predicate", which is what
	// every rule the mitigator builds carries: this axis is STATIC RULES ONLY,
	// because FlowSpec has no way to express a payload test and a dynamic rule
	// setting one would mean the two encoders no longer select the same
	// packets. Encode does not police that — the mitigator simply never sets
	// it, and TestDynamicRulesNeverSetMatchExt proves it stays that way.
	MatchExt uint8

	// IPv6 selects the address family. It is only consulted when neither Src
	// nor Dst is set; otherwise it must agree with them, and Encode rejects a
	// disagreement rather than guessing.
	IPv6 bool
}

// MatchTCPFlags sets RFC 8955 bitmask semantics: "every bit in v is set in the
// packet". This is why FlowSpecRule documents that a SYN rule also catches
// SYN-ACK — 0x12 & 0x02 == 0x02 — and it is what flowSpecNLRI emits, so a rule
// handed to a FlowSpec peer and the same rule handed to this data plane select
// the same packets.
func (s RuleSpec) MatchTCPFlags(v uint8) RuleSpec {
	s.TCPFlags, s.TCPFlagsMask = v, v
	return s
}

// MatchTCPFlagsExact sets an exact flag-byte match, which FlowSpec's bitmask
// operator alone cannot express. The obvious use is a NULL scan (v = 0), where
// bitmask semantics would match every packet.
func (s RuleSpec) MatchTCPFlagsExact(v uint8) RuleSpec {
	s.TCPFlags, s.TCPFlagsMask = v, 0xFF
	return s
}

// Encode renders the spec as the kernel's struct kapkan_rule.
//
// It rejects, rather than silently narrowing, four encoder bugs that would
// otherwise show up as a rule that never fires (or, worse, one that fires on
// traffic nobody named):
//
//   - an unknown action;
//   - Src and Dst in different address families, or either disagreeing with
//     IPv6;
//   - an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d), because the datapath
//     deliberately does NOT normalise those — see the long note at the top of
//     kapkan_xdp.c. Callers must Unmap() and pick a family on purpose;
//   - flag bits set outside the flag mask, which can never match;
//   - an extended-match bit this build does not know, which the datapath would
//     ignore — so the rule would match MORE than the caller asked for.
func (s RuleSpec) Encode() (Rule, error) {
	switch s.Action {
	case ActionPass, ActionDrop, ActionRateLimit:
	default:
		return Rule{}, fmt.Errorf("dataplane: rule %d: unknown action %d", s.ID, s.Action)
	}
	if s.TCPFlags&^s.TCPFlagsMask != 0 {
		return Rule{}, fmt.Errorf(
			"dataplane: rule %d: tcp flags %#02x has bits outside mask %#02x, so it can never match",
			s.ID, s.TCPFlags, s.TCPFlagsMask)
	}
	// Rejected rather than masked off, and the direction of the failure is the
	// reason. An unknown flag bit is a narrowing predicate the datapath cannot
	// apply, so silently dropping it would WIDEN the rule — a caller asking to
	// rate-limit ClientHellos would instead rate-limit every packet the rest of
	// the match admits.
	if s.MatchExt&^knownMatchExt != 0 {
		return Rule{}, fmt.Errorf(
			"dataplane: rule %d: match_ext %#02x has bits this build does not implement (known: %#02x); "+
				"the datapath would ignore them and the rule would match more than intended",
			s.ID, s.MatchExt, knownMatchExt)
	}

	// Family resolution. -1 until a prefix pins it down.
	fam := -1
	for _, p := range []struct {
		name string
		pfx  netip.Prefix
	}{{"src", s.Src}, {"dst", s.Dst}} {
		if !p.pfx.IsValid() {
			continue
		}
		if p.pfx.Addr().Is4In6() {
			return Rule{}, fmt.Errorf(
				"dataplane: rule %d: %s prefix %s is IPv4-mapped IPv6; the datapath never "+
					"normalises families, so Unmap() it and choose one on purpose", s.ID, p.name, p.pfx)
		}
		f := 0
		if p.pfx.Addr().Is6() {
			f = 1
		}
		if fam >= 0 && fam != f {
			return Rule{}, fmt.Errorf("dataplane: rule %d: src %s and dst %s are different address families",
				s.ID, s.Src, s.Dst)
		}
		fam = f
	}
	v6 := s.IPv6
	if fam >= 0 {
		if (fam == 1) != s.IPv6 {
			return Rule{}, fmt.Errorf(
				"dataplane: rule %d: IPv6=%v disagrees with the prefixes (src %s, dst %s)",
				s.ID, s.IPv6, s.Src, s.Dst)
		}
		v6 = fam == 1
	}

	// Start from "matches every packet of its family" and clear an ANY bit for
	// each field the spec actually names.
	r := Rule{
		ExpiresAtNs:  s.ExpiresAt,
		RuleId:       s.ID,
		Profile:      s.Profile,
		Action:       uint8(s.Action),
		TcpFlags:     s.TCPFlags,
		TcpFlagsMask: s.TCPFlagsMask,
		Flags: RuleValid | RuleSrcAny | RuleDstAny |
			RuleProtoAny | RuleSportAny | RuleDportAny,
		MatchExt: s.MatchExt,
	}
	if v6 {
		r.Flags |= RuleIPv6
	}
	if s.Fragment {
		r.Flags |= RuleFragment
	}
	if s.Src.IsValid() {
		copyPrefix(r.Src[:], s.Src)
		r.SrcPrefixlen = uint8(s.Src.Bits())
		r.Flags &^= RuleSrcAny
	}
	if s.Dst.IsValid() {
		copyPrefix(r.Dst[:], s.Dst)
		r.DstPrefixlen = uint8(s.Dst.Bits())
		r.Flags &^= RuleDstAny
	}
	if s.Proto != nil {
		r.Proto = *s.Proto
		r.Flags &^= RuleProtoAny
	}
	if s.SrcPort != nil {
		r.Sport = *s.SrcPort
		r.Flags &^= RuleSportAny
	}
	if s.DstPort != nil {
		r.Dport = *s.DstPort
		r.Flags &^= RuleDportAny
	}
	return r, nil
}

// EncodeRules encodes a whole rule set, naming the offending index on failure.
func EncodeRules(specs ...RuleSpec) ([]Rule, error) {
	out := make([]Rule, len(specs))
	for i, s := range specs {
		r, err := s.Encode()
		if err != nil {
			return nil, fmt.Errorf("rule %d of %d: %w", i, len(specs), err)
		}
		out[i] = r
	}
	return out, nil
}

// copyPrefix writes a prefix's address into the rule's left-aligned 16-byte
// slot, network order, IPv4 in bytes [0..3]. Host bits are masked off.
func copyPrefix(dst []byte, p netip.Prefix) {
	a := p.Masked().Addr()
	if a.Is4() {
		b := a.As4()
		copy(dst, b[:])
		return
	}
	b := a.As16()
	copy(dst, b[:])
}

/* ========================================================================= */
/* One victim's dynamic rule set                                              */
/* ========================================================================= */

// DynamicRules is one victim's rule set as the MITIGATOR hands it over, and the
// three fields are exactly the split of responsibility between the two sides.
//
// The mitigator compiles its own IR (mitigate.FlowSpecRule) into Specs: every
// match field and the action, which is a pure function of the attack and can
// therefore be tested on any host. It cannot fill in the rest, because the rest
// is ALLOCATION against a live map set — a rule id, a slot in the 256-entry
// profile array, a deadline on the kernel's boot clock — and only the Installer
// knows what is free.
//
// So Installer.Install OVERWRITES RuleSpec.ID, RuleSpec.Profile and
// RuleSpec.ExpiresAt on every spec, whatever the caller put there. That is
// stated loudly rather than enforced by a second type, because a caller who
// sets one of them has made a mistake worth finding in a test (TestInstallerOwnsIDs)
// rather than a compile error worth a whole parallel struct.
type DynamicRules struct {
	// Specs are the match/action halves, at most RulesPerPolicy of them: a
	// victim's whole rule set lives in ONE policy block.
	Specs []RuleSpec
	// RateBytesPerSecond is the ceiling an ActionRateLimit spec must be
	// interned to, in bytes/s. It is 0 when nothing rate-limits.
	//
	// SEMANTIC DIVERGENCE FROM FLOWSPEC, stated here because it is invisible
	// otherwise: RFC 8955's traffic-rate community caps an AGGREGATE, while
	// this data plane's token bucket is keyed {anchor, source, profile} and
	// therefore caps EACH SOURCE at the rate. That is the datapath's whole
	// reason to exist for rate limits (see the token-bucket comment in
	// kapkan_xdp.c: "cap every source at N pps" would need one FlowSpec rule
	// per source), but it means the same configured number admits far more
	// traffic here than at a FlowSpec peer when the attack is diffuse. The
	// Installer logs that once per profile so it appears in an operator's
	// journal the first time it matters.
	RateBytesPerSecond uint64
	// TTL is how long these rules may live in the kernel, which becomes each
	// rule's boot-clock deadline. It is a DURATION and not a deadline on
	// purpose: the ban's ExpiresAt is on the wall clock and the rules' is on
	// CLOCK_BOOTTIME, and converting between them anywhere but next to the
	// boot-clock read is how a suspend/resume or an NTP step turns into rules
	// that expire early (traffic passes) or late (a customer stays filtered).
	TTL time.Duration
}

// DynamicRuleID is the rule id of the i-th rule in a victim's policy block.
//
// Ids are DERIVED from the policy id rather than allocated separately, which
// buys three things for one line of arithmetic: there is only one allocator to
// get wrong; a victim's kapkan_rule_stats counters survive a re-install (a TTL
// refresh mid-attack does not reset the operator's packet counts); and the id
// space cannot fragment, because a freed policy id frees its eight rule ids
// with it.
//
// The bottom half of the u32 space is dynamic and the top half is static — see
// StaticRuleIDBase — so a policy id is bounded by MaxPolicyID below, and the
// two can never collide in kapkan_rule_stats, where a collision would not be an
// error, just two rules silently sharing one counter.
func DynamicRuleID(policyID uint32, i int) uint32 {
	return policyID*RulesPerPolicy + uint32(i)
}

// StaticRuleIDBase is the first rule id given to a config static rule.
//
// The top half of the u32 id space belongs to static (operator) rules and the
// bottom half to dynamic (mitigator) ones, so the two can never collide in
// kapkan_rule_stats — where a collision would not be an error, just two rules
// silently sharing one counter.
const StaticRuleIDBase uint32 = 1 << 31

// MaxPolicyID is the highest policy id whose derived rule ids still fit in the
// dynamic (bottom) half of the rule-id space. It is far above any sizing an
// operator would configure — at the default max_dynamic_rules of 4096 the
// policy stride is 512 — and exists so the Installer can reject an absurd
// limits.max_dynamic_rules instead of wrapping into the static id range.
const MaxPolicyID = StaticRuleIDBase/RulesPerPolicy - 1

/* ========================================================================= */
/* Rate-limit profiles                                                        */
/* ========================================================================= */

const nsPerSecond = 1_000_000_000

// ProfileSpec is a rate-limit ceiling in the units an operator writes.
//
// Interning a rate into a profile is what keeps DIVISION out of the datapath:
// the kernel refills a bucket with (elapsed_ns * tokens_per_ns) in Q32 fixed
// point, and tokens_per_ns is computed here, once, per profile.
type ProfileSpec struct {
	// PPS is the packet ceiling in packets/s. 0 disables the packet ceiling.
	PPS uint64
	// BurstPackets is the bucket depth in packets. 0 derives one second of
	// PPS (and at least 1 — a zero depth with a non-zero rate would deny every
	// packet until the first refill, which is a default-deny by accident).
	BurstPackets uint64
	// BytesPerSecond is the byte ceiling. 0 disables it. Use
	// ProfileFromConfig to convert config.RateLimitProfile.Mbps.
	BytesPerSecond uint64
	// BurstBytes is the bucket depth in bytes; 0 derives one second of
	// BytesPerSecond.
	BurstBytes uint64
}

// ProfileFromConfig converts a config.RateLimitProfile's pps/mbps pair, where
// mbps is megabits per second and the kernel counts bytes.
func ProfileFromConfig(pps, mbps uint64) ProfileSpec {
	return ProfileSpec{PPS: pps, BytesPerSecond: mbps * 1_000_000 / 8}
}

// Encode renders the spec as struct kapkan_profile, precomputing both
// spellings of the rate: ns_per_* for userspace display and sanity checks, and
// the Q32 reciprocals the datapath actually multiplies by.
//
// SATURATION, stated plainly because it is invisible otherwise: the Q32
// reciprocal is clamped to 2^32-1 in the kernel so that
// delta(<=2^32) * q(<2^32) cannot wrap a u64. That caps the refill at one
// token per nanosecond, i.e. 1e9 packets/s or 1e9 bytes/s (8 Gbit/s). These
// are PER-SOURCE ceilings — the bucket is keyed {victim, source, profile} — so
// a per-attacker cap anywhere near 8 Gbit/s is not a ceiling anyone means, but
// a caller that asks for more gets 8 Gbit/s and no error.
func (s ProfileSpec) Encode() Profile {
	p := Profile{
		RatePps:      s.PPS,
		BurstPps:     s.BurstPackets,
		RateBps:      s.BytesPerSecond,
		BurstBps:     s.BurstBytes,
		PktPerNsQ32:  q32PerNs(s.PPS),
		BytePerNsQ32: q32PerNs(s.BytesPerSecond),
	}
	if s.PPS > 0 {
		p.NsPerPkt = nsPerSecond / s.PPS
		if p.BurstPps == 0 {
			p.BurstPps = max(s.PPS, 1)
		}
	}
	if s.BytesPerSecond > 0 {
		p.NsPerByte = nsPerSecond / s.BytesPerSecond
		if p.BurstBps == 0 {
			p.BurstBps = max(s.BytesPerSecond, 1)
		}
	}
	return p
}

// q32PerNs is tokens-per-nanosecond in Q32 fixed point: (rate << 32) / 1e9.
// The input is clamped to 2^32-1 first so the shift cannot overflow; the
// kernel clamps the result again for the same reason.
func q32PerNs(ratePerSecond uint64) uint64 {
	if ratePerSecond == 0 {
		return 0
	}
	if ratePerSecond > math.MaxUint32 {
		ratePerSecond = math.MaxUint32
	}
	return (ratePerSecond << 32) / nsPerSecond
}

//go:build linux

package dataplane

// The Go half of the data plane's map interface: encode ordinary Go values
// into the layouts frozen in bpf/include/kapkan_maps.h, and write them into a
// loaded map set. Everything that ever writes to a kapkan_* map goes through
// this file — the manager, the FlowSpec-to-BPF encoder and every test — so
// there is exactly one place where a struct field is filled in and exactly one
// place to fix when F6 moves.
//
// THE STRUCT DEFINITIONS ARE NOT HERE. They are the bpf2go-generated types in
// kapkanxdp_bpfel.go, derived from the object's BTF and aliased under readable
// names in bindings.go. A hand-written mirror is the classic way for userspace
// and kernel to drift silently and start dropping traffic nobody named; with the
// generated types a field added in C is a Go compile error on the next
// `make dataplane-sync`.
//
// Linux-only because writing a map needs the bpf(2) syscall. The pure encoders
// (RuleSpec.Encode, ProfileSpec.Encode) would build anywhere, but splitting
// them into a second file would put half the contract in each and invite
// exactly the drift this file exists to prevent.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"

	"github.com/cilium/ebpf"
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
//   - flag bits set outside the flag mask, which can never match.
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

// PutProfile writes kapkan_profiles[id].
func PutProfile(m *Maps, id uint32, s ProfileSpec) error {
	p := s.Encode()
	if err := m.KapkanProfiles.Put(id, &p); err != nil {
		return fmt.Errorf("dataplane: write profile %d: %w", id, err)
	}
	return nil
}

/* ========================================================================= */
/* Prefix lists                                                               */
/* ========================================================================= */

// AddAllowSource adds a SOURCE prefix to the precedence-1 allowlist
// (config Dataplane.Allowlist). Traffic from it is never touched by anything
// below, including an operator's own static drop.
func AddAllowSource(m *Maps, p netip.Prefix) error {
	return putPrefix(m.KapkanAllow4, m.KapkanAllow6, p, "allowlist")
}

// DeleteAllowSource removes a source prefix from the allowlist. A prefix that
// is not there is not an error: the manager reconciles toward a desired set
// and must be safe to run twice.
func DeleteAllowSource(m *Maps, p netip.Prefix) error {
	return deletePrefix(m.KapkanAllow4, m.KapkanAllow6, p, "allowlist")
}

// AddProtectedDestination adds a DESTINATION prefix to the precedence-2
// protected list — the protected_whitelist mirror, "never ban this victim".
//
// A different axis from the allowlist, and both must be in the kernel: without
// the destination map, a rule rehydrated from a previous process, or one
// installed in the same instant an operator adds a prefix here, blackholes
// that customer until the userspace sweep notices on its next 1 Hz tick.
func AddProtectedDestination(m *Maps, p netip.Prefix) error {
	return putPrefix(m.KapkanProtect4, m.KapkanProtect6, p, "protected list")
}

// DeleteProtectedDestination removes a destination prefix from the protected
// list. Absent is not an error, for the same reason as DeleteAllowSource.
func DeleteProtectedDestination(m *Maps, p netip.Prefix) error {
	return deletePrefix(m.KapkanProtect4, m.KapkanProtect6, p, "protected list")
}

// AddVictim points a prefix at a policy block.
//
// kapkan_victims4/6 is NOT "the list of destinations": it is "the set of
// prefixes that have a policy block", and the datapath consults it on BOTH
// axes — the packet's source at precedence 4 and its destination at precedence
// 5 — because a rule anchors on either end. Reaching a block by the "wrong"
// axis cannot produce a wrong verdict, because every rule in it re-checks both
// prefixes before it may fire; the trie only narrows the candidates.
func AddVictim(m *Maps, p netip.Prefix, policyID uint32) error {
	if p.Addr().Is4In6() {
		return fmt.Errorf("dataplane: victim %s is IPv4-mapped IPv6; Unmap() it", p)
	}
	var err error
	if p.Addr().Is4() {
		k := LPMKeyV4{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As4()}
		err = m.KapkanVictims4.Put(&k, policyID)
	} else {
		k := LPMKeyV6{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As16()}
		err = m.KapkanVictims6.Put(&k, policyID)
	}
	if err != nil {
		return fmt.Errorf("dataplane: point victim %s at policy %d: %w", p, policyID, err)
	}
	return nil
}

// DeleteVictim unpoints a prefix. Absent is not an error.
func DeleteVictim(m *Maps, p netip.Prefix) error {
	var err error
	if p.Addr().Is4() {
		k := LPMKeyV4{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As4()}
		err = m.KapkanVictims4.Delete(&k)
	} else {
		k := LPMKeyV6{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As16()}
		err = m.KapkanVictims6.Delete(&k)
	}
	if err != nil && !isMissing(err) {
		return fmt.Errorf("dataplane: unpoint victim %s: %w", p, err)
	}
	return nil
}

func putPrefix(v4, v6 *ebpf.Map, p netip.Prefix, what string) error {
	if !p.IsValid() {
		return fmt.Errorf("dataplane: %s: invalid prefix", what)
	}
	if p.Addr().Is4In6() {
		return fmt.Errorf("dataplane: %s: %s is IPv4-mapped IPv6; Unmap() it", what, p)
	}
	var err error
	if p.Addr().Is4() {
		k := LPMKeyV4{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As4()}
		err = v4.Put(&k, uint8(1))
	} else {
		k := LPMKeyV6{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As16()}
		err = v6.Put(&k, uint8(1))
	}
	if err != nil {
		return fmt.Errorf("dataplane: %s: add %s: %w", what, p, err)
	}
	return nil
}

func deletePrefix(v4, v6 *ebpf.Map, p netip.Prefix, what string) error {
	var err error
	if p.Addr().Is4() {
		k := LPMKeyV4{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As4()}
		err = v4.Delete(&k)
	} else {
		k := LPMKeyV6{Prefixlen: uint32(p.Bits()), Addr: p.Masked().Addr().As16()}
		err = v6.Delete(&k)
	}
	if err != nil && !isMissing(err) {
		return fmt.Errorf("dataplane: %s: remove %s: %w", what, p, err)
	}
	return nil
}

// isMissing reports a "key not present" result, which the reconciling helpers
// treat as success: the manager drives the maps toward a desired set and must
// be safe to run twice.
func isMissing(err error) bool { return errors.Is(err, ebpf.ErrKeyNotExist) }

/* ========================================================================= */
/* Double-buffered rule sets                                                  */
/* ========================================================================= */

// PolicyStride and StaticStride are the number of entries one generation owns
// in each double-buffered map. The maps are sized Generations x stride, and
// index arithmetic (generation*stride + id) selects the half; see the DOUBLE
// BUFFERING note in kapkan_maps.h for why that beats sibling maps and
// ARRAY_OF_MAPS.
func PolicyStride(m *Maps) uint32 { return m.KapkanPolicies.MaxEntries() / Generations }

// StaticStride is the per-generation capacity of kapkan_statics.
func StaticStride(m *Maps) uint32 { return m.KapkanStatics.MaxEntries() / Generations }

// PutPolicy writes one victim's whole rule set into a generation's half.
//
// WHICH GENERATION depends on which caller you are, and the two answers differ:
//
//   - Static policy reload builds the INACTIVE half and publishes it with
//     Activate. It rewrites everything at once, so an all-or-nothing flip is
//     both possible and correct.
//
//   - A dynamic rule installer writes the ACTIVE half, inside Manager.WithMaps,
//     which hands it the live generation under the same lock that serialises
//     Reload. That is not a compromise: a ban must take effect now, and a rule
//     parked in the inactive half would not be enforcing until something else
//     happened to flip. WithMaps also closes the window where a reload's
//     mirrorPolicyBlocks has already copied the blocks across but not yet
//     flipped — a rule written to the active half in that window would be
//     published into a half nobody copied it to and would simply vanish.
//
// The torn read is real either way — the block is a single 520-byte map value
// and bpf_map_update_elem copies it without excluding a concurrent reader, so a
// packet can see the new n_rules against a partially written rules[]. It is
// bounded to something harmless because slots past n_rules are left zeroed, so
// KAPKAN_RF_VALID is clear in every one of them: a torn read UNDER-matches and
// never over-matches. The worst case is one victim's own rule set enforcing a
// packet or two late, which is fail-open and exactly what the charter asks for.
// It could never produce a drop the operator did not configure.
func PutPolicy(m *Maps, gen, policyID uint32, rules []Rule) error {
	if len(rules) > RulesPerPolicy {
		return fmt.Errorf("dataplane: policy %d has %d rules, the block holds %d "+
			"(config.maxDataplaneRulesPerBan)", policyID, len(rules), RulesPerPolicy)
	}
	if err := checkGeneration(gen); err != nil {
		return err
	}
	stride := PolicyStride(m)
	if policyID >= stride {
		return fmt.Errorf("dataplane: policy id %d is past the %d-entry generation stride", policyID, stride)
	}
	// Slots past n_rules are left zeroed, so KAPKAN_RF_VALID is clear in every
	// one of them: a torn read can only ever under-match, never over-match.
	block := PolicyBlock{N_rules: uint32(len(rules))}
	copy(block.Rules[:], rules)
	if err := m.KapkanPolicies.Put(gen*stride+policyID, &block); err != nil {
		return fmt.Errorf("dataplane: write policy %d in generation %d: %w", policyID, gen, err)
	}
	return nil
}

// PutStatics fills a generation's half of kapkan_statics and returns the count
// to publish with Activate. Slots past the rule set are ZEROED, which matters
// for more than tidiness — see Activate.
func PutStatics(m *Maps, gen uint32, rules []Rule) (uint32, error) {
	if err := checkGeneration(gen); err != nil {
		return 0, err
	}
	stride := StaticStride(m)
	if uint32(len(rules)) > stride {
		return 0, fmt.Errorf("dataplane: %d static rules exceed the %d-entry generation stride "+
			"(config dataplane.limits.max_static_rules)", len(rules), stride)
	}
	base := gen * stride
	for i, r := range rules {
		if err := m.KapkanStatics.Put(base+uint32(i), &r); err != nil {
			return 0, fmt.Errorf("dataplane: write static %d in generation %d: %w", i, gen, err)
		}
	}
	var empty Rule // Flags == 0, so KAPKAN_RF_VALID is clear: never matches.
	for i := uint32(len(rules)); i < stride; i++ {
		if err := m.KapkanStatics.Put(base+i, &empty); err != nil {
			return 0, fmt.Errorf("dataplane: clear static %d in generation %d: %w", i, gen, err)
		}
	}
	return uint32(len(rules)), nil
}

func checkGeneration(gen uint32) error {
	if gen >= Generations {
		return fmt.Errorf("dataplane: generation %d is out of range [0,%d)", gen, Generations)
	}
	return nil
}

/* ========================================================================= */
/* kapkan_cfg and the generation flip                                         */
/* ========================================================================= */

// ConfigSpec is kapkan_cfg[0] in ordinary Go values. The strides and the schema
// version are not here: PutConfig derives the strides from the real map sizes
// and stamps MapSchemaVersion, because getting either wrong is a silent
// misread of every rule rather than an error anyone would see.
type ConfigSpec struct {
	Generation    uint32
	StaticCount   uint32
	DryRun        bool
	DropMalformed bool
}

// PutConfig writes kapkan_cfg[0] outright. Use it at attach; use Activate for
// a policy swap on a running program.
func PutConfig(m *Maps, s ConfigSpec) error {
	if err := checkGeneration(s.Generation); err != nil {
		return err
	}
	cfg := Config{
		Generation:       s.Generation,
		MapSchemaVersion: MapSchemaVersion,
		PolicyStride:     PolicyStride(m),
		StaticStride:     StaticStride(m),
		StaticCount:      s.StaticCount,
		DryRun:           b2u8(s.DryRun),
		DropMalformed:    b2u8(s.DropMalformed),
	}
	if err := m.KapkanCfg.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("dataplane: write kapkan_cfg[0]: %w", err)
	}
	return nil
}

// ReadConfig reads kapkan_cfg[0].
func ReadConfig(m *Maps) (Config, error) {
	var cfg Config
	if err := m.KapkanCfg.Lookup(uint32(0), &cfg); err != nil {
		return Config{}, fmt.Errorf("dataplane: read kapkan_cfg[0]: %w", err)
	}
	return cfg, nil
}

// InactiveGeneration is the half a caller may safely build into: the one the
// datapath is not reading.
func InactiveGeneration(m *Maps) (uint32, error) {
	cfg, err := ReadConfig(m)
	if err != nil {
		return 0, err
	}
	return (cfg.Generation + 1) % Generations, nil
}

// Activate publishes a generation: after it returns, every packet is evaluated
// against the rule set built in gen. Everything else in kapkan_cfg is
// preserved.
//
// WHY THIS IS NOT LITERALLY "ONE u32 STORE", AND WHY IT IS STILL SAFE.
// kapkan_maps.h describes the flip as a single 4-byte store of `generation`,
// and for the policy blocks it is exactly that. The statics need one more
// field: static_count bounds their scan and belongs to a generation, but F6
// has a single count rather than one per generation, so a swap that changes
// the number of statics must move both fields. The Go map API writes the whole
// 32-byte value, and BPF_MAP_TYPE_ARRAY updates are a plain memcpy with no
// exclusion against a reader, so a packet in flight can observe the new
// generation with the old count or vice versa.
//
// All four combinations are safe, and PutStatics is what makes them safe:
//
//	new gen + new count -> the intended new rule set.
//	old gen + old count -> the intended old rule set.
//	old gen + new count -> the old rules plus, if the count grew, slots that
//	                       PutStatics zeroed. KAPKAN_RF_VALID is clear in a
//	                       zeroed slot, so it never matches: the old set.
//	new gen + old count -> a PREFIX of the new set if the count shrank. Fewer
//	                       rules than intended, for the nanoseconds the memcpy
//	                       takes. It under-matches, which per the charter is
//	                       the safe direction — the packet passes.
//
// The load-bearing part is that PutStatics zeroes the tail of the half it
// fills. Skip that and "old gen + new count" starts reading whatever a
// previous, longer rule set left behind, which over-matches: it would drop
// traffic on the strength of a rule the operator already removed.
func Activate(m *Maps, gen, staticCount uint32) error {
	if err := checkGeneration(gen); err != nil {
		return err
	}
	cfg, err := ReadConfig(m)
	if err != nil {
		return err
	}
	if staticCount > cfg.StaticStride {
		return fmt.Errorf("dataplane: static_count %d exceeds the %d-entry stride",
			staticCount, cfg.StaticStride)
	}
	cfg.Generation = gen
	cfg.StaticCount = staticCount
	if err := m.KapkanCfg.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("dataplane: activate generation %d: %w", gen, err)
	}
	return nil
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

/* ========================================================================= */
/* Counters                                                                   */
/* ========================================================================= */

// ReadStat sums one kapkan_stats counter across every CPU. The map is PERCPU so
// the datapath can increment without an atomic; summing is userspace's job.
func ReadStat(m *Maps, s Stat) (Counter, error) {
	var per []Counter
	if err := m.KapkanStats.Lookup(uint32(s), &per); err != nil {
		return Counter{}, fmt.Errorf("dataplane: read stat %s: %w", s, err)
	}
	return sumCounters(per), nil
}

// ReadStats reads the whole counter block in one pass, which is what the API
// and the console want: a consistent-enough snapshot rather than StatMax
// separate syscalls interleaved with traffic.
func ReadStats(m *Maps) ([StatMax]Counter, error) {
	var out [StatMax]Counter
	for s := Stat(0); s < StatMax; s++ {
		c, err := ReadStat(m, s)
		if err != nil {
			return out, err
		}
		out[s] = c
	}
	return out, nil
}

// EnsureRuleStats creates the kapkan_rule_stats entry for each rule id. The
// datapath only bumps an entry that already exists — a miss means "not
// instrumented", not an error — so userspace creates them when it installs the
// rules.
func EnsureRuleStats(m *Maps, ids ...uint32) error {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("dataplane: possible CPUs: %w", err)
	}
	zero := make([]Counter, n)
	for _, id := range ids {
		if err := m.KapkanRuleStats.Put(uint64(id), zero); err != nil {
			return fmt.Errorf("dataplane: create rule_stats[%d]: %w", id, err)
		}
	}
	return nil
}

// ReadRuleStats sums one rule's per-CPU counter. The bool reports whether the
// entry exists at all.
func ReadRuleStats(m *Maps, id uint32) (Counter, bool, error) {
	var per []Counter
	if err := m.KapkanRuleStats.Lookup(uint64(id), &per); err != nil {
		if isMissing(err) {
			return Counter{}, false, nil
		}
		return Counter{}, false, fmt.Errorf("dataplane: read rule_stats[%d]: %w", id, err)
	}
	return sumCounters(per), true, nil
}

func sumCounters(per []Counter) Counter {
	var out Counter
	for _, c := range per {
		out.Pkts += c.Pkts
		out.Bytes += c.Bytes
	}
	return out
}

/* ========================================================================= */
/* Token buckets                                                              */
/* ========================================================================= */

// ReadBucket returns the token bucket for one {anchor, source, profile} triple,
// and whether it exists. The anchor is the prefix the matching rule was found
// under: the destination for a static or precedence-5 rule, the source for
// precedence 4.
//
// The map is an LRU, so an absent bucket is not an anomaly — under a spoofed
// flood cold entries are evicted, and an evicted source restarts with a full
// bucket, which fails open exactly as the charter requires.
func ReadBucket(m *Maps, anchor, src netip.Addr, profile uint32) (Bucket, bool, error) {
	var (
		b   Bucket
		err error
	)
	if anchor.Is4() != src.Is4() {
		return Bucket{}, false, fmt.Errorf("dataplane: bucket anchor %s and source %s are different families",
			anchor, src)
	}
	if anchor.Is4() {
		k := RLKeyV4{Victim: hostU32(anchor), Src: hostU32(src), Profile: profile}
		err = m.KapkanRlSrc4.Lookup(&k, &b)
	} else {
		k := RLKeyV6{Victim: anchor.As16(), Src: src.As16(), Profile: profile}
		err = m.KapkanRlSrc6.Lookup(&k, &b)
	}
	if err != nil {
		if isMissing(err) {
			return Bucket{}, false, nil
		}
		return Bucket{}, false, fmt.Errorf("dataplane: read bucket {%s,%s,%d}: %w", anchor, src, profile, err)
	}
	return b, true, nil
}

// hostU32 packs an IPv4 address into the u32 the kernel key holds. The C stores
// the raw network-order bytes in a __be32 field, so the Go value is whatever
// integer has those bytes in native (little-endian) order — which is why this
// reads LittleEndian and not Big.
func hostU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.LittleEndian.Uint32(b[:])
}

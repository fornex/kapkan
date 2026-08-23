//go:build linux

package dataplane

// The WRITING half of the data plane's map interface: putting the encoded
// layouts from encode.go into a loaded map set. Everything that ever writes to
// a kapkan_* map goes through this file — the manager, the mitigator's rule
// installer and every test — so there is exactly one place to fix when a map's
// update rules change.
//
// THE STRUCT DEFINITIONS ARE NOT HERE, AND NOT IN encode.go EITHER. They are
// the bpf2go-generated types in kapkanxdp_bpfel.go, derived from the object's
// BTF and aliased under readable names in bindings.go. A hand-written mirror is
// the classic way for userspace and kernel to drift silently and start dropping
// traffic nobody named; with the generated types a field added in C is a Go
// compile error on the next `make dataplane-sync`.
//
// Linux-only because writing a map needs the bpf(2) syscall. The pure encoders
// live in encode.go, which is untagged so that the mitigator's
// FlowSpecRule-to-RuleSpec compiler — the code that decides which packets get
// dropped — is unit-testable on a macOS development host; see the note at the
// top of that file.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

/* ========================================================================= */
/* Rate-limit profiles                                                        */
/* ========================================================================= */

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

	// The fingerprint plane (E2). FPEnabled turns the copy path on; the sampler
	// then caps copy volume so the plane cannot become its own DoS. FPSamplePPS
	// is the per-CPU copy ceiling in events/s and FPBurst the bucket depth in
	// events (0 defaults to one second's worth, mirroring a rate-limit profile).
	// These gate only the observation ring and never a verdict, so PutConfig may
	// write them outright with the rest of the config.
	FPEnabled   bool
	FPSamplePPS uint64
	FPBurst     uint64
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
		FpEnabled:        b2u8(s.FPEnabled),
		FpBurst:          s.FPBurst,
		FpRatePerNsQ32:   q32PerNs(s.FPSamplePPS),
	}
	// Default the sampler burst to one second of its rate, exactly as a
	// rate-limit profile does, so a fresh CPU can emit a burst before the refill
	// governs. Left at 0 when no rate is set (the plane copies nothing).
	if s.FPBurst == 0 && s.FPSamplePPS > 0 {
		cfg.FpBurst = max(s.FPSamplePPS, 1)
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

// DeleteRuleStats removes the kapkan_rule_stats entries for the given rule ids.
// An absent entry is not an error, for the same reason DeleteVictim tolerates
// one: the caller reconciles toward a desired state and must be safe to run
// twice.
//
// This is the other half of the contract limits.go states: kapkan_rule_stats is
// a PREALLOCATED PERCPU_HASH sized MaxDynamicRules + StaticStride, so an
// installer that creates entries and never reaps them fills the map and starts
// failing installs — during an attack, which is the only time it installs
// anything.
func DeleteRuleStats(m *Maps, ids ...uint32) error {
	for _, id := range ids {
		if err := m.KapkanRuleStats.Delete(uint64(id)); err != nil && !isMissing(err) {
			return fmt.Errorf("dataplane: delete rule_stats[%d]: %w", id, err)
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

package dataplane

// Map sizing: turning dataplane.limits into actual map sizes.
//
// This file pays off the debt S2 left behind. Until now dataplane.limits was
// accepted by config's validate() and then thrown away: with no loader, the
// maps were whatever the ELF was compiled with. An operator who set
// max_ratelimit_sources: 65536 to fit a 2 GiB box still got two 1,048,576-entry
// LRU hashes — 94% of a measured 234.9 MiB, charged to the unit's memory cgroup
// in one step at load, which on a small box is an OOM kill at startup for a
// limit the operator explicitly lowered.
//
// The fix is four lines of assignment and a lot of care about which maps may be
// resized at all, so the reasoning is here rather than inline in the manager.
//
// WHY REWRITE THE SPEC INSTEAD OF THE C. Because the sizes are policy, not
// contract. The C has to compile to *something*, and what it compiles to is the
// default; the operator's number is only known at startup. Rewriting
// MaxEntries on the CollectionSpec before ebpf.NewCollection is the only place
// where both are in hand. It is also why this file is untagged: a
// CollectionSpec is parsed from the embedded ELF with no kernel involved, so
// every rule below is unit-testable on the macOS development host and only the
// "the created map really is that size" assertion needs a Linux kernel.

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// Limits is the resolved map sizing — config.DataplaneSettings' three limit
// fields, restated here so this package does not force its callers through
// config (and so the sizing rules can be tested without building a Config).
type Limits struct {
	// MaxDynamicRules caps the rules the mitigator may install. It sizes
	// kapkan_policies, in blocks of RulesPerPolicy.
	MaxDynamicRules int
	// MaxStaticRules caps operator rules from the config file. It sizes
	// kapkan_statics.
	MaxStaticRules int
	// MaxRatelimitSources sizes the two per-source token-bucket LRUs. This is
	// the number that matters for memory.
	MaxRatelimitSources int
}

// DefaultLimits is what an operator who names no limits gets, identical to
// config's defaults and to the sizes the ELF is compiled with.
func DefaultLimits() Limits {
	return Limits{
		MaxDynamicRules:     DefaultMaxDynamicRules,
		MaxStaticRules:      DefaultMaxStaticRules,
		MaxRatelimitSources: DefaultMaxRatelimitSources,
	}
}

// MapSizing is the max_entries every resizable map is created with, plus the
// two per-generation strides derived from them. It exists as a value so the
// manager can log it, Stats can report it, and a test can assert it without
// re-deriving the arithmetic (a test that recomputes what it checks proves
// nothing).
type MapSizing struct {
	// Policies is kapkan_policies' max_entries: Generations * PolicyStride.
	Policies uint32
	// Statics is kapkan_statics' max_entries: Generations * StaticStride.
	Statics uint32
	// RLSources is max_entries of each of kapkan_rl_src4 and kapkan_rl_src6.
	RLSources uint32
	// RuleStats is kapkan_rule_stats' max_entries.
	RuleStats uint32

	// PolicyStride is how many policy blocks one generation owns, i.e. the
	// highest policy id + 1. It is the operator's rule budget divided by the
	// block size, because a block holds one victim's whole rule set.
	PolicyStride uint32
	// StaticStride is how many ENCODED static rules one generation owns,
	// which is StaticExpansion times the operator's max_static_rules — see
	// that constant.
	StaticStride uint32
}

// StaticExpansion is how many kernel rules one config static rule can compile
// to, and therefore the factor between dataplane.limits.max_static_rules (which
// counts rules as the operator wrote them) and kapkan_statics' per-generation
// stride (which counts encoded rules).
//
// It is 2 because the datapath tests a rule's KAPKAN_RF_IPV6 bit against the
// packet's family unconditionally — a v4 rule never matches a v6 packet, by
// design, so that IPv4-mapped addresses can never smuggle a match across
// families. A config rule that names no source prefix therefore has no family,
// and the honest compilation of
//
//   - name: drop-chargen
//     match: {proto: udp, src_port: 19}
//     action: drop
//
// is two kernel rules, one per family. Emitting one would silently protect
// exactly half of what the operator asked for, and the half it dropped would be
// the one nobody notices until it is the attack vector.
//
// The cost of sizing for the worst case is 33 KiB (kapkan_statics doubles from
// 512 to 1024 entries at the default limit). The cost of NOT sizing for it is
// an operator with 200 family-agnostic rules and max_static_rules: 256 getting
// a startup failure for a config that config's own validate() accepted.
const StaticExpansion = 2

// MapSizing resolves limits into map sizes, or explains why it cannot.
//
// The double-buffered maps are Generations x stride: that is the price of a
// lossless policy swap and it is stated in the docs, so an operator asking for
// 4096 dynamic rules gets 8192 policy-block slots' worth of memory. Being
// explicit here is better than the alternative, which is an operator setting
// max_dynamic_rules to half of what they wanted because they read the map
// footprint and worked backwards.
func (l Limits) MapSizing() (MapSizing, error) {
	if l.MaxDynamicRules < 1 {
		return MapSizing{}, fmt.Errorf("dataplane: limits.max_dynamic_rules must be > 0, got %d", l.MaxDynamicRules)
	}
	if l.MaxStaticRules < 1 {
		return MapSizing{}, fmt.Errorf("dataplane: limits.max_static_rules must be > 0, got %d", l.MaxStaticRules)
	}
	if l.MaxRatelimitSources < 1 {
		return MapSizing{}, fmt.Errorf("dataplane: limits.max_ratelimit_sources must be > 0, got %d", l.MaxRatelimitSources)
	}

	// Round UP: an operator who asks for 4097 rules must not silently get
	// 4096. One extra block costs 520 bytes per generation.
	policyStride := (l.MaxDynamicRules + RulesPerPolicy - 1) / RulesPerPolicy
	staticStride := l.MaxStaticRules * StaticExpansion

	// kapkan_rule_stats is keyed by rule id and holds one entry per LIVE rule,
	// so the bound is every rule that can exist at once. It is a preallocated
	// PERCPU_HASH (304 B/entry on a 14-CPU host, ~9x that on a 128-core box),
	// which is why it is worth sizing from the limits rather than leaving the
	// compiled-in 8192.
	//
	// CONTRACT THIS CREATES for the rule installer: an entry must be deleted
	// when its rule is removed. EnsureRuleStats creates entries and nothing
	// reaps them, so a caller that churns rule ids without deleting will fill
	// this map and start failing installs — where before it had the difference
	// between 8192 and the real rule count as accidental slack to hide in.
	ruleStats := l.MaxDynamicRules + staticStride

	// Overflow. Every product below is bounded by the checks here, so the
	// uint32 conversions cannot wrap. A limit this large is a typo (the
	// smallest of these maps would be ~2 TiB), and the kernel would refuse the
	// allocation anyway — but it would refuse it with ENOMEM after the
	// conversion had already produced a small, wrong number, which is the
	// failure mode worth preventing.
	const maxEntries = 1 << 31
	for _, c := range []struct {
		what string
		v    int
	}{
		{"limits.max_dynamic_rules", policyStride * Generations},
		{"limits.max_static_rules", staticStride * Generations},
		{"limits.max_ratelimit_sources", l.MaxRatelimitSources},
		{"limits.max_dynamic_rules + limits.max_static_rules", ruleStats},
	} {
		if c.v < 1 || c.v > maxEntries {
			return MapSizing{}, fmt.Errorf(
				"dataplane: %s is out of range: it sizes a map to %d entries (max %d)", c.what, c.v, maxEntries)
		}
	}

	return MapSizing{
		Policies:     uint32(policyStride * Generations),
		Statics:      uint32(staticStride * Generations),
		RLSources:    uint32(l.MaxRatelimitSources),
		RuleStats:    uint32(ruleStats),
		PolicyStride: uint32(policyStride),
		StaticStride: uint32(staticStride),
	}, nil
}

// resizable lists, for each map the loader rewrites, where its new size comes
// from. Every other map in AllMaps is left at its compiled-in size, and
// applySizing asserts that the set of names here plus the fixed ones below is
// exactly AllMaps — so a map added to the C side has to be classified as
// resizable or not, rather than defaulting to "whatever clang said".
func (s MapSizing) resizable() map[string]uint32 {
	return map[string]uint32{
		MapPolicies:  s.Policies,
		MapStatics:   s.Statics,
		MapRLSrc4:    s.RLSources,
		MapRLSrc6:    s.RLSources,
		MapRuleStats: s.RuleStats,
	}
}

// fixedSizes are the maps whose size is contract rather than policy, with the
// value each must have. A mismatch means the C and this package disagree about
// something structural, which is worth failing at startup over: kapkan_cfg
// having more than one entry, or kapkan_stats not covering StatMax, would make
// every counter read or generation flip address the wrong slot.
func fixedSizes() map[string]uint32 {
	return map[string]uint32{
		MapCfg:      1,
		MapStats:    uint32(StatMax),
		MapProfiles: MaxProfiles,
		MapAllow4:   MaxPrefixes,
		MapAllow6:   MaxPrefixes,
		MapProtect4: MaxPrefixes,
		MapProtect6: MaxPrefixes,
		MapVictims4: MaxPrefixes,
		MapVictims6: MaxPrefixes,
		// The fingerprint plane (E2). The sampler is one per-CPU slot; the ring
		// is a fixed byte size (max_entries on a RINGBUF is its byte length). The
		// ring is not operator-tunable in E2 — a full ring drops copies rather
		// than the datapath, so a bigger one only buys the reader more slack.
		MapFPSampler: 1,
		MapFPEvents:  FPRingBytes,
	}
}

// applySizing rewrites max_entries on spec so the maps are created at the
// operator's limits, and verifies everything it does not rewrite.
//
// Called BEFORE ebpf.NewCollection/LoadAndAssign. Afterwards it is far too
// late: a map's size is fixed at creation, and the only remedy is to tear the
// whole thing down and build it again.
func applySizing(spec *ebpf.CollectionSpec, s MapSizing) error {
	if len(spec.Maps) != len(AllMaps) {
		return fmt.Errorf("dataplane: object defines %d maps, the contract names %d",
			len(spec.Maps), len(AllMaps))
	}
	resize, fixed := s.resizable(), fixedSizes()
	for _, name := range AllMaps {
		ms, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("dataplane: object does not define map %q", name)
		}
		switch want, isResizable := resize[name]; {
		case isResizable:
			ms.MaxEntries = want
		default:
			want, isFixed := fixed[name]
			if !isFixed {
				return fmt.Errorf("dataplane: map %q is neither resizable nor fixed-size; "+
					"classify it in limits.go before shipping it", name)
			}
			if ms.MaxEntries != want {
				return fmt.Errorf("dataplane: map %q is compiled with max_entries %d, the contract requires %d",
					name, ms.MaxEntries, want)
			}
		}
	}
	return nil
}

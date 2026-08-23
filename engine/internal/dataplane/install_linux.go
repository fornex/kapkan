//go:build linux

package dataplane

// Compiling the operator's static policy into the kernel, and reconciling the
// parts of it that a config diff cannot describe.
//
// Three different update mechanisms live here, and which one a piece of policy
// gets is determined by what the datapath does with it:
//
//   - STATIC RULES are double-buffered. They are scanned in order, first match
//     wins, so a half-written set could drop traffic on the strength of a rule
//     the operator already removed. Built in the inactive generation, published
//     with one flip.
//
//   - PREFIX TRIES (allowlist, protected list) are reconciled by diff. An LPM
//     trie cannot be swapped atomically and has no generation, so the desired
//     set is compared against what is in the kernel and only the difference is
//     applied. That ordering is chosen on purpose: ADDS FIRST, then removes, so
//     a prefix that stays in the list is never absent for an instant.
//
//   - PROFILES are written in place, keyed by name. In place because they are a
//     plain array with no generation; keyed by name because positional ids would
//     make reordering the config silently reassign every rate — an
//     old-generation rule would read the new profile's numbers in the window
//     before the flip.
//
// What a torn profile read costs, stated because it is invisible otherwise: a
// profile is a 64-byte map value and BPF_MAP_TYPE_ARRAY updates are a memcpy
// with no exclusion against a reader, so a packet racing a rate change can
// refill a bucket at a blend of the old and new rates for the nanoseconds the
// copy takes. The operator asked for the new rate; getting it a few nanoseconds
// early or late on one packet is not a failure mode worth a second buffer.

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/cilium/ebpf"
)

// compiled is a StaticPolicy turned into the exact bytes and ids the kernel
// wants.
type compiled struct {
	// rules are the encoded static rules in config order (first match wins).
	rules []Rule
	// ruleIDs and ruleOwner are parallel to rules: the id assigned and the name
	// of the config rule it came from. ruleOwner is what lets a diagnostic name
	// a rule the way the operator wrote it.
	ruleIDs   []uint32
	ruleOwner []string
	// profileOf maps a profile name to the id it was assigned.
	profileOf map[string]uint32
	// profileSpec is the rate for each assigned id.
	profileSpec map[uint32]ProfileSpec
}

// compilePolicy encodes a static policy, assigning profile ids from prev so an
// id keeps its meaning across a reload.
//
// It fails rather than truncating on every count that exceeds a map: an operator
// whose 300th profile silently did not exist would have 300 static rules
// referencing a zeroed profile, which fails OPEN (the datapath admits when a
// profile caps neither packets nor bytes) — a rate limit that is not there and
// says nothing. config.validate() cannot catch these because it does not know
// the map sizes.
func compilePolicy(pol StaticPolicy, sizing MapSizing, prev map[string]uint32) (compiled, error) {
	c := compiled{
		profileOf:   make(map[string]uint32, len(pol.Profiles)),
		profileSpec: make(map[uint32]ProfileSpec, len(pol.Profiles)),
	}

	// Profile ids: keep the id a name already had, then fill the lowest free
	// slots for new names. Deterministic given (prev, pol), which is what makes
	// a reload's report reproducible.
	taken := make(map[uint32]bool, len(prev))
	for _, p := range pol.Profiles {
		if id, ok := prev[p.Name]; ok && !taken[id] {
			c.profileOf[p.Name] = id
			taken[id] = true
		}
	}
	next := uint32(0)
	for _, p := range pol.Profiles {
		if _, ok := c.profileOf[p.Name]; ok {
			continue
		}
		for taken[next] {
			next++
		}
		// DynamicProfileBase, not MaxProfiles: the top of the array is reserved
		// for the rates the mitigator interns while an attack is running. See
		// that constant for why the partition has to be static.
		if next >= DynamicProfileBase {
			return compiled{}, fmt.Errorf(
				"dataplane: %d ratelimit_profiles need more than the %d profile slots the config half "+
					"of the data plane has (ids %d..%d are reserved for the rates the mitigator interns "+
					"for rate_limit bans)",
				len(pol.Profiles), DynamicProfileBase, DynamicProfileBase, MaxProfiles-1)
		}
		c.profileOf[p.Name] = next
		taken[next] = true
	}
	for _, p := range pol.Profiles {
		c.profileSpec[c.profileOf[p.Name]] = ProfileFromConfig(p.PPS, p.Mbps)
	}

	// Static rules, in config order. Each config rule contributes one encoded
	// rule per address family it can match — see StaticExpansion.
	for i, sr := range pol.Statics {
		var profileID uint32
		if sr.Action == ActionRateLimit {
			id, ok := c.profileOf[sr.Profile]
			if !ok {
				return compiled{}, fmt.Errorf("dataplane: static rule %q names profile %q, "+
					"which is not declared in dataplane.ratelimit_profiles", sr.Name, sr.Profile)
			}
			profileID = id
		}
		for fi, v6 := range familiesFor(sr) {
			spec := RuleSpec{
				// Ids are positional so that a rule keeps its counter across a
				// reload that did not move it. i*StaticExpansion+fi leaves a
				// gap for the family a rule does not use, which is the price of
				// that stability.
				ID:      StaticRuleIDBase + uint32(i*StaticExpansion+fi),
				Action:  sr.Action,
				Profile: profileID,
				// 0 = never expires. Static rules come from the config file and
				// cannot be stranded by a manager crash, which is the only
				// reason the in-kernel expiry exists.
				ExpiresAt: 0,
				Src:       sr.Src,
				Proto:     sr.Proto,
				SrcPort:   sr.SrcPort,
				DstPort:   sr.DstPort,
				MatchExt:  sr.MatchExt,
				IPv6:      v6,
			}
			r, err := spec.Encode()
			if err != nil {
				return compiled{}, fmt.Errorf("dataplane: static rule %q: %w", sr.Name, err)
			}
			c.rules = append(c.rules, r)
			c.ruleIDs = append(c.ruleIDs, spec.ID)
			c.ruleOwner = append(c.ruleOwner, sr.Name)
		}
	}

	if n := uint32(len(c.rules)); n > sizing.StaticStride {
		return compiled{}, fmt.Errorf("dataplane: %d config static rules compile to %d kernel rules, "+
			"past the %d-entry generation stride (raise dataplane.limits.max_static_rules; "+
			"a rule with no match.src compiles to %d rules, one per address family)",
			len(pol.Statics), n, sizing.StaticStride, StaticExpansion)
	}
	return c, nil
}

/* ========================================================================= */
/* Prefix trie reconciliation                                                 */
/* ========================================================================= */

// trieEntries dumps an LPM trie's keys as prefixes. BPF_MAP_GET_NEXT_KEY for
// LPM_TRIE landed in 4.20, comfortably below the 5.15 floor, so a failure here
// is a real error and not a capability gap.
func trieEntries(m *ebpf.Map, v6 bool) ([]netip.Prefix, error) {
	var out []netip.Prefix
	var val uint8
	it := m.Iterate()
	if v6 {
		var k LPMKeyV6
		for it.Next(&k, &val) {
			out = append(out, netip.PrefixFrom(netip.AddrFrom16(k.Addr), int(k.Prefixlen)))
		}
	} else {
		var k LPMKeyV4
		for it.Next(&k, &val) {
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(k.Addr), int(k.Prefixlen)))
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("dataplane: dump prefix trie: %w", err)
	}
	return out, nil
}

// prefixDiff returns what to add and what to remove to turn have into want.
// Both results are sorted so a reload report is stable and diffable.
func prefixDiff(have, want []netip.Prefix) (add, remove []netip.Prefix) {
	h := make(map[netip.Prefix]bool, len(have))
	for _, p := range have {
		h[p] = true
	}
	w := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		w[p] = true
		if !h[p] {
			add = append(add, p)
		}
	}
	for _, p := range have {
		if !w[p] {
			remove = append(remove, p)
		}
	}
	sortPrefixes(add)
	sortPrefixes(remove)
	return add, remove
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool { return p[i].String() < p[j].String() })
}

func prefixStrings(p []netip.Prefix) []string {
	if len(p) == 0 {
		return nil
	}
	out := make([]string, len(p))
	for i := range p {
		out[i] = p[i].String()
	}
	return out
}

// reconcileTrie drives one prefix list toward want and returns the deltas.
//
// ADDS BEFORE REMOVES, always. The two lists here are "never touch this
// sender" and "never ban this victim"; a prefix that is in both the old and the
// new set must never be absent for an instant, and doing removes first would
// make it absent for exactly as long as the syscalls take. On the add path a
// duplicate is a no-op, so the overlap costs nothing.
func reconcileTrie(v4, v6 *ebpf.Map, want []netip.Prefix, what string,
	add func(p netip.Prefix) error, del func(p netip.Prefix) error,
) (added, removed []netip.Prefix, err error) {
	have4, err := trieEntries(v4, false)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	have6, err := trieEntries(v6, true)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	have := append(have4, have6...)

	toAdd, toRemove := prefixDiff(have, want)
	for _, p := range toAdd {
		if err := add(p); err != nil {
			return added, removed, fmt.Errorf("%s: %w", what, err)
		}
		added = append(added, p)
	}
	for _, p := range toRemove {
		if err := del(p); err != nil {
			return added, removed, fmt.Errorf("%s: %w", what, err)
		}
		removed = append(removed, p)
	}
	return added, removed, nil
}

/* ========================================================================= */
/* Carrying dynamic rules across a generation flip                            */
/* ========================================================================= */

// mirrorPolicyBlocks copies every policy block from one generation's half of
// kapkan_policies into the other's.
//
// THIS IS LOAD-BEARING AND EASY TO MISS. kapkan_policies is double-buffered on
// the SAME generation counter as kapkan_statics — the datapath indexes it
// `generation * policy_stride + policy_id` — so publishing a new static rule set
// by flipping the generation ALSO moves the datapath to the other half of the
// policy map. The dynamic rules the mitigator installed live in the half being
// left behind. Without this copy, a config reload (an operator fixing a typo in
// an allowlist entry) would silently un-mitigate every live attack, and so would
// adopting a pinned data plane at startup, which is the one operation whose
// entire purpose is to preserve them.
//
// EVERY slot is written, not only the occupied ones: the destination half holds
// whatever a previous generation left there, and a stale block with a non-zero
// n_rules would come back to life on the flip. That is the same reasoning as
// PutStatics zeroing its tail, and the same consequence if skipped — dropping
// traffic on the strength of a rule that was already removed.
//
// Cost: two syscalls per policy block. At the default max_dynamic_rules that is
// 1,024 syscalls per reload, which is nothing; at a max_dynamic_rules of a
// million it is a quarter of a million, which is a fraction of a second on an
// operation an operator triggers by hand. BPF_MAP_LOOKUP_BATCH would collapse it
// if that ever matters.
func mirrorPolicyBlocks(m *Maps, from, to, stride uint32) (occupied int, err error) {
	if from == to {
		return 0, nil
	}
	var block PolicyBlock
	for i := uint32(0); i < stride; i++ {
		if err := m.KapkanPolicies.Lookup(from*stride+i, &block); err != nil {
			return occupied, fmt.Errorf("dataplane: read policy block %d of generation %d: %w", i, from, err)
		}
		if err := m.KapkanPolicies.Put(to*stride+i, &block); err != nil {
			return occupied, fmt.Errorf("dataplane: mirror policy block %d into generation %d: %w", i, to, err)
		}
		if block.N_rules != 0 {
			occupied++
		}
	}
	return occupied, nil
}

/* ========================================================================= */
/* Shadowing                                                                  */
/* ========================================================================= */

// The static-rule half of this — an operator rule that can never fire, because
// the allowlist or an earlier rule already takes every packet it selects — is
// in shadow.go, untagged so it can be tested without a kernel. What is left
// here needs one: it reads the rules the MITIGATOR installed.

// shadowedDynamicRules counts the rules the MITIGATOR has installed whose source
// prefix is now covered by one of the allowlist prefixes in scan.
//
// It reads only the ACTIVE generation, which is where the live dynamic rules
// are, and only when the allowlist actually gained entries — the scan is one map
// lookup per policy block, which at a large max_dynamic_rules is not something
// to do on every reload for nothing.
//
// It REPORTS and does not repair, because there is nothing to repair: the
// allowlist is checked in the kernel before any rule is evaluated, so those
// rules stopped dropping the instant the trie entry landed. What the operator
// needs is to know it happened — an allowlist entry that silently neutered a
// live mitigation is a thing to find out now, not from a customer.
func shadowedDynamicRules(m *Maps, gen uint32, stride uint32, scan []netip.Prefix) (int, error) {
	if len(scan) == 0 || stride == 0 {
		return 0, nil
	}
	count := 0
	var block PolicyBlock
	for i := uint32(0); i < stride; i++ {
		if err := m.KapkanPolicies.Lookup(gen*stride+i, &block); err != nil {
			return count, fmt.Errorf("dataplane: read policy block %d: %w", i, err)
		}
		n := block.N_rules
		if n > RulesPerPolicy {
			n = RulesPerPolicy
		}
		for j := uint32(0); j < n; j++ {
			r := block.Rules[j]
			if r.Flags&RuleValid == 0 || r.Action == uint8(ActionPass) {
				continue
			}
			if r.Flags&RuleSrcAny != 0 {
				continue // no source to be covered
			}
			src := ruleSrcPrefix(r)
			for _, a := range scan {
				if covers(a, src) {
					count++
					break
				}
			}
		}
	}
	return count, nil
}

// ruleSrcPrefix reads an encoded rule's source back as a prefix, the inverse of
// RuleSpec.Encode's copyPrefix.
func ruleSrcPrefix(r Rule) netip.Prefix {
	if r.Flags&RuleIPv6 != 0 {
		return netip.PrefixFrom(netip.AddrFrom16(r.Src), int(r.SrcPrefixlen))
	}
	var b [4]byte
	copy(b[:], r.Src[:4])
	return netip.PrefixFrom(netip.AddrFrom4(b), int(r.SrcPrefixlen))
}

/* ========================================================================= */
/* kapkan_cfg flags                                                           */
/* ========================================================================= */

// putFlags writes only dry_run and drop_malformed, preserving the generation and
// the static count.
//
// Separate from Activate on purpose. Activate's safety argument enumerates the
// four ways a packet can observe a torn {generation, static_count} pair; folding
// two more fields into that store would widen the argument for no reason. These
// two are independent of the double buffer — dry_run rewrites a verdict at the
// very end and drop_malformed decides a branch before any rule is read — so they
// are written first and the flip stays exactly as analysed.
func putFlags(m *Maps, o Options) error {
	cfg, err := ReadConfig(m)
	if err != nil {
		return err
	}
	cfg.DryRun, cfg.DropMalformed = b2u8(o.DryRun), b2u8(o.DropMalformed)
	// Fingerprint-plane knobs are re-stamped here too, for the same reason as
	// dry_run: an ADOPTED plane must not inherit the previous process's fp
	// settings after the operator edited them (TestAdoptionRewritesFlags's
	// hazard). fp_enabled/sample_pps are restart-required, so on reload this
	// writes the unchanged values — a harmless no-op that keeps the one write
	// path honest.
	setFPConfig(&cfg, o.FPEnabled, o.FPSamplePPS, o.FPBurst)
	if err := m.KapkanCfg.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("dataplane: write kapkan_cfg flags: %w", err)
	}
	return nil
}

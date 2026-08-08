//go:build linux

package dataplane

// The DYNAMIC half of the data plane: installing and removing the rules the
// mitigator synthesises from a live attack.
//
// Everything the operator wrote goes in through Manager.Reload and lives in the
// double-buffered static maps. Everything the DETECTOR decided goes in through
// here, into kapkan_policies and kapkan_victims, one policy block per banned
// victim. The two never touch the same map entries, and this file is the only
// writer of the dynamic ones.
//
// ==========================================================================
// WHAT THIS TYPE ACTUALLY OWNS: three allocators and a lock discipline.
// ==========================================================================
//
//  1. POLICY IDS. A victim needs an index into kapkan_policies and an entry in
//     kapkan_victims pointing at it. Ids are bounded by the policy stride
//     (max_dynamic_rules / 8, rounded up), which config.validate() already
//     forces to exceed ban.max_active_bans, so exhaustion means an operator
//     lowered a limit under a live incident. It is an install FAILURE, which
//     the mitigator degrades to a blackhole — never a silently dropped rule.
//
//  2. RULE IDS, derived from the policy id (see DynamicRuleID). Not a separate
//     allocator on purpose.
//
//  3. PROFILE IDS for rate-limit rules, interned per distinct rate in the band
//     reserved by DynamicProfileBase and reference-counted so the last ban to
//     leave a rate releases its slot.
//
// The lock discipline is that every map write happens inside
// Manager.WithMaps, which holds the manager's lock and hands back the LIVE
// generation. That is not politeness: kapkan_policies is double-buffered on the
// same generation counter as kapkan_statics, so a config reload flips the
// generation and mirrors the policy blocks across. A rule written to the active
// half in the window between that mirror and the flip would be published into a
// half nobody copied it to, and would simply not exist. See PutPolicy's doc.
//
// Installer.mu is taken OUTSIDE WithMaps, always, so the order is
// installer.mu -> manager.mu and can never invert (nothing under the manager's
// lock calls back into an Installer).

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Installer installs and removes one victim's worth of mitigator-synthesised
// rules. It is safe for concurrent use.
//
// It holds no file descriptors of its own: every map it touches is borrowed
// from the Manager for the duration of one call, so a Manager that closes
// underneath it turns every subsequent call into an error rather than a use of
// a closed fd.
type Installer struct {
	mgr *Manager
	log *slog.Logger

	mu sync.Mutex

	// adopted records that the kernel's existing victim set has been read back
	// into the maps below. It happens on the first call rather than at
	// construction because the interesting case — a restart that ADOPTED a
	// pinned data plane — is followed immediately by the mitigator rehydrating
	// its persisted bans, so the first Install is where the answer is needed
	// and where a failure is still attributable.
	adopted bool
	stride  uint32

	// policyOf and takenPolicy are the two views of the policy-id allocator:
	// which victim holds which id, and which ids are unavailable. They are kept
	// separately because an id can be unavailable without this process knowing
	// whose it is — an adopted entry whose rules have not expired is exactly
	// that until the mitigator rehydrates the ban that owns it.
	policyOf    map[netip.Prefix]uint32
	takenPolicy map[uint32]bool

	// profileOf interns a rate (bytes/s) to a profile id; profileRefs counts
	// the victims currently pointing at each id; victimProfile remembers which
	// id a victim holds so a re-install or a withdraw can release exactly one
	// reference and not one too many.
	profileOf     map[uint64]uint32
	profileRefs   map[uint32]int
	victimProfile map[netip.Prefix]uint32

	// warnedPerSource makes the aggregate-vs-per-source warning fire once per
	// process instead of once per ban. It is a property of the datapath, not of
	// any one attack, and repeating it every install would bury the incident.
	warnedPerSource bool

	// bootNs reads CLOCK_BOOTTIME, overridden by tests.
	bootNs func() uint64
}

// NewInstaller binds an Installer to an open Manager.
//
// The Manager must outlive it. Nothing is read or written here: see the
// `adopted` field for why the kernel's existing state is picked up on the first
// call instead.
func NewInstaller(mgr *Manager, log *slog.Logger) *Installer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Installer{
		mgr:           mgr,
		log:           log.With("component", "dataplane-installer"),
		policyOf:      map[netip.Prefix]uint32{},
		takenPolicy:   map[uint32]bool{},
		profileOf:     map[uint64]uint32{},
		profileRefs:   map[uint32]int{},
		victimProfile: map[netip.Prefix]uint32{},
		bootNs:        bootTimeNs,
	}
}

/* ========================================================================= */
/* Install                                                                    */
/* ========================================================================= */

// Install puts one victim's rule set into the kernel, replacing whatever this
// victim had before.
//
// It is ALL OR NOTHING. On any failure — a full policy map, a full profile
// band, a rejected encode, a map write that fails — nothing of this victim's
// remains installed, including a rule set a previous Install had left there.
// That is the right direction because the caller's response to an error is to
// fall back to a blackhole, which is strictly stronger than the rules being
// rolled back; leaving a half-installed set behind would mean a victim filtered
// by two mitigations at once, one of which no ban record describes.
//
// ORDER OF WRITES IS LOAD-BEARING: the policy block is written BEFORE the
// kapkan_victims entry that points at it. A packet that reaches a victim entry
// whose block has not been written yet counts KAPKAN_STAT_ERR_POLICY_MISSING
// and passes — fail-open, but it is a real window and it is free to close.
// Withdraw does the reverse for the same reason.
func (i *Installer) Install(victim netip.Prefix, r DynamicRules) error {
	if !victim.IsValid() {
		return fmt.Errorf("dataplane: install: invalid victim prefix")
	}
	if victim.Addr().Is4In6() {
		return fmt.Errorf("dataplane: install %s: IPv4-mapped IPv6 victim; Unmap() it", victim)
	}
	if len(r.Specs) == 0 {
		return fmt.Errorf("dataplane: install %s: no rules", victim)
	}
	if len(r.Specs) > RulesPerPolicy {
		return fmt.Errorf("dataplane: install %s: %d rules, a policy block holds %d",
			victim, len(r.Specs), RulesPerPolicy)
	}
	if r.TTL <= 0 {
		// A zero deadline means "never expires" in the kernel and is reserved
		// for static rules. A mitigator rule that never expires is precisely
		// the failure the in-kernel expiry exists to prevent, so refuse rather
		// than encode one.
		return fmt.Errorf("dataplane: install %s: ttl must be positive, got %s "+
			"(a zero deadline means 'never expires' and is reserved for static rules)", victim, r.TTL)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	return i.mgr.WithMaps(func(maps *Maps, gen uint32) error {
		if err := i.adoptLocked(maps, gen); err != nil {
			return err
		}

		policyID, fresh, err := i.allocPolicyLocked(victim)
		if err != nil {
			return err
		}

		profileID, gotProfile, err := i.internProfileLocked(maps, victim, r.RateBytesPerSecond)
		if err != nil {
			i.releasePolicyLocked(victim, policyID, fresh)
			return err
		}

		// The deadline is computed HERE, from the boot clock, and not derived
		// from any wall-clock timestamp the caller holds. bootTimeNs returning
		// 0 means /proc/uptime could not be read, and encoding 0 would mean
		// "never expires" — the one value that must never come from a failure.
		now := i.bootNs()
		if now == 0 {
			i.releaseProfileLocked(maps, victim, gotProfile)
			i.releasePolicyLocked(victim, policyID, fresh)
			return fmt.Errorf("dataplane: install %s: cannot read CLOCK_BOOTTIME, so a rule deadline "+
				"cannot be set; refusing rather than installing rules that never expire", victim)
		}
		expiresAt := now + uint64(r.TTL.Nanoseconds())

		specs := make([]RuleSpec, len(r.Specs))
		ids := make([]uint32, len(r.Specs))
		for n, s := range r.Specs {
			s.ID = DynamicRuleID(policyID, n)
			s.ExpiresAt = expiresAt
			s.Profile = profileID
			specs[n], ids[n] = s, s.ID
		}
		rules, err := EncodeRules(specs...)
		if err != nil {
			i.releaseProfileLocked(maps, victim, gotProfile)
			i.releasePolicyLocked(victim, policyID, fresh)
			return err
		}

		// Rule-stats entries before the rules go live: the datapath only bumps
		// an entry that already exists, so creating them afterwards would lose
		// the first packets of every rule.
		if err := EnsureRuleStats(maps, ids...); err != nil {
			i.releaseProfileLocked(maps, victim, gotProfile)
			i.releasePolicyLocked(victim, policyID, fresh)
			return err
		}
		if err := PutPolicy(maps, gen, policyID, rules); err != nil {
			i.rollbackLocked(maps, gen, victim, policyID, ids, gotProfile, fresh)
			return err
		}
		if err := AddVictim(maps, victim, policyID); err != nil {
			i.rollbackLocked(maps, gen, victim, policyID, ids, gotProfile, fresh)
			return err
		}

		i.log.Info("installed data-plane rules",
			"victim", victim.String(), "policy_id", policyID, "rules", len(rules),
			"generation", gen, "ttl", r.TTL.Round(time.Second).String())
		return nil
	})
}

// rollbackLocked undoes a partially applied install. Errors are logged and
// swallowed: the caller already has a failure to report, and the operator
// cannot act on "the cleanup of the failure also failed" differently from "the
// install failed". Every step is a fail-open direction anyway — a deleted
// victim entry, a zeroed block and a deleted counter all mean "no rule".
func (i *Installer) rollbackLocked(maps *Maps, gen uint32, victim netip.Prefix, policyID uint32,
	ids []uint32, gotProfile bool, fresh bool,
) {
	if err := DeleteVictim(maps, victim); err != nil {
		i.log.Error("rolling back a failed install: unpointing the victim failed",
			"victim", victim.String(), "err", err)
	}
	if err := PutPolicy(maps, gen, policyID, nil); err != nil {
		i.log.Error("rolling back a failed install: clearing the policy block failed; "+
			"its rules still carry their own in-kernel deadline and will expire",
			"victim", victim.String(), "policy_id", policyID, "err", err)
	}
	if err := DeleteRuleStats(maps, ids...); err != nil {
		i.log.Error("rolling back a failed install: deleting rule counters failed",
			"victim", victim.String(), "err", err)
	}
	i.releaseProfileLocked(maps, victim, gotProfile)
	i.releasePolicyLocked(victim, policyID, fresh)
}

/* ========================================================================= */
/* Withdraw                                                                   */
/* ========================================================================= */

// Withdraw removes everything Install put in the kernel for victim. A victim
// that has nothing installed is not an error: the mitigator withdraws by
// method, and a ban that fell back to blackhole never installed anything.
//
// The victim entry goes FIRST, so no packet can reach a block that is about to
// be zeroed, and then the block, the counters and the allocations.
func (i *Installer) Withdraw(victim netip.Prefix) error {
	if !victim.IsValid() {
		return fmt.Errorf("dataplane: withdraw: invalid victim prefix")
	}
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.mgr.WithMaps(func(maps *Maps, gen uint32) error {
		if err := i.adoptLocked(maps, gen); err != nil {
			return err
		}
		policyID, ok := i.policyOf[victim]
		if !ok {
			return nil
		}

		var first error
		keep := false
		if err := DeleteVictim(maps, victim); err != nil {
			// The trie still points at the block. Zeroing the block below makes
			// that harmless (the datapath counts ERR_POLICY_MISSING and passes),
			// but the id must NOT go back on the free list: handing it to
			// another victim while a stale entry points at it would route this
			// victim's traffic into someone else's block. Every rule re-checks
			// both prefixes so it still could not produce a wrong drop, but the
			// leak is one slot and the alternative is confusing.
			first, keep = err, true
			i.log.Error("withdraw: unpointing the victim failed; leaking its policy slot",
				"victim", victim.String(), "policy_id", policyID, "err", err)
		}
		if err := PutPolicy(maps, gen, policyID, nil); err != nil && first == nil {
			first = err
		}
		ids := make([]uint32, RulesPerPolicy)
		for n := range ids {
			ids[n] = DynamicRuleID(policyID, n)
		}
		if err := DeleteRuleStats(maps, ids...); err != nil && first == nil {
			first = err
		}

		i.releaseProfileLocked(maps, victim, true)
		delete(i.policyOf, victim)
		if !keep {
			delete(i.takenPolicy, policyID)
		}
		i.log.Info("withdrew data-plane rules",
			"victim", victim.String(), "policy_id", policyID, "generation", gen)
		return first
	})
}

/* ========================================================================= */
/* Policy ids                                                                 */
/* ========================================================================= */

// allocPolicyLocked returns the policy id for victim, reusing the one it
// already holds. `fresh` reports whether this call created the binding, which
// is what a rollback needs to know: releasing an id a PREVIOUS install owns
// would strand that victim's rules with nothing tracking them.
func (i *Installer) allocPolicyLocked(victim netip.Prefix) (id uint32, fresh bool, err error) {
	if id, ok := i.policyOf[victim]; ok {
		return id, false, nil
	}
	for id := uint32(0); id < i.stride; id++ {
		if i.takenPolicy[id] {
			continue
		}
		if id > MaxPolicyID {
			break
		}
		i.policyOf[victim] = id
		i.takenPolicy[id] = true
		return id, true, nil
	}
	return 0, false, fmt.Errorf("%w: all %d in use (dataplane.limits.max_dynamic_rules / %d); "+
		"the ban will fall back rather than go unmitigated", ErrNoPolicySlots, i.stride, RulesPerPolicy)
}

// releasePolicyLocked undoes allocPolicyLocked, but only for a binding that
// call created.
func (i *Installer) releasePolicyLocked(victim netip.Prefix, id uint32, fresh bool) {
	if !fresh {
		return
	}
	delete(i.policyOf, victim)
	delete(i.takenPolicy, id)
}

/* ========================================================================= */
/* Rate-limit profiles                                                        */
/* ========================================================================= */

// internProfileLocked resolves a bytes/s ceiling to a profile id in the dynamic
// band, writing the profile if the rate is new. `got` reports whether a
// reference was taken, so a rollback releases exactly one.
//
// A rate of 0 is the discard case: no profile, no reference, and the returned
// id is ignored by the datapath because the action is not ratelimit.
func (i *Installer) internProfileLocked(maps *Maps, victim netip.Prefix, bps uint64) (id uint32, got bool, err error) {
	// Release whatever this victim held before: a re-install may carry a
	// different rate (the group's flowspec policy can change between a ban and
	// its rehydration), and keeping the old reference would pin a slot nothing
	// points at.
	i.releaseProfileLocked(maps, victim, true)

	if bps == 0 {
		return 0, false, nil
	}
	if !i.warnedPerSource {
		i.warnedPerSource = true
		i.log.Warn("a data-plane rate limit caps EACH SOURCE, not the aggregate: the same "+
			"ceiling handed to a FlowSpec peer would cap the whole flow, so a diffuse attack "+
			"admits this rate per attacker here. This is the datapath's per-source token bucket "+
			"working as designed; size the ceiling accordingly, or use a discard action",
			"bytes_per_second", bps)
	}

	id, ok := i.profileOf[bps]
	if !ok {
		free, err := i.freeProfileLocked()
		if err != nil {
			return 0, false, err
		}
		if err := PutProfile(maps, free, ProfileSpec{BytesPerSecond: bps}); err != nil {
			return 0, false, err
		}
		id = free
		i.profileOf[bps] = id
		i.log.Info("interned a dynamic rate-limit profile",
			"profile_id", id, "bytes_per_second", bps)
	}
	i.profileRefs[id]++
	i.victimProfile[victim] = id
	return id, true, nil
}

// freeProfileLocked picks the lowest free id in the dynamic band.
func (i *Installer) freeProfileLocked() (uint32, error) {
	used := make(map[uint32]bool, len(i.profileOf))
	for _, id := range i.profileOf {
		used[id] = true
	}
	for id := uint32(DynamicProfileBase); id < MaxProfiles; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("%w: all %d dynamic slots (ids %d..%d) hold a distinct live rate; "+
		"the ban will fall back rather than share a slot and enforce someone else's ceiling",
		ErrNoProfileSlots, MaxProfiles-DynamicProfileBase, DynamicProfileBase, MaxProfiles-1)
}

// releaseProfileLocked drops victim's reference, zeroing and freeing the slot
// when the last one goes.
//
// ZEROING IS THE RETIREMENT, and it fails open by construction: the datapath
// admits when a profile caps neither packets nor bytes. By the time this runs
// the victim's policy block is gone or about to be overwritten, so no live rule
// points at the slot — and if one somehow did, it would admit rather than drop.
func (i *Installer) releaseProfileLocked(maps *Maps, victim netip.Prefix, got bool) {
	if !got {
		return
	}
	id, ok := i.victimProfile[victim]
	if !ok {
		return
	}
	delete(i.victimProfile, victim)
	i.profileRefs[id]--
	if i.profileRefs[id] > 0 {
		return
	}
	delete(i.profileRefs, id)
	for rate, pid := range i.profileOf {
		if pid == id {
			delete(i.profileOf, rate)
		}
	}
	if err := PutProfile(maps, id, ProfileSpec{}); err != nil {
		i.log.Error("retiring a dynamic rate-limit profile failed; the slot is left in use",
			"profile_id", id, "err", err)
	}
}

/* ========================================================================= */
/* Adoption                                                                   */
/* ========================================================================= */

// adoptLocked reads the victim set already in the kernel into this process's
// allocator, and reaps the entries that are dead.
//
// WHY THIS EXISTS. A restart that adopts a pinned data plane inherits every
// policy block and every kapkan_victims entry the previous process installed.
// Without reading them back, a fresh allocator would start at policy id 0 and
// hand it to the first new victim — on top of a block another victim's trie
// entry still points at. That could not produce a wrong DROP (every rule
// re-checks both prefixes, so the mispointed victim simply matches nothing and
// passes), but it would silently un-mitigate a live attack the restart was
// supposed to preserve. Reading them back also makes rehydration exact: the
// mitigator re-installs the same victims, and each lands on the block it
// already owned.
//
// WHAT IT REAPS: an entry whose block is empty, or whose every rule is past its
// in-kernel deadline. Those are the previous process's bans that lapsed during
// the downtime — the datapath already treats them as absent, so removing them
// changes no verdict, and it returns their slots instead of leaking them for
// the life of the process.
//
// WHAT IT DELIBERATELY DOES NOT DO: reap an entry whose rules are still live
// but which the mitigator has no persisted ban for. Those rules keep enforcing
// until their own deadline, which is the S2 fail-safe working as intended — and
// if the reason there is no ban is that the target is now in
// protected_whitelist, the manager has already mirrored that list into
// kapkan_protect4/6, which is precedence 2 and stops evaluation before any
// dynamic rule is read.
func (i *Installer) adoptLocked(maps *Maps, gen uint32) error {
	if i.adopted {
		return nil
	}
	i.stride = PolicyStride(maps)
	if i.stride == 0 {
		return fmt.Errorf("dataplane: policy stride is 0; the map set is not sized")
	}

	entries, err := victimEntries(maps)
	if err != nil {
		return err
	}
	now := i.bootNs()
	var live, reaped int
	for _, e := range entries {
		var block PolicyBlock
		if err := maps.KapkanPolicies.Lookup(gen*i.stride+e.policyID, &block); err != nil {
			// An id past the stride, or an unreadable block. Keep the slot
			// marked taken (safe: nothing else may reuse it) and move on.
			i.takenPolicy[e.policyID] = true
			continue
		}
		if blockIsDead(block, now) {
			if err := DeleteVictim(maps, e.prefix); err != nil {
				i.log.Error("reaping an expired adopted victim failed", "victim", e.prefix.String(), "err", err)
				i.takenPolicy[e.policyID] = true
				continue
			}
			if err := PutPolicy(maps, gen, e.policyID, nil); err != nil {
				i.log.Error("clearing an expired adopted policy block failed",
					"victim", e.prefix.String(), "policy_id", e.policyID, "err", err)
			}
			reaped++
			continue
		}
		i.policyOf[e.prefix] = e.policyID
		i.takenPolicy[e.policyID] = true
		live++
	}
	i.adopted = true
	if live > 0 || reaped > 0 {
		i.log.Warn("adopted the previous process's dynamic rules",
			"live_victims", live, "reaped_expired", reaped, "policy_stride", i.stride)
	}
	return nil
}

// blockIsDead reports whether a policy block would produce no match at all: no
// rules, or every rule already past its boot-clock deadline. A zero nowNs means
// the boot clock could not be read, in which case nothing is called dead —
// guessing here would delete rules that are still enforcing.
func blockIsDead(b PolicyBlock, nowNs uint64) bool {
	n := b.N_rules
	if n == 0 {
		return true
	}
	if nowNs == 0 {
		return false
	}
	if n > RulesPerPolicy {
		n = RulesPerPolicy
	}
	for _, r := range b.Rules[:n] {
		if r.Flags&RuleValid == 0 {
			continue
		}
		if r.ExpiresAtNs == 0 || r.ExpiresAtNs > nowNs {
			return false
		}
	}
	return true
}

// victimEntry is one kapkan_victims row: a prefix and the policy block it names.
type victimEntry struct {
	prefix   netip.Prefix
	policyID uint32
}

// victimEntries dumps both victim tries. Unlike trieEntries next door it keeps
// the VALUE, which for these maps is the policy id and is the whole point.
func victimEntries(m *Maps) ([]victimEntry, error) {
	var out []victimEntry
	var id uint32

	var k4 LPMKeyV4
	it := m.KapkanVictims4.Iterate()
	for it.Next(&k4, &id) {
		out = append(out, victimEntry{
			prefix:   netip.PrefixFrom(netip.AddrFrom4(k4.Addr), int(k4.Prefixlen)),
			policyID: id,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("dataplane: dump kapkan_victims4: %w", err)
	}

	var k6 LPMKeyV6
	it = m.KapkanVictims6.Iterate()
	for it.Next(&k6, &id) {
		out = append(out, victimEntry{
			prefix:   netip.PrefixFrom(netip.AddrFrom16(k6.Addr), int(k6.Prefixlen)),
			policyID: id,
		})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("dataplane: dump kapkan_victims6: %w", err)
	}
	return out, nil
}

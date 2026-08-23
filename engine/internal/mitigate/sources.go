package mitigate

// Operator/API-initiated source blocks — the enforcement half of
// POST /api/v1/dataplane/sources.
//
// A source block is a TTL'd "drop source → victim" pair that whoever already
// terminates the traffic (an nginx in front of the victim, a log exporter, an
// operator at 3am) asks Kapkan to execute. It is the edge charter working as
// designed: the decision is made elsewhere, Kapkan enforces it at the cheapest
// layer that can express it, which is the XDP data plane.
//
// ANCHORED AT THE SOURCE, NOT THE VICTIM — this is the load-bearing choice.
// The kernel's victims trie is consulted on BOTH ends of the packet (see
// kapkan_xdp.c: the src lookup is precedence 4, the dst lookup 5), so a block
// installs as its own policy whose anchor prefix is the attacker /32-/128:
//
//	Install(source/32, [{Src: source, Dst: victim, Action: discard}, ...])
//
// Anchoring at the victim instead would collide with the ban machinery, which
// keys every policy block by the victim prefix: a source block and an active
// dataplane-rung ban for the same victim would silently replace each other's
// rules on every install, withdraw and TTL renewal. With the source as the
// anchor the two tables cannot meet — a ban's anchor is always a victim inside
// `networks` (ban() enforces InNetworks), and BlockSource refuses any source
// inside `networks` — so neither lifecycle needs to know the other exists.
//
// One source's pairs share one policy block, so one source can be blocked for
// at most dataplane.RulesPerPolicy victims at a time. Each pair carries its
// own TTL into the kernel (RuleSpec.TTL), so a pair expires exactly on
// schedule even if this process dies — the same fail-safe bans rely on.
//
// The ban guarantees hold unabridged: a TTL is mandatory and bounded (no
// permanent entries), installs are accounted against max_dynamic_rules (each
// blocked source consumes one policy slot), dry-run is honoured (the pair is
// recorded and reported, nothing reaches a map), and the API writes one audit
// event per call. Refusals are loud: a source the datapath would pass anyway
// (dataplane.allowlist), a victim the datapath refuses to filter
// (protected_whitelist passes its traffic at precedence 2, before any rule),
// and an absent data plane are all errors, never silent acceptance.

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// SourceBlock is one live source→victim drop pair.
type SourceBlock struct {
	// Source is the blocked address; the pair's policy anchors at its /32-/128.
	Source netip.Addr `json:"source"`
	// Victim is the protected destination the drop is scoped to.
	Victim netip.Addr `json:"victim"`
	// CreatedAt is when the pair was first installed; a refresh keeps it.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the wall-clock deadline. The kernel holds its own on the
	// boot clock, so the pair dies on time even with no userspace alive.
	ExpiresAt time.Time `json:"expires_at"`
	// DryRun is the config's dry-run flag frozen at creation, exactly as a
	// ban freezes it: a dry-run pair is recorded and audited, installs nothing.
	DryRun bool `json:"dry_run"`
	// Auto is true when the fingerprint plane installed this block (a JA4 match)
	// rather than an operator/API caller. Its anchor is budgeted separately so an
	// attacker-craftable, spoofable trigger cannot starve operator source blocks.
	Auto bool `json:"auto,omitempty"`
	// Reason is the caller's note, carried into the audit trail.
	Reason string `json:"reason,omitempty"`
}

// TTL bounds for a source block. The floor rejects degenerate calls; the
// ceiling is what makes "no permanent entries" true against a caller that
// refreshes nothing — a mistaken block heals itself within a day even if
// nobody notices it. Long-lived blocks are refreshes, not long TTLs.
const (
	MinSourceBlockTTL = time.Second
	MaxSourceBlockTTL = 24 * time.Hour
)

// ErrSourceBlockInput marks input-class refusals — the caller's request is
// malformed (API: 400), as opposed to well-formed and refused by policy.
var ErrSourceBlockInput = errors.New("invalid source block")

// Policy-class refusals (well-formed, refused by policy — API: 409). Each is
// its own value so tests and the API can tell them apart; all of them are
// counted on kapkan_mitigate_source_blocks_rejected_total.
var (
	ErrDataplaneAbsent = errors.New(
		"no data plane: the dataplane block is absent, disabled, or this build cannot attach one")
	ErrVictimProtected = errors.New(
		"victim is in protected_whitelist: the datapath passes its traffic before any rule, so the block would never match")
	ErrSourceAllowlisted = errors.New(
		"source is in dataplane.allowlist: the datapath passes it before any rule, so the block would never match")
	ErrSourceInNetworks = errors.New(
		"source is inside the protected networks: block outside sources here; an internal host is a ban, not a source block")
	ErrSourceVictimsFull = errors.New(
		"this source's policy block is full: one source can be blocked for at most 8 victims at a time")
	ErrSourceSlotsFull = errors.New(
		"no policy slots left for source blocks: slots are shared with bans and every ban must keep " +
			"its own; raise dataplane.limits.max_dynamic_rules or wait for blocks to expire")
	ErrFingerprintBlocksFull = errors.New(
		"the fingerprint plane's source-block budget is full: it is capped at half the anchor budget so " +
			"a spoofed crafted-JA4 flood cannot starve operator/API source blocks; existing fp blocks " +
			"age out on their TTL")
)

// ErrSourceBlockNotFound is UnblockSource's miss (API: 404).
var ErrSourceBlockNotFound = errors.New("no such source block")

// BlockSource installs (or refreshes) an OPERATOR/API source→victim drop pair
// with the given TTL. A pair that already exists keeps its CreatedAt and takes
// the new TTL and reason — the refresh contract an exporter needs to keep a
// persistent offender blocked without unblock/re-block churn.
func (m *Mitigator) BlockSource(victim, source netip.Addr, ttl time.Duration, reason string) (*SourceBlock, error) {
	return m.blockSource(victim, source, ttl, reason, false)
}

// BlockSourceFingerprint is BlockSource for the fingerprint plane (a JA4 match).
// Its anchor draws from a SEPARATE, smaller budget (fpSourceAnchorBudget, half
// the pool) so that a spoofable, attacker-craftable JA4 trigger cannot fill the
// shared anchor budget and starve operator/API source blocks.
func (m *Mitigator) BlockSourceFingerprint(victim, source netip.Addr, ttl time.Duration, reason string) (*SourceBlock, error) {
	return m.blockSource(victim, source, ttl, reason, true)
}

func (m *Mitigator) blockSource(victim, source netip.Addr, ttl time.Duration, reason string, auto bool) (*SourceBlock, error) {
	victim, source = victim.Unmap(), source.Unmap()
	if !victim.IsValid() || !source.IsValid() {
		return nil, fmt.Errorf("%w: victim and source must both be valid addresses", ErrSourceBlockInput)
	}
	if victim.Is4() != source.Is4() {
		return nil, fmt.Errorf("%w: victim %s and source %s are different address families",
			ErrSourceBlockInput, victim, source)
	}
	if ttl < MinSourceBlockTTL || ttl > MaxSourceBlockTTL {
		return nil, fmt.Errorf("%w: ttl must be within [%s, %s], got %s",
			ErrSourceBlockInput, MinSourceBlockTTL, MaxSourceBlockTTL, ttl)
	}

	cfg := m.store.Get()
	if err := m.sourceBlockPolicy(cfg, victim, source); err != nil {
		rejectSourceBlock(rejectReason(err))
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	pairs := m.sourceBlocks[source]
	old := pairs[victim]
	if old == nil && len(pairs) >= maxRulesPerAttack {
		rejectSourceBlock("victims_full")
		return nil, ErrSourceVictimsFull
	}
	// A NEW anchor claims a policy slot from the pool bans draw on, and the
	// config only sizes that pool for bans (max_active_bans*8 must fit). Cap
	// distinct sources at what is left after every ban — host and carpet —
	// could claim its slot, so a burst of blocks can never starve a ban into
	// its blackhole fallback. Enforced in dry-run too: it is also what bounds
	// this table and the state file.
	if pairs == nil && len(m.sourceBlocks) >= sourceAnchorBudget(cfg) {
		rejectSourceBlock("slots_full")
		return nil, ErrSourceSlotsFull
	}
	// A NEW fingerprint anchor is additionally capped at fpSourceAnchorBudget
	// (half the pool), the reservation that keeps a spoofed crafted-JA4 flood
	// from consuming every slot and starving operator blocks. Only a new anchor
	// is checked: adding a victim to an existing fp anchor consumes no new slot.
	if auto && pairs == nil && len(m.fpAnchors) >= fpSourceAnchorBudget(cfg) {
		rejectSourceBlock("fp_budget_full")
		return nil, ErrFingerprintBlocksFull
	}

	sb := &SourceBlock{
		Source:    source,
		Victim:    victim,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		DryRun:    cfg.DryRun,
		Auto:      auto,
		Reason:    reason,
	}
	if old != nil {
		sb.CreatedAt = old.CreatedAt
	}
	if pairs == nil {
		pairs = make(map[netip.Addr]*SourceBlock)
		m.sourceBlocks[source] = pairs
		if auto {
			// Attribute the anchor to the fingerprint plane for the separate
			// budget. Keyed by source and set once at creation, so a later block
			// of any origin on this anchor never changes its attribution.
			m.fpAnchors[source] = struct{}{}
		}
	}
	pairs[victim] = sb

	if err := m.reinstallSourceLocked(source, now); err != nil {
		// reinstallSourceLocked has already DROPPED this source's pairs — the
		// installer's rollback wipes the anchor's kernel state on any failure,
		// previous rules included, and a recorded-but-unenforced pair is the
		// one state this table must never hold. Restoring the old pairs here
		// would restore exactly that lie. The error says so, loudly.
		m.updateSourceGaugeLocked()
		m.markDirty()
		rejectSourceBlock("install_failed")
		return nil, fmt.Errorf("install source block %s -> %s: %w "+
			"(every pair for this source is withdrawn; re-add the ones you need)",
			source, victim, err)
	}

	if sb.DryRun {
		m.log.Warn("DRY-RUN: would block source (not installed)",
			"source", source.String(), "victim", victim.String(), "ttl", ttl.Round(time.Second).String())
	} else {
		m.log.Info("source block installed",
			"source", source.String(), "victim", victim.String(),
			"ttl", ttl.Round(time.Second).String(), "refresh", old != nil)
	}
	m.updateSourceGaugeLocked()
	m.markDirty()
	out := *sb
	return &out, nil
}

// UnblockSource removes one pair immediately — the operator's undo for a
// mistaken block, so nobody waits out a TTL they typed themselves.
func (m *Mitigator) UnblockSource(victim, source netip.Addr) (*SourceBlock, error) {
	victim, source = victim.Unmap(), source.Unmap()

	m.mu.Lock()
	defer m.mu.Unlock()

	pairs := m.sourceBlocks[source]
	sb := pairs[victim]
	if sb == nil {
		return nil, fmt.Errorf("%w: %s -> %s", ErrSourceBlockNotFound, source, victim)
	}
	delete(pairs, victim)
	if len(pairs) == 0 {
		delete(m.sourceBlocks, source)
		delete(m.fpAnchors, source)
	}
	// Reinstall whatever remains for this source (or withdraw its policy when
	// nothing does). A failure cannot resurrect the removed pair — the
	// operator asked for the block to END — and reinstallSourceLocked's
	// invariant handles the remainder: pairs it could not keep enforced are
	// dropped rather than left recorded as a lie.
	_ = m.reinstallSourceLocked(source, m.now())
	m.log.Info("source block removed", "source", source.String(), "victim", victim.String())
	m.updateSourceGaugeLocked()
	m.markDirty()
	out := *sb
	return &out, nil
}

// SourceBlocks returns the live pairs, sorted (source, then victim) — the
// stable order the API, tests and the state file all want.
func (m *Mitigator) SourceBlocks() []SourceBlock {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sourceBlocksLocked()
}

func (m *Mitigator) sourceBlocksLocked() []SourceBlock {
	out := make([]SourceBlock, 0, len(m.sourceBlocks))
	for _, pairs := range m.sourceBlocks {
		for _, sb := range pairs {
			out = append(out, *sb)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source.Less(out[j].Source)
		}
		return out[i].Victim.Less(out[j].Victim)
	})
	return out
}

// sourceBlockPolicy holds every policy refusal in one place so BlockSource,
// the sweep and rehydration cannot drift apart on what is blockable. Pure —
// the rejection counter belongs to the operator-facing call, not to a
// rehydration quietly dropping a stale entry.
func (m *Mitigator) sourceBlockPolicy(cfg *config.Config, victim, source netip.Addr) error {
	if m.dp == nil || !cfg.DataplaneCfg.Enabled {
		return ErrDataplaneAbsent
	}
	if cfg.IsWhitelisted(victim) {
		return ErrVictimProtected
	}
	if cfg.DataplaneAllowlistContains(source) {
		return ErrSourceAllowlisted
	}
	if cfg.InNetworks(source) {
		return ErrSourceInNetworks
	}
	return nil
}

// rejectReason maps a policy refusal onto its counter label.
func rejectReason(err error) string {
	switch {
	case errors.Is(err, ErrDataplaneAbsent):
		return "no_dataplane"
	case errors.Is(err, ErrVictimProtected):
		return "victim_protected"
	case errors.Is(err, ErrSourceAllowlisted):
		return "source_allowlisted"
	case errors.Is(err, ErrSourceInNetworks):
		return "source_in_networks"
	}
	return "other"
}

// sourceAnchorBudget is how many distinct sources may hold policy slots.
// The pool is shared with bans and sized only for them (config validates
// ban.max_active_bans*8 against max_dynamic_rules), so source anchors get
// what is left after every ban — host and carpet — could claim its slot.
func sourceAnchorBudget(cfg *config.Config) int {
	budget := cfg.DataplaneCfg.MaxDynamicRules/dataplane.RulesPerPolicy - cfg.Ban.MaxActiveBans
	if cfg.Carpet != nil {
		budget -= cfg.Carpet.MaxActivePrefixBans
	}
	return budget
}

// fpSourceAnchorBudget caps how many distinct sources the FINGERPRINT plane may
// block, at HALF the shared anchor budget. That reservation is what guarantees
// operator/API source blocks always have the other half: the fp trigger is a
// stateless, spoofable, attacker-craftable JA4 match (a single spoofed packet
// with a crafted ClientHello suffices), so its blocks must never be able to
// consume the whole pool. Floors at 0 — on a budget too small to split, fp gets
// no anchors rather than crowding out the operator's.
func fpSourceAnchorBudget(cfg *config.Config) int {
	if half := sourceAnchorBudget(cfg) / 2; half > 0 {
		return half
	}
	return 0
}

// reinstallSourceLocked makes the kernel match this source's live pairs: one
// policy block anchored at the source, one rule per non-dry-run pair, each
// with its own remaining TTL. No live pairs means withdrawing the policy.
//
// THE INVARIANT THIS FUNCTION OWNS: after it returns, the table and the
// kernel agree about this source. The installer's rollback is all-or-nothing
// INCLUDING rules a previous install left there, so a failed Install means
// the kernel now enforces nothing for this anchor — and the only honest
// response is to drop the source's pairs and say so, loudly. A pair the
// table reports as blocked while the kernel forwards its traffic is the
// exact lie the ban machinery's fallback ladder exists to prevent; source
// blocks have no weaker rung to fall back to, so they fall to the floor.
func (m *Mitigator) reinstallSourceLocked(source netip.Addr, now time.Time) error {
	anchor := hostPrefix(source)

	type live struct {
		victim netip.Addr
		ttl    time.Duration
	}
	var lives []live
	for victim, sb := range m.sourceBlocks[source] {
		if sb.DryRun {
			continue
		}
		if ttl := sb.ExpiresAt.Sub(now); ttl > 0 {
			lives = append(lives, live{victim, ttl})
		}
	}
	if len(lives) == 0 {
		// Withdraw only what was actually installed: a source whose pairs are
		// all dry-run has never touched a map and must not start now.
		if m.dp == nil || !m.sourceInstalled[source] {
			return nil
		}
		delete(m.sourceInstalled, source)
		if err := m.dp.Withdraw(anchor); err != nil {
			// Fail-open by construction: an unwithdrawn entry still dies on
			// its in-kernel deadline. Log and move on, exactly as ban
			// withdraws treat backend errors.
			m.log.Error("source-block withdraw failed; the kernel deadline will retire it",
				"source", source.String(), "err", err)
		}
		return nil
	}
	// Deterministic rule order (and therefore rule ids) so refreshes keep each
	// pair's kapkan_rule_stats counters exactly as reinstalls do for bans.
	sort.Slice(lives, func(i, j int) bool { return lives[i].victim.Less(lives[j].victim) })

	rules := make([]FlowSpecRule, len(lives))
	maxTTL := time.Duration(0)
	for i, l := range lives {
		rules[i] = FlowSpecRule{
			Dst:    hostPrefix(l.victim),
			Src:    anchor,
			Action: config.FlowSpecDiscard,
		}
		if l.ttl > maxTTL {
			maxTTL = l.ttl
		}
	}
	set, err := dataplaneRules(rules, maxTTL)
	if err != nil {
		return m.dropSourceLocked(source, err)
	}
	for i, l := range lives {
		set.Specs[i].TTL = l.ttl
	}
	if err := m.dp.Install(anchor, set); err != nil {
		return m.dropSourceLocked(source, err)
	}
	m.sourceInstalled[source] = true
	return nil
}

// dropSourceLocked implements reinstallSourceLocked's failure half: the
// kernel holds nothing for this anchor (the installer rolled everything
// back), so the table must not claim otherwise. Gauge and persistence are the
// caller's job — every caller already updates both on change.
func (m *Mitigator) dropSourceLocked(source netip.Addr, cause error) error {
	n := len(m.sourceBlocks[source])
	delete(m.sourceBlocks, source)
	delete(m.sourceInstalled, source)
	delete(m.fpAnchors, source)
	m.log.Error("source blocks dropped: the kernel could not be made to match the table",
		"source", source.String(), "pairs_dropped", n, "err", cause)
	return cause
}

// sweepSourceBlocksLocked retires expired pairs and takes down pairs a config
// reload has made unenforceable or forbidden — the same promptness the ban
// sweep gives the whitelist ("absolute" means "within a tick", not "until the
// TTL happens to lapse").
func (m *Mitigator) sweepSourceBlocksLocked(now time.Time, cfg *config.Config) {
	changed := false
	for source, pairs := range m.sourceBlocks {
		dirty := false
		for victim, sb := range pairs {
			why := ""
			switch {
			case now.After(sb.ExpiresAt):
				why = "ttl expired"
			case cfg.IsWhitelisted(victim):
				why = "victim now in protected_whitelist"
			case cfg.DataplaneAllowlistContains(source):
				why = "source now in dataplane.allowlist"
			case cfg.InNetworks(source):
				// The anchor-disjointness invariant: a ban's anchor is always
				// a victim inside networks, a block's never is. A reload that
				// onboards the source's range would let a ban for that very
				// address claim the same trie key and the two lifecycles
				// would silently clobber each other's rules — so the block
				// goes, promptly, exactly as the ban sweep retires targets
				// that LEFT networks.
				why = "source now inside protected networks"
			case m.dp == nil || !cfg.DataplaneCfg.Enabled:
				why = "data plane no longer available"
			}
			if why == "" {
				continue
			}
			m.log.Info("source block retired", "source", source.String(),
				"victim", victim.String(), "reason", why)
			delete(pairs, victim)
			dirty = true
		}
		if !dirty {
			continue
		}
		if len(pairs) == 0 {
			delete(m.sourceBlocks, source)
			delete(m.fpAnchors, source)
		}
		// A reinstall failure drops the source's remaining pairs and logs —
		// reinstallSourceLocked's invariant; changed already covers the gauge.
		_ = m.reinstallSourceLocked(source, now)
		changed = true
	}
	if changed {
		m.updateSourceGaugeLocked()
		m.markDirty()
	}
}

func (m *Mitigator) updateSourceGaugeLocked() {
	real, dry := 0, 0
	for _, pairs := range m.sourceBlocks {
		for _, sb := range pairs {
			if sb.DryRun {
				dry++
			} else {
				real++
			}
		}
	}
	// Both buckets always Set, never left stale — the house gauge convention.
	metrics.MitigateSourceBlocks.WithLabelValues("real").Set(float64(real))
	metrics.MitigateSourceBlocks.WithLabelValues("dry_run").Set(float64(dry))
}

func rejectSourceBlock(reason string) {
	metrics.MitigateSourceBlocksRejected.WithLabelValues(reason).Inc()
}

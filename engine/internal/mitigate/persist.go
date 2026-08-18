package mitigate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
)

// Ban persistence. Active bans live only in memory, so a restart would otherwise
// lose them: paired with BGP Graceful Restart (which has the peer hold the
// routes as stale across the session gap), persisting and re-announcing them on
// startup BEFORE the speaker's End-of-RIB is what actually keeps mitigation up
// across an upgrade — a stock GR helper purges any retained route the
// reconnecting instance does not re-advertise.
//
// The state is a single JSON file rewritten atomically on every ban change
// (bans are bounded by the caps, so a full-snapshot-on-change is cheap). It is
// best-effort: a missing/corrupt/unwritable file never fails startup or a ban
// operation — it just means no rehydration.

const persistVersion = 1

// attrs and the unexported ban fields are deliberately NOT serialized: the
// frozen BGP attribute sets are recomputed from the CURRENT config on rehydrate
// (so an operator's config edit during downtime takes effect, and the persisted
// format stays free of internal types). The route NLRI — a host /32-/128 or the
// FlowSpec rules — is what must match to refresh a retained stale route, and
// that is fully captured by Prefix and FlowSpec below.
type banSnapshot struct {
	Target         netip.Addr               `json:"target"`
	Prefix         netip.Prefix             `json:"prefix"`
	Metric         engine.Metric            `json:"metric,omitempty"`
	Rate           float64                  `json:"rate,omitempty"`
	Threshold      float64                  `json:"threshold,omitempty"`
	StartedAt      time.Time                `json:"started_at"`
	ExpiresAt      time.Time                `json:"expires_at"`
	Manual         bool                     `json:"manual,omitempty"`
	DryRun         bool                     `json:"dry_run,omitempty"`
	Method         config.MitigationMethod  `json:"method"`
	FlowSpec       []FlowSpecRule           `json:"flowspec,omitempty"`
	Escalation     []config.EscalationStage `json:"escalation,omitempty"`
	EscalationStep int                      `json:"escalation_step"`
	FellBackFrom   config.MitigationMethod  `json:"fell_back_from,omitempty"`
	FellBackReason string                   `json:"fell_back_reason,omitempty"`
	// Node is the frozen scrubbing-node choice, persisted so a brain restart
	// does not shuffle victims between nodes: rehydration KEEPS this node when
	// it is still configured and eligible, and re-selects only when it is gone.
	// omitempty, version unchanged — an old kapkan ignores it, and a pre-nodes
	// file simply re-selects, which is what it would have done anyway.
	Node string `json:"node,omitempty"`

	// The data-plane measurement, persisted as the LIFETIME TOTALS ONLY and not
	// as the BanDataplane object.
	//
	// What must survive a restart is the running count, because nothing else
	// can reconstruct it: kapkan_rule_stats is zeroed by the next install, and a
	// restart that could not adopt the pins has no counters at all. What must
	// NOT survive is everything describing the kernel's current state —
	// policy_id, measured_at, stale. Those are claims about map contents that no
	// one has verified since the process died, and rehydrating them would put a
	// timestamp on the API that says a measurement happened when none did. They
	// come back on the first scrape, one interval later.
	//
	// Every field is omitempty and the document version is UNCHANGED: load()
	// hard-fails on a version mismatch, so bumping it would discard every live
	// ban on upgrade — the exact mitigation gap the state file exists to close.
	// An old kapkan reading a new file ignores these keys; a new kapkan reading
	// an old file reads zeros, which is the correct starting total.
	DataplanePackets uint64             `json:"dataplane_packets,omitempty"`
	DataplaneBytes   uint64             `json:"dataplane_bytes,omitempty"`
	DataplaneRules   []BanDataplaneRule `json:"dataplane_rules,omitempty"`
}

// persistState is the on-disk document.
//
// SourceBlocks joined at version 1 UNBUMPED, by the same reasoning as the
// dataplane totals above: load() hard-fails on a version mismatch, an old
// kapkan ignores the unknown key, and a new kapkan reading an old file simply
// rehydrates no source blocks — which is what that file says.
type persistState struct {
	Version      int                   `json:"version"`
	SavedAt      time.Time             `json:"saved_at"`
	HostBans     []banSnapshot         `json:"host_bans,omitempty"`
	PrefixBans   []banSnapshot         `json:"prefix_bans,omitempty"`
	SourceBlocks []sourceBlockSnapshot `json:"source_blocks,omitempty"`
}

// sourceBlockSnapshot persists one source→victim pair. It is the SourceBlock
// fields verbatim — the pair IS its own description, there is no frozen
// attribute set to recompute — but kept a separate type so the API shape and
// the on-disk shape can drift apart without either noticing the other.
type sourceBlockSnapshot struct {
	Source    netip.Addr `json:"source"`
	Victim    netip.Addr `json:"victim"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	DryRun    bool       `json:"dry_run,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

func toSnapshot(b *Ban) banSnapshot {
	s := snapshotCore(b)
	if b.Dataplane != nil {
		s.DataplanePackets = b.Dataplane.Packets
		s.DataplaneBytes = b.Dataplane.Bytes
		s.DataplaneRules = b.Dataplane.Rules
	}
	return s
}

func snapshotCore(b *Ban) banSnapshot {
	return banSnapshot{
		Target:         b.Target,
		Prefix:         b.Prefix,
		Metric:         b.Metric,
		Rate:           b.Rate,
		Threshold:      b.Threshold,
		StartedAt:      b.StartedAt,
		ExpiresAt:      b.ExpiresAt,
		Manual:         b.Manual,
		DryRun:         b.DryRun,
		Method:         b.Method,
		FlowSpec:       b.FlowSpec,
		Escalation:     b.Escalation,
		EscalationStep: b.EscalationStep,
		FellBackFrom:   b.FellBackFrom,
		FellBackReason: b.FellBackReason,
		Node:           b.Node,
	}
}

// banPersistor reads and writes the state file. Writes are serialized by mu and
// atomic (write a temp file in the same directory, fsync, rename over).
type banPersistor struct {
	path string
}

func (p *banPersistor) load() (persistState, error) {
	var st persistState
	b, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil // first run / no prior state — not an error
		}
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return persistState{}, fmt.Errorf("parse %s: %w", p.path, err)
	}
	if st.Version != persistVersion {
		return persistState{}, fmt.Errorf("state file %s has version %d, want %d", p.path, st.Version, persistVersion)
	}
	return st, nil
}

func (p *banPersistor) save(st persistState) error {
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.path), ".bans-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p.path)
}

// snapshotLocked builds the on-disk document from the currently ACTIVE bans.
// Sorted for a stable file (deterministic, diffable, no churn from map order).
// The caller holds m.mu.
func (m *Mitigator) snapshotLocked() persistState {
	st := persistState{Version: persistVersion, SavedAt: m.now()}
	for _, b := range m.bans {
		if b.State == BanActive {
			st.HostBans = append(st.HostBans, toSnapshot(b))
		}
	}
	for _, b := range m.prefixBans {
		if b.State == BanActive {
			st.PrefixBans = append(st.PrefixBans, toSnapshot(b))
		}
	}
	for _, sb := range m.sourceBlocksLocked() {
		// A type CONVERSION on purpose: the day the API shape and the on-disk
		// shape drift apart, this line stops compiling and the writer decides
		// the mapping consciously instead of a field going quietly stale.
		st.SourceBlocks = append(st.SourceBlocks, sourceBlockSnapshot(sb))
	}
	sort.Slice(st.HostBans, func(i, j int) bool { return st.HostBans[i].Target.Less(st.HostBans[j].Target) })
	sort.Slice(st.PrefixBans, func(i, j int) bool { return st.PrefixBans[i].Prefix.String() < st.PrefixBans[j].Prefix.String() })
	return st
}

// markDirty signals both consumers of "the ban table changed": the persist
// loop (below) and the long-poll waiters behind RulesChanged (a scrub node
// holding GET /api/v1/dataplane/rules). One signal point on purpose — anything
// worth writing to the state file is exactly what a scrub node must hear about,
// and a future mutation that calls markDirty gets both behaviors for free.
// Non-blocking; every caller is a ban mutation already holding m.mu (which
// notifyRulesLocked requires). Persist writes coalesce: a full pending signal
// means a write is already queued, which will capture the latest state.
func (m *Mitigator) markDirty() {
	m.notifyRulesLocked()
	if m.persist == nil {
		return
	}
	select {
	case m.dirty <- struct{}{}:
	default:
	}
}

// persistLoop owns the state-file writes during normal operation, coalescing
// bursts of ban changes into one write each. flushPersist handles the final,
// synchronous write on shutdown (the loop's ctx is already cancelled by then).
func (m *Mitigator) persistLoop(ctx context.Context) {
	defer close(m.persistDone)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.dirty:
			m.flushPersist()
		}
	}
}

// flushPersist writes the current active-ban set to disk synchronously. Called
// from persistLoop on each change and directly on shutdown so the latest state
// reaches disk before the process exits. Best-effort: a write error is logged,
// never fatal.
func (m *Mitigator) flushPersist() {
	if m.persist == nil {
		return
	}
	// Hold persistMu across BOTH the snapshot and the save so concurrent flushes
	// fully serialize and an older snapshot can never clobber a newer one
	// (snapshot order == save order). persistMu is never taken under m.mu, so
	// this introduces no lock inversion.
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	st := m.snapshotLocked()
	m.mu.Unlock()
	if err := m.persist.save(st); err != nil {
		m.log.Error("persisting ban state failed; rehydration on next restart may be incomplete",
			"path", m.persist.path, "err", err)
	}
}

// drainPersist stops the persist loop and writes the final active-ban set
// synchronously, making that flush the sole, last writer so no concurrent loop
// flush can reorder behind it (and no final change is lost to the loop's
// ctx-vs-dirty select). The caller has already cancelled m.ctx, which both stops
// the sweeper (no further ban mutations) and ends persistLoop. No-op when
// persistence is disabled or was never started.
func (m *Mitigator) drainPersist() {
	if m.persist == nil {
		return
	}
	if m.persistDone != nil {
		<-m.persistDone // persistLoop has observed the cancelled ctx and exited
	}
	m.flushPersist()
}

// rehydrateLocked loads persisted bans and re-announces those that are still
// valid, BEFORE the speaker's End-of-RIB, so a GR helper refreshes the routes it
// retained across the restart instead of purging them. Each ban is re-validated
// against the CURRENT config: a now-whitelisted target, a target outside the
// (possibly shrunk) networks, an expired TTL, or a tightened cap all drop it —
// the persisted set is never trusted to override a live safety rule. The caller
// holds m.mu and m.ctx is set.
func (m *Mitigator) rehydrateLocked(cfg *config.Config) {
	if m.persist == nil {
		return
	}
	st, err := m.persist.load()
	if err != nil {
		m.log.Error("loading persisted ban state failed; starting with no rehydrated bans",
			"path", m.persist.path, "err", err)
		return
	}
	if len(st.HostBans) == 0 && len(st.PrefixBans) == 0 && len(st.SourceBlocks) == 0 {
		return
	}
	now := m.now()
	var host, prefix, blocks, dropped int
	for _, s := range st.HostBans {
		if m.rehydrateHostLocked(s, cfg, now) {
			host++
		} else {
			dropped++
		}
	}
	for _, s := range st.PrefixBans {
		if m.rehydratePrefixLocked(s, cfg, now) {
			prefix++
		} else {
			dropped++
		}
	}
	for _, s := range st.SourceBlocks {
		if m.rehydrateSourceBlockLocked(s, cfg, now) {
			blocks++
		} else {
			dropped++
		}
	}
	// One install per restored source, after its pairs are all back — the
	// per-pair loop above only rebuilds the table.
	for source := range m.sourceBlocks {
		if err := m.reinstallSourceLocked(source, now); err != nil {
			m.log.Error("reinstalling rehydrated source blocks failed",
				"source", source.String(), "err", err)
		}
	}
	m.updateGaugeLocked()
	m.updateSourceGaugeLocked()
	m.log.Warn("rehydrated active bans across restart",
		"host_bans", host, "prefix_bans", prefix, "source_blocks", blocks,
		"dropped", dropped, "saved_at", st.SavedAt)
}

// rehydrateSourceBlockLocked validates and restores one persisted source
// block, returning whether it survived. Validation mirrors BlockSource against
// the CURRENT config — the persisted set never overrides a live safety rule —
// plus the TTL check every rehydration does. The caller holds m.mu and
// reinstalls per source afterwards.
func (m *Mitigator) rehydrateSourceBlockLocked(s sourceBlockSnapshot, cfg *config.Config, now time.Time) bool {
	source, victim := s.Source.Unmap(), s.Victim.Unmap()
	if !source.IsValid() || !victim.IsValid() || victim.Is4() != source.Is4() {
		return false
	}
	if now.After(s.ExpiresAt) {
		m.log.Info("not rehydrating source block; TTL elapsed during downtime",
			"source", source.String(), "victim", victim.String())
		return false
	}
	if err := m.sourceBlockPolicy(cfg, victim, source); err != nil {
		m.log.Warn("not rehydrating source block; refused by current config",
			"source", source.String(), "victim", victim.String(), "reason", err)
		return false
	}
	pairs := m.sourceBlocks[source]
	if pairs == nil {
		pairs = make(map[netip.Addr]*SourceBlock)
		m.sourceBlocks[source] = pairs
	} else if pairs[victim] == nil && len(pairs) >= maxRulesPerAttack {
		// Cannot happen from our own snapshot, but the file is just a file.
		m.log.Warn("not rehydrating source block; policy block full",
			"source", source.String(), "victim", victim.String())
		return false
	}
	pairs[victim] = &SourceBlock{
		Source:    source,
		Victim:    victim,
		CreatedAt: s.CreatedAt,
		ExpiresAt: s.ExpiresAt,
		// Reconciled with the CURRENT config, exactly as ban rehydration does
		// (see rehydrateHostLocked): the reinstall below is what enforces, and
		// it honours this flag — a dry_run flip during downtime must win.
		DryRun: cfg.DryRun,
		Reason: s.Reason,
	}
	return true
}

// rehydrateHostLocked validates and re-announces one persisted host ban,
// returning whether it was restored. The caller holds m.mu.
func (m *Mitigator) rehydrateHostLocked(s banSnapshot, cfg *config.Config, now time.Time) bool {
	target := s.Target
	if !target.IsValid() {
		return false
	}
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		m.log.Info("not rehydrating ban; TTL elapsed during downtime", "target", target.String())
		return false
	}
	// SAFETY: never re-announce a now-whitelisted or out-of-networks target.
	if cfg.IsWhitelisted(target) {
		m.log.Warn("not rehydrating ban; target is now whitelisted", "target", target.String())
		return false
	}
	if !cfg.InNetworks(target) {
		m.log.Warn("not rehydrating ban; target is now outside configured networks", "target", target.String())
		return false
	}
	if m.activeCountLocked() >= cfg.Ban.MaxActiveBans {
		m.log.Warn("not rehydrating ban; max_active_bans reached", "target", target.String())
		return false
	}
	if !m.fractionAllowsLocked(cfg, target.Is6(), addressCountForPrefix(hostPrefix(target))) {
		m.log.Warn("not rehydrating ban; would exceed max_banned_fraction", "target", target.String())
		return false
	}
	b := banFromSnapshot(s, hostPrefix(target))
	if !validEscalationStep(b) {
		m.log.Warn("not rehydrating ban; persisted escalation step is out of range", "target", target.String())
		return false
	}
	// Reconcile dry-run with the CURRENT config, exactly as ban() does. The
	// announce below is gated on the live cfg.DryRun, and every future withdraw
	// is gated on this frozen flag — they must agree, or a dry_run flip across
	// the restart would either strand a real route (withdraws become no-ops) or
	// record a real ban that announced nothing.
	b.DryRun = cfg.DryRun
	m.freezeUnicastAttrs(b, cfg.GroupFor(target), target, cfg)
	if !m.reannounceLocked(b, cfg) {
		return false
	}
	m.bans[target] = b
	return true
}

// rehydratePrefixLocked validates and re-announces one persisted carpet ban.
func (m *Mitigator) rehydratePrefixLocked(s banSnapshot, cfg *config.Config, now time.Time) bool {
	p := s.Prefix
	if !p.IsValid() {
		return false
	}
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		m.log.Info("not rehydrating carpet ban; TTL elapsed during downtime", "prefix", p.String())
		return false
	}
	if cfg.PrefixContainsWhitelisted(p) {
		m.log.Warn("not rehydrating carpet ban; prefix now contains a whitelisted address", "prefix", p.String())
		return false
	}
	if !cfg.PrefixInNetworks(p) {
		m.log.Warn("not rehydrating carpet ban; prefix now outside configured networks", "prefix", p.String())
		return false
	}
	if m.activePrefixBansLocked() >= cfg.Carpet.MaxActivePrefixBans {
		m.log.Warn("not rehydrating carpet ban; max_active_prefix_bans reached", "prefix", p.String())
		return false
	}
	if !m.fractionAllowsLocked(cfg, p.Addr().Is6(), addressCountForPrefix(p)) {
		m.log.Warn("not rehydrating carpet ban; would exceed max_banned_fraction", "prefix", p.String())
		return false
	}
	b := banFromSnapshot(s, p)
	if !validEscalationStep(b) {
		m.log.Warn("not rehydrating carpet ban; persisted escalation step is out of range", "prefix", p.String())
		return false
	}
	b.DryRun = cfg.DryRun // reconcile with the live config (see rehydrateHostLocked)
	m.freezeUnicastAttrs(b, &cfg.Groups[0], p.Addr(), cfg)
	if !m.reannounceLocked(b, cfg) {
		return false
	}
	m.prefixBans[p] = b
	return true
}

// banFromSnapshot reconstructs an active *Ban from its persisted form. Frozen
// BGP attribute sets are filled in by the caller (freezeUnicastAttrs) from the
// current config; DryRun is reconciled with the live config by the caller; the
// route summary fields are set by reannounceLocked.
//
// dirMask is intentionally NOT carried across a restart: it tracks which live
// attack directions hold the ban, and a restarted process has no knowledge of
// which are still active (a direction that ended during downtime would otherwise
// pin the ban as a phantom hold until TTL). The rehydrated ban starts with no
// direction holds; the engine's re-detection re-establishes real holds via
// ban(), and the restored TTL remains the backstop.
func banFromSnapshot(s banSnapshot, prefix netip.Prefix) *Ban {
	b := banCoreFromSnapshot(s, prefix)
	// Restore the lifetime totals so the next scrape CONTINUES the count instead
	// of restarting it, and mark them stale immediately: nothing has been read
	// from a kernel map yet in this process, and a zero MeasuredAt would be
	// rendered as "measured at the epoch". The first successful scrape clears
	// the flag one interval later; a ban whose rules could not be reinstalled
	// keeps the last number the previous process saw, correctly flagged.
	if s.DataplanePackets != 0 || s.DataplaneBytes != 0 || len(s.DataplaneRules) != 0 {
		b.Dataplane = &BanDataplane{
			Packets: s.DataplanePackets,
			Bytes:   s.DataplaneBytes,
			Rules:   s.DataplaneRules,
			Stale:   true,
		}
	}
	return b
}

func banCoreFromSnapshot(s banSnapshot, prefix netip.Prefix) *Ban {
	return &Ban{
		Target:         s.Target,
		Prefix:         prefix,
		Metric:         s.Metric,
		Rate:           s.Rate,
		Threshold:      s.Threshold,
		State:          BanActive,
		DryRun:         s.DryRun,
		Manual:         s.Manual,
		StartedAt:      s.StartedAt,
		ExpiresAt:      s.ExpiresAt,
		Method:         s.Method,
		FlowSpec:       s.FlowSpec,
		Escalation:     s.Escalation,
		EscalationStep: s.EscalationStep,
		FellBackFrom:   s.FellBackFrom,
		FellBackReason: s.FellBackReason,
		// The rehydration PREFERENCE: freezeUnicastAttrs keeps this node when
		// still configured and eligible, re-selects otherwise.
		Node: s.Node,
	}
}

func validEscalationStep(b *Ban) bool {
	return len(b.Escalation) > 0 && b.EscalationStep >= 0 && b.EscalationStep < len(b.Escalation)
}

// reannounceLocked re-announces a rehydrated ban's CURRENT route (the same one
// it had before the restart), reusing the normal announce path so dry-run, the
// FlowSpec rule loop and route summaries all behave identically. It records the
// applied stage on the ban. On failure the ban is not restored. No fallback is
// attempted: the goal is to refresh the exact route the helper retained, not to
// pick a different method. The caller holds m.mu.
func (m *Mitigator) reannounceLocked(b *Ban, cfg *config.Config) bool {
	v := m.stageView(b, b.Escalation[b.EscalationStep])
	// The persisted METHOD wins when it disagrees with the rung: the ban FELL
	// BACK before the restart (a peer rejection, or every scrubbing node was
	// lost), and "the exact route the helper retained" is the fallback's.
	// Resurrecting the rung instead would re-announce a divert toward a node
	// that was dead when the process went down — attracting the victim's
	// traffic into a black hole — or de-escalate a blackhole the peer is
	// still holding, and it would do so successfully (the peer is fine; it is
	// the scrub node that is not), so nothing downstream corrects it until
	// the loss sweep re-judges the node a grace period later.
	if b.Method != "" && b.Method != v.method {
		switch b.Method {
		case config.MitigateBlackhole:
			v = m.blackholeStageView(b)
		case config.MitigateFlowSpec:
			v = stageView{method: config.MitigateFlowSpec, route: flowSpecSummary(b.FlowSpec)}
		default:
			// No other method can be recorded off-rung today (divert and
			// dataplane are never fallback targets); keep the rung view
			// rather than invent one.
		}
	}
	if err := m.announceMethodLocked(b, v.method, v.route, v.attrs, cfg); err != nil {
		m.log.Error("rehydrate re-announce failed; dropping ban",
			"target", b.Target.String(), "method", string(v.method), "err", err)
		return false
	}
	setActiveStage(b, b.EscalationStep, v)
	return true
}

// fractionAllowsLocked reports whether adding addrs more banned addresses keeps
// the family within ban.max_banned_fraction (0 disables the guard).
func (m *Mitigator) fractionAllowsLocked(cfg *config.Config, is6 bool, addrs float64) bool {
	if cfg.Ban.MaxBannedFraction <= 0 {
		return true
	}
	total := cfg.ProtectedAddrs(is6)
	if total <= 0 {
		return true
	}
	return (m.activeAddressesByFamilyLocked(is6)+addrs)/total <= cfg.Ban.MaxBannedFraction
}

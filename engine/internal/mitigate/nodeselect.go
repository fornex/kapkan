package mitigate

// Managed scrubbing-node selection and the node-loss sweep (plan task M4.5).
//
// The shape of the guarantee: a divert ban's node is chosen ONCE, at ban time,
// and frozen on the ban exactly like its BGP attribute sets — a victim's
// traffic must not hop between scrub sites because a reload reordered a list
// or a heartbeat jittered. The choice changes in exactly one place: the loss
// sweep below, when the frozen node has verifiably stopped polling. And when
// no node survives, the configured on_all_nodes_lost policy runs, because the
// alternative — keep announcing the victim toward a dead box — is the one
// outcome this whole design exists to prevent: a black hole that looks like a
// mitigation.

import (
	"net/netip"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// nodePollSlack is the extra allowance on top of stale_after before a node the
// brain has NEVER seen may be judged lost: one full documented long-poll cycle,
// so a healthy agent has had time to connect and complete at least one hold
// (see nodeLost — the allowance is anchored per node, covering both a brain
// restart and a node newly added by reload).
const nodePollSlack = 30 * time.Second

// findScrubNode returns the configured node with this name, or nil.
func findScrubNode(cfg *config.Config, name string) *config.ScrubNode {
	for i := range cfg.Scrubbing.Nodes {
		if cfg.Scrubbing.Nodes[i].Name == name {
			return &cfg.Scrubbing.Nodes[i]
		}
	}
	return nil
}

// nodeEligible reports whether a node can take this victim: it must have a
// next-hop for the victim's address family, and its hostgroups (when set) must
// claim the victim's group. An empty hostgroups list accepts any group.
func nodeEligible(n *config.ScrubNode, group *config.Group, target netip.Addr) bool {
	if target.Is6() {
		if n.NextHop6 == "" {
			return false
		}
	} else if n.NextHop == "" {
		return false
	}
	if len(n.Hostgroups) == 0 {
		return true
	}
	for _, g := range n.Hostgroups {
		if g == group.Name {
			return true
		}
	}
	return false
}

// selectScrubNode picks the managed node for a divert ban — affinity
// selection: config order, first eligible node wins (least_loaded and ecmp are
// the fleet milestone). Three tiers, in order:
//
//  1. preferred — the ban's existing choice (rehydration): kept whenever still
//     configured and eligible, even if not currently alive, because a brain
//     that just restarted has seen no polls from ANYONE and re-shuffling every
//     persisted ban on that ignorance would defeat freezing them.
//  2. The first eligible node that is currently ALIVE — a fresh ban should not
//     be pointed at a box the brain can already see is gone.
//  3. The first eligible node, alive or not (nobody has polled yet — startup,
//     or dry-run trials with no agents running). aliveOnly callers (the loss
//     sweep, which exists precisely because the current node is dead) skip
//     this tier: moving a victim from one dead node to another is churn with
//     no protection gained.
//
// Returns nil when no node is eligible — the caller falls back to the
// unmanaged scalar scrubbing.next_hop path.
func (m *Mitigator) selectScrubNode(cfg *config.Config, group *config.Group, target netip.Addr, preferred string, aliveOnly bool) *config.ScrubNode {
	staleAfter := time.Duration(cfg.Scrubbing.StaleAfterSeconds) * time.Second
	if preferred != "" && !aliveOnly {
		if n := findScrubNode(cfg, preferred); n != nil && nodeEligible(n, group, target) {
			return n
		}
	}
	var firstEligible *config.ScrubNode
	for i := range cfg.Scrubbing.Nodes {
		n := &cfg.Scrubbing.Nodes[i]
		if !nodeEligible(n, group, target) {
			continue
		}
		if m.NodeAlive(n.Name, staleAfter) {
			return n
		}
		if firstEligible == nil {
			firstEligible = n
		}
	}
	if aliveOnly {
		return nil
	}
	return firstEligible
}

// nodeDivertAttrs builds the frozen divert attribute set for a managed node:
// the NODE owns the next-hop, the group keeps the communities and local-pref
// (a node is a destination, not a policy).
func nodeDivertAttrs(n *config.ScrubNode, g *config.Group, target netip.Addr) blackholeAttrs {
	nh := n.NextHop
	if target.Is6() {
		nh = n.NextHop6
	}
	return blackholeAttrs{
		nextHop:     nh,
		communities: g.ScrubCommunities,
		commStr:     g.ScrubCommunityStr,
		localPref:   g.ScrubLocalPref,
	}
}

// nodeLost is the loss sweep's judgment, deliberately distinct from NodeAlive
// (selection's preference). A node that has POLLED and stopped is lost exactly
// staleAfter after its last completed poll — no extra allowance, a dead
// scrubber must not attract traffic a moment longer than the contract says.
// A node that has NEVER polled is not "alive" for choosing a target, but it is
// not lost either until one full appearance window (staleAfter plus a poll
// cycle) has passed from the moment the sweep first had to judge it. The
// window is anchored PER NODE, not to process start: a freshly restarted brain
// has seen polls from nobody and must not execute on_all_nodes_lost against
// every rehydrated ban on that ignorance, and a node newly added by a config
// reload — the natural rollout order, since its agent cannot poll until the
// brain knows the name — deserves exactly the same allowance.
func (m *Mitigator) nodeLost(name string, staleAfter time.Duration) bool {
	now := m.now()
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()
	if m.nodes == nil {
		m.nodes = make(map[string]*nodePresence)
	}
	p := m.nodes[name]
	if p == nil {
		p = &nodePresence{}
		m.nodes[name] = p
	}
	if p.open > 0 {
		return false // parked in a hold right now
	}
	if !p.lastSeen.IsZero() {
		return now.Sub(p.lastSeen) >= staleAfter
	}
	if p.graceUntil.IsZero() {
		p.graceUntil = now.Add(staleAfter + nodePollSlack)
		return false
	}
	return now.After(p.graceUntil)
}

// sweepNodesLocked walks the active divert bans on managed nodes and moves or
// degrades any whose node has stopped polling. Called from sweepExpired's 1 Hz
// tick; the caller holds m.mu.
//
// Only HOST bans are walked: carpet bans cannot divert (CarpetMethods excludes
// it) and bans with an empty Node divert to the unmanaged scalar next-hop,
// which has no liveness to judge.
func (m *Mitigator) sweepNodesLocked(cfg *config.Config) {
	staleAfter := time.Duration(cfg.Scrubbing.StaleAfterSeconds) * time.Second
	// Touch every configured node's judgment clock first: an appearance grace
	// is anchored to the first sweep that could see the node (process start,
	// or the reload that added it), not to whenever a ban first happened to
	// need it — otherwise the last-resort policy's timing would depend on
	// judgment order.
	for i := range cfg.Scrubbing.Nodes {
		_ = m.nodeLost(cfg.Scrubbing.Nodes[i].Name, staleAfter)
	}
	for _, b := range m.bans {
		if b.State != BanActive || b.Method != config.MitigateDivert || b.Node == "" {
			continue
		}
		if n := findScrubNode(cfg, b.Node); n != nil && !m.nodeLost(b.Node, staleAfter) {
			continue // configured and not verifiably lost: nothing to do
		}
		m.relocateBanLocked(b, cfg, staleAfter)
	}
}

// relocateBanLocked moves one divert ban off its lost node: onto a surviving
// eligible node when one exists, otherwise through on_all_nodes_lost. An
// announce failure is logged and left for the next tick — the old route stays
// up meanwhile, which is imperfect (it attracts traffic to a dead node) but
// strictly better than withdrawing protection because one announce failed.
func (m *Mitigator) relocateBanLocked(b *Ban, cfg *config.Config, staleAfter time.Duration) {
	// SAFETY RULE: the whitelist is absolute and may have changed since ban
	// time. A now-whitelisted target must never be degraded INTO a blackhole
	// or a drop rule by node loss — and diverting it toward a dead node
	// serves nobody — so its ban comes down instead.
	if cfg.IsWhitelisted(b.Target) {
		m.log.Warn("divert ban target is now whitelisted; withdrawing instead of relocating",
			"target", b.Target.String())
		m.withdrawLocked(b, "target is now whitelisted", false)
		return
	}
	// A live dry_run differing from the ban's frozen flag means announce and
	// withdraw would disagree (announces gate on the LIVE flag inside
	// announceMethodLocked, withdraws on the FROZEN one): moving or degrading
	// now could strand a real route or record a move that announced nothing.
	// The window is operator-made and short (a reload mid-incident); wait it
	// out — the ban lapses at its TTL, and new bans carry the new flag.
	if b.DryRun != cfg.DryRun {
		return
	}
	group := cfg.GroupFor(b.Target)
	if n := m.selectScrubNode(cfg, group, b.Target, "", true); n != nil {
		attrs := nodeDivertAttrs(n, group, b.Target)
		route := unicastRoute("divert", b.Prefix, attrs) + " node " + n.Name
		// Same host-route NLRI, so the announce REPLACES the old route
		// atomically (gobgp implicit withdraw) — the victim is never briefly
		// unprotected, and no explicit withdraw may follow it.
		if err := m.announceMethodLocked(b, config.MitigateDivert, route, attrs, cfg); err != nil {
			m.log.Error("re-announce toward surviving node failed; retrying next tick",
				"target", b.Target.String(), "lost", b.Node, "candidate", n.Name, "err", err)
			return
		}
		m.log.Warn("scrubbing node lost; victim re-announced toward a surviving node",
			"target", b.Target.String(), "lost", b.Node, "node", n.Name)
		b.Node = n.Name
		b.divAttrs = attrs
		setActiveStage(b, b.EscalationStep, stageView{method: config.MitigateDivert, route: route, attrs: attrs})
		m.updateGaugeLocked()
		m.markDirty()
		return
	}

	// No ALIVE survivor — but a node still inside its appearance grace is not
	// known-dead, only not-yet-seen (a brain restart, or a node just added by
	// reload). The last-resort policy waits until every eligible node is
	// verifiably lost: firing it while a survivor may be seconds from its
	// first poll would withdraw or null-route victims during a routine
	// rollout.
	for i := range cfg.Scrubbing.Nodes {
		n := &cfg.Scrubbing.Nodes[i]
		if nodeEligible(n, group, b.Target) && !m.nodeLost(n.Name, staleAfter) {
			return
		}
	}

	// No survivor. Execute on_all_nodes_lost.
	switch cfg.Scrubbing.OnAllNodesLost {
	case config.NodesLostBlackhole:
		fv := m.blackholeStageView(b)
		if err := m.announceMethodLocked(b, fv.method, fv.route, fv.attrs, cfg); err != nil {
			m.log.Error("on_all_nodes_lost blackhole announce failed; retrying next tick",
				"target", b.Target.String(), "err", err)
			return
		}
		// Same unicast family: the blackhole route implicitly replaced the
		// divert one; withdrawing now would tear down the route just installed.
		m.log.Error("ALL SCRUBBING NODES LOST: victim degraded to blackhole",
			"target", b.Target.String(), "lost", b.Node)
		metrics.MitigateFallbackTotal.WithLabelValues(string(config.MitigateDivert), string(fv.method)).Inc()
		b.FellBackFrom = config.MitigateDivert
		b.FellBackReason = "all scrubbing nodes lost"
		setActiveStage(b, b.EscalationStep, fv)
		m.updateGaugeLocked()
		m.markDirty()
	case config.NodesLostFlowSpec:
		if len(b.FlowSpec) == 0 {
			// Defensive: rules are generated at ban time whenever the ladder
			// diverts under this policy, but a reload can flip the policy
			// after the ban existed. An anchor-only rule (the same shape
			// generateRules falls back to without a classification) still
			// stops the flood, and announcing nothing would leave the victim
			// silently undefended.
			b.FlowSpec = generateRules(b.Target, "", nil, nil, group.FlowSpecAction, group.FlowSpecRateBps, false, 0)
		}
		fv := stageView{method: config.MitigateFlowSpec, route: flowSpecSummary(b.FlowSpec)}
		if err := m.announceMethodLocked(b, fv.method, fv.route, fv.attrs, cfg); err != nil {
			m.log.Error("on_all_nodes_lost flowspec announce failed; retrying next tick",
				"target", b.Target.String(), "err", err)
			return
		}
		// Different NLRI family: the divert host route must come down
		// explicitly, AFTER the rules are up (make-before-break).
		m.withdrawMethodLocked(b, config.MitigateDivert, b.Route, "all scrubbing nodes lost")
		m.log.Error("ALL SCRUBBING NODES LOST: victim degraded to flowspec",
			"target", b.Target.String(), "lost", b.Node)
		metrics.MitigateFallbackTotal.WithLabelValues(string(config.MitigateDivert), string(fv.method)).Inc()
		b.FellBackFrom = config.MitigateDivert
		b.FellBackReason = "all scrubbing nodes lost"
		setActiveStage(b, b.EscalationStep, fv)
		m.updateGaugeLocked()
		m.markDirty()
	default: // config.NodesLostWithdraw
		// Fail open: stop attracting the victim's traffic toward a dead box.
		// The ban ends; if the attack persists, re-detection opens a new one
		// (which will land on a node again the moment one is back).
		m.log.Error("ALL SCRUBBING NODES LOST: divert withdrawn, victim traffic no longer diverted",
			"target", b.Target.String(), "lost", b.Node)
		m.withdrawLocked(b, "all scrubbing nodes lost", false)
	}
}

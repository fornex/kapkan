package mitigate

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
)

// nodesYAML: a divert deployment with two managed nodes — fra1 claims only the
// "game" group, ams1 accepts anyone and is the only one with an IPv6 next-hop.
// dry_run false so the recorder sees real announces.
func nodesYAML(onAllLost string) string {
	lost := ""
	if onAllLost != "" {
		lost = "  on_all_nodes_lost: " + onAllLost + "\n"
	}
	return "dry_run: false\n" + baseYAML() + `
mitigation: divert
scrubbing:
  community: "65000:900"
` + lost + `  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
      hostgroups: [game]
    - name: ams1
      next_hop: "192.0.2.11"
      next_hop6: "2001:db8::11"
hostgroups:
  - name: game
    networks: ["203.0.113.0/25"]
`
}

// nodePoll simulates one completed rules poll from a node, the liveness
// signal.
func nodePoll(m *Mitigator, name string) {
	m.NodePollStarted(name)
	m.NodePollEnded(name)
}

// TestDivertBanToManagedNodeCarriesRules is the lab-surfaced invariant: a
// divert ban aimed at a managed scrub node MUST carry the narrowing FlowSpec
// rules, or the node — which pulls this ban and enforces its rules — would
// receive an empty set, drop nothing (default PASS), and pass the attack
// straight through to the victim it was diverting to protect.
func TestDivertBanToManagedNodeCarriesRules(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML(""), newRecorder(), clk)

	// A UDP-flood attack on a game-group victim, diverted to fra1.
	b := m.OnAttackStarted(engine.Event{
		Scope: engine.ScopeHost, Target: netip.MustParseAddr("203.0.113.5"),
		Metric: engine.MetricPPS, Rate: 500000, Threshold: 20000, BanEnabled: true,
		Direction:      engine.DirIncoming,
		Classification: &engine.Classification{Type: engine.AttackUDPFlood},
		Sample:         &engine.AttackSample{TotalPackets: 1000},
	})
	if b == nil || b.Method != config.MitigateDivert || b.Node != "fra1" {
		t.Fatalf("ban = %+v, want a divert ban on fra1", b)
	}
	if len(b.FlowSpec) == 0 {
		t.Fatal("a divert ban to a managed node carries no FlowSpec rules — the node would drop nothing")
	}
	// The UDP classification narrowed it to proto 17.
	if b.FlowSpec[0].Proto != 17 {
		t.Errorf("rule proto = %d, want 17 (the classified UDP vector)", b.FlowSpec[0].Proto)
	}
}

func TestDivertBanFreezesNode(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	rec := newRecorder()
	m := newMitigator(t, nodesYAML(""), rec, clk)

	// A game-group victim: fra1 claims the group and is first in config order.
	b := m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	if b.State != BanActive || b.Method != config.MitigateDivert {
		t.Fatalf("ban = %s/%s, want active divert", b.State, b.Method)
	}
	if b.Node != "fra1" || b.NextHop != "192.0.2.10" {
		t.Fatalf("node = %q next-hop = %q, want fra1 / 192.0.2.10", b.Node, b.NextHop)
	}
	if !strings.Contains(b.Route, "node fra1") {
		t.Errorf("route %q does not name the node", b.Route)
	}

	// A victim outside fra1's hostgroups: ams1 (unrestricted) takes it.
	b = m.ban(netip.MustParseAddr("203.0.113.200"), banOpts{manual: true})
	if b.Node != "ams1" || b.NextHop != "192.0.2.11" {
		t.Fatalf("out-of-group victim: node = %q next-hop = %q, want ams1 / 192.0.2.11", b.Node, b.NextHop)
	}

	// An IPv6 victim: only ams1 carries a v6 next-hop.
	b = m.ban(netip.MustParseAddr("2001:db8::66"), banOpts{manual: true})
	if b.Node != "ams1" || b.NextHop != "2001:db8::11" {
		t.Fatalf("v6 victim: node = %q next-hop = %q, want ams1 / 2001:db8::11", b.Node, b.NextHop)
	}
}

func TestSelectionPrefersAliveNode(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML(""), newRecorder(), clk)

	// Only ams1 is polling. A game victim would normally take fra1 (first
	// eligible), but a fresh ban must not be pointed at a box the brain can
	// already see is gone.
	nodePoll(m, "ams1")
	b := m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	if b.Node != "ams1" {
		t.Fatalf("node = %q, want the alive ams1 over the silent fra1", b.Node)
	}

	// Nobody alive at all (fresh deployment): first eligible wins.
	clk.Advance(time.Hour)
	b = m.ban(netip.MustParseAddr("203.0.113.6"), banOpts{manual: true})
	if b.Node != "fra1" {
		t.Fatalf("node = %q, want first-eligible fra1 when nobody has polled", b.Node)
	}
}

func TestScalarFallbackWhenNoNodeEligible(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	yaml := "dry_run: false\n" + baseYAML() + `
mitigation: divert
scrubbing:
  next_hop: "192.0.2.9"
  next_hop6: "2001:db8::9"
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
      hostgroups: [game]
hostgroups:
  - name: game
    networks: ["203.0.113.0/25"]
`
	m := newMitigator(t, yaml, newRecorder(), clk)
	// A victim no node claims: the unmanaged scalar next-hop takes it, and the
	// ban carries NO node — the loss sweep must never judge it.
	b := m.ban(netip.MustParseAddr("203.0.113.200"), banOpts{manual: true})
	if b.Node != "" || b.NextHop != "192.0.2.9" {
		t.Fatalf("unclaimed victim: node = %q next-hop = %q, want scalar 192.0.2.9 with no node", b.Node, b.NextHop)
	}
}

func TestNodeLossReannouncesToSurvivor(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	rec := newRecorder()
	m := newMitigator(t, nodesYAML(""), rec, clk)

	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	b := m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	if b.Node != "fra1" {
		t.Fatalf("setup: node = %q, want fra1", b.Node)
	}

	// fra1 goes silent past stale_after; ams1 keeps polling.
	clk.Advance(20 * time.Second)
	nodePoll(m, "ams1")
	m.sweepExpired()

	got := m.Snapshot()[0]
	if got.State != BanActive || got.Method != config.MitigateDivert {
		t.Fatalf("after loss: %s/%s, want the ban still active on divert", got.State, got.Method)
	}
	if got.Node != "ams1" || got.NextHop != "192.0.2.11" {
		t.Fatalf("after loss: node = %q next-hop = %q, want ams1 / 192.0.2.11", got.Node, got.NextHop)
	}
	if !strings.Contains(got.Route, "node ams1") {
		t.Errorf("route %q does not name the surviving node", got.Route)
	}

	// Frozen once moved: fra1 coming back must NOT pull the victim home.
	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	m.sweepExpired()
	if got := m.Snapshot()[0]; got.Node != "ams1" {
		t.Fatalf("node = %q after fra1 revived, want the choice to stay frozen on ams1", got.Node)
	}
}

func TestAllNodesLostWithdraw(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML(""), newRecorder(), clk) // default policy: withdraw

	// BOTH nodes were seen, so when both go silent nothing is in an
	// appearance grace and the last-resort policy may fire.
	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	clk.Advance(20 * time.Second) // everyone silent now
	m.sweepExpired()

	got := m.Snapshot()[0]
	if got.State != BanWithdrawn || got.Reason != "all scrubbing nodes lost" {
		t.Fatalf("state = %s reason = %q, want withdrawn / all scrubbing nodes lost", got.State, got.Reason)
	}
}

func TestAllNodesLostBlackhole(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	rec := newRecorder()
	m := newMitigator(t, nodesYAML("blackhole"), rec, clk)

	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	clk.Advance(20 * time.Second)
	m.sweepExpired()

	got := m.Snapshot()[0]
	if got.State != BanActive || got.Method != config.MitigateBlackhole {
		t.Fatalf("after all-lost: %s/%s, want an ACTIVE blackhole", got.State, got.Method)
	}
	if got.FellBackFrom != config.MitigateDivert || got.FellBackReason != "all scrubbing nodes lost" {
		t.Fatalf("fell_back = %q/%q, want divert / all scrubbing nodes lost", got.FellBackFrom, got.FellBackReason)
	}
	if got.NextHop != "192.0.2.1" { // bgp.next_hop from baseYAML — the blackhole set
		t.Errorf("blackhole next-hop = %q, want the frozen 192.0.2.1", got.NextHop)
	}
}

func TestAllNodesLostFlowSpec(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	rec := newRecorder()
	m := newMitigator(t, nodesYAML("flowspec"), rec, clk)

	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	b := m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	// The divert-under-flowspec-lost ladder generates rules AT BAN TIME: the
	// fallback fires long after the attack sample is gone.
	if len(b.FlowSpec) == 0 {
		t.Fatal("divert ban with on_all_nodes_lost=flowspec generated no rules at ban time")
	}
	clk.Advance(20 * time.Second)
	m.sweepExpired()

	got := m.Snapshot()[0]
	if got.State != BanActive || got.Method != config.MitigateFlowSpec {
		t.Fatalf("after all-lost: %s/%s, want ACTIVE flowspec", got.State, got.Method)
	}
	if rec.flowSpecDownTotal() != 0 && len(rec.flowSpecUp()) == 0 {
		t.Fatal("flowspec fallback announced nothing")
	}
}

// TestNeverSeenNodeGetsAppearanceGrace: a node nobody has ever seen (a fresh
// brain after restart, or a node just added by reload) is granted one
// appearance window from the sweep's FIRST judgment before it may be declared
// lost — without it, a restart would execute on_all_nodes_lost against every
// rehydrated ban on the first 1 Hz tick.
func TestNeverSeenNodeGetsAppearanceGrace(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML(""), newRecorder(), clk)

	b := m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	if b.Node != "fra1" {
		t.Fatalf("setup: node = %q, want fra1", b.Node)
	}
	m.sweepExpired() // first judgment starts the grace clocks
	if got := m.Snapshot()[0]; got.State != BanActive || got.Node != "fra1" {
		t.Fatalf("during grace: %s node=%q, want the ban untouched", got.State, got.Node)
	}
	clk.Advance(44 * time.Second) // still inside stale_after (15s) + slack (30s)
	m.sweepExpired()
	if got := m.Snapshot()[0]; got.State != BanActive {
		t.Fatalf("still inside grace: state = %s, want active", got.State)
	}
	// Grace over, still no poll from anyone, ever: the loss machinery runs
	// (default policy: withdraw).
	clk.Advance(2 * time.Second)
	m.sweepExpired()
	if got := m.Snapshot()[0]; got.State != BanWithdrawn {
		t.Fatalf("after grace with no polls ever: state = %s, want withdrawn", got.State)
	}
}

// TestReloadAddedNodeDefersAllNodesLost: the ban's node is verifiably lost,
// but another eligible node has never been seen (just added by reload, agent
// not yet started). The last-resort policy must WAIT for that node's
// appearance window instead of firing — a routine node rename must not
// withdraw or null-route victims — and the moment the new node polls, the
// victim moves onto it.
func TestReloadAddedNodeDefersAllNodesLost(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML(""), newRecorder(), clk)

	nodePoll(m, "fra1") // only fra1 has ever polled; ams1 is "newly added"
	b := m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	if b.Node != "fra1" {
		t.Fatalf("setup: node = %q, want fra1", b.Node)
	}

	clk.Advance(20 * time.Second) // fra1 seen-then-silent: verifiably lost
	m.sweepExpired()
	got := m.Snapshot()[0]
	if got.State != BanActive || got.Method != config.MitigateDivert || got.Node != "fra1" {
		t.Fatalf("with ams1 still in its appearance grace: %s/%s node=%q, want the ban held as-is",
			got.State, got.Method, got.Node)
	}

	// The new node appears: the victim moves onto it on the next tick.
	nodePoll(m, "ams1")
	m.sweepExpired()
	if got := m.Snapshot()[0]; got.Node != "ams1" || got.State != BanActive {
		t.Fatalf("after ams1 appeared: state=%s node=%q, want active on ams1", got.State, got.Node)
	}
}

// TestAllNodesLostBlackholeWithFallbackNone: ban.fallback=none means the
// normal peer-rejection fallback never freezes blackhole attributes — but
// on_all_nodes_lost=blackhole still needs them, frozen at ban time, or the
// degradation announces an empty next-hop forever.
func TestAllNodesLostBlackholeWithFallbackNone(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	yaml := strings.Replace(nodesYAML("blackhole"),
		"ban:\n", "ban:\n  fallback: \"none\"\n", 1)
	m := newMitigator(t, yaml, newRecorder(), clk)

	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	clk.Advance(20 * time.Second)
	m.sweepExpired()

	got := m.Snapshot()[0]
	if got.Method != config.MitigateBlackhole || got.State != BanActive {
		t.Fatalf("after all-lost: %s/%s, want an active blackhole", got.State, got.Method)
	}
	if got.NextHop == "" {
		t.Fatal("blackhole degradation announced an EMPTY next-hop: bhAttrs were never frozen for on_all_nodes_lost=blackhole under fallback=none")
	}
}

// TestRehydrationHonorsDegradedMethod: a ban that node-loss degraded to
// blackhole/flowspec must come back from the state file ON that method — not
// on its divert rung, which would successfully re-announce the victim toward
// the still-dead node (the peer is fine; the node is not) and attract its
// traffic into a black hole for a full appearance grace.
func TestRehydrationHonorsDegradedMethod(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML("blackhole"), newRecorder(), clk)

	nodePoll(m, "fra1")
	nodePoll(m, "ams1")
	m.ban(netip.MustParseAddr("203.0.113.5"), banOpts{manual: true})
	clk.Advance(20 * time.Second)
	m.sweepExpired()
	degraded := m.Snapshot()[0]
	if degraded.Method != config.MitigateBlackhole {
		t.Fatalf("setup: method = %s, want blackhole", degraded.Method)
	}
	snap := toSnapshot(m.bans[degraded.Target])

	// "Restart": a fresh mitigator rehydrates the snapshot.
	rec2 := newRecorder()
	m2 := newMitigator(t, nodesYAML("blackhole"), rec2, clk)
	m2.mu.Lock()
	ok := m2.rehydrateHostLocked(snap, m2.store.Get(), clk.Now())
	m2.mu.Unlock()
	if !ok {
		t.Fatal("rehydration refused the degraded ban")
	}
	got := m2.Snapshot()[0]
	if got.Method != config.MitigateBlackhole {
		t.Fatalf("rehydrated method = %s, want blackhole (the divert rung must NOT be resurrected)", got.Method)
	}
	if !strings.HasPrefix(got.Route, "blackhole ") {
		t.Errorf("rehydrated route = %q, want a blackhole route", got.Route)
	}
	if got.NextHop == "" {
		t.Error("rehydrated blackhole has no next-hop (bhAttrs not re-frozen)")
	}
}

func TestRehydrationKeepsPersistedNode(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, nodesYAML(""), newRecorder(), clk)

	// Even with ams1 alive and fra1 silent, a persisted choice of fra1 is
	// KEPT: a restarted brain has seen no polls from anyone, and shuffling
	// every rehydrated ban on that ignorance would defeat freezing them.
	nodePoll(m, "ams1")
	group := m.store.Get().GroupFor(netip.MustParseAddr("203.0.113.5"))
	n := m.selectScrubNode(m.store.Get(), group, netip.MustParseAddr("203.0.113.5"), "fra1", false)
	if n == nil || n.Name != "fra1" {
		t.Fatalf("preferred fra1 not kept: got %v", n)
	}
	// A preferred node that vanished from the config re-selects.
	n = m.selectScrubNode(m.store.Get(), group, netip.MustParseAddr("203.0.113.5"), "ghost", false)
	if n == nil || n.Name == "ghost" {
		t.Fatalf("vanished preferred node: got %v, want a re-selection", n)
	}
}

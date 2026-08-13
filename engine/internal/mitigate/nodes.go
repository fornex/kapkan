package mitigate

// Scrub-node LIVENESS, and nothing else. A node is alive because it keeps
// asking for rules — the long-poll on /api/v1/dataplane/rules — and this file
// is where those polls are recorded and judged.
//
// WHAT IS DELIBERATELY NOT HERE: the node's self-reported state (load,
// counters, versions). Reports live in internal/api and this package cannot
// import it, which turns a security rule into an import direction: a
// compromised agent token can inflate every number in its reports, and none of
// those numbers can reach the code that decides where a victim's traffic goes.
// If a future change needs a report field for a routing decision, it must
// argue with this comment first.
//
// Ephemeral by design. Liveness is a claim about NOW; persisting it would let
// a restarted brain trust a poll that a dead node made before the crash. A
// restart starts everyone at "never seen", and the first real poll (≤30 s for
// a healthy node) repopulates the map before staleness can matter — the
// re-announce machinery (M4.5) judges against stale_after, which exceeds the
// poll interval.

import "time"

// nodePresence is one node's poll state: how many rule polls it is holding
// open right now, and when it last completed one.
type nodePresence struct {
	open     int
	lastSeen time.Time
	// graceUntil is set for a node that has NEVER polled, the first time the
	// loss sweep needs to judge it: until it passes, "never seen" reads as
	// "not appeared yet", not "dead" (see Mitigator.nodeLost). Anchored per
	// node so one added by a config reload gets the same allowance a freshly
	// restarted brain grants everyone.
	graceUntil time.Time
}

// NodePollStarted records that node is holding a rules poll open. While at
// least one poll is open the node is alive regardless of timestamps — a
// healthy agent spends most of its life parked inside a 25 s hold, which is
// LONGER than the default stale_after (15 s), so "when did it last return"
// alone would declare a perfectly healthy node dead mid-hold.
func (m *Mitigator) NodePollStarted(name string) {
	if name == "" {
		return
	}
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
	p.open++
	// The arrival is itself a sighting: an agent whose poll is then refused
	// (hold cap) still demonstrated it is up and asking.
	p.lastSeen = m.now()
}

// NodePollEnded records that one of node's polls returned (however it ended:
// fresh document, 304, shutdown). Pairs with NodePollStarted.
func (m *Mitigator) NodePollEnded(name string) {
	if name == "" {
		return
	}
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()
	p := m.nodes[name]
	if p == nil {
		return
	}
	if p.open > 0 {
		p.open--
	}
	p.lastSeen = m.now()
}

// NodeSeen reports a node's poll presence: when it was last seen and whether
// it is holding a poll open right now. The zero time means "never" — a node
// that is configured but has not connected since this process started.
func (m *Mitigator) NodeSeen(name string) (lastSeen time.Time, holding bool) {
	m.nodesMu.Lock()
	defer m.nodesMu.Unlock()
	p := m.nodes[name]
	if p == nil {
		return time.Time{}, false
	}
	return p.lastSeen, p.open > 0
}

// NodeAlive is the ONE liveness predicate (the re-announce machinery and the
// nodes API must never disagree about what "up" means): a node is alive while
// it holds a poll open, or for staleAfter after its last completed one.
func (m *Mitigator) NodeAlive(name string, staleAfter time.Duration) bool {
	last, holding := m.NodeSeen(name)
	if holding {
		return true
	}
	return !last.IsZero() && m.now().Sub(last) < staleAfter
}

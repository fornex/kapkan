package mitigate

import (
	"testing"
	"time"
)

// TestNodeLiveness pins the ONE liveness predicate: alive while a poll is held
// open (however long — a healthy agent parks inside a hold LONGER than the
// default stale_after), alive for staleAfter after the last completed poll,
// dead after, and "never seen" for a node that has not connected.
func TestNodeLiveness(t *testing.T) {
	clk := &mockClock{t: time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)}
	m := newMitigator(t, baseYAML(), &recorder{}, clk)
	const stale = 15 * time.Second

	if m.NodeAlive("fra1", stale) {
		t.Fatal("a never-seen node must not be alive")
	}
	if last, holding := m.NodeSeen("fra1"); !last.IsZero() || holding {
		t.Fatalf("NodeSeen(never) = %v, %v; want zero, false", last, holding)
	}

	// A held poll keeps the node alive PAST stale_after — this is the case
	// that breaks if liveness ever degrades to timestamps alone.
	m.NodePollStarted("fra1")
	clk.Advance(25 * time.Second)
	if !m.NodeAlive("fra1", stale) {
		t.Fatal("a node holding a poll open must be alive regardless of stale_after")
	}

	// The poll returns: alive for staleAfter, then dead.
	m.NodePollEnded("fra1")
	clk.Advance(stale - time.Second)
	if !m.NodeAlive("fra1", stale) {
		t.Fatal("a node must stay alive within stale_after of its last poll")
	}
	clk.Advance(2 * time.Second)
	if m.NodeAlive("fra1", stale) {
		t.Fatal("a node must count as lost once stale_after elapses without a poll")
	}

	// Overlapping polls (an agent restarting while its old hold drains):
	// alive until the LAST one ends.
	m.NodePollStarted("fra1")
	m.NodePollStarted("fra1")
	m.NodePollEnded("fra1")
	clk.Advance(time.Hour)
	if !m.NodeAlive("fra1", stale) {
		t.Fatal("one of two overlapping polls ended; the node still holds the other")
	}

	// An unmatched extra end must not underflow the open count.
	m.NodePollEnded("fra1")
	m.NodePollEnded("fra1")
	if _, holding := m.NodeSeen("fra1"); holding {
		t.Fatal("open-poll count went negative or stuck after unmatched ends")
	}
}

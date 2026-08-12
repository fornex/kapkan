package mitigate

// The change-notification side of the scrub-node channel: a scrub node long-
// polls GET /api/v1/dataplane/rules, and the API layer needs one thing from
// this package — a way to block until the ban table changes. This is that way.
//
// It is a BROADCAST, not a queue. The rules document is rebuilt from the ban
// table on every request, so a waker carries no payload and coalescing wakes is
// harmless: N changes while nobody was looking must produce one visible fact
// (the table differs), not N events. The existing events channel could not be
// reused precisely because it is consumed destructively by one reader; this
// must wake every held poll at once.

// RulesChanged returns a channel that is closed on the next change to the ban
// table (any change markDirty records: create, refresh, escalate, withdraw,
// expire). After a wake the caller re-reads the table and calls RulesChanged
// again for a fresh channel — the classic closed-channel broadcast, so any
// number of concurrent long-polls can wait on one signal.
func (m *Mitigator) RulesChanged() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rulesCh == nil {
		m.rulesCh = make(chan struct{})
	}
	return m.rulesCh
}

// notifyRulesLocked wakes every RulesChanged waiter. The caller holds m.mu.
// Lazy: no allocation happens until someone is actually listening, so a
// deployment with no scrub nodes pays nothing.
func (m *Mitigator) notifyRulesLocked() {
	if m.rulesCh != nil {
		close(m.rulesCh)
		m.rulesCh = nil
	}
}

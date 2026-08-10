package dataplane

// The MEASURED half of a dynamic install: what the kernel actually did with the
// rules the mitigator asked for.
//
// This type is untagged (no //go:build) for the same reason encode.go is: the
// mitigator's ban record carries it all the way to /api/v1/bans and to the
// console, and those are compiled and tested on the macOS development host. A
// Linux-only VictimCounters would have put the shape of an operator-visible JSON
// object behind a build tag, where only a privileged container ever type-checks
// it. The READ is Linux-only (counters_linux.go); the shape is not.

// VictimCounters is one banned victim's per-rule packet/byte counts, read back
// from kapkan_rule_stats.
//
// Rules is INDEX-ALIGNED with the DynamicRules.Specs that were installed, which
// is in turn index-aligned with the ban's FlowSpec rules (see
// mitigate/dpencode.go). That alignment is the whole contract: the console joins
// "the rule you announced" to "what it caught" by position, and nothing else in
// the record could re-derive the pairing — a rule id is policyID*8+i, so the
// index IS the identity.
//
// It may be SHORT. A slot whose kapkan_rule_stats entry does not exist is not an
// error: the datapath only bumps an entry userspace created, and a rule the
// install rolled back, or one whose counter a withdraw already reaped, simply
// has none. Readers must tolerate fewer counters than rules rather than assume a
// zero.
type VictimCounters struct {
	// PolicyID is the block these counters came from. It is reported so a
	// consumer can tell "the same rules, still counting" from "re-installed onto
	// a different block, counters restarted from zero" — the two are
	// indistinguishable from the numbers alone, and the second one goes
	// backwards.
	PolicyID uint32
	// Rules holds one entry per installed rule, in install order.
	Rules []Counter
}

// Total sums every rule's counters. It is what a ban-level "dropped N packets"
// figure is: the block belongs to exactly one victim, so summing across its
// rules double-counts nothing (the datapath stops at the first matching rule).
func (v VictimCounters) Total() Counter {
	var out Counter
	for _, c := range v.Rules {
		out.Pkts += c.Pkts
		out.Bytes += c.Bytes
	}
	return out
}

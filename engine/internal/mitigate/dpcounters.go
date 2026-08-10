package mitigate

// The measured effect of a data-plane ban: what the kernel counted for the
// rules this ban put in its maps.
//
// WHY THE BAN CARRIES IT AT ALL, rather than the API joining ban -> counters at
// request time. Three consumers need the same numbers — /api/v1/bans,
// /api/v1/attacks, and the state file that survives a restart — and the ban is
// the only object all three already share. A join at the HTTP layer would have
// had to be written three times and would have left the persisted total with
// nowhere to live.
//
// WHO WRITES IT: internal/app, on a timer, through SetDataplaneCounters. Not
// this package. The mitigator installs rules through an interface that
// deliberately knows nothing about kernel maps (dataplaneBackend has exactly two
// methods), and reading counters is a Linux-only bpf(2) walk; internal/app is
// already the single place allowed to import both sides, and it already owns the
// data plane's scrape cadence for /metrics.

import (
	"net/netip"
	"time"
)

// BanDataplane is the `dataplane` object on a Ban.
//
// THE JSON CONTRACT IS FROZEN HERE. docs/callback-schema.json, the operator
// console and engine/deploy/dataplane-operations.md are all written against
// these key names; changing one is a breaking API change, not a rename.
type BanDataplane struct {
	// Packets and Bytes are this BAN's lifetime totals — monotonic across a
	// re-install, a policy-id change and a process restart, which the raw kernel
	// counters are not (a re-install zeroes kapkan_rule_stats, and a restart
	// that could not adopt the pins starts from empty maps). An operator asking
	// "how much did kapkan drop for this victim" means the lifetime number, so
	// that is the one that carries the plain name.
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	// Rules is index-aligned with Ban.FlowSpec: Rules[i] is what FlowSpec[i]
	// caught. It MAY BE SHORTER — a rule whose kernel counter has already been
	// reaped has no entry — and a consumer must render the missing tail as
	// "unknown", never as zero. It is never longer.
	Rules []BanDataplaneRule `json:"rules,omitempty"`
	// PolicyID is the kapkan_policies block the rules live in, so an operator
	// can line these numbers up with `kapkan dataplane status`. Never persisted:
	// ids are allocations against a map set that may have been resized or
	// rebuilt while the process was down.
	PolicyID uint32 `json:"policy_id"`
	// MeasuredAt is when the last SUCCESSFUL read happened, not when this object
	// was serialized. UTC RFC3339 like every other timestamp the API emits.
	MeasuredAt time.Time `json:"measured_at"`
	// Stale is true when the last successful read is older than the scraper's
	// staleness bound. The values are the last good ones, NOT zeros: a datapath
	// whose counters cannot be read has not stopped dropping, and showing zero
	// would say it had.
	Stale bool `json:"stale,omitempty"`
}

// BanDataplaneRule is one installed rule's measured effect.
//
// It carries no match description: the match is Ban.FlowSpec[i], and repeating
// it here would let the two drift into disagreeing about which rule a number
// belongs to. The index is the join.
type BanDataplaneRule struct {
	// ID is the kernel rule id (policy_id*8 + index), the key of
	// kapkan_rule_stats. Present so an operator can cross-check a number against
	// the pin inspector; NOT the join key — the index is.
	ID      uint32 `json:"id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// SetDataplaneCounters publishes freshly measured counters onto the live bans.
//
// It is a WHOLE-WORLD replace, not a merge: byVictim is the complete set of
// victims the scraper could measure this tick, and any active ban missing from
// it has its counters CLEARED. That direction is deliberate — a ban that
// escalated off the dataplane rung, or fell back to a blackhole, must stop
// showing in-kernel drop counts, and a merge would leave the last numbers on it
// forever, describing rules that are no longer installed.
//
// Bans that are not active are left alone. Their counters are the final tally of
// what the rules caught before they were withdrawn, and that is the number the
// history table and the attack record should keep.
func (m *Mitigator) SetDataplaneCounters(byVictim map[netip.Prefix]BanDataplane) {
	m.mu.Lock()
	defer m.mu.Unlock()
	apply := func(b *Ban) {
		if b.State != BanActive {
			return
		}
		if dp, ok := byVictim[b.Prefix]; ok {
			c := dp
			b.Dataplane = &c
			return
		}
		b.Dataplane = nil
	}
	for _, b := range m.bans {
		apply(b)
	}
	for _, b := range m.prefixBans {
		apply(b)
	}
}

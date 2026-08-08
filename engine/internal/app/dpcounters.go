package app

// Turning kapkan_rule_stats into a number on a ban.
//
// The kernel counts per RULE, in a per-CPU hash keyed by rule id, and it counts
// only while that rule exists. The operator's question is per BAN and per
// incident: "how much did kapkan actually drop for 203.0.113.66". Three things
// sit between the two, and this file is all three:
//
//  1. AGGREGATION. Eight rule counters -> one victim total, plus the per-rule
//     breakdown the console joins back onto the announced FlowSpec rules.
//
//  2. MONOTONICITY. The raw counters go BACKWARDS in normal operation. A
//     re-install recreates the kapkan_rule_stats entries at zero; a restart that
//     could not adopt the pins starts with empty maps; a policy-id change moves
//     the victim to a different block entirely. A ban-lifetime total that jumped
//     back to zero mid-incident would be read as "the mitigation stopped", so
//     this accumulates DELTAS and treats any decrease as a restart of the
//     underlying counter rather than as negative traffic.
//
//  3. HONESTY ABOUT FRESHNESS. When a read fails, the last good numbers are kept
//     and flagged stale. They are not replaced with zeros: a datapath whose
//     counters cannot be read has not stopped dropping packets, and zero would
//     say it had — the one wrong answer an operator would act on.
//
// It lives in internal/app for the same reason dataplaneReporter does: this is
// the only package that may import both internal/mitigate and internal/dataplane
// (see the comment on api.DataplaneReporter for why the API must not).

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

const (
	// banCounterInterval is the scrape cadence.
	//
	// NOT the 1 Hz the rest of the daemon runs on, and the difference is
	// deliberate. The global /metrics scrape is one per-CPU read of a 21-entry
	// array; this is up to eight bpf(2) lookups per ACTIVE BAN, so its cost
	// scales with an incident rather than being constant. At the default
	// ban.max_active_bans of 50 that is 400 lookups per scrape — trivial at 5s,
	// and pointless faster: these numbers are read by a human in a console that
	// polls every 3s, and a drop counter one tick behind is indistinguishable
	// from a fresh one at that rate.
	banCounterInterval = 5 * time.Second
	// banCounterStaleAfter is when the last good values stop being presented as
	// current. Three intervals, so a single missed or slow scrape does not paint
	// a healthy datapath as stale, but a genuinely wedged read is visible within
	// fifteen seconds.
	banCounterStaleAfter = 3 * banCounterInterval
)

// dpCounterSource is the read side of the data plane, as this file needs it.
// *dataplane.Installer implements it on every platform (the non-Linux stub
// reports "nothing installed" rather than an error, which is the truth there).
type dpCounterSource interface {
	Counters(victim netip.Prefix) (dataplane.VictimCounters, bool, error)
}

// victimCount is the running state for one banned prefix.
type victimCount struct {
	// policyID is the block the last successful read came from. A change means
	// the victim was re-installed elsewhere and every raw counter restarted.
	policyID uint32
	// haveRaw is false until the first successful read, so an initial raw value
	// is taken as a whole delta rather than compared against a zero we never
	// actually observed.
	haveRaw bool
	// lastRaw is the previous read, per rule index.
	lastRaw []dataplane.Counter
	// pkts/bytes/rules are the LIFETIME totals, seeded from the ban (which may
	// have been rehydrated from the state file) and only ever added to.
	pkts  uint64
	bytes uint64
	rules []mitigate.BanDataplaneRule
	// lastOK is when the numbers above last advanced from a real read.
	lastOK time.Time
}

// banCounterScraper measures every active data-plane ban on a timer and
// publishes the result onto the ban records.
type banCounterScraper struct {
	src dpCounterSource
	mit *mitigate.Mitigator
	log *slog.Logger
	now func() time.Time

	// state is keyed by victim prefix and pruned to the live bans on every tick,
	// so it cannot outgrow ban.max_active_bans.
	state map[netip.Prefix]*victimCount
	// report, when set, receives the measured dynamic rule count for
	// /api/v1/status and the rules{mode} gauge. nil in tests that only exercise
	// the accumulation.
	report *dataplaneReporter
	// warnedRead throttles the read-failure log to once per failing streak: the
	// failure mode is a closed or unreadable map, which repeats every interval
	// and would otherwise fill the journal during a shutdown race.
	warnedRead bool
}

func newBanCounterScraper(src dpCounterSource, mit *mitigate.Mitigator, log *slog.Logger, report *dataplaneReporter) *banCounterScraper {
	return &banCounterScraper{
		src:    src,
		mit:    mit,
		log:    log.With("component", "dataplane-counters"),
		now:    time.Now,
		state:  map[netip.Prefix]*victimCount{},
		report: report,
	}
}

// run scrapes on banCounterInterval until ctx is cancelled.
func (s *banCounterScraper) run(ctx context.Context) {
	t := time.NewTicker(banCounterInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick()
		}
	}
}

// tick measures every active data-plane ban once and publishes the result.
//
// The publish is a whole-world replace (see SetDataplaneCounters): a ban that
// escalated off the dataplane rung this tick is simply absent from the map and
// has its counters cleared, which is what "these rules are no longer installed"
// should look like.
func (s *banCounterScraper) tick() {
	now := s.now()
	out := map[netip.Prefix]mitigate.BanDataplane{}
	live := map[netip.Prefix]bool{}
	total := 0
	anyErr := false

	for _, b := range s.mit.ActiveBans() {
		if b.Method != config.MitigateDataplane {
			continue
		}
		// A dry-run ban installed nothing (announceMethodLocked returns before
		// the install), so there is nothing in the kernel to attribute to it.
		// Reading the ban's OWN frozen flag, not the live config, for the same
		// reason withdrawMethodLocked does: a dry_run flip mid-ban must not
		// change what this ban is claimed to have done.
		if b.DryRun {
			continue
		}
		live[b.Prefix] = true
		st := s.state[b.Prefix]
		if st == nil {
			st = seedFromBan(b)
			s.state[b.Prefix] = st
		}

		cur, ok, err := s.src.Counters(b.Prefix)
		switch {
		case err != nil:
			anyErr = true
			if !s.warnedRead {
				s.warnedRead = true
				s.log.Warn("reading in-kernel drop counters failed; the last measured values are "+
					"kept and will be reported as stale (the rules themselves are unaffected)",
					"victim", b.Prefix.String(), "err", err)
			}
		case !ok:
			// Nothing installed for this victim in THIS process. Either the ban
			// has not reached its install yet, or its rules were adopted from a
			// previous process and never rehydrated. Keep whatever was measured
			// before; it goes stale on its own if this persists.
		default:
			s.advance(st, cur, len(b.FlowSpec), now)
			total += len(cur.Rules)
		}

		out[b.Prefix] = mitigate.BanDataplane{
			Packets:    st.pkts,
			Bytes:      st.bytes,
			Rules:      append([]mitigate.BanDataplaneRule(nil), st.rules...),
			PolicyID:   st.policyID,
			MeasuredAt: st.lastOK.UTC(),
			Stale:      st.lastOK.IsZero() || now.Sub(st.lastOK) > banCounterStaleAfter,
		}
	}

	if !anyErr {
		s.warnedRead = false
	}
	for p := range s.state {
		if !live[p] {
			delete(s.state, p)
		}
	}
	if s.report != nil {
		s.report.dynRules.Store(int64(total))
	}
	s.mit.SetDataplaneCounters(out)
}

// seedFromBan starts a victim's running totals from whatever the ban already
// carries. That is how a restart keeps its count: rehydrateLocked puts the
// persisted lifetime totals back on the ban before anything scrapes, so the
// first measurement here CONTINUES from them instead of restarting at zero and
// throwing away everything the previous process saw.
func seedFromBan(b mitigate.Ban) *victimCount {
	st := &victimCount{}
	if b.Dataplane != nil {
		st.pkts = b.Dataplane.Packets
		st.bytes = b.Dataplane.Bytes
		st.rules = append([]mitigate.BanDataplaneRule(nil), b.Dataplane.Rules...)
	}
	return st
}

// advance folds one raw reading into the running totals.
//
// nRules is the ban's announced rule count; the per-rule breakdown is trimmed to
// it so the array the API publishes can never be LONGER than the FlowSpec array
// the console joins it against. (It can be shorter — a reaped counter — and the
// console renders that as unknown.) A re-install with fewer rules can leave a
// stale higher-index counter behind in the map, and without the trim it would be
// rendered against a rule that no longer exists.
func (s *banCounterScraper) advance(st *victimCount, cur dataplane.VictimCounters, nRules int, now time.Time) {
	n := len(cur.Rules)
	if nRules > 0 && n > nRules {
		n = nRules
	}
	// A block change restarts every counter, so nothing from the previous read
	// is comparable.
	reset := !st.haveRaw || st.policyID != cur.PolicyID
	for i := 0; i < n; i++ {
		raw := cur.Rules[i]
		var dp, db uint64
		prevKnown := !reset && i < len(st.lastRaw)
		if prevKnown && raw.Pkts >= st.lastRaw[i].Pkts && raw.Bytes >= st.lastRaw[i].Bytes {
			dp = raw.Pkts - st.lastRaw[i].Pkts
			db = raw.Bytes - st.lastRaw[i].Bytes
		} else {
			// Either the first reading of this rule or a counter that went
			// backwards, which only happens when the entry was recreated. Take
			// the whole current value: it is everything that rule has counted
			// since it was (re)created, and none of it has been added yet.
			dp, db = raw.Pkts, raw.Bytes
		}
		for len(st.rules) <= i {
			st.rules = append(st.rules, mitigate.BanDataplaneRule{})
		}
		st.rules[i].ID = dataplane.DynamicRuleID(cur.PolicyID, i)
		st.rules[i].Packets += dp
		st.rules[i].Bytes += db
		st.pkts += dp
		st.bytes += db
	}
	if len(st.rules) > n {
		st.rules = st.rules[:n]
	}
	st.lastRaw = append(st.lastRaw[:0], cur.Rules[:n]...)
	st.haveRaw = true
	st.policyID = cur.PolicyID
	st.lastOK = now
}

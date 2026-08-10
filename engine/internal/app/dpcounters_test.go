package app

// The arithmetic between a kernel counter and an operator-facing number.
//
// These run on every host, macOS included, because none of them needs a kernel:
// the readings are supplied directly. That is on purpose — the accumulation is
// where a wrong number would be produced, and it must be exercised on the
// developer loop rather than only inside a privileged container.

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// fakeCounters is a scripted data plane: whatever the test says the kernel
// currently holds.
type fakeCounters struct {
	byVictim map[netip.Prefix]dataplane.VictimCounters
	missing  bool  // report "nothing installed" for every victim
	err      error // report a read failure
	calls    int
}

func (f *fakeCounters) Counters(v netip.Prefix) (dataplane.VictimCounters, bool, error) {
	f.calls++
	if f.err != nil {
		return dataplane.VictimCounters{}, false, f.err
	}
	if f.missing {
		return dataplane.VictimCounters{}, false, nil
	}
	c, ok := f.byVictim[v]
	return c, ok, nil
}

// noopBackend is a data-plane backend whose installs always succeed, so a
// `dataplane` ladder produces a real active ban with Method=dataplane on a host
// with no kernel. It is NOT the counter source — the fake above is, and keeping
// them separate is what lets a test say "the rules are installed but their
// counters cannot be read", which is the interesting failure.
type noopBackend struct{}

func (noopBackend) Install(netip.Prefix, dataplane.DynamicRules) error { return nil }
func (noopBackend) Withdraw(netip.Prefix) error                        { return nil }

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// banFixture drives a REAL ban through the real mitigator on the given ladder,
// rather than hand-building a Ban. The method, the route string and the
// generated FlowSpec rules then come from the same code path production uses,
// so a change to how a dataplane rung resolves shows up here.
func banFixture(t *testing.T, action string, dryRun bool) (*mitigate.Mitigator, netip.Prefix) {
	t.Helper()
	// dry_run is stated explicitly in BOTH directions: kapkan defaults it to
	// true (nothing is ever announced until an operator says so), so a fixture
	// that only sets it when it wants dry-run would silently test the dry-run
	// path every time.
	yaml := "dry_run: false\n" + ladderBase +
		"escalation:\n  - {after_seconds: 0, action: " + action + "}\n"
	if dryRun {
		yaml = "dry_run: true\n" + ladderBase +
			"escalation:\n  - {after_seconds: 0, action: " + action + "}\n"
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}
	mit, err := mitigate.New(config.NewStore("", cfg), discardLog(), mitigate.WithDataplane(noopBackend{}))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	target := netip.MustParseAddr("203.0.113.66")
	b, err := mit.ManualBan(target)
	if err != nil {
		t.Fatalf("ManualBan: %v", err)
	}
	if b.State != mitigate.BanActive {
		t.Fatalf("ban state = %s (%s), want active", b.State, b.Reason)
	}
	return mit, b.Prefix
}

// activeDP returns the measured object on the active ban for victim, failing if
// there is none.
func activeDP(t *testing.T, mit *mitigate.Mitigator, victim netip.Prefix) mitigate.BanDataplane {
	t.Helper()
	for _, b := range mit.ActiveBans() {
		if b.Prefix == victim {
			if b.Dataplane == nil {
				t.Fatalf("the active ban for %s carries no measured counters", victim)
			}
			return *b.Dataplane
		}
	}
	t.Fatalf("no active ban for %s", victim)
	return mitigate.BanDataplane{}
}

// TestCountersAccumulateAcrossAReinstall is the property the whole file exists
// for.
//
// A TTL refresh or an escalation re-install recreates kapkan_rule_stats at zero,
// and a policy-id change moves the victim to a different block entirely. Both
// make the RAW counter go backwards. A ban-lifetime total that went backwards
// mid-incident would read as "the mitigation stopped working", which is the one
// conclusion an operator would act on immediately and wrongly.
func TestCountersAccumulateAcrossAReinstall(t *testing.T) {
	victim := netip.MustParsePrefix("203.0.113.66/32")
	fake := &fakeCounters{byVictim: map[netip.Prefix]dataplane.VictimCounters{}}
	s := newBanCounterScraper(fake, nil, discardLog(), nil)
	st := &victimCount{}
	now := time.Unix(1_800_000_000, 0)

	// First reading: everything the rule has counted so far.
	fake.byVictim[victim] = dataplane.VictimCounters{PolicyID: 3,
		Rules: []dataplane.Counter{{Pkts: 100, Bytes: 48200}}}
	s.advance(st, fake.byVictim[victim], 1, now)
	if st.pkts != 100 || st.bytes != 48200 {
		t.Fatalf("after first reading: %d pkts / %d bytes, want 100/48200", st.pkts, st.bytes)
	}

	// It keeps counting up: only the delta is added.
	s.advance(st, dataplane.VictimCounters{PolicyID: 3,
		Rules: []dataplane.Counter{{Pkts: 250, Bytes: 120500}}}, 1, now)
	if st.pkts != 250 {
		t.Fatalf("after a normal advance: %d pkts, want 250", st.pkts)
	}

	// A re-install zeroes the entry and it starts climbing again from 0. The
	// lifetime total must CONTINUE, not restart.
	s.advance(st, dataplane.VictimCounters{PolicyID: 3,
		Rules: []dataplane.Counter{{Pkts: 7, Bytes: 3400}}}, 1, now)
	if st.pkts != 257 || st.bytes != 123900 {
		t.Fatalf("after a counter reset: %d pkts / %d bytes, want 257/123900 "+
			"(the reset value must be ADDED, not compared against the old high-water mark)",
			st.pkts, st.bytes)
	}

	// A different policy block: same argument, different cause.
	s.advance(st, dataplane.VictimCounters{PolicyID: 9,
		Rules: []dataplane.Counter{{Pkts: 5, Bytes: 2000}}}, 1, now)
	if st.pkts != 262 {
		t.Fatalf("after a policy-id change: %d pkts, want 262", st.pkts)
	}
	if st.rules[0].ID != dataplane.DynamicRuleID(9, 0) {
		t.Errorf("rule id = %d, want the id derived from the NEW policy block", st.rules[0].ID)
	}
}

// TestCountersAreTrimmedToTheAnnouncedRules: the array the console joins by
// index must never be longer than the FlowSpec array it joins against.
//
// A re-install with fewer rules leaves the previous install's higher-index
// counters in the map. Rendering one of those against a rule that no longer
// exists would attribute real drops to a match nobody announced.
func TestCountersAreTrimmedToTheAnnouncedRules(t *testing.T) {
	s := newBanCounterScraper(&fakeCounters{}, nil, discardLog(), nil)
	st := &victimCount{}
	now := time.Unix(1_800_000_000, 0)
	s.advance(st, dataplane.VictimCounters{PolicyID: 0, Rules: []dataplane.Counter{
		{Pkts: 10}, {Pkts: 20}, {Pkts: 30},
	}}, 3, now)
	if len(st.rules) != 3 || st.pkts != 60 {
		t.Fatalf("3 announced rules: %d entries / %d pkts, want 3/60", len(st.rules), st.pkts)
	}
	// Re-announced with one rule; the kernel still holds the stale slots 1 and 2.
	s.advance(st, dataplane.VictimCounters{PolicyID: 0, Rules: []dataplane.Counter{
		{Pkts: 11}, {Pkts: 20}, {Pkts: 30},
	}}, 1, now)
	if len(st.rules) != 1 {
		t.Fatalf("after re-announcing 1 rule: %d entries, want 1", len(st.rules))
	}
	if st.pkts != 61 {
		t.Errorf("total = %d, want 61 (only the surviving rule's delta counts)", st.pkts)
	}
}

// TestAShortCounterArrayIsNotZeros: fewer counters than rules means "unknown",
// and the missing tail must simply be absent rather than reported as zero drops.
func TestAShortCounterArrayIsNotZeros(t *testing.T) {
	s := newBanCounterScraper(&fakeCounters{}, nil, discardLog(), nil)
	st := &victimCount{}
	s.advance(st, dataplane.VictimCounters{PolicyID: 0,
		Rules: []dataplane.Counter{{Pkts: 9, Bytes: 900}}}, 3, time.Unix(1_800_000_000, 0))
	if len(st.rules) != 1 {
		t.Fatalf("%d entries for 1 readable counter of 3 rules, want 1", len(st.rules))
	}
}

// TestStalenessKeepsTheLastValues is the requirement stated the other way round:
// when the read stops working, show the last good numbers and SAY they are old.
// Zeros would claim the datapath had stopped dropping.
func TestStalenessKeepsTheLastValues(t *testing.T) {
	victim := netip.MustParsePrefix("203.0.113.66/32")
	fake := &fakeCounters{byVictim: map[netip.Prefix]dataplane.VictimCounters{
		victim: {PolicyID: 0, Rules: []dataplane.Counter{{Pkts: 4242, Bytes: 2_000_000}}},
	}}
	mit, _ := banFixture(t, "dataplane", false)
	s := newBanCounterScraper(fake, mit, discardLog(), nil)

	base := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return base }
	s.tick()

	got := activeDP(t, mit, victim)
	if got.Packets != 4242 || got.Stale {
		t.Fatalf("first scrape: %d pkts stale=%v, want 4242 and not stale", got.Packets, got.Stale)
	}

	// The reads start failing. One interval later the numbers are still current
	// enough to present as live.
	fake.err = errRead{}
	s.now = func() time.Time { return base.Add(banCounterInterval) }
	s.tick()
	got = activeDP(t, mit, victim)
	if got.Packets != 4242 {
		t.Errorf("a failed read replaced the values: %d pkts, want the last good 4242", got.Packets)
	}
	if got.Stale {
		t.Error("one missed scrape must not be reported as stale")
	}

	// Past 3x the interval it must say so — with the values intact.
	s.now = func() time.Time { return base.Add(banCounterStaleAfter + time.Second) }
	s.tick()
	got = activeDP(t, mit, victim)
	if !got.Stale {
		t.Errorf("last good read %s ago is not marked stale", banCounterStaleAfter+time.Second)
	}
	if got.Packets != 4242 || got.Bytes != 2_000_000 {
		t.Errorf("stale reading shows %d pkts / %d bytes, want the last good 4242 / 2000000 "+
			"(zeros would say the datapath stopped dropping)", got.Packets, got.Bytes)
	}
	if !got.MeasuredAt.Equal(base.UTC()) {
		t.Errorf("measured_at = %s, want the last SUCCESSFUL read at %s", got.MeasuredAt, base.UTC())
	}
}

// TestDryRunBansAreNotMeasured: a dry-run ban installed nothing, so there is
// nothing in the kernel to attribute to it. Reporting a count would claim rules
// exist that the announce path deliberately never wrote.
func TestDryRunBansAreNotMeasured(t *testing.T) {
	mit, victim := banFixture(t, "dataplane", true)
	for _, b := range mit.ActiveBans() {
		if b.Method != config.MitigateDataplane {
			t.Fatalf("fixture produced method %q; this test is only meaningful for a "+
				"dataplane ban that happens to be dry-run", b.Method)
		}
	}
	fake := &fakeCounters{byVictim: map[netip.Prefix]dataplane.VictimCounters{
		victim: {PolicyID: 0, Rules: []dataplane.Counter{{Pkts: 999}}},
	}}
	s := newBanCounterScraper(fake, mit, discardLog(), nil)
	s.tick()
	for _, b := range mit.ActiveBans() {
		if b.Dataplane != nil {
			t.Errorf("a dry-run ban carries measured drops: %+v", b.Dataplane)
		}
	}
	if fake.calls != 0 {
		t.Errorf("the data plane was read %d times for a dry-run ban; it should not be read at all", fake.calls)
	}
}

// TestNonDataplaneBansAreNotMeasured: a ban that is not on the dataplane rung
// has no rules in these maps, so it must carry no measurement — even when the
// kernel does hold counters for that prefix from an earlier incident.
//
// The fixture is an ALERT-ONLY rung rather than a blackhole so the ban is not
// also dry-run: kapkan defaults dry_run to true, a live blackhole would need a
// started BGP speaker, and a dry-run fixture would let this pass for the wrong
// reason (the dry-run branch instead of the method branch). The blackhole shape
// itself is pinned byte-for-byte by api.TestBlackholeBanJSONIsByteIdentical.
func TestNonDataplaneBansAreNotMeasured(t *testing.T) {
	mit, victim := banFixture(t, "none", false)
	for _, b := range mit.ActiveBans() {
		if b.DryRun {
			t.Fatal("the fixture is dry-run; this test would pass for the wrong reason")
		}
		if b.Method == config.MitigateDataplane {
			t.Fatalf("fixture produced a dataplane ban")
		}
	}
	fake := &fakeCounters{byVictim: map[netip.Prefix]dataplane.VictimCounters{
		victim: {PolicyID: 0, Rules: []dataplane.Counter{{Pkts: 999}}},
	}}
	s := newBanCounterScraper(fake, mit, discardLog(), nil)
	s.tick()
	for _, b := range mit.ActiveBans() {
		if b.Dataplane != nil {
			t.Errorf("a %q-method ban carries measured drops: %+v", b.Method, b.Dataplane)
		}
	}
	if fake.calls != 0 {
		t.Errorf("the data plane was read %d times for a non-dataplane ban", fake.calls)
	}
}

// TestWithdrawKeepsTheFinalTallyAndReleasesTheState is two properties that pull
// in opposite directions and must both hold.
//
// The withdrawn ban KEEPS its numbers: they are the last place the count exists
// once the map entries are reaped, and the bans history table and the ended
// attack record both read them. The SCRAPER releases its running state: it is
// keyed by victim and would otherwise grow for the life of the process, and a
// later ban on the same address must start a fresh count rather than inherit a
// previous incident's.
func TestWithdrawKeepsTheFinalTallyAndReleasesTheState(t *testing.T) {
	mit, victim := banFixture(t, "dataplane", false)
	fake := &fakeCounters{byVictim: map[netip.Prefix]dataplane.VictimCounters{
		victim: {PolicyID: 0, Rules: []dataplane.Counter{{Pkts: 7, Bytes: 3500}}},
	}}
	s := newBanCounterScraper(fake, mit, discardLog(), nil)
	s.tick()
	if activeDP(t, mit, victim).Packets != 7 {
		t.Fatal("the first scrape did not publish")
	}

	if _, err := mit.ManualUnban(victim.Addr()); err != nil {
		t.Fatal(err)
	}
	s.tick()

	var final *mitigate.BanDataplane
	for _, b := range mit.Snapshot() {
		if b.Prefix == victim {
			final = b.Dataplane
		}
	}
	if final == nil || final.Packets != 7 {
		t.Errorf("the withdrawn ban lost its final tally: %+v", final)
	}
	if len(s.state) != 0 {
		t.Errorf("scraper kept state for %d withdrawn victims", len(s.state))
	}
}

// TestPersistedTotalsAreContinued: a restart rehydrates the ban with its
// persisted lifetime total, and the first scrape must build on it. Starting from
// zero would silently discard everything the previous process measured, which is
// precisely the number the state file exists to carry.
func TestPersistedTotalsAreContinued(t *testing.T) {
	mit, victim := banFixture(t, "dataplane", false)
	// What rehydrateLocked leaves on the ban: totals, marked stale, no policy id.
	mit.SetDataplaneCounters(map[netip.Prefix]mitigate.BanDataplane{
		victim: {Packets: 1_000_000, Bytes: 500_000_000, Stale: true,
			Rules: []mitigate.BanDataplaneRule{{ID: 0, Packets: 1_000_000, Bytes: 500_000_000}}},
	})
	fake := &fakeCounters{byVictim: map[netip.Prefix]dataplane.VictimCounters{
		// A freshly re-installed block: the kernel counter starts near zero.
		victim: {PolicyID: 1, Rules: []dataplane.Counter{{Pkts: 12, Bytes: 6000}}},
	}}
	s := newBanCounterScraper(fake, mit, discardLog(), nil)
	s.tick()
	got := activeDP(t, mit, victim)
	if got.Packets != 1_000_012 || got.Bytes != 500_006_000 {
		t.Errorf("after rehydration + one scrape: %d pkts / %d bytes, want 1000012 / 500006000",
			got.Packets, got.Bytes)
	}
	if got.Stale {
		t.Error("a successful scrape must clear the stale flag the rehydration set")
	}
}

type errRead struct{}

func (errRead) Error() string { return "simulated map read failure" }

//go:build linux

package mitigate

// THE PCAP BLOCK-RATE SUITE.
//
// This is the file every public pps/Gbps/percentage claim rests on. Until it
// existed, kapkan's documentation was not allowed to state a single one.
//
// ==========================================================================
// WHY IT LIVES IN package mitigate
// ==========================================================================
// Because this is the only package that can see the WHOLE chain without an
// import cycle. internal/mitigate already imports internal/engine (the
// detector and the classifier) and internal/dataplane (the encoder, the
// installer, the maps), and it owns the two hops in between —
// generateRules and dataplaneRules. A suite anywhere else would have had to
// reach one of those through a seam that production does not use, and a seam
// that exists only for a test is exactly how a suite starts measuring
// something other than the product.
//
// It is an IN-PACKAGE test file (not mitigate_test) so it can reach the
// unexported announcer seam (withAnnouncer) that keeps eighteen fixtures from
// needing a BGP peer. It no longer needs in-package access for the carpet
// fixture: carpet.mitigation now accepts "dataplane", so the eighteenth fixture
// reaches the kernel through Mitigator.OnAttackStarted like the other
// seventeen, instead of calling dataplaneRules + Installer.Install by hand.
//
// ==========================================================================
// WHAT MAKES IT A FULL LOOP, AND WHY THAT IS THE POINT
// ==========================================================================
// Replaying frames against hand-written rules measures the BPF program. It
// does not measure the product, and the number it produces is not quotable.
// Every fixture here starts from TELEMETRY:
//
//	flowgen-shaped flow records
//	  -> engine.Engine.Process / evalTick   real windows, real thresholds
//	  -> engine.classify                    real vector inference
//	  -> Mitigator.OnAttackStarted -> ban   real safety rules, real ladder
//	  -> generateRules                      real FlowSpec IR
//	  -> dataplaneRules                     real IR -> RuleSpec encoder
//	  -> dataplane.Installer.Install        real ids, profiles, kernel maps
//	  -> committed pcap frames
//	  -> BPF_PROG_TEST_RUN                  real verdicts from a real kernel
//
// A regression at any hop fails the suite. A classifier that starts calling an
// ACK flood a SYN flood installs a tcp-flags rule that never fires, and the
// block rate goes to zero.
//
// ==========================================================================
// THE FIVE ASSERTIONS, PER FIXTURE
// ==========================================================================
//  1. block rate >= 0.98 (single-vector) or 0.95 (composite / rate-limited);
//  2. false-positive rate <= 0.001 against an interleaved legitimate baseline
//     that every fixture carries — without it a block rate is not a
//     measurement, since dropping everything scores 1.0;
//  3. allowlist inviolability: ZERO frames from an allowlisted source dropped;
//  4. with an EMPTY policy the block rate is exactly 0 — the anti-vacuity
//     gate, without which a suite that accidentally dropped everything
//     unconditionally would pass;
//  5. under dry_run the block rate is 0 and dryrun_would_drop equals the
//     live-mode drop count, packet for packet.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/kapkan-io/kapkan/internal/blockrate"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"
)

const (
	xdpDropVerdict = 1
	xdpPassVerdict = 2
)

/* ========================================================================= */
/* The host-scoped suite                                                      */
/* ========================================================================= */

// TestPcapBlockRateSuite runs the seventeen host-scoped fixtures against ONE
// kernel, ONE detector and ONE mitigator, simultaneously.
//
// Simultaneously is not an optimisation. Seventeen live policies at once is
// what a scrubber under a real incident looks like, and it turns every
// fixture's legitimate baseline into a test of every OTHER fixture's rules: a
// rule that widened past its victim shows up as somebody else's false
// positive rather than as a better block rate for itself.
func TestPcapBlockRateSuite(t *testing.T) {
	dir := bpffsDir(t, "blockrate")
	cfg, err := blockrate.ParseConfig(blockrate.ConfigYAML(dir))
	if err != nil {
		t.Fatalf("%v", err)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(&brWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mgr, prog := openDataplane(t, cfg, log)
	installer := dataplane.NewInstaller(mgr, log)

	runs := loadFixtures(t, blockrate.ScopeHost)
	t.Logf("loaded %d host fixtures, %d frames total, from committed captures",
		len(runs), totalFrames(runs))

	/* ---- 4. EMPTY POLICY: the anti-vacuity gate ------------------------- */

	for _, r := range runs {
		r.empty = runPass(t, prog, r)
	}
	for _, r := range runs {
		if r.empty.attackDropped != 0 {
			t.Fatalf("%s: %d/%d attack frames were dropped with NO policy installed. "+
				"Every rate this suite reports would be meaningless: something is dropping "+
				"unconditionally.", r.name(), r.empty.attackDropped, r.empty.attack)
		}
	}
	t.Logf("EMPTY POLICY: 0 of %d attack frames dropped across all fixtures (block rate exactly 0)",
		totalAttack(runs))

	/* ---- detection, from telemetry, through the real chain -------------- */

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng := engine.New(store, engine.WithLogger(log), engine.WithWindow(2))
	go eng.Run(ctx)

	mit, err := New(store, log, withAnnouncer(newRecorder()), WithDataplane(installer))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	if err := mit.Start(ctx); err != nil {
		t.Fatalf("mitigate.Start: %v", err)
	}
	defer mit.Stop()

	driveDetection(t, ctx, eng, runs)

	for _, r := range runs {
		verifyBan(t, mit, r)
	}

	/* ---- 5. DRY RUN: rewrites every drop, counts what it would have done -- */

	clearRateLimitBuckets(t, mgr) // the token bucket is stateful; both passes start level
	reloadDryRun(t, mgr, cfg, log, true)
	for _, r := range runs {
		before := readStats(t, mgr)
		r.dry = runPass(t, prog, r)
		after := readStats(t, mgr)
		r.wouldDrop = after[dataplane.StatDryRunWouldDrop].Pkts - before[dataplane.StatDryRunWouldDrop].Pkts
	}

	/* ---- 1..3. LIVE ----------------------------------------------------- */

	clearRateLimitBuckets(t, mgr)
	reloadDryRun(t, mgr, cfg, log, false)
	for _, r := range runs {
		before := readStats(t, mgr)
		beforeRules := victimCounters(t, installer, r)
		r.live = runPass(t, prog, r)
		after := readStats(t, mgr)
		r.rlDrops = after[dataplane.StatDropRL].Pkts - before[dataplane.StatDropRL].Pkts
		r.rlAdmits = after[dataplane.StatPassRLAdmit].Pkts - before[dataplane.StatPassRLAdmit].Pkts
		r.ruleHits = victimCounters(t, installer, r) - beforeRules
	}

	assertFixtures(t, runs)
	reportTable(t, runs)

	/* ---- the per-core numbers, on the rules the real chain installed ---- */

	measureThroughput(t, prog, runs)
}

/* ========================================================================= */
/* The carpet-bomb fixture                                                    */
/* ========================================================================= */

// TestPcapBlockRateSuiteCarpet runs the eighteenth fixture on its own, for one
// structural reason and no other: carpet detection aggregates EVERY protected
// host into its /24, so enabling it in the shared config would fold the other
// seventeen victims into one 203.0.113.0/24 attack and mitigate the whole
// prefix out from under them.
//
// It is otherwise the SAME test. Every hop is the product — per-host thresholds
// that deliberately never trip, the aggregate that does, the fan-out gate,
// banPrefix's safety rules, generateCarpetRules, dataplaneRules and
// Installer.Install — and every one of them is reached the way an operator
// reaches it, by setting carpet.mitigation: dataplane and letting
// Mitigator.OnAttackStarted do the rest. The suite used to make the last hop by
// hand because configuration could not express it; a number measured through a
// seam production does not use is a number about the seam.
//
// The ban is asserted to be METHOD dataplane, not merely active. A carpet ban
// that fell back would blackhole 256 addresses, and a blackhole is not measured
// by this program at all — the block rate would read 0.0 and the reason would
// have nothing to do with the data plane.
func TestPcapBlockRateSuiteCarpet(t *testing.T) {
	dir := bpffsDir(t, "blockrate-carpet")
	cfg, err := blockrate.ParseConfig(blockrate.CarpetConfigYAML(dir))
	if err != nil {
		t.Fatalf("%v", err)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(&brWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mgr, prog := openDataplane(t, cfg, log)
	installer := dataplane.NewInstaller(mgr, log)

	runs := loadFixtures(t, blockrate.ScopePrefix)
	if len(runs) != 1 {
		t.Fatalf("expected exactly one prefix-scoped fixture, got %d", len(runs))
	}
	r := runs[0]

	r.empty = runPass(t, prog, r)
	if r.empty.attackDropped != 0 {
		t.Fatalf("%s: %d attack frames dropped with no policy installed", r.name(), r.empty.attackDropped)
	}
	t.Logf("EMPTY POLICY: 0 of %d attack frames dropped (block rate exactly 0)", r.empty.attack)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := engine.New(store, engine.WithLogger(log), engine.WithWindow(2))
	go eng.Run(ctx)
	mit, err := New(store, log, withAnnouncer(newRecorder()), WithDataplane(installer))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	if err := mit.Start(ctx); err != nil {
		t.Fatalf("mitigate.Start: %v", err)
	}
	defer mit.Stop()

	driveDetection(t, ctx, eng, runs)

	ban := mit.OnAttackStarted(r.ev)
	if ban == nil || ban.State != BanActive {
		t.Fatalf("carpet ban = %+v, want an active ban", ban)
	}
	if ban.Method != config.MitigateDataplane {
		t.Fatalf("carpet ban method %q (fell back from %q: %s), want %q — nothing reached the "+
			"kernel, and a carpet fallback null-routes the whole %s",
			ban.Method, ban.FellBackFrom, ban.FellBackReason, config.MitigateDataplane, r.fx.Prefix)
	}
	if len(ban.FlowSpec) != r.fx.WantRuleCount {
		t.Fatalf("generateCarpetRules produced %d rules, want %d: %v",
			len(ban.FlowSpec), r.fx.WantRuleCount, ban.FlowSpec)
	}
	if got := ban.FlowSpec[0].Dst; got != r.fx.Prefix {
		t.Fatalf("the carpet rule anchors on %s, want the whole aggregation prefix %s", got, r.fx.Prefix)
	}
	r.ban = ban
	r.detectedClass = r.ev.Classification.Type
	r.installedRuleCount = len(ban.FlowSpec)
	r.installedRuleString = ban.FlowSpec[0].String()
	t.Logf("CARPET  %s -> %s (method %s, installed by the mitigator)",
		r.fx.Prefix, ban.FlowSpec[0], ban.Method)

	clearRateLimitBuckets(t, mgr)
	reloadDryRun(t, mgr, cfg, log, true)
	before := readStats(t, mgr)
	r.dry = runPass(t, prog, r)
	r.wouldDrop = readStats(t, mgr)[dataplane.StatDryRunWouldDrop].Pkts - before[dataplane.StatDryRunWouldDrop].Pkts

	clearRateLimitBuckets(t, mgr)
	reloadDryRun(t, mgr, cfg, log, false)
	beforeRules := victimCounters(t, installer, r)
	r.live = runPass(t, prog, r)
	r.ruleHits = victimCounters(t, installer, r) - beforeRules

	assertFixtures(t, runs)
	reportTable(t, runs)

	/* ---- the withdraw, on the widest rule the product installs ---------- */

	// A carpet rule covers 256 addresses. "It came down cleanly" is therefore a
	// safety property, not housekeeping: a stranded /24 rule keeps filtering a
	// whole customer subnet that the mitigator no longer believes is banned.
	mit.OnAttackEnded(engine.Event{
		Kind: engine.AttackEnded, Scope: engine.ScopePrefix,
		Prefix: r.fx.Prefix.String(), At: time.Now(),
	})
	if n := len(mit.ActiveBans()); n != 0 {
		t.Errorf("active bans = %d after the carpet attack ended, want 0", n)
	}
	if _, ok, err := installer.Counters(r.fx.Prefix); err != nil {
		t.Fatalf("reading the policy block for %s after the withdraw: %v", r.fx.Prefix, err)
	} else if ok {
		t.Errorf("the policy block for %s is STILL in the kernel after the ban was withdrawn; "+
			"a /24 of rules outlived the mitigation that installed them", r.fx.Prefix)
	}
	after := runPass(t, prog, r)
	if after.attackDropped != 0 {
		t.Errorf("AFTER the withdraw %d/%d attack frames were still dropped: the rules outlived "+
			"the ban", after.attackDropped, after.attack)
	}
	t.Logf("WITHDRAWN  %s: policy block gone, 0 of %d attack frames dropped",
		r.fx.Prefix, after.attack)
}

/* ========================================================================= */
/* One fixture's state through the run                                        */
/* ========================================================================= */

type tally struct {
	attack, attackDropped int
	legit, legitDropped   int
	allow, allowDropped   int
}

func (t tally) blockRate() float64 {
	if t.attack == 0 {
		return 0
	}
	return float64(t.attackDropped) / float64(t.attack)
}

func (t tally) falsePositiveRate() float64 {
	if t.legit == 0 {
		return 0
	}
	return float64(t.legitDropped) / float64(t.legit)
}

type fixtureRun struct {
	fx      blockrate.Fixture
	packets [][]byte

	ev  engine.Event
	ban *Ban

	empty, dry, live  tally
	wouldDrop         uint64
	rlDrops, rlAdmits uint64
	// ruleHits is what kapkan_rule_stats recorded for THIS ban across the live
	// pass — the number an operator reads on /api/v1/bans. It is asserted
	// against the verdicts because the two are separately derived: the verdicts
	// come back from PROG_TEST_RUN, the counters from a map the datapath bumps
	// on a different line.
	ruleHits            uint64
	detectedClass       engine.AttackType
	installedRuleCount  int
	installedSrcAnchor  bool
	installedRuleString string
}

func (r *fixtureRun) name() string { return r.fx.Name }

/* ========================================================================= */
/* Loading, replaying, tallying                                               */
/* ========================================================================= */

// loadFixtures reads the COMMITTED captures — never the in-memory catalog —
// and builds each frame once. Reading the files is the point: a number
// measured on bytes the repository does not contain is not reproducible.
func loadFixtures(t *testing.T, scope blockrate.Scope) []*fixtureRun {
	t.Helper()
	var out []*fixtureRun
	for _, fx := range blockrate.Fixtures() {
		if fx.Scope != scope {
			continue
		}
		frames, err := fx.CommittedFrames()
		if err != nil {
			t.Fatalf("%v", err)
		}
		pkts := make([][]byte, len(frames))
		for i, f := range frames {
			b, err := f.Build()
			if err != nil {
				t.Fatalf("%s: rebuilding frame %d from the capture: %v", fx.Name, i, err)
			}
			pkts[i] = b
		}
		out = append(out, &fixtureRun{fx: fx, packets: pkts})
	}
	return out
}

// runPass replays one fixture's whole capture and tallies verdicts by role.
func runPass(t *testing.T, prog *ebpf.Program, r *fixtureRun) tally {
	t.Helper()
	var got tally
	for i, pkt := range r.packets {
		ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			t.Fatalf("%s: BPF_PROG_TEST_RUN on frame %d: %v", r.name(), i, err)
		}
		dropped := ret == xdpDropVerdict
		if ret != xdpDropVerdict && ret != xdpPassVerdict {
			t.Fatalf("%s: frame %d got verdict XDP_%d, want DROP or PASS — the charter says "+
				"the data plane only ever passes or drops", r.name(), i, ret)
		}
		switch r.fx.Roles[i] {
		case blockrate.RoleAttack:
			got.attack++
			if dropped {
				got.attackDropped++
			}
		case blockrate.RoleLegit:
			got.legit++
			if dropped {
				got.legitDropped++
			}
		case blockrate.RoleAllow:
			got.allow++
			if dropped {
				got.allowDropped++
			}
		}
	}
	return got
}

/* ========================================================================= */
/* Detection                                                                  */
/* ========================================================================= */

// driveDetection feeds every fixture's telemetry into ONE engine until each
// has reported an attack, then records the event on its run.
//
// All fixtures are fed together on purpose: it keeps the whole suite inside a
// few seconds of wall clock (the detector's window is real time and cannot be
// faked from outside the package), and it exercises the engine with the
// several-simultaneous-victims shape a scrubber actually sees.
func driveDetection(t *testing.T, ctx context.Context, eng *engine.Engine, runs []*fixtureRun) {
	t.Helper()
	pending := map[string]*fixtureRun{}
	for _, r := range runs {
		pending[r.fx.Target()] = r
	}

	deadline := time.Now().Add(60 * time.Second)
	for len(pending) > 0 && time.Now().Before(deadline) {
		for _, r := range runs {
			for _, f := range r.fx.Telemetry {
				eng.Process(f)
			}
		}
		drain := time.After(60 * time.Millisecond)
	inner:
		for {
			select {
			case ev := <-eng.Events():
				if ev.Kind != engine.AttackStarted {
					continue
				}
				key := ev.Target.String()
				if ev.Scope == engine.ScopePrefix {
					key = ev.Prefix
				}
				if r, ok := pending[key]; ok {
					r.ev = ev
					delete(pending, key)
				}
			case <-ctx.Done():
				t.Fatal("context cancelled before every fixture was detected")
			case <-drain:
				break inner
			}
		}
	}
	if len(pending) > 0 {
		var missing []string
		for k := range pending {
			missing = append(missing, k)
		}
		sort.Strings(missing)
		t.Fatalf("the engine never reported an attack for %v; the telemetry did not trip the "+
			"thresholds, so nothing downstream can be measured", missing)
	}

	for _, r := range runs {
		if r.ev.Classification == nil {
			t.Fatalf("%s: detection carried NO classification; the rules would fall back to an "+
				"anchor-only blackhole and the fixture would measure the wrong thing", r.name())
		}
		r.detectedClass = r.ev.Classification.Type
		if r.detectedClass != r.fx.WantClass {
			t.Errorf("%s: the classifier said %q, fixture expects %q (confidence %.2f). "+
				"A misclassification installs a rule for a different vector; the block rate "+
				"below is measuring that mistake, not the data plane.",
				r.name(), r.detectedClass, r.fx.WantClass, r.ev.Classification.Confidence)
		}
	}
}

// verifyBan asserts the ban the real mitigator produced is the one the fixture
// describes: enforced in the KERNEL (not degraded to a blackhole), with the
// rule count and anchoring shape the vector calls for.
func verifyBan(t *testing.T, mit *Mitigator, r *fixtureRun) {
	t.Helper()
	ban := mit.OnAttackStarted(r.ev)
	if ban == nil {
		t.Fatalf("%s: OnAttackStarted returned nil; policy refused to mitigate", r.name())
	}
	if ban.State != BanActive {
		t.Fatalf("%s: ban state %q (%s), want active", r.name(), ban.State, ban.Reason)
	}
	if ban.Method != config.MitigateDataplane {
		t.Fatalf("%s: ban method %q (fell back from %q: %s), want %q — the rules never reached "+
			"the kernel, so the block rate below would be zero for a reason that has nothing "+
			"to do with the data plane",
			r.name(), ban.Method, ban.FellBackFrom, ban.FellBackReason, config.MitigateDataplane)
	}
	r.ban = ban
	r.installedRuleCount = len(ban.FlowSpec)
	if r.fx.WantRuleCount != 0 && r.installedRuleCount != r.fx.WantRuleCount {
		t.Errorf("%s: generateRules produced %d rules, want %d: %v",
			r.name(), r.installedRuleCount, r.fx.WantRuleCount, ban.FlowSpec)
	}
	if len(ban.FlowSpec) > 0 {
		r.installedRuleString = ban.FlowSpec[0].String()
		r.installedSrcAnchor = ban.FlowSpec[0].Src.IsValid() && ban.FlowSpec[0].Dst.IsValid()
	}
	if r.installedSrcAnchor != r.fx.WantSourceAnchored {
		t.Errorf("%s: source-anchored = %v, want %v (rules: %v)",
			r.name(), r.installedSrcAnchor, r.fx.WantSourceAnchored, ban.FlowSpec)
	}
}

/* ========================================================================= */
/* Assertions                                                                 */
/* ========================================================================= */

func assertFixtures(t *testing.T, runs []*fixtureRun) {
	t.Helper()
	for _, r := range runs {
		// 1. block rate.
		if got := r.live.blockRate(); got < r.fx.MinBlockRate {
			t.Errorf("%s: BLOCK RATE %.4f (%d/%d attack frames dropped), want >= %.2f. Rule: %s",
				r.name(), got, r.live.attackDropped, r.live.attack, r.fx.MinBlockRate,
				r.installedRuleString)
		}
		// 2. false positives.
		if got := r.live.falsePositiveRate(); got > r.fx.MaxFalsePositiveRate {
			t.Errorf("%s: FALSE-POSITIVE RATE %.4f (%d/%d legitimate frames dropped), want <= %.4f. "+
				"A mitigation that takes the victim's real traffic with the attack is not a "+
				"mitigation. Rule: %s",
				r.name(), got, r.live.legitDropped, r.live.legit, r.fx.MaxFalsePositiveRate,
				r.installedRuleString)
		}
		// 3. the allowlist is absolute.
		if r.live.allowDropped != 0 {
			t.Errorf("%s: %d/%d frames from an ALLOWLISTED source were dropped. Precedence 1 is "+
				"the one guarantee an operator gets unconditionally; it does not have a rate.",
				r.name(), r.live.allowDropped, r.live.allow)
		}
		// 4. empty policy (already fatal above, restated per fixture).
		if r.empty.attackDropped != 0 {
			t.Errorf("%s: %d attack frames dropped under an EMPTY policy", r.name(), r.empty.attackDropped)
		}
		// 5. dry run.
		if r.dry.attackDropped != 0 || r.dry.legitDropped != 0 || r.dry.allowDropped != 0 {
			t.Errorf("%s: dry_run dropped %d attack / %d legit / %d allowlisted frames; dry_run "+
				"must rewrite EVERY drop to a pass",
				r.name(), r.dry.attackDropped, r.dry.legitDropped, r.dry.allowDropped)
		}
		liveDrops := uint64(r.live.attackDropped + r.live.legitDropped + r.live.allowDropped)
		if r.wouldDrop != liveDrops {
			t.Errorf("%s: dryrun_would_drop = %d but live mode dropped %d. The counter an "+
				"operator uses to decide whether to arm the filter must equal what arming it "+
				"would actually do.", r.name(), r.wouldDrop, liveDrops)
		}
		// The operator-visible number. kapkan_rule_stats counts every packet a
		// rule MATCHED, which for a discard rule is the drop count and for a
		// rate-limit rule is drops plus admits (the bucket decides after the
		// counter is bumped). If these diverge, /api/v1/bans is telling an
		// operator a different story than the wire.
		if want := liveDrops + r.rlAdmits; r.ruleHits != want {
			t.Errorf("%s: kapkan_rule_stats recorded %d matched packets for this ban, but the "+
				"verdicts say %d (%d dropped + %d rate-limit admits). The number on /api/v1/bans "+
				"and the number on the wire must be the same number.",
				r.name(), r.ruleHits, want, liveDrops, r.rlAdmits)
		}
	}
}

// victimCounters sums the ban's per-rule kernel counters, or 0 when the fixture
// has no ban yet (the empty-policy pass).
func victimCounters(t *testing.T, installer *dataplane.Installer, r *fixtureRun) uint64 {
	t.Helper()
	if r.ban == nil {
		return 0
	}
	vc, ok, err := installer.Counters(r.ban.Prefix)
	if err != nil {
		t.Fatalf("%s: reading kapkan_rule_stats for %s: %v", r.name(), r.ban.Prefix, err)
	}
	if !ok {
		t.Fatalf("%s: no policy block for %s; the rules are not installed", r.name(), r.ban.Prefix)
	}
	return vc.Total().Pkts
}

/* ========================================================================= */
/* Output                                                                     */
/* ========================================================================= */

func reportTable(t *testing.T, runs []*fixtureRun) {
	t.Helper()
	t.Log("")
	t.Log("PCAP BLOCK-RATE SUITE — measured on this kernel, from committed captures")
	t.Logf("%-26s %-24s %6s %6s %6s %6s %8s %6s %8s",
		"fixture", "classified", "atk", "block", "legit", "fp", "wouldDrp", "allow", "ruleHits")
	for _, r := range runs {
		t.Logf("%-26s %-24s %6d %6.4f %6d %6.4f %8d %6d %8d",
			r.fx.Name, string(r.detectedClass),
			r.live.attack, r.live.blockRate(),
			r.live.legit, r.live.falsePositiveRate(),
			r.wouldDrop, r.live.allowDropped, r.ruleHits)
	}
	t.Log("")
	for _, r := range runs {
		t.Logf("%-26s rules=%d  %s", r.fx.Name, r.installedRuleCount, r.installedRuleString)
		if r.rlDrops > 0 || r.rlAdmits > 0 {
			t.Logf("%-26s token bucket: %d admitted, %d denied (per-source ceiling)",
				"", r.rlAdmits, r.rlDrops)
		}
	}
	t.Log("")
}

/* ========================================================================= */
/* Per-core throughput                                                        */
/* ========================================================================= */

// measureThroughput reports the per-core packet rate of the three hot paths,
// measured with the KERNEL's own PROG_TEST_RUN repeat loop against THE RULES
// THIS SUITE'S DETECTOR JUST INSTALLED — not a hand-built worst case.
//
// ==========================================================================
// WHAT THIS NUMBER IS, AND WHAT IT IS NOT
// ==========================================================================
// IT IS: the cost of one execution of kapkan_xdp_filter on one core, averaged
// over a large repeat count inside a single bpf(2) syscall, on the machine the
// test ran on, against a real policy.
//
// IT IS NOT a line-rate claim, and it must never be quoted as one. There is no
// NIC in this measurement: no DMA, no descriptor ring, no driver, no per-packet
// page allocation, no interrupt, no cache pressure from real traffic, no PCIe.
// PROG_TEST_RUN re-runs the program over one already-warm buffer, so it is the
// UPPER BOUND of the program's own cost and nothing else. Real forwarding
// throughput on a real NIC is lower, by a factor that depends on the driver,
// the XDP mode (native vs generic), the queue count and the packet size — none
// of which this measures.
//
// It also says nothing about aggregate capacity: multiply by cores at your own
// risk, because memory bandwidth and the LRU maps are shared.
//
// The honest use of these numbers is COMPARATIVE — this release against the
// last, the drop path against the pass path, one rule count against another.
func measureThroughput(t *testing.T, prog *ebpf.Program, runs []*fixtureRun) {
	t.Helper()
	const repeat = 200000

	byName := map[string]*fixtureRun{}
	for _, r := range runs {
		byName[r.fx.Name] = r
	}

	type probe struct {
		label   string
		pkt     []byte
		want    uint32
		explain string
	}
	var probes []probe

	if r := byName["udp_flood_v4"]; r != nil {
		probes = append(probes, probe{
			label: "drop  (dynamic dst rule)", pkt: r.packets[firstOfRole(r, blockrate.RoleAttack)],
			want:    xdpDropVerdict,
			explain: "victim LPM hit, 1-rule policy block, first rule matches",
		})
		probes = append(probes, probe{
			label: "pass  (fall-through)", pkt: r.packets[firstOfRole(r, blockrate.RoleLegit)],
			want:    xdpPassVerdict,
			explain: "allow miss, protect miss, no statics, victim hit, no rule matches",
		})
	}
	if r := byName["source_flood_ratelimit"]; r != nil {
		probes = append(probes, probe{
			label: "ratelimit (bucket empty)", pkt: r.packets[firstOfRole(r, blockrate.RoleAttack)],
			want:    xdpDropVerdict,
			explain: "composite rule, LRU bucket lookup + Q32 refill, denied",
		})
	}

	t.Log("PER-CORE THROUGHPUT (BPF_PROG_TEST_RUN, repeat=200000)")
	t.Log("  SYNTHETIC, PER-CORE, NO NIC. This is the cost of the program alone: no driver,")
	t.Log("  no DMA, no descriptor ring, no interrupt, one warm buffer re-run in a loop.")
	t.Log("  It is an UPPER BOUND on the program's own cost and NOT a line-rate claim.")
	t.Log("  Real forwarding throughput on a real NIC is lower. Do not multiply by cores.")
	t.Logf("  %-26s %10s %10s   %s", "path", "ns/pkt", "Mpps/core", "what it exercises")
	for _, p := range probes {
		ret, per, err := prog.Benchmark(p.pkt, repeat, nil)
		if err != nil {
			t.Fatalf("PROG_TEST_RUN benchmark (%s): %v", p.label, err)
		}
		if ret != p.want {
			t.Fatalf("%s: verdict XDP_%d during the benchmark, want XDP_%d — the measurement "+
				"is of the wrong path", p.label, ret, p.want)
		}
		ns := float64(per.Nanoseconds())
		mpps := 0.0
		if ns > 0 {
			mpps = 1000.0 / ns
		}
		t.Logf("  %-26s %10.1f %10.2f   %s", p.label, ns, mpps, p.explain)
	}
	t.Log("")
}

// firstOfRole returns the index of the first frame with the given role.
func firstOfRole(r *fixtureRun, want blockrate.Role) int {
	for i, got := range r.fx.Roles {
		if got == want {
			return i
		}
	}
	return 0
}

/* ========================================================================= */
/* Kernel plumbing                                                            */
/* ========================================================================= */

// openDataplane brings up the real Manager and returns it with a handle on the
// program it PINNED — the same program an operator's kernel would be running,
// reached the way an outside observer would reach it.
func openDataplane(t *testing.T, cfg *config.Config, log *slog.Logger) (*dataplane.Manager, *ebpf.Program) {
	t.Helper()
	opts, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	opts.Log = log
	opts.WatchInterval = -1
	mgr, err := dataplane.Open(opts)
	if err != nil {
		skipOrFail(t, "cannot bring up the data plane here (%v); run `make blockrate`", err)
	}
	t.Cleanup(func() { _ = mgr.Close(config.OnExitDetach) })

	path := filepath.Join(cfg.DataplaneCfg.PinPath, "prog")
	prog, err := ebpf.LoadPinnedProgram(path, nil)
	if err != nil {
		t.Fatalf("open the pinned program at %s: %v", path, err)
	}
	t.Cleanup(func() { _ = prog.Close() })
	return mgr, prog
}

// reloadDryRun flips the kernel's dry_run flag through the REAL reload path,
// so the suite exercises what an operator's SIGHUP does rather than poking
// kapkan_cfg behind the manager's back.
func reloadDryRun(t *testing.T, mgr *dataplane.Manager, cfg *config.Config, log *slog.Logger, dry bool) {
	t.Helper()
	next, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	next.Log = log
	next.WatchInterval = -1
	next.DryRun = dry
	if _, err := mgr.Reload(next); err != nil {
		t.Fatalf("Reload(dry_run=%v): %v", dry, err)
	}
	if got := mgr.EffectiveDryRun(); got != dry {
		t.Fatalf("EffectiveDryRun() = %v after reloading with dry_run=%v; the kernel did not "+
			"take the flag", got, dry)
	}
}

// clearRateLimitBuckets empties the token-bucket LRUs.
//
// It exists for one fixture and one assertion. The bucket is STATEFUL: the
// dry-run pass and the live pass replay the same frames, and whichever runs
// second would find the buckets already drained and deny a frame the first
// pass admitted. That would make dryrun_would_drop differ from the live drop
// count by exactly the number of attacking sources — a difference with no
// meaning at all. Levelling the buckets between passes is what makes the two
// numbers comparable.
func clearRateLimitBuckets(t *testing.T, mgr *dataplane.Manager) {
	t.Helper()
	maps := mgr.Maps()
	if maps == nil {
		t.Fatal("the manager is closed")
	}

	var k4 dataplane.RLKeyV4
	var b dataplane.Bucket
	var stale4 []dataplane.RLKeyV4
	it := maps.KapkanRlSrc4.Iterate()
	for it.Next(&k4, &b) {
		stale4 = append(stale4, k4)
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate kapkan_rl_src4: %v", err)
	}
	for _, k := range stale4 {
		if err := maps.KapkanRlSrc4.Delete(&k); err != nil && !isKeyMissing(err) {
			t.Fatalf("delete kapkan_rl_src4 entry: %v", err)
		}
	}

	var k6 dataplane.RLKeyV6
	var stale6 []dataplane.RLKeyV6
	it = maps.KapkanRlSrc6.Iterate()
	for it.Next(&k6, &b) {
		stale6 = append(stale6, k6)
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate kapkan_rl_src6: %v", err)
	}
	for _, k := range stale6 {
		if err := maps.KapkanRlSrc6.Delete(&k); err != nil && !isKeyMissing(err) {
			t.Fatalf("delete kapkan_rl_src6 entry: %v", err)
		}
	}
}

// isKeyMissing reports a benign delete race: an LRU may evict between the
// iteration and the delete.
func isKeyMissing(err error) bool { return err != nil && os.IsNotExist(err) }

func readStats(t *testing.T, mgr *dataplane.Manager) [dataplane.StatMax]dataplane.Counter {
	t.Helper()
	maps := mgr.Maps()
	if maps == nil {
		t.Fatal("the manager is closed")
	}
	c, err := dataplane.ReadStats(maps)
	if err != nil {
		t.Fatalf("ReadStats: %v", err)
	}
	return c
}

// bpfFSMagic is BPF_FS_MAGIC from <linux/magic.h>.
const bpfFSMagic = 0xcafe4a11

// skipOrFail skips on a host that cannot run the kernel half — the macOS
// development loop, a container with no bpffs — unless KAPKAN_BLOCKRATE is set
// to "require", in which case it FAILS.
//
// That knob is what makes CI an enforcement point instead of a very confident
// no-op. This suite is the gate on every published performance figure, and a
// gate that silently degrades to a skip when the environment shifts (a runner
// image without bpffs, a capability set trimmed one bit too far) is worse than
// no gate at all: it keeps reporting green while measuring nothing. Same
// pattern, and same reasoning, as KAPKAN_BPF_DRIFT=require on the object drift
// gate.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("KAPKAN_BLOCKRATE") == "require" {
		t.Fatalf("KAPKAN_BLOCKRATE=require: "+format, args...)
	}
	t.Skipf(format, args...)
}

// bpffsDir returns a fresh pin directory on a bpffs mount.
//
// The root honours KAPKAN_BPFFS so CI can point the suite at a mount the
// unprivileged test user owns: the stock /sys/fs/bpf is root-only, and the CI
// job that runs this deliberately holds three capabilities and no more. Inside
// the privileged container `make blockrate` uses there is no bpffs at all
// until something mounts one, so this mounts it — and skips, rather than
// fails, when it cannot, because that is the macOS developer loop where the
// kernel half of the suite is not expected to run.
func bpffsDir(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv("KAPKAN_BPFFS")
	if root == "" {
		root = "/sys/fs/bpf"
	}
	if !isBpffs(root) {
		if err := os.MkdirAll(root, 0o755); err != nil {
			skipOrFail(t, "no bpffs at %s (%v); run `make blockrate`", root, err)
		}
		if err := syscall.Mount("bpffs", root, "bpf", 0, ""); err != nil {
			skipOrFail(t, "no bpffs at %s and it could not be mounted (%v); run `make blockrate`", root, err)
		}
	}
	dir := filepath.Join(root, "kapkan-"+name)
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func isBpffs(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return uint64(st.Type) == bpfFSMagic //nolint:unconvert // Type is int64 on some arches
}

func totalFrames(runs []*fixtureRun) int {
	var n int
	for _, r := range runs {
		n += len(r.packets)
	}
	return n
}

func totalAttack(runs []*fixtureRun) int {
	var n int
	for _, r := range runs {
		n += r.empty.attack
	}
	return n
}

// brWriter routes slog output through t.Log so the narration lands next to the
// assertions it explains.
type brWriter struct{ t *testing.T }

func (w *brWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

package mitigate

// Tests for the data-plane ladder rung: the seam, the lifecycle, and every
// safety property the feature had to preserve.
//
// The backend here is a recorder, not a kernel. That is the point of the split:
// these tests answer "does the MITIGATOR do the right thing", on every host and
// in milliseconds, while internal/dataplane's container tests answer "does the
// kernel drop the packet". Neither can substitute for the other, and running
// the ladder logic only inside a privileged container would mean the safety
// gates — dry-run, the whitelist, the caps, the TTL — were exercised by
// whoever remembered to run `make dataplane-test`.

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"
)

/* ------------------------------------------------------------ the recorder */

// dpRecorder is a dataplaneBackend that records calls and can be told to fail.
type dpRecorder struct {
	mu        sync.Mutex
	installs  []dpInstall
	withdraws []netip.Prefix
	failWith  error
	events    []string
}

type dpInstall struct {
	victim netip.Prefix
	rules  dataplane.DynamicRules
}

func (d *dpRecorder) Install(victim netip.Prefix, rules dataplane.DynamicRules) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failWith != nil {
		d.events = append(d.events, "install-failed "+victim.String())
		return d.failWith
	}
	d.installs = append(d.installs, dpInstall{victim: victim, rules: rules})
	d.events = append(d.events, "dp-install "+victim.String())
	return nil
}

func (d *dpRecorder) Withdraw(victim netip.Prefix) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.withdraws = append(d.withdraws, victim)
	d.events = append(d.events, "dp-withdraw "+victim.String())
	return nil
}

func (d *dpRecorder) installCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.installs)
}

func (d *dpRecorder) withdrawCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.withdraws)
}

func (d *dpRecorder) lastInstall(t *testing.T) dpInstall {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.installs) == 0 {
		t.Fatal("no install was recorded")
	}
	return d.installs[len(d.installs)-1]
}

func (d *dpRecorder) log() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.events...)
}

/* ------------------------------------------------------------- fixtures */

// dpYAML is the base config plus a data plane and a ladder that uses it.
// config.requireDataplane refuses the action without the block, so the two
// always travel together.
func dpYAML(extra string) string {
	return "dry_run: false\n" + baseYAML() + `
dataplane:
  enabled: true
  interfaces: ["eth0"]
escalation:
  - {after_seconds: 0, action: dataplane}
` + extra
}

func newDataplaneMitigator(t *testing.T, yaml string, dp dataplaneBackend, clk *mockClock) (*Mitigator, *recorder) {
	t.Helper()
	rec := newRecorder()
	store := storeFrom(t, yaml)
	opts := []Option{withAnnouncer(rec), WithDataplane(dp)}
	if clk != nil {
		opts = append(opts, WithClock(clk.Now))
	}
	m, err := New(store, testLogger(t), opts...)
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()
	return m, rec
}

func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, nil))
}

/* ------------------------------------------------------- the happy path */

// TestDataplaneRungInstallsAndWithdraws is the whole feature in one test: an
// attack installs rules, the attack ending removes them.
func TestDataplaneRungInstallsAndWithdraws(t *testing.T) {
	dp := &dpRecorder{}
	m, rec := newDataplaneMitigator(t, dpYAML(""), dp, nil)

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.State != BanActive {
		t.Fatalf("ban state = %s (%s), want active", b.State, b.Reason)
	}
	if b.Method != config.MitigateDataplane {
		t.Fatalf("method = %q, want %q", b.Method, config.MitigateDataplane)
	}
	if !strings.HasPrefix(b.Route, "dataplane: ") {
		t.Errorf("route = %q, want a dataplane summary", b.Route)
	}

	if dp.installCount() != 1 {
		t.Fatalf("installs = %d, want 1", dp.installCount())
	}
	in := dp.lastInstall(t)
	if in.victim != netip.MustParsePrefix("203.0.113.5/32") {
		t.Errorf("installed for %s, want the victim host prefix", in.victim)
	}
	if len(in.rules.Specs) == 0 {
		t.Error("installed an empty rule set")
	}
	// Nothing was announced to a peer: this rung is local by definition.
	if len(rec.eventLog()) != 0 {
		t.Errorf("the dataplane rung announced something to BGP: %v", rec.eventLog())
	}

	m.OnAttackEnded(endedEvent("203.0.113.5"))
	if dp.withdrawCount() != 1 {
		t.Fatalf("withdraws = %d, want 1", dp.withdrawCount())
	}
}

// TestDataplaneRuleTTLIsTheBanTTL checks the deadline handed to the kernel is
// the ban's own, which is what makes the in-kernel expiry a real backstop for a
// crashed userspace rather than an unrelated timer.
func TestDataplaneRuleTTLIsTheBanTTL(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	m, _ := newDataplaneMitigator(t, dpYAML(""), dp, clk)

	m.OnAttackStarted(startedEvent("203.0.113.5"))
	got := dp.lastInstall(t).rules.TTL
	want := m.store.Get().Ban.TTL()
	if got != want {
		t.Errorf("installed ttl = %s, want the ban ttl %s: a rule that outlives its ban would keep "+
			"filtering a customer after the mitigation was withdrawn", got, want)
	}
	if got <= 0 {
		t.Error("a non-positive ttl encodes as 'never expires' in the kernel")
	}
}

/* --------------------------------------------------------------- dry run */

// TestDryRunInstallsNothing is the first safety property: dry-run announces
// nothing and installs nothing.
func TestDryRunInstallsNothing(t *testing.T) {
	dp := &dpRecorder{}
	// baseYAML defaults dry_run to true; dpYAML forces it off, so build the
	// dry-run variant by hand.
	yaml := strings.Replace(dpYAML(""), "dry_run: false\n", "dry_run: true\n", 1)
	m, _ := newDataplaneMitigator(t, yaml, dp, nil)

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.State != BanActive {
		t.Fatalf("ban state = %s (%s), want active", b.State, b.Reason)
	}
	if !b.DryRun {
		t.Fatal("the ban did not freeze dry-run")
	}
	if n := dp.installCount(); n != 0 {
		t.Fatalf("DRY-RUN INSTALLED %d rule sets into the kernel", n)
	}

	m.OnAttackEnded(endedEvent("203.0.113.5"))
	if n := dp.withdrawCount(); n != 0 {
		t.Fatalf("DRY-RUN called Withdraw %d times; it never installed anything", n)
	}
	if ev := dp.log(); len(ev) != 0 {
		t.Fatalf("DRY-RUN touched the data plane: %v", ev)
	}
}

// TestDryRunGateIsAboveTheDataplaneBranch proves the property structurally as
// well as behaviourally.
//
// The behavioural test above passes for the wrong reason if someone moves the
// dataplane branch ABOVE the dry-run early return and the recorder happens not
// to be reached for some other cause. The gate's position in
// announceMethodLocked is the actual guarantee — it is what makes dry-run
// unbypassable for EVERY method, including ones nobody has written yet — so
// assert on it directly.
func TestDryRunGateIsAboveTheDataplaneBranch(t *testing.T) {
	src, err := os.ReadFile("mitigate.go")
	if err != nil {
		t.Fatalf("read mitigate.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (m *Mitigator) announceMethodLocked(")
	if start < 0 {
		t.Fatal("announceMethodLocked not found; this test needs updating")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n// installDataplaneLocked"); end > 0 {
		fn = fn[:end]
	}
	gate := strings.Index(fn, "if cfg.DryRun {")
	branch := strings.Index(fn, "if method == config.MitigateDataplane {")
	if gate < 0 || branch < 0 {
		t.Fatalf("could not find both the dry-run gate (%d) and the dataplane branch (%d) "+
			"in announceMethodLocked", gate, branch)
	}
	if gate > branch {
		t.Fatal("the data-plane branch is ABOVE the dry-run early return in announceMethodLocked: " +
			"a dry-run ban would install real rules in the kernel")
	}
}

/* ------------------------------------------------------------- whitelist */

// TestWhitelistIsAbsoluteForTheDataplane checks the userspace half of the
// two-layer whitelist guarantee: ban() refuses a whitelisted target before any
// backend is consulted.
//
// The kernel half — protected_whitelist mirrored into kapkan_protect4/6, which
// is precedence 2 and stops evaluation before any dynamic rule is read — is
// proved on a real kernel by TestProtectedWhitelistBeatsAnInstalledRule in
// internal/dataplane. Both layers are needed: this one stops a rule being
// created, that one stops a rule that already exists (rehydrated from a
// previous process, or racing an operator's edit) from dropping a protected
// customer's traffic.
func TestWhitelistIsAbsoluteForTheDataplane(t *testing.T) {
	dp := &dpRecorder{}
	m, _ := newDataplaneMitigator(t, dpYAML(""), dp, nil)

	// 203.0.113.1 is in baseYAML's protected_whitelist.
	b := m.OnAttackStarted(startedEvent("203.0.113.1"))
	if b.State != BanRejected || b.Reason != "whitelisted" {
		t.Fatalf("ban state = %s reason = %q, want rejected/whitelisted", b.State, b.Reason)
	}
	if n := dp.installCount(); n != 0 {
		t.Fatalf("INSTALLED %d rule sets for a whitelisted address", n)
	}

	// And a manual ban, which is the path that bypasses detection entirely.
	mb, err := m.ManualBan(netip.MustParseAddr("203.0.113.1"))
	if err != nil {
		t.Fatalf("ManualBan: %v", err)
	}
	if mb.State != BanRejected {
		t.Fatalf("manual ban of a whitelisted address = %s, want rejected", mb.State)
	}
	if n := dp.installCount(); n != 0 {
		t.Fatalf("a MANUAL ban installed %d rule sets for a whitelisted address", n)
	}
}

/* ----------------------------------------------------------------- caps */

// TestCapsBoundDataplaneInstalls checks that the blast-radius gates, which all
// live above the backend in ban(), bound what can reach the kernel. A cap that
// only bounded BGP announcements would let a spoofed-source storm fill the
// policy map instead.
func TestCapsBoundDataplaneInstalls(t *testing.T) {
	dp := &dpRecorder{}
	// baseYAML caps max_active_bans at 3.
	m, _ := newDataplaneMitigator(t, dpYAML(""), dp, nil)

	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8"} {
		m.OnAttackStarted(startedEvent(ip))
	}
	if n := dp.installCount(); n != 3 {
		t.Fatalf("installs = %d, want 3 (max_active_bans); the cap must bound kernel rules, "+
			"not only BGP announcements", n)
	}
}

// TestBanRateCapBoundsDataplaneInstalls does the same for the per-window rate
// gate, which is the one that contains a storm before the count cap is reached.
func TestBanRateCapBoundsDataplaneInstalls(t *testing.T) {
	dp := &dpRecorder{}
	yaml := strings.Replace(dpYAML(""),
		"  max_active_bans: 3\n",
		"  max_active_bans: 50\n  max_bans_per_window: 2\n  ban_window_seconds: 600\n", 1)
	m, _ := newDataplaneMitigator(t, yaml, dp, nil)

	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8"} {
		m.OnAttackStarted(startedEvent(ip))
	}
	if n := dp.installCount(); n != 2 {
		t.Fatalf("installs = %d, want 2 (max_bans_per_window)", n)
	}
}

/* -------------------------------------------------------------- lifecycle */

// TestDataplaneTTLExpiryWithdraws checks that "no permanent bans" reaches the
// kernel: the sweeper's TTL withdraw removes the map entries.
func TestDataplaneTTLExpiryWithdraws(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	m, _ := newDataplaneMitigator(t, dpYAML(""), dp, clk)

	m.OnAttackStarted(startedEvent("203.0.113.5"))
	if dp.installCount() != 1 {
		t.Fatalf("installs = %d, want 1", dp.installCount())
	}

	clk.Advance(m.store.Get().Ban.TTL() + time.Second)
	m.sweepExpired()

	if dp.withdrawCount() != 1 {
		t.Fatalf("withdraws after TTL = %d, want 1: an expired ban must remove its kernel rules",
			dp.withdrawCount())
	}
	if got := m.Snapshot()[0].State; got != BanWithdrawn {
		t.Errorf("ban state = %s, want withdrawn", got)
	}
}

// TestDataplaneManualUnbanWithdraws covers the operator path.
func TestDataplaneManualUnbanWithdraws(t *testing.T) {
	dp := &dpRecorder{}
	m, _ := newDataplaneMitigator(t, dpYAML(""), dp, nil)

	m.OnAttackStarted(startedEvent("203.0.113.5"))
	if _, err := m.ManualUnban(netip.MustParseAddr("203.0.113.5")); err != nil {
		t.Fatalf("ManualUnban: %v", err)
	}
	if dp.withdrawCount() != 1 {
		t.Fatalf("withdraws = %d, want 1", dp.withdrawCount())
	}
}

/* ------------------------------------------------------------ escalation */

// TestEscalationOffDataplaneWithdrawsMapEntries is the route-family test.
//
// escalateLocked withdraws the old rung ONLY when its route family differs from
// the applied one. If MitigateDataplane shared rfFlowSpec — the tempting choice,
// since both rungs carry the same generated rules — this withdraw would never
// happen and the kernel rules would stay installed for the life of the ban while
// the ban record, the API and the console all said the mitigation had moved
// upstream.
func TestEscalationOffDataplaneWithdrawsMapEntries(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	yaml := strings.Replace(dpYAML(""),
		"escalation:\n  - {after_seconds: 0, action: dataplane}\n",
		"escalation:\n  - {after_seconds: 0, action: dataplane}\n  - {after_seconds: 60, action: flowspec}\n", 1)
	m, rec := newDataplaneMitigator(t, yaml, dp, clk)

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.Method != config.MitigateDataplane {
		t.Fatalf("first rung = %q, want dataplane", b.Method)
	}
	if dp.installCount() != 1 {
		t.Fatalf("installs = %d, want 1", dp.installCount())
	}

	clk.Advance(61 * time.Second)
	m.sweepExpired()

	if dp.withdrawCount() != 1 {
		t.Fatalf("withdraws after escalating to flowspec = %d, want 1: the map entries would stay "+
			"installed forever", dp.withdrawCount())
	}
	if len(rec.flowSpecUp()) == 0 {
		t.Fatal("escalation announced no flowspec rules")
	}
	if got := m.Snapshot()[0].Method; got != config.MitigateFlowSpec {
		t.Errorf("method after escalation = %q, want flowspec", got)
	}

	// Make-before-break: the new rung goes up before the old comes down.
	ev := dp.log()
	if len(ev) < 2 || ev[len(ev)-1] != "dp-withdraw 203.0.113.5/32" {
		t.Errorf("data-plane event order = %v, want the withdraw last", ev)
	}
}

// TestEscalationOntoDataplaneFromAlertOnly checks the other direction: an
// alert-only first rung has no family, so nothing is withdrawn and the rules
// simply go in.
func TestEscalationOntoDataplane(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	yaml := strings.Replace(dpYAML(""),
		"escalation:\n  - {after_seconds: 0, action: dataplane}\n",
		"escalation:\n  - {after_seconds: 0, action: none}\n  - {after_seconds: 60, action: dataplane}\n", 1)
	m, _ := newDataplaneMitigator(t, yaml, dp, clk)

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.Method != "" {
		t.Fatalf("first rung = %q, want alert-only", b.Method)
	}
	if dp.installCount() != 0 {
		t.Fatal("an alert-only rung installed rules")
	}

	clk.Advance(61 * time.Second)
	m.sweepExpired()
	if dp.installCount() != 1 {
		t.Fatalf("installs after escalating onto dataplane = %d, want 1", dp.installCount())
	}
}

/* -------------------------------------------------------------- fallback */

// TestInstallFailureFallsBackToBlackhole is the "never leave the victim
// undefended" property. A full policy map is an operator-set limit, and the
// answer to it must be a coarser mitigation, not none.
func TestInstallFailureFallsBackToBlackhole(t *testing.T) {
	dp := &dpRecorder{failWith: dataplane.ErrNoPolicySlots}
	m, rec := newDataplaneMitigator(t, dpYAML(""), dp, nil)

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.State != BanActive {
		t.Fatalf("ban state = %s (%s), want active via the fallback", b.State, b.Reason)
	}
	if b.Method != config.MitigateBlackhole {
		t.Fatalf("method = %q, want blackhole", b.Method)
	}
	if b.FellBackFrom != config.MitigateDataplane {
		t.Errorf("fell_back_from = %q, want dataplane; a silent fallback is the thing an operator "+
			"must never have to discover from a customer", b.FellBackFrom)
	}
	if b.NextHop == "" {
		t.Error("the fallback announced a host route with no next-hop: freezeUnicastAttrs did not " +
			"freeze the blackhole attributes for a dataplane-only ladder")
	}
	if rec.announced["203.0.113.5/32"] != 1 {
		t.Errorf("blackhole announces = %d, want 1", rec.announced["203.0.113.5/32"])
	}
}

// TestNoBackendFallsBackRatherThanAlerting is the failure the whole feature was
// gated on: a dataplane rung with nowhere to install must not resolve to a
// silent alert.
func TestNoBackendFallsBackRatherThanAlerting(t *testing.T) {
	rec := newRecorder()
	store := storeFrom(t, dpYAML(""))
	m, err := New(store, testLogger(t), withAnnouncer(rec)) // no WithDataplane
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.Method == "" {
		t.Fatal("a dataplane rung with no backend resolved to the empty (alert-only) method: the " +
			"attack would be recorded and notified while the traffic was forwarded")
	}
	if b.Method != config.MitigateBlackhole || b.FellBackFrom != config.MitigateDataplane {
		t.Fatalf("method = %q fell_back_from = %q, want blackhole/dataplane", b.Method, b.FellBackFrom)
	}
}

// TestInstallFailureWithNoFallbackRejectsTheBan checks ban.fallback: none, where
// the operator has said they would rather have no mitigation than a blackhole.
// The ban must be REJECTED and say why, not recorded as active.
func TestInstallFailureWithNoFallbackRejectsTheBan(t *testing.T) {
	dp := &dpRecorder{failWith: dataplane.ErrNoPolicySlots}
	yaml := strings.Replace(dpYAML(""), "  max_active_bans: 3\n", "  max_active_bans: 3\n  fallback: none\n", 1)
	m, _ := newDataplaneMitigator(t, yaml, dp, nil)

	b := m.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.State != BanRejected {
		t.Fatalf("ban state = %s, want rejected under fallback: none", b.State)
	}
	if !strings.Contains(b.Reason, "policy slots") {
		t.Errorf("reason = %q, want the install failure named", b.Reason)
	}
}

/* ----------------------------------------------------------- rehydration */

// TestDataplaneRehydration checks that a restart re-installs a live ban's map
// entries.
//
// It needs NO new persisted field, and that is worth stating: the ban already
// round-trips Method, FlowSpec and Escalation, which between them are the whole
// input to the data-plane rung. The policy id and the profile id are NOT
// persisted on purpose — they are allocations against a map set that may have
// been resized, rebuilt or adopted while this process was down, and a
// remembered id would be a claim about kernel state nobody verified.
// dataplane.Installer re-derives them by reading kapkan_victims back.
func TestDataplaneRehydration(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "bans.json")
	yaml := strings.Replace(dpYAML(""), "  max_active_bans: 3\n",
		"  max_active_bans: 3\n  state_file: "+state+"\n", 1)

	first := &dpRecorder{}
	m1, _ := newDataplaneMitigator(t, yaml, first, nil)
	b := m1.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.Method != config.MitigateDataplane {
		t.Fatalf("method = %q, want dataplane", b.Method)
	}
	m1.flushPersist()

	if _, err := os.Stat(state); err != nil {
		t.Fatalf("state file not written: %v", err)
	}

	// A second process: same config, same state file, a fresh backend.
	second := &dpRecorder{}
	m2, _ := newDataplaneMitigator(t, yaml, second, nil)
	m2.mu.Lock()
	m2.rehydrateLocked(m2.store.Get())
	m2.mu.Unlock()

	if second.installCount() != 1 {
		t.Fatalf("installs after rehydration = %d, want 1: a restart mid-attack would leave the "+
			"victim unfiltered until the next detection window", second.installCount())
	}
	in := second.lastInstall(t)
	if in.victim != netip.MustParsePrefix("203.0.113.5/32") {
		t.Errorf("rehydrated install for %s, want the victim", in.victim)
	}
	if len(in.rules.Specs) != len(first.lastInstall(t).rules.Specs) {
		t.Errorf("rehydrated %d rules, originally %d: the restored ban must filter the same vector",
			len(in.rules.Specs), len(first.lastInstall(t).rules.Specs))
	}
	if in.rules.TTL <= 0 {
		t.Errorf("rehydrated ttl = %s, want the remaining ban lifetime", in.rules.TTL)
	}

	bans := m2.ActiveBans()
	if len(bans) != 1 || bans[0].Method != config.MitigateDataplane {
		t.Fatalf("rehydrated bans = %+v, want one dataplane ban", bans)
	}
}

// TestDataplaneRehydrationRefusesANowWhitelistedTarget checks that the persisted
// set never overrides a live safety rule: an operator who whitelists a host
// during the downtime gets no rules reinstalled for it.
func TestDataplaneRehydrationRefusesANowWhitelistedTarget(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "bans.json")
	yaml := strings.Replace(dpYAML(""), "  max_active_bans: 3\n",
		"  max_active_bans: 3\n  state_file: "+state+"\n", 1)

	first := &dpRecorder{}
	m1, _ := newDataplaneMitigator(t, yaml, first, nil)
	m1.OnAttackStarted(startedEvent("203.0.113.5"))
	m1.flushPersist()

	// The operator adds the victim to protected_whitelist while we are down.
	guarded := strings.Replace(yaml, "protected_whitelist:\n  - \"203.0.113.1\"\n",
		"protected_whitelist:\n  - \"203.0.113.1\"\n  - \"203.0.113.5\"\n", 1)
	second := &dpRecorder{}
	m2, _ := newDataplaneMitigator(t, guarded, second, nil)
	m2.mu.Lock()
	m2.rehydrateLocked(m2.store.Get())
	m2.mu.Unlock()

	if n := second.installCount(); n != 0 {
		t.Fatalf("rehydration installed %d rule sets for a now-whitelisted target", n)
	}
}

/* ---------------------------------------------------------------- wiring */

// TestDataplaneRouteFamilyIsItsOwn is a direct assertion on the constant,
// because the consequence of getting it wrong is invisible in every other test
// that does not escalate.
func TestDataplaneRouteFamilyIsItsOwn(t *testing.T) {
	dpFam := routeFamilyOf(config.MitigateDataplane)
	for _, other := range []config.MitigationMethod{
		config.MitigateFlowSpec, config.MitigateBlackhole, config.MitigateDivert, "",
	} {
		if routeFamilyOf(other) == dpFam {
			t.Errorf("dataplane shares a route family with %q; escalating between them would skip "+
				"the withdraw and strand one of the two mitigations", other)
		}
	}
}

// endedEvent is the AttackEnded counterpart of startedEvent.
func endedEvent(target string) engine.Event {
	ev := startedEvent(target)
	ev.Kind = engine.AttackEnded
	return ev
}

// TestSustainedAttackRenewsTheKernelDeadline covers the failure a sustained
// flood produces, which is the normal case rather than an edge one.
//
// Refreshing Ban.ExpiresAt is enough for BGP — an announcement sits on the peer
// until withdrawn — but a data-plane rule carries its OWN boot-clock deadline in
// the kernel. Without a re-install, an attack outlasting ban.ttl_seconds stopped
// being dropped at the original deadline while the API, console and metrics all
// still reported an active ban whose expires_in never counted down. With the
// shipped default of 600s that is every flood over ten minutes.
//
// The renewal is throttled to TTL/2, so this also pins that heartbeats do not
// rewrite the policy block every second for the duration of an attack.
func TestSustainedAttackRenewsTheKernelDeadline(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	m, _ := newDataplaneMitigator(t, dpYAML(""), dp, clk)

	m.OnAttackStarted(startedEvent("203.0.113.5"))
	if dp.installCount() != 1 {
		t.Fatalf("installs = %d, want 1", dp.installCount())
	}
	ttl := m.store.Get().Ban.TTL()

	// Heartbeats well inside TTL/2 must NOT reinstall: the deadline is still far
	// enough ahead, and per-second churn on a policy block is pure cost.
	for i := 0; i < 5; i++ {
		clk.Advance(time.Second)
		m.OnAttackOngoing(ongoingEvent("203.0.113.5"))
	}
	if got := dp.installCount(); got != 1 {
		t.Errorf("installs after 5s of heartbeats = %d, want 1: renewal is throttled to TTL/2", got)
	}

	// Past TTL/2 the deadline is renewed, and the rules the kernel now holds
	// must expire later than the ones it held before.
	first := dp.lastInstall(t)
	clk.Advance(ttl/2 + time.Second)
	m.OnAttackOngoing(ongoingEvent("203.0.113.5"))
	if got := dp.installCount(); got != 2 {
		t.Fatalf("installs after TTL/2 of heartbeats = %d, want 2: a sustained attack must renew "+
			"the in-kernel deadline, or it silently stops being dropped while the ban reads active", got)
	}
	second := dp.lastInstall(t)
	if len(first.rules.Specs) == 0 || len(second.rules.Specs) == 0 {
		t.Fatal("both installs must carry rules")
	}
	// The boot-clock deadline itself is computed by the installer, where the
	// boot clock is readable; what travels here is the WINDOW. The renewal is
	// only worth anything if that window is a full TTL rather than the stale
	// remainder of the original one — a shrinking window would move the kernel
	// deadline forward by less each time and still strand the ban eventually.
	if second.rules.TTL < ttl-time.Minute {
		t.Errorf("renewed window = %s, want ~%s: the re-install must give the kernel a fresh full "+
			"TTL, not what was left of the old one", second.rules.TTL, ttl)
	}

	// A ban that stops being refreshed still lapses: renewal must not make a
	// ban immortal.
	clk.Advance(ttl + time.Second)
	m.sweepExpired()
	if dp.withdrawCount() != 1 {
		t.Errorf("withdraws after the heartbeats stopped = %d, want 1", dp.withdrawCount())
	}
}

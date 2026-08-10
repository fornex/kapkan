package mitigate

// The carpet method -> mechanism gate.
//
// ==========================================================================
// WHY THIS FILE EXISTS
// ==========================================================================
// banPrefix used to map carpet.mitigation to a ladder action with a TWO-WAY
// branch:
//
//	action := config.EscalateBlackhole
//	if method == config.MitigateFlowSpec {
//		action = config.EscalateFlowSpec
//	}
//
// and gated rule generation with a second, separately-maintained copy of the
// same comparison. That is correct for exactly two methods and silently wrong
// for three: any method the branch did not name fell into the `else` and was
// BLACKHOLED, with no rules generated and nothing in the logs to say the
// operator got a different mechanism than the one they configured.
//
// On the carpet path that failure is the widest one this product can produce.
// A carpet ban targets an aggregation prefix, so "blackholed instead of
// filtered" means 256 addresses (a /24) or 2^80 (a /48) taken offline in
// answer to a request for a surgical, vector-narrowed drop.
//
// So this table is not a nicety. It walks config.CarpetMethods() — the same
// list the validator and the schema read — and asserts, for EVERY method:
//
//   - the ladder action banPrefix synthesized (the mechanism that will run);
//   - the method recorded on the ban (what the API and notifications report);
//   - whether the match rules were generated (a rule-driven mechanism with an
//     empty rule set enforces NOTHING);
//   - what actually reached the outside world — an RTBH announce, FlowSpec
//     NLRI, or a kernel install — because the recorded action and the call
//     that was made are separately derived and both have to agree.
//
// A method added to CarpetMethods() without a row here FAILS the test rather
// than defaulting to anything.

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
)

// carpetDataplaneBlock is the top-level dataplane block a carpet
// mitigation: dataplane config must carry (validateCarpet enforces the
// cross-field rule, so the two always travel together).
const carpetDataplaneBlock = `dataplane:
  enabled: true
  interfaces: ["eth0"]
`

// newMitigatorDP builds a mitigator with BOTH backends wired — a BGP announcer
// and a kernel installer — so one table can watch all three mechanisms and
// assert that only the configured one was used.
func newMitigatorDP(t *testing.T, yaml string, rec announcer, dp dataplaneBackend) *Mitigator {
	t.Helper()
	m, err := New(storeFrom(t, yaml), testLogger(t), withAnnouncer(rec), WithDataplane(dp))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()
	return m
}

// carpetEndedEvent is the AttackEnded counterpart of carpetEvent.
func carpetEndedEvent(prefix string) engine.Event {
	ev := carpetEvent(prefix)
	ev.Kind = engine.AttackEnded
	return ev
}

// carpetMethodCase is the expected mechanism for one carpet method.
type carpetMethodCase struct {
	// action is the ladder action banPrefix must synthesize from the method.
	action config.EscalationAction
	// wantRules is whether the ban must carry generated match rules. It is true
	// for every mechanism that is DRIVEN BY those rules; installing such a rung
	// with an empty rule set is a mitigation that filters nothing.
	wantRules bool
	// wantRTBH is whether an RTBH unicast route for the whole prefix is
	// announced. Exactly one method may do this.
	wantRTBH bool
	// wantFlowSpecNLRI is whether the rules were announced to a BGP peer.
	wantFlowSpecNLRI bool
	// wantKernelInstall is whether the rules were installed in this box's kernel.
	wantKernelInstall bool
}

func carpetMethodTable() map[config.MitigationMethod]carpetMethodCase {
	return map[config.MitigationMethod]carpetMethodCase{
		config.MitigateBlackhole: {
			action: config.EscalateBlackhole, wantRules: false,
			wantRTBH: true, wantFlowSpecNLRI: false, wantKernelInstall: false,
		},
		config.MitigateFlowSpec: {
			action: config.EscalateFlowSpec, wantRules: true,
			wantRTBH: false, wantFlowSpecNLRI: true, wantKernelInstall: false,
		},
		config.MitigateDataplane: {
			action: config.EscalateDataplane, wantRules: true,
			wantRTBH: false, wantFlowSpecNLRI: false, wantKernelInstall: true,
		},
	}
}

// TestCarpetMethodActionMapping is the regression gate: every method
// carpet.mitigation accepts must reach the mechanism it names, and nothing
// else.
func TestCarpetMethodActionMapping(t *testing.T) {
	const prefix = "203.0.113.0/24"
	table := carpetMethodTable()

	for _, method := range config.CarpetMethods() {
		want, ok := table[method]
		if !ok {
			t.Fatalf("config.CarpetMethods() offers %q but this table has no row for it. Add one. "+
				"An untested carpet method is exactly how a /24 gets blackholed when the operator "+
				"asked for a surgical drop.", method)
		}

		t.Run(string(method), func(t *testing.T) {
			extra := ""
			if want.wantKernelInstall {
				extra = carpetDataplaneBlock
			}
			dp := &dpRecorder{}
			rec := newRecorder()
			m := newMitigatorDP(t, carpetMitigYAML(string(method), extra), rec, dp)

			ban := m.OnAttackStarted(carpetEvent(prefix))
			if ban == nil || ban.State != BanActive {
				t.Fatalf("carpet ban = %+v, want active", ban)
			}

			/* --- the mapping itself --- */

			if len(ban.Escalation) != 1 {
				t.Fatalf("carpet ladder = %+v, want exactly one rung", ban.Escalation)
			}
			if got := ban.Escalation[0].Action; got != want.action {
				t.Errorf("carpet.mitigation %q synthesized ladder action %q, want %q — the ban will "+
					"be enforced by a DIFFERENT mechanism than the operator configured",
					method, got, want.action)
			}
			if ban.Method != method {
				t.Errorf("ban.Method = %q, want %q — /api/v1/bans, the console and every "+
					"notification would report a method that is not the one running",
					ban.Method, method)
			}

			/* --- the rules the mechanism runs on --- */

			if gotRules := len(ban.FlowSpec) > 0; gotRules != want.wantRules {
				t.Errorf("rules generated = %v, want %v. A rule-driven mechanism installed with an "+
					"empty rule set enforces nothing at all; a route-driven one does not need them. "+
					"rules: %v", gotRules, want.wantRules, ban.FlowSpec)
			}
			if want.wantRules && len(ban.FlowSpec) > 0 {
				if got := ban.FlowSpec[0].Dst; got != netip.MustParsePrefix(prefix) {
					t.Errorf("the carpet rule anchors on %s, want the whole aggregation prefix %s",
						got, prefix)
				}
			}

			/* --- what actually left the process --- */

			if gotRTBH := rec.announceCount(prefix) > 0; gotRTBH != want.wantRTBH {
				t.Errorf("RTBH announce of %s = %v, want %v. THIS is the silent-wrong-method "+
					"failure: an unannounced blackhole of a whole prefix is %d addresses taken "+
					"offline that nobody asked to take offline",
					prefix, gotRTBH, want.wantRTBH, 256)
			}
			if gotNLRI := len(rec.flowSpecUp()) > 0; gotNLRI != want.wantFlowSpecNLRI {
				t.Errorf("FlowSpec NLRI announced = %v, want %v (rules seen: %v)",
					gotNLRI, want.wantFlowSpecNLRI, rec.flowSpecUp())
			}
			if gotInstall := dp.installCount() > 0; gotInstall != want.wantKernelInstall {
				t.Errorf("kernel install = %v, want %v (backend log: %v)",
					gotInstall, want.wantKernelInstall, dp.log())
			}
			if want.wantKernelInstall && dp.installCount() > 0 {
				in := dp.lastInstall(t)
				if in.victim != netip.MustParsePrefix(prefix) {
					t.Errorf("installed for %s, want the whole aggregation prefix %s", in.victim, prefix)
				}
				if len(in.rules.Specs) == 0 {
					t.Error("installed an EMPTY kernel rule set for the prefix: the ban reports " +
						"active and drops nothing")
				}
			}

			/* --- and the withdraw takes down what the install put up --- */

			m.OnAttackEnded(carpetEndedEvent(prefix))
			if len(m.ActiveBans()) != 0 {
				t.Errorf("active bans = %d after the carpet attack ended, want 0", len(m.ActiveBans()))
			}
			if want.wantKernelInstall && dp.withdrawCount() != 1 {
				t.Errorf("kernel withdraws = %d, want 1 — rules that outlive their ban keep "+
					"filtering a prefix the mitigator no longer considers banned", dp.withdrawCount())
			}
			if want.wantRTBH && rec.withdrawCount(prefix) != 1 {
				t.Errorf("RTBH withdraws of %s = %d, want 1", prefix, rec.withdrawCount(prefix))
			}
		})
	}
}

// TestCarpetDataplaneRequiresADataplaneBlock is the cross-field half of the
// same guarantee. Accepting the method while the kernel backend is absent would
// mean every install fails and every carpet ban degrades to blackholing the
// whole prefix — the widest outcome, reached from the most surgical request.
func TestCarpetDataplaneRequiresADataplaneBlock(t *testing.T) {
	_, err := config.Parse([]byte(carpetMitigYAML("dataplane", "")))
	if err == nil {
		t.Fatal("carpet.mitigation: dataplane parsed with NO dataplane block; every install would " +
			"fail and fall back to blackholing the whole /24")
	}
	if !strings.Contains(err.Error(), "carpet.mitigation") || !strings.Contains(err.Error(), "dataplane block") {
		t.Errorf("error %q does not name carpet.mitigation and the missing dataplane block", err)
	}

	off := strings.Replace(carpetDataplaneBlock, "enabled: true", "enabled: false", 1)
	if _, err := config.Parse([]byte(carpetMitigYAML("dataplane", off))); err == nil ||
		!strings.Contains(err.Error(), "dataplane.enabled") {
		t.Errorf("carpet.mitigation: dataplane with dataplane.enabled: false gave %v, want a "+
			"rejection naming dataplane.enabled", err)
	}
}

// TestCarpetDataplaneRenewsTheKernelDeadline is the prefix half of the renewal
// that TestSustainedAttackRenewsTheKernelDeadline pins for hosts.
//
// A data-plane rule carries its own boot-clock deadline in the kernel, so
// refreshing Ban.ExpiresAt on the Go side is not enough: without a re-install,
// an attack outlasting ban.ttl_seconds stops being dropped at the ORIGINAL
// deadline while /api/v1/bans still reports an active ban. The renewal loop
// walked only the host ban table, because a carpet ban could not select the
// data plane. It can now, and a carpet ban is the widest rule there is — so it
// has to be walked too, or the exact bug that renewal exists to fix comes back
// on the widest possible target.
func TestCarpetDataplaneRenewsTheKernelDeadline(t *testing.T) {
	const prefix = "203.0.113.0/24"
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	store := storeFrom(t, carpetMitigYAML("dataplane", carpetDataplaneBlock))
	m, err := New(store, testLogger(t), withAnnouncer(newRecorder()),
		WithDataplane(dp), WithClock(clk.Now))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()

	if b := m.OnAttackStarted(carpetEvent(prefix)); b == nil || b.State != BanActive {
		t.Fatalf("carpet ban = %+v, want active", b)
	}
	if dp.installCount() != 1 {
		t.Fatalf("installs = %d, want 1", dp.installCount())
	}
	ttl := store.Get().Ban.TTL()

	// Inside TTL/2: no churn.
	ongoing := carpetEvent(prefix)
	ongoing.Kind = engine.AttackOngoing
	for i := 0; i < 5; i++ {
		clk.Advance(time.Second)
		m.OnAttackOngoing(ongoing)
	}
	if got := dp.installCount(); got != 1 {
		t.Errorf("installs after 5s of heartbeats = %d, want 1 (renewal is throttled to TTL/2)", got)
	}

	// Past TTL/2: the in-kernel deadline is renewed with a fresh full window.
	clk.Advance(ttl/2 + time.Second)
	m.OnAttackOngoing(ongoing)
	if got := dp.installCount(); got != 2 {
		t.Fatalf("installs after TTL/2 of heartbeats = %d, want 2: a sustained CARPET attack must "+
			"renew its in-kernel deadline, or a whole /24 silently stops being filtered while the "+
			"ban still reads active", got)
	}
	if got := dp.lastInstall(t).rules.TTL; got < ttl-time.Minute {
		t.Errorf("renewed window = %s, want ~%s: a shrinking window strands the ban eventually",
			got, ttl)
	}

	// And renewal does not make it immortal.
	clk.Advance(ttl + time.Second)
	m.sweepExpired()
	if dp.withdrawCount() != 1 {
		t.Errorf("withdraws after the heartbeats stopped = %d, want 1", dp.withdrawCount())
	}
}

// TestCarpetDataplaneBlastRadiusAndCaps re-proves the two quantitative safety
// gates with the in-kernel method selected.
//
// They are method-independent code — banPrefix runs them before it looks at the
// method at all — but "it should still work" is exactly the assumption that
// makes a widening change dangerous. A kernel rule for a /24 covers 256
// addresses just as an RTBH route for it does, and the accounting must say so.
func TestCarpetDataplaneBlastRadiusAndCaps(t *testing.T) {
	base := carpetMitigYAML("dataplane", carpetDataplaneBlock)

	t.Run("a /24 counts as 256 addresses", func(t *testing.T) {
		// v4 protected space = /24 + /16 = 65792 addrs. One /24 is 256/65792 =
		// 0.0039 (admitted under 0.005); two would be 0.0078 (refused). If a
		// prefix ban counted as ONE address the second would sail through.
		yaml := strings.Replace(base, "max_active_bans: 50",
			"max_active_bans: 50, max_banned_fraction: 0.005", 1)
		dp := &dpRecorder{}
		m := newMitigatorDP(t, yaml, newRecorder(), dp)
		if b := m.OnAttackStarted(carpetEvent("203.0.113.0/24")); b.State != BanActive {
			t.Fatalf("first /24 = %+v, want active (256/65792 < 0.005)", b)
		}
		b := m.OnAttackStarted(carpetEvent("198.51.100.0/24"))
		if b.State != BanRejected || !strings.Contains(b.Reason, "max_banned_fraction") {
			t.Fatalf("second /24 = %+v, want rejected — a kernel rule over a /24 must weigh 256 "+
				"addresses, not one", b)
		}
		if dp.installCount() != 1 {
			t.Errorf("kernel installs = %d, want 1: the refused ban still installed rules",
				dp.installCount())
		}
	})

	t.Run("max_active_prefix_bans bounds it", func(t *testing.T) {
		yaml := strings.Replace(base, "mitigation: dataplane",
			"mitigation: dataplane\n  max_active_prefix_bans: 1", 1)
		dp := &dpRecorder{}
		m := newMitigatorDP(t, yaml, newRecorder(), dp)
		if b := m.OnAttackStarted(carpetEvent("203.0.113.0/24")); b.State != BanActive {
			t.Fatalf("first carpet ban = %+v, want active", b)
		}
		b := m.OnAttackStarted(carpetEvent("198.51.100.0/24"))
		if b.State != BanRejected || !strings.Contains(b.Reason, "max_active_prefix_bans") {
			t.Fatalf("second carpet ban = %+v, want rejected (prefix cap)", b)
		}
		if dp.installCount() != 1 {
			t.Errorf("kernel installs = %d, want 1: the cap did not stop the install",
				dp.installCount())
		}
		// And the separate cap still does not starve host bans.
		if hb := m.OnAttackStarted(startedEvent("198.51.100.7")); hb.State != BanActive {
			t.Errorf("host ban = %+v, want active", hb)
		}
	})
}

// TestCarpetDataplaneWhitelistSweepAfterReload is the second half of the
// whitelist guarantee, and the half that only a reload can reach.
//
// banPrefix refuses a prefix containing a whitelisted address at BAN time. But
// an operator can add a protected address to a /24 that is already banned —
// mid-attack, which is precisely when someone notices their resolver is inside
// the blast radius. Three things must then happen, and this test checks all
// three for the in-kernel method:
//
//  1. the heartbeat stops refreshing the ban (OnAttackOngoing bails), so it
//     cannot be kept alive indefinitely;
//  2. the sweep takes it down promptly instead of waiting out the TTL;
//  3. the KERNEL rules come down with it — a withdrawn ban whose /24 of rules
//     are still installed protects nobody.
func TestCarpetDataplaneWhitelistSweepAfterReload(t *testing.T) {
	const prefix = "203.0.113.0/24"
	yaml := carpetMitigYAML("dataplane", carpetDataplaneBlock)
	store, path := fileStore(t, yaml)
	dp := &dpRecorder{}
	m, err := New(store, testLogger(t), withAnnouncer(newRecorder()), WithDataplane(dp))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()

	ban := m.OnAttackStarted(carpetEvent(prefix))
	if ban == nil || ban.State != BanActive || ban.Method != config.MitigateDataplane {
		t.Fatalf("carpet ban = %+v, want an active dataplane ban", ban)
	}
	if dp.installCount() != 1 {
		t.Fatalf("kernel installs = %d, want 1", dp.installCount())
	}

	// The reload an operator performs at the worst possible moment: a protected
	// address appears INSIDE the banned /24.
	reloaded := strings.Replace(yaml, "networks: [\"203.0.113.0/24\", \"198.51.0.0/16\"]\n",
		"networks: [\"203.0.113.0/24\", \"198.51.0.0/16\"]\nprotected_whitelist: [\"203.0.113.5\"]\n", 1)
	if reloaded == yaml {
		t.Fatal("the reload fixture did not change the config; the test would prove nothing")
	}
	if err := os.WriteFile(path, []byte(reloaded), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// 1. the heartbeat must stop refreshing it.
	before := m.ActiveBans()[0].ExpiresAt
	ev := carpetEvent(prefix)
	ev.Kind = engine.AttackOngoing
	m.OnAttackOngoing(ev)
	if got := m.ActiveBans()[0].ExpiresAt; !got.Equal(before) {
		t.Errorf("the ongoing heartbeat refreshed a ban whose prefix now contains a whitelisted "+
			"address (%s -> %s); it could be held alive for as long as the attack lasts",
			before, got)
	}

	// 2 and 3. the sweep takes it down, kernel rules included.
	m.sweepExpired()
	if n := len(m.ActiveBans()); n != 0 {
		t.Errorf("active bans = %d after the sweep, want 0: a whitelisted address is still inside "+
			"a banned /24", n)
	}
	if dp.withdrawCount() != 1 {
		t.Fatalf("kernel withdraws = %d, want 1 — the ban is gone but its /24 of rules is still "+
			"in the kernel, filtering the address the operator just protected", dp.withdrawCount())
	}
}

// TestCarpetWhitelistIsAbsoluteForEveryMethod extends the existing
// whitelisted-member gate to the full method set. The whitelist guarantee has
// no per-method exceptions: a prefix containing a protected address is refused
// outright, and nothing — no route, no NLRI, no kernel rule — is installed.
func TestCarpetWhitelistIsAbsoluteForEveryMethod(t *testing.T) {
	const prefix = "203.0.113.0/24"
	for _, method := range config.CarpetMethods() {
		t.Run(string(method), func(t *testing.T) {
			extra := "protected_whitelist: [\"203.0.113.5\"]\n"
			if method == config.MitigateDataplane {
				extra += carpetDataplaneBlock
			}
			dp := &dpRecorder{}
			rec := newRecorder()
			m := newMitigatorDP(t, carpetMitigYAML(string(method), extra), rec, dp)

			ban := m.OnAttackStarted(carpetEvent(prefix))
			if ban == nil || ban.State != BanRejected || !strings.Contains(ban.Reason, "whitelisted member") {
				t.Fatalf("ban = %+v, want rejected (whitelisted member in prefix)", ban)
			}
			if rec.announceCount(prefix) != 0 || len(rec.flowSpecUp()) != 0 || dp.installCount() != 0 {
				t.Errorf("a prefix with a whitelisted member installed something: rtbh=%d nlri=%v kernel=%v",
					rec.announceCount(prefix), rec.flowSpecUp(), dp.log())
			}
		})
	}
}

// TestRenewalSkipsAPrefixThatGainedAProtectedMember covers the gap between
// OnAttackOngoing's whitelist re-check and the renewal walk.
//
// OnAttackOngoing re-checks only the prefix whose heartbeat arrived, but
// renewDataplaneLocked walks EVERY ban table — so a neighbouring prefix's
// heartbeat used to push a fresh in-kernel deadline onto a prefix that had just
// acquired a protected member. It was never a hole (the sweep withdraws it a
// tick later, and the protected host is immune anyway through the kernel's own
// precedence-2 map), but "the whitelist is absolute" is stated without
// qualification, and extending the life of a rule we are about to withdraw is
// not something to leave implicit.
func TestRenewalSkipsAPrefixThatGainedAProtectedMember(t *testing.T) {
	const banned = "203.0.113.0/24"
	const neighbour = "198.51.100.0/24"

	clk := &mockClock{t: time.Now()}
	// 198.51.100.0/24 needs no extra networks entry: the fixture already
	// protects 198.51.0.0/16, which contains it.
	yaml := carpetMitigYAML("dataplane", carpetDataplaneBlock)
	store, path := fileStore(t, yaml)
	dp := &dpRecorder{}
	m, err := New(store, testLogger(t), withAnnouncer(newRecorder()), WithDataplane(dp), WithClock(clk.Now))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()

	if b := m.OnAttackStarted(carpetEvent(banned)); b == nil || b.Method != config.MitigateDataplane {
		t.Fatalf("carpet ban on %s = %+v, want an active dataplane ban", banned, b)
	}
	if b := m.OnAttackStarted(carpetEvent(neighbour)); b == nil || b.Method != config.MitigateDataplane {
		t.Fatalf("carpet ban on %s = %+v, want an active dataplane ban", neighbour, b)
	}
	if got := dp.installCount(); got != 2 {
		t.Fatalf("kernel installs = %d, want 2", got)
	}

	// A protected address appears inside ONE of the two banned prefixes.
	reloaded := strings.Replace(yaml, "networks: [",
		"protected_whitelist: [\"203.0.113.5\"]\nnetworks: [", 1)
	if reloaded == yaml {
		t.Fatal("the reload fixture did not change the config; the test would prove nothing")
	}
	if err := os.WriteFile(path, []byte(reloaded), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Past the renewal throttle, drive a heartbeat for the OTHER prefix only.
	clk.Advance(store.Get().Ban.TTL()/2 + time.Second)
	ev := carpetEvent(neighbour)
	ev.Kind = engine.AttackOngoing
	m.OnAttackOngoing(ev)

	// The neighbour renews; the disqualified prefix must not.
	var renewed []string
	for _, in := range dp.allInstalls(t) {
		renewed = append(renewed, in.victim.String())
	}
	got := strings.Join(renewed, ",")
	if strings.Count(got, banned) != 1 {
		t.Errorf("installs = [%s]: %s was re-installed after a protected address entered it, so a "+
			"neighbouring prefix's heartbeat extended the deadline of a rule the whitelist has "+
			"already disqualified", got, banned)
	}
	if strings.Count(got, neighbour) != 2 {
		t.Errorf("installs = [%s]: %s should have renewed on its own heartbeat", got, neighbour)
	}
}

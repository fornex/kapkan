//go:build linux

package dataplane

// Kernel tests for the dynamic rule installer: every packet here goes through
// BPF_PROG_TEST_RUN on a real kernel, and every assertion checks both the
// verdict AND the counter that explains it, because passing for the wrong
// reason is the bug that hides longest.
//
// Run with `make dataplane-test`.

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

/* ---------------------------------------------------------------- fixtures */

var (
	instVictim   = netip.MustParsePrefix("203.0.113.9/32")
	instVictim2  = netip.MustParsePrefix("203.0.113.10/32")
	instAttacker = [4]byte{198, 51, 100, 7}
)

// ntpReflection is the packet the rules below are written for: a UDP datagram
// from a reflector's port 123 to the victim.
func ntpReflection() []byte {
	return cat(eth(etherTypeIPv4),
		ipv4From(instAttacker, [4]byte{203, 0, 113, 9}, 17, 0, 28),
		udp(123, 40000, 20))
}

// legitimateUDP is the same victim, same protocol, a DIFFERENT source port: the
// traffic a surgical rule must spare. Asserting on it is the whole difference
// between this and a blackhole.
func legitimateUDP() []byte {
	return cat(eth(etherTypeIPv4),
		ipv4From(instAttacker, [4]byte{203, 0, 113, 9}, 17, 0, 28),
		udp(53000, 443, 20))
}

// ntpRules is the rule set a real ban for an NTP amplification produces: udp,
// source port 123, to the victim, discard.
func ntpRules(victim netip.Prefix, ttl time.Duration) DynamicRules {
	proto := uint8(17)
	sport := uint16(123)
	return DynamicRules{
		Specs: []RuleSpec{{
			Action:  ActionDrop,
			Dst:     victim,
			Proto:   &proto,
			SrcPort: &sport,
		}},
		TTL: ttl,
	}
}

// newInstaller builds an Installer on an open manager. Tests that need a
// deterministic boot clock replace bootNs afterwards.
func newInstaller(t *testing.T, m *Manager) *Installer {
	t.Helper()
	return NewInstaller(m, testLogger(t))
}

// statOf reads one terminal counter, for the "and it passed for the RIGHT
// reason" half of every assertion.
func statOf(t *testing.T, m *Manager, s Stat) uint64 {
	t.Helper()
	c, err := ReadStat(m.Maps(), s)
	if err != nil {
		t.Fatalf("read stat %s: %v", s, err)
	}
	return c.Pkts
}

/* ----------------------------------------------------- install and withdraw */

// TestInstallerDropsTheAttackAndSparesTheRest is the feature: an installed rule
// drops the vector it names and nothing else.
func TestInstallerDropsTheAttackAndSparesTheRest(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)

	if got := runMgr(t, m, ntpReflection()); got != xdpPass {
		t.Fatalf("before install: verdict %d, want PASS — the default verdict is always pass", got)
	}

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}

	before := statOf(t, m, StatDropDynDst)
	if got := runMgr(t, m, ntpReflection()); got != xdpDrop {
		t.Fatalf("after install: verdict %d, want DROP", got)
	}
	if after := statOf(t, m, StatDropDynDst); after != before+1 {
		t.Errorf("drop_dyn_dst %d -> %d, want +1: the packet was dropped by something other than "+
			"the installed rule", before, after)
	}

	if got := runMgr(t, m, legitimateUDP()); got != xdpPass {
		t.Fatalf("the victim's legitimate UDP was dropped (verdict %d); a surgical rule that drops "+
			"everything is a blackhole with extra steps", got)
	}
}

// TestInstallerWithdrawRestoresPass closes the lifecycle.
func TestInstallerWithdrawRestoresPass(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := runMgr(t, m, ntpReflection()); got != xdpDrop {
		t.Fatalf("verdict %d, want DROP", got)
	}
	if err := inst.Withdraw(instVictim); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}

	before := statOf(t, m, StatPassDefault)
	if got := runMgr(t, m, ntpReflection()); got != xdpPass {
		t.Fatalf("after withdraw: verdict %d, want PASS", got)
	}
	if after := statOf(t, m, StatPassDefault); after != before+1 {
		t.Errorf("pass_default %d -> %d, want +1: the packet passed but not by falling through "+
			"every rule, so something is still installed", before, after)
	}

	// The victim entry is gone, not merely pointing at an empty block: a
	// lingering entry would count err_policy_missing on every packet.
	ents, err := victimEntries(m.Maps())
	if err != nil {
		t.Fatalf("victimEntries: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("kapkan_victims still holds %v after a withdraw", ents)
	}
}

// TestWithdrawOfAnUninstalledVictimIsNotAnError: the mitigator withdraws by
// method, and a ban that fell back to blackhole never installed anything.
func TestWithdrawOfAnUninstalledVictimIsNotAnError(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	if err := newInstaller(t, m).Withdraw(instVictim); err != nil {
		t.Fatalf("Withdraw of a victim with nothing installed: %v", err)
	}
}

/* --------------------------------------------------------------- the expiry */

// TestInKernelDeadlinePassesOnItsOwn is the fail-safe for a dead userspace: a
// rule past its boot-clock deadline is treated as ABSENT by the datapath, with
// no help from this process.
//
// The deterministic boot clock is what makes this a test rather than a sleep.
func TestInKernelDeadlinePassesOnItsOwn(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)
	inst.bootNs = func() uint64 { return 1 } // 1ns after boot: any deadline we set is in the past

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Nanosecond)); err != nil {
		t.Fatalf("Install: %v", err)
	}

	beforeExpired := statOf(t, m, StatPassRuleExpired)
	if got := runMgr(t, m, ntpReflection()); got != xdpPass {
		t.Fatalf("verdict %d, want PASS: an expired rule must be treated as absent, which is what "+
			"degrades a crashed userspace to a wire instead of leaving a customer blackholed", got)
	}
	if after := statOf(t, m, StatPassRuleExpired); after != beforeExpired+1 {
		t.Errorf("pass_rule_expired %d -> %d, want +1: the packet passed, but not because the rule "+
			"had expired", beforeExpired, after)
	}
}

// TestZeroTTLIsRefused: a zero deadline means "never expires" in the kernel and
// is reserved for static rules, which cannot be stranded by a crash.
func TestZeroTTLIsRefused(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := inst.Install(instVictim, ntpRules(instVictim, ttl)); err == nil {
			t.Fatalf("accepted ttl %s; the rule would never expire", ttl)
		}
	}
}

/* ------------------------------------------------- the two whitelist layers */

// TestProtectedWhitelistBeatsAnInstalledRule is the KERNEL half of the
// "protected_whitelist is absolute" guarantee.
//
// mitigate.ban() refuses a whitelisted target, so in normal operation no rule
// for one is ever created — that is the userspace half, proved by
// TestWhitelistIsAbsoluteForTheDataplane in internal/mitigate. This is the case
// that layer cannot cover: a rule that ALREADY EXISTS. It happens on a restart
// that adopts a pinned data plane whose rules the previous process installed
// before the operator added the address, and in the window between an operator's
// edit and the userspace sweep noticing. Precedence 2 is checked before any
// dynamic rule is read, so the answer is immediate rather than one 1 Hz tick
// later.
func TestProtectedWhitelistBeatsAnInstalledRule(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	m := mustOpen(t, opts)
	inst := newInstaller(t, m)

	// Install first, protect afterwards: the order that models an operator
	// whitelisting a host mid-attack.
	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := runMgr(t, m, ntpReflection()); got != xdpDrop {
		t.Fatalf("verdict %d, want DROP before the whitelist entry", got)
	}

	next := opts
	next.Policy.Protected = []netip.Prefix{instVictim}
	if _, err := m.Reload(next); err != nil {
		t.Fatalf("Reload with a protected victim: %v", err)
	}

	before := statOf(t, m, StatPassProtectDst)
	if got := runMgr(t, m, ntpReflection()); got != xdpPass {
		t.Fatalf("A PROTECTED DESTINATION WAS DROPPED (verdict %d). protected_whitelist is "+
			"absolute and is enforced at precedence 2, above every dynamic rule", got)
	}
	if after := statOf(t, m, StatPassProtectDst); after != before+1 {
		t.Errorf("pass_protect_dst %d -> %d, want +1: it passed for some other reason, so the "+
			"kernel-side guarantee is not the thing that saved it", before, after)
	}

	// And the rule is still there for everyone else — the whitelist exempts the
	// destination, it does not delete the mitigation.
	if got := runMgr(t, m, ntpReflectionTo([4]byte{203, 0, 113, 10})); got != xdpPass {
		t.Logf("unrelated victim verdict %d (no rule installed for it)", got)
	}
}

// TestAllowlistBeatsAnInstalledRule is the same argument on the other axis:
// dataplane.allowlist names SOURCES that always pass, checked at precedence 1.
func TestAllowlistBeatsAnInstalledRule(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	m := mustOpen(t, opts)
	inst := newInstaller(t, m)

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	next := opts
	next.Policy.Allow = []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}
	if _, err := m.Reload(next); err != nil {
		t.Fatalf("Reload with an allowlisted source: %v", err)
	}

	before := statOf(t, m, StatPassAllowSrc)
	if got := runMgr(t, m, ntpReflection()); got != xdpPass {
		t.Fatalf("an allowlisted source was dropped (verdict %d)", got)
	}
	if after := statOf(t, m, StatPassAllowSrc); after != before+1 {
		t.Errorf("pass_allow_src %d -> %d, want +1", before, after)
	}
}

/* ------------------------------------------------------- the kernel dry run */

// TestDatapathDryRunRewritesAnInstalledDrop is the SECOND dry-run layer.
//
// internal/mitigate proves the mitigator installs nothing at all in dry-run.
// This proves that if something ever did — a rehydrated rule, an adopted pin
// set, a future caller — the datapath still forwards the packet, and still says
// it would not have.
func TestDatapathDryRunRewritesAnInstalledDrop(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.DryRun = true
	m := mustOpen(t, opts)
	inst := newInstaller(t, m)

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	beforeWould := statOf(t, m, StatDryRunWouldDrop)
	beforeDrop := statOf(t, m, StatDropDynDst)

	if got := runMgr(t, m, ntpReflection()); got != xdpPass {
		t.Fatalf("DRY-RUN DROPPED A PACKET (verdict %d)", got)
	}
	if after := statOf(t, m, StatDryRunWouldDrop); after != beforeWould+1 {
		t.Errorf("dryrun_would_drop %d -> %d, want +1: the operator gets no evidence of what a "+
			"live run would have done", beforeWould, after)
	}
	if after := statOf(t, m, StatDropDynDst); after != beforeDrop+1 {
		t.Errorf("drop_dyn_dst %d -> %d, want +1: accounting happens BEFORE the rewrite, so the "+
			"per-rule counters are the same in dry-run as in a live run", beforeDrop, after)
	}
}

/* ------------------------------------------------------- id and slot budget */

// TestPolicyIDsAreReusedPerVictim: a re-install (a TTL refresh, a rehydration)
// must land on the victim's own block, or its counters reset and a slot leaks
// on every refresh.
func TestPolicyIDsAreReusedPerVictim(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	first := policyIDOf(t, inst, instVictim)
	for range 5 {
		if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
			t.Fatalf("re-Install: %v", err)
		}
	}
	if got := policyIDOf(t, inst, instVictim); got != first {
		t.Errorf("policy id moved from %d to %d across a re-install", first, got)
	}
	ents, err := victimEntries(m.Maps())
	if err != nil {
		t.Fatalf("victimEntries: %v", err)
	}
	if len(ents) != 1 {
		t.Errorf("kapkan_victims holds %d entries after 6 installs of one victim, want 1", len(ents))
	}
}

// TestPolicySlotExhaustionFailsRatherThanDropsRules is the property the
// mitigator's fallback depends on: a full map is an ERROR, never a silently
// discarded rule set.
func TestPolicySlotExhaustionFailsRatherThanDropsRules(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo") // MaxDynamicRules 64 => stride 8
	m := mustOpen(t, opts)
	inst := newInstaller(t, m)

	stride := PolicyStride(m.Maps())
	if stride == 0 || stride > 64 {
		t.Fatalf("unexpected policy stride %d", stride)
	}
	for i := uint32(0); i < stride; i++ {
		v := victimN(i)
		if err := inst.Install(v, ntpRules(v, time.Hour)); err != nil {
			t.Fatalf("Install %s (%d of %d): %v", v, i, stride, err)
		}
	}
	over := victimN(stride)
	err := inst.Install(over, ntpRules(over, time.Hour))
	if err == nil {
		t.Fatal("the installer accepted a rule set past the policy stride; something was silently " +
			"overwritten")
	}
	if !errors.Is(err, ErrNoPolicySlots) {
		t.Errorf("error = %v, want ErrNoPolicySlots so a caller can tell 'full' from 'broken'", err)
	}

	// A withdraw returns the slot, so the next ban fits.
	if err := inst.Withdraw(victimN(0)); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if err := inst.Install(over, ntpRules(over, time.Hour)); err != nil {
		t.Fatalf("Install after freeing a slot: %v", err)
	}
}

// TestInstallerOwnsIDsProfilesAndDeadlines pins the contract DynamicRules
// documents: whatever the caller put in these three fields is overwritten.
func TestInstallerOwnsIDsProfilesAndDeadlines(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)

	set := ntpRules(instVictim, time.Hour)
	set.Specs[0].ID = 999999
	set.Specs[0].Profile = 7
	set.Specs[0].ExpiresAt = 42
	if err := inst.Install(instVictim, set); err != nil {
		t.Fatalf("Install: %v", err)
	}

	id := policyIDOf(t, inst, instVictim)
	block := blockOf(t, m, id)
	if block.N_rules != 1 {
		t.Fatalf("n_rules = %d, want 1", block.N_rules)
	}
	r := block.Rules[0]
	if want := DynamicRuleID(id, 0); r.RuleId != want {
		t.Errorf("rule id = %d, want %d derived from the policy id", r.RuleId, want)
	}
	if r.ExpiresAtNs == 42 || r.ExpiresAtNs == 0 {
		t.Errorf("expires_at_ns = %d: the installer must set a real boot-clock deadline "+
			"(0 means 'never expires')", r.ExpiresAtNs)
	}
	if r.Profile != 0 {
		t.Errorf("profile = %d on a DROP rule, want 0: the caller's value was not overwritten", r.Profile)
	}
	// The counter the datapath needs must exist, or the first packets of the
	// rule are lost to accounting.
	if _, ok, err := ReadRuleStats(m.Maps(), r.RuleId); err != nil || !ok {
		t.Errorf("rule_stats[%d] missing (ok=%v err=%v)", r.RuleId, ok, err)
	}
}

// TestWithdrawReapsRuleStats is the other half of the contract limits.go states:
// kapkan_rule_stats is preallocated and bounded, so an installer that never
// reaps fills it and starts failing installs during an attack.
func TestWithdrawReapsRuleStats(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)

	if err := inst.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	id := DynamicRuleID(policyIDOf(t, inst, instVictim), 0)
	if _, ok, _ := ReadRuleStats(m.Maps(), id); !ok {
		t.Fatal("rule_stats entry was not created")
	}
	if err := inst.Withdraw(instVictim); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if _, ok, err := ReadRuleStats(m.Maps(), id); err != nil || ok {
		t.Errorf("rule_stats[%d] still present after a withdraw (ok=%v err=%v)", id, ok, err)
	}
}

/* -------------------------------------------------------------- rate limits */

// TestRateLimitProfilesAreInternedInTheReservedBand checks the whole profile
// design at once: the band, the sharing, and that a config reload cannot take
// the slot.
func TestRateLimitProfilesAreInternedInTheReservedBand(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.Policy.Profiles = []NamedRate{{Name: "operator", Mbps: 10}}
	m := mustOpen(t, opts)
	inst := newInstaller(t, m)

	set := ntpRules(instVictim, time.Hour)
	set.Specs[0].Action = ActionRateLimit
	set.RateBytesPerSecond = 1_250_000
	if err := inst.Install(instVictim, set); err != nil {
		t.Fatalf("Install: %v", err)
	}

	id := profileIDOf(t, inst, instVictim)
	if id < DynamicProfileBase || id >= MaxProfiles {
		t.Fatalf("dynamic profile id %d is outside the reserved band [%d,%d)",
			id, DynamicProfileBase, MaxProfiles)
	}
	if opID, ok := m.ProfileID("operator"); !ok || opID >= DynamicProfileBase {
		t.Errorf("the config profile got id %d (ok=%v); config ids must stay below %d",
			opID, ok, DynamicProfileBase)
	}

	// A second victim at the SAME rate shares the slot rather than burning one.
	set2 := ntpRules(instVictim2, time.Hour)
	set2.Specs[0].Action = ActionRateLimit
	set2.Specs[0].Dst = instVictim2
	set2.RateBytesPerSecond = 1_250_000
	if err := inst.Install(instVictim2, set2); err != nil {
		t.Fatalf("Install second victim: %v", err)
	}
	if got := profileIDOf(t, inst, instVictim2); got != id {
		t.Errorf("second victim at the same rate got profile %d, want the interned %d", got, id)
	}

	// A config reload must not reassign the dynamic slot out from under them.
	next := opts
	next.Policy.Profiles = []NamedRate{{Name: "operator", Mbps: 10}, {Name: "second", Mbps: 20}}
	if _, err := m.Reload(next); err != nil {
		t.Fatalf("Reload with a new config profile: %v", err)
	}
	for name, want := range map[string]bool{"operator": true, "second": true} {
		gotID, ok := m.ProfileID(name)
		if ok != want {
			t.Fatalf("profile %q resolved = %v", name, ok)
		}
		if gotID == id {
			t.Fatalf("config profile %q was assigned the dynamic slot %d; a live ban's rate would "+
				"have been silently replaced by the operator's", name, id)
		}
	}
	if p, err := readProfile(m, id); err != nil || p.RateBps != 1_250_000 {
		t.Errorf("the interned profile now reads %+v (err %v), want 1250000 bytes/s", p, err)
	}

	// The last withdraw retires the slot, and a retired profile caps nothing —
	// the fail-open direction.
	if err := inst.Withdraw(instVictim); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if p, _ := readProfile(m, id); p.RateBps != 1_250_000 {
		t.Errorf("the profile was retired while another victim still used it: %+v", p)
	}
	if err := inst.Withdraw(instVictim2); err != nil {
		t.Fatalf("Withdraw second: %v", err)
	}
	p, err := readProfile(m, id)
	if err != nil {
		t.Fatalf("read retired profile: %v", err)
	}
	if p.RateBps != 0 || p.RatePps != 0 {
		t.Errorf("retired profile still caps something: %+v; a stale rule pointing at it would be "+
			"rate-limited by a ceiling nobody configured", p)
	}
}

// TestRateLimitBandExhaustionFails: 64 distinct live rates is the budget, and
// the 65th is an error rather than a shared slot enforcing someone else's
// ceiling.
func TestRateLimitBandExhaustionFails(t *testing.T) {
	opts := testOptions(t, pinDir(t), "lo")
	opts.Limits = Limits{MaxDynamicRules: 1024, MaxStaticRules: 8, MaxRatelimitSources: 1024}
	m := mustOpen(t, opts)
	inst := newInstaller(t, m)

	band := uint32(MaxProfiles - DynamicProfileBase)
	for i := uint32(0); i < band; i++ {
		v := victimN(i)
		set := ntpRules(v, time.Hour)
		set.Specs[0].Action = ActionRateLimit
		set.RateBytesPerSecond = uint64(1_000_000 + i) // a distinct rate each time
		if err := inst.Install(v, set); err != nil {
			t.Fatalf("Install %d of %d distinct rates: %v", i, band, err)
		}
	}
	v := victimN(band)
	set := ntpRules(v, time.Hour)
	set.Specs[0].Action = ActionRateLimit
	set.RateBytesPerSecond = 9_999_999
	err := inst.Install(v, set)
	if err == nil {
		t.Fatal("the installer accepted a 65th distinct rate; one of them is now enforcing the " +
			"wrong ceiling")
	}
	if !errors.Is(err, ErrNoProfileSlots) {
		t.Errorf("error = %v, want ErrNoProfileSlots", err)
	}
	// And nothing of the failed install is left behind.
	if _, ok := inst.policyOf[v]; ok {
		t.Error("a failed install kept its policy slot")
	}
}

/* --------------------------------------------------------------- adoption */

// TestAdoptionKeepsPolicyIDsAcrossARestart is the rehydration path at the map
// level: a new process re-installs the same victim and must land on the block it
// already owns, not on top of somebody else's.
func TestAdoptionKeepsPolicyIDsAcrossARestart(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")

	m1 := mustOpen(t, opts)
	inst1 := newInstaller(t, m1)
	// Two victims, so "the same id" is a real claim and not id 0 by luck.
	for _, v := range []netip.Prefix{instVictim, instVictim2} {
		if err := inst1.Install(v, ntpRules(v, time.Hour)); err != nil {
			t.Fatalf("Install %s: %v", v, err)
		}
	}
	want := map[netip.Prefix]uint32{
		instVictim:  policyIDOf(t, inst1, instVictim),
		instVictim2: policyIDOf(t, inst1, instVictim2),
	}
	if want[instVictim] == want[instVictim2] {
		t.Fatal("two victims share a policy id")
	}
	if err := m1.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close(keep): %v", err)
	}

	// The rules are still enforcing while no manager is open at all: that is
	// what "keep" means, and it is why the ids must be adopted rather than
	// reallocated.
	m2 := mustOpen(t, opts)
	if !m2.Health().Adopted {
		t.Fatalf("the second manager did not adopt the pins; this test proves nothing. health: %s",
			m2.Health().Summary())
	}
	if got := runMgr(t, m2, ntpReflection()); got != xdpDrop {
		t.Fatalf("after adopting: verdict %d, want DROP — the restart lost the live mitigation", got)
	}

	inst2 := newInstaller(t, m2)
	if err := inst2.Install(instVictim, ntpRules(instVictim, time.Hour)); err != nil {
		t.Fatalf("re-Install after adoption: %v", err)
	}
	if got := policyIDOf(t, inst2, instVictim); got != want[instVictim] {
		t.Errorf("policy id after adoption = %d, want the adopted %d", got, want[instVictim])
	}
	// The other victim's id must still be reserved even though this process has
	// not rehydrated it yet.
	if !inst2.takenPolicy[want[instVictim2]] {
		t.Errorf("policy id %d (still live in the kernel for %s) is on the free list; the next new "+
			"victim would be pointed at another victim's rules", want[instVictim2], instVictim2)
	}
	if got := runMgr(t, m2, ntpReflection()); got != xdpDrop {
		t.Fatalf("after re-install: verdict %d, want DROP", got)
	}
}

// TestAdoptionReapsExpiredVictims: the previous process's bans that lapsed
// during the downtime are already inert (the datapath treats an expired rule as
// absent), so their slots come back instead of leaking for the life of the
// process.
func TestAdoptionReapsExpiredVictims(t *testing.T) {
	dir := pinDir(t)
	opts := testOptions(t, dir, "lo")

	m1 := mustOpen(t, opts)
	inst1 := newInstaller(t, m1)
	inst1.bootNs = func() uint64 { return 1 }
	if err := inst1.Install(instVictim, ntpRules(instVictim, time.Nanosecond)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := m1.Close(config.OnExitKeep); err != nil {
		t.Fatalf("Close(keep): %v", err)
	}

	m2 := mustOpen(t, opts)
	inst2 := newInstaller(t, m2)
	// Any call triggers adoption; use the unrelated victim a fresh attack would.
	if err := inst2.Install(instVictim2, ntpRules(instVictim2, time.Hour)); err != nil {
		t.Fatalf("Install after adoption: %v", err)
	}
	if _, ok := inst2.policyOf[instVictim]; ok {
		t.Error("an expired adopted victim was kept; its slot is leaked for the life of the process")
	}
	ents, err := victimEntries(m2.Maps())
	if err != nil {
		t.Fatalf("victimEntries: %v", err)
	}
	for _, e := range ents {
		if e.prefix == instVictim {
			t.Errorf("the expired victim %s is still in kapkan_victims", e.prefix)
		}
	}
}

/* ---------------------------------------------------------------- refusals */

// TestInstallerRefusesWhatTheBlockCannotHold: more rules than a policy block,
// none at all, and a mapped-IPv6 victim.
func TestInstallerRefusesWhatTheBlockCannotHold(t *testing.T) {
	m := mustOpen(t, testOptions(t, pinDir(t), "lo"))
	inst := newInstaller(t, m)

	if err := inst.Install(instVictim, DynamicRules{TTL: time.Hour}); err == nil {
		t.Error("accepted an empty rule set")
	}

	too := DynamicRules{TTL: time.Hour}
	for range RulesPerPolicy + 1 {
		too.Specs = append(too.Specs, RuleSpec{Action: ActionDrop, Dst: instVictim})
	}
	if err := inst.Install(instVictim, too); err == nil {
		t.Errorf("accepted %d rules; a block holds %d, so some would have been dropped silently",
			len(too.Specs), RulesPerPolicy)
	}

	mapped := netip.MustParsePrefix("::ffff:203.0.113.9/128")
	if err := inst.Install(mapped, DynamicRules{
		Specs: []RuleSpec{{Action: ActionDrop, Dst: mapped}}, TTL: time.Hour,
	}); err == nil {
		t.Error("accepted an IPv4-mapped IPv6 victim; the datapath never normalises those, so the " +
			"rules would match nothing")
	}
}

/* ----------------------------------------------------------------- helpers */

func policyIDOf(t *testing.T, i *Installer, v netip.Prefix) uint32 {
	t.Helper()
	i.mu.Lock()
	defer i.mu.Unlock()
	id, ok := i.policyOf[v]
	if !ok {
		t.Fatalf("no policy id for %s", v)
	}
	return id
}

func profileIDOf(t *testing.T, i *Installer, v netip.Prefix) uint32 {
	t.Helper()
	i.mu.Lock()
	defer i.mu.Unlock()
	id, ok := i.victimProfile[v]
	if !ok {
		t.Fatalf("no profile id for %s", v)
	}
	return id
}

func blockOf(t *testing.T, m *Manager, policyID uint32) PolicyBlock {
	t.Helper()
	maps := m.Maps()
	cfg, err := ReadConfig(maps)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	var b PolicyBlock
	if err := maps.KapkanPolicies.Lookup(cfg.Generation*PolicyStride(maps)+policyID, &b); err != nil {
		t.Fatalf("read policy block %d: %v", policyID, err)
	}
	return b
}

func readProfile(m *Manager, id uint32) (Profile, error) {
	var p Profile
	err := m.Maps().KapkanProfiles.Lookup(id, &p)
	return p, err
}

// victimN is the n-th distinct victim in 203.0.113.0/24 and 203.0.114.0/24, so a
// test can fill a policy map without hand-writing addresses.
func victimN(n uint32) netip.Prefix {
	b := [4]byte{203, 0, 113 + byte(n/200), byte(n % 200)}
	return netip.PrefixFrom(netip.AddrFrom4(b), 32)
}

// ntpReflectionTo is ntpReflection aimed at a different victim.
func ntpReflectionTo(dst [4]byte) []byte {
	return cat(eth(etherTypeIPv4), ipv4From(instAttacker, dst, 17, 0, 28), udp(123, 40000, 20))
}

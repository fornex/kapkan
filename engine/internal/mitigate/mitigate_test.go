package mitigate

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"log/slog"
)

func baseYAML() string {
	return `
listen:
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
  - "2001:db8::/32"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 3
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  next_hop6: "100::1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
notify: {}
api:
  listen: "127.0.0.1:8080"
`
}

// liveYAML returns the base config with dry-run explicitly disabled.
func liveYAML() string { return "dry_run: false\n" + baseYAML() }

func storeFrom(t *testing.T, yaml string) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return config.NewStore("", cfg)
}

// recorder is a test announcer capturing AddPath/DeletePath calls for both
// RTBH (keyed by prefix) and FlowSpec (keyed by rule string).
type recorder struct {
	mu        sync.Mutex
	announced map[string]int
	withdrawn map[string]int
	fsUp      map[string]int
	fsDown    map[string]int
	// lastCommunities / lastLocalPref record the BGP attributes of the most
	// recent blackhole Announce, so a test can assert they are frozen at ban
	// time rather than read live at a (possibly post-reload) escalation.
	lastCommunities []uint32
	lastLocalPref   uint32
	// events records every announce/withdraw in call order so a test can
	// assert make-before-break: the new rung goes up before the old comes
	// down. Entries: "announce <prefix>", "withdraw <prefix>",
	// "fs-announce", "fs-withdraw".
	events []string
}

func newRecorder() *recorder {
	return &recorder{announced: map[string]int{}, withdrawn: map[string]int{}, fsUp: map[string]int{}, fsDown: map[string]int{}}
}

func (r *recorder) Announce(_ context.Context, prefix netip.Prefix, attrs blackholeAttrs) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.announced[prefix.String()]++
	r.lastCommunities = append([]uint32(nil), attrs.communities...)
	r.lastLocalPref = attrs.localPref
	r.events = append(r.events, "announce "+prefix.String())
	return nil
}

func (r *recorder) Withdraw(_ context.Context, prefix netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawn[prefix.String()]++
	r.events = append(r.events, "withdraw "+prefix.String())
	return nil
}

// eventLog returns a copy of the ordered announce/withdraw event log.
func (r *recorder) eventLog() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

// communities returns the community set of the most recent blackhole announce.
func (r *recorder) communities() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint32(nil), r.lastCommunities...)
}

// localPref returns the local-pref of the most recent blackhole announce.
func (r *recorder) localPref() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastLocalPref
}

func (r *recorder) announceCount(p string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.announced[p]
}

func (r *recorder) withdrawCount(p string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.withdrawn[p]
}

func (r *recorder) AnnounceFlowSpec(_ context.Context, rule FlowSpecRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fsUp[rule.String()]++
	r.events = append(r.events, "fs-announce")
	return nil
}

func (r *recorder) WithdrawFlowSpec(_ context.Context, rule FlowSpecRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fsDown[rule.String()]++
	r.events = append(r.events, "fs-withdraw")
	return nil
}

func (r *recorder) flowSpecUp() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int{}
	for k, v := range r.fsUp {
		out[k] = v
	}
	return out
}

func (r *recorder) flowSpecDownTotal() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.fsDown {
		n += v
	}
	return n
}

type mockClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mockClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *mockClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newMitigator(t *testing.T, yaml string, rec announcer, clk *mockClock) *Mitigator {
	t.Helper()
	return newMitigatorStore(t, storeFrom(t, yaml), rec, clk)
}

func newMitigatorStore(t *testing.T, store *config.Store, rec announcer, clk *mockClock) *Mitigator {
	t.Helper()
	opts := []Option{withAnnouncer(rec)}
	if clk != nil {
		opts = append(opts, WithClock(clk.Now))
	}
	m, err := New(store, slog.New(slog.NewTextHandler(testWriter{t}, nil)), opts...)
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = context.Background()
	return m
}

// testWriter routes slog output to t.Log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func startedEvent(target string) engine.Event {
	return engine.Event{
		Kind:       engine.AttackStarted,
		Scope:      engine.ScopeHost,
		Target:     netip.MustParseAddr(target),
		Group:      "global",
		BanEnabled: true,
		Metric:     engine.MetricPPS,
		Rate:       200000,
		Threshold:  80000,
		At:         time.Now(),
	}
}

func TestLiveAnnounceAndWithdraw(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)

	ev := startedEvent("203.0.113.66")
	ban := m.OnAttackStarted(ev)
	if ban.State != BanActive {
		t.Fatalf("ban state = %s, want active", ban.State)
	}
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("announce count = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}

	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: ev.Target, At: time.Now()})
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("withdraw count = %d, want 1", rec.withdrawCount("203.0.113.66/32"))
	}
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0 after withdraw", len(m.ActiveBans()))
	}
}

func TestDryRunNeverSends(t *testing.T) {
	rec := newRecorder()
	// Default config (no dry_run key) => dry_run true.
	m := newMitigator(t, baseYAML(), rec, nil)
	if !m.DryRun() {
		t.Fatal("expected dry-run by default")
	}
	ban := m.OnAttackStarted(startedEvent("203.0.113.66"))
	if ban.State != BanActive {
		t.Fatalf("dry-run ban state = %s, want active (virtual)", ban.State)
	}
	if !ban.DryRun {
		t.Error("ban.DryRun = false, want true")
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Errorf("dry-run announced %d routes; must never send", rec.announceCount("203.0.113.66/32"))
	}
	// Virtual ban still tracked and withdrawable without sending.
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: netip.MustParseAddr("203.0.113.66"), At: time.Now()})
	if rec.withdrawCount("203.0.113.66/32") != 0 {
		t.Errorf("dry-run withdrew %d routes; must never send", rec.withdrawCount("203.0.113.66/32"))
	}
}

func TestWhitelistNeverBanned(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)

	ban := m.OnAttackStarted(startedEvent("203.0.113.1")) // whitelisted
	if ban.State != BanRejected {
		t.Fatalf("whitelisted ban state = %s, want rejected", ban.State)
	}
	if rec.announceCount("203.0.113.1/32") != 0 {
		t.Error("whitelisted address was announced; safety rule violated")
	}
	// Manual ban must also refuse.
	mb, err := m.ManualBan(netip.MustParseAddr("203.0.113.1"))
	if err != nil {
		t.Fatalf("ManualBan err = %v", err)
	}
	if mb.State != BanRejected {
		t.Errorf("manual whitelisted ban = %s, want rejected", mb.State)
	}
}

func TestMaxActiveBansCap(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil) // max_active_bans: 3

	for i := 0; i < 3; i++ {
		addr := netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)})
		ban := m.OnAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: addr, BanEnabled: true, At: time.Now()})
		if ban.State != BanActive {
			t.Fatalf("ban %d state = %s, want active", i, ban.State)
		}
	}
	// 4th must be rejected.
	ban := m.OnAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: netip.MustParseAddr("203.0.113.20"), BanEnabled: true, At: time.Now()})
	if ban.State != BanRejected {
		t.Fatalf("4th ban state = %s, want rejected (cap reached)", ban.State)
	}
	if rec.announceCount("203.0.113.20/32") != 0 {
		t.Error("over-cap ban was announced; must refuse")
	}
	if len(m.ActiveBans()) != 3 {
		t.Errorf("active bans = %d, want 3", len(m.ActiveBans()))
	}
}

func TestTTLExpiryAutoWithdraws(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "ttl_seconds: 600", "ttl_seconds: 5", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	m.OnAttackStarted(startedEvent("203.0.113.66"))
	if len(m.ActiveBans()) != 1 {
		t.Fatalf("active bans = %d, want 1", len(m.ActiveBans()))
	}
	// Before TTL: sweep is a no-op.
	clk.Advance(4 * time.Second)
	m.sweepExpired()
	if len(m.ActiveBans()) != 1 {
		t.Fatalf("ban withdrawn before TTL; active = %d, want 1", len(m.ActiveBans()))
	}
	// After TTL: auto-withdrawn.
	clk.Advance(2 * time.Second)
	m.sweepExpired()
	if len(m.ActiveBans()) != 0 {
		t.Fatalf("ban not auto-withdrawn after TTL; active = %d, want 0", len(m.ActiveBans()))
	}
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("TTL expiry withdraw count = %d, want 1", rec.withdrawCount("203.0.113.66/32"))
	}
}

func TestTTLRefreshedWhileAttackPersists(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "ttl_seconds: 600", "ttl_seconds: 10", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	ev := startedEvent("203.0.113.66")
	m.OnAttackStarted(ev)
	clk.Advance(8 * time.Second)
	// Re-report through ban() (e.g. a manual re-ban, or a fresh AttackStarted
	// after the attack flapped): refreshes the TTL. The engine's own
	// re-mitigation of a *sustained* attack goes through AttackOngoing instead —
	// see TestOnAttackOngoingRefreshesTTL.
	m.OnAttackStarted(ev)
	clk.Advance(5 * time.Second) // 13s since first ban, but only 5s since refresh
	m.sweepExpired()
	if len(m.ActiveBans()) != 1 {
		t.Errorf("ban expired despite refresh; active = %d, want 1", len(m.ActiveBans()))
	}
}

// ongoingEvent is the heartbeat the engine emits every detection window while
// an attack it already reported stays above threshold.
func ongoingEvent(target string) engine.Event {
	return engine.Event{
		Kind:       engine.AttackOngoing,
		Scope:      engine.ScopeHost,
		Target:     netip.MustParseAddr(target),
		Group:      "global",
		BanEnabled: true,
		At:         time.Now(),
	}
}

// TestOnAttackOngoingRefreshesTTL: a sustained attack that outlives
// ban.ttl_seconds stays mitigated — the per-window AttackOngoing heartbeat
// refreshes the live ban's TTL without re-announcing the (already up) route.
func TestOnAttackOngoingRefreshesTTL(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "ttl_seconds: 600", "ttl_seconds: 10", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	m.OnAttackStarted(startedEvent("203.0.113.66"))
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Fatalf("announce count after start = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}

	// 8s in, still attacking: refresh the TTL, but do NOT re-announce the route.
	clk.Advance(8 * time.Second)
	m.OnAttackOngoing(ongoingEvent("203.0.113.66"))
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("ongoing re-announced the live route; announce count = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}

	// 13s since the original ban (> 10s TTL) but only 5s since the refresh: the
	// ban must still be up. Without the refresh it would have been swept.
	clk.Advance(5 * time.Second)
	m.sweepExpired()
	if len(m.ActiveBans()) != 1 {
		t.Errorf("ban lapsed mid-attack despite ongoing refresh; active = %d, want 1", len(m.ActiveBans()))
	}
}

// TestOnAttackOngoingNoBanIsNoOp: an ongoing heartbeat never CREATES a ban —
// that is AttackStarted's job (full safety checks + the attack sample).
func TestOnAttackOngoingNoBanIsNoOp(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)

	m.OnAttackOngoing(ongoingEvent("203.0.113.66"))
	if len(m.ActiveBans()) != 0 {
		t.Errorf("ongoing created a ban from nothing; active = %d, want 0", len(m.ActiveBans()))
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Errorf("ongoing announced a route with no ban; count = %d, want 0", rec.announceCount("203.0.113.66/32"))
	}
}

// TestOnAttackOngoingRespectsPolicy: ongoing events that policy forbids
// (ban disabled, or group scope) must be ignored — they must not refresh a TTL.
func TestOnAttackOngoingRespectsPolicy(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "ttl_seconds: 600", "ttl_seconds: 10", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)
	m.OnAttackStarted(startedEvent("203.0.113.66"))

	clk.Advance(8 * time.Second)
	noBan := ongoingEvent("203.0.113.66")
	noBan.BanEnabled = false
	m.OnAttackOngoing(noBan) // alert-only: ignored
	// Group scope: ignored even though Target matches the active host ban — a
	// group-total event has no single host to keep mitigated. The matching
	// Target makes this non-vacuous: drop the ScopeGroup guard and the ban would
	// be refreshed and survive, failing the assertion below.
	m.OnAttackOngoing(engine.Event{Kind: engine.AttackOngoing, Scope: engine.ScopeGroup,
		Target: netip.MustParseAddr("203.0.113.66"), Group: "pool", BanEnabled: true, At: clk.Now()})

	// Neither refreshed the TTL, so by 11s (> 10s TTL) the ban lapses.
	clk.Advance(3 * time.Second)
	m.sweepExpired()
	if len(m.ActiveBans()) != 0 {
		t.Errorf("ban survived despite only ignored ongoing events; active = %d, want 0", len(m.ActiveBans()))
	}
}

// TestOnAttackOngoingRefreshesPrefixTTL: the carpet (prefix) ban lifecycle gets
// the same sustained-attack protection as per-host bans.
func TestOnAttackOngoingRefreshesPrefixTTL(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(carpetMitigYAML("blackhole", ""), "ttl_seconds: 600", "ttl_seconds: 10", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	if b := m.OnAttackStarted(carpetEvent("203.0.113.0/24")); b == nil || b.State != BanActive {
		t.Fatalf("carpet ban = %+v, want active", b)
	}

	clk.Advance(8 * time.Second)
	ev := carpetEvent("203.0.113.0/24")
	ev.Kind = engine.AttackOngoing
	m.OnAttackOngoing(ev)

	clk.Advance(5 * time.Second) // 13s since ban, 5s since refresh
	m.sweepExpired()
	if len(m.ActiveBans()) != 1 {
		t.Errorf("carpet ban lapsed despite ongoing refresh; active = %d, want 1", len(m.ActiveBans()))
	}
}

// TestOnAttackOngoingPreservesBothDirections: a host attacked in both
// directions holds one shared ban; an ongoing refresh from a single direction
// must keep BOTH holds (dirMask OR, not replace) as well as refresh the TTL.
func TestOnAttackOngoingPreservesBothDirections(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "ttl_seconds: 600", "ttl_seconds: 10", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)
	target := "203.0.113.66"

	in := startedEvent(target)
	in.Direction = engine.DirIncoming
	out := startedEvent(target)
	out.Direction = engine.DirOutgoing
	m.OnAttackStarted(in)
	m.OnAttackStarted(out) // one shared ban held by both directions

	// 8s in, only the outgoing direction re-reports: refresh the shared ban's
	// TTL while keeping both direction holds.
	clk.Advance(8 * time.Second)
	ongoingOut := ongoingEvent(target)
	ongoingOut.Direction = engine.DirOutgoing
	m.OnAttackOngoing(ongoingOut)

	clk.Advance(5 * time.Second) // 13s since ban (> 10s TTL), 5s since refresh
	m.sweepExpired()
	if len(m.ActiveBans()) != 1 {
		t.Fatalf("shared ban lapsed despite ongoing refresh; active = %d, want 1", len(m.ActiveBans()))
	}

	// Both holds survived the refresh: ending ONE direction keeps the ban up,
	// ending the second withdraws it.
	endIn := engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr(target), Direction: engine.DirIncoming, At: clk.Now()}
	if b := m.OnAttackEnded(endIn); b == nil || b.State != BanActive {
		t.Fatalf("ban after incoming ended = %+v, want still active (outgoing hold survived refresh)", b)
	}
	endOut := engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr(target), Direction: engine.DirOutgoing, At: clk.Now()}
	if b := m.OnAttackEnded(endOut); b == nil || b.State != BanWithdrawn {
		t.Fatalf("ban after outgoing ended = %+v, want withdrawn", b)
	}
}

func TestIPv6Ban(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)
	ban := m.OnAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: netip.MustParseAddr("2001:db8::dead"), BanEnabled: true, At: time.Now()})
	if ban.State != BanActive {
		t.Fatalf("ipv6 ban state = %s, want active", ban.State)
	}
	if ban.Prefix.Bits() != 128 {
		t.Errorf("ipv6 prefix bits = %d, want 128", ban.Prefix.Bits())
	}
	if rec.announceCount("2001:db8::dead/128") != 1 {
		t.Errorf("ipv6 announce count = %d, want 1", rec.announceCount("2001:db8::dead/128"))
	}
}

func TestManualUnbanUnknown(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, baseYAML(), rec, nil)
	if _, err := m.ManualUnban(netip.MustParseAddr("203.0.113.99")); err == nil {
		t.Error("ManualUnban of unknown target: err = nil, want error")
	}
}

// failingAnnouncer fails every announce, to exercise the BGP-error path.
type failingAnnouncer struct{}

func (failingAnnouncer) Announce(context.Context, netip.Prefix, blackholeAttrs) error {
	return fmt.Errorf("bgp session down")
}
func (failingAnnouncer) Withdraw(context.Context, netip.Prefix) error { return nil }
func (failingAnnouncer) AnnounceFlowSpec(context.Context, FlowSpecRule) error {
	return fmt.Errorf("bgp session down")
}
func (failingAnnouncer) WithdrawFlowSpec(context.Context, FlowSpecRule) error { return nil }

func TestBGPAnnounceFailureRejectsBan(t *testing.T) {
	m := newMitigator(t, liveYAML(), failingAnnouncer{}, nil)
	ban := m.OnAttackStarted(startedEvent("203.0.113.66"))
	if ban.State != BanRejected {
		t.Fatalf("ban state = %s, want rejected on announce failure", ban.State)
	}
	if !strings.Contains(ban.Reason, "announce failed") {
		t.Errorf("reason = %q, want it to mention announce failure", ban.Reason)
	}
	// A failed announce must not be tracked as an active ban.
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0 after announce failure", len(m.ActiveBans()))
	}
}

// fsFailAnnouncer rejects every FlowSpec announce but accepts unicast
// (blackhole/divert) — the "upstream does not honor FlowSpec" case the ban
// fallback targets. It embeds *recorder so a test can inspect the resulting
// blackhole route.
type fsFailAnnouncer struct{ *recorder }

func (fsFailAnnouncer) AnnounceFlowSpec(context.Context, FlowSpecRule) error {
	return fmt.Errorf("peer rejected flowspec")
}

// TestFlowSpecAnnounceFallsBackToBlackhole: when the peer rejects a flowspec
// announce and fallback is enabled (the default), the ban degrades to a
// blackhole route rather than leaving the victim undefended.
func TestFlowSpecAnnounceFallsBackToBlackhole(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, flowSpecYAML(), fsFailAnnouncer{rec}, nil)

	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || ban.State != BanActive {
		t.Fatalf("ban = %+v, want active (fell back to blackhole)", ban)
	}
	if ban.Method != config.MitigateBlackhole {
		t.Errorf("method = %q, want blackhole after fallback", ban.Method)
	}
	if ban.FellBackFrom != config.MitigateFlowSpec {
		t.Errorf("fell_back_from = %q, want flowspec", ban.FellBackFrom)
	}
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("blackhole announce count = %d, want 1 (the fallback route)", rec.announceCount("203.0.113.66/32"))
	}
	if len(m.ActiveBans()) != 1 {
		t.Errorf("active bans = %d, want 1", len(m.ActiveBans()))
	}
}

// TestFlowSpecAnnounceFallbackDisabledRejects: with ban.fallback=none a rejected
// flowspec announce rejects the ban and announces no blackhole route.
func TestFlowSpecAnnounceFallbackDisabledRejects(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, flowSpecYAMLNoFallback(), fsFailAnnouncer{rec}, nil)

	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || ban.State != BanRejected {
		t.Fatalf("ban = %+v, want rejected (fallback disabled)", ban)
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("fallback disabled: no blackhole route should be announced")
	}
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0", len(m.ActiveBans()))
	}
}

// TestBlastRadiusFractionCap: max_banned_fraction refuses new bans once the
// banned share of the protected (per-family) space is exceeded, even when each
// ban is under max_active_bans.
func TestBlastRadiusFractionCap(t *testing.T) {
	// /24 = 256 addresses; 0.01 allows (banned+1)/256 <= 0.01 → at most 2 bans,
	// so the 3rd distinct ban is refused though max_active_bans is 50.
	yaml := strings.Replace(liveYAML(), "max_active_bans: 3",
		"max_active_bans: 50\n  max_banned_fraction: 0.01", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, nil)

	for i := 0; i < 2; i++ {
		addr := netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)})
		ban := m.OnAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: addr, BanEnabled: true, At: time.Now()})
		if ban.State != BanActive {
			t.Fatalf("ban %d = %s, want active", i, ban.State)
		}
	}
	ban := m.OnAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: netip.MustParseAddr("203.0.113.20"), BanEnabled: true, At: time.Now()})
	if ban.State != BanRejected {
		t.Fatalf("3rd ban = %s, want rejected (blast-radius fraction)", ban.State)
	}
	if ban.Reason != "max_banned_fraction reached" {
		t.Errorf("reason = %q, want max_banned_fraction reached", ban.Reason)
	}
	if len(m.ActiveBans()) != 2 {
		t.Errorf("active bans = %d, want 2", len(m.ActiveBans()))
	}
}

// TestBlastRadiusRateCap: max_bans_per_window bounds how fast new bans accrue;
// after the window elapses the counter resets and bans are allowed again.
func TestBlastRadiusRateCap(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "max_active_bans: 3",
		"max_active_bans: 50\n  max_bans_per_window: 2\n  ban_window_seconds: 60", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	banAt := func(last byte) *Ban {
		return m.OnAttackStarted(engine.Event{Kind: engine.AttackStarted, Scope: engine.ScopeHost,
			Target: netip.AddrFrom4([4]byte{203, 0, 113, last}), BanEnabled: true, At: clk.Now()})
	}
	if banAt(10).State != BanActive || banAt(11).State != BanActive {
		t.Fatal("first two bans should be active within the window")
	}
	if b := banAt(12); b.State != BanRejected || b.Reason != "max_bans_per_window reached" {
		t.Fatalf("3rd ban = %+v, want rejected (rate)", b)
	}
	// Advance past the window: the counter resets and a new ban is allowed.
	clk.Advance(61 * time.Second)
	if b := banAt(13); b.State != BanActive {
		t.Fatalf("ban after window reset = %s, want active", b.State)
	}
}

func TestBanOutsideNetworksRejected(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)
	out := "198.51.100.9" // outside 203.0.113.0/24 and 2001:db8::/32

	ban := m.OnAttackStarted(startedEvent(out))
	if ban.State != BanRejected || !strings.Contains(ban.Reason, "outside configured networks") {
		t.Fatalf("auto ban outside networks: state=%s reason=%q, want rejected/outside", ban.State, ban.Reason)
	}
	// Manual ban must also be refused.
	mb, err := m.ManualBan(netip.MustParseAddr(out))
	if err != nil {
		t.Fatalf("ManualBan err = %v", err)
	}
	if mb.State != BanRejected {
		t.Errorf("manual ban outside networks = %s, want rejected", mb.State)
	}
	if rec.announceCount(out+"/32") != 0 {
		t.Error("address outside networks was announced; must never happen")
	}
}

// fileStore writes yaml to a temp file and returns a reloadable store.
func fileStore(t *testing.T, yaml string) (*config.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return config.NewStore(path, cfg), path
}

// TestNetworksShrinkWithdrawsBan verifies that when a config reload removes
// the prefix an active ban belongs to, the sweep auto-withdraws it instead
// of leaving a route up for space we no longer protect.
func TestNetworksShrinkWithdrawsBan(t *testing.T) {
	store, path := fileStore(t, liveYAML())
	rec := newRecorder()
	m := newMitigatorStore(t, store, rec, nil)

	if ban := m.OnAttackStarted(startedEvent("203.0.113.66")); ban.State != BanActive {
		t.Fatalf("ban state = %s, want active", ban.State)
	}
	// Reload with the /24 removed (keep the IPv6 prefix so networks is non-empty).
	shrunk := strings.Replace(liveYAML(), "  - \"203.0.113.0/24\"\n", "", 1)
	if err := os.WriteFile(path, []byte(shrunk), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	m.sweepExpired()
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0 after target left networks", len(m.ActiveBans()))
	}
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("withdraw count = %d, want 1", rec.withdrawCount("203.0.113.66/32"))
	}
}

// TestDryRunReloadDoesNotStrandLiveBan verifies that a ban announced in live
// mode is still withdrawn for real after a reload flips dry_run to true. If
// the withdrawal were skipped, the real route would be stranded forever —
// violating the no-permanent-bans rule.
func TestDryRunReloadDoesNotStrandLiveBan(t *testing.T) {
	store, path := fileStore(t, liveYAML()) // dry_run: false
	rec := newRecorder()
	m := newMitigatorStore(t, store, rec, nil)

	ban := m.OnAttackStarted(startedEvent("203.0.113.66"))
	if ban.DryRun {
		t.Fatal("ban should be live (dry_run false)")
	}
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Fatalf("announce count = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}

	// Flip to dry-run and reload.
	dry := strings.Replace(liveYAML(), "dry_run: false", "dry_run: true", 1)
	if err := os.WriteFile(path, []byte(dry), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: netip.MustParseAddr("203.0.113.66"), At: time.Now()})
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Error("live ban must get a real BGP withdraw even after reload to dry-run; otherwise the route is stranded")
	}
}

// TestPolicyDisabledEventsNeverBan: events without explicit ban permission —
// ban:false hostgroups and group-scoped (total) attacks — must never reach
// the BGP speaker. The zero value of BanEnabled is the safe value.
func TestPolicyDisabledEventsNeverBan(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)

	noBan := startedEvent("203.0.113.66")
	noBan.BanEnabled = false
	if ban := m.OnAttackStarted(noBan); ban != nil {
		t.Fatalf("ban for BanEnabled=false event = %+v, want nil", ban)
	}

	groupEv := engine.Event{
		Kind:   engine.AttackStarted,
		Scope:  engine.ScopeGroup,
		Group:  "pool",
		Metric: engine.MetricPPS,
		Rate:   200000,
		At:     time.Now(),
	}
	if ban := m.OnAttackStarted(groupEv); ban != nil {
		t.Fatalf("ban for group-scoped event = %+v, want nil", ban)
	}
	if ban := m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeGroup, Group: "pool", At: time.Now()}); ban != nil {
		t.Fatalf("unban for group-scoped event = %+v, want nil", ban)
	}

	if got := rec.announceCount("203.0.113.66/32"); got != 0 {
		t.Errorf("BGP announces for policy-disabled target = %d, want 0", got)
	}
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0", len(m.ActiveBans()))
	}
}

// TestDirectionRefcountedBan: one host attacked (incoming) and attacking
// (outgoing) shares one RTBH route; the route survives the first attack
// ending and is withdrawn only when the last direction ends.
func TestDirectionRefcountedBan(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)
	target := "203.0.113.66"

	in := startedEvent(target)
	in.Direction = engine.DirIncoming
	out := startedEvent(target)
	out.Direction = engine.DirOutgoing

	if ban := m.OnAttackStarted(in); ban.State != BanActive {
		t.Fatalf("incoming ban state = %s, want active", ban.State)
	}
	if ban := m.OnAttackStarted(out); ban.State != BanActive {
		t.Fatalf("outgoing ban state = %s, want active", ban.State)
	}
	if got := rec.announceCount(target + "/32"); got != 1 {
		t.Fatalf("announce count = %d, want 1 (one shared route)", got)
	}

	// First direction ends: ban must stay up.
	endIn := engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr(target), Direction: engine.DirIncoming, At: time.Now()}
	if ban := m.OnAttackEnded(endIn); ban == nil || ban.State != BanActive {
		t.Fatalf("ban after first direction ended = %+v, want still active", ban)
	}
	if got := rec.withdrawCount(target + "/32"); got != 0 {
		t.Fatalf("withdraw count = %d, want 0 while outgoing attack persists", got)
	}

	// Second direction ends: now the route comes down.
	endOut := engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr(target), Direction: engine.DirOutgoing, At: time.Now()}
	if ban := m.OnAttackEnded(endOut); ban == nil || ban.State != BanWithdrawn {
		t.Fatalf("ban after last direction ended = %+v, want withdrawn", ban)
	}
	if got := rec.withdrawCount(target + "/32"); got != 1 {
		t.Errorf("withdraw count = %d, want 1", got)
	}
}

// fsEvent builds an attack-started event for a flowspec mitigation test.
func fsEvent(target string, typ engine.AttackType) engine.Event {
	return engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr(target), Group: "global", BanEnabled: true,
		Direction: engine.DirIncoming, Metric: engine.MetricUDPPPS, Rate: 30000, Threshold: 20000,
		Classification: &engine.Classification{Type: typ, SrcPort: 123},
		At:             time.Now(),
	}
}

func flowSpecYAML() string {
	return strings.Replace(liveYAML(), "thresholds:",
		"mitigation: flowspec\nflowspec:\n  action: discard\nthresholds:", 1)
}

// flowSpecYAMLNoFallback is flowSpecYAML with the blackhole fallback disabled,
// so a failed flowspec announce rejects the ban — exercising the pure
// rollback/reject path rather than degrading to blackhole.
func flowSpecYAMLNoFallback() string {
	return strings.Replace(flowSpecYAML(), "max_active_bans: 3",
		"max_active_bans: 3\n  fallback: none", 1)
}

func TestFlowSpecMitigationLifecycle(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, flowSpecYAML(), rec, nil)

	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || ban.State != BanActive {
		t.Fatalf("ban = %+v, want active", ban)
	}
	if ban.Method != config.MitigateFlowSpec {
		t.Errorf("method = %q, want flowspec", ban.Method)
	}
	if len(ban.FlowSpec) != 1 {
		t.Fatalf("rules = %+v, want 1 (ntp)", ban.FlowSpec)
	}
	r := ban.FlowSpec[0]
	if r.Proto != 17 || r.SrcPort != 123 || r.Action != config.FlowSpecDiscard {
		t.Errorf("rule = %+v, want udp src-port 123 discard", r)
	}
	if up := rec.flowSpecUp(); up[r.String()] != 1 {
		t.Errorf("flowspec announce count for %q = %d, want 1; got %v", r.String(), up[r.String()], up)
	}
	// No RTBH /32 was announced for a flowspec ban.
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("flowspec ban must not announce an RTBH route")
	}

	// Ending the attack withdraws the rule.
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: time.Now()})
	if rec.flowSpecDownTotal() != 1 {
		t.Errorf("flowspec withdraw total = %d, want 1", rec.flowSpecDownTotal())
	}
}

func TestFlowSpecDryRunNeverSends(t *testing.T) {
	rec := newRecorder()
	// baseYAML() defaults to dry_run true; add flowspec policy.
	yaml := strings.Replace(baseYAML(), "thresholds:",
		"mitigation: flowspec\nflowspec:\n  action: discard\nthresholds:", 1)
	m := newMitigator(t, yaml, rec, nil)

	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || ban.State != BanActive || !ban.DryRun {
		t.Fatalf("ban = %+v, want active dry-run", ban)
	}
	if len(ban.FlowSpec) != 1 {
		t.Errorf("dry-run ban should still carry generated rules, got %+v", ban.FlowSpec)
	}
	if len(rec.flowSpecUp()) != 0 {
		t.Errorf("dry-run announced flowspec rules: %v", rec.flowSpecUp())
	}
}

// flakyFS announces the first FlowSpec rule, then fails — to exercise the
// partial-announce rollback. It tracks announces and withdraws.
type flakyFS struct {
	mu       sync.Mutex
	announce int
	up       []string
	down     []string
}

func (f *flakyFS) Announce(context.Context, netip.Prefix, blackholeAttrs) error { return nil }
func (f *flakyFS) Withdraw(context.Context, netip.Prefix) error                 { return nil }
func (f *flakyFS) AnnounceFlowSpec(_ context.Context, r FlowSpecRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.announce++
	if f.announce >= 2 {
		return fmt.Errorf("flowspec session down")
	}
	f.up = append(f.up, r.String())
	return nil
}
func (f *flakyFS) WithdrawFlowSpec(_ context.Context, r FlowSpecRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = append(f.down, r.String())
	return nil
}

// TestFlowSpecPartialAnnounceRollback: when a later rule in the set fails to
// announce, the rules already installed are withdrawn (no half-mitigated
// RIB) and — with fallback disabled — the ban is rejected.
func TestFlowSpecPartialAnnounceRollback(t *testing.T) {
	rec := &flakyFS{}
	m := newMitigator(t, flowSpecYAMLNoFallback(), rec, nil)

	// A mixed-vector attack with two known reflector ports → 3 rules
	// (dst-only + udp/123 + udp/53), so the 2nd announce fails.
	ev := fsEvent("203.0.113.66", engine.AttackMixed)
	ev.Sample = &engine.AttackSample{TopSrcPorts: []engine.Counter{
		{Key: "123", Packets: 100}, {Key: "53", Packets: 50},
	}}
	ban := m.OnAttackStarted(ev)
	if ban == nil || ban.State != BanRejected {
		t.Fatalf("ban = %+v, want rejected on announce failure", ban)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	// Rule 0 announced, rule 1 failed, rule 2 never attempted → rule 0 rolled back.
	if len(rec.up) != 1 || len(rec.down) != 1 {
		t.Errorf("announced %d / withdrew %d, want 1 announced then 1 rolled back", len(rec.up), len(rec.down))
	}
	if len(rec.up) == 1 && len(rec.down) == 1 && rec.up[0] != rec.down[0] {
		t.Errorf("rolled-back rule %q != announced rule %q", rec.down[0], rec.up[0])
	}
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0 (rejected ban not tracked)", len(m.ActiveBans()))
	}
}

// escalationYAML builds a live config with a global none → flowspec →
// blackhole ladder.
func escalationYAML() string {
	return strings.Replace(liveYAML(), "thresholds:",
		"flowspec:\n  action: discard\nescalation:\n"+
			"  - {after_seconds: 0, action: none}\n"+
			"  - {after_seconds: 5, action: flowspec}\n"+
			"  - {after_seconds: 10, action: blackhole}\n"+
			"thresholds:", 1)
}

func TestEscalationLadderProgression(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, escalationYAML(), rec, clk)

	// Rung 0 (t=0): alert only — nothing announced.
	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || ban.State != BanActive {
		t.Fatalf("ban = %+v, want active", ban)
	}
	if ban.Method != "" || ban.EscalationStep != 0 {
		t.Errorf("initial method/step = %q/%d, want alert-only at step 0", ban.Method, ban.EscalationStep)
	}
	if len(rec.flowSpecUp()) != 0 || rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("rung 0 (none) announced something")
	}

	// t=6s: escalate to flowspec.
	clk.Advance(6 * time.Second)
	m.sweepExpired()
	if up := rec.flowSpecUp(); len(up) != 1 {
		t.Fatalf("after 6s: flowspec announces = %v, want 1", up)
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("blackhole announced too early")
	}

	// t=11s: escalate to blackhole — flowspec withdrawn, RTBH announced.
	clk.Advance(5 * time.Second)
	m.sweepExpired()
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("after 11s: blackhole announces = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}
	if rec.flowSpecDownTotal() != 1 {
		t.Errorf("flowspec not withdrawn on escalation to blackhole: down=%d", rec.flowSpecDownTotal())
	}
	bans := m.ActiveBans()
	if len(bans) != 1 || bans[0].Method != config.MitigateBlackhole || bans[0].EscalationStep != 2 {
		t.Errorf("final ban = %+v, want blackhole at step 2", bans)
	}

	// Attack ends: blackhole withdrawn.
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: clk.Now()})
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("blackhole not withdrawn on attack end: %d", rec.withdrawCount("203.0.113.66/32"))
	}
}

// TestEscalationEndsMidLadder: an attack that ends while at the flowspec rung
// withdraws the flowspec rules and never reaches blackhole.
func TestEscalationEndsMidLadder(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, escalationYAML(), rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	clk.Advance(6 * time.Second)
	m.sweepExpired() // → flowspec
	if len(rec.flowSpecUp()) != 1 {
		t.Fatal("expected flowspec rung")
	}
	// End before the blackhole rung's 10s.
	clk.Advance(1 * time.Second)
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: clk.Now()})
	if rec.flowSpecDownTotal() != 1 {
		t.Errorf("flowspec not withdrawn on mid-ladder end: %d", rec.flowSpecDownTotal())
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("blackhole reached despite ending at the flowspec rung")
	}
}

// TestEscalationTTLStops: a TTL shorter than the ladder withdraws the ban
// before it can escalate further.
func TestEscalationTTLStops(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(escalationYAML(), "ttl_seconds: 600", "ttl_seconds: 7", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	clk.Advance(6 * time.Second)
	m.sweepExpired() // → flowspec at 6s
	if len(rec.flowSpecUp()) != 1 {
		t.Fatal("expected flowspec rung at 6s")
	}
	// TTL (7s) fires before the 10s blackhole rung.
	clk.Advance(2 * time.Second) // t=8s > ttl 7s
	m.sweepExpired()
	if len(m.ActiveBans()) != 0 {
		t.Error("ban should have TTL-expired before reaching blackhole")
	}
	if rec.flowSpecDownTotal() != 1 {
		t.Errorf("flowspec not withdrawn on TTL expiry: %d", rec.flowSpecDownTotal())
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("blackhole reached despite TTL expiring first")
	}
}

// TestEscalationMakeBeforeBreak: escalating flowspec → blackhole must bring
// the blackhole route UP before tearing the flowspec rules DOWN, so the victim
// is never momentarily unprotected during the switch.
func TestEscalationMakeBeforeBreak(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, escalationYAML(), rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	clk.Advance(6 * time.Second)
	m.sweepExpired() // → flowspec
	clk.Advance(5 * time.Second)
	m.sweepExpired() // → blackhole

	log := rec.eventLog()
	annIdx, wdIdx := -1, -1
	for i, e := range log {
		if e == "announce 203.0.113.66/32" && annIdx == -1 {
			annIdx = i
		}
		if e == "fs-withdraw" {
			wdIdx = i
		}
	}
	if annIdx == -1 || wdIdx == -1 {
		t.Fatalf("expected a blackhole announce and a flowspec withdraw; log=%v", log)
	}
	if annIdx > wdIdx {
		t.Errorf("make-before-break violated: blackhole announced at idx %d AFTER flowspec withdrawn at idx %d; log=%v", annIdx, wdIdx, log)
	}
}

// TestEscalationSkipsIntermediateRung: when several rungs come due before a
// single sweep (a long-running attack, or the daemon catching up), the ban
// jumps straight to the highest due rung and never announces the rungs it
// skips past.
func TestEscalationSkipsIntermediateRung(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, escalationYAML(), rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	// Jump past BOTH the 5s flowspec rung and the 10s blackhole rung at once.
	clk.Advance(12 * time.Second)
	m.sweepExpired()

	if len(rec.flowSpecUp()) != 0 {
		t.Errorf("intermediate flowspec rung announced during catch-up: %v", rec.flowSpecUp())
	}
	if rec.flowSpecDownTotal() != 0 {
		t.Errorf("skipped flowspec rung was withdrawn (it was never up): %d", rec.flowSpecDownTotal())
	}
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("blackhole announces = %d, want 1 (jumped straight to it)", rec.announceCount("203.0.113.66/32"))
	}
	bans := m.ActiveBans()
	if len(bans) != 1 || bans[0].EscalationStep != 2 || bans[0].Method != config.MitigateBlackhole {
		t.Errorf("ban = %+v, want blackhole at step 2", bans)
	}
}

// TestEscalationBoundaryDueTime: a rung fires at exactly its after_seconds,
// neither a tick early nor a tick late.
func TestEscalationBoundaryDueTime(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, escalationYAML(), rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))

	// Just before the 5s flowspec rung: nothing yet.
	clk.Advance(4*time.Second + 999*time.Millisecond)
	m.sweepExpired()
	if len(rec.flowSpecUp()) != 0 {
		t.Errorf("flowspec fired before its 5s due time: %v", rec.flowSpecUp())
	}
	// Exactly at 5s: it fires.
	clk.Advance(1 * time.Millisecond)
	m.sweepExpired()
	if len(rec.flowSpecUp()) != 1 {
		t.Errorf("flowspec did not fire at exactly 5s: %v", rec.flowSpecUp())
	}
}

// TestEscalationStopsAfterAttackEnds: once the attack ends and the ban is
// withdrawn, later rungs never fire even as their delays elapse — the ladder
// only advances while the ban is still active.
func TestEscalationStopsAfterAttackEnds(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, escalationYAML(), rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	clk.Advance(6 * time.Second)
	m.sweepExpired() // → flowspec
	clk.Advance(1 * time.Second)
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: clk.Now()})

	// Time marches past the 10s blackhole rung, but the ban is gone.
	clk.Advance(10 * time.Second)
	m.sweepExpired()
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Errorf("blackhole announced after the attack already ended: %d", rec.announceCount("203.0.113.66/32"))
	}
}

// hostgroupEscalationYAML gives the "web" group its own flowspec → blackhole
// ladder while the global config keeps the default single-rung blackhole.
func hostgroupEscalationYAML() string {
	return strings.Replace(liveYAML(), "thresholds:",
		"flowspec:\n  action: discard\n"+
			"hostgroups:\n"+
			"  - name: web\n"+
			"    networks:\n"+
			"      - \"203.0.113.64/26\"\n"+
			"    escalation:\n"+
			"      - {after_seconds: 0, action: flowspec}\n"+
			"      - {after_seconds: 5, action: blackhole}\n"+
			"thresholds:", 1)
}

// TestEscalationPerHostgroupLadder: a hostgroup's own ladder is applied to
// targets inside it, independent of the global policy.
func TestEscalationPerHostgroupLadder(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	m := newMitigator(t, hostgroupEscalationYAML(), rec, clk)

	// 203.0.113.66 is inside 203.0.113.64/26 → the "web" group, whose rung 0
	// is flowspec (not the global blackhole default).
	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || ban.Method != config.MitigateFlowSpec || ban.EscalationStep != 0 {
		t.Fatalf("ban = %+v, want flowspec at step 0 (group ladder)", ban)
	}
	if rec.announceCount("203.0.113.66/32") != 0 {
		t.Error("group rung-0 is flowspec; no blackhole should be announced")
	}
	if len(rec.flowSpecUp()) != 1 {
		t.Errorf("group rung-0 flowspec not announced: %v", rec.flowSpecUp())
	}

	// After 5s it climbs to the group's blackhole rung.
	clk.Advance(6 * time.Second)
	m.sweepExpired()
	if rec.announceCount("203.0.113.66/32") != 1 || rec.flowSpecDownTotal() != 1 {
		t.Errorf("group did not escalate to blackhole: ann=%d fsDown=%d",
			rec.announceCount("203.0.113.66/32"), rec.flowSpecDownTotal())
	}
}

// TestEscalationRateLimitFlowSpecRung: a flowspec rung honours a rate_limit
// policy (not just discard).
func TestEscalationRateLimitFlowSpecRung(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	yaml := strings.Replace(liveYAML(), "thresholds:",
		"flowspec:\n  action: rate_limit\n  rate_mbps: 100\n"+
			"escalation:\n"+
			"  - {after_seconds: 0, action: none}\n"+
			"  - {after_seconds: 5, action: flowspec}\n"+
			"thresholds:", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	clk.Advance(6 * time.Second)
	m.sweepExpired() // → flowspec rate_limit

	bans := m.ActiveBans()
	if len(bans) != 1 || bans[0].Method != config.MitigateFlowSpec {
		t.Fatalf("ban = %+v, want flowspec", bans)
	}
	if len(bans[0].FlowSpec) != 1 || bans[0].FlowSpec[0].Action != config.FlowSpecRateLimit {
		t.Errorf("rule = %+v, want a single rate_limit rule", bans[0].FlowSpec)
	}
	if len(rec.flowSpecUp()) != 1 {
		t.Errorf("rate_limit flowspec rule not announced: %v", rec.flowSpecUp())
	}
}

// TestEscalationDryRunAdvances: in dry-run the ladder still advances (state and
// method change) but nothing is ever announced to BGP.
func TestEscalationDryRunAdvances(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	// baseYAML defaults to dry_run: true.
	yaml := strings.Replace(baseYAML(), "thresholds:",
		"flowspec:\n  action: discard\nescalation:\n"+
			"  - {after_seconds: 0, action: none}\n"+
			"  - {after_seconds: 5, action: flowspec}\n"+
			"  - {after_seconds: 10, action: blackhole}\n"+
			"thresholds:", 1)
	rec := newRecorder()
	m := newMitigator(t, yaml, rec, clk)

	ban := m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if ban == nil || !ban.DryRun {
		t.Fatalf("ban = %+v, want active dry-run", ban)
	}
	clk.Advance(11 * time.Second)
	m.sweepExpired() // jumps straight to blackhole in dry-run

	bans := m.ActiveBans()
	if len(bans) != 1 || bans[0].EscalationStep != 2 || bans[0].Method != config.MitigateBlackhole {
		t.Errorf("dry-run ban = %+v, want blackhole at step 2", bans)
	}
	if len(rec.flowSpecUp()) != 0 || rec.announceCount("203.0.113.66/32") != 0 {
		t.Errorf("dry-run announced to BGP: fsUp=%v rtbh=%d", rec.flowSpecUp(), rec.announceCount("203.0.113.66/32"))
	}
	if len(rec.eventLog()) != 0 {
		t.Errorf("dry-run emitted BGP events: %v", rec.eventLog())
	}
}

// TestManualBanSurvivesAutoAttackEnd: a manual ban is held by the operator,
// not by traffic. An overlapping automatic attack ending must not release it —
// only ManualUnban or the TTL does. (Regression: the dirMask reaching 0 must
// not auto-withdraw a manual ban.)
func TestManualBanSurvivesAutoAttackEnd(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, liveYAML(), rec, nil)

	mb, err := m.ManualBan(netip.MustParseAddr("203.0.113.66"))
	if err != nil || mb.State != BanActive {
		t.Fatalf("manual ban = %+v err=%v, want active", mb, err)
	}
	// An automatic incoming attack overlaps the manual ban, then ends.
	m.OnAttackStarted(startedEvent("203.0.113.66"))
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: time.Now()})

	if len(m.ActiveBans()) != 1 {
		t.Fatalf("active bans = %d, want 1 (manual ban must survive the auto-attack ending)", len(m.ActiveBans()))
	}
	if rec.withdrawCount("203.0.113.66/32") != 0 {
		t.Errorf("manual ban withdrawn on auto-attack end: %d", rec.withdrawCount("203.0.113.66/32"))
	}
	// ManualUnban still takes it down.
	if _, err := m.ManualUnban(netip.MustParseAddr("203.0.113.66")); err != nil {
		t.Errorf("ManualUnban err = %v", err)
	}
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("manual unban withdraw = %d, want 1", rec.withdrawCount("203.0.113.66/32"))
	}
}

// TestPerGroupBGPAttributesAnnounced: a hostgroup's BGP override (next-hop,
// next-hop6, communities, local-pref) is frozen on the ban and announced;
// hosts outside the group use the global defaults.
func TestPerGroupBGPAttributesAnnounced(t *testing.T) {
	rec := newRecorder()
	yaml := strings.Replace(liveYAML(), "thresholds:",
		"hostgroups:\n"+
			"  - name: customer-a\n"+
			"    networks:\n"+
			"      - \"203.0.113.64/26\"\n"+
			"      - \"2001:db8:1::/48\"\n"+
			"    bgp:\n"+
			"      next_hop: \"192.0.2.50\"\n"+
			"      next_hop6: \"100::50\"\n"+
			"      communities: [\"65000:100\", \"65001:200\"]\n"+
			"      local_pref: 250\n"+
			"thresholds:", 1)
	m := newMitigator(t, yaml, rec, nil)

	// IPv4 host inside customer-a: blackhole carries the group's attributes.
	ban := m.OnAttackStarted(startedEvent("203.0.113.66"))
	if ban.State != BanActive || ban.Method != config.MitigateBlackhole {
		t.Fatalf("ban = %+v, want active blackhole", ban)
	}
	if ban.NextHop != "192.0.2.50" || ban.LocalPref != 250 {
		t.Errorf("ban next-hop/local-pref = %q/%d, want 192.0.2.50/250", ban.NextHop, ban.LocalPref)
	}
	if !strings.Contains(ban.Route, "local-pref 250") || !strings.Contains(ban.Route, "65000:100 65001:200") {
		t.Errorf("route = %q, want community set + local-pref 250", ban.Route)
	}
	want := []uint32{65000<<16 | 100, 65001<<16 | 200}
	if got := rec.communities(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("announced communities = %v, want %v", got, want)
	}
	if rec.localPref() != 250 {
		t.Errorf("announced local-pref = %d, want 250", rec.localPref())
	}

	// IPv6 host inside customer-a uses the group's IPv6 next-hop override.
	ban6 := m.OnAttackStarted(startedEvent("2001:db8:1::99"))
	if ban6.NextHop != "100::50" {
		t.Errorf("v6 ban next-hop = %q, want 100::50 (group override)", ban6.NextHop)
	}

	// A host outside the group uses the global defaults: single community, no
	// local-pref attached.
	ban2 := m.OnAttackStarted(startedEvent("203.0.113.10"))
	if ban2.NextHop != "192.0.2.1" || ban2.LocalPref != 0 {
		t.Errorf("global ban next-hop/local-pref = %q/%d, want 192.0.2.1/0", ban2.NextHop, ban2.LocalPref)
	}
	if strings.Contains(ban2.Route, "local-pref") {
		t.Errorf("global ban route must omit local-pref: %q", ban2.Route)
	}
	if got := rec.communities(); len(got) != 1 || got[0] != 65000<<16|666 {
		t.Errorf("global announced communities = %v, want [65000:666]", got)
	}
}

// TestEscalationFreezesCommunityAcrossReload: the BGP community is frozen at
// ban time alongside the next-hop. A config reload that changes the community
// between ban creation and a delayed escalation to the blackhole rung must NOT
// change the community the ban announces. (Regression: announce used the live
// cfg community while the next-hop was frozen.)
func TestEscalationFreezesCommunityAcrossReload(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	base := strings.Replace(liveYAML(), "thresholds:",
		"escalation:\n"+
			"  - {after_seconds: 0, action: none}\n"+
			"  - {after_seconds: 5, action: blackhole}\n"+
			"thresholds:", 1)
	store, path := fileStore(t, base)
	rec := newRecorder()
	m := newMitigatorStore(t, store, rec, clk)

	// Ban starts at the alert-only rung; community 65000:666 is frozen in.
	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))

	// Operator reloads with a DIFFERENT community before the blackhole rung.
	reloaded := strings.Replace(base, `community: "65000:666"`, `community: "65000:999"`, 1)
	if err := os.WriteFile(path, []byte(reloaded), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Escalate to blackhole: it must announce with the ORIGINAL community.
	clk.Advance(6 * time.Second)
	m.sweepExpired()
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Fatalf("blackhole not announced on escalation")
	}
	want, err := config.ParseCommunity("65000:666")
	if err != nil {
		t.Fatalf("ParseCommunity: %v", err)
	}
	got := rec.communities()
	if len(got) != 1 || got[0] != want {
		t.Errorf("announced communities = %v, want [%d] (frozen at ban time, not the reloaded 65000:999)", got, want)
	}
}

// flakyRollback announces the first two FlowSpec rules, fails the third, and
// fails EVERY withdraw — to lock in that rollback is best-effort: it attempts
// to withdraw every already-installed rule even when a withdraw errors (it must
// not break on the first failure, which would orphan the rest).
type flakyRollback struct {
	mu           sync.Mutex
	announce     int
	downAttempts int
}

func (f *flakyRollback) Announce(context.Context, netip.Prefix, blackholeAttrs) error { return nil }
func (f *flakyRollback) Withdraw(context.Context, netip.Prefix) error                 { return nil }
func (f *flakyRollback) AnnounceFlowSpec(_ context.Context, _ FlowSpecRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.announce++
	if f.announce >= 3 {
		return fmt.Errorf("flowspec session down")
	}
	return nil
}
func (f *flakyRollback) WithdrawFlowSpec(_ context.Context, _ FlowSpecRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downAttempts++
	return fmt.Errorf("withdraw failed too")
}

// TestFlowSpecRollbackWithdrawFailureBestEffort: a failed rollback withdraw
// does not stop the rollback — every already-installed rule is still attempted.
func TestFlowSpecRollbackWithdrawFailureBestEffort(t *testing.T) {
	rec := &flakyRollback{}
	m := newMitigator(t, flowSpecYAMLNoFallback(), rec, nil)

	// Mixed-vector attack with two reflector ports → 3 rules (dst-only +
	// udp/123 + udp/53); the 3rd announce fails after the first two install.
	ev := fsEvent("203.0.113.66", engine.AttackMixed)
	ev.Sample = &engine.AttackSample{TopSrcPorts: []engine.Counter{
		{Key: "123", Packets: 100}, {Key: "53", Packets: 50},
	}}
	ban := m.OnAttackStarted(ev)
	if ban == nil || ban.State != BanRejected {
		t.Fatalf("ban = %+v, want rejected on announce failure", ban)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.downAttempts != 2 {
		t.Errorf("rollback withdraw attempts = %d, want 2 (best-effort continues past a failed withdraw)", rec.downAttempts)
	}
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0", len(m.ActiveBans()))
	}
}

// scrubBlock is a global scrubbing target with both v4 and v6 next-hops (the
// test base config protects IPv6 space, so divert requires next_hop6).
func scrubBlock() string {
	return "scrubbing:\n  next_hop: \"192.0.2.200\"\n  next_hop6: \"100::200\"\n  community: \"65000:300\"\n  local_pref: 200\n"
}

// TestDivertMitigation: a single-method divert ban announces the victim host
// route toward the scrubbing next-hop with the divert community, and withdraws
// it on attack end.
func TestDivertMitigation(t *testing.T) {
	rec := newRecorder()
	yaml := strings.Replace(liveYAML(), "thresholds:", scrubBlock()+"mitigation: divert\nthresholds:", 1)
	m := newMitigator(t, yaml, rec, nil)

	ban := m.OnAttackStarted(startedEvent("203.0.113.66"))
	if ban.State != BanActive || ban.Method != config.MitigateDivert {
		t.Fatalf("ban = %+v, want active divert", ban)
	}
	if ban.NextHop != "192.0.2.200" {
		t.Errorf("next-hop = %q, want scrubbing 192.0.2.200", ban.NextHop)
	}
	if !strings.Contains(ban.Route, "divert") || !strings.Contains(ban.Route, "192.0.2.200") {
		t.Errorf("route = %q, want divert via scrubbing next-hop", ban.Route)
	}
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("divert announces = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}
	if got := rec.communities(); len(got) != 1 || got[0] != 65000<<16|300 {
		t.Errorf("announced communities = %v, want scrub [65000:300]", got)
	}
	if rec.localPref() != 200 {
		t.Errorf("local-pref = %d, want 200", rec.localPref())
	}

	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: time.Now()})
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("divert host route not withdrawn on end: %d", rec.withdrawCount("203.0.113.66/32"))
	}
}

// TestEscalationDivertToBlackhole: divert → blackhole share the host-route
// NLRI, so escalating re-announces the SAME /32 with blackhole attributes
// (gobgp implicit-withdraw replaces it atomically). No explicit withdraw fires
// during the transition.
func TestEscalationDivertToBlackhole(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	yaml := strings.Replace(liveYAML(), "thresholds:",
		scrubBlock()+"escalation:\n"+
			"  - {after_seconds: 0, action: none}\n"+
			"  - {after_seconds: 5, action: divert}\n"+
			"  - {after_seconds: 10, action: blackhole}\n"+
			"thresholds:", 1)
	m := newMitigator(t, yaml, rec, clk)

	m.OnAttackStarted(startedEvent("203.0.113.66"))
	// t=6 → divert via the scrubbing next-hop.
	clk.Advance(6 * time.Second)
	m.sweepExpired()
	if bans := m.ActiveBans(); len(bans) != 1 || bans[0].Method != config.MitigateDivert || bans[0].NextHop != "192.0.2.200" {
		t.Fatalf("after 6s ban = %+v, want divert via 192.0.2.200", bans)
	}
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("divert announces = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}

	// t=11 → blackhole: same /32 re-announced with blackhole attrs, NO withdraw.
	clk.Advance(5 * time.Second)
	m.sweepExpired()
	bans := m.ActiveBans()
	if len(bans) != 1 || bans[0].Method != config.MitigateBlackhole || bans[0].NextHop != "192.0.2.1" {
		t.Fatalf("after 11s ban = %+v, want blackhole via 192.0.2.1", bans)
	}
	if rec.announceCount("203.0.113.66/32") != 2 {
		t.Errorf("announces = %d, want 2 (divert then blackhole re-announce)", rec.announceCount("203.0.113.66/32"))
	}
	if rec.withdrawCount("203.0.113.66/32") != 0 {
		t.Errorf("withdraws = %d, want 0 (same-NLRI atomic replace)", rec.withdrawCount("203.0.113.66/32"))
	}
	if got := rec.communities(); len(got) != 1 || got[0] != 65000<<16|666 {
		t.Errorf("blackhole communities = %v, want [65000:666]", got)
	}

	// Attack ends → the host route is withdrawn exactly once.
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopeHost,
		Target: netip.MustParseAddr("203.0.113.66"), Direction: engine.DirIncoming, At: clk.Now()})
	if rec.withdrawCount("203.0.113.66/32") != 1 {
		t.Errorf("withdraws after end = %d, want 1", rec.withdrawCount("203.0.113.66/32"))
	}
}

// TestEscalationFlowSpecToDivert: flowspec → divert is a cross-family switch
// (flowspec NLRI vs host route), so it is make-before-break: the divert route
// goes up before the flowspec rules come down.
func TestEscalationFlowSpecToDivert(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	rec := newRecorder()
	yaml := strings.Replace(liveYAML(), "thresholds:",
		scrubBlock()+"flowspec:\n  action: discard\nescalation:\n"+
			"  - {after_seconds: 0, action: flowspec}\n"+
			"  - {after_seconds: 5, action: divert}\n"+
			"thresholds:", 1)
	m := newMitigator(t, yaml, rec, clk)

	m.OnAttackStarted(fsEvent("203.0.113.66", engine.AttackNTPAmplification))
	if len(rec.flowSpecUp()) != 1 {
		t.Fatal("rung 0 flowspec not announced")
	}
	clk.Advance(6 * time.Second)
	m.sweepExpired()
	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("divert host route announces = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}
	if rec.flowSpecDownTotal() != 1 {
		t.Errorf("flowspec not withdrawn on cross-family escalation: %d", rec.flowSpecDownTotal())
	}
	log := rec.eventLog()
	ann, wd := -1, -1
	for i, e := range log {
		if e == "announce 203.0.113.66/32" && ann == -1 {
			ann = i
		}
		if e == "fs-withdraw" {
			wd = i
		}
	}
	if ann == -1 || wd == -1 || ann > wd {
		t.Errorf("make-before-break violated: divert announce idx %d, flowspec withdraw idx %d; log=%v", ann, wd, log)
	}
}

// TestEscalationFreezesScrubAttrsAcrossReload: the divert (scrubbing) attribute
// set is frozen on the ban at creation, like the blackhole set. A reload that
// changes the scrubbing target before the divert rung fires must not change the
// ban's announced next-hop/community.
func TestEscalationFreezesScrubAttrsAcrossReload(t *testing.T) {
	clk := &mockClock{t: time.Unix(1_700_000_000, 0)}
	base := strings.Replace(liveYAML(), "thresholds:",
		scrubBlock()+"escalation:\n  - {after_seconds: 0, action: none}\n  - {after_seconds: 5, action: divert}\nthresholds:", 1)
	store, path := fileStore(t, base)
	rec := newRecorder()
	m := newMitigatorStore(t, store, rec, clk)

	m.OnAttackStarted(startedEvent("203.0.113.66")) // alert-only rung; scrub attrs frozen

	reloaded := strings.Replace(base, "192.0.2.200", "192.0.2.250", 1)
	reloaded = strings.Replace(reloaded, "65000:300", "65000:999", 1)
	if err := os.WriteFile(path, []byte(reloaded), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	clk.Advance(6 * time.Second)
	m.sweepExpired() // → divert with the FROZEN scrubbing attrs
	if bans := m.ActiveBans(); len(bans) != 1 || bans[0].NextHop != "192.0.2.200" {
		t.Errorf("divert next-hop = %v, want frozen 192.0.2.200 (not reloaded 192.0.2.250)", m.ActiveBans())
	}
	want, err := config.ParseCommunity("65000:300")
	if err != nil {
		t.Fatalf("ParseCommunity: %v", err)
	}
	if got := rec.communities(); len(got) != 1 || got[0] != want {
		t.Errorf("divert communities = %v, want frozen [65000:300]", got)
	}
}

// TestGaugeBucketsBansByOwnDryRun: each ban is counted in the gauge bucket
// matching its OWN frozen DryRun, not the daemon's current mode. A reload that
// flips dry_run must not move a live ban's count into the dry_run bucket.
func TestGaugeBucketsBansByOwnDryRun(t *testing.T) {
	base := liveYAML() // dry_run: false
	store, path := fileStore(t, base)
	rec := newRecorder()
	m := newMitigatorStore(t, store, rec, nil)

	// A live ban → "real" bucket.
	m.OnAttackStarted(startedEvent("203.0.113.10"))
	if got := testutil.ToFloat64(metrics.AnnouncedRoutes.WithLabelValues("real")); got != 1 {
		t.Fatalf("real announced = %v, want 1", got)
	}

	// Reload flips the daemon to dry-run; the next ban is frozen as dry-run.
	dry := strings.Replace(base, "dry_run: false", "dry_run: true", 1)
	if err := os.WriteFile(path, []byte(dry), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	m.OnAttackStarted(startedEvent("203.0.113.11"))

	// The live ban stays in "real"; only the post-reload ban lands in "dry_run".
	if got := testutil.ToFloat64(metrics.AnnouncedRoutes.WithLabelValues("real")); got != 1 {
		t.Errorf("real announced = %v, want 1 (the live ban stays real)", got)
	}
	if got := testutil.ToFloat64(metrics.AnnouncedRoutes.WithLabelValues("dry_run")); got != 1 {
		t.Errorf("dry_run announced = %v, want 1 (the post-reload ban)", got)
	}
}

// carpetMitigYAML is a live config with carpet detection + the given mitigation
// method. `extra` injects top-level lines (e.g. a protected_whitelist). The
// networks are a /24 and a /16 so address-unit accounting has room.
func carpetMitigYAML(method, extra string) string {
	return `dry_run: false
listen: {netflow: ":2055"}
sampling: {default_rate: 1000}
networks: ["203.0.113.0/24", "198.51.0.0/16"]
` + extra + `thresholds: {pps: 80000, mbps: 1000, flows_per_sec: 35000}
ban: {ttl_seconds: 600, unban_hysteresis_seconds: 120, max_active_bans: 50}
carpet:
  aggregation_prefix_v4: 24
  min_hosts: 5
  thresholds: {pps: 100000}
  mitigation: ` + method + `
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors: [{address: "10.0.0.254", remote_asn: 65000}]
api: {listen: "127.0.0.1:8080"}
`
}

func carpetEvent(prefix string) engine.Event {
	p := netip.MustParsePrefix(prefix)
	return engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopePrefix,
		Target: p.Addr(), Prefix: prefix, Group: "global", BanEnabled: true,
		Metric: engine.MetricPPS, Rate: 200000, Threshold: 100000,
		Classification: &engine.Classification{Type: engine.AttackUDPFlood}, At: time.Now(),
	}
}

// TestCarpetFlowSpecBan: a carpet attack with mitigation=flowspec yields a
// FlowSpec ban anchored on the WHOLE /24 (vector-narrowed), no RTBH route, and
// ending it withdraws.
func TestCarpetFlowSpecBan(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, carpetMitigYAML("flowspec", ""), rec, nil)
	ban := m.OnAttackStarted(carpetEvent("203.0.113.0/24"))
	if ban == nil || ban.State != BanActive || ban.Method != config.MitigateFlowSpec {
		t.Fatalf("ban = %+v, want active flowspec", ban)
	}
	if len(ban.FlowSpec) != 1 || ban.FlowSpec[0].Dst != netip.MustParsePrefix("203.0.113.0/24") || ban.FlowSpec[0].Proto != 17 {
		t.Fatalf("flowspec = %+v, want one dst=203.0.113.0/24 udp rule", ban.FlowSpec)
	}
	if rec.announceCount("203.0.113.0/24") != 0 {
		t.Error("flowspec carpet ban must not announce an RTBH route")
	}
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Scope: engine.ScopePrefix, Prefix: "203.0.113.0/24", At: time.Now()})
	if len(m.ActiveBans()) != 0 {
		t.Errorf("active bans = %d, want 0 after carpet attack ended", len(m.ActiveBans()))
	}
}

// TestCarpetBlackholeBan: mitigation=blackhole announces an RTBH route for the
// whole /24.
func TestCarpetBlackholeBan(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, carpetMitigYAML("blackhole", ""), rec, nil)
	ban := m.OnAttackStarted(carpetEvent("203.0.113.0/24"))
	if ban == nil || ban.State != BanActive || ban.Method != config.MitigateBlackhole {
		t.Fatalf("ban = %+v, want active blackhole", ban)
	}
	if rec.announceCount("203.0.113.0/24") != 1 {
		t.Errorf("RTBH announce of the /24 = %d, want 1", rec.announceCount("203.0.113.0/24"))
	}
}

// TestCarpetWhitelistedMemberRejected: the absolute whitelist guarantee — a
// prefix containing a whitelisted address is refused outright, announcing
// nothing, for either method.
func TestCarpetWhitelistedMemberRejected(t *testing.T) {
	for _, method := range []string{"blackhole", "flowspec"} {
		rec := newRecorder()
		m := newMitigator(t, carpetMitigYAML(method, "protected_whitelist: [\"203.0.113.5\"]\n"), rec, nil)
		ban := m.OnAttackStarted(carpetEvent("203.0.113.0/24"))
		if ban == nil || ban.State != BanRejected || !strings.Contains(ban.Reason, "whitelisted member") {
			t.Fatalf("method %s: ban = %+v, want rejected (whitelisted member in prefix)", method, ban)
		}
		if rec.announceCount("203.0.113.0/24") != 0 || len(rec.flowSpecUp()) != 0 {
			t.Errorf("method %s: a prefix with a whitelisted member must announce nothing", method)
		}
	}
}

// TestCarpetAlertOnlyWhenBanDisabled: an alert-only carpet event (BanEnabled
// false, as the engine sets when carpet.mitigation is empty) creates no ban.
func TestCarpetAlertOnlyWhenBanDisabled(t *testing.T) {
	rec := newRecorder()
	m := newMitigator(t, carpetMitigYAML("flowspec", ""), rec, nil)
	ev := carpetEvent("203.0.113.0/24")
	ev.BanEnabled = false
	if ban := m.OnAttackStarted(ev); ban != nil {
		t.Fatalf("alert-only carpet event produced a ban: %+v", ban)
	}
	if len(m.ActiveBans()) != 0 {
		t.Error("alert-only carpet must create no ban")
	}
}

// TestCarpetPrefixCapSeparateFromHosts: max_active_prefix_bans caps carpet bans
// without starving host bans (separate cap).
func TestCarpetPrefixCapSeparateFromHosts(t *testing.T) {
	rec := newRecorder()
	yaml := strings.Replace(carpetMitigYAML("blackhole", ""), "mitigation: blackhole", "mitigation: blackhole\n  max_active_prefix_bans: 1", 1)
	m := newMitigator(t, yaml, rec, nil)
	if b := m.OnAttackStarted(carpetEvent("203.0.113.0/24")); b.State != BanActive {
		t.Fatalf("first carpet ban = %s, want active", b.State)
	}
	if b := m.OnAttackStarted(carpetEvent("198.51.100.0/24")); b.State != BanRejected || !strings.Contains(b.Reason, "max_active_prefix_bans") {
		t.Fatalf("second carpet ban = %+v, want rejected (prefix cap)", b)
	}
	if hb := m.OnAttackStarted(startedEvent("198.51.100.7")); hb.State != BanActive {
		t.Errorf("host ban = %s, want active (prefix cap must not starve host bans)", hb.State)
	}
}

// TestCarpetBlastRadiusAddressUnits: a /24 ban is weighed by its 256-address
// span, not as one unit. v4 protected = /24 + /16 = 65792 addrs; one /24
// (256/65792=0.0039) fits under 0.005, two (512/65792=0.0078) exceed.
func TestCarpetBlastRadiusAddressUnits(t *testing.T) {
	rec := newRecorder()
	yaml := strings.Replace(carpetMitigYAML("blackhole", ""), "max_active_bans: 50", "max_active_bans: 50, max_banned_fraction: 0.005", 1)
	m := newMitigator(t, yaml, rec, nil)
	if b := m.OnAttackStarted(carpetEvent("203.0.113.0/24")); b.State != BanActive {
		t.Fatalf("first /24 = %s, want active (256/65792 < 0.005)", b.State)
	}
	if b := m.OnAttackStarted(carpetEvent("198.51.100.0/24")); b.State != BanRejected || !strings.Contains(b.Reason, "max_banned_fraction") {
		t.Fatalf("second /24 = %+v, want rejected — proves a /24 counts as 256 addresses", b)
	}
}

// carpetMitigYAMLv6 mirrors carpetMitigYAML but protects an IPv6 /32
// (2001:db8::/32 => ProtectedAddrs(is6) = 2^96) and sets an IPv6 aggregation
// prefix so carpet bans on an IPv6 supernet sit inside the configured network.
// `extra` injects top-level lines; networks include an IPv4 net too so a mixed
// config is exercised, but the IPv6 /32 is what the v6 blast-radius math uses.
func carpetMitigYAMLv6(method, extra string) string {
	return `dry_run: false
listen: {netflow: ":2055"}
sampling: {default_rate: 1000}
networks: ["203.0.113.0/24", "2001:db8::/32"]
` + extra + `thresholds: {pps: 80000, mbps: 1000, flows_per_sec: 35000}
ban: {ttl_seconds: 600, unban_hysteresis_seconds: 120, max_active_bans: 50}
carpet:
  aggregation_prefix_v4: 24
  aggregation_prefix_v6: 48
  min_hosts: 5
  thresholds: {pps: 100000}
  mitigation: ` + method + `
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors: [{address: "10.0.0.254", remote_asn: 65000}]
api: {listen: "127.0.0.1:8080"}
`
}

// TestCarpetBlastRadiusAddressUnitsV6 is the IPv6 analogue of
// TestCarpetBlastRadiusAddressUnits: it locks addressCountForPrefix for the
// 128-bit family (2^(128-bits)) and the blast-radius fraction gate against
// ProtectedAddrs(is6). Protected space is the IPv6 /32 = 2^96 addresses.
// With max_banned_fraction = 1e-5:
//   - a /64 spans 2^64 addrs; (0+2^64)/2^96 = 2^-32 ≈ 2.3e-10 < 1e-5 -> ADMIT.
//   - a /48 spans 2^80 addrs; (0+2^80)/2^96 = 2^-16 ≈ 1.526e-5 > 1e-5 -> REJECT
//     with state BanRejected, reason max_banned_fraction, and the
//     blast_radius_fraction rejection metric incremented.
//
// Picking /64 (admit) and /48 (reject) makes both cases unambiguous and proves
// the IPv6 span is 2^(128-bits), not a 32-bit (IPv4) computation.
func TestCarpetBlastRadiusAddressUnitsV6(t *testing.T) {
	rec := newRecorder()
	yaml := strings.Replace(carpetMitigYAMLv6("blackhole", ""),
		"max_active_bans: 50", "max_active_bans: 50, max_banned_fraction: 0.00001", 1)
	m := newMitigator(t, yaml, rec, nil)

	// ADMIT: a /64 within the protected /32 is far under the fraction.
	const v64 = "2001:db8:0:1::/64" // 2^64 addrs; 2^64/2^96 = 2^-32 < 1e-5
	if b := m.OnAttackStarted(carpetEvent(v64)); b == nil || b.State != BanActive ||
		b.Method != config.MitigateBlackhole {
		t.Fatalf("IPv6 /64 carpet ban = %+v, want active blackhole (2^64/2^96 = 2^-32 < 1e-5)", b)
	}
	if got := rec.announceCount(netip.MustParsePrefix(v64).String()); got != 1 {
		t.Errorf("RTBH announce of the IPv6 /64 = %d, want 1", got)
	}

	// REJECT: a /48 (2^80 addrs) alone already exceeds the fraction, even with an
	// empty ban table — proves the span is 2^(128-48)=2^80, not an IPv4-width calc.
	before := testutil.ToFloat64(metrics.BansRejectedTotal.WithLabelValues("blast_radius_fraction"))
	rec48 := newRecorder()
	m48 := newMitigator(t, yaml, rec48, nil)
	const v48 = "2001:db8::/48" // 2^80 addrs; 2^80/2^96 = 2^-16 > 1e-5
	b := m48.OnAttackStarted(carpetEvent(v48))
	if b == nil || b.State != BanRejected {
		t.Fatalf("IPv6 /48 carpet ban = %+v, want rejected (2^80/2^96 = 2^-16 > 1e-5)", b)
	}
	if b.Reason != "max_banned_fraction reached" {
		t.Errorf("reason = %q, want max_banned_fraction reached", b.Reason)
	}
	if rec48.announceCount(netip.MustParsePrefix(v48).String()) != 0 {
		t.Error("a blast-radius-rejected IPv6 /48 must announce no route")
	}
	after := testutil.ToFloat64(metrics.BansRejectedTotal.WithLabelValues("blast_radius_fraction"))
	if after-before != 1 {
		t.Errorf("blast_radius_fraction metric delta = %v, want 1", after-before)
	}
}

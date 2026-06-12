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

// recorder is a test announcer capturing AddPath/DeletePath calls.
type recorder struct {
	mu        sync.Mutex
	announced map[string]int
	withdrawn map[string]int
}

func newRecorder() *recorder {
	return &recorder{announced: map[string]int{}, withdrawn: map[string]int{}}
}

func (r *recorder) Announce(_ context.Context, prefix netip.Prefix, _ string, _ uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.announced[prefix.String()]++
	return nil
}

func (r *recorder) Withdraw(_ context.Context, prefix netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawn[prefix.String()]++
	return nil
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
	store := storeFrom(t, yaml)
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
	// Re-report (engine re-emit / ongoing): refreshes TTL.
	m.OnAttackStarted(ev)
	clk.Advance(5 * time.Second) // 13s since first ban, but only 5s since refresh
	m.sweepExpired()
	if len(m.ActiveBans()) != 1 {
		t.Errorf("ban expired despite refresh; active = %d, want 1", len(m.ActiveBans()))
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

func (failingAnnouncer) Announce(context.Context, netip.Prefix, string, uint32) error {
	return fmt.Errorf("bgp session down")
}
func (failingAnnouncer) Withdraw(context.Context, netip.Prefix) error { return nil }

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

func newMitigatorStore(t *testing.T, store *config.Store, rec announcer) *Mitigator {
	t.Helper()
	m, err := New(store, slog.New(slog.NewTextHandler(testWriter{t}, nil)), withAnnouncer(rec))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = context.Background()
	return m
}

// TestNetworksShrinkWithdrawsBan verifies that when a config reload removes
// the prefix an active ban belongs to, the sweep auto-withdraws it instead
// of leaving a route up for space we no longer protect.
func TestNetworksShrinkWithdrawsBan(t *testing.T) {
	store, path := fileStore(t, liveYAML())
	rec := newRecorder()
	m := newMitigatorStore(t, store, rec)

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
	m := newMitigatorStore(t, store, rec)

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

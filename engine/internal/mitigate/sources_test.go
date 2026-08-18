package mitigate

// Unit tests for operator/API source blocks (sources.go). Everything here
// runs against dpRecorder on any host — the in-kernel half is covered by the
// dataplane package's Linux tests, and the two meet at the DynamicRules
// contract these tests pin: anchor = the SOURCE host prefix, one rule per
// victim pair, each with its own TTL.

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// srcYAML is the live dataplane config plus an allowlist entry the refusal
// tests aim at. No escalation override — source blocks need no ladder.
func srcYAML() string {
	return "dry_run: false\n" + baseYAML() + `
dataplane:
  enabled: true
  interfaces: ["eth0"]
  allowlist:
    - "198.51.100.128/28"
`
}

func newSourceMitigator(t *testing.T, yaml string, dp dataplaneBackend, clk *mockClock) *Mitigator {
	t.Helper()
	store := storeFrom(t, yaml)
	opts := []Option{withAnnouncer(newRecorder()), WithDataplane(dp)}
	if clk != nil {
		opts = append(opts, WithClock(clk.Now))
	}
	m, err := New(store, testLogger(t), opts...)
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	m.ctx = t.Context()
	return m
}

func mustBlock(t *testing.T, m *Mitigator, victim, source string, ttl time.Duration) *SourceBlock {
	t.Helper()
	sb, err := m.BlockSource(netip.MustParseAddr(victim), netip.MustParseAddr(source), ttl, "test")
	if err != nil {
		t.Fatalf("BlockSource(%s, %s): %v", victim, source, err)
	}
	return sb
}

func TestBlockSourceInstallsAnAnchoredPolicy(t *testing.T) {
	dp := &dpRecorder{}
	m := newSourceMitigator(t, srcYAML(), dp, nil)

	sb := mustBlock(t, m, "203.0.113.10", "198.51.100.7", 5*time.Minute)

	if sb.DryRun {
		t.Fatal("dry_run: false config produced a dry-run source block")
	}
	in := dp.lastInstall(t)
	wantAnchor := netip.MustParsePrefix("198.51.100.7/32")
	if in.victim != wantAnchor {
		t.Fatalf("policy anchored at %s, want the SOURCE %s", in.victim, wantAnchor)
	}
	if len(in.rules.Specs) != 1 {
		t.Fatalf("got %d specs, want 1", len(in.rules.Specs))
	}
	spec := in.rules.Specs[0]
	if spec.Src != wantAnchor {
		t.Fatalf("spec.Src = %s, want %s", spec.Src, wantAnchor)
	}
	if want := netip.MustParsePrefix("203.0.113.10/32"); spec.Dst != want {
		t.Fatalf("spec.Dst = %s, want %s", spec.Dst, want)
	}
	if spec.Action != dataplane.ActionDrop {
		t.Fatalf("spec.Action = %v, want drop", spec.Action)
	}
	if spec.TTL != 5*time.Minute {
		t.Fatalf("spec.TTL = %s, want the pair's own 5m", spec.TTL)
	}
	if in.rules.TTL != 5*time.Minute {
		t.Fatalf("set TTL = %s, want 5m", in.rules.TTL)
	}
}

func TestBlockSourceRefreshKeepsCreatedAtAndExtends(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	m := newSourceMitigator(t, srcYAML(), dp, clk)

	first := mustBlock(t, m, "203.0.113.10", "198.51.100.7", time.Minute)
	clk.Advance(30 * time.Second)
	second := mustBlock(t, m, "203.0.113.10", "198.51.100.7", 10*time.Minute)

	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("refresh changed CreatedAt: %s -> %s", first.CreatedAt, second.CreatedAt)
	}
	if want := clk.Now().Add(10 * time.Minute); !second.ExpiresAt.Equal(want) {
		t.Fatalf("refresh ExpiresAt = %s, want %s", second.ExpiresAt, want)
	}
	if got := len(m.SourceBlocks()); got != 1 {
		t.Fatalf("refresh duplicated the pair: %d entries", got)
	}
	if dp.installCount() != 2 {
		t.Fatalf("refresh must reinstall: %d installs", dp.installCount())
	}
}

func TestBlockSourceSecondVictimSharesTheAnchor(t *testing.T) {
	dp := &dpRecorder{}
	// A mock clock, because the second install re-stamps the FIRST pair with
	// its REMAINING TTL — which only equals 5m when no wall time has passed.
	m := newSourceMitigator(t, srcYAML(), dp, &mockClock{t: time.Now()})

	mustBlock(t, m, "203.0.113.10", "198.51.100.7", 5*time.Minute)
	mustBlock(t, m, "203.0.113.20", "198.51.100.7", time.Minute)

	in := dp.lastInstall(t)
	if len(in.rules.Specs) != 2 {
		t.Fatalf("got %d specs, want the source's two pairs in one policy", len(in.rules.Specs))
	}
	// Deterministic victim order, each pair with its own TTL.
	if want := netip.MustParsePrefix("203.0.113.10/32"); in.rules.Specs[0].Dst != want {
		t.Fatalf("spec[0].Dst = %s, want %s", in.rules.Specs[0].Dst, want)
	}
	if in.rules.Specs[0].TTL != 5*time.Minute || in.rules.Specs[1].TTL != time.Minute {
		t.Fatalf("per-pair TTLs = %s, %s; want 5m, 1m", in.rules.Specs[0].TTL, in.rules.Specs[1].TTL)
	}
	if in.rules.TTL != 5*time.Minute {
		t.Fatalf("set TTL = %s, want the max pair TTL 5m", in.rules.TTL)
	}
}

func TestBlockSourceRefusals(t *testing.T) {
	cases := []struct {
		name           string
		victim, source string
		ttl            time.Duration
		want           error
	}{
		{"whitelisted victim", "203.0.113.1", "198.51.100.7", time.Minute, ErrVictimProtected},
		{"allowlisted source", "203.0.113.10", "198.51.100.130", time.Minute, ErrSourceAllowlisted},
		{"source inside networks", "203.0.113.10", "203.0.113.50", time.Minute, ErrSourceInNetworks},
		{"family mismatch", "203.0.113.10", "2001:db8::bad", time.Minute, ErrSourceBlockInput},
		{"ttl too short", "203.0.113.10", "198.51.100.7", 0, ErrSourceBlockInput},
		{"ttl too long", "203.0.113.10", "198.51.100.7", 25 * time.Hour, ErrSourceBlockInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dp := &dpRecorder{}
			m := newSourceMitigator(t, srcYAML(), dp, nil)
			_, err := m.BlockSource(netip.MustParseAddr(tc.victim), netip.MustParseAddr(tc.source), tc.ttl, "")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if dp.installCount() != 0 {
				t.Fatal("a refused block reached the backend")
			}
			if len(m.SourceBlocks()) != 0 {
				t.Fatal("a refused block was recorded")
			}
		})
	}
}

func TestBlockSourceWithoutADataplaneIsRefused(t *testing.T) {
	// Live config, no dataplane block, no backend: the explicit refusal the
	// plan demands instead of silent acceptance.
	m := newMitigator(t, liveYAML(), newRecorder(), nil)
	_, err := m.BlockSource(netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7"), time.Minute, "")
	if !errors.Is(err, ErrDataplaneAbsent) {
		t.Fatalf("err = %v, want ErrDataplaneAbsent", err)
	}
}

func TestBlockSourceVictimsCapAtPolicyBlock(t *testing.T) {
	dp := &dpRecorder{}
	m := newSourceMitigator(t, srcYAML(), dp, nil)

	for i := 0; i < maxRulesPerAttack; i++ {
		mustBlock(t, m, "203.0.113."+strconv.Itoa(10+i), "198.51.100.7", time.Minute)
	}
	_, err := m.BlockSource(netip.MustParseAddr("203.0.113.99"), netip.MustParseAddr("198.51.100.7"), time.Minute, "")
	if !errors.Is(err, ErrSourceVictimsFull) {
		t.Fatalf("err = %v, want ErrSourceVictimsFull", err)
	}
	if got := len(m.SourceBlocks()); got != maxRulesPerAttack {
		t.Fatalf("refused pair leaked into the table: %d entries", got)
	}
	// A REFRESH of an existing pair must still be allowed at the cap.
	if _, err := m.BlockSource(netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7"), time.Minute, ""); err != nil {
		t.Fatalf("refresh at the cap refused: %v", err)
	}
}

func TestBlockSourceInstallFailureLeavesNoRecord(t *testing.T) {
	dp := &dpRecorder{failWith: errors.New("no policy slots")}
	m := newSourceMitigator(t, srcYAML(), dp, nil)

	_, err := m.BlockSource(netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7"), time.Minute, "")
	if err == nil {
		t.Fatal("install failure did not surface")
	}
	if len(m.SourceBlocks()) != 0 {
		t.Fatal("failed install left a half-recorded pair")
	}

	// And a failed REFRESH restores the previous pair rather than dropping it.
	dp.failWith = nil
	first := mustBlock(t, m, "203.0.113.10", "198.51.100.7", time.Minute)
	dp.failWith = errors.New("no policy slots")
	if _, err := m.BlockSource(netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7"), 10*time.Minute, ""); err == nil {
		t.Fatal("failed refresh did not surface")
	}
	got := m.SourceBlocks()
	if len(got) != 1 || !got[0].ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("failed refresh did not restore the old pair: %+v", got)
	}
}

func TestBlockSourceDryRunTouchesNoBackend(t *testing.T) {
	dp := &dpRecorder{}
	// baseYAML has no dry_run key; the default is dry-run ON.
	m := newSourceMitigator(t, baseYAML()+`
dataplane:
  enabled: true
  interfaces: ["eth0"]
`, dp, nil)

	sb := mustBlock(t, m, "203.0.113.10", "198.51.100.7", time.Minute)
	if !sb.DryRun {
		t.Fatal("default-dry-run config produced a live source block")
	}
	if dp.installCount() != 0 || dp.withdrawCount() != 0 {
		t.Fatalf("dry-run touched the backend: %v", dp.log())
	}
	if got := testutil.ToFloat64(metrics.MitigateSourceBlocks.WithLabelValues("dry_run")); got != 1 {
		t.Fatalf("dry_run gauge = %v, want 1", got)
	}

	// Unblocking the dry-run pair must not reach the backend either.
	if _, err := m.UnblockSource(netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7")); err != nil {
		t.Fatalf("UnblockSource: %v", err)
	}
	if dp.installCount() != 0 || dp.withdrawCount() != 0 {
		t.Fatalf("dry-run unblock touched the backend: %v", dp.log())
	}
}

func TestUnblockSourceNarrowsThenWithdraws(t *testing.T) {
	dp := &dpRecorder{}
	m := newSourceMitigator(t, srcYAML(), dp, nil)

	mustBlock(t, m, "203.0.113.10", "198.51.100.7", 5*time.Minute)
	mustBlock(t, m, "203.0.113.20", "198.51.100.7", 5*time.Minute)

	// Removing one victim narrows the policy to the remaining pair.
	if _, err := m.UnblockSource(netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7")); err != nil {
		t.Fatalf("UnblockSource: %v", err)
	}
	in := dp.lastInstall(t)
	if len(in.rules.Specs) != 1 || in.rules.Specs[0].Dst != netip.MustParsePrefix("203.0.113.20/32") {
		t.Fatalf("narrowed policy wrong: %+v", in.rules.Specs)
	}
	// Removing the last victim withdraws the anchor entirely.
	if _, err := m.UnblockSource(netip.MustParseAddr("203.0.113.20"), netip.MustParseAddr("198.51.100.7")); err != nil {
		t.Fatalf("UnblockSource: %v", err)
	}
	if dp.withdrawCount() != 1 {
		t.Fatalf("withdraws = %d, want 1", dp.withdrawCount())
	}
	if len(m.SourceBlocks()) != 0 {
		t.Fatal("pairs left after full unblock")
	}
	// A second unblock is a miss, not a crash.
	if _, err := m.UnblockSource(netip.MustParseAddr("203.0.113.20"), netip.MustParseAddr("198.51.100.7")); !errors.Is(err, ErrSourceBlockNotFound) {
		t.Fatalf("err = %v, want ErrSourceBlockNotFound", err)
	}
}

func TestSweepRetiresExpiredSourceBlocks(t *testing.T) {
	clk := &mockClock{t: time.Now()}
	dp := &dpRecorder{}
	m := newSourceMitigator(t, srcYAML(), dp, clk)

	mustBlock(t, m, "203.0.113.10", "198.51.100.7", time.Minute)
	mustBlock(t, m, "203.0.113.20", "198.51.100.7", 10*time.Minute)

	clk.Advance(2 * time.Minute)
	m.sweepExpired()

	// The 1m pair expired; the 10m pair survives in a narrowed policy.
	got := m.SourceBlocks()
	if len(got) != 1 || got[0].Victim != netip.MustParseAddr("203.0.113.20") {
		t.Fatalf("sweep result wrong: %+v", got)
	}
	in := dp.lastInstall(t)
	if len(in.rules.Specs) != 1 {
		t.Fatalf("sweep did not narrow the policy: %d specs", len(in.rules.Specs))
	}

	clk.Advance(20 * time.Minute)
	m.sweepExpired()
	if len(m.SourceBlocks()) != 0 {
		t.Fatal("sweep left an expired pair")
	}
	if dp.withdrawCount() != 1 {
		t.Fatalf("withdraws = %d, want 1 after the last pair expired", dp.withdrawCount())
	}
}

func TestSourceBlocksPersistAcrossRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "bans.json")
	yaml := strings.Replace(srcYAML(),
		"  max_active_bans: 3\n",
		"  max_active_bans: 3\n  state_file: "+state+"\n", 1)

	clk := &mockClock{t: time.Now()}
	dp1 := &dpRecorder{}
	m1 := newSourceMitigator(t, yaml, dp1, clk)
	mustBlock(t, m1, "203.0.113.10", "198.51.100.7", time.Hour)
	mustBlock(t, m1, "203.0.113.99", "198.51.100.9", time.Hour) // whitelisted after the restart
	m1.flushPersist()

	// "Restart" into a config whose whitelist has grown: the persisted pair
	// aimed at the now-whitelisted victim must be dropped, the other restored
	// and reinstalled. The persisted set never overrides a live safety rule.
	yaml2 := strings.Replace(yaml,
		`  - "203.0.113.1"`,
		"  - \"203.0.113.1\"\n  - \"203.0.113.99\"", 1)
	if yaml2 == yaml {
		t.Fatal("test fixture drifted: whitelist entry not found for replacement")
	}
	dp2 := &dpRecorder{}
	m2 := newSourceMitigator(t, yaml2, dp2, clk)
	m2.mu.Lock()
	m2.rehydrateLocked(m2.store.Get())
	m2.mu.Unlock()

	got := m2.SourceBlocks()
	if len(got) != 1 || got[0].Victim != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("rehydrated pairs wrong: %+v", got)
	}
	in := dp2.lastInstall(t)
	if in.victim != netip.MustParsePrefix("198.51.100.7/32") {
		t.Fatalf("rehydrate reinstalled anchor %s, want 198.51.100.7/32", in.victim)
	}

	// TTL elapsed during downtime: nothing comes back.
	clk.Advance(2 * time.Hour)
	dp3 := &dpRecorder{}
	m3 := newSourceMitigator(t, yaml, dp3, clk)
	m3.mu.Lock()
	m3.rehydrateLocked(m3.store.Get())
	m3.mu.Unlock()
	if len(m3.SourceBlocks()) != 0 {
		t.Fatal("rehydrated a pair whose TTL elapsed during downtime")
	}
	if dp3.installCount() != 0 {
		t.Fatal("expired rehydration reached the backend")
	}
}

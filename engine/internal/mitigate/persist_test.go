package mitigate

import (
	"context"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"

	"log/slog"
)

// liveYAMLWithState returns the live unit-test config with ban persistence
// pointed at stateFile.
func liveYAMLWithState(stateFile string) string {
	return strings.Replace(liveYAML(),
		"  max_active_bans: 3\n",
		"  max_active_bans: 3\n  state_file: "+stateFile+"\n", 1)
}

// baseYAMLWithState is the dry-run base config with ban persistence enabled.
func baseYAMLWithState(stateFile string) string {
	return strings.Replace(baseYAML(),
		"  max_active_bans: 3\n",
		"  max_active_bans: 3\n  state_file: "+stateFile+"\n", 1)
}

// hostSnap builds a persisted host-ban snapshot (single blackhole rung) for
// tests that craft a state file directly.
func hostSnap(addr string, expiresAt time.Time) banSnapshot {
	a := netip.MustParseAddr(addr)
	return banSnapshot{
		Target:     a,
		Prefix:     hostPrefix(a),
		Method:     config.MitigateBlackhole,
		StartedAt:  expiresAt.Add(-600 * time.Second),
		ExpiresAt:  expiresAt,
		Escalation: []config.EscalationStage{{AfterSeconds: 0, Action: config.EscalateBlackhole}},
	}
}

func writeState(t *testing.T, path string, host ...banSnapshot) {
	t.Helper()
	p := &banPersistor{path: path}
	if err := p.save(persistState{Version: persistVersion, SavedAt: time.Unix(1700000000, 0).UTC(), HostBans: host}); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

// TestBanPersistorRoundTrip covers atomic save + load and the missing-file case.
func TestBanPersistorRoundTrip(t *testing.T) {
	p := &banPersistor{path: filepath.Join(t.TempDir(), "bans.json")}

	// Missing file loads as empty, not an error (first run).
	if st, err := p.load(); err != nil || len(st.HostBans) != 0 {
		t.Fatalf("load(missing) = %+v, %v; want empty, nil", st, err)
	}

	in := persistState{
		Version:  persistVersion,
		SavedAt:  time.Unix(1700000000, 0).UTC(),
		HostBans: []banSnapshot{hostSnap("203.0.113.66", time.Unix(1700000600, 0).UTC())},
		PrefixBans: []banSnapshot{{
			Target:     netip.MustParseAddr("203.0.113.0"),
			Prefix:     netip.MustParsePrefix("203.0.113.0/24"),
			Method:     config.MitigateBlackhole,
			Escalation: []config.EscalationStage{{Action: config.EscalateBlackhole}},
			ExpiresAt:  time.Unix(1700000600, 0).UTC(),
		}},
	}
	if err := p.save(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := p.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(out.HostBans) != 1 || out.HostBans[0].Target != in.HostBans[0].Target || out.HostBans[0].Method != config.MitigateBlackhole {
		t.Fatalf("host ban round-trip mismatch: %+v", out.HostBans)
	}
	if len(out.PrefixBans) != 1 || out.PrefixBans[0].Prefix != in.PrefixBans[0].Prefix {
		t.Fatalf("prefix ban round-trip mismatch: %+v", out.PrefixBans)
	}
}

// TestPersistWritesActiveBans verifies the state file tracks the active set: a
// ban appears, an unban removes it.
func TestPersistWritesActiveBans(t *testing.T) {
	sf := filepath.Join(t.TempDir(), "bans.json")
	rec := newRecorder()
	m := newMitigator(t, liveYAMLWithState(sf), rec, nil)
	if m.persist == nil {
		t.Fatal("persistence not enabled from ban.state_file")
	}

	m.OnAttackStarted(startedEvent("203.0.113.66"))
	m.flushPersist()
	st, err := (&banPersistor{path: sf}).load()
	if err != nil || len(st.HostBans) != 1 || st.HostBans[0].Target.String() != "203.0.113.66" {
		t.Fatalf("after ban, state = %+v, err %v; want 1 host ban for .66", st, err)
	}

	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: netip.MustParseAddr("203.0.113.66"), At: time.Now()})
	m.flushPersist()
	st, err = (&banPersistor{path: sf}).load()
	if err != nil || len(st.HostBans) != 0 {
		t.Fatalf("after unban, state = %+v, err %v; want no host bans", st, err)
	}
}

// TestRehydrateReannounces proves a fresh mitigator re-announces a persisted ban
// on startup (the core of cross-restart mitigation continuity).
func TestRehydrateReannounces(t *testing.T) {
	sf := filepath.Join(t.TempDir(), "bans.json")

	// First instance bans and persists.
	m1 := newMitigator(t, liveYAMLWithState(sf), newRecorder(), nil)
	if m1.OnAttackStarted(startedEvent("203.0.113.66")).State != BanActive {
		t.Fatal("ban not active")
	}
	m1.flushPersist()

	// Fresh instance rehydrates from the same file and re-announces.
	rec := newRecorder()
	m2 := newMitigator(t, liveYAMLWithState(sf), rec, nil)
	m2.mu.Lock()
	m2.rehydrateLocked(m2.store.Get())
	m2.mu.Unlock()

	if rec.announceCount("203.0.113.66/32") != 1 {
		t.Errorf("rehydrate announce count = %d, want 1", rec.announceCount("203.0.113.66/32"))
	}
	if got := m2.ActiveBans(); len(got) != 1 || got[0].Target.String() != "203.0.113.66" || got[0].State != BanActive {
		t.Errorf("active bans after rehydrate = %+v, want 1 active for .66", got)
	}
}

// TestRehydrateFlowSpecReannounces proves a persisted flowspec ban re-announces
// its rules (the NLRI must match to refresh a retained stale route).
func TestRehydrateFlowSpecReannounces(t *testing.T) {
	sf := filepath.Join(t.TempDir(), "bans.json")
	rule := FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.66/32"), Proto: 17, Action: config.FlowSpecDiscard}
	writeState(t, sf, banSnapshot{
		Target:     netip.MustParseAddr("203.0.113.66"),
		Prefix:     netip.MustParsePrefix("203.0.113.66/32"),
		Method:     config.MitigateFlowSpec,
		FlowSpec:   []FlowSpecRule{rule},
		Escalation: []config.EscalationStage{{Action: config.EscalateFlowSpec}},
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	rec := newRecorder()
	m := newMitigator(t, liveYAMLWithState(sf), rec, nil)
	m.mu.Lock()
	m.rehydrateLocked(m.store.Get())
	m.mu.Unlock()

	if rec.flowSpecUp()[rule.String()] != 1 {
		t.Errorf("flowspec rule not re-announced on rehydrate: %+v", rec.flowSpecUp())
	}
}

// TestRehydrateDropsUnsafe is the safety gate: a persisted ban that no longer
// passes the live rules is NOT re-announced.
func TestRehydrateDropsUnsafe(t *testing.T) {
	cases := []struct {
		name string
		snap banSnapshot
	}{
		{"now whitelisted", hostSnap("203.0.113.1", time.Now().Add(time.Hour))},                                 // 203.0.113.1 is in protected_whitelist
		{"outside networks", hostSnap("198.51.100.5", time.Now().Add(time.Hour))},                               // not in networks
		{"ttl elapsed", hostSnap("203.0.113.66", time.Now().Add(-time.Hour))},                                   // expired during downtime
		{"invalid target", banSnapshot{Method: config.MitigateBlackhole, ExpiresAt: time.Now().Add(time.Hour)}}, // zero Target
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sf := filepath.Join(t.TempDir(), "bans.json")
			writeState(t, sf, tc.snap)
			rec := newRecorder()
			m := newMitigator(t, liveYAMLWithState(sf), rec, nil)
			m.mu.Lock()
			m.rehydrateLocked(m.store.Get())
			m.mu.Unlock()

			if n := len(m.ActiveBans()); n != 0 {
				t.Errorf("%s: rehydrated %d bans, want 0", tc.name, n)
			}
			if len(rec.eventLog()) != 0 {
				t.Errorf("%s: announced %v on rehydrate, want nothing", tc.name, rec.eventLog())
			}
		})
	}
}

// TestRehydrateReconcilesDryRun guards the critical invariant that a rehydrated
// ban's announce mode and its frozen DryRun (which gates every later withdraw)
// agree with the CURRENT config — even when dry_run flipped across the restart.
// Without reconciliation, a dry→live flip would announce a real route the ban
// records as dry-run, so withdraws become no-ops and the null-route is stranded.
func TestRehydrateReconcilesDryRun(t *testing.T) {
	target := netip.MustParseAddr("203.0.113.66")

	t.Run("persisted dry-run, restart live", func(t *testing.T) {
		sf := filepath.Join(t.TempDir(), "bans.json")
		m1 := newMitigator(t, baseYAMLWithState(sf), newRecorder(), nil) // dry-run
		m1.OnAttackStarted(startedEvent("203.0.113.66"))
		m1.flushPersist()

		rec := newRecorder()
		m2 := newMitigator(t, liveYAMLWithState(sf), rec, nil) // live
		m2.mu.Lock()
		m2.rehydrateLocked(m2.store.Get())
		m2.mu.Unlock()

		if rec.announceCount("203.0.113.66/32") != 1 {
			t.Fatalf("live rehydrate announce count = %d, want 1 (real announce)", rec.announceCount("203.0.113.66/32"))
		}
		if ab := m2.ActiveBans(); len(ab) != 1 || ab[0].DryRun {
			t.Fatalf("rehydrated ban DryRun not reconciled to live: %+v", ab)
		}
		// The decisive check: a real announce must yield a real withdraw.
		if _, err := m2.ManualUnban(target); err != nil {
			t.Fatalf("unban: %v", err)
		}
		if rec.withdrawCount("203.0.113.66/32") != 1 {
			t.Errorf("withdraw count = %d, want 1; a no-op withdraw means dry_run was not reconciled and the route is stranded", rec.withdrawCount("203.0.113.66/32"))
		}
	})

	t.Run("persisted live, restart dry-run", func(t *testing.T) {
		sf := filepath.Join(t.TempDir(), "bans.json")
		m1 := newMitigator(t, liveYAMLWithState(sf), newRecorder(), nil) // live
		m1.OnAttackStarted(startedEvent("203.0.113.66"))
		m1.flushPersist()

		rec := newRecorder()
		m2 := newMitigator(t, baseYAMLWithState(sf), rec, nil) // dry-run
		m2.mu.Lock()
		m2.rehydrateLocked(m2.store.Get())
		m2.mu.Unlock()

		if len(rec.eventLog()) != 0 {
			t.Errorf("dry-run rehydrate announced %v, want nothing", rec.eventLog())
		}
		if ab := m2.ActiveBans(); len(ab) != 1 || !ab[0].DryRun {
			t.Fatalf("rehydrated ban DryRun not reconciled to dry-run: %+v", ab)
		}
	})
}

// TestRehydrateRespectsMaxActiveBans drops the overflow when the persisted set
// exceeds a (now-tightened) cap.
func TestRehydrateRespectsMaxActiveBans(t *testing.T) {
	sf := filepath.Join(t.TempDir(), "bans.json")
	exp := time.Now().Add(time.Hour)
	writeState(t, sf,
		hostSnap("203.0.113.10", exp),
		hostSnap("203.0.113.11", exp),
		hostSnap("203.0.113.12", exp),
		hostSnap("203.0.113.13", exp), // 4th exceeds max_active_bans: 3
	)
	rec := newRecorder()
	m := newMitigator(t, liveYAMLWithState(sf), rec, nil) // max_active_bans: 3
	m.mu.Lock()
	m.rehydrateLocked(m.store.Get())
	m.mu.Unlock()

	if n := len(m.ActiveBans()); n != 3 {
		t.Fatalf("rehydrated %d bans, want exactly 3 (cap)", n)
	}
}

// TestBGPRehydrateRestoresMitigationAfterRestart is the end-to-end proof against
// a real gobgp peer: an instance bans and persists, fully stops (the peer
// flushes), and a FRESH instance reading the same state file rehydrates and
// re-announces the route on startup — restoring mitigation across the restart
// without waiting for the engine to re-detect.
func TestBGPRehydrateRestoresMitigationAfterRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in -short mode")
	}
	ctx := context.Background()
	const recvPort = 17991
	const prefix = "203.0.113.66/32"
	sf := filepath.Join(t.TempDir(), "bans.json")
	yaml := strings.Replace(bgpYAML(recvPort),
		"  max_active_bans: 50\n",
		"  max_active_bans: 50\n  state_file: "+sf+"\n", 1)

	recv := server.NewBgpServer()
	go recv.Serve()
	defer recv.Stop()
	if err := recv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 65000, RouterId: "2.2.2.2", ListenPort: recvPort, ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatalf("receiver StartBgp: %v", err)
	}
	if err := recv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{PassiveMode: true},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		AfiSafis:  bothFamilies(),
	}}); err != nil {
		t.Fatalf("receiver AddPeer: %v", err)
	}

	// Instance #1: ban, persist, then stop (clean Stop hard-resets → peer flushes).
	store1 := storeFrom(t, yaml)
	m1, err := New(store1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New m1: %v", err)
	}
	if err := m1.Start(ctx); err != nil {
		t.Fatalf("m1 Start: %v", err)
	}
	if !m1.speaker.waitEstablished(ctx, 20*time.Second) {
		t.Fatal("m1 session never established")
	}
	if m1.OnAttackStarted(startedEvent("203.0.113.66")).State != BanActive {
		t.Fatal("m1 ban not active")
	}
	if !waitForPrefix(t, recv, familyV4, prefix, true) {
		t.Fatalf("receiver never saw m1's announced prefix %s", prefix)
	}
	m1.Stop() // flushPersist writes the state file; the peer then flushes the route
	if !waitForPrefix(t, recv, familyV4, prefix, false) {
		t.Fatalf("receiver still has %s after m1 clean stop", prefix)
	}

	// Instance #2: fresh process reading the same state file. On startup it
	// rehydrates and re-announces — the route returns with no re-detection.
	store2 := storeFrom(t, yaml)
	m2, err := New(store2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New m2: %v", err)
	}
	if err := m2.Start(ctx); err != nil {
		t.Fatalf("m2 Start: %v", err)
	}
	defer m2.Stop()
	if got := m2.ActiveBans(); len(got) != 1 {
		t.Fatalf("m2 rehydrated %d bans, want 1", len(got))
	}
	if !waitForPrefix(t, recv, familyV4, prefix, true) {
		t.Fatalf("receiver never saw %s re-announced by the rehydrated instance", prefix)
	}
}

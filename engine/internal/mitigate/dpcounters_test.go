package mitigate

// What the state file carries across a restart, and what it deliberately does
// not.

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// TestPersistVersionIsUnchanged is a one-line gate with a long reason.
//
// load() hard-fails on a version mismatch and rehydrateLocked then starts with
// NO bans. Bumping the version to accommodate an additive field would therefore
// discard every live ban on the upgrade that shipped it — the exact mitigation
// gap the state file exists to close, caused by the code meant to improve it.
// Additive fields are omitempty and the version stays 1.
func TestPersistVersionIsUnchanged(t *testing.T) {
	if persistVersion != 1 {
		t.Fatalf("persistVersion = %d, want 1: a bump makes every previously written state "+
			"file unreadable, so the upgrade that ships it drops all active bans", persistVersion)
	}
}

// TestSnapshotOfABanWithNoDataplaneIsUnchanged: the on-disk document for a
// blackhole ban must not gain keys. An older kapkan reading it must see exactly
// what it wrote.
func TestSnapshotOfABanWithNoDataplaneIsUnchanged(t *testing.T) {
	b := &Ban{
		Target:     netip.MustParseAddr("203.0.113.66"),
		Prefix:     netip.MustParsePrefix("203.0.113.66/32"),
		Method:     config.MitigateBlackhole,
		State:      BanActive,
		StartedAt:  time.Unix(1700000000, 0).UTC(),
		ExpiresAt:  time.Unix(1700000600, 0).UTC(),
		Escalation: []config.EscalationStage{{Action: config.EscalateBlackhole}},
	}
	raw, err := json.Marshal(toSnapshot(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"dataplane_packets", "dataplane_bytes", "dataplane_rules"} {
		if strings.Contains(string(raw), k) {
			t.Errorf("a blackhole ban's snapshot carries %q: %s", k, raw)
		}
	}
}

// TestDataplaneTotalsSurviveARestart is the property the persisted fields exist
// for.
//
// The kernel cannot supply this number after a restart: kapkan_rule_stats is
// recreated at zero by the next install, and a process that could not adopt the
// pins has no counters at all. If the total did not round-trip, every restart
// would silently reset an operator's "how much have we dropped for this victim"
// to zero mid-incident.
//
// It also pins what does NOT round-trip. policy_id and measured_at are claims
// about kernel state that nobody has verified since the process died; they come
// back on the first scrape, and until then the record says so with stale=true
// rather than presenting an old timestamp as current.
func TestDataplaneTotalsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "bans.json")
	yaml := strings.Replace(dpYAML(""), "  max_active_bans: 3\n",
		"  max_active_bans: 3\n  state_file: "+state+"\n", 1)

	m1, _ := newDataplaneMitigator(t, yaml, &dpRecorder{}, nil)
	b := m1.OnAttackStarted(startedEvent("203.0.113.5"))
	if b.Method != config.MitigateDataplane {
		t.Fatalf("method = %q, want dataplane", b.Method)
	}
	measured := time.Unix(1700000000, 0).UTC()
	m1.SetDataplaneCounters(map[netip.Prefix]BanDataplane{
		b.Prefix: {
			Packets: 4_100_000, Bytes: 2_050_000_000,
			Rules:      []BanDataplaneRule{{ID: 7, Packets: 4_100_000, Bytes: 2_050_000_000}},
			PolicyID:   7,
			MeasuredAt: measured,
		},
	})
	m1.flushPersist()

	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "dataplane_packets") {
		t.Fatalf("the totals were not persisted:\n%s", raw)
	}
	for _, k := range []string{"policy_id", "measured_at", "\"stale\""} {
		if strings.Contains(string(raw), k) {
			t.Errorf("%q was persisted; it is a claim about kernel state nobody verified "+
				"after a restart:\n%s", k, raw)
		}
	}

	// A second process reads it back.
	m2, _ := newDataplaneMitigator(t, yaml, &dpRecorder{}, nil)
	m2.mu.Lock()
	m2.rehydrateLocked(m2.store.Get())
	m2.mu.Unlock()

	bans := m2.ActiveBans()
	if len(bans) != 1 {
		t.Fatalf("rehydrated %d bans, want 1", len(bans))
	}
	dp := bans[0].Dataplane
	if dp == nil {
		t.Fatal("the rehydrated ban lost its measured totals")
	}
	if dp.Packets != 4_100_000 || dp.Bytes != 2_050_000_000 {
		t.Errorf("rehydrated totals = %d pkts / %d bytes, want 4100000 / 2050000000",
			dp.Packets, dp.Bytes)
	}
	if len(dp.Rules) != 1 || dp.Rules[0].Packets != 4_100_000 {
		t.Errorf("rehydrated per-rule totals = %+v", dp.Rules)
	}
	if !dp.Stale {
		t.Error("a rehydrated total is not marked stale; nothing has been read from a kernel " +
			"map yet in this process")
	}
	if !dp.MeasuredAt.IsZero() {
		t.Errorf("measured_at = %s, want zero: no measurement has happened in this process",
			dp.MeasuredAt)
	}
	if dp.PolicyID != 0 {
		t.Errorf("policy_id = %d, want 0: ids are reallocated against maps that may have been "+
			"rebuilt while the process was down", dp.PolicyID)
	}
}

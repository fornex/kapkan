package rollup

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// TestRulesLadderInAutoZones pins the rung's place in the ladder (D9): in an
// auto zone the flood rule CHALLENGES a first-time flooder for ChallengeTTL,
// DENIES one that is already challenged or already cleared, and in any other
// zone denies as before; a source under a deny is skipped either way.
func TestRulesLadderInAutoZones(t *testing.T) {
	now := time.Now()
	r := &Rules{Now: func() time.Time { return now }}
	r.SetZones(map[string]ZoneRule{"auto.example": {Auto: true}, "manual.example": {Auto: false}})
	sink := &fakeSink{
		denied:     map[string]bool{"auto.example/198.51.100.7": true},
		challenged: map[string]bool{"auto.example/198.51.100.2": true},
	}
	flooding := func(ip string, cleared uint64) SourceStats {
		return SourceStats{Src: netip.MustParseAddr(ip), Requests: 100, Decided: 100, Denied: 80, DeniedRate: 80, Cleared: cleared}
	}
	got := r.Apply(WindowStats{Zone: "auto.example", Requests: 400, Sources: []SourceStats{
		flooding("198.51.100.1", 0),  // first flood: the rung
		flooding("198.51.100.2", 0),  // still flooding while challenged: the block
		flooding("198.51.100.3", 20), // cleared the rung and floods anyway: the block
		flooding("198.51.100.7", 0),  // already denied: skipped
	}}, sink)
	if got.Challenged != 1 || got.Denied != 2 || got.Skipped != 1 || got.ZoneChallenge {
		t.Fatalf("Applied = %+v challenges=%v denies=%v", got, sink.challenges, sink.denies)
	}
	if strings.Join(sink.challenges, ",") != "auto.example/198.51.100.1/flood/5m0s" {
		t.Fatalf("challenges = %v", sink.challenges)
	}
	if strings.Join(sink.denies, ",") != "auto.example/198.51.100.2/flood,auto.example/198.51.100.3/flood" {
		t.Fatalf("denies = %v", sink.denies)
	}
	// A zone whose rung is not auto denies a flooder outright, as before.
	sink = &fakeSink{}
	got = r.Apply(WindowStats{Zone: "manual.example", Requests: 100, Sources: []SourceStats{flooding("198.51.100.1", 0)}}, sink)
	if got.Denied != 1 || got.Challenged != 0 || len(sink.challenges) != 0 {
		t.Fatalf("manual zone: %+v %v", got, sink.challenges)
	}
	// So does a zone the rules were never told about.
	sink = &fakeSink{}
	if got := r.Apply(WindowStats{Zone: "unknown.example", Requests: 100, Sources: []SourceStats{flooding("198.51.100.1", 0)}}, sink); got.Denied != 1 {
		t.Fatalf("unknown zone: %+v", got)
	}
}

// TestRulesZoneRPSTrigger pins the zone-wide trigger: an auto zone at or over
// its zone_rps flips the whole zone to challenge for the hold, every window
// over the rate extends it, a window under it does not, and zones without a
// trigger (or not auto) never flip.
func TestRulesZoneRPSTrigger(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	r := &Rules{Now: func() time.Time { return now }}
	r.SetZones(map[string]ZoneRule{
		"auto.example":   {Auto: true, ZoneRPS: 1000, Hold: 5 * time.Minute},
		"quiet.example":  {Auto: true},
		"manual.example": {Auto: false, ZoneRPS: 1000, Hold: 5 * time.Minute},
	})
	sink := &fakeSink{}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 9990, RPS: 999}, sink); got.ZoneChallenge || len(sink.flips) != 0 {
		t.Fatalf("under the rate flipped: %+v %v", got, sink.flips)
	}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 10000, RPS: 1000}, sink); !got.ZoneChallenge || strings.Join(sink.flips, ",") != "auto.example/zone-rps/2026-09-05T12:05:00Z" {
		t.Fatalf("at the rate: %+v %v", got, sink.flips)
	}
	now = now.Add(10 * time.Second)
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 20000, RPS: 2000}, sink); !got.ZoneChallenge || sink.flips[len(sink.flips)-1] != "auto.example/zone-rps/2026-09-05T12:05:10Z" {
		t.Fatalf("over the rate did not extend: %+v %v", got, sink.flips)
	}
	before := len(sink.flips)
	r.Apply(WindowStats{Zone: "quiet.example", Requests: 100000, RPS: 10000}, sink)
	r.Apply(WindowStats{Zone: "manual.example", Requests: 100000, RPS: 10000}, sink)
	if len(sink.flips) != before {
		t.Fatalf("a zone without a trigger, or not auto, flipped: %v", sink.flips)
	}
}

// TestZoneRulesFromDoc pins how the document becomes rule settings: only
// deciding zones, auto from policy.challenge, the trigger and hold from
// challenge_options.auto with the hold's default.
func TestZoneRulesFromDoc(t *testing.T) {
	d := edgedoc.Empty()
	pol := func(challenge string, auto *edgedoc.AutoChallenge) edgedoc.Policy {
		p := edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: challenge}
		if auto != nil {
			p.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false, Auto: auto}
		}
		return p
	}
	d.Zones = append(d.Zones,
		edgedoc.Zone{Name: "a.example", Policy: pol(edgedoc.ChallengeAuto, &edgedoc.AutoChallenge{ZoneRPS: 500, HoldSeconds: 60})},
		edgedoc.Zone{Name: "b.example", Policy: pol(edgedoc.ChallengeAuto, nil)},
		edgedoc.Zone{Name: "c.example", Policy: pol(edgedoc.ChallengeManual, nil)},
		edgedoc.Zone{Name: "d.example", Policy: edgedoc.Policy{Mode: edgedoc.ModeNone, Challenge: edgedoc.ChallengeAuto}},
	)
	got := ZoneRulesFromDoc(&d)
	if len(got) != 3 {
		t.Fatalf("rules for %d zones, want 3 (mode none excluded): %+v", len(got), got)
	}
	if a := got["a.example"]; !a.Auto || a.ZoneRPS != 500 || a.Hold != time.Minute {
		t.Fatalf("a: %+v", a)
	}
	if b := got["b.example"]; !b.Auto || b.ZoneRPS != 0 || b.Hold != 5*time.Minute {
		t.Fatalf("b: %+v", b)
	}
	if c := got["c.example"]; c.Auto {
		t.Fatalf("c: %+v", c)
	}
}

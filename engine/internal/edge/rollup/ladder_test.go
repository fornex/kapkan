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
// DENIES one that already had the rung's chance — challenged, cleared, or
// remembered from an earlier promotion — and in any other zone denies as
// before; a source under a deny is skipped either way.
func TestRulesLadderInAutoZones(t *testing.T) {
	now := time.Now()
	r := &Rules{Now: func() time.Time { return now }}
	r.SetZones(map[string]ZoneRule{"auto.example": {Auto: true}, "manual.example": {Auto: false}})
	// 198.51.100.4 was promoted before: its deny expired, the memory has not.
	r.repeats = map[repeatKey]*repeat{{zone: "auto.example", src: netip.MustParseAddr("198.51.100.4")}: {n: 2, last: now.Add(-20 * time.Minute)}}
	sink := &fakeSink{
		denied:     map[string]bool{"auto.example/198.51.100.7": true},
		challenged: map[string]bool{"auto.example/198.51.100.2": true},
	}
	flooding := func(ip string, cleared uint64) SourceStats {
		return SourceStats{Src: netip.MustParseAddr(ip), Requests: 100, Decided: 100, Denied: 80, DeniedRate: 80, Cleared: cleared}
	}
	got := r.Apply(WindowStats{Zone: "auto.example", Requests: 500, Sources: []SourceStats{
		flooding("198.51.100.1", 0),  // first flood: the rung
		flooding("198.51.100.2", 0),  // still flooding while challenged: the block
		flooding("198.51.100.3", 20), // cleared the rung and floods anyway: the block
		flooding("198.51.100.4", 0),  // remembered repeat offender: the block, escalated
		flooding("198.51.100.7", 0),  // already denied: skipped
	}}, sink)
	if got.Challenged != 1 || got.Denied != 3 || got.Skipped != 1 || got.ZoneChallenge {
		t.Fatalf("Applied = %+v challenges=%v denies=%v", got, sink.challenges, sink.denies)
	}
	if strings.Join(sink.challenges, ",") != "auto.example/198.51.100.1/flood/5m0s" {
		t.Fatalf("challenges = %v", sink.challenges)
	}
	if strings.Join(sink.denies, ",") != "auto.example/198.51.100.2/flood,auto.example/198.51.100.3/flood,auto.example/198.51.100.4/flood" {
		t.Fatalf("denies = %v", sink.denies)
	}
	if sink.ttls[2] != 4*time.Minute {
		t.Fatalf("the remembered offender's deny TTL = %v, want the escalated 4m", sink.ttls[2])
	}
	// While the whole zone is under challenge, a flooder has had the rung:
	// it is denied, not given a challenge of its own on top.
	sink = &fakeSink{zoneOn: map[string]bool{"auto.example": true}}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 100, Sources: []SourceStats{flooding("198.51.100.1", 0)}}, sink); got.Denied != 1 || got.Challenged != 0 {
		t.Fatalf("flooder under the zone flip: %+v %v %v", got, sink.challenges, sink.denies)
	}
	// The window's own evidence counts even when the sink's state lapsed at
	// the close: a source served 401s (or their preview) during the window
	// had the rung.
	served := flooding("198.51.100.5", 0)
	served.Challenged = 30
	previewed := flooding("198.51.100.6", 0)
	previewed.WouldChallenge = 30
	sink = &fakeSink{}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 200, Sources: []SourceStats{served, previewed}}, sink); got.Denied != 2 || got.Challenged != 0 {
		t.Fatalf("flooders served the rung during the window: %+v %v", got, sink.challenges)
	}
	// A rung that cannot be offered (the challenge quota is full) does not
	// spare the flooder: the block follows — a fresh source, so the deny can
	// only be the fall-through's, at the base TTL, with no challenge landed.
	sink = &fakeSink{refuseChallenges: true}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 100, Sources: []SourceStats{flooding("198.51.100.8", 0)}}, sink); got.Denied != 1 || got.Challenged != 0 || len(sink.denies) != 1 || len(sink.challenges) != 0 || sink.ttls[0] != DefaultDenyTTL {
		t.Fatalf("flooder with the quota full: %+v denies=%v challenges=%v ttls=%v", got, sink.denies, sink.challenges, sink.ttls)
	}
	// The order of the window's two effects: the zone flip is read BEFORE
	// this window's trigger, so the flooder that trips the trigger is
	// offered the rung in that same window, not denied for a flip that did
	// not exist while it flooded.
	r.SetZones(map[string]ZoneRule{"auto.example": {Auto: true, ZoneRPS: 50, Hold: time.Minute}})
	sink = &fakeSink{}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 1000, AdmittedRPS: 60, Sources: []SourceStats{flooding("198.51.100.9", 0)}}, sink); !got.ZoneChallenge || got.Challenged != 1 || got.Denied != 0 {
		t.Fatalf("flip and first flood in one window: %+v %v %v", got, sink.challenges, sink.denies)
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

// TestRulesZoneRPSTrigger pins the zone-wide trigger: an auto zone whose
// ADMITTED rate is at or over its zone_rps flips the whole zone to challenge
// for the hold, every window over the rate extends it, a window under it
// does not — however much refused traffic it carries — and zones without a
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
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 9990, RPS: 999, AdmittedRPS: 999}, sink); got.ZoneChallenge || len(sink.flips) != 0 {
		t.Fatalf("under the rate flipped: %+v %v", got, sink.flips)
	}
	// A blocked bot's 403s, a flooder's 429s or an :80 flood are requests,
	// not admitted load: the zone stays as it is.
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 50000, RPS: 5000, AdmittedRPS: 12}, sink); got.ZoneChallenge || len(sink.flips) != 0 {
		t.Fatalf("refused traffic flipped the zone: %+v %v", got, sink.flips)
	}
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 10000, RPS: 1000, AdmittedRPS: 1000}, sink); !got.ZoneChallenge || strings.Join(sink.flips, ",") != "auto.example/zone-rps/2026-09-05T12:05:00Z" {
		t.Fatalf("at the rate: %+v %v", got, sink.flips)
	}
	now = now.Add(10 * time.Second)
	if got := r.Apply(WindowStats{Zone: "auto.example", Requests: 20000, RPS: 2000, AdmittedRPS: 2000}, sink); !got.ZoneChallenge || sink.flips[len(sink.flips)-1] != "auto.example/zone-rps/2026-09-05T12:05:10Z" {
		t.Fatalf("over the rate did not extend: %+v %v", got, sink.flips)
	}
	before := len(sink.flips)
	r.Apply(WindowStats{Zone: "quiet.example", Requests: 100000, RPS: 10000, AdmittedRPS: 10000}, sink)
	r.Apply(WindowStats{Zone: "manual.example", Requests: 100000, RPS: 10000, AdmittedRPS: 10000}, sink)
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
		// The brain's lever (E4.6): a live auto override makes the rules
		// challenge before they deny; a lapsed one is the file's word again.
		edgedoc.Zone{Name: "e.example", Policy: pol(edgedoc.ChallengeOff, nil), ChallengeOverride: &edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeAuto, Until: time.Now().Add(time.Hour)}},
		edgedoc.Zone{Name: "f.example", Policy: pol(edgedoc.ChallengeOff, nil), ChallengeOverride: &edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeAuto, Until: time.Now().Add(-time.Minute)}},
	)
	got := ZoneRulesFromDoc(&d)
	if len(got) != 5 {
		t.Fatalf("rules for %d zones, want 5 (mode none excluded): %+v", len(got), got)
	}
	if !got["e.example"].autoAt(time.Now()) || got["f.example"].autoAt(time.Now()) || got["e.example"].Auto || got["f.example"].Auto {
		t.Fatalf("override: e=%+v f=%+v", got["e.example"], got["f.example"])
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

package decide

import (
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// TestZoneDryRunIsPerZoneAndAFloor pins E4.7's three layers. On an enforcing
// node a zone with policy.dry_run previews its denies and challenges as marks
// while its sibling enforces; the zone's flag also makes the rung watch-only
// whatever challenge_options.dry_run says; and the node's dry-run is the
// floor — a zone that says false on a watch-only node is still watch-only.
func TestZoneDryRunIsPerZoneAndAFloor(t *testing.T) {
	c := newClock()
	watched := zone("watched.example", 1, 0)
	watched.Policy.DryRun = true
	live := zone("live.example", 1, 0)
	s := newService(t, c, watched, live)
	ip := src("198.51.100.70")

	// The ceiling: 1 rps in both zones. The second request is a deny in the
	// live zone and a would-deny — allowed, marked, flagged — in the watched.
	for _, z := range []string{"watched.example", "live.example"} {
		if v := s.DecideRequest(Request{Zone: z, Src: ip}); !v.Allow || v.Reason != ReasonAllow {
			t.Fatalf("%s first request: %+v", z, v)
		}
	}
	if v := s.DecideRequest(Request{Zone: "live.example", Src: ip}); v.Allow || v.DryRun || v.Reason != ReasonRate {
		t.Fatalf("live zone over the rate: %+v", v)
	}
	if v := s.DecideRequest(Request{Zone: "watched.example", Src: ip}); !v.Allow || !v.DryRun || v.Mark != "would-deny:rate" || v.Reason != ReasonRate || !v.Denied() {
		t.Fatalf("watched zone over the rate: %+v", v)
	}
	// A table deny is previewed the same way in the watched zone alone.
	other := src("198.51.100.71")
	s.Deny("watched.example", other, time.Minute, "flood")
	s.Deny("live.example", other, time.Minute, "flood")
	if v := s.DecideRequest(Request{Zone: "watched.example", Src: other}); !v.Allow || !v.DryRun || v.Mark != "would-deny:table:flood" {
		t.Fatalf("watched zone table deny: %+v", v)
	}
	if v := s.DecideRequest(Request{Zone: "live.example", Src: other}); v.Allow || v.Reason != "table:flood" {
		t.Fatalf("live zone table deny: %+v", v)
	}

	// The rung: challenge_options.dry_run false, but the zone is watch-only —
	// the zone's flag wins and the challenge is a would-challenge.
	rung, _ := challengeZone(t, "rung.example", edgedoc.ChallengeManual, 0)
	rung.Policy.DryRun = true
	s2 := newService(t, c, rung)
	if v := s2.DecideRequest(Request{Zone: "rung.example", Src: ip}); !v.Allow || !v.DryRun || !v.Challenge || v.Mark != "would-challenge:manual" {
		t.Fatalf("rung in a watch-only zone: %+v", v)
	}
	if !rung.Policy.ChallengeDryRun() {
		t.Fatal("ChallengeDryRun must be true for a watch-only zone")
	}

	// The floor: a watch-only NODE previews every zone, whatever the zone says.
	s3 := New(Options{Now: c.now, DryRun: true})
	s3.SetZones(doc(live))
	s3.DecideRequest(Request{Zone: "live.example", Src: ip})
	if v := s3.DecideRequest(Request{Zone: "live.example", Src: ip}); !v.Allow || !v.DryRun || v.Mark != "would-deny:rate" {
		t.Fatalf("live zone on a watch-only node: %+v", v)
	}
}

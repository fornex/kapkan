package decide

import (
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// TestChallengeOverrideIsTheModeWhileLive pins the brain's lever (E4.6): a
// zone whose file says off challenges everyone while a manual override is
// live, its page has a rung to offer, the flood rule's zone-wide flip is
// accepted under an auto override — and the moment the override lapses the
// zone is back to its file, without a new document.
func TestChallengeOverrideIsTheModeWhileLive(t *testing.T) {
	c := newClock()
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeOff, 0)
	z.ChallengeOverride = &edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeManual, Until: c.t.Add(10 * time.Minute), Reason: "incident 42"}
	s := newService(t, c, z)
	ip := src("198.51.100.80")

	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge || v.Reason != "challenge:manual" {
		t.Fatalf("under a manual override: %+v", v)
	}
	if _, ok := s.Rung("shop.example"); !ok {
		t.Fatal("the page has no rung to offer under the override")
	}
	// An auto override accepts the zone-wide flip the rules may ask for.
	z.ChallengeOverride.Mode = edgedoc.ChallengeAuto
	s.SetZones(doc(z))
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("under an auto override nobody is challenged until told: %+v", v)
	}
	if !s.SetZoneChallenge("shop.example", true, c.t.Add(time.Minute), "zone-rps") {
		t.Fatal("the flip was refused under an auto override")
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge || v.Reason != "challenge:zone:zone-rps" {
		t.Fatalf("flipped under an auto override: %+v", v)
	}
	// A new document with the SAME auto override keeps the live flip; one
	// that drops the override (the file says off) drops the flip with it.
	s.SetZones(doc(z))
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge || v.Reason != "challenge:zone:zone-rps" {
		t.Fatalf("the flip did not survive a document under the same auto override: %+v", v)
	}
	if on, _, _ := s.ZoneChallenge("shop.example"); !on {
		t.Fatal("ZoneChallenge lost the flip across a document")
	}
	same := z
	same.ChallengeOverride = nil
	s.SetZones(doc(same))
	if on, _, _ := s.ZoneChallenge("shop.example"); on {
		t.Fatal("the flip survived the override's removal in a zone whose file says off")
	}
	// Back under the auto override, flipped again: when the override LAPSES
	// the flip is retired at once — an inert flip must not read as active.
	s.SetZones(doc(z))
	if !s.SetZoneChallenge("shop.example", true, c.t.Add(time.Hour), "zone-rps") {
		t.Fatal("re-flip refused")
	}
	// The override lapses: the file's mode (off) is back, on the clock, with
	// the same document, and the flip with its gauge goes with it.
	c.add(11 * time.Minute)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("after the override lapsed: %+v", v)
	}
	if _, ok := s.Rung("shop.example"); ok {
		t.Fatal("the rung is still on after the override lapsed")
	}
	if on, _, _ := s.ZoneChallenge("shop.example"); on {
		t.Fatal("an inert flip is still reported active after the override lapsed")
	}
	// A mode the node does not know is not applied: no challenge, no rung.
	z.ChallengeOverride = &edgedoc.ChallengeOverride{Mode: "puzzle-v9", Until: c.t.Add(time.Hour)}
	s.SetZones(doc(z))
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("an unknown override mode was applied: %+v", v)
	}
	if _, ok := s.Rung("shop.example"); ok {
		t.Fatal("an unknown override mode offered a rung")
	}
}

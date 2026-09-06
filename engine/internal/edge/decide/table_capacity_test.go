package decide

import (
	"testing"
	"time"
)

// TestDenyDisplacesChallengeAndChallengesAreCapped pins the verdict table's
// shape under a flood of challenges (E4.4): challenges may fill at most half
// of the table, and a deny for a challenged source always lands — it takes
// the room its own challenge held — however full the table is otherwise.
func TestDenyDisplacesChallengeAndChallengesAreCapped(t *testing.T) {
	c := newClock()
	s := New(Options{Now: c.now, MaxSources: 4})
	s.SetZones(doc(zone("example.com", 0, 0)))
	// Challenges fill their half; the third is refused while a deny still
	// finds room.
	if !s.Challenge("example.com", src("198.51.100.1"), time.Minute, "flood") || !s.Challenge("example.com", src("198.51.100.2"), time.Minute, "flood") {
		t.Fatal("the first two challenges were refused")
	}
	if s.Challenge("example.com", src("198.51.100.3"), time.Minute, "flood") {
		t.Fatal("a third challenge exceeded the challenges' share of a four-entry table")
	}
	if !s.Deny("example.com", src("198.51.100.8"), time.Minute, "a") || !s.Deny("example.com", src("198.51.100.9"), time.Minute, "b") {
		t.Fatal("denies refused while the table had room")
	}
	// Full: a deny for a NEW source is refused, not evicting a live verdict —
	// but the deny a challenged source earned by flooding on displaces its
	// own challenge and lands.
	if s.Deny("example.com", src("198.51.100.7"), time.Minute, "c") {
		t.Fatal("a full table took a deny for a new source")
	}
	if !s.Deny("example.com", src("198.51.100.1"), time.Minute, "flood") {
		t.Fatal("the deny for a challenged source was refused by a full table")
	}
	if !s.Denied("example.com", src("198.51.100.1")) || s.Challenged("example.com", src("198.51.100.1")) {
		t.Fatal("the deny did not displace the challenge")
	}
	if v := s.Decide("example.com", src("198.51.100.1")); v.Allow || v.Reason != "table:flood" {
		t.Fatalf("displaced source: %+v", v)
	}
	// The same key's challenge is not double-counted once denied.
	if n := len(s.Verdicts()); n != 4 {
		t.Fatalf("verdicts = %d, want 4 (three denies, one challenge)", n)
	}
}

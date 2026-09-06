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
	// finds room. The challenges are LONGER than the denies below, so a deny
	// for a challenged source can land only by displacing its challenge.
	if !s.Challenge("example.com", src("198.51.100.1"), 5*time.Minute, "flood") || !s.Challenge("example.com", src("198.51.100.2"), 5*time.Minute, "flood") {
		t.Fatal("the first two challenges were refused")
	}
	if s.Challenge("example.com", src("198.51.100.3"), time.Minute, "flood") {
		t.Fatal("a third challenge exceeded the challenges' share of a four-entry table")
	}
	if !s.Deny("example.com", src("198.51.100.8"), time.Minute, "a") || !s.Deny("example.com", src("198.51.100.9"), time.Minute, "b") {
		t.Fatal("denies refused while the table had room")
	}
	// Full: the deny a challenged source earned by flooding on displaces its
	// own (longer) challenge and lands — the on-full path.
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
	// Full again with .2's challenge live and NOT beneath a deny: a deny for
	// a new source is refused — a live verdict is never evicted at random.
	if s.Deny("example.com", src("198.51.100.7"), time.Minute, "c") {
		t.Fatal("a full table took a deny for a new source by evicting a live challenge")
	}
	// But a challenge hidden beneath a live deny is not a verdict anyone can
	// see: when a new block needs the room, it makes way. Six slots: two
	// bots challenged (5m) then denied (1m) with room to spare keep their
	// challenges beneath — six entries, full — and a new flooder's block
	// lands by dropping what is beneath, not by refusing.
	// Seven slots: two bots challenged then denied keep their challenges
	// beneath, a third source (.3) is challenged and NOT denied — a live,
	// visible verdict that must survive the room-making.
	c3 := newClock()
	s3 := New(Options{Now: c3.now, MaxSources: 7})
	s3.SetZones(doc(zone("example.com", 0, 0)))
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if !s3.Challenge("example.com", src(ip), 5*time.Minute, "flood") {
			t.Fatalf("challenge %s refused", ip)
		}
	}
	s3.Deny("example.com", src("198.51.100.8"), time.Minute, "a")
	s3.Deny("example.com", src("198.51.100.9"), time.Minute, "b")
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if !s3.Deny("example.com", src(ip), time.Minute, "flood") {
			t.Fatalf("deny %s refused with room to spare", ip)
		}
	}
	if n := len(s3.Verdicts()); n != 7 {
		t.Fatalf("verdicts with two challenges beneath their denies = %d, want 7", n)
	}
	c3.add(2 * time.Second)
	if !s3.Deny("example.com", src("198.51.100.7"), time.Minute, "c") {
		t.Fatal("a full table refused a new block while challenges sat beneath live denies")
	}
	// The two hidden challenges went; .3's visible one did not.
	if n := len(s3.Verdicts()); n != 6 || !s3.Challenged("example.com", src("198.51.100.3")) || !s3.Denied("example.com", src("198.51.100.1")) || !s3.Denied("example.com", src("198.51.100.7")) {
		t.Fatalf("room-making was not selective: verdicts=%d challenged(.3)=%v", n, s3.Challenged("example.com", src("198.51.100.3")))
	}
	// The same room-making serves a challenge refused by its share: with the
	// share held only by hidden challenges, a new flooder still gets the rung.
	c4 := newClock()
	s4 := New(Options{Now: c4.now, MaxSources: 8})
	s4.SetZones(doc(zone("example.com", 0, 0)))
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		s4.Challenge("example.com", src(ip), 5*time.Minute, "flood")
		s4.Deny("example.com", src(ip), time.Minute, "flood")
	}
	c4.add(2 * time.Second)
	if !s4.Challenge("example.com", src("198.51.100.5"), 5*time.Minute, "flood") {
		t.Fatal("hidden challenges kept the share from a new flooder")
	}

	// With room to spare, a challenge that OUTLIVES the deny stays beneath
	// it: hidden while the block is live, in force again when it lapses —
	// the block does not set the source free.
	c2 := newClock()
	s2 := New(Options{Now: c2.now, MaxSources: 16})
	s2.SetZones(doc(zone("example.com", 0, 0)))
	s2.Challenge("example.com", src("198.51.100.1"), 5*time.Minute, "flood")
	s2.Deny("example.com", src("198.51.100.1"), time.Minute, "flood")
	if v := s2.Decide("example.com", src("198.51.100.1")); v.Allow || v.Reason != "table:flood" || v.Challenge {
		t.Fatalf("under the deny: %+v", v)
	}
	if s2.Challenged("example.com", src("198.51.100.1")) || len(s2.Verdicts()) != 2 {
		t.Fatalf("challenge beneath the deny: challenged=%v verdicts=%d", s2.Challenged("example.com", src("198.51.100.1")), len(s2.Verdicts()))
	}
	c2.add(61 * time.Second)
	if !s2.Challenged("example.com", src("198.51.100.1")) {
		t.Fatal("the challenge did not outlive the deny")
	}
	// A challenge the deny outlives is dropped at once.
	s2.Challenge("example.com", src("198.51.100.2"), time.Minute, "flood")
	s2.Deny("example.com", src("198.51.100.2"), time.Hour, "flood")
	if n := len(s2.Verdicts()); n != 2 {
		t.Fatalf("verdicts after a longer deny = %d, want 2 (the .1 challenge, the .2 deny)", n)
	}
}

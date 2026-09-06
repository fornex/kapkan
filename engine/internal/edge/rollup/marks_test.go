package rollup

import (
	"net/netip"
	"testing"
	"time"
)

// TestWindowCountsPreviewsAndMarks pins the counters the report shows as "who
// would be" (E4.5): every dry-run denial counts as WouldDeny (only the rate
// ones as WouldDenyRate), a would-challenge as WouldChallenge, any other mark
// as Marked, a clearance as Cleared — per source and, for the previews, per
// zone.
func TestWindowCountsPreviewsAndMarks(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	var got []WindowStats
	a := &Aggregator{Window: 10 * time.Second, Now: func() time.Time { return now }, OnWindow: func(w WindowStats) { got = append(got, w) }}
	src := netip.MustParseAddr("203.0.113.9")
	rec := func(decision, mark string) Record {
		return Record{TS: now, Zone: "z.example", Src: src, Port: 443, Status: 200, Decision: decision, Mark: mark}
	}
	a.Observe(rec("200", "would-deny:rate"))
	a.Observe(rec("200", "would-deny:concurrency"))
	a.Observe(rec("200", "would-deny:table:flood"))
	a.Observe(rec("200", "would-challenge:manual"))
	a.Observe(rec("200", "cleared"))
	a.Observe(rec("200", "cleared:nojs"))
	a.Observe(rec("200", "errors"))
	a.Observe(rec("200", ""))
	now = now.Add(11 * time.Second)
	a.Tick()
	if len(got) != 1 {
		t.Fatalf("windows: %d", len(got))
	}
	w := got[0]
	if w.WouldDeny != 3 || w.WouldChallenge != 1 || w.Cleared != 2 || w.Requests != 8 || w.Decided != 8 {
		t.Fatalf("zone counters: %+v", w)
	}
	if len(w.Sources) != 1 {
		t.Fatalf("sources: %+v", w.Sources)
	}
	s := w.Sources[0]
	if s.WouldDeny != 3 || s.WouldDenyRate != 2 || s.WouldChallenge != 1 || s.Cleared != 2 || s.Marked != 1 {
		t.Fatalf("source counters: %+v", s)
	}
}

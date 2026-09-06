package rollup

import (
	"net/netip"
	"strconv"
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

// TestMarkedSourceErrorsStillCount pins that a reputation mark travels beside
// the status: a marked source's 4xx/5xx are counted, so the errors rule that
// set the mark sees them and can renew it.
func TestMarkedSourceErrorsStillCount(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	var got []WindowStats
	a := &Aggregator{Window: 10 * time.Second, Now: func() time.Time { return now }, OnWindow: func(w WindowStats) { got = append(got, w) }}
	src := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 5; i++ {
		a.Observe(Record{TS: now, Zone: "z.example", Src: src, Port: 443, Status: 503, Decision: "200", Mark: "errors"})
	}
	a.Observe(Record{TS: now, Zone: "z.example", Src: src, Port: 443, Status: 404, Decision: "200", Mark: "errors"})
	now = now.Add(11 * time.Second)
	a.Tick()
	if len(got) != 1 || len(got[0].Sources) != 1 {
		t.Fatalf("windows: %+v", got)
	}
	if s := got[0].Sources[0]; s.Marked != 6 || s.Errors5xx != 5 || s.Errors4xx != 1 {
		t.Fatalf("a marked source's errors: %+v", s)
	}
}

// TestTopSourcesRankTellingFirst pins the bounded view: the sources the node
// refused, challenged or previewed rank ahead of busier allowed ones, the
// telling ones the bound cut are counted, and the view is a copy — it does
// not pin the window's whole source array.
func TestTopSourcesRankTellingFirst(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	var top []WindowStats
	a := &Aggregator{Window: 10 * time.Second, TopSources: 5, Now: func() time.Time { return now }, OnWindow: func(w WindowStats) { top = append(top, w) }}
	// Eight busy allowed sources, then three quiet previewed ones.
	for i := 0; i < 8; i++ {
		src := netip.MustParseAddr("198.51.100." + strconv.Itoa(10+i))
		for j := 0; j < 50; j++ {
			a.Observe(Record{TS: now, Zone: "z.example", Src: src, Port: 443, Status: 200, Decision: "200"})
		}
	}
	for i := 0; i < 3; i++ {
		a.Observe(Record{TS: now, Zone: "z.example", Src: netip.MustParseAddr("203.0.113." + strconv.Itoa(1+i)), Port: 443, Status: 200, Decision: "200", Mark: "would-challenge:manual"})
	}
	now = now.Add(11 * time.Second)
	a.Tick()
	if len(top) != 1 || len(top[0].Sources) != 5 || top[0].SourcesTotal != 11 || top[0].TellingTruncated != 0 {
		t.Fatalf("bounded view: %+v", top)
	}
	for i := 0; i < 3; i++ {
		if top[0].Sources[i].WouldChallenge != 1 {
			t.Fatalf("a telling source was outranked by a busy allowed one: %+v", top[0].Sources)
		}
	}
	if top[0].Sources[3].Requests != 50 || cap(top[0].Sources) >= top[0].SourcesTotal {
		t.Fatalf("the rest are the busiest, in a copy: requests=%d cap=%d total=%d", top[0].Sources[3].Requests, cap(top[0].Sources), top[0].SourcesTotal)
	}
	// More telling sources than the bound: the cut is counted.
	top = nil
	for i := 0; i < 7; i++ {
		a.Observe(Record{TS: now, Zone: "z.example", Src: netip.MustParseAddr("203.0.113." + strconv.Itoa(20+i)), Port: 443, Status: 200, Decision: "200", Mark: "would-deny:rate"})
	}
	now = now.Add(11 * time.Second)
	a.Tick()
	if len(top) != 1 || len(top[0].Sources) != 5 || top[0].TellingTruncated != 2 {
		t.Fatalf("telling cut: %+v", top)
	}
}

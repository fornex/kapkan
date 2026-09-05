package rollup

import (
	"testing"
	"time"
)

// TestRecordChallengeShapes pins how a challenge reads off the access log: a
// 401 decision is decided (it opened a slot) and challenged; the dry-run mark
// and the cleared marks are recognised, nothing else is mistaken for them.
func TestRecordChallengeShapes(t *testing.T) {
	r := rec("a.example.com", "198.51.100.1", 403, "401", reason("challenge:manual"))
	if !r.Decided() || r.Undecided() || !r.Challenged() || r.Cleared() || r.WouldChallengeReason() != "" {
		t.Fatalf("401 record: %+v", r)
	}
	dry := rec("a.example.com", "198.51.100.1", 200, "200", mark("would-challenge:zone:rps"), reason("challenge:zone:rps"))
	if dry.WouldChallengeReason() != "zone:rps" || dry.Challenged() || dry.WouldDenyReason() != "" {
		t.Fatalf("would-challenge record: %+v", dry)
	}
	for _, m := range []string{"cleared", "cleared:nojs"} {
		if !rec("a.example.com", "198.51.100.1", 200, "200", mark(m)).Cleared() {
			t.Fatalf("mark %q not read as cleared", m)
		}
	}
	for _, m := range []string{"clearedx", "would-deny:rate", "vip", ""} {
		if rec("a.example.com", "198.51.100.1", 200, "200", mark(m)).Cleared() {
			t.Fatalf("mark %q read as cleared", m)
		}
	}
}

// TestAggregatorCountsTheRung pins the window counters the report and the
// "who would be challenged" view read: challenged and would-challenge per
// zone and per source, cleared per source; a challenge is neither a denial
// nor an error of the source.
func TestAggregatorCountsTheRung(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	var full []WindowStats
	a := &Aggregator{Window: 10 * time.Second, Now: func() time.Time { return now }, OnWindowFull: func(w WindowStats) { full = append(full, w) }}
	for i := 0; i < 5; i++ {
		a.Observe(rec("a.example.com", "198.51.100.1", 403, "401", reason("challenge:manual")))
		a.Observe(rec("a.example.com", "198.51.100.2", 200, "200", mark("would-challenge:manual"), reason("challenge:manual")))
		a.Observe(rec("a.example.com", "198.51.100.3", 200, "200", mark("cleared")))
	}
	a.Observe(rec("a.example.com", "198.51.100.3", 200, "200", mark("cleared:nojs")))
	now = now.Add(11 * time.Second)
	a.Tick()
	if len(full) != 1 {
		t.Fatalf("windows: %d", len(full))
	}
	w := full[0]
	if w.Requests != 16 || w.Decided != 16 || w.Denied != 0 || w.Challenged != 5 || w.Cleared != 6 || w.WouldChallenge != 5 || w.Status4xx != 5 || w.Status2xx != 11 {
		t.Fatalf("zone: %+v", w)
	}
	by := map[string]SourceStats{}
	for _, s := range w.Sources {
		by[s.Src.String()] = s
	}
	if s := by["198.51.100.1"]; s.Challenged != 5 || s.Denied != 0 || s.Errors4xx != 0 || s.Decided != 5 {
		t.Fatalf("challenged source: %+v", s)
	}
	if s := by["198.51.100.2"]; s.WouldChallenge != 5 || s.WouldDenyRate != 0 || s.Challenged != 0 {
		t.Fatalf("would-challenge source: %+v", s)
	}
	if s := by["198.51.100.3"]; s.Cleared != 6 || s.Challenged != 0 || s.Decided != 6 {
		t.Fatalf("cleared source: %+v", s)
	}
}

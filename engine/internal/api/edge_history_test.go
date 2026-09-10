package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/storage"
)

// histWriter records what the history enqueues. Non-blocking like the real
// writer; every other Writer method is a no-op.
type histWriter struct {
	mu      sync.Mutex
	windows []storage.EdgeWindowRow
	sources []storage.EdgeSourceRow
	events  []storage.EdgeEventRow
}

func (h *histWriter) WriteAttack(storage.AttackRow)     {}
func (h *histWriter) WriteTraffic([]storage.TrafficRow) {}
func (h *histWriter) WriteAudit(storage.AuditRow)       {}
func (h *histWriter) Start(context.Context)             {}
func (h *histWriter) Stop()                             {}
func (h *histWriter) WriteEdgeWindows(r []storage.EdgeWindowRow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.windows = append(h.windows, r...)
}
func (h *histWriter) WriteEdgeSources(r []storage.EdgeSourceRow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sources = append(h.sources, r...)
}
func (h *histWriter) WriteEdgeEvent(r storage.EdgeEventRow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, r)
}
func (h *histWriter) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.windows, h.sources, h.events = nil, nil, nil
}
func (h *histWriter) kinds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.events))
	for _, e := range h.events {
		k := e.Kind
		if e.Zone != "" {
			k += ":" + e.Zone
		}
		out = append(out, k)
	}
	return out
}

var dropReasons = []string{"unknown_zone", "no_at", "duplicate", "extra_window", "bad_source", "source_cap"}

func dropped(reason string) float64 {
	return testutil.ToFloat64(metrics.EdgeHistoryDropped.WithLabelValues(reason))
}

func dropSnapshot() map[string]float64 {
	m := map[string]float64{}
	for _, r := range dropReasons {
		m[r] = dropped(r)
	}
	return m
}

// dropDelta asserts what moved since before: every reason in want by exactly
// that much, every other reason not at all.
func dropDelta(t *testing.T, before map[string]float64, want map[string]float64) {
	t.Helper()
	for _, r := range dropReasons {
		if got := dropped(r) - before[r]; got != want[r] {
			t.Errorf("dropped{%s} moved by %v, want %v", r, got, want[r])
		}
	}
}

const edgeZonesThree = edgeZonesTwo + `  - name: c.example
    origins: ["10.0.0.3:8080"]
`

func histFixture(t *testing.T, zonesYAML string) (*Server, *histWriter, *config.Config) {
	t.Helper()
	store, _ := edgeStore(t, zonesYAML)
	s := testServer(t, store)
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	return s, hw, store.Get()
}

func window(zone string, at time.Time, requests uint64, sources ...EdgeReportSource) EdgeReportZone {
	return EdgeReportZone{Zone: zone, At: at, WindowSeconds: 10, Challenge: "off", RPS: float64(requests) / 10, Requests: requests, Decided: requests, TopSources: sources}
}

// TestEdgeHistoryWindowsAndSources: one row per unique (node, zone, at) of a
// zone the file has, every counter in its own column; only telling, parseable
// sources, at most twenty; every skipped part counted by reason and the quiet
// shape counted as nothing; the same report again writes nothing.
func TestEdgeHistoryWindowsAndSources(t *testing.T) {
	s, hw, cfg := histFixture(t, edgeZonesTwo) // a.example decides, b.example is mode: none
	now := time.Date(2026, 9, 10, 12, 0, 30, 0, time.UTC)
	at := now.Add(-10 * time.Second)
	var srcs []EdgeReportSource
	srcs = append(srcs,
		EdgeReportSource{Source: "203.0.113.9", Requests: 500, State: SourceStateDenied},
		EdgeReportSource{Source: "203.0.113.11", Requests: 10, State: SourceStateAllow},
		EdgeReportSource{Source: "203.0.113.12", Requests: 10, State: SourceStateCleared},
		EdgeReportSource{Source: "203.0.113.13", Requests: 10, State: SourceStateMarked},
		EdgeReportSource{Source: "not-an-ip", Requests: 10, State: SourceStateWouldChallenge},
		EdgeReportSource{Source: "2001:db8:1:2::", Requests: 7, State: SourceStateWouldChallenge},
	)
	for i := 1; i <= 22; i++ {
		srcs = append(srcs, EdgeReportSource{Source: fmt.Sprintf("198.51.100.%d", i), Requests: uint64(100 - i), State: SourceStateWouldDeny})
	}
	before := dropSnapshot()
	first := window("a.example", at, 425, srcs...)
	// Every counter distinct, so a swapped column shows.
	first.Decided, first.Denied, first.Challenged, first.Cleared, first.WouldDeny, first.WouldChallenge = 420, 31, 17, 5, 200, 100
	first.Status2xx, first.Status3xx, first.Status4xx, first.Status5xx = 400, 3, 20, 2
	first.DryRun = true
	first.H3Requests = 7
	first.SourcesTruncated = 3
	first.ChallengeActive = &EdgeReportChallenge{Reason: "zone-rps", Until: now.Add(time.Minute)}
	rep := EdgeReport{Version: "1.8.0", Zones: []EdgeReportZone{
		first,
		window("ghost.example", at, 1),   // not in the file
		{Zone: "a.example", Requests: 1}, // counters but no close time
		window("a.example", at.Add(time.Second), 2), // a second window for the zone in one report
		{Zone: "a.example"},                         // the quiet shape: nothing to write, nothing to count
	}}
	s.edgeHist.observe(cfg, "e1", nil, rep, now)

	want := storage.EdgeWindowRow{
		TS: "2026-09-10 12:00:20", ReceivedAt: "2026-09-10 12:00:30", WindowSeconds: 10, Zone: "a.example", Node: "e1",
		Challenge: "off", DryRun: 1, RungDryRun: 0,
		Requests: 425, Decided: 420, Denied: 31, Challenged: 17, Cleared: 5, WouldDeny: 200, WouldChallenge: 100,
		Status2xx: 400, Status3xx: 3, Status4xx: 20, Status5xx: 2, H3Requests: 7, SourcesTruncated: 3,
		ChallengeActive: 1, ChallengeReason: "zone-rps",
	}
	if len(hw.windows) != 1 || hw.windows[0] != want {
		t.Fatalf("window rows:\n got %+v\nwant %+v", hw.windows, want)
	}
	if len(hw.sources) != storage.EdgeSourcesPerWindow {
		t.Fatalf("sources = %d, want %d (the cap)", len(hw.sources), storage.EdgeSourcesPerWindow)
	}
	if hw.sources[0].Source != "203.0.113.9" || hw.sources[0].State != SourceStateDenied || hw.sources[0].Requests != 500 || hw.sources[0].TS != want.TS || hw.sources[1].Source != "2001:db8:1:2::" {
		t.Fatalf("sources: %+v", hw.sources[:2])
	}
	for _, src := range hw.sources {
		if !tellingState(src.State) || src.Source == "not-an-ip" || strings.HasPrefix(src.Source, "198.51.100.19") || src.Source == "198.51.100.22" {
			t.Fatalf("a visitor, a bad key or a capped source was written: %+v", src)
		}
	}
	dropDelta(t, before, map[string]float64{"unknown_zone": 1, "no_at": 1, "extra_window": 1, "bad_source": 1, "source_cap": 4})
	// No events: the first report is the baseline, and the clock is within the gate.
	if len(hw.events) != 0 {
		t.Fatalf("events on a baseline report: %+v", hw.events)
	}

	// The same report again: the window is a duplicate, nothing is written,
	// and an identical report has no transitions.
	hw.reset()
	before = dropSnapshot()
	s.edgeHist.observe(cfg, "e1", &rep, rep, now.Add(time.Second))
	if len(hw.windows) != 0 || len(hw.sources) != 0 || len(hw.events) != 0 {
		t.Fatalf("a re-sent report wrote something: %d windows %d sources %v", len(hw.windows), len(hw.sources), hw.kinds())
	}
	if got := dropped("duplicate") - before["duplicate"]; got != 1 {
		t.Fatalf("dropped{duplicate} = %v, want 1", got)
	}
	// The next window is new: no challenge now (the column says so), a mode
	// the document does not define is "other", a negative shortfall is zero.
	next := EdgeReport{Version: "1.8.0", Zones: []EdgeReportZone{window("a.example", at.Add(10*time.Second), 10)}}
	next.Zones[0].Challenge = "weird"
	next.Zones[0].SourcesTruncated = -5
	s.edgeHist.observe(cfg, "e1", &rep, next, now.Add(10*time.Second))
	if len(hw.windows) != 1 || hw.windows[0].TS != "2026-09-10 12:00:30" || hw.windows[0].ChallengeActive != 0 || hw.windows[0].ChallengeReason != "" ||
		hw.windows[0].Challenge != "other" || hw.windows[0].SourcesTruncated != 0 {
		t.Fatalf("the next window: %+v", hw.windows)
	}
	// No transitions: the previous report's last entry for a.example (the
	// quiet shape) carried no challenge either.
	if k := hw.kinds(); len(k) != 0 {
		t.Fatalf("events between two challenge-less reports: %v", k)
	}
	// A mode: none zone reports no windows; a report without a zones section,
	// or with only the quiet shape, writes nothing and drops nothing.
	hw.reset()
	before = dropSnapshot()
	s.edgeHist.observe(cfg, "e1", &next, EdgeReport{Version: "1.8.0"}, now.Add(20*time.Second))
	s.edgeHist.observe(cfg, "e1", &next, EdgeReport{Version: "1.8.0", Zones: []EdgeReportZone{{Zone: "a.example"}}}, now.Add(30*time.Second))
	if len(hw.windows)+len(hw.sources)+len(hw.events) != 0 {
		t.Fatalf("a quiet report wrote something: %+v %+v %+v", hw.windows, hw.sources, hw.events)
	}
	dropDelta(t, before, nil)
}

// TestEdgeHistoryClockSkew (D11): a window close outside the gate is stamped
// with the brain's clock, received_at is always the brain's, and clock_skew
// is written once per transition — into skew and back.
func TestEdgeHistoryClockSkew(t *testing.T) {
	s, hw, cfg := histFixture(t, edgeZonesTwo)
	now := time.Date(2026, 9, 10, 12, 0, 30, 0, time.UTC)
	nine := now.Add(-9 * time.Minute) // behind, within the gate
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", nine, 1)}}, now)
	if len(hw.windows) != 1 || hw.windows[0].TS != historyTime(nine) || len(hw.events) != 0 {
		t.Fatalf("a window nine minutes behind must keep its own clock: %+v %+v", hw.windows, hw.events)
	}
	hw.reset()
	thirty := now.Add(30 * time.Second) // ahead, within the gate
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", thirty, 1)}}, now)
	if len(hw.windows) != 1 || hw.windows[0].TS != historyTime(thirty) || len(hw.events) != 0 {
		t.Fatalf("a window thirty seconds ahead must keep its own clock: %+v %+v", hw.windows, hw.events)
	}
	hw.reset()
	ahead := now.Add(5 * time.Minute)
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", ahead, 1)}}, now)
	if len(hw.windows) != 1 || hw.windows[0].TS != historyTime(now) || hw.windows[0].ReceivedAt != historyTime(now) {
		t.Fatalf("a window five minutes ahead must be stamped with the brain's clock: %+v", hw.windows)
	}
	if len(hw.events) != 1 || hw.events[0].Kind != EventClockSkew || hw.events[0].Node != "e1" || !strings.Contains(hw.events[0].Detail, "5m0s") {
		t.Fatalf("clock_skew event: %+v", hw.events)
	}
	// Still skewed: no second event.
	hw.reset()
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", ahead.Add(10*time.Second), 1)}}, now.Add(10*time.Second))
	if len(hw.events) != 0 {
		t.Fatalf("a second skewed report must not repeat clock_skew: %+v", hw.events)
	}
	// A report with no measurable window says nothing about the clock.
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{}, now.Add(20*time.Second))
	if len(hw.events) != 0 {
		t.Fatalf("an empty report changed the skew state: %+v", hw.events)
	}
	// Back within the gate: one recovery event, and the corrected clock's
	// windows — earlier than the skewed ones — are written, not deduplicated.
	hw.reset()
	sane := now.Add(40 * time.Second)
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", sane, 1)}}, sane)
	if len(hw.events) != 1 || hw.events[0].Kind != EventClockSkew || !strings.Contains(hw.events[0].Detail, "recovered") || len(hw.windows) != 1 || hw.windows[0].TS != historyTime(sane) {
		t.Fatalf("recovery: %+v %+v", hw.events, hw.windows)
	}
	// Eleven minutes behind is skew again.
	hw.reset()
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", sane.Add(-11*time.Minute), 1)}}, sane.Add(10*time.Second))
	if len(hw.events) != 1 || hw.windows[0].TS != historyTime(sane.Add(10*time.Second)) || !strings.Contains(hw.events[0].Detail, "11m") {
		t.Fatalf("a window eleven minutes behind: %+v %+v", hw.windows, hw.events)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestEdgeHistoryEvents: every transition between two reports is exactly one
// event, an identical repeat is none, the first report is a silent baseline,
// a certificate or challenge for a zone the file lacks is dropped, and a cut
// list is never read as "gone".
func TestEdgeHistoryEvents(t *testing.T) {
	s, hw, cfg := histFixture(t, edgeZonesThree)
	now := time.Date(2026, 9, 10, 12, 0, 30, 0, time.UTC)
	t1 := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	prev := EdgeReport{
		Version: "1.8.0", DryRun: true, ZonesETag: `"e1"`,
		Terminator: &EdgeReportTerminator{Kind: "nginx", Version: "1.26.3", Generation: 3, TestOK: true, Alive: boolPtr(true), H3: &EdgeReportH3{State: H3StateReady, Module: true}},
		Certs:      []EdgeReportCert{{Zone: "a.example", NotAfter: t1, Issuer: "R11"}, {Zone: "b.example", NotAfter: t1}},
		Zones:      []EdgeReportZone{window("a.example", now.Add(-10*time.Second), 5)},
	}
	s.edgeHist.observe(cfg, "e1", nil, prev, now)
	if len(hw.events) != 0 {
		t.Fatalf("the baseline report produced events: %v", hw.kinds())
	}

	next := prev
	next.Version = "1.9.0"
	next.DryRun = false
	next.ZonesETag = `"e2"`
	next.Terminator = &EdgeReportTerminator{Kind: "nginx", Version: "1.26.3", Generation: 4, TestOK: false, TestError: "nginx: [emerg] unknown directive", Alive: boolPtr(false), H3: &EdgeReportH3{State: H3StateNoModule}}
	next.Certs = []EdgeReportCert{{Zone: "a.example", NotAfter: t1.AddDate(0, 2, 0), Issuer: "R11"}, {Zone: "c.example", NotAfter: t1}, {Zone: "ghost.example", NotAfter: t1}}
	next.Zones = []EdgeReportZone{window("a.example", now, 5)}
	next.Zones[0].ChallengeActive = &EdgeReportChallenge{Reason: "zone-rps", Until: now.Add(time.Minute), DryRun: true}
	next.ZonesTruncated = 1
	hw.reset()
	before := dropSnapshot()
	s.edgeHist.observe(cfg, "e1", &prev, next, now.Add(10*time.Second))
	want := []string{
		EventVersion, EventDryRun, EventDocumentRendered, EventGenerationInstalled, EventGenerationRefused, EventTerminatorAlive, EventH3State,
		EventCertRenewed + ":a.example", EventCertIssued + ":c.example", EventCertGone + ":b.example",
		EventChallengeStarted + ":a.example", EventReportTruncated,
	}
	got := hw.kinds()
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	have := map[string]int{}
	for _, k := range got {
		have[k]++
	}
	for _, k := range want {
		if have[k] != 1 {
			t.Errorf("event %s seen %d times, want once (all: %v)", k, have[k], got)
		}
	}
	// The certificate for a zone the file does not have is no event, and counted.
	dropDelta(t, before, map[string]float64{"unknown_zone": 1})
	details := map[string]string{}
	for _, e := range hw.events {
		details[e.Kind] = e.Detail
	}
	if details[EventVersion] != "1.9.0" || details[EventDryRun] != "off" || !strings.Contains(details[EventGenerationInstalled], "generation 4") ||
		!strings.Contains(details[EventGenerationRefused], "unknown directive") || details[EventTerminatorAlive] != "not running" || details[EventH3State] != H3StateNoModule ||
		!strings.Contains(details[EventChallengeStarted], "zone-rps") || !strings.Contains(details[EventChallengeStarted], "(preview)") || details[EventReportTruncated] != "zones=1 certs=0" {
		t.Fatalf("event details: %+v", details)
	}
	// Identical repeat: no events (its window is a duplicate too).
	hw.reset()
	s.edgeHist.observe(cfg, "e1", &next, next, now.Add(20*time.Second))
	if len(hw.events) != 0 || len(hw.windows) != 0 {
		t.Fatalf("an identical report produced %v and %d windows", hw.kinds(), len(hw.windows))
	}
	// The challenge ends, the truncation persists (no second report_truncated).
	after := next
	after.Zones = []EdgeReportZone{window("a.example", now.Add(20*time.Second), 5)}
	hw.reset()
	s.edgeHist.observe(cfg, "e1", &next, after, now.Add(30*time.Second))
	if k := hw.kinds(); len(k) != 1 || k[0] != EventChallengeEnded+":a.example" {
		t.Fatalf("after the challenge ended: %v", k)
	}
	// A certificate list that had to be cut: c.example missing from it is
	// unknown, not gone; and back with a full list, c.example is not "issued"
	// either — absence from a cut list said nothing.
	cut := after
	cut.Certs = []EdgeReportCert{after.Certs[0]}
	cut.CertsTruncated = 1
	hw.reset()
	s.edgeHist.observe(cfg, "e1", &after, cut, now.Add(40*time.Second))
	if k := hw.kinds(); len(k) != 0 {
		t.Fatalf("a cut certificate list was read as transitions: %v", k)
	}
	back := cut
	back.Certs = after.Certs
	back.CertsTruncated = 0
	s.edgeHist.observe(cfg, "e1", &cut, back, now.Add(50*time.Second))
	if k := hw.kinds(); len(k) != 0 {
		t.Fatalf("a list restored after a cut was read as transitions: %v", k)
	}
	// A zone with an active challenge that is missing from the next report:
	// "zone left the report" when the report is whole, nothing when its zones
	// were cut (report_truncated says why).
	p1 := EdgeReport{Zones: []EdgeReportZone{{Zone: "a.example", ChallengeActive: &EdgeReportChallenge{Reason: "manual", Until: now.Add(time.Hour)}}}}
	hw.reset()
	s.edgeHist.observe(cfg, "e1", &p1, EdgeReport{ZonesTruncated: 1}, now.Add(time.Minute))
	if k := hw.kinds(); len(k) != 1 || k[0] != EventReportTruncated {
		t.Fatalf("a cut zones list: %v, want only report_truncated", k)
	}
	hw.reset()
	s.edgeHist.observe(cfg, "e1", &p1, EdgeReport{}, now.Add(time.Minute))
	if k := hw.kinds(); len(k) != 1 || k[0] != EventChallengeEnded+":a.example" || hw.events[0].Detail != "zone left the report" {
		t.Fatalf("a whole report without the zone: %v %+v", k, hw.events)
	}
	// A challenge on a zone the file does not have: dropped and counted, like its window.
	hw.reset()
	before = dropSnapshot()
	s.edgeHist.observe(cfg, "e1", &EdgeReport{}, EdgeReport{Zones: []EdgeReportZone{{Zone: "ghost.example", ChallengeActive: &EdgeReportChallenge{Until: now.Add(time.Hour)}}}}, now.Add(time.Minute))
	if len(hw.events) != 0 {
		t.Fatalf("a challenge for an unknown zone became an event: %+v", hw.events)
	}
	dropDelta(t, before, map[string]float64{"unknown_zone": 2}) // the window and the challenge
}

// TestEdgeHistoryHandlerNeverBlocks: the report handler answers 204 whether
// the history is a recording writer, a real writer whose queue of one is full
// and never drained, or no writer at all.
func TestEdgeHistoryHandlerNeverBlocks(t *testing.T) {
	store, _ := edgeStore(t, edgeZonesOne)
	s := testServer(t, store)
	h := s.Handler()
	at := time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339)
	body := func(n int) string {
		return fmt.Sprintf(`{"version":"1.8.0","zones":[{"zone":"a.example","at":%q,"window_seconds":10,"requests":%d,"top_sources":[{"source":"203.0.113.9","requests":%d,"state":"would-deny"}]}]}`, at, n, n)
	}
	// No writer (storage off): stored and shown, nothing to write to, nothing counted.
	before := dropSnapshot()
	if rec := postEdgeReport(h, "e1", body(1), "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report without a writer = %d", rec.Code)
	}
	if rec := postEdgeReport(h, "e1", `{"version":"1.8.0","zones":[{"zone":"ghost.example","requests":1}]}`, "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report without a writer = %d", rec.Code)
	}
	dropDelta(t, before, nil)
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	// The writer-less report wrote nothing, so the same window is not a
	// duplicate yet: the first writer sees it once.
	if rec := postEdgeReport(h, "e1", body(2), "agent-secret"); rec.Code != http.StatusNoContent || len(hw.windows) != 1 || len(hw.sources) != 1 {
		t.Fatalf("first report with a writer: %d, %d windows %d sources", rec.Code, len(hw.windows), len(hw.sources))
	}
	if rec := postEdgeReport(h, "e1", body(2), "agent-secret"); rec.Code != http.StatusNoContent || len(hw.windows) != 1 {
		t.Fatalf("a re-sent report through the handler: %d, %d windows (want still 1)", rec.Code, len(hw.windows))
	}
	at2 := time.Now().UTC().Add(-4 * time.Second).Format(time.RFC3339)
	if rec := postEdgeReport(h, "e1", strings.Replace(body(3), at, at2, 1), "agent-secret"); rec.Code != http.StatusNoContent || len(hw.windows) != 2 || len(hw.sources) != 2 {
		t.Fatalf("the next window through the handler: %d, %d windows %d sources", rec.Code, len(hw.windows), len(hw.sources))
	}
	// A real writer with a queue of one, never started (never drained), a dead
	// server: the enqueue drops, the handler answers — bounded by a deadline,
	// not by the test's patience.
	real := storage.NewWriter(config.StorageSettings{Enabled: true, URL: "http://127.0.0.1:1", Database: "kapkan", TTLDays: 1, BatchSize: 100, QueueSize: 1, FlushInterval: time.Hour, TrafficInterval: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetStorageWriter(real)
	done := make(chan int, 1)
	go func() {
		for i := 0; i < 5; i++ {
			atN := time.Now().UTC().Add(time.Duration(-3+i) * time.Second).Format(time.RFC3339)
			if rec := postEdgeReport(h, "e1", strings.Replace(body(10+i), at, atN, 1), "agent-secret"); rec.Code != http.StatusNoContent {
				done <- rec.Code
				return
			}
		}
		done <- http.StatusNoContent
	}()
	select {
	case code := <-done:
		if code != http.StatusNoContent {
			t.Fatalf("a report with a full storage queue = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reports with a full storage queue did not answer within 5 s: the history blocked the handler")
	}
}

// TestEdgePresenceTick: the ticker turns the poll-based liveness into
// node_alive / node_lost, one per transition, the loss stamped when it
// happened (lastSeen + stale_after). The first observation of a node is a
// silent baseline — its first poll after a brain start, or "lost" once
// stale_after has passed unheard — so a restart is never a fleet-wide burst.
func TestEdgePresenceTick(t *testing.T) {
	store, _ := edgeStoreWith(t, edgeZonesOne, 1) // stale_after 1 s
	s := testServer(t, store)
	h := s.Handler()
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	cfg := store.Get()

	t0 := time.Now()
	s.edgePresenceTick(cfg, t0) // just started, nobody heard from: not a baseline yet
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	last, _ := s.edgePresence.seen("e1")
	s.edgePresenceTick(cfg, last)
	if len(hw.events) != 0 {
		t.Fatalf("a node's first poll after a start is a silent baseline, got %v", hw.kinds())
	}
	s.edgePresenceTick(cfg, last.Add(3*time.Second))
	if k := hw.kinds(); len(k) != 1 || k[0] != EventNodeLost || hw.events[0].Node != "e1" {
		t.Fatalf("after stale_after passed: %v", k)
	}
	if lost := hw.events[0]; lost.EventTime != historyTime(last.Add(time.Second)) || !strings.Contains(lost.Detail, "last_seen=") {
		t.Fatalf("node_lost must be stamped lastSeen + stale_after: %+v (last %s)", lost, historyTime(last))
	}
	// Still lost: nothing new.
	s.edgePresenceTick(cfg, last.Add(4*time.Second))
	if len(hw.events) != 1 {
		t.Fatalf("a repeated loss was announced again: %v", hw.kinds())
	}
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	last, _ = s.edgePresence.seen("e1")
	s.edgePresenceTick(cfg, last)
	if k := hw.kinds(); len(k) != 2 || k[1] != EventNodeAlive {
		t.Fatalf("after the node returned: %v", k)
	}

	// A node that never polls: baselined as lost, silently, once stale_after
	// has passed since the ticker started; its first poll is then node_alive.
	s2 := testServer(t, store)
	h2 := s2.Handler()
	hw2 := &histWriter{}
	s2.SetStorageWriter(hw2)
	s2.edgePresenceTick(cfg, t0)
	s2.edgePresenceTick(cfg, t0.Add(1500*time.Millisecond))
	if len(hw2.events) != 0 {
		t.Fatalf("an unheard-from node was announced: %v", hw2.kinds())
	}
	if rec := getZones(h2, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	last2, _ := s2.edgePresence.seen("e1")
	s2.edgePresenceTick(cfg, last2)
	if k := hw2.kinds(); len(k) != 1 || k[0] != EventNodeAlive {
		t.Fatalf("a lost-baselined node's first poll: %v", k)
	}

	// Without a writer the ticker still runs, and the INFO line is the product.
	var buf bytes.Buffer
	bare := testServer(t, store)
	bare.log = slog.New(slog.NewTextHandler(&buf, nil))
	h3 := bare.Handler()
	bare.edgePresenceTick(cfg, t0)
	if rec := getZones(h3, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	last3, _ := bare.edgePresence.seen("e1")
	bare.edgePresenceTick(cfg, last3)
	bare.edgePresenceTick(cfg, last3.Add(3*time.Second))
	bare.edgePresenceTick(cfg, last3.Add(4*time.Second))
	if rec := getZones(h3, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	last3, _ = bare.edgePresence.seen("e1")
	bare.edgePresenceTick(cfg, last3)
	logged := buf.String()
	if strings.Count(logged, "edge node lost") != 1 || !strings.Contains(logged, "node=e1") || !strings.Contains(logged, "lost_at=") || strings.Count(logged, "edge node alive") != 1 {
		t.Fatalf("presence log without storage:\n%s", logged)
	}
}

// TestRunEdgePresence: the ticker loop itself — started, it observes the
// polls on its own clock, announces the transitions, and stops with its
// context. stale_after is two seconds against the one-second tick floor, so
// the tick after the poll always finds the node alive (the baseline) and the
// one after stale_after finds it lost; with stale_after equal to the period
// the first observation could already be "lost" — a legitimate baseline the
// test could not tell from a missed transition.
func TestRunEdgePresence(t *testing.T) {
	store, _ := edgeStoreWith(t, edgeZonesOne, 2) // stale_after 2 s → a tick every second (the floor)
	s := testServer(t, store)
	h := s.Handler()
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runEdgePresence(ctx)
		close(done)
	}()
	waitKinds := func(want []string) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if k := hw.kinds(); len(k) >= len(want) {
				if len(k) != len(want) {
					t.Fatalf("events = %v, want %v", k, want)
				}
				for i := range want {
					if k[i] != want[i] {
						t.Fatalf("events = %v, want %v", k, want)
					}
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("events = %v after 8 s, want %v", hw.kinds(), want)
	}
	// One poll, then silence: the node is baselined alive at the next tick
	// (silently) and lost once stale_after has passed.
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	waitKinds([]string{EventNodeLost})
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	waitKinds([]string{EventNodeLost, EventNodeAlive})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runEdgePresence did not return after its context was cancelled")
	}
}

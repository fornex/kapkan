package api

import (
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

func dropped(reason string) float64 {
	return testutil.ToFloat64(metrics.EdgeHistoryDropped.WithLabelValues(reason))
}

func histFixture(t *testing.T) (*Server, *histWriter, *config.Config) {
	t.Helper()
	store, _ := edgeStore(t, edgeZonesTwo) // a.example decides, b.example is mode: none
	s := testServer(t, store)
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	return s, hw, store.Get()
}

func window(zone string, at time.Time, requests uint64, sources ...EdgeReportSource) EdgeReportZone {
	return EdgeReportZone{Zone: zone, At: at, WindowSeconds: 10, Challenge: "off", RPS: float64(requests) / 10, Requests: requests, Decided: requests, TopSources: sources}
}

// TestEdgeHistoryWindowsAndSources: one row per unique (node, zone, at) of a
// zone the file has; only telling, parseable sources, at most twenty; every
// skipped part counted by reason; the same report again writes nothing.
func TestEdgeHistoryWindowsAndSources(t *testing.T) {
	s, hw, cfg := histFixture(t)
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
	before := map[string]float64{}
	for _, r := range []string{"unknown_zone", "no_at", "duplicate", "bad_source", "source_cap"} {
		before[r] = dropped(r)
	}
	rep := EdgeReport{Version: "1.8.0", Zones: []EdgeReportZone{
		window("a.example", at, 425, srcs...),
		window("ghost.example", at, 1),
		{Zone: "a.example", Requests: 1}, // no close time
	}}
	rep.Zones[0].DryRun = true
	rep.Zones[0].Status2xx = 400
	rep.Zones[0].H3Requests = 7
	rep.Zones[0].SourcesTruncated = 3
	rep.Zones[0].ChallengeActive = &EdgeReportChallenge{Reason: "zone-rps", Until: now.Add(time.Minute)}
	s.edgeHist.observe(cfg, "e1", nil, rep, now)

	if len(hw.windows) != 1 {
		t.Fatalf("windows = %+v, want one (a.example)", hw.windows)
	}
	w := hw.windows[0]
	if w.TS != "2026-09-10 12:00:20" || w.ReceivedAt != "2026-09-10 12:00:30" || w.Zone != "a.example" || w.Node != "e1" || w.Requests != 425 || w.WindowSeconds != 10 ||
		w.Challenge != "off" || w.DryRun != 1 || w.RungDryRun != 0 || w.Status2xx != 400 || w.H3Requests != 7 || w.SourcesTruncated != 3 || w.ChallengeActive != 1 || w.ChallengeReason != "zone-rps" {
		t.Fatalf("window row: %+v", w)
	}
	if len(hw.sources) != storage.EdgeSourcesPerWindow {
		t.Fatalf("sources = %d, want %d (the cap)", len(hw.sources), storage.EdgeSourcesPerWindow)
	}
	if hw.sources[0].Source != "203.0.113.9" || hw.sources[0].State != SourceStateDenied || hw.sources[0].Requests != 500 || hw.sources[0].TS != w.TS || hw.sources[1].Source != "2001:db8:1:2::" {
		t.Fatalf("sources: %+v", hw.sources[:2])
	}
	for _, src := range hw.sources {
		if !tellingState(src.State) || src.Source == "not-an-ip" || strings.HasPrefix(src.Source, "198.51.100.19") || src.Source == "198.51.100.22" {
			t.Fatalf("a visitor, a bad key or a capped source was written: %+v", src)
		}
	}
	for reason, want := range map[string]float64{"unknown_zone": 1, "no_at": 1, "duplicate": 0, "bad_source": 1, "source_cap": 4} {
		if got := dropped(reason) - before[reason]; got != want {
			t.Errorf("dropped{%s} = %v, want %v", reason, got, want)
		}
	}
	// No events: the first report is the baseline, and the clock is within the gate.
	if len(hw.events) != 0 {
		t.Fatalf("events on a baseline report: %+v", hw.events)
	}

	// The same report again: the window is a duplicate, nothing is written,
	// and an identical report has no transitions.
	hw.reset()
	s.edgeHist.observe(cfg, "e1", &rep, rep, now.Add(time.Second))
	if len(hw.windows) != 0 || len(hw.sources) != 0 || len(hw.events) != 0 {
		t.Fatalf("a re-sent report wrote something: %d windows %d sources %v", len(hw.windows), len(hw.sources), hw.kinds())
	}
	if got := dropped("duplicate") - before["duplicate"]; got != 1 {
		t.Fatalf("dropped{duplicate} = %v, want 1", got)
	}
	// The next window is new.
	next := EdgeReport{Version: "1.8.0", Zones: []EdgeReportZone{window("a.example", at.Add(10*time.Second), 10)}}
	s.edgeHist.observe(cfg, "e1", &rep, next, now.Add(10*time.Second))
	if len(hw.windows) != 1 || hw.windows[0].TS != "2026-09-10 12:00:30" {
		t.Fatalf("the next window: %+v", hw.windows)
	}
	// A mode: none zone reports no windows; a report without a zones section
	// writes nothing and drops nothing.
	hw.reset()
	quietBefore := dropped("unknown_zone") + dropped("no_at") + dropped("duplicate")
	s.edgeHist.observe(cfg, "e1", &next, EdgeReport{Version: "1.8.0"}, now.Add(20*time.Second))
	if len(hw.windows)+len(hw.sources)+len(hw.events) != 0 || dropped("unknown_zone")+dropped("no_at")+dropped("duplicate") != quietBefore {
		t.Fatalf("a quiet report wrote or dropped something: %+v %+v %+v", hw.windows, hw.sources, hw.events)
	}
}

// TestEdgeHistoryClockSkew (D11): a window close outside the gate is stamped
// with the brain's clock, received_at is always the brain's, and clock_skew
// is written once per transition — into skew and back.
func TestEdgeHistoryClockSkew(t *testing.T) {
	s, hw, cfg := histFixture(t)
	now := time.Date(2026, 9, 10, 12, 0, 30, 0, time.UTC)
	nine := now.Add(-9 * time.Minute) // behind, within the gate
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", nine, 1)}}, now)
	if len(hw.windows) != 1 || hw.windows[0].TS != historyTime(nine) || len(hw.events) != 0 {
		t.Fatalf("a window nine minutes behind must keep its own clock: %+v %+v", hw.windows, hw.events)
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
	// Back within the gate: one recovery event.
	sane := now.Add(30 * time.Second)
	s.edgeHist.observe(cfg, "e1", nil, EdgeReport{Zones: []EdgeReportZone{window("a.example", sane, 1)}}, sane)
	if len(hw.events) != 1 || hw.events[0].Kind != EventClockSkew || !strings.Contains(hw.events[0].Detail, "recovered") {
		t.Fatalf("recovery event: %+v", hw.events)
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
// event, an identical repeat is none, and the first report is a silent
// baseline.
func TestEdgeHistoryEvents(t *testing.T) {
	s, hw, cfg := histFixture(t)
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
	next.Certs = []EdgeReportCert{{Zone: "a.example", NotAfter: t1.AddDate(0, 2, 0), Issuer: "R11"}, {Zone: "c.example", NotAfter: t1}}
	next.Zones = []EdgeReportZone{window("a.example", now, 5)}
	next.Zones[0].ChallengeActive = &EdgeReportChallenge{Reason: "zone-rps", Until: now.Add(time.Minute), DryRun: true}
	next.ZonesTruncated = 1
	hw.reset()
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
	details := map[string]string{}
	for _, e := range hw.events {
		details[e.Kind] = e.Detail
	}
	if details[EventVersion] != "1.9.0" || details[EventDryRun] != "off" || !strings.Contains(details[EventGenerationInstalled], "generation 4") ||
		!strings.Contains(details[EventGenerationRefused], "unknown directive") || details[EventTerminatorAlive] != "not running" || details[EventH3State] != H3StateNoModule ||
		!strings.Contains(details[EventChallengeStarted], "zone-rps") || !strings.Contains(details[EventChallengeStarted], "(preview)") || details[EventReportTruncated] != "zones=1 certs=0 sources=0" {
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
	// No writer yet: stored and shown, nothing to write to.
	if rec := postEdgeReport(h, "e1", body(1), "agent-secret"); rec.Code != http.StatusNoContent {
		t.Fatalf("report without a writer = %d", rec.Code)
	}
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
	// server: the enqueue drops, the handler answers.
	real := storage.NewWriter(config.StorageSettings{Enabled: true, URL: "http://127.0.0.1:1", Database: "kapkan", TTLDays: 1, BatchSize: 100, QueueSize: 1, FlushInterval: time.Hour, TrafficInterval: time.Second}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetStorageWriter(real)
	start := time.Now()
	for i := 0; i < 5; i++ {
		atN := time.Now().UTC().Add(time.Duration(-3+i) * time.Second).Format(time.RFC3339)
		if rec := postEdgeReport(h, "e1", strings.Replace(body(10+i), at, atN, 1), "agent-secret"); rec.Code != http.StatusNoContent {
			t.Fatalf("report %d with a full queue = %d", i, rec.Code)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("reports with a full storage queue took %s", time.Since(start))
	}
}

// TestEdgePresenceTick: the ticker turns the poll-based liveness into
// node_alive / node_lost, one per transition, the loss stamped when it
// happened (lastSeen + stale_after), the first observation a silent baseline.
func TestEdgePresenceTick(t *testing.T) {
	store, _ := edgeStoreWith(t, edgeZonesOne, 1)
	s := testServer(t, store)
	h := s.Handler()
	hw := &histWriter{}
	s.SetStorageWriter(hw)
	cfg := store.Get()

	s.edgePresenceTick(cfg, time.Now())
	if len(hw.events) != 0 {
		t.Fatalf("the first tick is a baseline, got %v", hw.kinds())
	}
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	s.edgePresenceTick(cfg, time.Now())
	if k := hw.kinds(); len(k) != 1 || k[0] != EventNodeAlive || hw.events[0].Node != "e1" {
		t.Fatalf("after the poll: %v", k)
	}
	last, _ := s.edgePresence.seen("e1")
	s.edgePresenceTick(cfg, last.Add(3*time.Second))
	if k := hw.kinds(); len(k) != 2 || k[1] != EventNodeLost {
		t.Fatalf("after stale_after passed: %v", k)
	}
	if lost := hw.events[1]; lost.EventTime != historyTime(last.Add(time.Second)) || !strings.Contains(lost.Detail, "last_seen=") {
		t.Fatalf("node_lost must be stamped lastSeen + stale_after: %+v (last %s)", lost, historyTime(last))
	}
	// Still lost: nothing new.
	s.edgePresenceTick(cfg, last.Add(4*time.Second))
	if len(hw.events) != 2 {
		t.Fatalf("a repeated loss was announced again: %v", hw.kinds())
	}
	if rec := getZones(h, "", "agent-secret", "e1"); rec.Code != http.StatusOK {
		t.Fatalf("poll = %d", rec.Code)
	}
	s.edgePresenceTick(cfg, time.Now())
	if k := hw.kinds(); len(k) != 3 || k[2] != EventNodeAlive {
		t.Fatalf("after the node returned: %v", k)
	}
	// Without a writer the ticker still runs (the log line is the product).
	bare := testServer(t, store)
	bare.edgePresenceTick(cfg, time.Now())
	bare.edgePresenceTick(cfg, time.Now().Add(time.Hour))
}

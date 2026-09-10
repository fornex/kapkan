package storage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// TestEdgeSchemaDDL: Start issues the three edge tables' DDL after the core
// tables', each a MergeTree with the documented ORDER BY and a ttl_days TTL,
// enum-like columns as LowCardinality(String) and never an Enum.
func TestEdgeSchemaDDL(t *testing.T) {
	rec := newRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()

	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	defer func() { cancel(); w.Stop() }()

	rec.mu.Lock()
	ddl := append([]string(nil), rec.ddl...)
	rec.mu.Unlock()
	joined := strings.Join(ddl, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS kapkan.edge_windows (", "ORDER BY (zone, ts, node)", "TTL ts + INTERVAL 7 DAY",
		"CREATE TABLE IF NOT EXISTS kapkan.edge_sources (", "ORDER BY (zone, ts, source)",
		"CREATE TABLE IF NOT EXISTS kapkan.edge_events (", "ORDER BY (event_time, node)", "TTL event_time + INTERVAL 7 DAY",
		"received_at DateTime", "window_seconds Float64", "h3_requests UInt64", "sources_truncated UInt32",
		"challenge LowCardinality(String)", "state LowCardinality(String)", "kind LowCardinality(String)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("edge DDL missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "Enum") {
		t.Errorf("an Enum column would fail the inserts of every older table:\n%s", joined)
	}
	for _, s := range ddl {
		if strings.Contains(s, "edge_") && !strings.Contains(s, "ENGINE = MergeTree()") {
			t.Errorf("edge table without MergeTree: %s", s)
		}
	}
	// Order: the core tables first (their loop is fail-fast), the edge tables
	// after them (best-effort, each on its own).
	first := func(name string) int {
		for i, s := range ddl {
			if strings.Contains(s, name) {
				return i
			}
		}
		return -1
	}
	if first("audit_events") > first("edge_windows") || first("edge_windows") < 0 {
		t.Errorf("edge DDL must follow the core tables: %v", ddl)
	}
}

// TestEdgeSchemaIsBestEffort: a ClickHouse that refuses the edge DDL (a writer
// credential from before E6.4, say) leaves the core tables created and the
// writer working — the three tables a deployment always had are not held
// hostage by the three new ones.
func TestEdgeSchemaIsBestEffort(t *testing.T) {
	var mu sync.Mutex
	var created []string
	var inserted int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		s := strings.TrimSpace(string(body))
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasPrefix(s, "CREATE") && strings.Contains(s, "edge_"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Code: 497. DB::Exception: not enough privileges"))
			return
		case strings.HasPrefix(s, "CREATE"):
			created = append(created, s)
		case strings.HasPrefix(req.URL.Query().Get("query"), "INSERT INTO"):
			inserted += strings.Count(s, "\n") + 1
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := config.StorageSettings{Enabled: true, URL: srv.URL, Database: "kapkan", TTLDays: 7, BatchSize: 100, QueueSize: 1000, FlushInterval: 20 * time.Millisecond, TrafficInterval: time.Second}

	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	w.WriteAttack(sampleAttack())
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return inserted == 1 })
	cancel()
	w.Stop()
	mu.Lock()
	defer mu.Unlock()
	if len(created) != 4 { // database + the three core tables
		t.Fatalf("core DDL statements = %d, want 4 (database + attack_events, traffic, audit_events): %v", len(created), created)
	}
}

// TestEdgeWritesAreStandaloneJSON: the three writers land rows in their
// tables as one standalone JSON object per line, with the column names.
func TestEdgeWritesAreStandaloneJSON(t *testing.T) {
	rec := newRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	defer func() { cancel(); w.Stop() }()

	w.WriteEdgeWindows([]EdgeWindowRow{{
		TS: "2026-09-10 12:00:10", ReceivedAt: "2026-09-10 12:00:11", WindowSeconds: 10, Zone: "shop.example", Node: "e1",
		Challenge: "auto", DryRun: 1, RungDryRun: 1, ChallengeActive: 1, ChallengeReason: "zone-rps",
		Requests: 425, Decided: 420, Denied: 30, Challenged: 5, WouldDeny: 3, WouldChallenge: 12,
		Status2xx: 380, Status4xx: 45, H3Requests: 7, SourcesTruncated: 2,
	}, {TS: "2026-09-10 12:00:20", ReceivedAt: "2026-09-10 12:00:21", WindowSeconds: 10, Zone: "shop.example", Node: "e1"}})
	w.WriteEdgeSources([]EdgeSourceRow{{TS: "2026-09-10 12:00:10", Zone: "shop.example", Node: "e1", Source: "203.0.113.9", State: "would-deny", Requests: 200, RPS: 20}})
	w.WriteEdgeEvent(EdgeEventRow{EventTime: "2026-09-10 12:00:00", Node: "e1", Kind: "node_alive"})
	waitFor(t, func() bool {
		return len(rec.inserts(tableEdgeWindows)) == 2 && len(rec.inserts(tableEdgeSources)) == 1 && len(rec.inserts(tableEdgeEvents)) == 1
	})

	win := rec.inserts(tableEdgeWindows)[0]
	for _, want := range []string{`"ts":"2026-09-10 12:00:10"`, `"received_at":"2026-09-10 12:00:11"`, `"window_seconds":10`, `"zone":"shop.example"`, `"node":"e1"`,
		`"challenge":"auto"`, `"dry_run":1`, `"rung_dry_run":1`, `"challenge_active":1`, `"challenge_reason":"zone-rps"`,
		`"requests":425`, `"would_deny":3`, `"would_challenge":12`, `"status_2xx":380`, `"status_4xx":45`, `"h3_requests":7`, `"sources_truncated":2`} {
		if !strings.Contains(win, want) {
			t.Errorf("window row missing %q: %s", want, win)
		}
	}
	if strings.Contains(win, `"rps"`) || strings.Contains(win, `"tenant"`) {
		t.Errorf("a window row carries a derived or an ownership column: %s", win)
	}
	src := rec.inserts(tableEdgeSources)[0]
	for _, want := range []string{`"source":"203.0.113.9"`, `"state":"would-deny"`, `"requests":200`, `"rps":20`} {
		if !strings.Contains(src, want) {
			t.Errorf("source row missing %q: %s", want, src)
		}
	}
	ev := rec.inserts(tableEdgeEvents)[0]
	for _, want := range []string{`"event_time":"2026-09-10 12:00:00"`, `"node":"e1"`, `"kind":"node_alive"`, `"zone":""`, `"detail":""`} {
		if !strings.Contains(ev, want) {
			t.Errorf("event row missing %q: %s", want, ev)
		}
	}
	for _, table := range []string{tableEdgeWindows, tableEdgeSources, tableEdgeEvents} {
		for _, line := range rec.inserts(table) {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Errorf("%s line is not standalone JSON: %q (%v)", table, line, err)
			}
		}
	}
}

// TestEdgeNoopAndNilQuerier: disabled storage is a no-op writer for the edge
// rows too, and no querier.
func TestEdgeNoopAndNilQuerier(t *testing.T) {
	w := NewWriter(config.StorageSettings{}, discardLogger())
	w.WriteEdgeWindows([]EdgeWindowRow{{Zone: "a"}})
	w.WriteEdgeSources([]EdgeSourceRow{{Zone: "a"}})
	w.WriteEdgeEvent(EdgeEventRow{Kind: "node_alive"})
	if NewQuerier(config.StorageSettings{}, discardLogger()) != nil {
		t.Fatal("querier for disabled storage must be nil")
	}
}

// TestQueryEdgeHistorySQLAndDecode: the history query binds zone (and node
// when asked) through param_*, embeds the clamped step as an integer literal,
// carries the read-path hardening plus unquoted 64-bit integers, and decodes
// the buckets.
func TestQueryEdgeHistorySQLAndDecode(t *testing.T) {
	rec := newReadRecorder()
	rec.resp = `{"ts":"2026-09-10 12:00:00","nodes":2,"window_seconds":120,"requests":8124,"decided":8124,"denied":0,"challenged":0,"cleared":0,"would_deny":37,"would_challenge":1240,"status_2xx":7000,"status_3xx":10,"status_4xx":1100,"status_5xx":14,"h3_requests":2048}
{"ts":"2026-09-10 12:01:00","nodes":1,"window_seconds":60,"requests":10}`
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)
	from := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	out, err := ch.QueryEdgeHistory(context.Background(), "shop.example", "", from, to, 0)
	if err != nil {
		t.Fatalf("QueryEdgeHistory: %v", err)
	}
	if len(out) != 2 || out[0].Nodes != 2 || out[0].Requests != 8124 || out[0].WouldChallenge != 1240 || out[0].H3Requests != 2048 || out[0].WindowSeconds != 120 || out[1].Requests != 10 {
		t.Fatalf("decoded points: %+v", out)
	}
	sql, q, _ := rec.snapshot()
	for _, want := range []string{
		"toStartOfInterval(ts, INTERVAL 60 SECOND) AS ts", // step 0 → the 60 s default
		"uniqExact(node) AS nodes", "sum(window_seconds) AS window_seconds", "sum(requests) AS requests",
		"sum(would_challenge) AS would_challenge", "sum(h3_requests) AS h3_requests",
		"FROM kapkan.edge_windows", "zone = {zone:String}", "ts BETWEEN {from:DateTime} AND {to:DateTime}",
		"GROUP BY ts ORDER BY ts LIMIT 5001 FORMAT JSONEachRow",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("history SQL missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "node = {node:String}") {
		t.Errorf("no node asked for, yet the SQL filters by node:\n%s", sql)
	}
	assertParam(t, q, "param_zone", "shop.example")
	assertParam(t, q, "param_from", "2026-09-10 12:00:00")
	assertParam(t, q, "param_to", "2026-09-10 13:00:00")
	assertParam(t, q, "readonly", "2")
	assertParam(t, q, "max_execution_time", "10")
	assertParam(t, q, "max_result_rows", "5001")
	assertParam(t, q, "result_overflow_mode", "throw")
	assertParam(t, q, "output_format_json_quote_64bit_integers", "0")
	if q.Has("param_node") {
		t.Errorf("param_node bound without a node filter: %v", q)
	}

	// One node, a clamped step.
	if _, err := ch.QueryEdgeHistory(context.Background(), "shop.example", "e1", from, to, 100000); err != nil {
		t.Fatal(err)
	}
	sql, q, _ = rec.snapshot()
	if !strings.Contains(sql, "AND node = {node:String}") || !strings.Contains(sql, "INTERVAL 86400 SECOND") {
		t.Errorf("node filter or step clamp missing:\n%s", sql)
	}
	assertParam(t, q, "param_node", "e1")
}

// TestQueryEdgeSourcesSQLAndDecode: the strongest state wins, the busiest
// first, an optional state filter, LIMIT 1001.
func TestQueryEdgeSourcesSQLAndDecode(t *testing.T) {
	rec := newReadRecorder()
	rec.resp = `{"source":"203.0.113.9","state":"would-deny","requests":1210,"windows":12,"nodes":2,"first_seen":"2026-09-10 12:00:10","last_seen":"2026-09-10 12:02:00"}`
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)
	from := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	out, err := ch.QueryEdgeSources(context.Background(), EdgeSourceFilter{Zone: "shop.example", From: from, To: from.Add(time.Hour)})
	if err != nil {
		t.Fatalf("QueryEdgeSources: %v", err)
	}
	if len(out) != 1 || out[0].Source != "203.0.113.9" || out[0].State != "would-deny" || out[0].Requests != 1210 || out[0].Windows != 12 || out[0].Nodes != 2 || out[0].LastSeen != "2026-09-10 12:02:00" {
		t.Fatalf("decoded sources: %+v", out)
	}
	sql, q, _ := rec.snapshot()
	for _, want := range []string{
		"argMax(state, multiIf(state = 'denied', 4, state = 'challenged', 3, state = 'would-deny', 2, 1)) AS state",
		"sum(requests) AS requests", "count() AS windows", "uniqExact(node) AS nodes", "min(ts) AS first_seen", "max(ts) AS last_seen",
		"FROM kapkan.edge_sources", "zone = {zone:String}", "GROUP BY source ORDER BY requests DESC, source LIMIT 1001 FORMAT JSONEachRow",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("sources SQL missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "{state:String}") || q.Has("param_state") {
		t.Errorf("state filter present although none was asked for:\n%s %v", sql, q)
	}
	assertParam(t, q, "param_zone", "shop.example")
	assertParam(t, q, "readonly", "2")
	assertParam(t, q, "max_result_rows", "1001")
	assertParam(t, q, "output_format_json_quote_64bit_integers", "0")
	// The filters must sit on the base rows (a subquery): the outer SELECT
	// aliases its aggregate `state`, and a `state = …` in an outer WHERE would
	// be read as that aggregate by the server.
	if !strings.Contains(sql, "FROM (SELECT source, state, requests, node, ts FROM kapkan.edge_sources WHERE zone = {zone:String}") || !strings.Contains(sql, ") GROUP BY source") {
		t.Errorf("the source filters are not in a subquery:\n%s", sql)
	}

	if _, err := ch.QueryEdgeSources(context.Background(), EdgeSourceFilter{Zone: "shop.example", State: "denied", From: from, To: from.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	sql, q, _ = rec.snapshot()
	if !strings.Contains(sql, "AND state = {state:String}") {
		t.Errorf("state filter missing:\n%s", sql)
	}
	assertParam(t, q, "param_state", "denied")
}

// TestQueryEdgeEventsSQLAndDecode: newest first, every optional filter bound
// only when given, LIMIT 1001.
func TestQueryEdgeEventsSQLAndDecode(t *testing.T) {
	rec := newReadRecorder()
	rec.resp = `{"event_time":"2026-09-10 12:05:00","node":"e1","zone":"","kind":"node_lost","detail":""}
{"event_time":"2026-09-10 12:00:00","node":"e1","zone":"shop.example","kind":"cert_renewed","detail":"not_after=2026-12-01T00:00:00Z"}`
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)
	from := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	out, err := ch.QueryEdgeEvents(context.Background(), EdgeEventFilter{From: from, To: from.Add(time.Hour)})
	if err != nil {
		t.Fatalf("QueryEdgeEvents: %v", err)
	}
	if len(out) != 2 || out[0].Kind != "node_lost" || out[1].Zone != "shop.example" || out[1].Detail != "not_after=2026-12-01T00:00:00Z" {
		t.Fatalf("decoded events: %+v", out)
	}
	sql, q, _ := rec.snapshot()
	for _, want := range []string{"SELECT event_time, node, zone, kind, detail FROM kapkan.edge_events", "event_time BETWEEN {from:DateTime} AND {to:DateTime}", "ORDER BY event_time DESC LIMIT 1001 FORMAT JSONEachRow"} {
		if !strings.Contains(sql, want) {
			t.Errorf("events SQL missing %q:\n%s", want, sql)
		}
	}
	for _, absent := range []string{"{node:String}", "{zone:String}", "{kind:String}"} {
		if strings.Contains(sql, absent) {
			t.Errorf("unrequested filter %s in:\n%s", absent, sql)
		}
	}
	assertParam(t, q, "readonly", "2")
	assertParam(t, q, "max_result_rows", "1001")

	if _, err := ch.QueryEdgeEvents(context.Background(), EdgeEventFilter{Node: "e1", Zone: "shop.example", Kind: "cert_renewed", From: from, To: from.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	sql, q, _ = rec.snapshot()
	for _, want := range []string{"AND node = {node:String}", "AND zone = {zone:String}", "AND kind = {kind:String}"} {
		if !strings.Contains(sql, want) {
			t.Errorf("filter missing %q:\n%s", want, sql)
		}
	}
	assertParam(t, q, "param_node", "e1")
	assertParam(t, q, "param_zone", "shop.example")
	assertParam(t, q, "param_kind", "cert_renewed")
}

// TestQueryEdgeErrorPropagates: a ClickHouse error is returned, never an empty
// success.
func TestQueryEdgeErrorPropagates(t *testing.T) {
	rec := newReadRecorder()
	rec.status = http.StatusInternalServerError
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)
	from := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	if _, err := ch.QueryEdgeHistory(context.Background(), "z", "", from, from.Add(time.Hour), 60); err == nil || !strings.Contains(err.Error(), "clickhouse status 500") {
		t.Fatalf("history err = %v, want the ClickHouse status", err)
	}
	if _, err := ch.QueryEdgeSources(context.Background(), EdgeSourceFilter{Zone: "z", From: from, To: from.Add(time.Hour)}); err == nil {
		t.Fatal("sources: want an error")
	}
	if _, err := ch.QueryEdgeEvents(context.Background(), EdgeEventFilter{From: from, To: from.Add(time.Hour)}); err == nil {
		t.Fatal("events: want an error")
	}
}

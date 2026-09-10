package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// ddlColumns lists the column names of a CREATE TABLE statement, in order.
func ddlColumns(t *testing.T, ddl string) []string {
	t.Helper()
	open := strings.Index(ddl, "(")
	closeAt := strings.Index(ddl, ") ENGINE")
	if open < 0 || closeAt < 0 || closeAt < open {
		t.Fatalf("cannot find the column list in %q", ddl)
	}
	var cols []string
	for _, def := range strings.Split(ddl[open+1:closeAt], ",") {
		def = strings.TrimSpace(def)
		if def == "" {
			continue
		}
		// A type with a parenthesis (LowCardinality(String)) never splits on
		// the comma above, so the first field is always the column name.
		cols = append(cols, strings.Trim(strings.Fields(def)[0], "`"))
	}
	return cols
}

// jsonTags lists a row struct's JSON names, in field order.
func jsonTags(rt reflect.Type) []string {
	var tags []string
	for i := 0; i < rt.NumField(); i++ {
		tags = append(tags, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	return tags
}

// TestEdgeRowTagsMatchDDL: every row struct's JSON names are exactly its
// table's columns, in order. ClickHouse skips unknown fields on insert by
// default, so a misspelled tag would not fail an insert — the column would
// silently take its default; this is the gate against that.
func TestEdgeRowTagsMatchDDL(t *testing.T) {
	want := map[string]reflect.Type{
		tableEdgeWindows: reflect.TypeOf(EdgeWindowRow{}),
		tableEdgeSources: reflect.TypeOf(EdgeSourceRow{}),
		tableEdgeEvents:  reflect.TypeOf(EdgeEventRow{}),
	}
	for _, td := range edgeSchema("kapkan", 7) {
		rt, ok := want[td.table]
		if !ok {
			t.Fatalf("edgeSchema names an unexpected table %q", td.table)
		}
		delete(want, td.table)
		if cols, tags := ddlColumns(t, td.ddl), jsonTags(rt); !reflect.DeepEqual(cols, tags) {
			t.Errorf("%s: DDL columns %v != %s json tags %v", td.table, cols, rt.Name(), tags)
		}
	}
	if len(want) != 0 {
		t.Fatalf("tables without DDL: %v", want)
	}
}

// TestEdgeSchemaDDLPerTable checks each edge table's own statement — a TTL
// or a LowCardinality lost on one table is not covered by another's.
func TestEdgeSchemaDDLPerTable(t *testing.T) {
	wants := map[string][]string{
		tableEdgeWindows: {"ENGINE = MergeTree()", "ORDER BY (zone, ts, node)", "TTL ts + INTERVAL 7 DAY", "zone LowCardinality(String)", "node LowCardinality(String)", "challenge LowCardinality(String)", "challenge_reason LowCardinality(String)"},
		tableEdgeSources: {"ENGINE = MergeTree()", "ORDER BY (zone, ts, source)", "TTL ts + INTERVAL 7 DAY", "zone LowCardinality(String)", "node LowCardinality(String)", "state LowCardinality(String)", "source String"},
		tableEdgeEvents:  {"ENGINE = MergeTree()", "ORDER BY (event_time, node)", "TTL event_time + INTERVAL 7 DAY", "zone LowCardinality(String)", "node LowCardinality(String)", "kind LowCardinality(String)", "detail String"},
	}
	for _, td := range edgeSchema("kapkan", 7) {
		for _, w := range wants[td.table] {
			if !strings.Contains(td.ddl, w) {
				t.Errorf("%s DDL missing %q:\n%s", td.table, w, td.ddl)
			}
		}
		if strings.Contains(td.ddl, "Enum") {
			t.Errorf("%s uses an Enum", td.table)
		}
		if !strings.HasPrefix(td.ddl, "CREATE TABLE IF NOT EXISTS kapkan."+td.table+" (") {
			t.Errorf("%s DDL does not start with its CREATE IF NOT EXISTS: %s", td.table, td.ddl)
		}
	}
}

// ddlRecorder is a ClickHouse stand-in that refuses the statements `refuse`
// says so for (HTTP 403) and records every DDL and ALTER it saw, in order.
type ddlRecorder struct {
	mu     sync.Mutex
	stmts  []string
	refuse func(stmt string) bool
}

func (r *ddlRecorder) server(t *testing.T) (*httptest.Server, config.StorageSettings) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		s := strings.TrimSpace(string(body))
		r.mu.Lock()
		defer r.mu.Unlock()
		if strings.HasPrefix(s, "CREATE") || strings.HasPrefix(s, "ALTER") {
			r.stmts = append(r.stmts, s)
			if r.refuse != nil && r.refuse(s) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Code: 497. DB::Exception: not enough privileges"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	return srv, config.StorageSettings{Enabled: true, URL: srv.URL, Database: "kapkan", TTLDays: 7, BatchSize: 100, QueueSize: 1000, FlushInterval: 20 * time.Millisecond, TrafficInterval: time.Second}
}

func (r *ddlRecorder) count(prefix string) (n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.stmts {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

// TestEnsureSchemaAttemptsEverything: with the edge DDL refused, ensureSchema
// still returns nil (the contract: the new tables never fail schema init),
// attempts all three edge CREATEs (it does not stop at the first) and runs
// the ALTER upgrades after them; with a CORE statement refused it returns
// that error but still attempts every remaining statement, edge tables and
// upgrades included — a credential that may INSERT but not CREATE gets every
// line it can act on, not just the first.
func TestEnsureSchemaAttemptsEverything(t *testing.T) {
	t.Run("edge refused", func(t *testing.T) {
		rec := &ddlRecorder{refuse: func(s string) bool { return strings.Contains(s, ".edge_") }}
		srv, cfg := rec.server(t)
		defer srv.Close()
		w := NewWriter(cfg, discardLogger()).(*ClickHouse)
		if err := w.ensureSchema(context.Background()); err != nil {
			t.Fatalf("ensureSchema with the edge DDL refused: %v, want nil", err)
		}
		if got := rec.count("CREATE TABLE IF NOT EXISTS kapkan.edge_"); got != 3 {
			t.Fatalf("edge CREATEs attempted = %d, want 3", got)
		}
		if got := rec.count("ALTER TABLE kapkan.attack_events ADD COLUMN IF NOT EXISTS"); got != 3 {
			t.Fatalf("ALTERs attempted = %d, want 3", got)
		}
		rec.mu.Lock()
		last := rec.stmts[len(rec.stmts)-1]
		rec.mu.Unlock()
		if !strings.HasPrefix(last, "ALTER") {
			t.Fatalf("the upgrades must run after the edge tables; last statement: %s", last)
		}
	})
	t.Run("core refused", func(t *testing.T) {
		rec := &ddlRecorder{refuse: func(s string) bool { return strings.Contains(s, "kapkan.attack_events (") }}
		srv, cfg := rec.server(t)
		defer srv.Close()
		w := NewWriter(cfg, discardLogger()).(*ClickHouse)
		err := w.ensureSchema(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not enough privileges") {
			t.Fatalf("ensureSchema with a core CREATE refused: %v, want the refusal", err)
		}
		if got := rec.count("CREATE TABLE IF NOT EXISTS kapkan."); got != 6 {
			t.Fatalf("CREATE TABLEs attempted = %d, want all 6", got)
		}
		if got := rec.count("ALTER TABLE"); got != 3 {
			t.Fatalf("ALTERs attempted after a refused core CREATE = %d, want 3", got)
		}
	})
}

// TestEdgeQueriesFilterOnRows: the range and state filters sit in a subquery
// on the base rows — an outer WHERE would be read against the SELECT aliases
// (the bucket `ts`, the aggregate `state`) — and the alias rule the queries
// are written for is pinned in every read.
func TestEdgeQueriesFilterOnRows(t *testing.T) {
	rec := newReadRecorder()
	rec.resp = ""
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)
	from := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)

	if _, err := ch.QueryEdgeHistory(context.Background(), "shop.example", "e1", from, to, 60); err != nil {
		t.Fatal(err)
	}
	sql, q, _ := rec.snapshot()
	if !strings.Contains(sql, "FROM (SELECT ts, node, window_seconds, requests, decided, denied, challenged, cleared, would_deny, would_challenge, status_2xx, status_3xx, status_4xx, status_5xx, h3_requests FROM kapkan.edge_windows WHERE zone = {zone:String} AND ts BETWEEN {from:DateTime} AND {to:DateTime} AND node = {node:String}) GROUP BY ts ORDER BY ts") {
		t.Errorf("history filters are not on the base rows:\n%s", sql)
	}
	assertParam(t, q, "prefer_column_name_to_alias", "0")

	if _, err := ch.QueryEdgeSources(context.Background(), EdgeSourceFilter{Zone: "shop.example", State: "denied", From: from, To: to}); err != nil {
		t.Fatal(err)
	}
	sql, q, _ = rec.snapshot()
	if !strings.Contains(sql, "AND state = {state:String}) GROUP BY source ORDER BY requests DESC, source") {
		t.Errorf("the state filter is not on the base rows:\n%s", sql)
	}
	assertParam(t, q, "prefer_column_name_to_alias", "0")

	if _, err := ch.QueryEdgeEvents(context.Background(), EdgeEventFilter{From: from, To: to}); err != nil {
		t.Fatal(err)
	}
	_, q, _ = rec.snapshot()
	assertParam(t, q, "prefer_column_name_to_alias", "0")

	// The traffic query carries the same fix and pin.
	if _, err := ch.QueryTraffic(context.Background(), "203.0.113.20", from, to, 60); err != nil {
		t.Fatal(err)
	}
	sql, q, _ = rec.snapshot()
	if !strings.Contains(sql, "FROM (SELECT ts, pps, mbps, flows_per_sec, in_attack, baseline_pps FROM kapkan.traffic WHERE `key` = {key:String} AND ts BETWEEN {from:DateTime} AND {to:DateTime}) GROUP BY ts ORDER BY ts") {
		t.Errorf("traffic filters are not on the base rows:\n%s", sql)
	}
	assertParam(t, q, "prefer_column_name_to_alias", "0")
}

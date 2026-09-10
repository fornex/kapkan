package storage

// The real-ClickHouse suite (E6.4). The recorder tests pin what the package
// SENDS; this one pins what ClickHouse DOES with it — the DDL parses, the
// upgrade path adds a missing column, every table takes its rows, the TTL
// drops a stale row, the read client cannot write, and the three edge queries
// answer in the documented shapes. It runs against a server named by
// KAPKAN_CLICKHOUSE_URL (default http://127.0.0.1:8123 when
// KAPKAN_CLICKHOUSE=require) and SKIPS when no server is reachable — unless
// KAPKAN_CLICKHOUSE=require, which is what the CI job `storage-clickhouse`
// sets: there, a skip would be a silent hole. The user has full rights (the
// default user; KAPKAN_CLICKHOUSE_USER / KAPKAN_CLICKHOUSE_PASSWORD when the
// server wants a credential — the official image restricts a password-less
// default user to localhost unless CLICKHOUSE_SKIP_USER_SETUP=1): each run
// works in its own database and drops it afterwards.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// realClickHouse returns settings for a throwaway database on the configured
// server, or skips (fails under require).
func realClickHouse(t *testing.T) config.StorageSettings {
	t.Helper()
	require := os.Getenv("KAPKAN_CLICKHOUSE") == "require"
	base := os.Getenv("KAPKAN_CLICKHOUSE_URL")
	if base == "" {
		if !require {
			t.Skip("set KAPKAN_CLICKHOUSE_URL (or KAPKAN_CLICKHOUSE=require for the default http://127.0.0.1:8123) to run against a real ClickHouse")
		}
		base = "http://127.0.0.1:8123"
	}
	base = strings.TrimRight(base, "/")
	resp, err := http.Get(base + "/ping")
	if err == nil {
		_ = resp.Body.Close()
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		if require {
			t.Fatalf("KAPKAN_CLICKHOUSE=require but %s/ping is not answering: %v", base, err)
		}
		t.Skipf("no ClickHouse at %s: %v", base, err)
	}
	db := fmt.Sprintf("kapkan_test_%d", time.Now().UnixNano())
	cfg := config.StorageSettings{
		Enabled: true, URL: base, Database: db,
		TTLDays: 7, BatchSize: 10, QueueSize: 1000,
		FlushInterval: 50 * time.Millisecond, TrafficInterval: time.Second,
	}
	if os.Getenv("KAPKAN_CLICKHOUSE_USER") != "" {
		cfg.UsernameEnv, cfg.PasswordEnv = "KAPKAN_CLICKHOUSE_USER", "KAPKAN_CLICKHOUSE_PASSWORD"
	}
	// The suite's own statements must reach the server too: a credential the
	// server rejects is a failure of the environment, said so, not a skip.
	if _, err := chExec(base, "SELECT 1"); err != nil {
		t.Fatalf("ClickHouse at %s refuses the test's credentials (set KAPKAN_CLICKHOUSE_USER/_PASSWORD, or start the container with CLICKHOUSE_SKIP_USER_SETUP=1): %v", base, err)
	}
	t.Cleanup(func() { _, _ = chExec(base, "DROP DATABASE IF EXISTS "+db) })
	return cfg
}

// chExec runs one statement with the suite's credentials and returns the body.
func chExec(base, sql string) (string, error) {
	req, err := http.NewRequest(http.MethodPost, base+"/", bytes.NewBufferString(sql))
	if err != nil {
		return "", err
	}
	if u := os.Getenv("KAPKAN_CLICKHOUSE_USER"); u != "" {
		req.Header.Set("X-ClickHouse-User", u)
		req.Header.Set("X-ClickHouse-Key", os.Getenv("KAPKAN_CLICKHOUSE_PASSWORD"))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return strings.TrimSpace(string(body)), nil
}

func chCount(t *testing.T, base, db, table string) int {
	t.Helper()
	out, err := chExec(base, fmt.Sprintf("SELECT count() FROM %s.%s FORMAT TabSeparated", db, table))
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	n, err := strconv.Atoi(out)
	if err != nil {
		t.Fatalf("count %s: %q: %v", table, out, err)
	}
	return n
}

// tLogWriter routes the package's log lines into the test log, so a refused
// insert says why in the failure output.
type tLogWriter struct{ t *testing.T }

func (w tLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func TestRealClickHouse(t *testing.T) {
	cfg := realClickHouse(t)
	base, db := cfg.URL, cfg.Database
	log := slog.New(slog.NewTextHandler(tLogWriter{t}, nil))
	ctx := context.Background()
	w := NewWriter(cfg, log).(*ClickHouse)

	// 1. The schema parses and is idempotent.
	for i := 0; i < 2; i++ {
		if err := w.ensureSchema(ctx); err != nil {
			t.Fatalf("ensureSchema #%d: %v", i+1, err)
		}
	}
	for _, table := range []string{tableAttacks, tableTraffic, tableAudit, tableEdgeWindows, tableEdgeSources, tableEdgeEvents} {
		if out, err := chExec(base, fmt.Sprintf("SELECT engine FROM system.tables WHERE database = '%s' AND name = '%s' FORMAT TabSeparated", db, table)); err != nil || out != "MergeTree" {
			t.Fatalf("table %s: engine %q err %v, want MergeTree", table, out, err)
		}
	}

	// 2. A table created before a column existed gains it on the next start.
	if _, err := chExec(base, fmt.Sprintf("ALTER TABLE %s.%s DROP COLUMN top_asns", db, tableAttacks)); err != nil {
		t.Fatal(err)
	}
	if err := w.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if out, _ := chExec(base, fmt.Sprintf("SELECT count() FROM system.columns WHERE database = '%s' AND table = '%s' AND name = 'top_asns' FORMAT TabSeparated", db, tableAttacks)); out != "1" {
		t.Fatalf("top_asns after the upgrade pass: %q columns, want 1", out)
	}

	// 3. Every table takes its rows through the writer.
	wctx, cancel := context.WithCancel(ctx)
	w.Start(wctx)
	now := time.Now().UTC().Truncate(time.Second)
	at := now.Format(chDateTime)
	// Fresh timestamps everywhere a row must survive: ClickHouse filters rows
	// whose TTL has already expired while writing the part, so the fixtures'
	// June dates would land as nothing (and did, on the first run of this
	// suite).
	attack := sampleAttack()
	attack.EventTime = at
	w.WriteAttack(attack)
	w.WriteTraffic([]TrafficRow{{TS: at, Scope: "host", Key: "203.0.113.20", Group: "global", PPS: 1000}})
	audit := sampleAudit()
	audit.EventTime = at
	w.WriteAudit(audit)
	stale := now.Add(-time.Duration(cfg.TTLDays+1) * 24 * time.Hour).Format(chDateTime)
	w.WriteEdgeWindows([]EdgeWindowRow{
		{TS: at, ReceivedAt: at, WindowSeconds: 10, Zone: "shop.example", Node: "e1", Challenge: "auto", Requests: 400, Decided: 400, WouldDeny: 3, WouldChallenge: 12, Status2xx: 380, H3Requests: 7},
		{TS: now.Add(-10 * time.Second).Format(chDateTime), ReceivedAt: at, WindowSeconds: 10, Zone: "shop.example", Node: "e2", Challenge: "auto", Requests: 100, Decided: 100, Status2xx: 100},
		{TS: stale, ReceivedAt: at, WindowSeconds: 10, Zone: "shop.example", Node: "e1", Requests: 1},
	})
	w.WriteEdgeSources([]EdgeSourceRow{
		{TS: at, Zone: "shop.example", Node: "e1", Source: "203.0.113.9", State: "would-deny", Requests: 200, RPS: 20},
		{TS: now.Add(-10 * time.Second).Format(chDateTime), Zone: "shop.example", Node: "e2", Source: "203.0.113.9", State: "would-challenge", Requests: 50, RPS: 5},
		{TS: at, Zone: "shop.example", Node: "e1", Source: "198.51.100.7", State: "denied", Requests: 10, RPS: 1},
	})
	w.WriteEdgeEvent(EdgeEventRow{EventTime: now.Add(-time.Minute).Format(chDateTime), Node: "e1", Kind: "node_alive"})
	w.WriteEdgeEvent(EdgeEventRow{EventTime: at, Node: "e1", Zone: "shop.example", Kind: "cert_renewed", Detail: "not_after=2026-12-01T00:00:00Z"})
	cancel()
	w.Stop()
	// 4. The TTL holds: the window older than ttl_days never lands (expired
	// rows are filtered as the part is written — three were sent, two exist),
	// and a merge keeps it that way.
	for table, want := range map[string]int{tableAttacks: 1, tableTraffic: 1, tableAudit: 1, tableEdgeWindows: 2, tableEdgeSources: 3, tableEdgeEvents: 2} {
		if got := chCount(t, base, db, table); got != want {
			t.Fatalf("%s rows = %d, want %d", table, got, want)
		}
	}
	if out, err := chExec(base, fmt.Sprintf("SELECT count() FROM %s.%s WHERE ts < now() - INTERVAL %d DAY FORMAT TabSeparated", db, tableEdgeWindows, cfg.TTLDays)); err != nil || out != "0" {
		t.Fatalf("a window older than ttl_days survived: %q %v", out, err)
	}
	if _, err := chExec(base, fmt.Sprintf("OPTIMIZE TABLE %s.%s FINAL", db, tableEdgeWindows)); err != nil {
		t.Fatal(err)
	}
	if got := chCount(t, base, db, tableEdgeWindows); got != 2 {
		t.Fatalf("edge_windows after OPTIMIZE FINAL = %d, want 2", got)
	}

	// 5. The read client cannot write: readonly=2 is enforced by the server.
	q := NewQuerier(cfg, log).(*ClickHouse)
	params := edgeReadParams(10)
	if _, err := q.queryRaw(ctx, fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow {\"event_time\":\"%s\",\"node\":\"x\",\"kind\":\"node_alive\"}", db, tableEdgeEvents, at), params); err == nil {
		t.Fatal("an INSERT through the read client succeeded; readonly=2 is not enforced")
	}
	if got := chCount(t, base, db, tableEdgeEvents); got != 2 {
		t.Fatalf("edge_events after the refused insert = %d, want 2", got)
	}

	// 6. The three queries answer in the documented shapes.
	from, to := now.Add(-time.Hour), now.Add(time.Minute)
	hist, err := q.QueryEdgeHistory(ctx, "shop.example", "", from, to, 3600)
	if err != nil {
		t.Fatalf("QueryEdgeHistory: %v", err)
	}
	if len(hist) != 1 || hist[0].Nodes != 2 || hist[0].Requests != 500 || hist[0].WindowSeconds != 20 || hist[0].WouldChallenge != 12 || hist[0].H3Requests != 7 || hist[0].Status2xx != 480 {
		t.Fatalf("history: %+v", hist)
	}
	one, err := q.QueryEdgeHistory(ctx, "shop.example", "e2", from, to, 3600)
	if err != nil || len(one) != 1 || one[0].Nodes != 1 || one[0].Requests != 100 {
		t.Fatalf("history for e2: %+v %v", one, err)
	}
	srcs, err := q.QueryEdgeSources(ctx, EdgeSourceFilter{Zone: "shop.example", From: from, To: to})
	if err != nil {
		t.Fatalf("QueryEdgeSources: %v", err)
	}
	if len(srcs) != 2 || srcs[0].Source != "203.0.113.9" || srcs[0].State != "would-deny" || srcs[0].Requests != 250 || srcs[0].Windows != 2 || srcs[0].Nodes != 2 ||
		srcs[1].Source != "198.51.100.7" || srcs[1].State != "denied" || srcs[0].FirstSeen == "" || srcs[0].LastSeen < srcs[0].FirstSeen {
		t.Fatalf("sources: %+v", srcs)
	}
	denied, err := q.QueryEdgeSources(ctx, EdgeSourceFilter{Zone: "shop.example", State: "denied", From: from, To: to})
	if err != nil || len(denied) != 1 || denied[0].Source != "198.51.100.7" {
		t.Fatalf("denied sources: %+v %v", denied, err)
	}
	evs, err := q.QueryEdgeEvents(ctx, EdgeEventFilter{From: from, To: to})
	if err != nil {
		t.Fatalf("QueryEdgeEvents: %v", err)
	}
	if len(evs) != 2 || evs[0].Kind != "cert_renewed" || evs[0].Zone != "shop.example" || evs[1].Kind != "node_alive" || evs[1].Zone != "" {
		t.Fatalf("events (newest first): %+v", evs)
	}
	if only, err := q.QueryEdgeEvents(ctx, EdgeEventFilter{Kind: "node_alive", From: from, To: to}); err != nil || len(only) != 1 {
		t.Fatalf("events by kind: %+v %v", only, err)
	}
	// Nothing about a zone nobody wrote.
	if none, err := q.QueryEdgeHistory(ctx, "nobody.example", "", from, to, 60); err != nil || len(none) != 0 {
		t.Fatalf("history for an unknown zone: %+v %v", none, err)
	}
}

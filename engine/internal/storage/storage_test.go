package storage

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// recorder captures every request ClickHouse would receive.
type recorder struct {
	mu     sync.Mutex
	ddl    []string
	insert map[string][]string // table -> JSON rows (newline-split)
	status int                 // response status to return (default 200)
}

func newRecorder() *recorder { return &recorder{insert: map[string][]string{}, status: 200} }

func (r *recorder) server(t *testing.T) (*httptest.Server, config.StorageSettings) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		q := req.URL.Query().Get("query")
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.status != 200 {
			w.WriteHeader(r.status)
			_, _ = w.Write([]byte("boom"))
			return
		}
		switch {
		case strings.HasPrefix(strings.TrimSpace(string(body)), "CREATE"):
			r.ddl = append(r.ddl, strings.TrimSpace(string(body)))
		case strings.HasPrefix(q, "INSERT INTO"):
			// query is "INSERT INTO db.table FORMAT JSONEachRow"
			table := strings.Fields(q)[2]
			if i := strings.IndexByte(table, '.'); i >= 0 {
				table = table[i+1:] // strip the database prefix
			}
			for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				if line != "" {
					r.insert[table] = append(r.insert[table], line)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	cfg := config.StorageSettings{
		Enabled: true, URL: srv.URL, Database: "kapkan",
		TTLDays: 7, BatchSize: 100, QueueSize: 1000,
		FlushInterval: 20 * time.Millisecond, TrafficInterval: time.Second,
	}
	return srv, cfg
}

func (r *recorder) inserts(table string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.insert[table]...)
}

func sampleAttack() AttackRow {
	return AttackRow{
		EventTime: "2026-06-13 12:00:00", Kind: "attack_started", Scope: "host",
		Target: "203.0.113.20", Group: "global", Direction: "incoming",
		AttackType: "ntp_amplification", Metric: "pps", Rate: 200000, Threshold: 80000,
		PPS: 200000, DryRun: 1, TopSources: "198.51.100.7",
	}
}

func TestSchemaInitAndInsert(t *testing.T) {
	rec := newRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()

	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)

	// Schema DDL issued on Start: database + two tables, each with a TTL.
	rec.mu.Lock()
	ddl := strings.Join(rec.ddl, "\n")
	rec.mu.Unlock()
	for _, want := range []string{"CREATE DATABASE IF NOT EXISTS kapkan", "attack_events", "traffic", "TTL", "INTERVAL 7 DAY"} {
		if !strings.Contains(ddl, want) {
			t.Errorf("schema DDL missing %q:\n%s", want, ddl)
		}
	}

	w.WriteAttack(sampleAttack())
	w.WriteTraffic([]TrafficRow{{TS: "2026-06-13 12:00:00", Scope: "host", Key: "203.0.113.20", PPS: 1000}})

	// Wait for the flush interval to fire.
	waitFor(t, func() bool { return len(rec.inserts("attack_events")) == 1 && len(rec.inserts("traffic")) == 1 })

	got := rec.inserts("attack_events")[0]
	for _, want := range []string{`"target":"203.0.113.20"`, `"attack_type":"ntp_amplification"`, `"dry_run":1`} {
		if !strings.Contains(got, want) {
			t.Errorf("attack row missing %q: %s", want, got)
		}
	}
	// JSONEachRow framing: every emitted line must be a standalone valid
	// JSON object (one object per line, newline-delimited).
	for _, table := range []string{"attack_events", "traffic"} {
		for _, line := range rec.inserts(table) {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Errorf("%s line is not valid standalone JSON: %q (%v)", table, line, err)
			}
		}
	}
	cancel()
	w.Stop()
}

func TestBatchSizeFlush(t *testing.T) {
	rec := newRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	cfg.BatchSize = 5
	cfg.FlushInterval = time.Hour // only the batch-size path can fire

	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	defer func() { cancel(); w.Stop() }()

	for i := 0; i < 5; i++ {
		w.WriteAttack(sampleAttack())
	}
	waitFor(t, func() bool { return len(rec.inserts("attack_events")) == 5 })
}

func TestDropOnFullQueue(t *testing.T) {
	rec := newRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	// Tiny queue, no consumer started yet: every enqueue past capacity drops.
	cfg.QueueSize = 2
	cfg.BatchSize = 2

	w := NewWriter(cfg, discardLogger()).(*ClickHouse)
	before := testutil.ToFloat64(metrics.StorageRowsTotal.WithLabelValues("attack_events", "dropped"))
	// Do NOT Start: the queue never drains, so writes past QueueSize drop
	// instead of blocking — the property that protects detection.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			w.WriteAttack(sampleAttack())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WriteAttack blocked on a full queue; storage must never block the caller")
	}
	// 1000 writes, queue capacity 2: the overflow must be counted as dropped.
	dropped := testutil.ToFloat64(metrics.StorageRowsTotal.WithLabelValues("attack_events", "dropped")) - before
	if dropped < 900 {
		t.Errorf("dropped counter rose by %v, want ~998 (1000 writes, queue 2)", dropped)
	}
}

func TestFlushOnShutdown(t *testing.T) {
	rec := newRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	cfg.FlushInterval = time.Hour // force the shutdown-drain path, not the ticker

	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	w.WriteAttack(sampleAttack())
	w.WriteAttack(sampleAttack())

	cancel() // triggers drain + flushFinal
	w.Stop()
	if got := len(rec.inserts("attack_events")); got != 2 {
		t.Errorf("rows flushed on shutdown = %d, want 2", got)
	}
}

func TestInsertErrorDoesNotBlock(t *testing.T) {
	rec := newRecorder()
	rec.status = 500 // ClickHouse rejects everything
	srv, cfg := rec.server(t)
	defer srv.Close()

	w := NewWriter(cfg, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)
	for i := 0; i < 10; i++ {
		w.WriteAttack(sampleAttack())
	}
	// A failing ClickHouse must not wedge the writer; shutdown still returns.
	done := make(chan struct{})
	go func() { cancel(); w.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not shut down with a failing ClickHouse")
	}
}

func TestDisabledIsNoop(t *testing.T) {
	w := NewWriter(config.StorageSettings{Enabled: false}, discardLogger())
	if _, ok := w.(noop); !ok {
		t.Fatalf("disabled storage = %T, want noop", w)
	}
	// No-op methods must be safe to call without Start.
	w.WriteAttack(sampleAttack())
	w.WriteTraffic([]TrafficRow{{}})
	w.Start(context.Background())
	w.Stop()
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// waitFor polls cond until true or a timeout fails the test.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

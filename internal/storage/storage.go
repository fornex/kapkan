// Package storage persists attack events and periodic traffic snapshots to
// ClickHouse for forensics and reporting ("what hit us last Tuesday").
//
// It talks to ClickHouse over its HTTP interface using only the standard
// library — no driver dependency. Persistence is strictly best-effort and
// decoupled from detection: callers enqueue rows on a bounded buffer with a
// non-blocking send, so a slow or down ClickHouse drops rows (counted in a
// metric) instead of ever stalling the engine, the event loop, or ingest.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// Writer persists rows. The no-op implementation is used when storage is
// disabled, so callers never need a nil check.
type Writer interface {
	WriteAttack(AttackRow)
	WriteTraffic([]TrafficRow)
	Start(ctx context.Context)
	Stop()
}

// AttackRow is one attack lifecycle event persisted to the attack_events
// table. JSON field names are the ClickHouse column names (JSONEachRow).
type AttackRow struct {
	EventTime  string  `json:"event_time"` // "2006-01-02 15:04:05" UTC
	Kind       string  `json:"kind"`       // attack_started | attack_ended
	Scope      string  `json:"scope"`
	Target     string  `json:"target"`
	Group      string  `json:"group"`
	Direction  string  `json:"direction"`
	AttackType string  `json:"attack_type"`
	Metric     string  `json:"metric"`
	Rate       float64 `json:"rate"`
	Threshold  float64 `json:"threshold"`
	PPS        float64 `json:"pps"`
	Mbps       float64 `json:"mbps"`
	FlowsPS    float64 `json:"flows_per_sec"`
	BanState   string  `json:"ban_state"`
	DryRun     uint8   `json:"dry_run"`
	TopSources string  `json:"top_sources"` // comma-joined for quick reading
}

// TrafficRow is one per-host or per-group rate snapshot persisted to the
// traffic table.
type TrafficRow struct {
	TS          string  `json:"ts"`
	Scope       string  `json:"scope"` // currently always "host" ("group" reserved)
	Key         string  `json:"key"`   // address (or group name, reserved)
	Group       string  `json:"group"`
	PPS         float64 `json:"pps"`
	Mbps        float64 `json:"mbps"`
	FlowsPS     float64 `json:"flows_per_sec"`
	InAttack    uint8   `json:"in_attack"`
	BaselinePPS float64 `json:"baseline_pps"`
}

// table names (validated-charset database is from config).
const (
	tableAttacks = "attack_events"
	tableTraffic = "traffic"
)

// pending is a marshaled row tagged with its destination table.
type pending struct {
	table string
	json  []byte
}

// doer is the HTTP seam; tests substitute a recorder.
type doer interface {
	Do(*http.Request) (*http.Response, error)
}

// ClickHouse is the HTTP-interface writer.
type ClickHouse struct {
	cfg  config.StorageSettings
	log  *slog.Logger
	http doer
	user string
	pass string

	queue chan pending
	wg    sync.WaitGroup
}

// NewWriter builds a Writer from the resolved settings. When storage is
// disabled it returns a no-op so the app wiring is unconditional.
func NewWriter(cfg config.StorageSettings, log *slog.Logger) Writer {
	if !cfg.Enabled {
		return noop{}
	}
	ch := &ClickHouse{
		cfg:   cfg,
		log:   log.With("component", "storage"),
		http:  &http.Client{Timeout: 30 * time.Second},
		queue: make(chan pending, cfg.QueueSize),
	}
	if cfg.UsernameEnv != "" {
		ch.user = os.Getenv(cfg.UsernameEnv)
	}
	if cfg.PasswordEnv != "" {
		ch.pass = os.Getenv(cfg.PasswordEnv)
	}
	return ch
}

// Start creates the schema (best-effort) and launches the flush loop.
func (c *ClickHouse) Start(ctx context.Context) {
	if err := c.ensureSchema(ctx); err != nil {
		c.log.Error("clickhouse schema init failed; persistence may not work", "err", err)
	}
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.run(ctx) }()
}

// Stop drains and flushes the queue, then waits for the flush loop to exit.
func (c *ClickHouse) Stop() { c.wg.Wait() }

// WriteAttack enqueues one attack event. Non-blocking: a full queue drops
// the row and increments a metric rather than stalling the caller.
func (c *ClickHouse) WriteAttack(r AttackRow) {
	c.enqueue(tableAttacks, r)
}

// WriteTraffic enqueues a batch of traffic rows.
func (c *ClickHouse) WriteTraffic(rows []TrafficRow) {
	for i := range rows {
		c.enqueue(tableTraffic, rows[i])
	}
}

func (c *ClickHouse) enqueue(table string, row any) {
	b, err := json.Marshal(row)
	if err != nil {
		metrics.StorageRowsTotal.WithLabelValues(table, "error").Inc()
		return
	}
	select {
	case c.queue <- pending{table: table, json: b}:
	default:
		metrics.StorageRowsTotal.WithLabelValues(table, "dropped").Inc()
	}
}

// run batches queued rows by table and flushes on size or interval. It
// drains the queue on ctx cancellation so a clean shutdown loses nothing
// already enqueued.
func (c *ClickHouse) run(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.FlushInterval)
	defer ticker.Stop()
	batch := make(map[string][][]byte)
	n := 0
	flush := func() {
		if n == 0 {
			return
		}
		for table, rows := range batch {
			c.send(ctx, table, rows)
		}
		batch = make(map[string][][]byte)
		n = 0
	}
	for {
		select {
		case <-ctx.Done():
			// Drain whatever is already queued, then flush and exit.
			for draining := true; draining; {
				select {
				case p := <-c.queue:
					batch[p.table] = append(batch[p.table], p.json)
					n++
				default:
					draining = false
				}
			}
			c.flushFinal(batch)
			return
		case p := <-c.queue:
			batch[p.table] = append(batch[p.table], p.json)
			n++
			if n >= c.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flushFinal sends remaining batches during shutdown with a fresh bounded
// context (the run context is already cancelled).
func (c *ClickHouse) flushFinal(batch map[string][][]byte) {
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for table, rows := range batch {
		c.send(ctx, table, rows)
	}
}

// send POSTs one table's rows as JSONEachRow. Errors are logged and counted;
// the batch is dropped (best-effort) so a failing ClickHouse never backs up.
func (c *ClickHouse) send(ctx context.Context, table string, rows [][]byte) {
	if len(rows) == 0 {
		return
	}
	var body bytes.Buffer
	for _, r := range rows {
		body.Write(r)
		body.WriteByte('\n')
	}
	q := url.Values{}
	q.Set("query", fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", c.cfg.Database, table))
	endpoint := c.cfg.URL + "/?" + q.Encode()

	if err := c.post(ctx, endpoint, &body); err != nil {
		metrics.StorageRowsTotal.WithLabelValues(table, "error").Add(float64(len(rows)))
		c.log.Warn("clickhouse insert failed", "table", table, "rows", len(rows), "err", err)
		return
	}
	metrics.StorageRowsTotal.WithLabelValues(table, "written").Add(float64(len(rows)))
}

// ensureSchema creates the database and tables (idempotent). MergeTree with
// a per-row TTL keeps retention bounded without operator intervention.
func (c *ClickHouse) ensureSchema(ctx context.Context) error {
	stmts := []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", c.cfg.Database),
		// `group` and `key` are backtick-quoted: they are soft keywords in
		// ClickHouse and quoting keeps the DDL valid across versions.
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"event_time DateTime, kind LowCardinality(String), scope LowCardinality(String), "+
			"target String, `group` String, direction LowCardinality(String), "+
			"attack_type LowCardinality(String), metric LowCardinality(String), "+
			"rate Float64, threshold Float64, pps Float64, mbps Float64, flows_per_sec Float64, "+
			"ban_state LowCardinality(String), dry_run UInt8, top_sources String"+
			") ENGINE = MergeTree() ORDER BY (event_time, target) "+
			"TTL event_time + INTERVAL %d DAY", c.cfg.Database, tableAttacks, c.cfg.TTLDays),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"ts DateTime, scope LowCardinality(String), `key` String, `group` String, "+
			"pps Float64, mbps Float64, flows_per_sec Float64, in_attack UInt8, baseline_pps Float64"+
			") ENGINE = MergeTree() ORDER BY (ts, `key`) "+
			"TTL ts + INTERVAL %d DAY", c.cfg.Database, tableTraffic, c.cfg.TTLDays),
	}
	for _, s := range stmts {
		if err := c.post(ctx, c.cfg.URL+"/", bytes.NewBufferString(s)); err != nil {
			return fmt.Errorf("ddl: %w", err)
		}
	}
	return nil
}

// post sends one request to ClickHouse and treats non-2xx as an error,
// quoting the (bounded) response body so DDL/insert failures are diagnosable.
func (c *ClickHouse) post(ctx context.Context, endpoint string, body *bytes.Buffer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Bounded, deterministic read of the error body (a single Read may
		// short-read and truncate ClickHouse's "Code: ..." diagnostics).
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// noop is the disabled-storage Writer.
type noop struct{}

func (noop) WriteAttack(AttackRow)     {}
func (noop) WriteTraffic([]TrafficRow) {}
func (noop) Start(context.Context)     {}
func (noop) Stop()                     {}

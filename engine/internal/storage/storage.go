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
	"strings"
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
	WriteAudit(AuditRow)
	// The edge history (E6.4, edge_rows.go).
	WriteEdgeWindows([]EdgeWindowRow)
	WriteEdgeSources([]EdgeSourceRow)
	WriteEdgeEvent(EdgeEventRow)
	Start(ctx context.Context)
	Stop()
}

// Querier reads persisted history for the dashboard's Traffic/Reports view,
// the audit trail and the edge history. It is nil when storage is disabled
// (the API then reports history as unavailable rather than failing).
type Querier interface {
	QueryTraffic(ctx context.Context, key string, from, to time.Time, stepSec int) ([]TrafficPoint, error)
	QueryAudit(ctx context.Context, f AuditFilter) ([]AuditRow, error)
	// The edge history (E6.4, edge_rows.go).
	QueryEdgeHistory(ctx context.Context, zone, node string, from, to time.Time, stepSec int) ([]EdgeHistoryPoint, error)
	QueryEdgeSources(ctx context.Context, f EdgeSourceFilter) ([]EdgeSourceAgg, error)
	QueryEdgeEvents(ctx context.Context, f EdgeEventFilter) ([]EdgeEventRow, error)
}

// AuditFilter scopes an audit query. Tenant is bound server-side from the
// caller's scope ("" = unscoped admin, no tenant filter); Action/Target are
// optional. From/To bound the time window.
type AuditFilter struct {
	Tenant string
	Action string
	Target string
	From   time.Time
	To     time.Time
}

// TrafficPoint is one time-bucket of a host's persisted rates. JSON field
// names are the SELECT aliases (ClickHouse JSONEachRow).
type TrafficPoint struct {
	TS          string  `json:"ts"` // bucket start, "2006-01-02 15:04:05" UTC
	PPS         float64 `json:"pps"`
	Mbps        float64 `json:"mbps"`
	FlowsPS     float64 `json:"flows_per_sec"`
	InAttack    uint8   `json:"in_attack"`
	BaselinePPS float64 `json:"baseline_pps"`
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
	// Method is the mitigation method applied to this attack — "blackhole",
	// "flowspec", "divert", "dataplane", or "" for an alert-only stage.
	//
	// The column is LowCardinality(String) and NOT an Enum, which matters: an
	// Enum would have to list every method, and a release adding one (this one
	// added `dataplane`) would start failing every insert against a table created
	// by the previous release — silently dropping the attack history for exactly
	// the deployments running the newest mitigation. LowCardinality is a storage
	// encoding, not a constraint; unknown values cost nothing and insert fine.
	Method     string `json:"method"`
	DryRun     uint8  `json:"dry_run"`
	TopSources string `json:"top_sources"` // comma-joined for quick reading
	TopASNs    string `json:"top_asns"`    // pipe-joined "AS<n> <org>" (orgs may contain commas); empty when geoip off
	Reason     string `json:"reason"`      // compact JSON of the detection Reason (why it fired); empty on attack_ended
}

// AuditRow is one operator-attributed mutation persisted to the audit_events
// table — the answer to "who banned 10.0.5.7 at 03:14 and who reloaded config".
// JSON field names are the ClickHouse column names (JSONEachRow / SELECT alias).
type AuditRow struct {
	EventTime  string `json:"event_time"`  // "2006-01-02 15:04:05" UTC
	Action     string `json:"action"`      // ban | unban | config_reload | source_block | source_unblock
	Result     string `json:"result"`      // active | rejected | withdrawn | ok | error | blocked | removed
	Operator   string `json:"operator"`    // matched API token name ("" in open/token-less mode)
	Role       string `json:"role"`        // caller role
	Tenant     string `json:"tenant"`      // caller's scope ("" = unscoped admin); scopes reads
	Target     string `json:"target"`      // IP for ban/unban; "src->victim" for source_(un)block; empty for config_reload
	TargetType string `json:"target_type"` // host | global | source
	Reason     string `json:"reason"`      // rejection/error detail; empty on success
	Source     string `json:"source"`      // api (auto/reload reserved for engine-internal)
	BanState   string `json:"ban_state"`   // final ban state for ban/unban; empty for reload
	DryRun     uint8  `json:"dry_run"`     // 1 when the deployment is in dry-run
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
	tableAudit   = "audit_events"
	// chDateTime is ClickHouse's DateTime literal layout (UTC).
	chDateTime = "2006-01-02 15:04:05"
	// maxTrafficRows caps the read endpoint's result (SQL LIMIT + server-side
	// max_result_rows) so a wide range / tiny step can't return a huge payload.
	maxTrafficRows = 5001
	// maxAuditRows caps the audit read endpoint's result the same way.
	maxAuditRows = 1001
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

// NewQuerier builds a read-only ClickHouse client for the API's history
// endpoint. It returns nil when storage is disabled, so the API can report
// history as unavailable instead of erroring. No flush loop is started.
func NewQuerier(cfg config.StorageSettings, log *slog.Logger) Querier {
	if !cfg.Enabled {
		return nil
	}
	ch := &ClickHouse{
		cfg:  cfg,
		log:  log.With("component", "storage-read"),
		http: &http.Client{Timeout: 15 * time.Second},
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

// WriteAudit enqueues one audit event. Non-blocking, like WriteAttack.
func (c *ClickHouse) WriteAudit(r AuditRow) {
	c.enqueue(tableAudit, r)
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
	// Every flush sends on bounded contexts of its own, never on the run
	// context: that one is the STOP signal, and a cancel arriving while a batch
	// is in flight (or a size-triggered flush racing the shutdown) would
	// otherwise abort the POST with "context canceled" and lose rows that are
	// already ours — the real-ClickHouse suite caught exactly that. A hung
	// server costs this loop at most flushSendTimeout per table of a batch
	// (enqueue stays non-blocking and drops meanwhile, counted).
	flush := func() {
		if n == 0 {
			return
		}
		c.flushFinal(batch)
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

// flushSendTimeout bounds one table's INSERT; each table of a batch gets its
// own, so a slow first table never starves the later ones of their budget.
const flushSendTimeout = 10 * time.Second

// flushFinal sends a set of batches, each table on a fresh bounded context —
// every flush goes through here, so a cancelled run context (shutdown) never
// aborts a POST that is already carrying rows.
func (c *ClickHouse) flushFinal(batch map[string][][]byte) {
	for table, rows := range batch {
		ctx, cancel := context.WithTimeout(context.Background(), flushSendTimeout)
		c.send(ctx, table, rows)
		cancel()
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
			"ban_state LowCardinality(String), method LowCardinality(String), dry_run UInt8, "+
			"top_sources String, top_asns String, reason String"+
			") ENGINE = MergeTree() ORDER BY (event_time, target) "+
			"TTL event_time + INTERVAL %d DAY", c.cfg.Database, tableAttacks, c.cfg.TTLDays),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"ts DateTime, scope LowCardinality(String), `key` String, `group` String, "+
			"pps Float64, mbps Float64, flows_per_sec Float64, in_attack UInt8, baseline_pps Float64"+
			") ENGINE = MergeTree() ORDER BY (ts, `key`) "+
			"TTL ts + INTERVAL %d DAY", c.cfg.Database, tableTraffic, c.cfg.TTLDays),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"event_time DateTime, action LowCardinality(String), result LowCardinality(String), "+
			"operator String, role LowCardinality(String), tenant String, "+
			"target String, target_type LowCardinality(String), reason String, "+
			"source LowCardinality(String), ban_state LowCardinality(String), dry_run UInt8"+
			") ENGINE = MergeTree() ORDER BY (event_time, tenant) "+
			"TTL event_time + INTERVAL %d DAY", c.cfg.Database, tableAudit, c.cfg.TTLDays),
	}
	// Every statement is attempted: a credential that may INSERT but not
	// CREATE (the usual state after the first run) is refused on each CREATE
	// even when the object exists, and stopping at the first refusal would
	// skip the tables and column upgrades below that the same start could
	// still complete. The first failure is what the caller logs.
	var firstErr error
	for _, s := range stmts {
		if err := c.post(ctx, c.cfg.URL+"/", bytes.NewBufferString(s)); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("ddl: %w", err)
			}
			c.log.Warn("clickhouse: core DDL statement refused (a credential that may INSERT but not CREATE sees this on every start; harmless once the tables exist)", "ddl", ddlHead(s), "err", err)
		}
	}
	// The edge history's tables (E6.4) come AFTER the core loop and each on
	// its own: a writer credential from before them may lack CREATE, and the
	// three tables a deployment always had must not be held hostage by the
	// three new ones — so a failure here is logged, never returned.
	for _, t := range edgeSchema(c.cfg.Database, c.cfg.TTLDays) {
		if err := c.post(ctx, c.cfg.URL+"/", bytes.NewBufferString(t.ddl)); err != nil {
			c.log.Warn("clickhouse: edge history table not created (the core tables are unaffected; grant CREATE or create it by hand)", "table", t.table, "err", err)
		}
	}
	// Best-effort upgrades: the columns a release added to a table an earlier
	// release created (CREATE ... IF NOT EXISTS never alters an existing
	// table). Outside the fail-fast loop for the same reason: fresh installs
	// already have them, so a failure here — e.g. a writer credential without
	// ALTER rights — must not fail schema init or block the other tables.
	for _, up := range schemaUpgrades {
		for _, col := range up.cols {
			alter := fmt.Sprintf("ALTER TABLE %s.%s ADD COLUMN IF NOT EXISTS %s", c.cfg.Database, up.table, col)
			if err := c.post(ctx, c.cfg.URL+"/", bytes.NewBufferString(alter)); err != nil {
				c.log.Warn("clickhouse: column upgrade skipped (fresh installs already have it)", "table", up.table, "column", col, "err", err)
			}
		}
	}
	return firstErr
}

// ddlHead is the statement up to its column list, for a log line.
func ddlHead(s string) string {
	if i := strings.IndexByte(s, '('); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// schemaUpgrades lists, per table, the columns added after the table's first
// release — applied with ADD COLUMN IF NOT EXISTS on every start. A new
// column on any table goes here as well as into its CREATE.
var schemaUpgrades = []struct {
	table string
	cols  []string
}{
	{tableAttacks, []string{"top_asns String", "reason String", "method LowCardinality(String)"}},
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

// QueryTraffic returns a host's persisted rates bucketed into stepSec windows
// between from and to. key is bound as a query parameter (no SQL injection);
// stepSec is clamped and embedded as an integer literal.
func (c *ClickHouse) QueryTraffic(ctx context.Context, key string, from, to time.Time, stepSec int) ([]TrafficPoint, error) {
	if stepSec < 1 {
		stepSec = 60
	}
	if stepSec > 86400 {
		stepSec = 86400
	}
	// The key and range filters sit on the base rows in a subquery: the outer
	// SELECT aliases the bucket `ts`, and a `ts BETWEEN` beside it would be
	// read as the bucket start (the E6.4 review found this on the edge twin of
	// this query: the first partly covered bucket lost every row, the last
	// admitted rows past `to`). GROUP BY ts is the alias, by the pinned rule.
	sql := fmt.Sprintf("SELECT toStartOfInterval(ts, INTERVAL %d SECOND) AS ts, "+
		"avg(pps) AS pps, avg(mbps) AS mbps, avg(flows_per_sec) AS flows_per_sec, "+
		"max(in_attack) AS in_attack, avg(baseline_pps) AS baseline_pps "+
		"FROM (SELECT ts, pps, mbps, flows_per_sec, in_attack, baseline_pps FROM %s.%s "+
		"WHERE `key` = {key:String} AND ts BETWEEN {from:DateTime} AND {to:DateTime}) "+
		"GROUP BY ts ORDER BY ts LIMIT %d FORMAT JSONEachRow",
		stepSec, c.cfg.Database, tableTraffic, maxTrafficRows)
	params := url.Values{}
	params.Set("param_key", key)
	params.Set("param_from", from.UTC().Format(chDateTime))
	params.Set("param_to", to.UTC().Format(chDateTime))
	// Read-path hardening: enforce read-only at the protocol level (the shared
	// credential cannot write/DDL through this client), cap server-side cost,
	// and pin the alias rule the GROUP BY is written for (see edgeReadParams).
	params.Set("readonly", "2")
	params.Set("max_execution_time", "10")
	params.Set("max_result_rows", fmt.Sprintf("%d", maxTrafficRows))
	params.Set("result_overflow_mode", "throw")
	params.Set("prefer_column_name_to_alias", "0")
	body, err := c.queryRaw(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	var out []TrafficPoint
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var p TrafficPoint
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("decode traffic row: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}

// QueryAudit reads audit rows matching f, newest first. Tenant/Action/Target
// are optional filters bound via param_* (a scoped caller's tenant is bound
// server-side; an empty tenant means no tenant filter — unscoped admin).
func (c *ClickHouse) QueryAudit(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	where := "event_time BETWEEN {from:DateTime} AND {to:DateTime}"
	params := url.Values{}
	params.Set("param_from", f.From.UTC().Format(chDateTime))
	params.Set("param_to", f.To.UTC().Format(chDateTime))
	if f.Tenant != "" {
		where += " AND tenant = {tenant:String}"
		params.Set("param_tenant", f.Tenant)
	}
	if f.Action != "" {
		where += " AND action = {action:String}"
		params.Set("param_action", f.Action)
	}
	if f.Target != "" {
		where += " AND target = {target:String}"
		params.Set("param_target", f.Target)
	}
	sql := fmt.Sprintf("SELECT event_time, action, result, operator, role, tenant, target, "+
		"target_type, reason, source, ban_state, dry_run "+
		"FROM %s.%s WHERE %s ORDER BY event_time DESC LIMIT %d FORMAT JSONEachRow",
		c.cfg.Database, tableAudit, where, maxAuditRows)
	params.Set("readonly", "2")
	params.Set("max_execution_time", "10")
	params.Set("max_result_rows", fmt.Sprintf("%d", maxAuditRows))
	params.Set("result_overflow_mode", "throw")
	body, err := c.queryRaw(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	var out []AuditRow
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var row AuditRow
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("decode audit row: %w", err)
		}
		out = append(out, row)
	}
	return out, nil
}

// queryRaw POSTs a read query (params bound via param_* in the URL) and
// returns the raw response body. Read path only.
func (c *ClickHouse) queryRaw(ctx context.Context, sql string, params url.Values) ([]byte, error) {
	endpoint := c.cfg.URL + "/?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(sql))
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		trunc := body
		if len(trunc) > 512 {
			trunc = trunc[:512]
		}
		return nil, fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, bytes.TrimSpace(trunc))
	}
	return body, nil
}

// noop is the disabled-storage Writer.
type noop struct{}

func (noop) WriteAttack(AttackRow)     {}
func (noop) WriteTraffic([]TrafficRow) {}
func (noop) WriteAudit(AuditRow)       {}
func (noop) Start(context.Context)     {}
func (noop) Stop()                     {}

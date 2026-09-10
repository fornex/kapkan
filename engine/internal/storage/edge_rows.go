package storage

// Edge history (edge-spec §8, milestone E6.4): three tables the brain fills
// from the edge nodes' advisory reports (E6.5) and the console reads (E6.6) —
// the answer to "who would have been challenged last Tuesday", per zone, over
// time, once the ten-second live window has scrolled away.
//
// Shape decisions, from the E6 design round: raw ten-second windows in a flat
// MergeTree, bucketed on READ with toStartOfInterval exactly like `traffic`
// (D13 — no compaction on the brain, no second engine); no tenant column —
// ownership is read from the live zones file at query time, one truth (D12);
// only the TELLING sources are kept (denied, challenged, would-deny,
// would-challenge), at most EdgeSourcesPerWindow per (node, zone, window) —
// a tenant's ordinary visitors are never stored (D14); `ts` is the node's
// window close, gated by the brain (D11), `received_at` the brain's clock,
// always. No rps column: it is sum(requests)/sum(window_seconds). Every row
// is a CLAIM, like the report it came from; the brain sums, never acts on it.
//
// Package conventions hold: MergeTree with a per-row TTL from ttl_days,
// LowCardinality(String) for the enum-like columns (never an Enum — a value a
// release adds must not fail the inserts of every older table), CREATE IF NOT
// EXISTS run AFTER the core tables' fail-fast loop and each logged on its own,
// so an upgrade whose writer credential lacks CREATE keeps the three tables it
// always had. Read queries bind every caller value through param_*, run with
// readonly=2, a server-side time and row cap, and a LIMIT.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

const (
	tableEdgeWindows = "edge_windows"
	tableEdgeSources = "edge_sources"
	tableEdgeEvents  = "edge_events"

	// The read caps: history buckets like traffic's, the source and event
	// lists like audit's (one over the documented limit, so a consumer can
	// tell "full" from "more").
	maxEdgeHistoryRows = 5001
	maxEdgeSourceRows  = 1001
	maxEdgeEventRows   = 1001

	// EdgeSourcesPerWindow bounds edge_sources: the most telling sources one
	// (node, zone, window) may store. The brain enforces it (E6.5); the
	// aggregator's top-N is the same number, so more cannot be known anyway.
	EdgeSourcesPerWindow = 20
)

// EdgeWindowRow is one node's closed rollup window for one zone, as reported.
// JSON field names are the ClickHouse column names (JSONEachRow).
type EdgeWindowRow struct {
	// TS is the window's close by the node's clock when the brain accepted it
	// (D11), else the brain's; ReceivedAt is always the brain's clock. Both
	// "2006-01-02 15:04:05" UTC.
	TS            string  `json:"ts"`
	ReceivedAt    string  `json:"received_at"`
	WindowSeconds float64 `json:"window_seconds"`
	Zone          string  `json:"zone"`
	Node          string  `json:"node"`
	// Challenge is the zone's challenge mode as the node applied it (off,
	// manual, auto); DryRun / RungDryRun the zone's and the rung's watch-only
	// state on that node; ChallengeActive whether a zone-wide challenge was
	// in force, with its reason.
	Challenge       string `json:"challenge"`
	DryRun          uint8  `json:"dry_run"`
	RungDryRun      uint8  `json:"rung_dry_run"`
	ChallengeActive uint8  `json:"challenge_active"`
	ChallengeReason string `json:"challenge_reason"`
	// The window's counters, verbatim from the report.
	Requests       uint64 `json:"requests"`
	Decided        uint64 `json:"decided"`
	Denied         uint64 `json:"denied"`
	Challenged     uint64 `json:"challenged"`
	Cleared        uint64 `json:"cleared"`
	WouldDeny      uint64 `json:"would_deny"`
	WouldChallenge uint64 `json:"would_challenge"`
	Status2xx      uint64 `json:"status_2xx"`
	Status3xx      uint64 `json:"status_3xx"`
	Status4xx      uint64 `json:"status_4xx"`
	Status5xx      uint64 `json:"status_5xx"`
	H3Requests     uint64 `json:"h3_requests"`
	// SourcesTruncated is the report's count of telling sources that did not
	// fit — so an edge_sources set short of this window's is "short", not
	// "nobody".
	SourcesTruncated uint32 `json:"sources_truncated"`
}

// EdgeSourceRow is one telling source of one window: what one node did to it.
type EdgeSourceRow struct {
	TS   string `json:"ts"`
	Zone string `json:"zone"`
	Node string `json:"node"`
	// Source is the accounting key (an IPv4 address or an IPv6 /64), checked
	// by the brain before it is written.
	Source string `json:"source"`
	// State is denied, challenged, would-deny or would-challenge — never
	// allow, cleared or marked (those are visitors, not findings).
	State    string  `json:"state"`
	Requests uint64  `json:"requests"`
	RPS      float64 `json:"rps"`
}

// EdgeEventRow is one transition the brain saw in a node's reports or
// presence (E6.5 lists the kinds: node_alive, node_lost, version, dry_run,
// document_rendered, generation_installed, generation_refused,
// terminator_alive, h3_state, cert_issued, cert_renewed, cert_gone,
// challenge_started, challenge_ended, clock_skew, report_truncated).
type EdgeEventRow struct {
	EventTime string `json:"event_time"`
	Node      string `json:"node"`
	// Zone is set for the zone-scoped kinds, empty for the node-wide ones.
	Zone string `json:"zone"`
	Kind string `json:"kind"`
	// Detail is the transition's short free text (a version, a generation
	// number, an h3 state, a certificate's expiry) — never key material.
	Detail string `json:"detail"`
}

// EdgeHistoryPoint is one read bucket of a zone's windows: the fleet's
// figures summed (each node's windows are not aligned, so a bucket is a rate
// to the nearest window), Nodes the distinct nodes that reported in it. The
// client derives rps as requests/window_seconds and the h3 share as
// h3_requests/requests.
type EdgeHistoryPoint struct {
	TS             string  `json:"ts"`
	Nodes          uint64  `json:"nodes"`
	WindowSeconds  float64 `json:"window_seconds"`
	Requests       uint64  `json:"requests"`
	Decided        uint64  `json:"decided"`
	Denied         uint64  `json:"denied"`
	Challenged     uint64  `json:"challenged"`
	Cleared        uint64  `json:"cleared"`
	WouldDeny      uint64  `json:"would_deny"`
	WouldChallenge uint64  `json:"would_challenge"`
	Status2xx      uint64  `json:"status_2xx"`
	Status3xx      uint64  `json:"status_3xx"`
	Status4xx      uint64  `json:"status_4xx"`
	Status5xx      uint64  `json:"status_5xx"`
	H3Requests     uint64  `json:"h3_requests"`
}

// EdgeSourceFilter scopes QueryEdgeSources: the zone (required; ownership is
// the caller's to check against the live zones file), an optional state and
// the time window.
type EdgeSourceFilter struct {
	Zone  string
	State string
	From  time.Time
	To    time.Time
}

// EdgeSourceAgg is one source over a range: the strongest state any node
// gave it, its requests summed, how many windows and distinct nodes saw it,
// and when — the §8 question "who would have been challenged" over a period
// rather than a ten-second window.
type EdgeSourceAgg struct {
	Source    string `json:"source"`
	State     string `json:"state"`
	Requests  uint64 `json:"requests"`
	Windows   uint64 `json:"windows"`
	Nodes     uint64 `json:"nodes"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// EdgeEventFilter scopes QueryEdgeEvents; every field but the window is
// optional.
type EdgeEventFilter struct {
	Node string
	Zone string
	Kind string
	From time.Time
	To   time.Time
}

// tableDDL is one table's CREATE statement, named so a failure can say which.
type tableDDL struct{ table, ddl string }

// edgeSchema is the DDL of the three edge tables for database db.
func edgeSchema(db string, ttlDays int) []tableDDL {
	return []tableDDL{
		{tableEdgeWindows, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"ts DateTime, received_at DateTime, window_seconds Float64, "+
			"zone LowCardinality(String), node LowCardinality(String), challenge LowCardinality(String), "+
			"dry_run UInt8, rung_dry_run UInt8, challenge_active UInt8, challenge_reason LowCardinality(String), "+
			"requests UInt64, decided UInt64, denied UInt64, challenged UInt64, cleared UInt64, "+
			"would_deny UInt64, would_challenge UInt64, "+
			"status_2xx UInt64, status_3xx UInt64, status_4xx UInt64, status_5xx UInt64, "+
			"h3_requests UInt64, sources_truncated UInt32"+
			") ENGINE = MergeTree() ORDER BY (zone, ts, node) "+
			"TTL ts + INTERVAL %d DAY", db, tableEdgeWindows, ttlDays)},
		{tableEdgeSources, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"ts DateTime, zone LowCardinality(String), node LowCardinality(String), "+
			"source String, state LowCardinality(String), requests UInt64, rps Float64"+
			") ENGINE = MergeTree() ORDER BY (zone, ts, source) "+
			"TTL ts + INTERVAL %d DAY", db, tableEdgeSources, ttlDays)},
		{tableEdgeEvents, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s.%s ("+
			"event_time DateTime, node LowCardinality(String), zone LowCardinality(String), "+
			"kind LowCardinality(String), detail String"+
			") ENGINE = MergeTree() ORDER BY (event_time, node) "+
			"TTL event_time + INTERVAL %d DAY", db, tableEdgeEvents, ttlDays)},
	}
}

// WriteEdgeWindows enqueues a report's closed windows. Non-blocking, like
// every writer here.
func (c *ClickHouse) WriteEdgeWindows(rows []EdgeWindowRow) {
	for i := range rows {
		c.enqueue(tableEdgeWindows, rows[i])
	}
}

// WriteEdgeSources enqueues a report's telling sources.
func (c *ClickHouse) WriteEdgeSources(rows []EdgeSourceRow) {
	for i := range rows {
		c.enqueue(tableEdgeSources, rows[i])
	}
}

// WriteEdgeEvent enqueues one transition.
func (c *ClickHouse) WriteEdgeEvent(r EdgeEventRow) {
	c.enqueue(tableEdgeEvents, r)
}

func (noop) WriteEdgeWindows([]EdgeWindowRow) {}
func (noop) WriteEdgeSources([]EdgeSourceRow) {}
func (noop) WriteEdgeEvent(EdgeEventRow)      {}

// edgeReadParams is the read-path hardening every edge query carries: the
// protocol-level read-only flag (the shared credential cannot write or DDL
// through this client), a server-side time cap, a row cap that throws rather
// than truncates, 64-bit integers as JSON numbers (ClickHouse quotes them by
// default, which the uint64 fields above would refuse), and the alias rule
// the queries are written for: a SELECT alias wins over a column of the same
// name (the server default, pinned here because it is a per-user profile
// setting — under the other value the bucket GROUP BY ts would group by the
// raw column and hand back one row per window, silently unbucketed).
func edgeReadParams(limit int) url.Values {
	params := url.Values{}
	params.Set("readonly", "2")
	params.Set("max_execution_time", "10")
	params.Set("max_result_rows", fmt.Sprintf("%d", limit))
	params.Set("result_overflow_mode", "throw")
	params.Set("output_format_json_quote_64bit_integers", "0")
	params.Set("prefer_column_name_to_alias", "0")
	return params
}

// decodeRows decodes a JSONEachRow body into a slice of T.
func decodeRows[T any](body []byte, what string) ([]T, error) {
	var out []T
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var row T
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("decode %s row: %w", what, err)
		}
		out = append(out, row)
	}
	return out, nil
}

// QueryEdgeHistory returns a zone's windows summed into stepSec buckets
// between from and to, across the fleet or for one node. zone and node are
// bound as parameters; stepSec is clamped like the traffic query's and
// embedded as an integer literal.
func (c *ClickHouse) QueryEdgeHistory(ctx context.Context, zone, node string, from, to time.Time, stepSec int) ([]EdgeHistoryPoint, error) {
	if stepSec < 1 {
		stepSec = 60
	}
	if stepSec > 86400 {
		stepSec = 86400
	}
	where := "zone = {zone:String} AND ts BETWEEN {from:DateTime} AND {to:DateTime}"
	params := edgeReadParams(maxEdgeHistoryRows)
	params.Set("param_zone", zone)
	params.Set("param_from", from.UTC().Format(chDateTime))
	params.Set("param_to", to.UTC().Format(chDateTime))
	if node != "" {
		where += " AND node = {node:String}"
		params.Set("param_node", node)
	}
	// The range and zone filters sit on the base rows in a subquery: the outer
	// SELECT aliases the bucket `ts`, and a `ts BETWEEN` in the same SELECT
	// would be read as the BUCKET start — dropping every window of a partly
	// covered first bucket and admitting windows past `to` (the real suite
	// pins both edges). The outer GROUP BY ts is the alias, by the pinned rule.
	sql := fmt.Sprintf("SELECT toStartOfInterval(ts, INTERVAL %d SECOND) AS ts, uniqExact(node) AS nodes, "+
		"sum(window_seconds) AS window_seconds, sum(requests) AS requests, sum(decided) AS decided, "+
		"sum(denied) AS denied, sum(challenged) AS challenged, sum(cleared) AS cleared, "+
		"sum(would_deny) AS would_deny, sum(would_challenge) AS would_challenge, "+
		"sum(status_2xx) AS status_2xx, sum(status_3xx) AS status_3xx, sum(status_4xx) AS status_4xx, sum(status_5xx) AS status_5xx, "+
		"sum(h3_requests) AS h3_requests "+
		"FROM (SELECT ts, node, window_seconds, requests, decided, denied, challenged, cleared, would_deny, would_challenge, "+
		"status_2xx, status_3xx, status_4xx, status_5xx, h3_requests FROM %s.%s WHERE %s) "+
		"GROUP BY ts ORDER BY ts LIMIT %d FORMAT JSONEachRow",
		stepSec, c.cfg.Database, tableEdgeWindows, where, maxEdgeHistoryRows)
	body, err := c.queryRaw(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	return decodeRows[EdgeHistoryPoint](body, "edge history")
}

// QueryEdgeSources aggregates a zone's telling sources over f's window: the
// strongest state any node gave a source wins (denied over challenged over
// would-deny over would-challenge), the busiest first.
func (c *ClickHouse) QueryEdgeSources(ctx context.Context, f EdgeSourceFilter) ([]EdgeSourceAgg, error) {
	where := "zone = {zone:String} AND ts BETWEEN {from:DateTime} AND {to:DateTime}"
	params := edgeReadParams(maxEdgeSourceRows)
	params.Set("param_zone", f.Zone)
	params.Set("param_from", f.From.UTC().Format(chDateTime))
	params.Set("param_to", f.To.UTC().Format(chDateTime))
	if f.State != "" {
		where += " AND state = {state:String}"
		params.Set("param_state", f.State)
	}
	// The filters sit on the base rows in a subquery: the outer SELECT names
	// its aggregate `state` after the column, and ClickHouse resolves a name
	// in an outer WHERE to the alias — an aggregate in WHERE (the real suite
	// caught it as ILLEGAL_AGGREGATION).
	sql := fmt.Sprintf("SELECT source, "+
		"argMax(state, multiIf(state = 'denied', 4, state = 'challenged', 3, state = 'would-deny', 2, 1)) AS state, "+
		"sum(requests) AS requests, count() AS windows, uniqExact(node) AS nodes, "+
		"min(ts) AS first_seen, max(ts) AS last_seen "+
		"FROM (SELECT source, state, requests, node, ts FROM %s.%s WHERE %s) "+
		"GROUP BY source ORDER BY requests DESC, source LIMIT %d FORMAT JSONEachRow",
		c.cfg.Database, tableEdgeSources, where, maxEdgeSourceRows)
	body, err := c.queryRaw(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	return decodeRows[EdgeSourceAgg](body, "edge source")
}

// QueryEdgeEvents reads the transitions matching f, newest first.
func (c *ClickHouse) QueryEdgeEvents(ctx context.Context, f EdgeEventFilter) ([]EdgeEventRow, error) {
	where := "event_time BETWEEN {from:DateTime} AND {to:DateTime}"
	params := edgeReadParams(maxEdgeEventRows)
	params.Set("param_from", f.From.UTC().Format(chDateTime))
	params.Set("param_to", f.To.UTC().Format(chDateTime))
	for _, opt := range []struct{ col, val string }{{"node", f.Node}, {"zone", f.Zone}, {"kind", f.Kind}} {
		if opt.val != "" {
			where += fmt.Sprintf(" AND %s = {%s:String}", opt.col, opt.col)
			params.Set("param_"+opt.col, opt.val)
		}
	}
	sql := fmt.Sprintf("SELECT event_time, node, zone, kind, detail FROM %s.%s WHERE %s "+
		"ORDER BY event_time DESC LIMIT %d FORMAT JSONEachRow",
		c.cfg.Database, tableEdgeEvents, where, maxEdgeEventRows)
	body, err := c.queryRaw(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	return decodeRows[EdgeEventRow](body, "edge event")
}

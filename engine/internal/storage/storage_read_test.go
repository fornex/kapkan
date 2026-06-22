package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// readRecorder captures every request the read path (queryRaw) sends to
// ClickHouse: the request body (the SQL), the URL query params (SQL parameter
// bindings + read-only hardening), and the auth headers. It returns a canned
// JSONEachRow body so decoding into []TrafficPoint / []AuditRow is exercised.
// It is the read-path analogue of the write-path `recorder` in storage_test.go.
type readRecorder struct {
	mu     sync.Mutex
	body   string     // last request body (the SQL)
	query  url.Values // last request URL query params
	header http.Header
	status int    // response status to return (default 200)
	resp   string // response body to return on a 2xx (canned JSONEachRow)
}

func newReadRecorder() *readRecorder { return &readRecorder{status: 200} }

func (r *readRecorder) server(t *testing.T) (*httptest.Server, config.StorageSettings) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.body = string(body)
		r.query = req.URL.Query()
		r.header = req.Header.Clone()
		status, resp := r.status, r.resp
		r.mu.Unlock()
		if status != 200 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("Code: 241. DB::Exception: Memory limit exceeded"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resp))
	}))
	cfg := config.StorageSettings{
		Enabled: true, URL: srv.URL, Database: "kapkan",
		TTLDays: 7, BatchSize: 100, QueueSize: 1000,
		FlushInterval: 20 * time.Millisecond, TrafficInterval: time.Second,
	}
	return srv, cfg
}

func (r *readRecorder) snapshot() (sql string, q url.Values, h http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body, r.query, r.header.Clone()
}

func querier(t *testing.T, cfg config.StorageSettings) *ClickHouse {
	t.Helper()
	q := NewQuerier(cfg, discardLogger())
	if q == nil {
		t.Fatal("NewQuerier returned nil for enabled storage")
	}
	ch, ok := q.(*ClickHouse)
	if !ok {
		t.Fatalf("NewQuerier returned %T, want *ClickHouse", q)
	}
	return ch
}

// TestQueryTrafficSQLAndDecode covers the generated traffic SQL (param binding,
// readonly=2, FORMAT JSONEachRow), the stepSec clamp embedded as an integer
// literal, the param_* time bindings, and the JSONEachRow decode into
// []TrafficPoint.
func TestQueryTrafficSQLAndDecode(t *testing.T) {
	rec := newReadRecorder()
	// Two newline-delimited JSONEachRow objects, the second has no trailing
	// newline — the decoder must still pick it up via dec.More().
	rec.resp = `{"ts":"2026-06-13 12:00:00","pps":1000,"mbps":8,"flows_per_sec":50,"in_attack":1,"baseline_pps":120.5}
{"ts":"2026-06-13 12:01:00","pps":2000.25,"mbps":16,"flows_per_sec":75,"in_attack":0,"baseline_pps":130}`
	srv, cfg := rec.server(t)
	defer srv.Close()

	ch := querier(t, cfg)
	from := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	to := time.Date(2026, 6, 13, 13, 0, 0, 0, time.UTC)

	out, err := ch.QueryTraffic(context.Background(), "203.0.113.20", from, to, 300)
	if err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}

	// Decode into []TrafficPoint.
	if len(out) != 2 {
		t.Fatalf("got %d points, want 2", len(out))
	}
	want0 := TrafficPoint{TS: "2026-06-13 12:00:00", PPS: 1000, Mbps: 8, FlowsPS: 50, InAttack: 1, BaselinePPS: 120.5}
	if out[0] != want0 {
		t.Errorf("point[0] = %+v, want %+v", out[0], want0)
	}
	want1 := TrafficPoint{TS: "2026-06-13 12:01:00", PPS: 2000.25, Mbps: 16, FlowsPS: 75, InAttack: 0, BaselinePPS: 130}
	if out[1] != want1 {
		t.Errorf("point[1] = %+v, want %+v", out[1], want1)
	}

	sql, q, _ := rec.snapshot()
	for _, want := range []string{
		"WHERE `key` = {key:String}",
		"ts BETWEEN {from:DateTime} AND {to:DateTime}",
		"INTERVAL 300 SECOND", // stepSec=300 embedded as integer literal
		"FROM kapkan.traffic",
		"GROUP BY ts ORDER BY ts",
		"LIMIT 5001",
		"FORMAT JSONEachRow",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("traffic SQL missing %q:\n%s", want, sql)
		}
	}
	// Parameters are bound via param_* (no SQL injection), times in UTC ClickHouse layout.
	assertParam(t, q, "param_key", "203.0.113.20")
	assertParam(t, q, "param_from", "2026-06-13 12:00:00")
	assertParam(t, q, "param_to", "2026-06-13 13:00:00")
	// Read-path hardening.
	assertParam(t, q, "readonly", "2")
	assertParam(t, q, "max_execution_time", "10")
	assertParam(t, q, "max_result_rows", "5001")
	assertParam(t, q, "result_overflow_mode", "throw")
}

// TestQueryTrafficStepClamp covers the stepSec clamping: <1 -> 60, >86400 ->
// 86400, and an in-range value passes through. The clamped value must appear
// verbatim as the INTERVAL literal in the SQL.
func TestQueryTrafficStepClamp(t *testing.T) {
	cases := []struct {
		name string
		step int
		want string
	}{
		{"zero clamps to 60", 0, "INTERVAL 60 SECOND"},
		{"negative clamps to 60", -5, "INTERVAL 60 SECOND"},
		{"one passes through", 1, "INTERVAL 1 SECOND"},
		{"in range passes through", 3600, "INTERVAL 3600 SECOND"},
		{"max passes through", 86400, "INTERVAL 86400 SECOND"},
		{"over max clamps to 86400", 90000, "INTERVAL 86400 SECOND"},
	}
	from := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := newReadRecorder() // empty resp -> zero rows decoded
			srv, cfg := rec.server(t)
			defer srv.Close()
			ch := querier(t, cfg)
			if _, err := ch.QueryTraffic(context.Background(), "h", from, to, tc.step); err != nil {
				t.Fatalf("QueryTraffic: %v", err)
			}
			sql, _, _ := rec.snapshot()
			if !strings.Contains(sql, tc.want) {
				t.Errorf("step %d: SQL missing %q:\n%s", tc.step, tc.want, sql)
			}
		})
	}
}

// TestQueryTrafficEmpty: a 2xx with no body decodes to an empty (nil) slice,
// not an error.
func TestQueryTrafficEmpty(t *testing.T) {
	rec := newReadRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)
	out, err := ch.QueryTraffic(context.Background(), "h", time.Now(), time.Now(), 60)
	if err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d points, want 0", len(out))
	}
}

// TestQueryAuditTenantFilter is the tenant-isolation guarantee: a scoped
// caller's tenant must produce both the `tenant = {tenant:String}` WHERE clause
// and the param_tenant binding the server receives. Action/Target filters are
// included here too to confirm dynamic WHERE construction and param_* binding,
// and the decode into []AuditRow is asserted.
func TestQueryAuditTenantFilter(t *testing.T) {
	rec := newReadRecorder()
	rec.resp = `{"event_time":"2026-06-13 12:00:00","action":"ban","result":"active","operator":"b-op","role":"operator","tenant":"custB","target":"203.0.113.70","target_type":"host","reason":"","source":"api","ban_state":"active","dry_run":1}`
	srv, cfg := rec.server(t)
	defer srv.Close()

	ch := querier(t, cfg)
	f := AuditFilter{
		Tenant: "custB",
		Action: "ban",
		Target: "203.0.113.70",
		From:   time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC),
		To:     time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC),
	}
	out, err := ch.QueryAudit(context.Background(), f)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}

	// Decode into []AuditRow.
	if len(out) != 1 {
		t.Fatalf("got %d rows, want 1", len(out))
	}
	want := AuditRow{
		EventTime: "2026-06-13 12:00:00", Action: "ban", Result: "active",
		Operator: "b-op", Role: "operator", Tenant: "custB",
		Target: "203.0.113.70", TargetType: "host", Reason: "", Source: "api",
		BanState: "active", DryRun: 1,
	}
	if out[0] != want {
		t.Errorf("row[0] = %+v, want %+v", out[0], want)
	}

	sql, q, _ := rec.snapshot()
	// Tenant isolation: the clause and the bound parameter must both be present.
	if !strings.Contains(sql, "tenant = {tenant:String}") {
		t.Errorf("audit SQL missing tenant clause:\n%s", sql)
	}
	assertParam(t, q, "param_tenant", "custB")
	// Other dynamic filters.
	for _, want := range []string{
		"event_time BETWEEN {from:DateTime} AND {to:DateTime}",
		"action = {action:String}",
		"target = {target:String}",
		"FROM kapkan.audit_events",
		"ORDER BY event_time DESC",
		"LIMIT 1001",
		"FORMAT JSONEachRow",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("audit SQL missing %q:\n%s", want, sql)
		}
	}
	assertParam(t, q, "param_action", "ban")
	assertParam(t, q, "param_target", "203.0.113.70")
	assertParam(t, q, "param_from", "2026-06-13 00:00:00")
	assertParam(t, q, "param_to", "2026-06-14 00:00:00")
	assertParam(t, q, "readonly", "2")
	assertParam(t, q, "max_result_rows", "1001")
}

// TestQueryAuditUnscopedAdmin: an empty Tenant ("" = unscoped admin) omits the
// tenant filter entirely — neither the clause nor param_tenant is present.
// This is the complement of the tenant-isolation test: it confirms an admin
// reads across tenants, while the absence of the clause when scoped would be a
// leak.
func TestQueryAuditUnscopedAdmin(t *testing.T) {
	rec := newReadRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)

	f := AuditFilter{From: time.Now().Add(-time.Hour), To: time.Now()}
	if _, err := ch.QueryAudit(context.Background(), f); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	sql, q, _ := rec.snapshot()
	if strings.Contains(sql, "{tenant:String}") {
		t.Errorf("unscoped admin query unexpectedly contains tenant clause:\n%s", sql)
	}
	if _, ok := q["param_tenant"]; ok {
		t.Errorf("unscoped admin query unexpectedly bound param_tenant: %v", q["param_tenant"])
	}
	// Optional filters absent too.
	if strings.Contains(sql, "{action:String}") || strings.Contains(sql, "{target:String}") {
		t.Errorf("unscoped admin query unexpectedly contains action/target clause:\n%s", sql)
	}
}

// TestQueryAuditPartialFilters: only some optional filters set still binds the
// right params and omits the rest (dynamic WHERE construction).
func TestQueryAuditPartialFilters(t *testing.T) {
	rec := newReadRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)

	// Action only, no tenant, no target.
	f := AuditFilter{Action: "config_reload", From: time.Now().Add(-time.Hour), To: time.Now()}
	if _, err := ch.QueryAudit(context.Background(), f); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	sql, q, _ := rec.snapshot()
	if !strings.Contains(sql, "action = {action:String}") {
		t.Errorf("audit SQL missing action clause:\n%s", sql)
	}
	assertParam(t, q, "param_action", "config_reload")
	if strings.Contains(sql, "{tenant:String}") || strings.Contains(sql, "{target:String}") {
		t.Errorf("audit SQL has unexpected tenant/target clause:\n%s", sql)
	}
	if _, ok := q["param_tenant"]; ok {
		t.Error("param_tenant bound but Tenant was empty")
	}
	if _, ok := q["param_target"]; ok {
		t.Error("param_target bound but Target was empty")
	}
}

// TestQueryRawAuthHeaders: when UsernameEnv/PasswordEnv resolve to non-empty,
// queryRaw sets X-ClickHouse-User / X-ClickHouse-Key.
func TestQueryRawAuthHeaders(t *testing.T) {
	t.Setenv("KAPKAN_CH_USER", "reader")
	t.Setenv("KAPKAN_CH_PASS", "s3cret")

	rec := newReadRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	cfg.UsernameEnv = "KAPKAN_CH_USER"
	cfg.PasswordEnv = "KAPKAN_CH_PASS"

	ch := querier(t, cfg)
	if _, err := ch.QueryTraffic(context.Background(), "h", time.Now(), time.Now(), 60); err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	_, _, h := rec.snapshot()
	if got := h.Get("X-ClickHouse-User"); got != "reader" {
		t.Errorf("X-ClickHouse-User = %q, want %q", got, "reader")
	}
	if got := h.Get("X-ClickHouse-Key"); got != "s3cret" {
		t.Errorf("X-ClickHouse-Key = %q, want %q", got, "s3cret")
	}
}

// TestQueryRawNoAuthHeadersWhenUnset: with no username configured, no auth
// headers are sent (the open/credential-less mode).
func TestQueryRawNoAuthHeadersWhenUnset(t *testing.T) {
	rec := newReadRecorder()
	srv, cfg := rec.server(t) // UsernameEnv/PasswordEnv empty
	defer srv.Close()
	ch := querier(t, cfg)
	if _, err := ch.QueryTraffic(context.Background(), "h", time.Now(), time.Now(), 60); err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	_, _, h := rec.snapshot()
	if _, ok := h["X-Clickhouse-User"]; ok {
		t.Errorf("X-ClickHouse-User set with no credentials: %v", h["X-Clickhouse-User"])
	}
	if _, ok := h["X-Clickhouse-Key"]; ok {
		t.Errorf("X-ClickHouse-Key set with no credentials: %v", h["X-Clickhouse-Key"])
	}
}

// TestQueryRawErrorStatus: a non-2xx response returns an error whose message
// includes the status code and a snippet of the response body. Both query
// entry points go through queryRaw, so assert via each.
func TestQueryRawErrorStatus(t *testing.T) {
	t.Run("traffic", func(t *testing.T) {
		rec := newReadRecorder()
		rec.status = 500
		srv, cfg := rec.server(t)
		defer srv.Close()
		ch := querier(t, cfg)
		out, err := ch.QueryTraffic(context.Background(), "h", time.Now(), time.Now(), 60)
		if err == nil {
			t.Fatal("QueryTraffic: want error on 500, got nil")
		}
		if out != nil {
			t.Errorf("QueryTraffic returned %v on error, want nil", out)
		}
		for _, want := range []string{"500", "DB::Exception"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %q", err.Error(), want)
			}
		}
	})
	t.Run("audit", func(t *testing.T) {
		rec := newReadRecorder()
		rec.status = 403
		srv, cfg := rec.server(t)
		defer srv.Close()
		ch := querier(t, cfg)
		out, err := ch.QueryAudit(context.Background(), AuditFilter{From: time.Now(), To: time.Now()})
		if err == nil {
			t.Fatal("QueryAudit: want error on 403, got nil")
		}
		if out != nil {
			t.Errorf("QueryAudit returned %v on error, want nil", out)
		}
		if !strings.Contains(err.Error(), "403") {
			t.Errorf("error %q missing status 403", err.Error())
		}
	})
}

// TestQueryRawBodyLimit: queryRaw caps the response read at exactly 1MB
// (io.LimitReader). Each JSONEachRow line is padded to a length that divides
// 1MB evenly, so the cap lands precisely on a newline boundary: every object
// read is whole, decoding succeeds, and we get exactly oneMB/lineLen rows even
// though the server sent strictly more.
func TestQueryRawBodyLimit(t *testing.T) {
	const oneMB = 1 << 20
	const lineLen = 128 // divides 1<<20 evenly => the cap lands on a newline
	const wantRows = oneMB / lineLen

	// One JSONEachRow object, padded with whitespace before the trailing
	// newline so the whole line is exactly lineLen bytes (JSON ignores the
	// inter-token whitespace).
	base := `{"ts":"2026-06-13 12:00:00","pps":1,"mbps":1,"flows_per_sec":1,"in_attack":0,"baseline_pps":1}`
	pad := strings.Repeat(" ", lineLen-len(base)-1) // -1 for the newline
	line := base + pad + "\n"
	if len(line) != lineLen {
		t.Fatalf("test setup: line length %d, want %d", len(line), lineLen)
	}

	rec := newReadRecorder()
	var b strings.Builder
	for i := 0; i < wantRows+1000; i++ { // send well over 1MB
		b.WriteString(line)
	}
	rec.resp = b.String()
	srv, cfg := rec.server(t)
	defer srv.Close()
	ch := querier(t, cfg)

	out, err := ch.QueryTraffic(context.Background(), "h", time.Now(), time.Now(), 60)
	if err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	// Exactly the rows that fit under the 1MB cap, not the full body.
	if len(out) != wantRows {
		t.Errorf("decoded %d rows, want exactly %d (1MB cap at %d-byte lines)", len(out), wantRows, lineLen)
	}
}

// TestNewQuerierDisabledReturnsNil: NewQuerier returns nil when storage is
// disabled so the API reports history as unavailable rather than erroring.
func TestNewQuerierDisabledReturnsNil(t *testing.T) {
	if q := NewQuerier(config.StorageSettings{Enabled: false}, discardLogger()); q != nil {
		t.Fatalf("NewQuerier(disabled) = %v, want nil", q)
	}
}

// TestNewQuerierReadsCredentials: NewQuerier reads user/pass from the configured
// env vars; the resolved values flow through to the auth headers.
func TestNewQuerierReadsCredentials(t *testing.T) {
	t.Setenv("KAPKAN_CH_USER", "queryuser")
	t.Setenv("KAPKAN_CH_PASS", "querypass")

	rec := newReadRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	cfg.UsernameEnv = "KAPKAN_CH_USER"
	cfg.PasswordEnv = "KAPKAN_CH_PASS"

	ch := querier(t, cfg)
	if ch.user != "queryuser" {
		t.Errorf("ch.user = %q, want %q", ch.user, "queryuser")
	}
	if ch.pass != "querypass" {
		t.Errorf("ch.pass = %q, want %q", ch.pass, "querypass")
	}

	// And those resolved credentials reach ClickHouse as auth headers.
	if _, err := ch.QueryTraffic(context.Background(), "h", time.Now(), time.Now(), 60); err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	_, _, h := rec.snapshot()
	if h.Get("X-ClickHouse-User") != "queryuser" || h.Get("X-ClickHouse-Key") != "querypass" {
		t.Errorf("auth headers = (%q,%q), want (queryuser,querypass)",
			h.Get("X-ClickHouse-User"), h.Get("X-ClickHouse-Key"))
	}
}

// TestNewQuerierNoCredentialsWhenEnvUnset: an env var that resolves to empty
// (unset) leaves user/pass empty.
func TestNewQuerierNoCredentialsWhenEnvUnset(t *testing.T) {
	rec := newReadRecorder()
	srv, cfg := rec.server(t)
	defer srv.Close()
	cfg.UsernameEnv = "KAPKAN_DEFINITELY_UNSET_USER_ENV"
	cfg.PasswordEnv = "KAPKAN_DEFINITELY_UNSET_PASS_ENV"
	ch := querier(t, cfg)
	if ch.user != "" || ch.pass != "" {
		t.Errorf("credentials = (%q,%q), want empty for unset env vars", ch.user, ch.pass)
	}
}

// assertParam asserts the URL query carries exactly the wanted value for key.
func assertParam(t *testing.T, q url.Values, key, want string) {
	t.Helper()
	if got := q.Get(key); got != want {
		t.Errorf("query param %s = %q, want %q", key, got, want)
	}
}

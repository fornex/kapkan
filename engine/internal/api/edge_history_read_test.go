package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/storage"
)

// histQuerier records the edge history reads the handlers issue and answers
// with canned rows; the traffic and audit reads are not its business.
type histQuerier struct {
	err      error
	points   []storage.EdgeHistoryPoint
	sources  []storage.EdgeSourceAgg
	events   []storage.EdgeEventRow
	gotZone  string
	gotNode  string
	gotStep  int
	gotFrom  time.Time
	gotTo    time.Time
	gotSrc   storage.EdgeSourceFilter
	gotEvent storage.EdgeEventFilter
	calls    int
}

func (f *histQuerier) QueryTraffic(context.Context, string, time.Time, time.Time, int) ([]storage.TrafficPoint, error) {
	return nil, nil
}
func (f *histQuerier) QueryAudit(context.Context, storage.AuditFilter) ([]storage.AuditRow, error) {
	return nil, nil
}
func (f *histQuerier) QueryEdgeHistory(_ context.Context, zone, node string, from, to time.Time, step int) ([]storage.EdgeHistoryPoint, error) {
	f.calls++
	f.gotZone, f.gotNode, f.gotFrom, f.gotTo, f.gotStep = zone, node, from, to, step
	return f.points, f.err
}
func (f *histQuerier) QueryEdgeSources(_ context.Context, filter storage.EdgeSourceFilter) ([]storage.EdgeSourceAgg, error) {
	f.calls++
	f.gotSrc = filter
	return f.sources, f.err
}
func (f *histQuerier) QueryEdgeEvents(_ context.Context, filter storage.EdgeEventFilter) ([]storage.EdgeEventRow, error) {
	f.calls++
	f.gotEvent = filter
	return f.events, f.err
}

func decodeInto(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
}

func zoneRefused(route string) float64 {
	return testutil.ToFloat64(metrics.APIZoneRefused.WithLabelValues(route))
}

var (
	rangeFrom = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	rangeTo   = time.Date(2026, 9, 10, 13, 0, 0, 0, time.UTC)
)

const rangeQuery = "from=2026-09-10T12:00:00Z&to=2026-09-10T13:00:00Z"

// TestParseRangeAndStep pins the rules five endpoints share: the last hour
// by default with to = now, one bound at a time, the four messages; a step of
// 60 by default, raised for the bucket cap, capped at a day.
func TestParseRangeAndStep(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	from, to, msg := parseRange(url.Values{}, now)
	if msg != "" || !to.Equal(now) || to.Sub(from) != time.Hour {
		t.Fatalf("default range: %s..%s %q, want the hour up to now", from, to, msg)
	}
	from, to, msg = parseRange(url.Values{"from": {"2026-09-10T11:30:00Z"}}, now)
	if msg != "" || !to.Equal(now) || !from.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("from only: %s..%s %q", from, to, msg)
	}
	from, to, msg = parseRange(url.Values{"to": {"2026-09-10T11:30:00Z"}}, now)
	if msg != "" || !to.Equal(now.Add(-30*time.Minute)) || !from.Equal(now.Add(-time.Hour)) {
		t.Fatalf("to only: %s..%s %q (from stays the default, an hour before now)", from, to, msg)
	}
	for _, tc := range []struct{ q, msg string }{
		{"from=yesterday", "invalid from (expected RFC3339)"},
		{"to=yesterday", "invalid to (expected RFC3339)"},
		{"from=2026-09-10T12:00:00Z&to=2026-09-10T11:00:00Z", "to must be after from"},
		{"from=2026-09-10T12:00:00Z&to=2026-09-10T12:00:00Z", "to must be after from"},
		{"from=2026-08-01T00:00:00Z&to=2026-09-10T00:00:00Z", "time range too large (max 31 days)"},
	} {
		q, _ := url.ParseQuery(tc.q)
		if _, _, msg := parseRange(q, now); msg != tc.msg {
			t.Errorf("parseRange(%s) = %q, want %q", tc.q, msg, tc.msg)
		}
	}
	month := now.Add(-31 * 24 * time.Hour)
	if step, msg := parseStep(url.Values{}, now.Add(-time.Hour), now); step != 60 || msg != "" {
		t.Errorf("default step = %d %q, want 60", step, msg)
	}
	if step, _ := parseStep(url.Values{"step": {"1"}}, month, now); step != 536 {
		t.Errorf("31 days at step=1 = %d, want 536 (5 000 buckets)", step)
	}
	if step, _ := parseStep(url.Values{"step": {"604800"}}, month, now); step != 86400 {
		t.Errorf("step=604800 = %d, want 86400 (a day is the widest bucket, as the query clamps)", step)
	}
	for _, v := range []string{"0", "-5", "ten"} {
		if _, msg := parseStep(url.Values{"step": {v}}, month, now); msg != "invalid step (positive integer seconds)" {
			t.Errorf("step=%s = %q", v, msg)
		}
	}
}

// TestEdgeHistoryReadUnscoped: no querier answers available:false with empty
// arrays on all three reads; the zone is required, folded and must be in the
// file; range and step follow the shared rules with the shared messages; the
// node filter is passed through, echoed and must name a configured node; the
// rows come back under the documented keys; a failed query is 502 with a
// body that says nothing of storage.
func TestEdgeHistoryReadUnscoped(t *testing.T) {
	store, _ := tenantStore(t)
	s := testServer(t, store)
	h := s.Handler()

	for path, key := range map[string]string{
		"/api/v1/edge/history?zone=a.example":         `"points":[]`,
		"/api/v1/edge/history/sources?zone=a.example": `"sources":[]`,
		"/api/v1/edge/events":                         `"events":[]`,
	} {
		rec := getWith(h, path, "op-secret")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"available":false`) || !strings.Contains(rec.Body.String(), key) {
			t.Fatalf("%s without a querier: %d %s (want available:false and %s)", path, rec.Code, rec.Body.String(), key)
		}
	}

	fq := &histQuerier{points: []storage.EdgeHistoryPoint{{TS: "2026-09-10 12:00:00", Nodes: 2, WindowSeconds: 120, Requests: 8124, WouldChallenge: 1240, H3Requests: 2048}}}
	s.SetQuerier(fq)
	for path, want := range map[string]struct {
		code int
		msg  string
	}{
		"/api/v1/edge/history":                                                                  {http.StatusBadRequest, "missing zone"},
		"/api/v1/edge/history?zone=nope.example":                                                {http.StatusNotFound, "unknown zone"},
		"/api/v1/edge/history?zone=a.example&from=yesterday":                                    {http.StatusBadRequest, "invalid from (expected RFC3339)"},
		"/api/v1/edge/history?zone=a.example&to=yesterday":                                      {http.StatusBadRequest, "invalid to (expected RFC3339)"},
		"/api/v1/edge/history?zone=a.example&from=2026-09-10T12:00:00Z&to=2026-09-10T11:00:00Z": {http.StatusBadRequest, "to must be after from"},
		"/api/v1/edge/history?zone=a.example&from=2026-08-01T00:00:00Z&to=2026-09-10T00:00:00Z": {http.StatusBadRequest, "time range too large (max 31 days)"},
		"/api/v1/edge/history?zone=a.example&step=0":                                            {http.StatusBadRequest, "invalid step (positive integer seconds)"},
		"/api/v1/edge/history?zone=a.example&step=ten":                                          {http.StatusBadRequest, "invalid step (positive integer seconds)"},
		"/api/v1/edge/history?zone=a.example&node=e9":                                           {http.StatusNotFound, "unknown edge node"},
		"/api/v1/edge/history?zone=a.example&node=e1":                                           {http.StatusOK, ""},
		"/api/v1/edge/history?zone=h.example":                                                   {http.StatusOK, ""}, // a house zone: the unscoped operator's
		"/api/v1/edge/history?zone=A.example":                                                   {http.StatusOK, ""}, // folded like the file's names
	} {
		rec := getWith(h, path, "op-secret")
		if rec.Code != want.code {
			t.Errorf("%s = %d, want %d: %s", path, rec.Code, want.code, rec.Body.String())
		}
		if want.msg != "" && !strings.Contains(rec.Body.String(), `"error":"`+want.msg+`"`) {
			t.Errorf("%s body = %s, want the message %q", path, rec.Body.String(), want.msg)
		}
	}
	rec := getWith(h, "/api/v1/edge/history?zone=a.example&"+rangeQuery+"&step=300", "op-secret")
	var doc EdgeHistoryDoc
	decodeInto(t, rec.Body.String(), &doc)
	if rec.Code != http.StatusOK || !doc.Available || doc.Zone != "a.example" || doc.Node != "" || doc.StepSeconds != 300 || len(doc.Points) != 1 || doc.Points[0].Requests != 8124 || doc.Points[0].Nodes != 2 {
		t.Fatalf("history doc: %d %+v", rec.Code, doc)
	}
	if fq.gotZone != "a.example" || fq.gotNode != "" || fq.gotStep != 300 || !fq.gotFrom.Equal(rangeFrom) || !fq.gotTo.Equal(rangeTo) {
		t.Fatalf("query received: zone %q node %q step %d from %s to %s", fq.gotZone, fq.gotNode, fq.gotStep, fq.gotFrom, fq.gotTo)
	}
	// The folded name is what the query gets and what the doc echoes.
	rec = getWith(h, "/api/v1/edge/history?zone=%20A.Example%20", "op-secret")
	decodeInto(t, rec.Body.String(), &doc)
	if rec.Code != http.StatusOK || doc.Zone != "a.example" || fq.gotZone != "a.example" {
		t.Fatalf("a folded zone name: %d doc %+v query %q", rec.Code, doc, fq.gotZone)
	}
	// A range wider than the bucket cap raises the step (31 d / 5000 → 536 s);
	// a step wider than a day is a day — in the query and in the echo alike.
	getWith(h, "/api/v1/edge/history?zone=a.example&from=2026-08-10T00:00:00Z&to=2026-09-10T00:00:00Z&step=1", "op-secret")
	if fq.gotStep != 536 {
		t.Fatalf("step for a 31-day range at step=1 = %d, want 536 (5000 buckets)", fq.gotStep)
	}
	rec = getWith(h, "/api/v1/edge/history?zone=a.example&from=2026-08-10T00:00:00Z&to=2026-09-10T00:00:00Z&step=604800", "op-secret")
	decodeInto(t, rec.Body.String(), &doc)
	if fq.gotStep != 86400 || doc.StepSeconds != 86400 {
		t.Fatalf("step=604800: query got %d, doc says %d, want 86400 both", fq.gotStep, doc.StepSeconds)
	}
	// The node filter reaches the query and is echoed.
	rec = getWith(h, "/api/v1/edge/history?zone=a.example&node=e1", "op-secret")
	decodeInto(t, rec.Body.String(), &doc)
	if fq.gotNode != "e1" || doc.Node != "e1" {
		t.Fatalf("node filter: query got %q, doc says %q", fq.gotNode, doc.Node)
	}
	// No rows is an empty array, never null; a failed query is 502 and the
	// body names no storage detail.
	fq.points = nil
	rec = getWith(h, "/api/v1/edge/history?zone=a.example", "op-secret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"points":[]`) {
		t.Fatalf("empty history: %d %s", rec.Code, rec.Body.String())
	}
	fq.err = context.DeadlineExceeded
	if rec := getWith(h, "/api/v1/edge/history?zone=a.example", "op-secret"); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"error":"edge history query failed"`) || strings.Contains(rec.Body.String(), "deadline") {
		t.Fatalf("failed query = %d %s, want 502 with the generic message", rec.Code, rec.Body.String())
	}
}

// TestEdgeHistoryReadScoped: a tenant reads its own zones (folded too); any
// other zone — another tenant's, the house zone, unknown — is one uniform
// 403, counted under route=edge_history and never reaching storage; the node
// filter and the events are unscoped-only.
func TestEdgeHistoryReadScoped(t *testing.T) {
	store, _ := tenantStore(t)
	s := testServer(t, store)
	fq := &histQuerier{}
	s.SetQuerier(fq)
	h := s.Handler()
	beforeHist, beforeLever := zoneRefused("edge_history"), zoneRefused("edge_lever")

	own := getWith(h, "/api/v1/edge/history?zone=a.example", "acme-op-secret")
	if own.Code != http.StatusOK || fq.gotZone != "a.example" {
		t.Fatalf("own zone = %d %s", own.Code, own.Body.String())
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=A.example", "acme-op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("own zone, upper case = %d %s (a benign spelling must not read as a leaked token)", rec.Code, rec.Body.String())
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=a.example", "acme-view-secret"); rec.Code != http.StatusOK {
		t.Fatalf("viewer of the tenant = %d", rec.Code)
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=s.example", "shop-op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("zone-only tenant on its zone = %d", rec.Code)
	}
	if got := zoneRefused("edge_history") - beforeHist; got != 0 {
		t.Fatalf("own-zone reads moved the refusal counter by %v", got)
	}
	fq.calls = 0
	var refusal string
	for _, zone := range []string{"s.example", "h.example", "ghost.example", "nope.example"} {
		for _, path := range []string{"/api/v1/edge/history?zone=" + zone, "/api/v1/edge/history/sources?zone=" + zone} {
			rec := getWith(h, path, "acme-op-secret")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s as acme = %d, want 403", path, rec.Code)
			}
			if refusal == "" {
				refusal = rec.Body.String()
				if !strings.Contains(refusal, `"error":"zone is outside your tenant"`) {
					t.Fatalf("refusal body = %s", refusal)
				}
			} else if rec.Body.String() != refusal {
				t.Fatalf("refusal bodies differ (%q vs %q): an existence oracle", rec.Body.String(), refusal)
			}
		}
	}
	if fq.calls != 0 {
		t.Fatalf("a refused read reached storage %d times", fq.calls)
	}
	if got := zoneRefused("edge_history") - beforeHist; got != 8 {
		t.Fatalf("kapkan_api_zone_refused_total{route=edge_history} moved by %v, want 8 (one per refused read)", got)
	}
	if got := zoneRefused("edge_lever") - beforeLever; got != 0 {
		t.Fatalf("the lever's series moved by %v on history reads", got)
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=a.example&node=e1", "acme-op-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped node filter = %d, want 403", rec.Code)
	}
	if rec := getWith(h, "/api/v1/edge/events", "acme-op-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped events = %d, want 403", rec.Code)
	}
	// Without a querier the scope still decides before the availability answer
	// for the events (a 403 is not "unavailable"); the history answers
	// available:false to anyone, since no zone is looked at — and counts nothing.
	bare := testServer(t, store)
	bh := bare.Handler()
	if rec := getWith(bh, "/api/v1/edge/events", "acme-op-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped events without a querier = %d, want 403", rec.Code)
	}
	beforeHist = zoneRefused("edge_history")
	if rec := getWith(bh, "/api/v1/edge/history?zone=s.example", "acme-op-secret"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("history without a querier = %d %s", rec.Code, rec.Body.String())
	}
	if got := zoneRefused("edge_history") - beforeHist; got != 0 {
		t.Fatalf("a storage-off read moved the refusal counter by %v", got)
	}
}

// TestEdgeHistorySourcesAndEvents: the source read validates the state and
// passes zone/state/range through exactly, echoes the filter, answers [] for
// no rows and 502 for a failed query; the events read is unscoped-only,
// accepts every documented kind and no other, passes every filter through
// exactly, and fails the same way.
func TestEdgeHistorySourcesAndEvents(t *testing.T) {
	store, _ := tenantStore(t)
	s := testServer(t, store)
	fq := &histQuerier{
		sources: []storage.EdgeSourceAgg{{Source: "203.0.113.9", State: "would-deny", Requests: 1210, Windows: 12, Nodes: 2, FirstSeen: "2026-09-10 12:00:10", LastSeen: "2026-09-10 12:02:00"}},
		events:  []storage.EdgeEventRow{{EventTime: "2026-09-10 12:05:00", Node: "e1", Kind: EventNodeLost}},
	}
	s.SetQuerier(fq)
	h := s.Handler()

	if rec := getWith(h, "/api/v1/edge/history/sources?zone=a.example&state=allow", "op-secret"); rec.Code != http.StatusBadRequest {
		t.Fatalf("state=allow = %d, want 400 (visitors are never stored)", rec.Code)
	}
	rec := getWith(h, "/api/v1/edge/history/sources?zone=a.example&state=denied&"+rangeQuery, "op-secret")
	var sd EdgeHistorySourcesDoc
	decodeInto(t, rec.Body.String(), &sd)
	if rec.Code != http.StatusOK || !sd.Available || sd.Zone != "a.example" || sd.State != "denied" || len(sd.Sources) != 1 || sd.Sources[0].Requests != 1210 {
		t.Fatalf("sources doc: %d %+v", rec.Code, sd)
	}
	if fq.gotSrc.Zone != "a.example" || fq.gotSrc.State != "denied" || !fq.gotSrc.From.Equal(rangeFrom) || !fq.gotSrc.To.Equal(rangeTo) {
		t.Fatalf("source filter received: %+v", fq.gotSrc)
	}
	// No filter: no top-level state in the body; no rows: an empty array.
	fq.sources = nil
	rec = getWith(h, "/api/v1/edge/history/sources?zone=a.example", "op-secret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sources":[]`) || strings.Contains(rec.Body.String(), `"state"`) {
		t.Fatalf("unfiltered, empty sources: %d %s", rec.Code, rec.Body.String())
	}
	// The scoped tenant reads its own zone's sources.
	if rec := getWith(h, "/api/v1/edge/history/sources?zone=a.example", "acme-op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("scoped sources on own zone = %d", rec.Code)
	}
	fq.err = context.DeadlineExceeded
	if rec := getWith(h, "/api/v1/edge/history/sources?zone=a.example", "op-secret"); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"error":"edge history query failed"`) {
		t.Fatalf("failed sources query = %d %s, want 502 with the generic message", rec.Code, rec.Body.String())
	}
	fq.err = nil

	if rec := getWith(h, "/api/v1/edge/events?kind=meteor", "op-secret"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error":"invalid kind"`) {
		t.Fatalf("kind=meteor = %d %s, want 400", rec.Code, rec.Body.String())
	}
	// Every documented kind is accepted and reaches the query; the list is
	// the sixteen api.mdx names.
	if len(edgeEventKindList) != 16 {
		t.Fatalf("edgeEventKindList has %d kinds, api.mdx lists 16", len(edgeEventKindList))
	}
	for _, kind := range edgeEventKindList {
		if rec := getWith(h, "/api/v1/edge/events?kind="+kind, "op-secret"); rec.Code != http.StatusOK || fq.gotEvent.Kind != kind {
			t.Fatalf("kind=%s = %d, query got %q", kind, rec.Code, fq.gotEvent.Kind)
		}
	}
	rec = getWith(h, "/api/v1/edge/events?node=e1&zone=a.example&kind=node_lost&"+rangeQuery, "op-secret")
	var ed EdgeEventsDoc
	decodeInto(t, rec.Body.String(), &ed)
	if rec.Code != http.StatusOK || !ed.Available || len(ed.Events) != 1 || ed.Events[0].Kind != EventNodeLost {
		t.Fatalf("events doc: %d %+v", rec.Code, ed)
	}
	if fq.gotEvent.Node != "e1" || fq.gotEvent.Zone != "a.example" || fq.gotEvent.Kind != EventNodeLost || !fq.gotEvent.From.Equal(rangeFrom) || !fq.gotEvent.To.Equal(rangeTo) {
		t.Fatalf("event filter received: %+v", fq.gotEvent)
	}
	// A viewer reads events too (viewer rank), the agent does not.
	if rec := getWith(h, "/api/v1/edge/events", "op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("events for the operator = %d", rec.Code)
	}
	if rec := getWith(h, "/api/v1/edge/events", "agent-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("events for the agent = %d, want 403", rec.Code)
	}
	fq.events = nil
	if rec := getWith(h, "/api/v1/edge/events", "op-secret"); !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Fatalf("empty events must be [], got %s", rec.Body.String())
	}
	fq.err = context.DeadlineExceeded
	if rec := getWith(h, "/api/v1/edge/events", "op-secret"); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"error":"edge events query failed"`) {
		t.Fatalf("failed events query = %d %s, want 502 with the generic message", rec.Code, rec.Body.String())
	}
}

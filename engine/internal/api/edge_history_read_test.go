package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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

// TestEdgeHistoryReadUnscoped: no querier answers available:false; the zone
// is required and must be in the file; range and step follow the traffic
// rules; the node filter is passed through and must name a configured node;
// the rows come back under the documented keys.
func TestEdgeHistoryReadUnscoped(t *testing.T) {
	store, _ := tenantStore(t)
	s := testServer(t, store)
	h := s.Handler()

	rec := getWith(h, "/api/v1/edge/history?zone=a.example", "op-secret")
	var off EdgeHistoryDoc
	decodeInto(t, rec.Body.String(), &off)
	if rec.Code != http.StatusOK || off.Available || off.Points == nil {
		t.Fatalf("no querier: %d %s (want available:false and points [])", rec.Code, rec.Body.String())
	}

	fq := &histQuerier{points: []storage.EdgeHistoryPoint{{TS: "2026-09-10 12:00:00", Nodes: 2, WindowSeconds: 120, Requests: 8124, WouldChallenge: 1240, H3Requests: 2048}}}
	s.SetQuerier(fq)
	for path, want := range map[string]int{
		"/api/v1/edge/history":                                                                  http.StatusBadRequest, // missing zone
		"/api/v1/edge/history?zone=nope.example":                                                http.StatusNotFound,
		"/api/v1/edge/history?zone=a.example&from=yesterday":                                    http.StatusBadRequest,
		"/api/v1/edge/history?zone=a.example&from=2026-09-10T12:00:00Z&to=2026-09-10T11:00:00Z": http.StatusBadRequest,
		"/api/v1/edge/history?zone=a.example&from=2026-08-01T00:00:00Z&to=2026-09-10T00:00:00Z": http.StatusBadRequest, // > 31 days
		"/api/v1/edge/history?zone=a.example&step=0":                                            http.StatusBadRequest,
		"/api/v1/edge/history?zone=a.example&step=ten":                                          http.StatusBadRequest,
		"/api/v1/edge/history?zone=a.example&node=e9":                                           http.StatusNotFound,
		"/api/v1/edge/history?zone=a.example&node=e1":                                           http.StatusOK,
		"/api/v1/edge/history?zone=h.example":                                                   http.StatusOK, // a house zone: the unscoped operator's
	} {
		if rec := getWith(h, path, "op-secret"); rec.Code != want {
			t.Errorf("%s = %d, want %d: %s", path, rec.Code, want, rec.Body.String())
		}
	}
	rec = getWith(h, "/api/v1/edge/history?zone=a.example&from=2026-09-10T12:00:00Z&to=2026-09-10T13:00:00Z&step=300", "op-secret")
	var doc EdgeHistoryDoc
	decodeInto(t, rec.Body.String(), &doc)
	if rec.Code != http.StatusOK || !doc.Available || doc.Zone != "a.example" || doc.Node != "" || doc.StepSeconds != 300 || len(doc.Points) != 1 || doc.Points[0].Requests != 8124 || doc.Points[0].Nodes != 2 {
		t.Fatalf("history doc: %d %+v", rec.Code, doc)
	}
	if fq.gotZone != "a.example" || fq.gotNode != "" || fq.gotStep != 300 || !fq.gotFrom.Equal(time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)) || !fq.gotTo.Equal(time.Date(2026, 9, 10, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("query received: zone %q node %q step %d from %s to %s", fq.gotZone, fq.gotNode, fq.gotStep, fq.gotFrom, fq.gotTo)
	}
	// A range wider than the bucket cap raises the step (31 d / 5000 → 536 s).
	getWith(h, "/api/v1/edge/history?zone=a.example&from=2026-08-10T00:00:00Z&to=2026-09-10T00:00:00Z&step=1", "op-secret")
	if fq.gotStep != 536 {
		t.Fatalf("step for a 31-day range at step=1 = %d, want 536 (5000 buckets)", fq.gotStep)
	}
	// The node filter reaches the query.
	getWith(h, "/api/v1/edge/history?zone=a.example&node=e1", "op-secret")
	if fq.gotNode != "e1" {
		t.Fatalf("node filter not passed: %q", fq.gotNode)
	}
	// No rows is an empty array, never null; a failed query is 502.
	fq.points = nil
	rec = getWith(h, "/api/v1/edge/history?zone=a.example", "op-secret")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"points":[]`) {
		t.Fatalf("empty history: %d %s", rec.Code, rec.Body.String())
	}
	fq.err = context.DeadlineExceeded
	if rec := getWith(h, "/api/v1/edge/history?zone=a.example", "op-secret"); rec.Code != http.StatusBadGateway {
		t.Fatalf("failed query = %d, want 502", rec.Code)
	}
}

// TestEdgeHistoryReadScoped: a tenant reads its own zones; any other zone —
// another tenant's, the house zone, unknown — is one uniform 403; the node
// filter is unscoped-only; the refusal is counted like the lever's.
func TestEdgeHistoryReadScoped(t *testing.T) {
	store, _ := tenantStore(t)
	s := testServer(t, store)
	fq := &histQuerier{}
	s.SetQuerier(fq)
	h := s.Handler()

	own := getWith(h, "/api/v1/edge/history?zone=a.example", "acme-op-secret")
	if own.Code != http.StatusOK || fq.gotZone != "a.example" {
		t.Fatalf("own zone = %d %s", own.Code, own.Body.String())
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=a.example", "acme-view-secret"); rec.Code != http.StatusOK {
		t.Fatalf("viewer of the tenant = %d", rec.Code)
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=s.example", "shop-op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("zone-only tenant on its zone = %d", rec.Code)
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
			} else if rec.Body.String() != refusal {
				t.Fatalf("refusal bodies differ (%q vs %q): an existence oracle", rec.Body.String(), refusal)
			}
		}
	}
	if fq.calls != 0 {
		t.Fatalf("a refused read reached storage %d times", fq.calls)
	}
	if rec := getWith(h, "/api/v1/edge/history?zone=a.example&node=e1", "acme-op-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped node filter = %d, want 403", rec.Code)
	}
	if rec := getWith(h, "/api/v1/edge/events", "acme-op-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped events = %d, want 403", rec.Code)
	}
	// Without a querier the scope still decides before the availability answer
	// for the events (a 403 is not "unavailable"); the history answers
	// available:false to anyone, since no zone is looked at.
	bare := testServer(t, store)
	bh := bare.Handler()
	if rec := getWith(bh, "/api/v1/edge/events", "acme-op-secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped events without a querier = %d, want 403", rec.Code)
	}
	if rec := getWith(bh, "/api/v1/edge/history?zone=s.example", "acme-op-secret"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("history without a querier = %d %s", rec.Code, rec.Body.String())
	}
}

// TestEdgeHistorySourcesAndEvents: the source read validates the state and
// passes zone/state/range through; the events read is unscoped-only,
// validates the kind and passes every filter through.
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
	rec := getWith(h, "/api/v1/edge/history/sources?zone=a.example&state=denied&from=2026-09-10T12:00:00Z&to=2026-09-10T13:00:00Z", "op-secret")
	var sd EdgeHistorySourcesDoc
	decodeInto(t, rec.Body.String(), &sd)
	if rec.Code != http.StatusOK || !sd.Available || sd.Zone != "a.example" || sd.State != "denied" || len(sd.Sources) != 1 || sd.Sources[0].Requests != 1210 {
		t.Fatalf("sources doc: %d %+v", rec.Code, sd)
	}
	if fq.gotSrc.Zone != "a.example" || fq.gotSrc.State != "denied" || fq.gotSrc.From.IsZero() || !fq.gotSrc.To.After(fq.gotSrc.From) {
		t.Fatalf("source filter received: %+v", fq.gotSrc)
	}
	// The scoped tenant reads its own zone's sources.
	if rec := getWith(h, "/api/v1/edge/history/sources?zone=a.example", "acme-op-secret"); rec.Code != http.StatusOK {
		t.Fatalf("scoped sources on own zone = %d", rec.Code)
	}

	if rec := getWith(h, "/api/v1/edge/events?kind=meteor", "op-secret"); rec.Code != http.StatusBadRequest {
		t.Fatalf("kind=meteor = %d, want 400", rec.Code)
	}
	rec = getWith(h, "/api/v1/edge/events?node=e1&zone=a.example&kind=node_lost&from=2026-09-10T12:00:00Z&to=2026-09-10T13:00:00Z", "op-secret")
	var ed EdgeEventsDoc
	decodeInto(t, rec.Body.String(), &ed)
	if rec.Code != http.StatusOK || !ed.Available || len(ed.Events) != 1 || ed.Events[0].Kind != EventNodeLost {
		t.Fatalf("events doc: %d %+v", rec.Code, ed)
	}
	if fq.gotEvent.Node != "e1" || fq.gotEvent.Zone != "a.example" || fq.gotEvent.Kind != EventNodeLost || !fq.gotEvent.From.Equal(time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)) {
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
}

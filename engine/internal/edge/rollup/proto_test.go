package rollup

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

// The window counts the requests that arrived over HTTP/3 from the log's
// proto field, and the counter labels every record by protocol — an absent
// field (a node rendered before E5) is "other", never a wrong protocol.
func TestAggregatorCountsProtocols(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	var closed []WindowStats
	a := &Aggregator{Window: time.Second, Now: func() time.Time { return now }, OnWindow: func(w WindowStats) { closed = append(closed, w) }}
	zone := "proto-test.example"
	a.SetZones([]string{zone}) // the per-zone counter series exists only once a document is known
	before := map[string]float64{}
	for _, l := range []string{"h1", "h2", "h3", "other"} {
		before[l] = testutil.ToFloat64(metrics.EdgeRequestsTotal.WithLabelValues(zone, l))
	}
	for _, proto := range []string{"HTTP/3.0", "HTTP/3.0", "HTTP/2.0", "HTTP/1.1", "HTTP/1.0", "", "SPDY/3"} {
		a.Observe(Record{TS: now, Zone: zone, Src: netip.MustParseAddr("10.0.0.1"), Port: 443, Proto: proto, Status: 200})
	}
	now = now.Add(2 * time.Second)
	a.Tick()
	if len(closed) != 1 {
		t.Fatalf("%d windows closed, want 1", len(closed))
	}
	w := closed[0]
	if w.Requests != 7 || w.H3Requests != 2 {
		t.Errorf("requests %d h3 %d, want 7 and 2", w.Requests, w.H3Requests)
	}
	want := map[string]float64{"h1": 2, "h2": 1, "h3": 2, "other": 2}
	for l, n := range want {
		if got := testutil.ToFloat64(metrics.EdgeRequestsTotal.WithLabelValues(zone, l)) - before[l]; got != n {
			t.Errorf("kapkan_edge_requests_total{protocol=%s} += %v, want %v", l, got, n)
		}
	}
	for proto, want := range map[string]string{"HTTP/1.1": "h1", "HTTP/1.0": "h1", "HTTP/2.0": "h2", "HTTP/2": "h2", "HTTP/3.0": "h3", "HTTP/3": "h3", "": "other", "HTTP/0.9": "other", "h3": "other"} {
		if got := protoLabel(proto); got != want {
			t.Errorf("protoLabel(%q) = %s, want %s", proto, got, want)
		}
	}
}

// A record for a zone the document does not have — and any record before the
// first SetZones — must not open a kapkan_edge_requests_total series, so the
// metric's zone label stays bounded by the document.
func TestRequestsTotalStaysBounded(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	before := testutil.CollectAndCount(metrics.EdgeRequestsTotal)
	// No SetZones yet: known is nil, the record is still folded into a window
	// but opens no series.
	a := &Aggregator{Window: time.Second, Now: func() time.Time { return now }}
	a.Observe(Record{TS: now, Zone: "never-carded.example", Src: netip.MustParseAddr("10.0.0.9"), Port: 443, Proto: "HTTP/2.0", Status: 200})
	// With a document, a record for an unknown zone is dropped as unknown_zone
	// and still opens no series.
	a.SetZones([]string{"known.example"})
	a.Observe(Record{TS: now, Zone: "stranger.example", Src: netip.MustParseAddr("10.0.0.9"), Port: 443, Proto: "HTTP/2.0", Status: 200})
	if after := testutil.CollectAndCount(metrics.EdgeRequestsTotal); after != before {
		t.Errorf("kapkan_edge_requests_total series count %d → %d: an unknown zone opened a series", before, after)
	}
}

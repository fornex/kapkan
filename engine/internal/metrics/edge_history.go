package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EdgeHistoryDropped counts the parts of an edge node's report the brain did
// NOT write to the edge history (E6.5), by reason: unknown_zone (a zone the
// zones file does not have), no_at (a window without a close time),
// duplicate (a window already written — one report sent six times is one
// row), bad_source (a source that is not an address or a /64), source_cap
// (more telling sources than the per-window bound). The report itself is
// still accepted (204) and shown live; only the history skips the part. A
// rising count names a node whose reports the history cannot use.
var EdgeHistoryDropped = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "kapkan",
	Subsystem: "edge",
	Name:      "history_dropped_total",
	Help:      "Report parts not written to the edge history, by reason (unknown_zone|no_at|duplicate|bad_source|source_cap).",
}, []string{"reason"})

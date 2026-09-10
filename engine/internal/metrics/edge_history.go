package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EdgeHistoryDropped counts the parts of an edge node's report the brain did
// NOT write to the edge history (E6.5), by reason: unknown_zone (a zone the
// zones file does not have — a window, a certificate or a challenge naming
// it), no_at (a window that carries counters but no close time), duplicate
// (a close time already written for that node and zone — a report re-sent;
// expected once per burst end when reports are more frequent than windows),
// extra_window (a second window for one zone in one report), bad_source (a
// source that is not an address), source_cap (more
// telling sources than the per-window bound). The report itself is still
// accepted (204) and shown live; only the history skips the part. A quiet
// deciding zone (no close time, nothing counted) is nothing to write and is
// not counted. Only counted while storage is on.
var EdgeHistoryDropped = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "kapkan",
	Subsystem: "edge",
	Name:      "history_dropped_total",
	Help:      "Report parts not written to the edge history, by reason (unknown_zone|no_at|duplicate|extra_window|bad_source|source_cap).",
}, []string{"reason"})

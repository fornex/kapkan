package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Edge-node metrics (edge-spec §5, §2.3): the decision service and the
// access-log rollups that run on a `kapkan edge` node.
var (
	// EdgeDecisionsTotal counts decision-service verdicts. The zone label is
	// bounded by the zones document (an unknown zone is reported as "unknown",
	// never by its claimed name). result: allow, allow_marked, deny_rate,
	// deny_concurrency, deny_table, would_deny (a dry-run deny, answered as
	// allow), unknown_zone, untracked (the per-source tables were full and the
	// request passed undecided), bad_request (a subrequest off the contract).
	EdgeDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "decisions_total",
		Help:      "Decision-service verdicts, by zone and result.",
	}, []string{"zone", "result"})

	// EdgeLogRecordsTotal counts access-log datagrams from the terminator by
	// result: ok, malformed (no JSON, or fields the renderer never emits),
	// oversized (a datagram that did not fit the receive buffer), dropped (the
	// handler queue was full), unknown_zone (a zone the document does not
	// have — a forged or stale line).
	EdgeLogRecordsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "log_records_total",
		Help:      "Access-log datagrams received from the terminator, by result.",
	}, []string{"result"})

	// EdgeInflightResetsTotal counts in-flight concurrency counters the
	// decision service reset because a busy source had seen no completion for
	// a whole idle period — the access-log stream for it was lossy or dead, so
	// the count was meaningless. A steady rate here means log datagrams are
	// being lost (see net.unix.max_dgram_qlen).
	EdgeInflightResetsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "inflight_resets_total",
		Help:      "In-flight counters reset for lack of completions while a source stayed busy.",
	})

	// EdgeVerdictTableEntries is the number of live deny/mark entries in the
	// decision service's verdict table.
	EdgeVerdictTableEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "verdict_table_entries",
		Help:      "Live deny/mark entries in the decision service's verdict table.",
	})
)

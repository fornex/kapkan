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
	// oversized (a datagram that did not fit the receive buffer).
	EdgeLogRecordsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "log_records_total",
		Help:      "Access-log datagrams received from the terminator, by result.",
	}, []string{"result"})

	// EdgeVerdictTableEntries is the number of live deny/mark entries in the
	// decision service's verdict table.
	EdgeVerdictTableEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "verdict_table_entries",
		Help:      "Live deny/mark entries in the decision service's verdict table.",
	})
)

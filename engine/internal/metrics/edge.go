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
	// never by its claimed name). result: allow, allow_marked, allow_cleared
	// (a valid clearance cookie passed the rung), deny_rate, deny_concurrency,
	// deny_table, challenge (a 401: the client must clear the rung),
	// would_deny / would_challenge (a dry-run deny or challenge, answered as
	// allow), unknown_zone, mode_none (a zone that does not decide), untracked
	// (the per-source tables were full and the request passed undecided),
	// bad_request (a subrequest off the contract).
	EdgeDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "decisions_total",
		Help:      "Decision-service verdicts, by zone and result.",
	}, []string{"zone", "result"})

	// EdgeChallengeActive is 1 while a zone-wide challenge is in force on this
	// node (every request of the zone is challenged), 0 otherwise. The reason
	// is a log line and a report field, not a label.
	EdgeChallengeActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "challenge_active",
		Help:      "1 while a zone-wide challenge is in force on this node, 0 otherwise.",
	}, []string{"zone"})

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

	// EdgeCertNotAfter is the expiry of the certificate this node holds for a
	// zone, as unix seconds — the T−30 d alarm of edge-spec §2.4 is a rule on
	// this gauge. Absent for a zone with no certificate yet.
	EdgeCertNotAfter = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "cert_not_after_seconds",
		Help:      "Expiry (unix seconds) of the certificate held for a zone.",
	}, []string{"zone"})

	// EdgeACMEAttemptsTotal counts issuance attempts by zone and result:
	// issued, renewed, failed, fallback (the fallback CA was used).
	EdgeACMEAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "edge",
		Name:      "acme_attempts_total",
		Help:      "ACME issuance attempts, by zone and result.",
	}, []string{"zone", "result"})
)

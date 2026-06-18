// Package metrics defines all Prometheus collectors exposed on /metrics.
// Collectors are package-level and registered with the default registry so
// every component records into the same place without plumbing.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Ingestion metrics.
var (
	// FlowsTotal counts normalized flow records per wire protocol.
	FlowsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "ingest",
		Name:      "flows_total",
		Help:      "Normalized flow records produced, by wire protocol.",
	}, []string{"proto"})

	// PacketsTotal counts received UDP datagrams per exporter address. The
	// exporter label is cardinality-bounded (the source address is spoofable):
	// sources outside the configured flow_sources allowlist — or beyond an
	// internal cap when none is set — are bucketed under "other".
	PacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "ingest",
		Name:      "packets_total",
		Help:      "Telemetry UDP datagrams received, by exporter address (cardinality-bounded; see flow_sources) and protocol.",
	}, []string{"exporter", "proto"})

	// DecodeErrorsTotal counts datagrams that failed to decode.
	DecodeErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "ingest",
		Name:      "decode_errors_total",
		Help:      "Telemetry datagrams that failed to decode, by protocol.",
	}, []string{"proto"})

	// DroppedFlowsTotal counts flows dropped because the engine queue was full.
	DroppedFlowsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "ingest",
		Name:      "dropped_flows_total",
		Help:      "Flows dropped because the engine input queue was full.",
	})
)

// Engine metrics.
var (
	// ActiveAttacks is the number of attacks currently in progress.
	ActiveAttacks = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "engine",
		Name:      "active_attacks",
		Help:      "Attacks currently in progress.",
	})

	// AttacksTotal counts attack-started events since process start.
	AttacksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "engine",
		Name:      "attacks_total",
		Help:      "AttackStarted events emitted since start.",
	})

	// ProcessLatency observes per-flow hot-path processing time.
	ProcessLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "kapkan",
		Subsystem: "engine",
		Name:      "process_latency_seconds",
		Help:      "Per-batch flow processing latency.",
		Buckets:   prometheus.ExponentialBuckets(1e-6, 4, 12),
	})

	// TrackedHosts is the number of destination hosts with live counters.
	TrackedHosts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "engine",
		Name:      "tracked_hosts",
		Help:      "Destination hosts currently tracked in the sliding window.",
	})
)

// Mitigation metrics.
var (
	// AnnouncedRoutes is the number of currently announced (or, in dry-run,
	// virtually announced) blackhole routes.
	AnnouncedRoutes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "announced_routes",
		Help:      "Blackhole routes currently announced, by mode (real|dry_run).",
	}, []string{"mode"})

	// BansRejectedTotal counts bans refused by the max_active_bans cap.
	BansRejectedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "bans_rejected_total",
		Help:      "Ban requests refused because max_active_bans was reached.",
	})

	// FlowSpecRules is the number of FlowSpec rules currently announced (or,
	// in dry-run, virtually so). A single ban can carry several rules, so
	// this can exceed active bans — watch it against your upstream's
	// FlowSpec route limit.
	FlowSpecRules = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "flowspec_rules",
		Help:      "FlowSpec rules currently announced, by mode (real|dry_run).",
	}, []string{"mode"})

	// NotificationsTotal counts notification deliveries by channel and result.
	NotificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "notify",
		Name:      "notifications_total",
		Help:      "Notification attempts, by channel and result.",
	}, []string{"channel", "result"})
)

// Storage metrics.
var (
	// StorageRowsTotal counts rows by destination table and result
	// (written|dropped|error). "dropped" means the bounded queue was full —
	// storage never blocks detection.
	StorageRowsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "storage",
		Name:      "rows_total",
		Help:      "Storage rows, by table and result (written|dropped|error).",
	}, []string{"table", "result"})
)

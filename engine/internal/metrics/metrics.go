// Package metrics defines all Prometheus collectors exposed on /metrics.
// Collectors are package-level and registered with the default registry so
// every component records into the same place without plumbing.
package metrics

import (
	"runtime"

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

	// BoundaryDebugBytes is a discovery aid for interface-boundary counting,
	// emitted only while sampling.boundary_debug is true. It reports the
	// sampling-corrected bytes seen toward (dir=in) or from (dir=out) protected
	// hosts, broken down by exporter and interface (ifIndex), so an operator
	// can identify which interfaces are the external/edge boundary. It is NOT
	// cardinality-bounded — enable it briefly, read the breakdown, disable it.
	BoundaryDebugBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "engine",
		Name:      "boundary_debug_bytes_total",
		Help:      "Sampling-corrected bytes toward/from protected hosts by exporter and interface (only while sampling.boundary_debug is set).",
	}, []string{"exporter", "iface", "dir"})
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

	// BansRejectedTotal counts bans refused by a safety guard, labeled by the
	// reason (max_active_bans | blast_radius_fraction | blast_radius_rate). A
	// climbing blast_radius_* series means a runaway-detection or poisoned
	// baseline is being contained.
	BansRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "bans_rejected_total",
		Help:      "Ban requests refused by a safety guard, by reason.",
	}, []string{"reason"})

	// MitigateFallbackTotal counts mitigation announces that fell back to a
	// secondary method because the primary was rejected by the peer, labeled by
	// from/to method. A non-zero from="flowspec" series flags upstreams that do
	// not honor FlowSpec.
	MitigateFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "fallback_total",
		Help:      "Mitigation announces that degraded to a fallback method, by from/to.",
	}, []string{"from", "to"})

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

// Build / update metrics.
var (
	// BuildInfo is a constant-1 info gauge carrying the running version in its
	// labels (the node_exporter idiom) — so a fleet's version drift is queryable
	// with `count by (version)(kapkan_build_info)` and zero phone-home.
	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Name:      "build_info",
		Help:      "Build metadata; constant 1, version/revision/goversion/goos/goarch in labels.",
	}, []string{"version", "revision", "goversion", "goos", "goarch"})

	// UpdateAvailable is emitted only when the opt-in update check finds a newer
	// release: a constant-1 gauge labeled with the latest version and whether it
	// is security-relevant. Reset before each set, so at most one series exists.
	UpdateAvailable = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Name:      "update_available",
		Help:      "1 when a newer release is available (opt-in update check), latest_version/security in labels.",
	}, []string{"latest_version", "security"})
)

// RecordBuildInfo sets the kapkan_build_info series for this binary. version and
// revision come from internal/buildinfo; the runtime fields are filled here so
// the metrics package stays free of a buildinfo import.
func RecordBuildInfo(version, revision string) {
	BuildInfo.WithLabelValues(version, revision, runtime.Version(), runtime.GOOS, runtime.GOARCH).Set(1)
}

// SetUpdateAvailable replaces the kapkan_update_available series: a single 1 for
// (latest, security) when an update is available, or none when not.
func SetUpdateAvailable(available bool, latest string, security bool) {
	UpdateAvailable.Reset()
	if available {
		sec := "false"
		if security {
			sec = "true"
		}
		UpdateAvailable.WithLabelValues(latest, sec).Set(1)
	}
}

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

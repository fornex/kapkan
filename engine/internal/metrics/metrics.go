// Package metrics defines all Prometheus collectors exposed on /metrics.
// Collectors are package-level and registered with the default registry so
// every component records into the same place without plumbing.
package metrics

import (
	"runtime"
	"sync"

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

	// EventsDroppedTotal counts lifecycle events shed because the event channel
	// was full, labelled by kind. A dropped attack_started/attack_ended is a
	// real loss (the episode's mitigation/notification is missed); a dropped
	// attack_ongoing self-heals on the next tick.
	EventsDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "engine",
		Name:      "events_dropped_total",
		Help:      "Engine lifecycle events dropped due to a full event channel, by kind.",
	}, []string{"kind"})

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
	//
	// It counts only the rungs that ask a PEER to enforce something — blackhole,
	// divert, flowspec. A `dataplane` rung enforces on this box's own NIC and
	// announces nothing to anybody, so counting it here would inflate a gauge
	// whose name is a claim about the RIB; those bans are in
	// MitigateDataplaneBans.
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

	// MitigateDataplaneBans is AnnouncedRoutes' counterpart for the `dataplane` rung:
	// bans currently enforced by THIS box's XDP data plane rather than by an
	// upstream. Split out rather than folded into AnnouncedRoutes because the
	// operational question differs — an announced route can be rejected or
	// filtered by the peer and is only as good as the session, while these are
	// enforced locally and survive a BGP outage entirely.
	//
	// mode is the BAN's frozen dry-run flag, matching AnnouncedRoutes. Note that
	// a dry-run ban never reaches the installer at all (announceMethodLocked
	// returns before it), so mode="dry_run" here means "would have installed",
	// exactly as it means "would have announced" on the other gauges.
	MitigateDataplaneBans = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "dataplane_bans",
		Help:      "Bans currently enforced by the local XDP data plane, by mode (real|dry_run).",
	}, []string{"mode"})

	// MitigateDataplaneRules is FlowSpecRules' counterpart for the `dataplane`
	// rung: the rules those bans installed into the kernel. One ban carries
	// several rules, so this exceeds MitigateDataplaneBans — watch it against
	// dataplane.limits.max_dynamic_rules the way flowspec_rules is watched
	// against an upstream's route limit.
	//
	// This is the MITIGATOR's account of what it INTENDED, keyed by the ban that
	// owns it and filed under that ban's frozen dry-run flag. DataplaneRules is
	// the MEASURED total actually in the kernel maps (statics included), filed
	// under the datapath's own flag.
	//
	// The two agree only under mode="real". Under dry-run they diverge BY
	// DESIGN and permanently: announceMethodLocked returns before the installer,
	// so nothing enters the maps, and app/dpcounters skips dry-run bans outright
	// — so this gauge reports the rules that WOULD have been installed while
	// DataplaneRules' dynamic half stays flat at zero. Only the real bucket is
	// worth alerting on; a real-mode divergence means a withdraw failed or the
	// kernel expired rules out from under a ban that still believes it is
	// mitigating.
	MitigateDataplaneRules = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "dataplane_rules",
		Help:      "Rules installed in the local XDP data plane by active bans, by mode (real|dry_run).",
	}, []string{"mode"})

	// MitigateSourceBlocks counts live operator/API source blocks (the
	// source→victim pairs installed via POST /api/v1/dataplane/sources), by the
	// pair's frozen dry-run flag. Same mode semantics as the gauges above:
	// mode="dry_run" means "recorded, would have installed, installed nothing".
	MitigateSourceBlocks = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "source_blocks",
		Help:      "Live API-installed source blocks (source→victim pairs), by mode (real|dry_run).",
	}, []string{"mode"})

	// MitigateSourceBlocksRejected counts source-block requests refused by
	// policy — not input validation, which is the caller's bug, but the
	// refusals an operator should see trending: an exporter aiming at an
	// allowlisted source, a full policy block, an absent data plane.
	MitigateSourceBlocksRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "mitigate",
		Name:      "source_blocks_rejected_total",
		Help:      "Source-block requests refused by policy, by reason.",
	}, []string{"reason"})

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

// Data-plane (XDP) metrics.
//
// The lifecycle ones exist because of an asymmetry: every other component in
// kapkan fails in a way an operator eventually notices, while an XDP program
// that is not attached looks exactly like one that is — the daemon is up, the
// API answers, bans are recorded — and the only visible difference is that the
// packets the operator asked to drop are not dropped. So "is it attached" is a
// first-class metric and not an inference from a log line at boot.
var (
	// DataplaneXDPMode is 1 for the mode actually in force on an interface and 0
	// for the other, so a mode change (auto falling back from native to generic
	// across a restart) does not leave a stale series claiming both. When an
	// interface is not attached at all, BOTH series read 0 — which is the
	// difference between "filtering on the generic path" and "not filtering".
	DataplaneXDPMode = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "xdp_mode",
		Help:      "1 when the XDP program is attached to this interface in this mode (native|generic), else 0.",
	}, []string{"interface", "mode"})

	// DataplaneDegraded is the single number to alert on: any configured
	// interface not filtering.
	DataplaneDegraded = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "degraded",
		Help:      "1 when at least one configured interface has no live XDP attachment.",
	})

	// DataplaneAttachErrorsTotal counts failed attach attempts, including the
	// watcher's retries. A rising counter with degraded=1 is a NIC that will not
	// take the program; a rising counter with degraded=0 is a flapping link that
	// is being recovered.
	DataplaneAttachErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "attach_errors_total",
		Help:      "Failed XDP attach attempts, by interface.",
	}, []string{"interface"})

	// DataplaneReattachTotal counts successful re-attachments after a loss,
	// which is the metric that makes an intermittent NIC visible: the box looks
	// healthy at every scrape and this counter says it was not.
	DataplaneReattachTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "reattach_total",
		Help:      "Times the XDP program was re-attached to an interface after losing the attachment.",
	}, []string{"interface"})

	// DataplaneMapEntries and DataplaneMapBytes report what dataplane.limits
	// actually bought. They are the feedback loop for sizing MemoryMax= on the
	// unit: the maps are charged to the unit's memory cgroup in one step at
	// load, so an operator lowering max_ratelimit_sources needs to see the
	// result rather than infer it.
	DataplaneMapEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "map_entries",
		Help:      "max_entries of each BPF map as created, after dataplane.limits were applied.",
	}, []string{"map"})

	// DataplaneMapBytes is the kernel's own footprint estimate per map.
	DataplaneMapBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "map_bytes",
		Help:      "Kernel footprint estimate per BPF map, in bytes (the memlock field of map fdinfo).",
	}, []string{"map"})

	// DataplanePinsRebuilt is 1 when this process found an existing pinned
	// program and REJECTED it, so the pins were torn down and rebuilt. That
	// discards every dynamic rule the previous process had installed, which is
	// the one piece of data-plane state a restart cannot otherwise lose.
	DataplanePinsRebuilt = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "pins_rebuilt",
		Help:      "1 when an existing pinned program was rejected and rebuilt at startup (dynamic rules were lost).",
	})

	// DataplaneShadowedStaticRules is how many config static rules can never
	// fire, because the allowlist or an earlier static rule already takes every
	// packet they select. 0 is the only healthy value and it is worth an alert
	// at any other, because this defect has NO other symptom: the rule's own
	// counter stays at zero, which is what a correct rule looks like when its
	// traffic has not arrived. Republished on every policy apply, so it clears
	// on the reload that fixes the config.
	DataplaneShadowedStaticRules = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "shadowed_static_rules",
		Help:      "Config static rules that can never fire (covered by the allowlist or by an earlier rule).",
	})

	// DataplanePacketsTotal counts packets the datapath reached a TERMINAL
	// verdict on, by verdict name (pass_default, drop_static, drop_rl, ...).
	//
	// Only terminal verdicts appear here, and that is load-bearing. kapkan_stats
	// also carries OBSERVATION counters (dryrun_would_drop, pass_rule_expired,
	// pass_frag_noports, err_policy_missing) which are bumped ALONGSIDE a
	// terminal counter for the same packet — see dataplane.Stat.IsObservation.
	// Exporting them under the same metric name would make the obvious query,
	// sum(rate(kapkan_dataplane_packets_total[1m])), silently over-count every
	// packet that tripped one. With observations split out into
	// DataplaneObservationsTotal, that sum is exactly "packets through the
	// datapath" and the ratio of drop_* to it is exactly the drop rate.
	//
	// NOTE for whoever reads a graph across a restart: this counter starts at
	// zero with the process, while the kernel maps it is fed from do NOT (an
	// adopted pin set carries the previous process's totals). The scraper seeds
	// its baseline from the first read, so what is published is what THIS process
	// observed. That keeps rate() correct at startup instead of producing a spike
	// the width of the previous process's whole lifetime. The absolute kernel
	// totals are on /api/v1/status for anyone who needs them.
	DataplanePacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "packets_total",
		Help:      "Packets by terminal XDP verdict (see also observations_total, which double-counts by design).",
	}, []string{"verdict"})

	// DataplaneBytesTotal is DataplanePacketsTotal's byte accumulator. A pps
	// graph alone cannot tell a 64-byte SYN flood from a 1500-byte amplification
	// reflection, and the two call for different responses.
	DataplaneBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "bytes_total",
		Help:      "Bytes by terminal XDP verdict.",
	}, []string{"verdict"})

	// DataplaneObservationsTotal counts the annotations that accompany a terminal
	// verdict rather than replacing it. Kept out of packets_total so that summing
	// packets_total is honest; see the comment there.
	//
	// dryrun_would_drop is the one an operator watches during a dry run: it is
	// the number of packets that WOULD have been dropped, and it is the whole
	// argument for turning dry_run off.
	DataplaneObservationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "observations_total",
		Help:      "Datapath observations that co-occur with a terminal verdict (dryrun_would_drop, pass_rule_expired, ...).",
	}, []string{"kind"})

	// DataplaneFilterBypassPacketsTotal is an ALARM, and the only counter in this
	// file that is meant to page somebody.
	//
	// It counts packets the datapath forwarded WITHOUT EVALUATING A SINGLE RULE,
	// because they hit a parser limit before the rule scan started. Every other
	// pass_* verdict means "the rules ran and none said drop"; this one means the
	// rules never ran. An attacker who can build such a packet has, for that
	// packet, switched the filter off — allow-lists, drop rules and rate limits
	// alike.
	//
	// reason="ipv6_exthdr_cap" is the one class today: eight or more IPv6
	// extension headers, which is dataplane.MaxIPv6ExtHdrs. See
	// dataplane.Stat.BypassReason for why that class and not the other parse
	// limit, and engine/deploy/dataplane-operations.md for what to do about it.
	//
	// The packet is PASSED, not dropped, by charter — a parse budget must never
	// become a default-deny — so this metric is the entire mitigation, and the
	// alert threshold is zero:
	//
	//	sum(rate(kapkan_dataplane_filter_bypass_packets_total[5m])) > 0
	//
	// It DUPLICATES a series already published as
	// kapkan_dataplane_packets_total{verdict="pass_exthdr_cap"}. That is
	// deliberate and it is not a double count of traffic: packets_total still
	// partitions the traffic exactly once, and this is a second, named view of
	// one of its members, lifted out so an alert rule can name the thing it
	// means instead of a parser statistic. Never add the two together.
	DataplaneFilterBypassPacketsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "filter_bypass_packets_total",
		Help:      "ALARM: packets PASSED without any rule being evaluated, because they hit a datapath parse limit (possible filter evasion). Alert on any non-zero rate.",
	}, []string{"reason"})

	// DataplaneFilterBypassBytesTotal is the byte accumulator for the above. It
	// separates a probe from a flood: a handful of crafted packets an hour is
	// somebody measuring your parser, and a sustained bitrate is the attack that
	// measurement was for.
	DataplaneFilterBypassBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "filter_bypass_bytes_total",
		Help:      "Bytes PASSED without any rule being evaluated, by bypass reason.",
	}, []string{"reason"})

	// DataplaneRules is the number of rules the kernel is enforcing, split by
	// mode exactly as mitigate.FlowSpecRules is — so "how much is real and how
	// much is simulated" is the same question with the same answer shape whether
	// the enforcement point is an upstream router or this box's NIC.
	//
	// dry_run here is the DATAPATH's flag read back from kapkan_cfg, not the
	// global config's: an adopted pin set can be running the previous process's
	// flag, and a rule count filed under the wrong mode would state the opposite
	// of the truth about whether traffic is being dropped.
	//
	// This is the TOTAL — config statics plus the mitigator's dynamic rules —
	// and it is measured, not intended: the static half is read back from
	// kapkan_cfg and the dynamic half comes from the ban counter scraper's walk
	// of the kernel maps. It answers "how many rules is this box actually
	// running", which is the question that matters against the map sizing.
	//
	// MitigateDataplaneRules answers the neighbouring question — what the
	// MITIGATOR believes it installed, attributed to the bans that own it — and
	// its value should track this gauge's dynamic half. They are deliberately two
	// gauges and not one: a lasting divergence is a real fault, and a single
	// summed number is exactly where such a fault would hide.
	DataplaneRules = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "rules",
		Help:      "Rules currently installed in the kernel (static + mitigator dynamic, as measured), by mode (real|dry_run).",
	}, []string{"mode"})

	// DataplanePolicyGeneration is the live half of the double buffer. It is not
	// interesting in itself; its RATE is. kapkan_statics and kapkan_policies flip
	// together, so a generation climbing once per second means something is
	// republishing static policy in a loop, and every flip walks the policy map.
	DataplanePolicyGeneration = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "policy_generation",
		Help:      "The generation of the double-buffered policy currently live in the kernel.",
	})

	// DataplanePolicyApplySeconds times one build-and-publish of static policy:
	// encode, write the inactive generation, mirror the dynamic policy blocks,
	// flip. It bounds how long a config reload holds the Manager lock, and that
	// lock also serialises rule installs — so this histogram is the answer to
	// "could a reload have delayed mitigating an attack?".
	DataplanePolicyApplySeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "kapkan",
		Subsystem: "dataplane",
		Name:      "policy_apply_seconds",
		Help:      "Time to build and publish one generation of static policy (holds the lock that serialises rule installs).",
		Buckets:   prometheus.ExponentialBuckets(1e-4, 4, 10),
	})
)

// SetDataplaneAttached records the attachment state of one interface, writing
// both modes so the series never claims two at once.
//
// Writing the zero for the mode NOT in force matters more than it looks: under
// xdp_mode: auto an interface can come back on the generic path after a flap,
// and a bare Set on the new mode would leave the old series reading 1 forever —
// a dashboard would show one NIC attached twice, in two modes, one of which is a
// lie.
func SetDataplaneAttached(iface, mode string, attached bool) {
	for _, m := range []string{"native", "generic"} {
		v := 0.0
		if attached && m == mode {
			v = 1
		}
		DataplaneXDPMode.WithLabelValues(iface, m).Set(v)
	}
}

// SetDataplaneRules files the installed-rule count under the mode the DATAPATH
// is actually in, zeroing the other, mirroring mitigate's updateGaugeLocked.
func SetDataplaneRules(rules int, dryRun bool) {
	real, dry := float64(rules), 0.0
	if dryRun {
		real, dry = 0, float64(rules)
	}
	DataplaneRules.WithLabelValues("real").Set(real)
	DataplaneRules.WithLabelValues("dry_run").Set(dry)
}

// dpCounters tracks the last absolute value seen for each kernel counter so the
// scraper can turn absolute reads into the deltas a Prometheus counter needs.
//
// A Prometheus counter can only be incremented, and the kernel's per-CPU arrays
// can only be read absolutely, so something has to hold the previous value.
// Doing it here rather than in the scraper keeps it next to the collectors it
// feeds, and keeps the scraper a pure function of one Stats() call.
var dpCounters = struct {
	mu   sync.Mutex
	last map[string]uint64
}{last: map[string]uint64{}}

// AddDataplaneVerdict publishes one terminal verdict's ABSOLUTE kernel counters,
// converting them to Prometheus counter deltas.
//
// First sight of a key seeds the baseline and publishes nothing: see the note on
// DataplanePacketsTotal for why an adopted pin set must not dump the previous
// process's lifetime totals into a fresh counter as one spike.
//
// A value that went DOWN can only mean the counters were reset under us (pins
// rebuilt, a map recreated). Add() would panic on a negative delta, so this
// re-seeds and publishes nothing rather than taking the process down over a
// metric.
func AddDataplaneVerdict(verdict string, packets, bytes uint64) {
	if d := dpAdvance("pkt/"+verdict, packets); d > 0 {
		DataplanePacketsTotal.WithLabelValues(verdict).Add(d)
	}
	if d := dpAdvance("byt/"+verdict, bytes); d > 0 {
		DataplaneBytesTotal.WithLabelValues(verdict).Add(d)
	}
}

// AddDataplaneObservation is AddDataplaneVerdict for the co-occurring
// observation counters, which are deliberately a different metric family.
func AddDataplaneObservation(kind string, packets uint64) {
	if d := dpAdvance("obs/"+kind, packets); d > 0 {
		DataplaneObservationsTotal.WithLabelValues(kind).Add(d)
	}
}

// AddDataplaneFilterBypass publishes the absolute kernel counters for one
// filter-bypass class, converting them to Prometheus counter deltas.
//
// It uses its own dpAdvance keys rather than sharing the verdict's, because the
// same kernel counter feeds both this metric and packets_total and each needs
// its own baseline; sharing one would make whichever published second see a zero
// delta forever.
// Unlike the verdict counters, both series are MATERIALISED on every call even
// when nothing has moved, so a data plane that has never been bypassed publishes
// an explicit zero rather than no series at all. That distinction is the whole
// difference between a dashboard panel that says "0" and one that says "No
// data" — and between an alert an operator trusts and one they cannot tell is
// wired up.
func AddDataplaneFilterBypass(reason string, packets, bytes uint64) {
	pkts := DataplaneFilterBypassPacketsTotal.WithLabelValues(reason)
	byts := DataplaneFilterBypassBytesTotal.WithLabelValues(reason)
	if d := dpAdvance("byp.pkt/"+reason, packets); d > 0 {
		pkts.Add(d)
	}
	if d := dpAdvance("byp.byt/"+reason, bytes); d > 0 {
		byts.Add(d)
	}
}

// dpAdvance returns the delta to add for an absolute reading, seeding on first
// sight and on any decrease.
func dpAdvance(key string, absolute uint64) float64 {
	dpCounters.mu.Lock()
	defer dpCounters.mu.Unlock()
	prev, seen := dpCounters.last[key]
	dpCounters.last[key] = absolute
	if !seen || absolute < prev {
		return 0
	}
	return float64(absolute - prev)
}

// ResetDataplaneCounterBaseline forgets every counter baseline, so the next
// publish re-seeds instead of emitting a delta. Called when the map set is
// replaced (pins rebuilt) — the counters restart at zero there and the stale
// baseline would swallow real traffic until the kernel counter climbed past it.
func ResetDataplaneCounterBaseline() {
	dpCounters.mu.Lock()
	defer dpCounters.mu.Unlock()
	dpCounters.last = map[string]uint64{}
}

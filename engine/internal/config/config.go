// Package config loads, validates and hot-reloads the kapkan YAML
// configuration. Load returns an immutable *Config; consumers that support
// hot reload hold a Store and read a fresh snapshot per evaluation cycle.
package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// errStatDeferred marks a filesystem check (geoip database, exec-hook path) that
// the browser/wasm build cannot perform; statFile returns it there and the
// validate() call sites skip the check, leaving it to the server at load.
var errStatDeferred = errors.New("file check deferred to server-side load")

// Config is the root of the kapkan configuration. Fields mirror the YAML
// shape exactly; parsed derivatives (prefixes, addresses, community value)
// are populated during validation and must not be set by hand.
type Config struct {
	DryRun   bool     `yaml:"dry_run"`
	Listen   Listen   `yaml:"listen"`
	Sampling Sampling `yaml:"sampling"`
	// FlowSources optionally allowlists the trusted flow-exporter source
	// addresses. Telemetry arrives over unauthenticated UDP, so the exporter
	// (source) address is spoofable; when this list is set, only telemetry
	// from a listed source is labeled by exporter on the packets_total metric
	// and everything else is bucketed under "other", bounding metric
	// cardinality. When empty a hard cap on distinct exporter labels provides
	// the same protection automatically. It does not affect detection.
	FlowSources        []string   `yaml:"flow_sources"`
	Networks           []string   `yaml:"networks"`
	ProtectedWhitelist []string   `yaml:"protected_whitelist"`
	Thresholds         Thresholds `yaml:"thresholds"`
	// ThresholdsOutgoing enables detection of attacks ORIGINATED by
	// protected hosts (compromised machines). Absent, outgoing traffic is
	// not even counted.
	ThresholdsOutgoing *Thresholds `yaml:"thresholds_outgoing"`
	// Baseline enables continuous per-host learned thresholds; static
	// thresholds remain as floor/ceiling guards.
	Baseline *Baseline `yaml:"baseline"`
	// Carpet enables carpet-bombing (subnet-spread) detection; absent disables
	// it. See the Carpet type.
	Carpet *Carpet `yaml:"carpet"`
	// Mitigation selects the default mitigation method (blackhole|flowspec);
	// hostgroups may override it.
	Mitigation string `yaml:"mitigation"`
	// FlowSpec is the default FlowSpec action policy, used by groups whose
	// method is flowspec.
	FlowSpec *FlowSpec `yaml:"flowspec"`
	// Escalation is the default mitigation ladder; when set it supersedes
	// the single `mitigation` method. Hostgroups may override it.
	Escalation []EscalationStep `yaml:"escalation"`
	// Tenant optionally labels the implicit global/fallback group, attributing
	// catch-all traffic to a tenant (see Hostgroup.Tenant). Empty = unlabeled
	// (admin-only visibility).
	Tenant     string      `yaml:"tenant"`
	Hostgroups []Hostgroup `yaml:"hostgroups"`
	Samples    Samples     `yaml:"samples"`
	Storage    Storage     `yaml:"storage"`
	GeoIP      GeoIP       `yaml:"geoip"`
	Ban        Ban         `yaml:"ban"`
	BGP        BGP         `yaml:"bgp"`
	// Scrubbing is the default traffic-diversion target (scrubbing center
	// next-hops + divert community), used by groups whose ladder diverts.
	Scrubbing Scrubbing `yaml:"scrubbing"`
	// Dataplane enables the in-kernel XDP filter, letting this instance drop
	// attack traffic on its own interfaces instead of only announcing routes.
	// Absent (nil) disables it entirely and the binary behaves exactly as it
	// does without the feature. Required when any ladder uses the dataplane
	// action or method.
	Dataplane *Dataplane `yaml:"dataplane"`
	// Edge is the edge track's brain-side block (edge-spec §2.3/§4, E3): the
	// zones file this brain serves to edge nodes and the nodes allowed to poll
	// it. Absent (the default) it is off entirely: the edge routes serve an
	// empty document and no other block references it.
	Edge *Edge `yaml:"edge"`
	// ZonesCfg is the loaded zones file named by Edge.ZonesFile — populated by
	// Load, NEVER by Parse (which must stay pure for the browser-side
	// validator), so it is nil unless the daemon was started or reloaded from a
	// file whose edge.zones_file was read and validated in full.
	ZonesCfg    *Zones      `yaml:"-"`
	Notify      Notify      `yaml:"notify"`
	API         API         `yaml:"api"`
	UpdateCheck UpdateCheck `yaml:"update_check"`

	// Parsed forms, populated by validate().
	NetworkPrefixes []netip.Prefix `yaml:"-"`
	WhitelistAddrs  []netip.Addr   `yaml:"-"`
	// protectedAddrs4/6 are the total address counts of the protected networks
	// per family (float64 because an IPv6 range exceeds uint64), populated in
	// validate() and read by the mitigator's blast-radius fraction guard.
	protectedAddrs4 float64
	protectedAddrs6 float64
	// FlowSourceSet is the parsed FlowSources allowlist. Empty/nil means no
	// allowlist is configured (the exporter-label cardinality cap applies).
	FlowSourceSet map[netip.Addr]struct{} `yaml:"-"`
	// boundary is the resolved sampling.boundary config, keyed by exporter
	// address. nil/empty means interface-boundary counting is disabled (every
	// sample counted). Populated by validate().
	boundary map[netip.Addr]exporterBoundary `yaml:"-"`
	// Groups are the resolved hostgroups; Groups[0] is always the implicit
	// global fallback group carrying the top-level thresholds.
	Groups []Group `yaml:"-"`
	// OutgoingEnabled reports whether any group has outgoing thresholds, so
	// the engine can skip outgoing accounting entirely when unused.
	OutgoingEnabled bool `yaml:"-"`
	// SampleCfg is the resolved (defaults applied) form of Samples. It is
	// comparable so reload can detect changes that require a restart.
	SampleCfg SampleSettings `yaml:"-"`
	// StorageCfg is the resolved ClickHouse configuration.
	StorageCfg StorageSettings `yaml:"-"`
	// GeoIPCfg is the resolved GeoIP/ASN configuration. It is comparable so
	// reload can detect database-path changes that require a restart.
	GeoIPCfg GeoIPSettings `yaml:"-"`
	// DataplaneCfg is the resolved XDP data-plane configuration. It is
	// comparable so reload can detect the changes that require a restart
	// (attachment and map sizing); the policy itself hot-reloads.
	DataplaneCfg DataplaneSettings `yaml:"-"`
	// DataplaneAllowlist is the parsed dataplane.allowlist — SOURCE prefixes
	// the datapath passes before evaluating any rule. Kept off DataplaneCfg
	// because a slice would break its ==-comparability; kept parsed here so
	// callers can refuse to aim a dynamic rule at an allowlisted source (the
	// kernel would install it and then silently never match it).
	DataplaneAllowlist []netip.Prefix `yaml:"-"`
	// groupRoutes maps prefixes to Groups indexes, longest prefix first.
	groupRoutes []groupRoute
}

// Listen holds the UDP listen addresses for flow ingestion.
type Listen struct {
	SFlow   string `yaml:"sflow"`
	NetFlow string `yaml:"netflow"`
}

// Sampling controls sampling-rate handling.
type Sampling struct {
	// DefaultRate is used when an exporter does not report its own rate.
	DefaultRate uint64 `yaml:"default_rate"`
	// Boundary optionally enables interface-boundary counting, which
	// deduplicates a flow seen at multiple sampling vantage points (redundant
	// exporters, ingress+egress sampling, transit/peer-links). Each entry
	// classifies one exporter's external/edge interfaces; a flow is then
	// counted toward a protected host only when it crosses the boundary —
	// inbound when its input interface is external, outbound when its output
	// interface is external. Exporters without an entry keep legacy behavior
	// (every sample counted), so this is safe to enable per exporter.
	Boundary []ExporterBoundary `yaml:"boundary"`
	// BoundaryDebug, when true, exports the
	// kapkan_boundary_debug_bytes_total{exporter,iface,dir} metric: the
	// sampling-corrected bytes seen toward/from protected hosts, broken down
	// by exporter and interface. It is a discovery aid for picking the
	// external interfaces to list under Boundary; enable it briefly, read the
	// breakdown, then turn it off (the metric is not cardinality-bounded).
	BoundaryDebug bool `yaml:"boundary_debug"`
}

// ExporterBoundary classifies the external (edge/uplink/border) interfaces of
// one flow exporter for interface-boundary counting. See Sampling.Boundary.
type ExporterBoundary struct {
	// Exporter is the sampler/agent IP this rule applies to.
	Exporter string `yaml:"exporter"`
	// ExternalIfindexes are the ifIndex values of that exporter's external
	// interfaces (the uplinks/border ports where traffic enters/leaves the
	// protected network).
	ExternalIfindexes []uint32 `yaml:"external_ifindexes"`
	// EgressSampling marks an exporter that also samples on egress (e.g.
	// Arista `sflow sample output`), which makes every boundary-crossing
	// packet appear twice. When true, the sampling rate of boundary-counted
	// traffic for this exporter is halved, correcting the double back to one.
	EgressSampling bool `yaml:"egress_sampling"`
}

// exporterBoundary is the resolved, lookup-ready form of one ExporterBoundary.
type exporterBoundary struct {
	external map[uint32]struct{}
	egress   bool
}

// Thresholds are per-host limits after sampling correction. The base trio
// (pps/mbps/flows_per_sec) must be > 0 in an incoming threshold set; the
// per-protocol limits default to 0, which disables them. Any crossed
// threshold triggers detection (they are OR-ed).
type Thresholds struct {
	PPS         uint64 `yaml:"pps" json:"pps"`
	Mbps        uint64 `yaml:"mbps" json:"mbps"`
	FlowsPerSec uint64 `yaml:"flows_per_sec" json:"flows_per_sec"`

	TCPPPS     uint64 `yaml:"tcp_pps" json:"tcp_pps,omitempty"`
	TCPMbps    uint64 `yaml:"tcp_mbps" json:"tcp_mbps,omitempty"`
	UDPPPS     uint64 `yaml:"udp_pps" json:"udp_pps,omitempty"`
	UDPMbps    uint64 `yaml:"udp_mbps" json:"udp_mbps,omitempty"`
	ICMPPPS    uint64 `yaml:"icmp_pps" json:"icmp_pps,omitempty"`
	ICMPMbps   uint64 `yaml:"icmp_mbps" json:"icmp_mbps,omitempty"`
	TCPSYNPPS  uint64 `yaml:"tcp_syn_pps" json:"tcp_syn_pps,omitempty"`
	TCPSYNMbps uint64 `yaml:"tcp_syn_mbps" json:"tcp_syn_mbps,omitempty"`
	FragPPS    uint64 `yaml:"frag_pps" json:"frag_pps,omitempty"`
	FragMbps   uint64 `yaml:"frag_mbps" json:"frag_mbps,omitempty"`
}

// Zero reports whether no threshold is set at all.
func (t Thresholds) Zero() bool { return t == Thresholds{} }

// Samples configures the traffic buffer used to attach flow samples to
// attack events. Fields mirror the YAML shape; the resolved form (defaults
// applied) lives in Config.SampleCfg.
type Samples struct {
	// Enabled defaults to true; set false to disable the buffer entirely.
	Enabled *bool `yaml:"enabled"`
	// BufferFlows is the total capacity of the recent-flows ring across the
	// engine (default 65536, max 1048576). More flows = better samples at
	// high rates, at roughly 120 bytes per slot of fixed memory.
	BufferFlows int `yaml:"buffer_flows"`
	// FlowsPerAttack caps the raw flow records attached to one attack
	// event (default 20).
	FlowsPerAttack int `yaml:"flows_per_attack"`
}

// SampleSettings is the resolved, comparable form of Samples.
type SampleSettings struct {
	Enabled        bool
	BufferFlows    int
	FlowsPerAttack int
}

// Storage configures optional long-term persistence. ClickHouse is the only
// backend; absent, kapkan keeps everything in-process (live data only).
type Storage struct {
	ClickHouse ClickHouse `yaml:"clickhouse"`
}

// ClickHouse configures the optional ClickHouse writer. kapkan talks to the
// server's HTTP interface with the standard library — no driver dependency.
// Credentials are read from the environment, never the config file.
type ClickHouse struct {
	// URL is the ClickHouse HTTP endpoint, e.g. "http://127.0.0.1:8123".
	// Empty disables persistence entirely.
	URL         string `yaml:"url"`
	Database    string `yaml:"database"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
	// TTLDays is how long rows are retained (default 7).
	TTLDays int `yaml:"ttl_days"`
	// FlushIntervalSeconds bounds how long a batch waits before being sent
	// (default 5).
	FlushIntervalSeconds int `yaml:"flush_interval_seconds"`
	// BatchSize flushes early once this many rows are queued (default 1000).
	BatchSize int `yaml:"batch_size"`
	// QueueSize bounds the in-memory row buffer; rows are dropped (and
	// counted) when it is full so storage never blocks detection (default
	// 100000).
	QueueSize int `yaml:"queue_size"`
	// TrafficIntervalSeconds is how often a per-host/per-group traffic
	// snapshot is persisted (default 10).
	TrafficIntervalSeconds int `yaml:"traffic_interval_seconds"`
}

// StorageSettings is the resolved ClickHouse configuration.
type StorageSettings struct {
	Enabled         bool
	URL             string
	Database        string
	UsernameEnv     string
	PasswordEnv     string
	TTLDays         int
	FlushInterval   time.Duration
	BatchSize       int
	QueueSize       int
	TrafficInterval time.Duration
}

// GeoIP configures optional GeoIP/ASN attribution of attack-sample sources
// against MaxMind GeoLite2 (or GeoIP2) databases. Both database paths are
// optional and independent; the feature is off unless enabled with at least
// one database. Fields mirror the YAML shape; the resolved form lives in
// Config.GeoIPCfg.
type GeoIP struct {
	// Enabled turns ASN/country enrichment on. Default off.
	Enabled bool `yaml:"enabled"`
	// ASNDatabase is the path to a GeoLite2-ASN.mmdb file (AS number + org).
	ASNDatabase string `yaml:"asn_database"`
	// CountryDatabase is the path to a GeoLite2-Country.mmdb (or City) file.
	CountryDatabase string `yaml:"country_database"`
}

// GeoIPSettings is the resolved, comparable form of GeoIP.
type GeoIPSettings struct {
	Enabled     bool
	ASNPath     string
	CountryPath string
}

// Baseline configures continuous EWMA-learned per-host thresholds. Fields
// mirror the YAML shape; the resolved form lives in BaselineSettings.
type Baseline struct {
	// Enabled defaults to true when the block is present.
	Enabled *bool `yaml:"enabled"`
	// Factor multiplies the learned baseline into the effective threshold
	// (default 3): traffic above baseline*factor is an attack.
	Factor float64 `yaml:"factor"`
	// HalfLifeSeconds is the EWMA half-life (default 3600): how long until
	// a sustained change moves the baseline halfway to the new level.
	HalfLifeSeconds int `yaml:"half_life_seconds"`
	// WarmupSeconds is how long a host must be observed before its
	// baseline gates detection (default 600). Until then only the static
	// thresholds apply.
	WarmupSeconds int `yaml:"warmup_seconds"`
	// Floor is the minimum effective threshold per metric — a quiet host's
	// tiny baseline must not make detection hair-trigger. Required.
	Floor BaselineFloor `yaml:"floor"`
}

// BaselineFloor bounds the effective thresholds from below.
type BaselineFloor struct {
	PPS         uint64 `yaml:"pps" json:"pps"`
	Mbps        uint64 `yaml:"mbps" json:"mbps"`
	FlowsPerSec uint64 `yaml:"flows_per_sec" json:"flows_per_sec"`
}

// BaselineSettings is the resolved form of Baseline used by the engine.
type BaselineSettings struct {
	Factor float64 `json:"factor"`
	// Alpha is the derived per-second EWMA weight: 1 - 2^(-1/half_life).
	Alpha         float64       `json:"-"`
	WarmupSeconds int           `json:"warmup_seconds"`
	Floor         BaselineFloor `json:"floor"`
}

// MitigationMethod selects how an attack is mitigated.
type MitigationMethod string

// Mitigation methods.
const (
	// MitigateBlackhole announces an RTBH /32 or /128 — drops ALL traffic to
	// the victim (the default; takes the victim offline).
	MitigateBlackhole MitigationMethod = "blackhole"
	// MitigateFlowSpec announces BGP FlowSpec rules matching the attack
	// vector — surgical drops that can spare the victim's legitimate
	// traffic. Requires upstreams that honor FlowSpec.
	MitigateFlowSpec MitigationMethod = "flowspec"
	// MitigateDivert announces the victim host route toward a scrubbing center
	// (the scrubbing.next_hop + divert community) so traffic is cleaned and
	// reinjected rather than dropped. Shares the RTBH host-route NLRI.
	MitigateDivert MitigationMethod = "divert"
	// MitigateDataplane installs the attack's match rules into the local
	// in-kernel XDP data plane, dropping (or rate-limiting) the attack on this
	// box instead of asking a BGP peer to do it. The most surgical method and
	// the only one that needs no router cooperation — but it can only act on
	// traffic that actually reaches this machine's NIC, so it does not help
	// once the uplink itself is saturated. Requires the dataplane block.
	MitigateDataplane MitigationMethod = "dataplane"
)

// FlowSpecAction is the action attached to generated FlowSpec rules.
type FlowSpecAction string

// FlowSpec actions.
const (
	// FlowSpecDiscard drops every packet matching a rule (traffic-rate 0).
	FlowSpecDiscard FlowSpecAction = "discard"
	// FlowSpecRateLimit caps matching traffic at a configured rate.
	FlowSpecRateLimit FlowSpecAction = "rate_limit"
)

// EscalationAction is one rung of a mitigation ladder.
type EscalationAction string

// Escalation actions.
const (
	// EscalateNone alerts only — no route is announced at this stage.
	EscalateNone EscalationAction = "none"
	// EscalateDataplane installs the attack's match rules into the local XDP
	// data plane at this stage. The most surgical rung: nothing is announced,
	// nothing leaves this box, and only traffic arriving on this machine's NIC
	// is affected — so it sits just above alert-only.
	EscalateDataplane EscalationAction = "dataplane"
	// EscalateFlowSpec announces FlowSpec rules at this stage.
	EscalateFlowSpec EscalationAction = "flowspec"
	// EscalateDivert announces the victim /32-/128 toward a scrubbing center
	// (its next-hop + divert community) so the traffic is cleaned rather than
	// dropped. Less destructive than a blackhole, stronger than flowspec.
	EscalateDivert EscalationAction = "divert"
	// EscalateBlackhole announces an RTBH route at this stage (drops all of the
	// victim's traffic) — the last-resort rung.
	EscalateBlackhole EscalationAction = "blackhole"
)

// EscalationStep is one configured rung of the ladder (YAML shape).
type EscalationStep struct {
	// AfterSeconds is the delay from attack start at which this rung
	// applies, provided the attack is still active. The first rung must be 0.
	AfterSeconds int `yaml:"after_seconds"`
	// Action is none | flowspec | blackhole.
	Action string `yaml:"action"`
}

// EscalationStage is one resolved rung used by the mitigator.
type EscalationStage struct {
	AfterSeconds int              `json:"after_seconds"`
	Action       EscalationAction `json:"action"`
}

// FlowSpec is the FlowSpec action policy. Fields mirror the YAML; the
// resolved per-second byte rate lives in Group.FlowSpecRateBps.
type FlowSpec struct {
	// Action is "discard" (default) or "rate_limit".
	Action string `yaml:"action"`
	// RateMbps is the rate-limit ceiling in megabits/sec; required and used
	// only when Action is rate_limit.
	RateMbps float64 `yaml:"rate_mbps"`
	// SourceAnchored, when true, lets a flowspec rule pin BOTH the victim as
	// destination AND a dominant attacker source (from the attack sample) so
	// only the attackers are filtered, sparing the victim's legitimate clients.
	// It applies only when the sample is concentrated enough (see
	// MinSourceConcentration); otherwise the rule falls back to victim-anchored.
	// Default false (victim-anchored, today's behavior).
	SourceAnchored bool `yaml:"source_anchored"`
	// MinSourceConcentration is the share (0–1) of sampled attack packets the
	// dominant sources must cover, within the rule budget, before source
	// anchoring is used instead of a victim-anchored rule. Omitted/0 defaults to
	// 0.8 when source_anchored is on; a diffuse attack (e.g. reflection from
	// thousands of sources) stays below it and falls back to victim-anchored.
	MinSourceConcentration float64 `yaml:"min_source_concentration"`
}

// Carpet configures carpet-bombing (subnet-spread) detection: an attack that
// distributes its volume across many hosts in a prefix, staying under each
// host's threshold so per-host detection never fires. When set, the engine
// folds every monitored per-host destination's incoming rates into its
// aggregation prefix and raises a prefix-scoped attack when the aggregate
// crosses Thresholds AND the traffic is spread across at least MinHosts
// distinct hosts. Absent (nil) disables it. Carpet attacks are alert-only by
// default; set Mitigation to auto-mitigate the aggregation prefix.
type Carpet struct {
	// AggregationPrefixV4/V6 are the supernet lengths per-host rates fold into
	// (defaults /24 and /48). A /24 with attack traffic spread across MinHosts
	// of its /32s raises one carpet attack on the /24.
	AggregationPrefixV4 int `yaml:"aggregation_prefix_v4"`
	AggregationPrefixV6 int `yaml:"aggregation_prefix_v6"`
	// MinHosts is the fan-out gate: at least this many distinct destination
	// hosts in the prefix must carry traffic this window before a carpet attack
	// fires, so a single heavy host (already caught per-host) is not reported as
	// a carpet bomb (default 10, minimum 2).
	MinHosts int `yaml:"min_hosts"`
	// Thresholds are the AGGREGATE volume thresholds for the whole prefix
	// (sampling-corrected, summed over its hosts). A zero metric is disabled; at
	// least one must be set. They should be well above the per-host thresholds.
	Thresholds Thresholds `yaml:"thresholds"`
	// Mitigation auto-mitigates the aggregation prefix: "" (the default) is
	// alert-only; "flowspec" announces a FlowSpec rule matching the attack
	// vector on the whole prefix (surgical — drops only the vector); "blackhole"
	// announces an RTBH route for the prefix (drops ALL of it). Either method
	// REFUSES a prefix that contains a protected_whitelist address — the
	// whitelist guarantee is absolute and a prefix mitigation cannot exempt a
	// single member. A diffuse attack still raises the alert regardless.
	Mitigation string `yaml:"mitigation"`
	// MaxActivePrefixBans caps simultaneous carpet (prefix) bans, separately from
	// ban.max_active_bans (host bans), so neither starves the other. Default 10.
	MaxActivePrefixBans int `yaml:"max_active_prefix_bans"`
}

// CarpetMethods returns every mitigation method a carpet-bomb detection may
// select, in documentation order.
//
// It is the SINGLE source of truth for three things that must never disagree:
// the validator (validateCarpet), the resolver (Carpet.Method) and the config
// schema enum (schema.go). When those were three hand-written lists, widening
// one of them was enough to make a method parse, resolve to "" and then be
// mitigated by something else entirely — which for a carpet ban means a whole
// /24 blackholed because the operator asked for a surgical kernel drop.
//
// Divert is deliberately absent: a carpet ban covers a whole aggregation
// prefix, and diverting a /24 into a scrubbing centre is a routing decision an
// operator makes deliberately, not one a detector should make automatically.
func CarpetMethods() []MitigationMethod {
	return []MitigationMethod{MitigateFlowSpec, MitigateBlackhole, MitigateDataplane}
}

// Method resolves carpet.mitigation to a MitigationMethod ("" = alert-only).
func (c Carpet) Method() MitigationMethod {
	for _, m := range CarpetMethods() {
		if c.Mitigation == string(m) {
			return m
		}
	}
	return ""
}

// CalcMethod selects how a hostgroup's thresholds are applied.
type CalcMethod string

// Hostgroup calculation methods.
const (
	// CalcPerHost evaluates every host in the group against the group's
	// thresholds individually.
	CalcPerHost CalcMethod = "per_host"
	// CalcTotal evaluates the summed traffic of the whole group. Total
	// groups alert only; they never trigger automatic bans because there is
	// no single host to blackhole.
	CalcTotal CalcMethod = "total"
)

// GlobalGroup is the name of the implicit fallback group that applies the
// top-level thresholds to hosts not matched by any configured hostgroup.
const GlobalGroup = "global"

// groupNameRe restricts hostgroup names to a log-, JSON- and header-safe
// charset.
var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// envNameRe matches a POSIX-ish environment variable name.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Hostgroup groups prefixes under a shared threshold set and mitigation
// policy. Fields mirror the YAML shape; the resolved form lives in
// Config.Groups.
type Hostgroup struct {
	Name     string   `yaml:"name"`
	Networks []string `yaml:"networks"`
	// Calculation is "per_host" (default) or "total".
	Calculation string `yaml:"calculation"`
	// Thresholds override the global thresholds; when omitted the group
	// inherits them.
	Thresholds *Thresholds `yaml:"thresholds"`
	// ThresholdsOutgoing overrides the global outgoing thresholds; when
	// omitted the group inherits them (or stays disabled if there are none).
	ThresholdsOutgoing *Thresholds `yaml:"thresholds_outgoing"`
	// Baseline overrides the global baseline block wholesale; when omitted
	// the group inherits it (or stays static-only if there is none).
	Baseline *Baseline `yaml:"baseline"`
	// Mitigation overrides the default method (blackhole|flowspec) for this
	// group; empty inherits the global default.
	Mitigation string `yaml:"mitigation"`
	// FlowSpec overrides the default FlowSpec action policy for this group.
	FlowSpec *FlowSpec `yaml:"flowspec"`
	// Escalation overrides the default mitigation ladder for this group;
	// when set it supersedes the group's `mitigation` method.
	Escalation []EscalationStep `yaml:"escalation"`
	// BGP overrides the blackhole BGP attributes (next-hop, communities,
	// local-pref) for this group; omitted fields inherit the global bgp block.
	BGP *BGPOverride `yaml:"bgp"`
	// Scrubbing overrides the divert target (scrubbing next-hop, communities,
	// local-pref) for this group; omitted fields inherit the global scrubbing
	// block.
	Scrubbing *BGPOverride `yaml:"scrubbing"`
	// Tenant optionally labels this group's owner. A tenant-scoped API token
	// sees and may mutate only data whose group carries its tenant. Empty =
	// unlabeled (visible only to unscoped/admin tokens).
	Tenant string `yaml:"tenant"`
	// Ban controls automatic RTBH for the group's hosts (default true).
	// Must not be set to true for total groups, which never auto-ban.
	Ban *bool `yaml:"ban"`
}

// Group is the resolved, immutable form of a hostgroup used by the engine.
type Group struct {
	Name       string     `json:"name"`
	Calc       CalcMethod `json:"calculation"`
	Thresholds Thresholds `json:"thresholds"`
	// OutThresholds is nil when outgoing detection is disabled for the group.
	OutThresholds *Thresholds `json:"thresholds_outgoing,omitempty"`
	// Baseline is nil when learned thresholds are disabled for the group.
	Baseline *BaselineSettings `json:"baseline,omitempty"`
	// Mitigation is the resolved method for this group.
	Mitigation MitigationMethod `json:"mitigation"`
	// FlowSpecAction and FlowSpecRateBps describe the action for generated
	// FlowSpec rules (rate is per-second bytes; 0 for discard).
	FlowSpecAction  FlowSpecAction `json:"flowspec_action,omitempty"`
	FlowSpecRateBps float64        `json:"-"`
	// FlowSpecSourceAnchored enables composite victim+attacker-source rules when
	// the attack sample is concentrated; FlowSpecMinConcentration is the gate.
	FlowSpecSourceAnchored   bool    `json:"flowspec_source_anchored,omitempty"`
	FlowSpecMinConcentration float64 `json:"-"`
	// Escalation is the resolved mitigation ladder; always at least one
	// stage (synthesized from Mitigation when not explicitly configured).
	Escalation []EscalationStage `json:"escalation,omitempty"`
	// Resolved blackhole BGP attributes (defaults inherited from the global
	// bgp block). BlackholeNextHop6 is "" when no IPv6 next-hop is configured;
	// the mitigator falls back to its IPv6 discard default. BlackholeCommunities
	// is the parsed community set, BlackholeCommunityStr its display form, and
	// LocalPref the LOCAL_PREF to attach (0 = omit).
	BlackholeNextHop      string   `json:"blackhole_next_hop,omitempty"`
	BlackholeNextHop6     string   `json:"blackhole_next_hop6,omitempty"`
	BlackholeCommunities  []uint32 `json:"-"`
	BlackholeCommunityStr string   `json:"blackhole_communities,omitempty"`
	LocalPref             uint32   `json:"blackhole_local_pref,omitempty"`
	// Resolved divert/scrubbing BGP attributes (defaults inherited from the
	// global scrubbing block). Populated only when the group's ladder diverts.
	ScrubNextHop      string   `json:"scrub_next_hop,omitempty"`
	ScrubNextHop6     string   `json:"scrub_next_hop6,omitempty"`
	ScrubCommunities  []uint32 `json:"-"`
	ScrubCommunityStr string   `json:"scrub_communities,omitempty"`
	ScrubLocalPref    uint32   `json:"scrub_local_pref,omitempty"`
	// Tenant is the resolved owner label (empty = unlabeled). Used only by the
	// API to scope what a tenant-scoped token may see and mutate; never read on
	// the hot path.
	Tenant     string `json:"tenant,omitempty"`
	BanEnabled bool   `json:"ban"`
}

// groupRoute maps one prefix to its owning group for longest-prefix-match
// lookup.
type groupRoute struct {
	prefix netip.Prefix
	group  int // index into Config.Groups
}

// Ban controls the lifecycle of blackhole announcements.
type Ban struct {
	TTLSeconds             int `yaml:"ttl_seconds"`
	UnbanHysteresisSeconds int `yaml:"unban_hysteresis_seconds"`
	MaxActiveBans          int `yaml:"max_active_bans"`
	// Fallback selects the mitigation method applied when a stage's primary
	// announce is rejected by the BGP peer. "blackhole" (the default) degrades a
	// failed flowspec/divert announce to an RTBH route so the victim is still
	// mitigated when an upstream does not honor the surgical method — leaving a
	// victim wholly undefended is the worse failure. "none" disables fallback (a
	// failed announce rejects the ban). Blackhole is terminal and has no fallback.
	Fallback string `yaml:"fallback"`
	// MaxBannedFraction caps the share of the protected address space (per
	// address family) that may be simultaneously blackholed, refusing new bans
	// once exceeded. A poisoned baseline or spoofed-source storm can drive many
	// distinct host bans — each under max_active_bans — that together null-route
	// a large fraction of your OWN network; this bounds that blast radius. The
	// range is (0,1]; 0 (the default) disables the guard.
	MaxBannedFraction float64 `yaml:"max_banned_fraction"`
	// MaxBansPerWindow caps how many NEW bans may be created within
	// ban_window_seconds, catching a runaway ban storm that the static
	// max_active_bans cap (a level, not a rate) cannot. 0 (the default) disables
	// the guard.
	MaxBansPerWindow int `yaml:"max_bans_per_window"`
	// BanWindowSeconds is the window for max_bans_per_window; required (> 0)
	// when that rate is set and ignored otherwise.
	BanWindowSeconds int `yaml:"ban_window_seconds"`
	// StateFile is a writable path where active bans are persisted so they can be
	// rehydrated and re-announced on startup — paired with BGP Graceful Restart,
	// this keeps mitigation up across a restart (e.g. an upgrade) instead of
	// dropping it until the engine re-detects. Empty (the default) disables
	// persistence. The directory must be writable by the kapkan user (the hardened
	// systemd unit provides one via StateDirectory=kapkan → /var/lib/kapkan); a
	// missing/unwritable path degrades gracefully to no persistence, never a
	// startup failure.
	StateFile string `yaml:"state_file"`
}

// TTL returns the ban TTL as a duration.
func (b Ban) TTL() time.Duration { return time.Duration(b.TTLSeconds) * time.Second }

// UnbanHysteresis returns the hysteresis as a duration.
func (b Ban) UnbanHysteresis() time.Duration {
	return time.Duration(b.UnbanHysteresisSeconds) * time.Second
}

// BanWindow returns the blast-radius rate window as a duration.
func (b Ban) BanWindow() time.Duration {
	return time.Duration(b.BanWindowSeconds) * time.Second
}

// FallbackMethod resolves ban.fallback to the method applied when a primary
// announce fails: "" (default) and "blackhole" both yield blackhole; "none"
// (returning the empty method) disables fallback. validate() guarantees the
// stored value is one of these.
func (b Ban) FallbackMethod() MitigationMethod {
	if b.Fallback == "none" {
		return ""
	}
	return MitigateBlackhole
}

// BGP configures the embedded BGP speaker.
type BGP struct {
	LocalASN  uint32 `yaml:"local_asn"`
	RouterID  string `yaml:"router_id"`
	NextHop   string `yaml:"next_hop"`
	NextHop6  string `yaml:"next_hop6"`
	Community string `yaml:"community"`
	// Communities optionally sets the full blackhole community set (overriding
	// the single `community`). When empty the set is just [community].
	Communities []string `yaml:"communities"`
	// LocalPref optionally attaches a LOCAL_PREF to blackhole announcements
	// (meaningful to iBGP peers). 0 (default) omits the attribute.
	LocalPref uint32     `yaml:"local_pref"`
	Neighbors []Neighbor `yaml:"neighbors"`
	// ListenPort is the local BGP listen port; -1 (default) disables
	// listening so kapkan only dials out. Used by tests.
	ListenPort int32 `yaml:"listen_port"`
	// GracefulRestart advertises BGP Graceful Restart so a peer retains
	// kapkan's mitigation routes across a kapkan restart (e.g. an upgrade).
	GracefulRestart GracefulRestart `yaml:"graceful_restart"`

	// CommunityValue is the parsed single Community, populated by validate()
	// (kept for back-compat / single-community callers).
	CommunityValue uint32 `yaml:"-"`
	// CommunityValues is the parsed default blackhole community set and
	// CommunityStr its human-readable form, populated by validate().
	CommunityValues []uint32 `yaml:"-"`
	CommunityStr    string   `yaml:"-"`
}

// GracefulRestart configures BGP Graceful Restart (RFC 4724) and, optionally,
// Long-Lived Graceful Restart (RFC 9494) on the embedded speaker. When enabled,
// kapkan advertises the GR capability so a peer that supports it RETAINS the
// blackhole / FlowSpec routes learned from kapkan as stale while the session is
// down, instead of flushing them the instant it drops. Without it, restarting
// kapkan during an active attack un-mitigates everything immediately.
//
// Note: this bridges the session gap. A stock helper holds the stale routes only
// until the reconnecting instance signals End-of-RIB; since active bans are not
// yet rehydrated on startup, fully covering an upgrade restart additionally
// requires re-announcing those bans before End-of-RIB (a planned follow-up).
//
// Enabled defaults to true: advertising the capability costs nothing against a
// peer that does not support it (it simply isn't negotiated), and retention is
// bounded by RestartSeconds, so it never becomes a permanent ban. Set
// `enabled: false` to opt out. Notification-aware retention (RFC 8538) is
// always advertised so a clean shutdown — which sends a CEASE NOTIFICATION —
// still triggers retention on peers that honor it.
type GracefulRestart struct {
	// Enabled advertises the GR capability. Defaults to true (set in Parse so an
	// absent block keeps the safe value); set `enabled: false` to disable.
	Enabled bool `yaml:"enabled"`
	// RestartSeconds is the advertised GR restart timer: how long the peer keeps
	// kapkan's routes as stale while the session is down. Must comfortably exceed
	// kapkan's restart time. 0 (default) resolves to 120. Capped at 4095 (the
	// 12-bit GR restart-time field).
	RestartSeconds uint32 `yaml:"restart_seconds"`
	// LongLived enables LLGR, extending retention beyond RestartSeconds by
	// LongLivedStaleSeconds (per family). Off by default: RFC 9494 warns about
	// transient forwarding loops with long LLGR for FlowSpec, so opt in only when
	// the peer and topology are understood.
	LongLived bool `yaml:"long_lived"`
	// LongLivedStaleSeconds is the LLGR stale timer in seconds. 0 (default)
	// resolves to 3600 (1h) when LongLived is set; capped at 86400 (24h) —
	// hours, not days, so a finished attack's route is not pinned indefinitely
	// if kapkan never recovers.
	LongLivedStaleSeconds uint32 `yaml:"long_lived_stale_seconds"`
}

// BGPOverride overrides the global blackhole BGP attributes for a hostgroup.
// Any field left empty/nil inherits the global bgp value, so a group can set
// just its community while sharing the global next-hop, etc. Reused for the
// per-group scrubbing override.
type BGPOverride struct {
	NextHop     string   `yaml:"next_hop"`
	NextHop6    string   `yaml:"next_hop6"`
	Communities []string `yaml:"communities"`
	LocalPref   *uint32  `yaml:"local_pref"`
}

// Scrubbing is the default traffic-diversion target: the scrubbing center's
// BGP next-hops, the divert community (optional — the next-hop does the
// rerouting), and an optional LOCAL_PREF. Required (next-hop) only when a
// ladder actually diverts.
type Scrubbing struct {
	NextHop     string   `yaml:"next_hop"`
	NextHop6    string   `yaml:"next_hop6"`
	Community   string   `yaml:"community"`
	Communities []string `yaml:"communities"`
	LocalPref   uint32   `yaml:"local_pref"`
	// Nodes lists managed scrubbing nodes (boxes running `kapkan scrub`), each
	// with its own next-hop. The scalar next_hop above stays valid and is the
	// one-node degenerate case; nodes and next_hop may both be set, in which
	// case next_hop is the fallback target for groups no node claims.
	Nodes []ScrubNode `yaml:"nodes"`
	// NodeSelection picks the node for a new ban: affinity (default — the
	// first node whose hostgroups claim the victim's group), least_loaded, or
	// ecmp (all nodes share a next-hop and the router balances). The chosen
	// node is frozen on the ban for its lifetime.
	NodeSelection string `yaml:"node_selection"`
	// OnAllNodesLost is what to do when no managed node is reachable:
	// withdraw (default — stop attracting traffic), blackhole, or flowspec.
	// While at least one node survives, the victim is re-announced toward it
	// rather than withdrawn.
	OnAllNodesLost string `yaml:"on_all_nodes_lost"`
	// StaleAfterSeconds is how long a node may go without polling before it
	// counts as lost (default 15). The real detection bound for a SILENT death
	// (power loss, partition — nothing sends a FIN) is this PLUS the rules
	// long-poll hold the node may be parked in (documented ≤30 s): the open
	// hold keeps the node present until its server-side deadline passes. Size
	// this against blackhole tolerance with that sum in mind, not this number
	// alone.
	StaleAfterSeconds int `yaml:"stale_after_seconds"`

	// Parsed forms, populated by validate().
	CommunityValues []uint32 `yaml:"-"`
	CommunityStr    string   `yaml:"-"`
}

// Scrubbing node selection modes.
const (
	// NodeSelectAffinity routes a victim to the first node whose hostgroups
	// claim it (the default; keeps traffic on the site it arrived at).
	NodeSelectAffinity = "affinity"
	// NodeSelectLeastLoaded picks the eligible node with the most headroom
	// against its capacity_mbps.
	NodeSelectLeastLoaded = "least_loaded"
	// NodeSelectECMP announces one shared next-hop and lets the router
	// balance. Every node then needs every rule, and per-source rate limits
	// fragment across nodes (each sees only its share of a source's traffic).
	NodeSelectECMP = "ecmp"
)

// Actions taken when no managed scrubbing node is reachable.
const (
	// NodesLostWithdraw stops attracting the victim's traffic (fail-open).
	NodesLostWithdraw = "withdraw"
	// NodesLostBlackhole falls back to an RTBH announcement.
	NodesLostBlackhole = "blackhole"
	// NodesLostFlowSpec falls back to FlowSpec rules.
	NodesLostFlowSpec = "flowspec"
)

// ScrubNode is one managed scrubbing node: a box running `kapkan scrub` that
// receives diverted traffic, drops the attack in its XDP data plane, and
// reinjects what is left. Kapkan announces the victim toward the node's
// next-hop; the node pulls its rules back over the API.
type ScrubNode struct {
	// Name identifies the node and must match the name its agent presents.
	Name string `yaml:"name"`
	// NextHop is the node's IPv4 BGP next-hop (required).
	NextHop string `yaml:"next_hop"`
	// NextHop6 is the node's IPv6 next-hop, required to divert IPv6 victims.
	NextHop6 string `yaml:"next_hop6"`
	// CapacityMbps is the node's scrubbing capacity, used by the least_loaded
	// selection mode and surfaced in the console. 0 means unknown.
	CapacityMbps uint64 `yaml:"capacity_mbps"`
	// Hostgroups restricts which groups this node serves under affinity
	// selection. Empty means the node accepts any group.
	Hostgroups []string `yaml:"hostgroups"`
}

// Edge is the brain-side configuration of the edge track (edge-spec §2.3, §4;
// milestone E3). It is deliberately small: WHAT to serve lives in the tenant's
// zones file (see zones.go), and HOW a node serves it lives in the node's own
// edge.yaml — this block only joins the two: the zones file this brain reads
// and republishes, and the edge nodes allowed to poll for it.
type Edge struct {
	// ZonesFile is the absolute path of the zones.yaml this brain serves.
	// Required when the block is present. It is a SECOND file on purpose —
	// zones are tenant data, and a tenant's zone edit must never touch the
	// operator's daemon configuration. Read and validated by Load on startup
	// and on every reload; a broken zones file fails the whole reload, so the
	// previous zones stay live (edge-spec: "a broken zone edit never reaches a
	// running nginx" starts here, on the brain).
	ZonesFile string `yaml:"zones_file"`
	// Nodes lists the edge nodes (boxes running `kapkan edge`) allowed to
	// present themselves on the zones poll. An unknown name is a loud 404, not
	// a silently-created node, for the same reason scrubbing.nodes[] is closed.
	Nodes []EdgeNode `yaml:"nodes"`
	// StaleAfterSeconds is how long an edge node may go without polling
	// before the inventory counts it as lost (default 15). As with scrubbing
	// nodes, a node parked in a long-poll hold counts as present.
	StaleAfterSeconds int `yaml:"stale_after_seconds"`
}

// EdgeNode is one edge node the brain knows by name.
type EdgeNode struct {
	// Name identifies the node and must match the name its agent presents.
	Name string `yaml:"name"`
}

// Dataplane configures the in-kernel XDP filter. Everything here is policy the
// operator writes; the rules that actually mitigate an attack are synthesized
// by the detector and installed by the mitigator, exactly as they are for
// FlowSpec. The data plane executes decisions made elsewhere: it never
// classifies traffic, and its default verdict is always PASS.
type Dataplane struct {
	// Enabled defaults to true when the block is present.
	Enabled *bool `yaml:"enabled"`
	// Interfaces are the NICs to attach the XDP program to. At least one is
	// required. Changing them requires a restart.
	Interfaces []string `yaml:"interfaces"`
	// XDPMode is auto (default — try native, fall back to generic), native
	// (fail if the driver has no native XDP), or generic (the slower skb
	// path, useful on virtio and for testing). Restart required.
	XDPMode string `yaml:"xdp_mode"`
	// PinPath is the bpffs directory holding the pinned program and maps, so
	// policy survives a restart of this process. Restart required.
	PinPath string `yaml:"pin_path"`
	// OnExit is what happens on a clean shutdown: keep (default — the pinned
	// program keeps enforcing static policy while dynamic rules age out on
	// their in-kernel expiry) or detach (remove the program entirely).
	OnExit string `yaml:"on_exit"`
	// DropMalformed drops frames that cannot be parsed instead of passing and
	// counting them. Default false: this is a mitigation executor, not a
	// firewall, so anything unrecognized is forwarded.
	DropMalformed bool `yaml:"drop_malformed"`
	// Allowlist holds SOURCE prefixes that always pass, checked before every
	// other rule. Note this is a different axis from protected_whitelist,
	// which names DESTINATIONS that are never banned; both are enforced in
	// the kernel.
	Allowlist []string `yaml:"allowlist"`
	// RateLimitProfiles are named pps/mbps ceilings referenced by static
	// rules. Profiles live and die with the config: one that nothing
	// references is removed on reload.
	RateLimitProfiles []RateLimitProfile `yaml:"ratelimit_profiles"`
	// StaticRules are always-on operator rules, evaluated after the
	// allowlists and before any rule the detector installs.
	StaticRules []StaticRule `yaml:"static_rules"`
	// Fingerprint configures the off-path fingerprint plane (E2): the datapath
	// copies sampled TLS ClientHello / QUIC Initial handshakes to userspace,
	// where JA4 is computed and a source whose JA4 is on ja4_blocklist is
	// blocked in the kernel through the source-block path.
	Fingerprint DataplaneFingerprint `yaml:"fingerprint"`
	// Limits size the BPF maps. Changing them requires a restart.
	Limits DataplaneLimits `yaml:"limits"`
}

// DataplaneFingerprint configures the off-path fingerprint plane. It never sees
// or forwards client bytes beyond the handshake prefix the kernel already
// recognises; it MEASURES (JA4) and pushes enforcement to the cheapest layer
// (an XDP source block), matching the edge charter.
type DataplaneFingerprint struct {
	// Enabled turns the plane on. Requires dataplane.enabled. Because it flips a
	// kernel flag written at attach and starts the copy sampler, changing it
	// requires a restart (like the interface set).
	Enabled bool `yaml:"enabled"`
	// SamplePPS caps handshake copies per second per CPU — the in-kernel sampler
	// that stops the plane from becoming its own DoS under a handshake flood.
	// 0 selects the default. Restart required.
	SamplePPS uint64 `yaml:"sample_pps"`
	// BlockTTLSeconds is how long a JA4-triggered source block lives in the
	// kernel before it must be refreshed; 0 selects the default. Hot-reloads.
	BlockTTLSeconds int `yaml:"block_ttl_seconds"`
	// JA4Blocklist is the set of JA4 client fingerprints to source-block on
	// sight (exact match, e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1").
	// Hot-reloads: editing it takes effect on the next handshake, no restart.
	JA4Blocklist []string `yaml:"ja4_blocklist"`
}

// RateLimitProfile is a named traffic ceiling. At least one of pps/mbps must
// be set; when both are, whichever is reached first admits no further packets.
type RateLimitProfile struct {
	Name string `yaml:"name"`
	PPS  uint64 `yaml:"pps"`
	Mbps uint64 `yaml:"mbps"`
}

// StaticRule is one always-on data-plane rule. An empty match field means
// "any", so a rule with an empty match matches every packet — which is only
// ever sensible with a ratelimit action.
type StaticRule struct {
	// Name identifies the rule in counters, logs and the console. Required
	// and unique: unlike xFW's implicit aliases, two rules can never silently
	// address the same entry.
	Name  string      `yaml:"name"`
	Match StaticMatch `yaml:"match"`
	// Action is pass, drop or ratelimit. ratelimit requires profile.
	Action string `yaml:"action"`
	// Profile names a ratelimit_profiles entry; only valid with the
	// ratelimit action.
	Profile string `yaml:"profile"`
}

// StaticMatch is the match criteria of a static rule. Fields are ANDed, and an
// unset field matches anything.
type StaticMatch struct {
	// Src is a source address or CIDR.
	Src string `yaml:"src"`
	// Proto is tcp, udp, icmp or icmp6.
	Proto string `yaml:"proto"`
	// SrcPort and DstPort match a single port each (0 = any).
	SrcPort uint16 `yaml:"src_port"`
	DstPort uint16 `yaml:"dst_port"`
	// Payload narrows on what the L4 payload BEGINS with, for the one case
	// where that is decidable from a fixed offset without reassembling a
	// stream. Empty means the rule does not look at the payload at all, which
	// is what every rule written before this field existed means.
	//
	// The values are StaticPayloadTLSClientHello (TCP) and
	// StaticPayloadQUICInitial (UDP). This is not a hook for a pattern
	// language: each value is a predicate the datapath implements in a
	// handful of instructions, and anything needing more than that belongs
	// somewhere other than an XDP program.
	Payload string `yaml:"payload"`
}

// DataplaneLimits sizes the BPF maps. They are allocated once at attach, so a
// change requires a restart.
type DataplaneLimits struct {
	// MaxDynamicRules caps the rules the mitigator may install (default 4096).
	// Each ban contributes up to 8, so this must be at least
	// ban.max_active_bans * 8 or installs will start failing mid-attack.
	MaxDynamicRules int `yaml:"max_dynamic_rules"`
	// MaxStaticRules caps operator rules (default 256).
	MaxStaticRules int `yaml:"max_static_rules"`
	// MaxRatelimitSources sizes the per-source token-bucket LRU (default
	// 1048576). Each entry costs kernel memory charged to this unit's cgroup.
	MaxRatelimitSources int `yaml:"max_ratelimit_sources"`
}

// XDP attach modes.
const (
	// XDPModeAuto tries native and falls back to generic.
	XDPModeAuto = "auto"
	// XDPModeNative requires driver-level XDP.
	XDPModeNative = "native"
	// XDPModeGeneric forces the slower skb path.
	XDPModeGeneric = "generic"
)

// Data-plane shutdown behaviours.
const (
	// OnExitKeep leaves the pinned program attached.
	OnExitKeep = "keep"
	// OnExitDetach removes the program on a clean shutdown.
	OnExitDetach = "detach"
)

// Static-rule actions.
const (
	// StaticActionPass admits matching traffic unconditionally.
	StaticActionPass = "pass"
	// StaticActionDrop discards matching traffic.
	StaticActionDrop = "drop"
	// StaticActionRateLimit caps matching traffic at a named profile.
	StaticActionRateLimit = "ratelimit"
	// StaticPayloadTLSClientHello matches a TCP segment whose payload opens a
	// TLS handshake record carrying a ClientHello — the shape a TLS handshake
	// flood is made of. Decided from three bytes at fixed offsets, with no
	// stream reassembly, so a ClientHello split across segments does NOT match
	// and is forwarded like any other packet.
	StaticPayloadTLSClientHello = "tls_client_hello"
	// StaticPayloadQUICInitial matches a UDP datagram whose payload opens a
	// QUIC v1 Initial — the handshake packet a QUIC/HTTP3 flood is made of,
	// and the UDP twin of tls_client_hello. Decided from five bytes at fixed
	// offsets; version negotiation and QUIC v2 do NOT match, and a payload too
	// short to decide is forwarded like any other packet.
	StaticPayloadQUICInitial = "quic_initial"
)

// Data-plane defaults, applied by validateDataplane.
const (
	defaultPinPath             = "/sys/fs/bpf/kapkan"
	defaultMaxDynamicRules     = 4096
	defaultMaxStaticRules      = 256
	defaultMaxRatelimitSources = 1 << 20
	defaultStaleAfterSeconds   = 15

	// Fingerprint-plane defaults.
	defaultFingerprintSamplePPS       = 1000
	defaultFingerprintBlockTTLSeconds = 300
	// maxFingerprintBlockTTLSeconds mirrors mitigate.MaxSourceBlockTTL (24h): a
	// JA4 block is a source block, and a mistaken one must heal itself within a
	// day even if nobody refreshes or notices it.
	maxFingerprintBlockTTLSeconds = 24 * 60 * 60
)

// maxDataplaneRulesPerBan mirrors the mitigator's per-attack rule cap: an
// attack yields at most this many match rules, so the dynamic map must hold
// ban.max_active_bans times this many entries to never fail an install.
const maxDataplaneRulesPerBan = 8

// ifaceNameRe matches a Linux interface name: IFNAMSIZ allows 15 characters,
// and the kernel rejects '/' and whitespace. Validated by pattern only — this
// package compiles to wasm, where the interface list cannot be enumerated.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,15}$`)

// parsePrefixOrAddr accepts either a CIDR or a bare address (treated as a
// host route) and returns the masked prefix. Data-plane policy lists accept
// both spellings because operators write single addresses far more often than
// /32s.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// DataplaneSettings is the resolved data-plane configuration. It is comparable
// so Store.Reload can reject the changes that cannot be applied to a running,
// attached program: the interface set, the attach mode, the pin path and the
// map sizes. Static policy (allowlist, rules, profiles) is deliberately absent
// — it hot-reloads through a shadow-map generation flip.
type DataplaneSettings struct {
	Enabled bool
	// Interfaces is the joined interface list; a slice would not be
	// comparable, and this struct is compared with == on reload.
	Interfaces          string
	XDPMode             string
	PinPath             string
	OnExit              string
	MaxDynamicRules     int
	MaxStaticRules      int
	MaxRatelimitSources int
	// FingerprintEnabled and FingerprintSamplePPS are the fingerprint-plane
	// knobs that touch the kernel (the fp_enabled flag and the copy sampler),
	// resolved here as comparable scalars so a reload detects a change to them
	// and demands a restart, exactly like the interface set. The blocklist and
	// TTL are deliberately NOT here — they hot-reload, read live by the reader.
	FingerprintEnabled   bool
	FingerprintSamplePPS uint64
}

// Neighbor is one BGP peer.
type Neighbor struct {
	Address   string `yaml:"address"`
	RemoteASN uint32 `yaml:"remote_asn"`
	// Port overrides the neighbor's BGP port (default 179). Used by tests.
	Port uint32 `yaml:"port"`
}

// Notify configures attack notifications.
type Notify struct {
	Telegram Telegram `yaml:"telegram"`
	Webhook  Webhook  `yaml:"webhook"`
	Slack    Slack    `yaml:"slack"`
	Email    Email    `yaml:"email"`
	Exec     Exec     `yaml:"exec"`
}

// Slack posts notifications to a Slack incoming webhook.
type Slack struct {
	WebhookURL string `yaml:"webhook_url"`
}

// Email sends notifications over SMTP. Credentials are read from the named
// environment variables, never from the config file. With no credentials
// the message is sent unauthenticated (e.g. a local relay). STARTTLS is
// used whenever the server offers it.
type Email struct {
	// SMTPHost is "host:port" of the SMTP server; empty disables email.
	SMTPHost    string   `yaml:"smtp_host"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
	// RequireTLS refuses to send unless the server offers STARTTLS,
	// protecting against active downgrade. It is implied whenever
	// credentials are configured; without it, plaintext delivery to a
	// non-loopback host is loudly logged.
	RequireTLS bool `yaml:"require_tls"`
}

// Exec runs an operator-provided hook on every attack event. The payload
// JSON (docs/callback-schema.json, versioned via its schema_version field)
// is written to the hook's stdin; the event name is passed as argv[1]. The
// command runs directly, without a shell.
type Exec struct {
	// Command is the absolute path of the executable; empty disables.
	Command string `yaml:"command"`
	// TimeoutSeconds bounds one invocation (default 10).
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// Format selects the invocation convention: "kapkan" (default) passes the
	// event name as argv[1] and the JSON payload on stdin; "fastnetmon" mimics
	// FastNetMon's notify_script — argv is "<ip> <direction> <pps> <action>"
	// with a plain-text attack summary on stdin — so existing FastNetMon notify
	// scripts run unchanged.
	Format string `yaml:"format"`
}

// Exec formats.
const (
	// ExecFormatKapkan is the native convention: event name argv + JSON stdin.
	ExecFormatKapkan = "kapkan"
	// ExecFormatFastNetMon mimics FastNetMon's notify_script contract.
	ExecFormatFastNetMon = "fastnetmon"
)

// Timeout returns the exec hook timeout as a duration.
func (e Exec) Timeout() time.Duration { return time.Duration(e.TimeoutSeconds) * time.Second }

// Telegram notification settings. The bot token is read from the
// environment variable named in TokenEnv, never from the config file.
type Telegram struct {
	TokenEnv string `yaml:"token_env"`
	ChatID   string `yaml:"chat_id"`
}

// Webhook is a generic JSON POST notification target.
type Webhook struct {
	URL string `yaml:"url"`
}

// API configures the REST API listener.
type API struct {
	Listen string `yaml:"listen"`
	// Dashboard serves the embedded web UI on the API listener. Defaults to
	// true; set false to expose only the JSON API and metrics.
	Dashboard *bool `yaml:"dashboard"`
	// TokenEnv names an environment variable holding a bearer token. When
	// set, every /api/v1 request must carry "Authorization: Bearer <token>".
	// The token is read from the environment, never from the config file.
	// Unset (default) leaves the API open — safe only on a trusted listener
	// such as the default 127.0.0.1 bind. Shorthand for a single operator
	// token; use `tokens` for role-based access. Mutually exclusive with it.
	TokenEnv string `yaml:"token_env"`
	// Tokens is the role-based token set: each names an env var holding its
	// secret and a role (viewer = read-only, operator = read + ban/unban/
	// reload). When set it supersedes token_env.
	Tokens []APIToken `yaml:"tokens"`

	// TokenSpecs is the resolved token set (env names + roles, never secrets),
	// populated by validate(). Empty leaves the API open.
	TokenSpecs []TokenSpec `yaml:"-"`
}

// UpdateCheck configures the OPTIONAL, opt-in check for a newer kapkan release.
// kapkan never phones home by default (it is a security tool); the running
// version is always exposed locally via /api/v1/status and the kapkan_build_info
// metric with zero egress. When Enabled, kapkan additionally polls the GitHub
// Releases API on Interval and surfaces "a newer version exists" on the status
// endpoint, the kapkan_update_available metric and a rate-limited log line. The
// check transmits only the HTTP request itself (source IP + a generic
// User-Agent) — never node identity, config, attack data or ban state — and runs
// off the startup path with a bounded timeout, so a firewalled or slow endpoint
// never delays the daemon or its BGP bring-up.
type UpdateCheck struct {
	// Enabled turns the periodic check on. Default false (no egress).
	Enabled bool `yaml:"enabled"`
	// IntervalSeconds is the poll interval; 0 (default) resolves to 21600 (6h).
	// Floored at 3600 (1h) to stay well within GitHub's unauthenticated rate
	// limit (ETag/304 responses do not count against it anyway).
	IntervalSeconds int `yaml:"interval_seconds"`
	// Channel selects which releases count: "stable" (default, the latest
	// non-prerelease) or "prerelease" (includes -rc tags).
	Channel string `yaml:"channel"`
	// URL overrides the releases endpoint (for a mirror or proxy). Empty uses the
	// public GitHub API for this repository, derived from Channel.
	URL string `yaml:"url"`
	// Notify also sends "update available" through the configured notification
	// channels (Telegram/webhook/Slack/email) the first time a new version is
	// seen. Default false.
	Notify bool `yaml:"notify"`
}

// APIToken is one configured API credential (YAML shape).
type APIToken struct {
	Name     string `yaml:"name"`
	TokenEnv string `yaml:"token_env"`
	Role     string `yaml:"role"`
	// Tenant optionally scopes this token: it then sees and may mutate only
	// data whose hostgroup carries this tenant. Empty = unscoped (all tenants).
	Tenant string `yaml:"tenant"`
}

// Role is an API access level.
type Role string

// API roles, in ascending privilege.
const (
	// RoleViewer may read (status, attacks, hosts, bans, metrics).
	RoleViewer Role = "viewer"
	// RoleOperator may read and mutate (manual ban/unban, config reload).
	RoleOperator Role = "operator"
	// RoleAgent is a scrub node's credential: it may pull the dataplane rules
	// document and (in a later milestone) report its own state — NOTHING else.
	// It sits OFF the privilege ladder, deliberately below viewer: an agent
	// token lives on a remote, often less-guarded box, and it must not become
	// a read-everything key if that box is compromised. Its routes are granted
	// by explicit membership (api.requireAnyRole), never by rank.
	RoleAgent Role = "agent"
)

// Rank orders roles so a check is "presented rank >= required rank".
func (r Role) Rank() int {
	switch r {
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	case RoleAgent:
		// Explicitly rank 0: the monotonic ladder cannot express "agent but
		// not viewer", so rank grants an agent nothing and requireAnyRole is
		// the only way it reaches a route.
		return 0
	default:
		return 0
	}
}

// TokenSpec is one resolved credential: the env var holding its secret and the
// role it grants. The secret itself is read from the environment per request,
// never stored here.
type TokenSpec struct {
	Name string
	Env  string
	Role Role
	// Tenant scopes the token (empty = unscoped / all tenants).
	Tenant string
}

// DashboardEnabled reports whether the embedded UI should be served.
func (a API) DashboardEnabled() bool { return a.Dashboard == nil || *a.Dashboard }

// Load reads, parses and validates the configuration file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	// edge.zones_file is a SECOND file, followed here and not in Parse: Parse
	// must stay pure (it is what the browser-side validator compiles), and a
	// reload that cannot read or validate the zones file must fail as a whole
	// so the previous configuration — zones included — stays live.
	if cfg.Edge != nil {
		z, err := LoadZones(cfg.Edge.ZonesFile)
		if err != nil {
			return nil, fmt.Errorf("edge.zones_file %q: %w", cfg.Edge.ZonesFile, err)
		}
		cfg.ZonesCfg = z
	}
	return cfg, nil
}

// Parse parses and validates raw YAML configuration bytes.
func Parse(raw []byte) (*Config, error) {
	// Safety default: mitigation is dry-run unless the file explicitly
	// says otherwise. Setting it before unmarshal means an absent key
	// keeps the safe value.
	cfg := &Config{DryRun: true}
	cfg.BGP.ListenPort = -1
	// Graceful Restart is on by default; an absent graceful_restart block keeps
	// it enabled, while `enabled: false` in the file overrides this. Timers
	// resolve to their defaults in validateBGP.
	cfg.BGP.GracefulRestart.Enabled = true
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Listen.SFlow == "" && c.Listen.NetFlow == "" {
		return fmt.Errorf("listen: at least one of sflow/netflow must be set")
	}
	for name, addr := range map[string]string{"sflow": c.Listen.SFlow, "netflow": c.Listen.NetFlow} {
		if addr == "" {
			continue
		}
		if _, err := netip.ParseAddrPort(normalizeListen(addr)); err != nil {
			return fmt.Errorf("listen.%s: invalid address %q: %w", name, addr, err)
		}
	}

	if c.Sampling.DefaultRate < 1 {
		return fmt.Errorf("sampling.default_rate must be >= 1, got %d", c.Sampling.DefaultRate)
	}
	if err := c.resolveBoundary(); err != nil {
		return err
	}

	if len(c.Networks) == 0 {
		return fmt.Errorf("networks: at least one protected prefix is required")
	}
	c.NetworkPrefixes = make([]netip.Prefix, 0, len(c.Networks))
	c.protectedAddrs4, c.protectedAddrs6 = 0, 0
	for _, s := range c.Networks {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("networks: invalid CIDR %q: %w", s, err)
		}
		p = p.Masked()
		for _, prev := range c.NetworkPrefixes {
			if prev == p {
				return fmt.Errorf("networks: duplicate prefix %s", p)
			}
			if prev.Overlaps(p) {
				return fmt.Errorf("networks: %s overlaps %s; remove the redundant entry", p, prev)
			}
		}
		c.NetworkPrefixes = append(c.NetworkPrefixes, p)
		// Tally the protected address space per family for the blast-radius
		// fraction guard. Overlap is already rejected above, so summing is exact.
		if p.Addr().Is4() {
			c.protectedAddrs4 += math.Ldexp(1, 32-p.Bits())
		} else {
			c.protectedAddrs6 += math.Ldexp(1, 128-p.Bits())
		}
	}

	c.WhitelistAddrs = make([]netip.Addr, 0, len(c.ProtectedWhitelist))
	for _, s := range c.ProtectedWhitelist {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("protected_whitelist: invalid IP %q: %w", s, err)
		}
		c.WhitelistAddrs = append(c.WhitelistAddrs, a)
	}

	if len(c.FlowSources) > 0 {
		c.FlowSourceSet = make(map[netip.Addr]struct{}, len(c.FlowSources))
		for _, s := range c.FlowSources {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("flow_sources: invalid IP %q: %w", s, err)
			}
			c.FlowSourceSet[a.Unmap()] = struct{}{}
		}
	}

	if c.Thresholds.PPS == 0 || c.Thresholds.Mbps == 0 || c.Thresholds.FlowsPerSec == 0 {
		return fmt.Errorf("thresholds: pps, mbps and flows_per_sec must all be > 0")
	}
	if c.ThresholdsOutgoing != nil && c.ThresholdsOutgoing.Zero() {
		return fmt.Errorf("thresholds_outgoing: set at least one threshold or remove the block")
	}

	// BGP and scrubbing are validated before hostgroups so the global blackhole
	// and scrubbing attribute sets are parsed and available as per-group
	// resolution defaults.
	if err := c.validateBGP(); err != nil {
		return err
	}
	if err := c.validateScrubbing(); err != nil {
		return err
	}
	// The data plane validates before hostgroups so a group whose ladder uses
	// the dataplane action can be checked against a resolved block.
	if err := c.validateDataplane(); err != nil {
		return err
	}

	if err := c.validateEdge(); err != nil {
		return err
	}
	if err := c.validateHostgroups(); err != nil {
		return err
	}
	if err := c.validateSamples(); err != nil {
		return err
	}
	if err := c.validateStorage(); err != nil {
		return err
	}
	if err := c.validateGeoIP(); err != nil {
		return err
	}
	if err := c.validateCarpet(); err != nil {
		return err
	}

	if c.Ban.TTLSeconds <= 0 {
		return fmt.Errorf("ban.ttl_seconds must be > 0, got %d", c.Ban.TTLSeconds)
	}
	if c.Ban.UnbanHysteresisSeconds < 0 {
		return fmt.Errorf("ban.unban_hysteresis_seconds must be >= 0, got %d", c.Ban.UnbanHysteresisSeconds)
	}
	if c.Ban.MaxActiveBans <= 0 {
		return fmt.Errorf("ban.max_active_bans must be > 0, got %d", c.Ban.MaxActiveBans)
	}
	switch c.Ban.Fallback {
	case "", "none", string(MitigateBlackhole):
	default:
		return fmt.Errorf("ban.fallback must be %q or %q, got %q", "none", MitigateBlackhole, c.Ban.Fallback)
	}
	if c.Ban.MaxBannedFraction < 0 || c.Ban.MaxBannedFraction > 1 {
		return fmt.Errorf("ban.max_banned_fraction must be between 0 and 1, got %v", c.Ban.MaxBannedFraction)
	}
	if c.Ban.MaxBansPerWindow < 0 {
		return fmt.Errorf("ban.max_bans_per_window must be >= 0, got %d", c.Ban.MaxBansPerWindow)
	}
	if c.Ban.BanWindowSeconds < 0 {
		return fmt.Errorf("ban.ban_window_seconds must be >= 0, got %d", c.Ban.BanWindowSeconds)
	}
	if c.Ban.MaxBansPerWindow > 0 && c.Ban.BanWindowSeconds <= 0 {
		return fmt.Errorf("ban.ban_window_seconds must be > 0 when ban.max_bans_per_window is set")
	}

	if err := c.validateNotify(); err != nil {
		return err
	}

	if c.API.Listen == "" {
		return fmt.Errorf("api.listen must be set")
	}
	if _, err := netip.ParseAddrPort(normalizeListen(c.API.Listen)); err != nil {
		return fmt.Errorf("api.listen: invalid address %q: %w", c.API.Listen, err)
	}
	if err := c.validateAPITokens(); err != nil {
		return err
	}
	if err := c.validateUpdateCheck(); err != nil {
		return err
	}
	return nil
}

// validateUpdateCheck applies the update-check defaults and validates the block.
// It is meaningful only when Enabled, but the channel/url are validated whenever
// set so a typo is caught even before the operator flips it on.
func (c *Config) validateUpdateCheck() error {
	u := &c.UpdateCheck
	if u.Channel == "" {
		u.Channel = "stable"
	}
	if u.Channel != "stable" && u.Channel != "prerelease" {
		return fmt.Errorf("update_check.channel must be \"stable\" or \"prerelease\", got %q", u.Channel)
	}
	if u.IntervalSeconds == 0 {
		u.IntervalSeconds = 21600 // 6h
	}
	if u.IntervalSeconds < 3600 {
		return fmt.Errorf("update_check.interval_seconds must be >= 3600 (1h), got %d", u.IntervalSeconds)
	}
	if u.URL != "" {
		parsed, err := url.Parse(u.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("update_check.url must be an http(s) URL, got %q", u.URL)
		}
	}
	return nil
}

// validateHostgroups checks the hostgroups section and builds the resolved
// Groups slice and the longest-prefix-first lookup table. It runs after the
// networks and thresholds sections have been validated, so it can rely on
// NetworkPrefixes and on the global thresholds being sane.
func (c *Config) validateHostgroups() error {
	globalBaseline, err := resolveBaseline(c.Baseline)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}

	// Tenant labels travel into logs, JSON and (via tokens) auth decisions; the
	// same log/JSON/header-safe charset as group names closes injection vectors.
	if c.Tenant != "" && !groupNameRe.MatchString(c.Tenant) {
		return fmt.Errorf("tenant %q must match %s", c.Tenant, groupNameRe)
	}

	globalMethod, globalAction, globalRate, err := resolveMitigation(c.Mitigation, c.FlowSpec, MitigateBlackhole, nil)
	if err != nil {
		return fmt.Errorf("mitigation: %w", err)
	}
	globalStages, err := resolveEscalation(c.Escalation, globalMethod)
	if err != nil {
		return err
	}
	// A FlowSpec stage needs an action policy even if the single `mitigation`
	// method is blackhole (e.g. escalation: none → flowspec).
	//
	// SO DOES A DATAPLANE STAGE, and for the same reason: the generated rules
	// are one IR with two backends, and the action rides on the rule, not on the
	// backend. A ladder that only ever drops in the kernel would otherwise leave
	// this empty and the mitigator would compile a rule with no action —
	// refused, so every ban of that group would fall back to a blackhole. The
	// gentlest rung on the ladder degrading to the harshest, for a field nobody
	// wrote, is exactly the silent failure this action was gated on.
	//
	// AND SO DOES A DIVERT STAGE toward a managed scrub node — the THIRD backend
	// for the same IR. The node pulls the ban and enforces its FlowSpec rules in
	// its own XDP data plane, so a divert ban whose rules carry no action would
	// leave the node unable to compile them and dropping nothing. The
	// on_all_nodes_lost: flowspec fallback needs it for the same reason.
	if (usesFlowSpec(globalStages) || usesDataplane(globalStages) ||
		DivertGeneratesRules(globalStages, &c.Scrubbing)) && globalAction == "" {
		if globalAction, globalRate, err = resolveFlowSpecPolicy(c.FlowSpec, nil); err != nil {
			return fmt.Errorf("flowspec: %w", err)
		}
	}

	globalBGP, err := resolveBGPAttrs(nil, c.BGP.defaults())
	if err != nil {
		return fmt.Errorf("bgp: %w", err)
	}
	globalScrub, err := resolveBGPAttrs(nil, c.Scrubbing.defaults())
	if err != nil {
		return fmt.Errorf("scrubbing: %w", err)
	}
	if usesDivert(globalStages) {
		if err := validateDivertTarget(GlobalGroup, globalScrub, &c.Scrubbing, c.hasV6Networks()); err != nil {
			return err
		}
	}
	if usesDataplane(globalStages) {
		if err := c.requireDataplane(GlobalGroup); err != nil {
			return err
		}
	}

	globalSrcAnchor, globalMinConc, err := resolveSourceAnchor(c.FlowSpec, nil)
	if err != nil {
		return fmt.Errorf("flowspec: %w", err)
	}

	c.Groups = make([]Group, 0, len(c.Hostgroups)+1)
	c.Groups = append(c.Groups, Group{
		Name:                     GlobalGroup,
		Calc:                     CalcPerHost,
		Thresholds:               c.Thresholds,
		OutThresholds:            c.ThresholdsOutgoing,
		Baseline:                 globalBaseline,
		Mitigation:               globalMethod,
		FlowSpecAction:           globalAction,
		FlowSpecRateBps:          globalRate,
		FlowSpecSourceAnchored:   globalSrcAnchor,
		FlowSpecMinConcentration: globalMinConc,
		Escalation:               globalStages,
		BlackholeNextHop:         globalBGP.nextHop,
		BlackholeNextHop6:        globalBGP.nextHop6,
		BlackholeCommunities:     globalBGP.communities,
		BlackholeCommunityStr:    globalBGP.commStr,
		LocalPref:                globalBGP.localPref,
		ScrubNextHop:             globalScrub.nextHop,
		ScrubNextHop6:            globalScrub.nextHop6,
		ScrubCommunities:         globalScrub.communities,
		ScrubCommunityStr:        globalScrub.commStr,
		ScrubLocalPref:           globalScrub.localPref,
		Tenant:                   c.Tenant,
		BanEnabled:               true,
	})
	c.groupRoutes = nil

	names := make(map[string]bool, len(c.Hostgroups))
	seen := make(map[netip.Prefix]string) // prefix → owning group name
	for i, hg := range c.Hostgroups {
		if hg.Name == "" {
			return fmt.Errorf("hostgroups[%d]: name is required", i)
		}
		// Group names travel into logs, JSON payloads, chat messages and
		// email headers; a restricted charset closes injection vectors
		// (CRLF into RFC 5322 headers, mrkdwn/HTML metacharacters) at the
		// single central point.
		if !groupNameRe.MatchString(hg.Name) {
			return fmt.Errorf("hostgroups[%d]: name %q must match %s", i, hg.Name, groupNameRe)
		}
		if hg.Tenant != "" && !groupNameRe.MatchString(hg.Tenant) {
			return fmt.Errorf("hostgroups[%q]: tenant %q must match %s", hg.Name, hg.Tenant, groupNameRe)
		}
		if hg.Name == GlobalGroup {
			return fmt.Errorf("hostgroups[%d]: name %q is reserved for the implicit fallback group", i, GlobalGroup)
		}
		if names[hg.Name] {
			return fmt.Errorf("hostgroups[%d]: duplicate name %q", i, hg.Name)
		}
		names[hg.Name] = true

		calc := CalcMethod(hg.Calculation)
		if calc == "" {
			calc = CalcPerHost
		}
		if calc != CalcPerHost && calc != CalcTotal {
			return fmt.Errorf("hostgroups[%q]: calculation must be %q or %q, got %q",
				hg.Name, CalcPerHost, CalcTotal, hg.Calculation)
		}

		banEnabled := hg.Ban == nil || *hg.Ban
		if calc == CalcTotal {
			if hg.Ban != nil && *hg.Ban {
				return fmt.Errorf("hostgroups[%q]: ban: true is not allowed with calculation: total — total groups alert only, there is no single host to blackhole", hg.Name)
			}
			banEnabled = false
		}

		th := c.Thresholds
		if hg.Thresholds != nil {
			th = *hg.Thresholds
			if th.PPS == 0 || th.Mbps == 0 || th.FlowsPerSec == 0 {
				return fmt.Errorf("hostgroups[%q]: thresholds: pps, mbps and flows_per_sec must all be > 0 (omit the block to inherit global thresholds)", hg.Name)
			}
		}

		outTh := c.ThresholdsOutgoing
		if hg.ThresholdsOutgoing != nil {
			if hg.ThresholdsOutgoing.Zero() {
				return fmt.Errorf("hostgroups[%q]: thresholds_outgoing: set at least one threshold or remove the block", hg.Name)
			}
			outTh = hg.ThresholdsOutgoing
		}

		groupBaseline := globalBaseline
		if hg.Baseline != nil {
			groupBaseline, err = resolveBaseline(hg.Baseline)
			if err != nil {
				return fmt.Errorf("hostgroups[%q]: baseline: %w", hg.Name, err)
			}
		}

		method, action, rate, err := resolveMitigation(hg.Mitigation, hg.FlowSpec, globalMethod, c.FlowSpec)
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: mitigation: %w", hg.Name, err)
		}
		// A total group has no single victim to write a dst-match rule for.
		// An explicit flowspec choice is an error; an inherited one (from the
		// global default) silently falls back to blackhole — like ban does.
		if calc == CalcTotal && method == MitigateFlowSpec {
			if hg.Mitigation == string(MitigateFlowSpec) {
				return fmt.Errorf("hostgroups[%q]: mitigation: flowspec is not valid with calculation: total (no single victim prefix)", hg.Name)
			}
			method, action, rate = MitigateBlackhole, "", 0
		}

		// Resolve the mitigation ladder: the group's own escalation, else the
		// global one, else a single rung synthesized from the method.
		escSteps, escExplicit := hg.Escalation, hg.Escalation != nil
		if escSteps == nil {
			escSteps = c.Escalation
		}
		stages, err := resolveEscalation(escSteps, method)
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: %w", hg.Name, err)
		}
		// A total group has no single victim prefix to write a flowspec/divert
		// rule for. An explicit such stage is an error; an inherited one
		// degrades to blackhole, like the method case.
		if calc == CalcTotal && (usesFlowSpec(stages) || usesDivert(stages)) {
			if escExplicit {
				return fmt.Errorf("hostgroups[%q]: escalation: a flowspec/divert stage is not valid with calculation: total (no single victim prefix)", hg.Name)
			}
			for i := range stages {
				if stages[i].Action == EscalateFlowSpec || stages[i].Action == EscalateDivert {
					stages[i].Action = EscalateBlackhole // inherited; degrade like the method case
				}
			}
		}
		// Same for a dataplane stage as for a flowspec one, and for a divert
		// stage toward a managed scrub node: one rule IR, three backends, and the
		// action lives on the rule. See the global case above.
		if (usesFlowSpec(stages) || usesDataplane(stages) || DivertGeneratesRules(stages, &c.Scrubbing)) && action == "" {
			if action, rate, err = resolveFlowSpecPolicy(hg.FlowSpec, c.FlowSpec); err != nil {
				return fmt.Errorf("hostgroups[%q]: flowspec: %w", hg.Name, err)
			}
		}

		groupBGP, err := resolveBGPAttrs(hg.BGP, c.BGP.defaults())
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: bgp: %w", hg.Name, err)
		}
		groupScrub, err := resolveBGPAttrs(hg.Scrubbing, c.Scrubbing.defaults())
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: scrubbing: %w", hg.Name, err)
		}

		if len(hg.Networks) == 0 {
			return fmt.Errorf("hostgroups[%q]: at least one prefix is required", hg.Name)
		}
		groupIdx := len(c.Groups)
		groupHasV6 := false
		for _, s := range hg.Networks {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("hostgroups[%q]: invalid CIDR %q: %w", hg.Name, s, err)
			}
			p = p.Masked()
			if p.Addr().Is6() {
				groupHasV6 = true
			}
			if owner, dup := seen[p]; dup {
				return fmt.Errorf("hostgroups[%q]: prefix %s already belongs to group %q", hg.Name, p, owner)
			}
			seen[p] = hg.Name
			contained := false
			for _, np := range c.NetworkPrefixes {
				if np.Contains(p.Addr()) && np.Bits() <= p.Bits() {
					contained = true
					break
				}
			}
			if !contained {
				return fmt.Errorf("hostgroups[%q]: prefix %s is not inside any configured networks entry — flows to it are never processed", hg.Name, p)
			}
			c.groupRoutes = append(c.groupRoutes, groupRoute{prefix: p, group: groupIdx})
		}

		if usesDivert(stages) {
			if err := validateDivertTarget(hg.Name, groupScrub, &c.Scrubbing, groupHasV6); err != nil {
				return err
			}
		}
		if usesDataplane(stages) {
			if err := c.requireDataplane(hg.Name); err != nil {
				return err
			}
		}

		groupSrcAnchor, groupMinConc, err := resolveSourceAnchor(hg.FlowSpec, c.FlowSpec)
		if err != nil {
			return fmt.Errorf("hostgroups[%q]: flowspec: %w", hg.Name, err)
		}

		c.Groups = append(c.Groups, Group{
			Name:                     hg.Name,
			Calc:                     calc,
			Thresholds:               th,
			OutThresholds:            outTh,
			Baseline:                 groupBaseline,
			Mitigation:               method,
			FlowSpecAction:           action,
			FlowSpecRateBps:          rate,
			FlowSpecSourceAnchored:   groupSrcAnchor,
			FlowSpecMinConcentration: groupMinConc,
			Escalation:               stages,
			BlackholeNextHop:         groupBGP.nextHop,
			BlackholeNextHop6:        groupBGP.nextHop6,
			BlackholeCommunities:     groupBGP.communities,
			BlackholeCommunityStr:    groupBGP.commStr,
			LocalPref:                groupBGP.localPref,
			ScrubNextHop:             groupScrub.nextHop,
			ScrubNextHop6:            groupScrub.nextHop6,
			ScrubCommunities:         groupScrub.communities,
			ScrubCommunityStr:        groupScrub.commStr,
			ScrubLocalPref:           groupScrub.localPref,
			Tenant:                   hg.Tenant,
			BanEnabled:               banEnabled,
		})
	}

	for i := range c.Groups {
		if c.Groups[i].OutThresholds != nil {
			c.OutgoingEnabled = true
			break
		}
	}

	// Longest prefix first so GroupFor's first match is the most specific.
	sort.SliceStable(c.groupRoutes, func(i, j int) bool {
		return c.groupRoutes[i].prefix.Bits() > c.groupRoutes[j].prefix.Bits()
	})
	return nil
}

// validateCarpet validates and applies defaults to the carpet-bombing
// detection block in place. A nil block leaves the feature disabled.
func (c *Config) validateCarpet() error {
	cp := c.Carpet
	if cp == nil {
		return nil
	}
	if cp.AggregationPrefixV4 == 0 {
		cp.AggregationPrefixV4 = 24
	}
	if cp.AggregationPrefixV6 == 0 {
		cp.AggregationPrefixV6 = 48
	}
	if cp.AggregationPrefixV4 < 8 || cp.AggregationPrefixV4 > 32 {
		return fmt.Errorf("carpet.aggregation_prefix_v4 must be in 8..32, got %d", cp.AggregationPrefixV4)
	}
	if cp.AggregationPrefixV6 < 16 || cp.AggregationPrefixV6 > 128 {
		return fmt.Errorf("carpet.aggregation_prefix_v6 must be in 16..128, got %d", cp.AggregationPrefixV6)
	}
	if cp.MinHosts == 0 {
		cp.MinHosts = 10
	}
	if cp.MinHosts < 2 {
		return fmt.Errorf("carpet.min_hosts must be >= 2, got %d", cp.MinHosts)
	}
	if cp.Thresholds.Zero() {
		return fmt.Errorf("carpet.thresholds: set at least one aggregate threshold")
	}
	if cp.Mitigation != "" && cp.Method() == "" {
		return fmt.Errorf("carpet.mitigation must be empty or one of %s, got %q",
			quotedMethods(CarpetMethods()), cp.Mitigation)
	}
	// CROSS-FIELD: dropping a carpet bomb in this box's kernel needs a kernel to
	// drop it in. Without this the mitigator would accept the method, fail every
	// install and fall back to blackholing the whole aggregation prefix — the
	// widest possible outcome, reached by the most surgical request.
	if cp.Method() == MitigateDataplane {
		switch {
		case c.Dataplane == nil:
			return fmt.Errorf("carpet.mitigation %q requires a dataplane block", MitigateDataplane)
		case !c.DataplaneCfg.Enabled:
			return fmt.Errorf("carpet.mitigation %q requires dataplane.enabled: true", MitigateDataplane)
		}
	}
	if cp.MaxActivePrefixBans == 0 {
		cp.MaxActivePrefixBans = 10
	}
	if cp.MaxActivePrefixBans < 1 {
		return fmt.Errorf("carpet.max_active_prefix_bans must be >= 1, got %d", cp.MaxActivePrefixBans)
	}
	return nil
}

// quotedMethods renders a method set for an error message ("flowspec",
// "blackhole" or "dataplane"), so the message can never fall behind the set it
// describes.
func quotedMethods(ms []MitigationMethod) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = strconv.Quote(string(m))
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
}

// resolveBaseline validates one baseline block and applies defaults. A nil
// block (or enabled: false) resolves to nil — static thresholds only.
func resolveBaseline(b *Baseline) (*BaselineSettings, error) {
	if b == nil || (b.Enabled != nil && !*b.Enabled) {
		return nil, nil
	}
	s := &BaselineSettings{
		Factor:        b.Factor,
		WarmupSeconds: b.WarmupSeconds,
		Floor:         b.Floor,
	}
	half := b.HalfLifeSeconds
	if half == 0 {
		half = 3600
	}
	if s.Factor == 0 {
		s.Factor = 3
	}
	if b.WarmupSeconds == 0 {
		s.WarmupSeconds = 600
	}
	if !(s.Factor >= 1.5 && s.Factor <= 100) {
		// Negated form rejects NaN too (NaN fails every comparison). Below
		// 1.5, normal jitter around the learned level trips constantly.
		return nil, fmt.Errorf("factor must be in 1.5..100, got %g", s.Factor)
	}
	if half < 10 || half > 7*86400 {
		return nil, fmt.Errorf("half_life_seconds must be in 10..604800, got %d", half)
	}
	if s.WarmupSeconds < 0 || s.WarmupSeconds > 86400 {
		return nil, fmt.Errorf("warmup_seconds must be in 0..86400, got %d", b.WarmupSeconds)
	}
	if s.Floor.PPS == 0 || s.Floor.Mbps == 0 || s.Floor.FlowsPerSec == 0 {
		return nil, fmt.Errorf("floor: pps, mbps and flows_per_sec must all be > 0 (hair-trigger guard)")
	}
	s.Alpha = 1 - math.Exp2(-1/float64(half))
	return s, nil
}

// dbNameRe restricts the ClickHouse database/table identifiers we
// interpolate into DDL to a safe charset (no injection surface).
var dbNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// resolveMitigation resolves a (method, flowspec) pair against a fallback
// default. methodStr empty inherits defMethod; the flowspec block falls back
// to defFlow (the global flowspec policy) when the group omits its own. It
// returns the resolved method, action, and rate-limit ceiling in bytes/sec
// (0 for discard or for the blackhole method).
func resolveMitigation(methodStr string, flow *FlowSpec, defMethod MitigationMethod, defFlow *FlowSpec) (MitigationMethod, FlowSpecAction, float64, error) {
	method := defMethod
	if methodStr != "" {
		method = MitigationMethod(methodStr)
		switch method {
		case MitigateBlackhole, MitigateFlowSpec, MitigateDivert, MitigateDataplane:
		default:
			return "", "", 0, fmt.Errorf("method must be %q, %q, %q or %q, got %q",
				MitigateBlackhole, MitigateFlowSpec, MitigateDivert, MitigateDataplane, methodStr)
		}
	}
	if method != MitigateFlowSpec {
		return method, "", 0, nil
	}
	action, rate, err := resolveFlowSpecPolicy(flow, defFlow)
	return method, action, rate, err
}

// resolveSourceAnchor resolves the source-anchoring policy from the effective
// FlowSpec block (the group's own, else the default). It returns whether source
// anchoring is enabled and the resolved concentration gate (defaulting to 0.8
// when enabled without an explicit value).
func resolveSourceAnchor(flow, defFlow *FlowSpec) (bool, float64, error) {
	fs := flow
	if fs == nil {
		fs = defFlow
	}
	if fs == nil || !fs.SourceAnchored {
		return false, 0, nil
	}
	mc := fs.MinSourceConcentration
	if mc < 0 || mc > 1 {
		return false, 0, fmt.Errorf("flowspec.min_source_concentration must be in 0..1, got %g", mc)
	}
	if mc == 0 {
		mc = 0.8
	}
	return true, mc, nil
}

// resolveFlowSpecPolicy resolves the FlowSpec action policy (own block, else
// the default), returning the action and the rate-limit ceiling in bytes/sec
// (0 for discard).
func resolveFlowSpecPolicy(flow, defFlow *FlowSpec) (FlowSpecAction, float64, error) {
	fs := flow
	if fs == nil {
		fs = defFlow
	}
	action := FlowSpecDiscard
	var rateMbps float64
	if fs != nil {
		if fs.Action != "" {
			action = FlowSpecAction(fs.Action)
		}
		rateMbps = fs.RateMbps
	}
	switch action {
	case FlowSpecDiscard:
		return action, 0, nil
	case FlowSpecRateLimit:
		if rateMbps <= 0 {
			return "", 0, fmt.Errorf("flowspec.rate_mbps must be > 0 for the rate_limit action")
		}
		// Mbit/s → bytes/s for the FlowSpec traffic-rate extended community.
		return action, rateMbps * 1e6 / 8, nil
	default:
		return "", 0, fmt.Errorf("flowspec.action must be %q or %q, got %q", FlowSpecDiscard, FlowSpecRateLimit, fs.Action)
	}
}

// maxEscalationStages bounds a mitigation ladder.
const maxEscalationStages = 5

// AllMitigationMethods returns every mitigation method, so a table test can
// prove Action() maps each one to the mechanism that actually enforces it
// rather than silently to the default.
func AllMitigationMethods() []MitigationMethod {
	return []MitigationMethod{MitigateBlackhole, MitigateFlowSpec, MitigateDivert, MitigateDataplane}
}

// Action maps a mitigation method to the ladder action that ENFORCES it. This
// is the ONE mapping: the synthesized single-rung ladders (global, per-group
// and carpet) all resolve through it, so a method cannot be accepted by a
// validator in one place and then enforced by a different mechanism in another.
//
// It is written as a total switch with no catch-all on purpose. The catch-all
// it replaced returned blackhole for anything it did not recognise, which meant
// a method added to the type — or simply forgotten in one branch of a two-way
// `if` — quietly became "blackhole the target". On the carpet path that is a
// whole /24 (or /48) null-routed when the operator asked for a surgical drop.
// An unknown method now returns EscalateNone (alert only): the failure mode of
// a lost method must be "did nothing and said so", never "took more offline
// than anyone asked for".
func (m MitigationMethod) Action() EscalationAction {
	switch m {
	case MitigateBlackhole:
		return EscalateBlackhole
	case MitigateFlowSpec:
		return EscalateFlowSpec
	case MitigateDivert:
		return EscalateDivert
	case MitigateDataplane:
		return EscalateDataplane
	}
	return EscalateNone
}

// methodAction maps a single mitigation method to its ladder action. An empty
// method (no explicit configuration anywhere) keeps the historical default of
// blackhole; every named method resolves through MitigationMethod.Action.
func methodAction(m MitigationMethod) EscalationAction {
	if m == "" {
		return EscalateBlackhole
	}
	return m.Action()
}

// resolveEscalation resolves a mitigation ladder. An empty steps slice
// synthesizes a single rung from method (the back-compatible behavior).
// Otherwise the ladder must start at 0, strictly increase, and use valid
// actions.
func resolveEscalation(steps []EscalationStep, method MitigationMethod) ([]EscalationStage, error) {
	if len(steps) == 0 {
		return []EscalationStage{{AfterSeconds: 0, Action: methodAction(method)}}, nil
	}
	if len(steps) > maxEscalationStages {
		return nil, fmt.Errorf("escalation: at most %d stages, got %d", maxEscalationStages, len(steps))
	}
	stages := make([]EscalationStage, len(steps))
	prev := -1
	prevSev := -1
	for i, s := range steps {
		act := EscalationAction(s.Action)
		switch act {
		case EscalateNone, EscalateDataplane, EscalateFlowSpec, EscalateDivert, EscalateBlackhole:
		default:
			return nil, fmt.Errorf("escalation[%d].action must be none|dataplane|flowspec|divert|blackhole, got %q", i, s.Action)
		}
		if i == 0 && s.AfterSeconds != 0 {
			return nil, fmt.Errorf("escalation[0].after_seconds must be 0 (the initial stage)")
		}
		if s.AfterSeconds <= prev {
			return nil, fmt.Errorf("escalation[%d].after_seconds (%d) must be greater than the previous stage (%d)", i, s.AfterSeconds, prev)
		}
		if s.AfterSeconds > 86400 {
			return nil, fmt.Errorf("escalation[%d].after_seconds must be <= 86400, got %d", i, s.AfterSeconds)
		}
		// A ladder may only hold or strengthen the response. De-escalating
		// (e.g. blackhole then flowspec) is a configuration error: an
		// escalation ladder climbs, it does not back off.
		sev := escalationSeverity(act)
		if sev < prevSev {
			return nil, fmt.Errorf("escalation[%d].action (%q) de-escalates from the previous stage; a ladder may only hold or strengthen the response", i, s.Action)
		}
		prevSev = sev
		prev = s.AfterSeconds
		stages[i] = EscalationStage{AfterSeconds: s.AfterSeconds, Action: act}
	}
	return stages, nil
}

// escalationSeverity ranks ladder actions so a ladder can be validated as
// non-decreasing: none < dataplane < flowspec < divert < blackhole. Dataplane
// drops locally and announces nothing, so it is the most surgical response and
// sits just above alert-only; divert (scrub) keeps the victim reachable, so it
// sits below the all-dropping blackhole.
func escalationSeverity(a EscalationAction) int {
	switch a {
	case EscalateBlackhole:
		return 4
	case EscalateDivert:
		return 3
	case EscalateFlowSpec:
		return 2
	case EscalateDataplane:
		return 1
	default: // EscalateNone
		return 0
	}
}

// usesFlowSpec reports whether any stage announces FlowSpec.
func usesFlowSpec(stages []EscalationStage) bool {
	for _, s := range stages {
		if s.Action == EscalateFlowSpec {
			return true
		}
	}
	return false
}

// usesDivert reports whether any stage diverts to a scrubbing center.
func usesDivert(stages []EscalationStage) bool {
	for _, s := range stages {
		if s.Action == EscalateDivert {
			return true
		}
	}
	return false
}

// usesDataplane reports whether any stage drops in the local XDP data plane.
func usesDataplane(stages []EscalationStage) bool {
	for _, s := range stages {
		if s.Action == EscalateDataplane {
			return true
		}
	}
	return false
}

// DivertGeneratesRules reports whether a divert ladder will produce FlowSpec
// rules that some backend must be able to compile — so the group needs a
// resolved FlowSpec action AND mitigate.ban must generate the rules. Two cases:
// the divert targets a MANAGED scrub node (which enforces the rules in its own
// data plane), or on_all_nodes_lost is flowspec (which announces them when
// every node is down). Exported and shared by BOTH sides on purpose: config
// resolves the action exactly when mitigate generates the rules, and a single
// predicate is the only way to keep them from drifting into a ban whose rules
// carry an action the config never resolved. An unmanaged scalar next-hop needs
// neither: a third-party scrubber decides its own policy.
func DivertGeneratesRules(stages []EscalationStage, s *Scrubbing) bool {
	if !usesDivert(stages) {
		return false
	}
	return len(s.Nodes) > 0 || s.OnAllNodesLost == NodesLostFlowSpec
}

// validateStorage resolves the storage block into StorageCfg with defaults.
// A nil/empty URL leaves persistence disabled with no further checks.
func (c *Config) validateStorage() error {
	ch := c.Storage.ClickHouse
	if ch.URL == "" {
		c.StorageCfg = StorageSettings{}
		return nil
	}
	u, err := url.ParseRequestURI(ch.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("storage.clickhouse.url must be an http(s) URL, got %q", ch.URL)
	}
	s := StorageSettings{
		Enabled:         true,
		URL:             strings.TrimRight(ch.URL, "/"),
		Database:        ch.Database,
		UsernameEnv:     ch.UsernameEnv,
		PasswordEnv:     ch.PasswordEnv,
		TTLDays:         ch.TTLDays,
		BatchSize:       ch.BatchSize,
		QueueSize:       ch.QueueSize,
		FlushInterval:   time.Duration(ch.FlushIntervalSeconds) * time.Second,
		TrafficInterval: time.Duration(ch.TrafficIntervalSeconds) * time.Second,
	}
	if s.Database == "" {
		s.Database = "kapkan"
	}
	if !dbNameRe.MatchString(s.Database) {
		return fmt.Errorf("storage.clickhouse.database %q must match %s", s.Database, dbNameRe)
	}
	for env, name := range map[string]string{ch.UsernameEnv: "username_env", ch.PasswordEnv: "password_env"} {
		if env != "" && !envNameRe.MatchString(env) {
			return fmt.Errorf("storage.clickhouse.%s %q is not a valid environment variable name", name, env)
		}
	}
	if s.TTLDays == 0 {
		s.TTLDays = 7
	}
	if s.BatchSize == 0 {
		s.BatchSize = 1000
	}
	if s.QueueSize == 0 {
		s.QueueSize = 100000
	}
	if s.FlushInterval == 0 {
		s.FlushInterval = 5 * time.Second
	}
	if s.TrafficInterval == 0 {
		s.TrafficInterval = 10 * time.Second
	}
	if s.TTLDays < 1 || s.TTLDays > 365 {
		return fmt.Errorf("storage.clickhouse.ttl_days must be in 1..365, got %d", s.TTLDays)
	}
	if s.BatchSize < 1 || s.BatchSize > s.QueueSize {
		return fmt.Errorf("storage.clickhouse.batch_size must be in 1..queue_size (%d), got %d", s.QueueSize, s.BatchSize)
	}
	if s.QueueSize < 1 || s.QueueSize > 10_000_000 {
		return fmt.Errorf("storage.clickhouse.queue_size must be in 1..10000000, got %d", s.QueueSize)
	}
	if s.FlushInterval < time.Second || s.FlushInterval > time.Hour {
		return fmt.Errorf("storage.clickhouse.flush_interval_seconds must be in 1..3600, got %d", ch.FlushIntervalSeconds)
	}
	if s.TrafficInterval < time.Second || s.TrafficInterval > time.Hour {
		return fmt.Errorf("storage.clickhouse.traffic_interval_seconds must be in 1..3600, got %d", ch.TrafficIntervalSeconds)
	}
	c.StorageCfg = s
	return nil
}

// validateSamples resolves the samples block into SampleCfg with defaults.
func (c *Config) validateSamples() error {
	s := SampleSettings{
		Enabled:        c.Samples.Enabled == nil || *c.Samples.Enabled,
		BufferFlows:    c.Samples.BufferFlows,
		FlowsPerAttack: c.Samples.FlowsPerAttack,
	}
	if !s.Enabled {
		// Sizes are meaningless while disabled; normalize them so reload
		// does not demand a restart for edits that change nothing.
		c.SampleCfg = SampleSettings{}
		return nil
	}
	if s.BufferFlows == 0 {
		s.BufferFlows = 65536
	}
	if s.FlowsPerAttack == 0 {
		s.FlowsPerAttack = 20
	}
	if s.BufferFlows < 256 || s.BufferFlows > 1<<20 {
		// Lower bound: one slot per shard. Upper bound: ~120 MB of fixed
		// memory, and sample collection cost scales linearly with ring
		// size while shard locks are held — an unbounded value lets a
		// config typo OOM the daemon or stall the evaluation loop.
		return fmt.Errorf("samples.buffer_flows must be in 256..1048576, got %d", s.BufferFlows)
	}
	if s.FlowsPerAttack < 1 || s.FlowsPerAttack > 500 {
		return fmt.Errorf("samples.flows_per_attack must be in 1..500, got %d", s.FlowsPerAttack)
	}
	c.SampleCfg = s
	return nil
}

// validateGeoIP resolves the geoip block into GeoIPCfg. When enabled at least
// one database path must be set and every set path must point at a readable
// file, so a typo fails fast at load instead of silently disabling attribution.
func (c *Config) validateGeoIP() error {
	g := c.GeoIP
	if !g.Enabled {
		// Normalize when disabled so reload does not demand a restart for an
		// edit that changes nothing the running engine observes.
		c.GeoIPCfg = GeoIPSettings{}
		return nil
	}
	if g.ASNDatabase == "" && g.CountryDatabase == "" {
		return fmt.Errorf("geoip.enabled is true but neither asn_database nor country_database is set")
	}
	for name, path := range map[string]string{"asn_database": g.ASNDatabase, "country_database": g.CountryDatabase} {
		if path == "" {
			continue
		}
		fi, err := statFile(path)
		switch {
		case errors.Is(err, errStatDeferred):
			// browser/wasm build: cannot stat; the server verifies at load.
		case err != nil:
			return fmt.Errorf("geoip.%s %q: %w", name, path, err)
		case fi.IsDir():
			return fmt.Errorf("geoip.%s %q is a directory, expected an .mmdb file", name, path)
		}
	}
	c.GeoIPCfg = GeoIPSettings{
		Enabled:     true,
		ASNPath:     g.ASNDatabase,
		CountryPath: g.CountryDatabase,
	}
	return nil
}

// GroupIndexFor returns the index into Groups of the group owning addr by
// longest prefix match; 0 (the implicit global group) when no hostgroup
// prefix matches.
func (c *Config) GroupIndexFor(addr netip.Addr) int {
	for i := range c.groupRoutes {
		if c.groupRoutes[i].prefix.Contains(addr) {
			return c.groupRoutes[i].group
		}
	}
	return 0
}

// GroupFor returns the resolved group owning addr by longest prefix match,
// falling back to the implicit global group. The returned pointer is into
// the immutable Config and must not be modified.
func (c *Config) GroupFor(addr netip.Addr) *Group {
	return &c.Groups[c.GroupIndexFor(addr)]
}

func (c *Config) validateBGP() error {
	b := &c.BGP
	if b.LocalASN == 0 {
		return fmt.Errorf("bgp.local_asn must be > 0")
	}
	rid, err := netip.ParseAddr(b.RouterID)
	if err != nil || !rid.Is4() {
		return fmt.Errorf("bgp.router_id must be a valid IPv4 address, got %q", b.RouterID)
	}
	nh, err := netip.ParseAddr(b.NextHop)
	if err != nil || !nh.Is4() {
		return fmt.Errorf("bgp.next_hop must be a valid IPv4 address, got %q", b.NextHop)
	}
	if b.NextHop6 != "" {
		nh6, err := netip.ParseAddr(b.NextHop6)
		if err != nil || !nh6.Is6() || nh6.Is4In6() {
			return fmt.Errorf("bgp.next_hop6 must be a valid IPv6 address, got %q", b.NextHop6)
		}
	}
	val, err := ParseCommunity(b.Community)
	if err != nil {
		return fmt.Errorf("bgp.community: %w", err)
	}
	b.CommunityValue = val
	// The default blackhole community set is the explicit list when given,
	// otherwise just the single `community`. An explicit but empty list is a
	// mistake (reject it rather than silently fall back to `community`).
	switch {
	case b.Communities == nil:
		b.CommunityValues = []uint32{val}
		b.CommunityStr = b.Community
	case len(b.Communities) == 0:
		return fmt.Errorf("bgp.communities: provide at least one community, or omit it to use bgp.community")
	default:
		vals, str, err := parseCommunities(b.Communities)
		if err != nil {
			return fmt.Errorf("bgp.communities: %w", err)
		}
		b.CommunityValues, b.CommunityStr = vals, str
	}
	for i, n := range b.Neighbors {
		if _, err := netip.ParseAddr(n.Address); err != nil {
			return fmt.Errorf("bgp.neighbors[%d]: invalid address %q: %w", i, n.Address, err)
		}
		if n.RemoteASN == 0 {
			return fmt.Errorf("bgp.neighbors[%d]: remote_asn must be > 0", i)
		}
	}
	gr := &b.GracefulRestart
	// Bounds match the JSON schema and are enforced regardless of Enabled; 0
	// means "use the default", so it is always accepted. RestartSeconds rides the
	// 12-bit GR restart-time field (max 4095s); LLGR stale time is capped at 24h.
	if gr.RestartSeconds > 4095 {
		return fmt.Errorf("bgp.graceful_restart.restart_seconds must be 0..4095, got %d", gr.RestartSeconds)
	}
	if gr.LongLivedStaleSeconds > 86400 {
		return fmt.Errorf("bgp.graceful_restart.long_lived_stale_seconds must be 0..86400, got %d", gr.LongLivedStaleSeconds)
	}
	if gr.Enabled {
		if gr.RestartSeconds == 0 {
			gr.RestartSeconds = 120
		}
		if gr.LongLived && gr.LongLivedStaleSeconds == 0 {
			gr.LongLivedStaleSeconds = 3600
		}
	}
	return nil
}

// validateScrubbing validates the optional scrubbing (traffic-diversion)
// target and resolves its community set. The next-hops are only REQUIRED when a
// ladder actually diverts; that per-group check happens in validateHostgroups.
// Here we just parse what is present so the values are ready as defaults.
// validateEdge checks the brain-side edge block. The zones FILE is not read
// here — validate() must stay pure (it is what the browser-side validator and
// Parse run) — Load follows edge.zones_file afterwards and fails the whole load
// if the zones do not validate.
func (c *Config) validateEdge() error {
	e := c.Edge
	if e == nil {
		return nil
	}
	if e.ZonesFile == "" {
		return fmt.Errorf("edge.zones_file is required when the edge block is present (the zones.yaml this brain serves)")
	}
	if !filepath.IsAbs(e.ZonesFile) {
		// Absolute so the daemon and `kapkan -check-config` resolve the same
		// file regardless of working directory.
		return fmt.Errorf("edge.zones_file must be an absolute path, got %q", e.ZonesFile)
	}
	seen := make(map[string]int, len(e.Nodes))
	for i, n := range e.Nodes {
		if !groupNameRe.MatchString(n.Name) {
			return fmt.Errorf("edge.nodes[%d].name %q must match %s", i, n.Name, groupNameRe)
		}
		if j, dup := seen[n.Name]; dup {
			return fmt.Errorf("edge.nodes[%d]: duplicate node name %q (also edge.nodes[%d])", i, n.Name, j)
		}
		seen[n.Name] = i
	}
	if e.StaleAfterSeconds == 0 {
		e.StaleAfterSeconds = 15
	}
	if e.StaleAfterSeconds < 1 {
		return fmt.Errorf("edge.stale_after_seconds must be > 0, got %d", e.StaleAfterSeconds)
	}
	return nil
}

func (c *Config) validateScrubbing() error {
	s := &c.Scrubbing
	if s.NextHop != "" {
		a, err := netip.ParseAddr(s.NextHop)
		if err != nil || !a.Is4() {
			return fmt.Errorf("scrubbing.next_hop must be a valid IPv4 address, got %q", s.NextHop)
		}
	}
	if s.NextHop6 != "" {
		a, err := netip.ParseAddr(s.NextHop6)
		if err != nil || !a.Is6() || a.Is4In6() {
			return fmt.Errorf("scrubbing.next_hop6 must be a valid IPv6 address, got %q", s.NextHop6)
		}
	}
	// The divert community is optional (the next-hop does the rerouting): an
	// explicit list, else the single `community`, else no community at all.
	switch {
	case len(s.Communities) > 0:
		vals, str, err := parseCommunities(s.Communities)
		if err != nil {
			return fmt.Errorf("scrubbing.communities: %w", err)
		}
		s.CommunityValues, s.CommunityStr = vals, str
	case s.Communities != nil:
		return fmt.Errorf("scrubbing.communities: provide at least one community, or omit it")
	case s.Community != "":
		v, err := ParseCommunity(s.Community)
		if err != nil {
			return fmt.Errorf("scrubbing.community: %w", err)
		}
		s.CommunityValues, s.CommunityStr = []uint32{v}, s.Community
	}

	// Managed scrubbing nodes. The node list is validated here so its shape is
	// frozen from the first release that ships it; selection and failover are
	// consumed by the mitigator later. The scalar next_hop above remains the
	// one-node degenerate case, which is the migration path for anyone already
	// diverting to a next-hop we do not manage.
	seen := make(map[string]struct{}, len(s.Nodes))
	for i, n := range s.Nodes {
		if !groupNameRe.MatchString(n.Name) {
			return fmt.Errorf("scrubbing.nodes[%d].name %q must match %s", i, n.Name, groupNameRe)
		}
		if _, dup := seen[n.Name]; dup {
			return fmt.Errorf("scrubbing.nodes[%d]: duplicate node name %q", i, n.Name)
		}
		seen[n.Name] = struct{}{}
		a, err := netip.ParseAddr(n.NextHop)
		if err != nil || !a.Is4() {
			return fmt.Errorf("scrubbing.nodes[%q].next_hop must be a valid IPv4 address, got %q", n.Name, n.NextHop)
		}
		if n.NextHop6 != "" {
			a6, err := netip.ParseAddr(n.NextHop6)
			if err != nil || !a6.Is6() || a6.Is4In6() {
				return fmt.Errorf("scrubbing.nodes[%q].next_hop6 must be a valid IPv6 address, got %q", n.Name, n.NextHop6)
			}
		}
	}

	switch s.NodeSelection {
	case "":
		s.NodeSelection = NodeSelectAffinity
	case NodeSelectAffinity, NodeSelectLeastLoaded, NodeSelectECMP:
	default:
		return fmt.Errorf("scrubbing.node_selection must be %q, %q or %q, got %q",
			NodeSelectAffinity, NodeSelectLeastLoaded, NodeSelectECMP, s.NodeSelection)
	}
	switch s.OnAllNodesLost {
	case "":
		s.OnAllNodesLost = NodesLostWithdraw
	case NodesLostWithdraw, NodesLostBlackhole, NodesLostFlowSpec:
	default:
		return fmt.Errorf("scrubbing.on_all_nodes_lost must be %q, %q or %q, got %q",
			NodesLostWithdraw, NodesLostBlackhole, NodesLostFlowSpec, s.OnAllNodesLost)
	}
	if s.StaleAfterSeconds == 0 {
		s.StaleAfterSeconds = defaultStaleAfterSeconds
	}
	if s.StaleAfterSeconds < 1 {
		return fmt.Errorf("scrubbing.stale_after_seconds must be > 0, got %d", s.StaleAfterSeconds)
	}
	if len(s.Nodes) == 0 && (s.NodeSelection != NodeSelectAffinity || s.OnAllNodesLost != NodesLostWithdraw) {
		return fmt.Errorf("scrubbing: node_selection and on_all_nodes_lost require at least one scrubbing.nodes entry")
	}
	return nil
}

// hasNodeTargetFor reports whether the scrubbing block offers a usable managed
// node FOR THIS GROUP and family, i.e. whether diverting a victim of this
// group can land somewhere even when the scalar next-hop is unset. Hostgroup-
// aware on purpose: a node restricted to other groups is not a target for this
// one, and validation that ignored the restriction blessed configs whose
// unclaimed victims would divert to an empty next-hop — an announce the peer
// rejects, silently degrading the victim to the fallback (blackhole) instead
// of scrubbing it.
func (s *Scrubbing) hasNodeTargetFor(group string, v6 bool) bool {
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if v6 {
			if n.NextHop6 == "" {
				continue
			}
		} else if n.NextHop == "" {
			continue
		}
		if len(n.Hostgroups) == 0 {
			return true // an unrestricted node serves every group
		}
		for _, g := range n.Hostgroups {
			if g == group {
				return true
			}
		}
	}
	return false
}

// validateDataplane resolves the dataplane block into DataplaneCfg, applying
// defaults and checking everything that can be checked without touching the
// machine. It deliberately performs no filesystem or netlink lookups: this
// package compiles to wasm for the kapkan.io config builder, so interface
// names and the pin path are checked syntactically only. Whether the NIC
// exists and whether the kernel will load the program are answered at attach
// time, by a clean startup error.
func (c *Config) validateDataplane() error {
	set, err := validateDataplaneBlock(c.Dataplane)
	if err != nil {
		return err
	}
	if set.Enabled {
		// Every ban may install up to maxRulesPerAttack entries. Sizing the map
		// below that ceiling means installs start failing mid-attack and quietly
		// falling back to blackhole, so refuse the configuration up front. This
		// cross-field check lives HERE and not in validateDataplaneBlock because
		// only the daemon role has ban caps — a scrub node's dynamic rules are
		// bounded by the brain that feeds it.
		if need := c.Ban.MaxActiveBans * maxDataplaneRulesPerBan; c.Ban.MaxActiveBans > 0 && need > c.Dataplane.Limits.MaxDynamicRules {
			return fmt.Errorf("dataplane.limits.max_dynamic_rules (%d) is below ban.max_active_bans * %d (%d): installs would fail mid-attack",
				c.Dataplane.Limits.MaxDynamicRules, maxDataplaneRulesPerBan, need)
		}
	}
	c.DataplaneCfg = set
	if c.Dataplane != nil {
		c.DataplaneAllowlist = make([]netip.Prefix, 0, len(c.Dataplane.Allowlist))
		for _, s := range c.Dataplane.Allowlist {
			p, err := parsePrefixOrAddr(s)
			if err != nil {
				// Unreachable: validateDataplaneBlock rejected malformed
				// entries just above. Kept as an error rather than a panic so
				// a future reordering fails loudly instead of half-parsing.
				return fmt.Errorf("dataplane.allowlist: %w", err)
			}
			c.DataplaneAllowlist = append(c.DataplaneAllowlist, p)
		}
	}
	return nil
}

// validateDataplaneBlock validates and defaults one dataplane block, returning
// its resolved comparable settings. A free function rather than a Config method
// because TWO roles carry the block: the daemon's kapkan.yaml and the scrub
// node's scrub.yaml — same keys, same defaults, same rejections, one validator.
func validateDataplaneBlock(d *Dataplane) (DataplaneSettings, error) {
	if d == nil {
		return DataplaneSettings{}, nil
	}
	if d.Enabled != nil && !*d.Enabled {
		// Present but switched off: zero the resolved form so a cosmetic edit
		// to a disabled block never demands a restart. A fingerprint block that
		// is on while the data plane is off is a misconfiguration, not a no-op:
		// say so rather than silently ignoring it.
		if d.Fingerprint.Enabled {
			return DataplaneSettings{}, fmt.Errorf(
				"dataplane.fingerprint.enabled requires dataplane.enabled: true (the plane runs in the kernel data plane)")
		}
		return DataplaneSettings{}, nil
	}

	if len(d.Interfaces) == 0 {
		return DataplaneSettings{}, fmt.Errorf("dataplane.interfaces: name at least one interface to attach to")
	}
	seenIface := make(map[string]struct{}, len(d.Interfaces))
	for i, name := range d.Interfaces {
		if !ifaceNameRe.MatchString(name) {
			return DataplaneSettings{}, fmt.Errorf("dataplane.interfaces[%d]: %q is not a valid interface name", i, name)
		}
		if _, dup := seenIface[name]; dup {
			return DataplaneSettings{}, fmt.Errorf("dataplane.interfaces[%d]: %q is listed twice", i, name)
		}
		seenIface[name] = struct{}{}
	}

	switch d.XDPMode {
	case "":
		d.XDPMode = XDPModeAuto
	case XDPModeAuto, XDPModeNative, XDPModeGeneric:
	default:
		return DataplaneSettings{}, fmt.Errorf("dataplane.xdp_mode must be %q, %q or %q, got %q",
			XDPModeAuto, XDPModeNative, XDPModeGeneric, d.XDPMode)
	}

	switch d.OnExit {
	case "":
		d.OnExit = OnExitKeep
	case OnExitKeep, OnExitDetach:
	default:
		return DataplaneSettings{}, fmt.Errorf("dataplane.on_exit must be %q or %q, got %q", OnExitKeep, OnExitDetach, d.OnExit)
	}

	if d.PinPath == "" {
		d.PinPath = defaultPinPath
	} else if !strings.HasPrefix(d.PinPath, "/") {
		return DataplaneSettings{}, fmt.Errorf("dataplane.pin_path must be an absolute path, got %q", d.PinPath)
	}

	for i, s := range d.Allowlist {
		if _, err := parsePrefixOrAddr(s); err != nil {
			return DataplaneSettings{}, fmt.Errorf("dataplane.allowlist[%d]: %w", i, err)
		}
	}

	profiles := make(map[string]struct{}, len(d.RateLimitProfiles))
	for i, p := range d.RateLimitProfiles {
		if !groupNameRe.MatchString(p.Name) {
			return DataplaneSettings{}, fmt.Errorf("dataplane.ratelimit_profiles[%d].name %q must match %s", i, p.Name, groupNameRe)
		}
		if _, dup := profiles[p.Name]; dup {
			return DataplaneSettings{}, fmt.Errorf("dataplane.ratelimit_profiles[%d]: duplicate profile name %q", i, p.Name)
		}
		if p.PPS == 0 && p.Mbps == 0 {
			return DataplaneSettings{}, fmt.Errorf("dataplane.ratelimit_profiles[%q]: set pps, mbps or both", p.Name)
		}
		profiles[p.Name] = struct{}{}
	}

	referenced := make(map[string]struct{}, len(profiles))
	seenRule := make(map[string]struct{}, len(d.StaticRules))
	for i, r := range d.StaticRules {
		if !groupNameRe.MatchString(r.Name) {
			return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%d].name %q must match %s", i, r.Name, groupNameRe)
		}
		if _, dup := seenRule[r.Name]; dup {
			return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%d]: duplicate rule name %q", i, r.Name)
		}
		seenRule[r.Name] = struct{}{}

		if r.Match.Src != "" {
			if _, err := parsePrefixOrAddr(r.Match.Src); err != nil {
				return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q].match.src: %w", r.Name, err)
			}
		}
		switch r.Match.Proto {
		case "", "tcp", "udp", "icmp", "icmp6":
		default:
			return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q].match.proto must be tcp|udp|icmp|icmp6, got %q", r.Name, r.Match.Proto)
		}
		if r.Match.Proto == "icmp" || r.Match.Proto == "icmp6" {
			if r.Match.SrcPort != 0 || r.Match.DstPort != 0 {
				return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q]: ports are meaningless for %s", r.Name, r.Match.Proto)
			}
		}
		switch r.Match.Payload {
		case "":
		case StaticPayloadTLSClientHello:
			// proto: tcp is REQUIRED, not merely recommended, even though the
			// datapath sets the ClientHello bit on TCP alone and an unset proto
			// would select the same packets. The rule has to say what it means
			// at the place an operator reads it: the commonest misreading of a
			// bare "tls_client_hello" is that it also covers HTTP/3, whose
			// handshake is inside QUIC on UDP/443 and is encrypted before this
			// program ever sees it.
			if r.Match.Proto != "tcp" {
				return DataplaneSettings{}, fmt.Errorf(
					"dataplane.static_rules[%q].match.payload %q requires proto: tcp (got %q) — "+
						"the ClientHello is read from the TCP payload; for QUIC/HTTP3 handshakes on UDP use %q",
					r.Name, r.Match.Payload, r.Match.Proto, StaticPayloadQUICInitial)
			}
		case StaticPayloadQUICInitial:
			// proto: udp is REQUIRED for the same say-what-you-mean reason
			// tls_client_hello requires tcp: the commonest misreading of a
			// bare "quic_initial" is that it is another way to spell the TLS
			// handshake, when it selects the opposite transport.
			if r.Match.Proto != "udp" {
				return DataplaneSettings{}, fmt.Errorf(
					"dataplane.static_rules[%q].match.payload %q requires proto: udp (got %q) — "+
						"a QUIC Initial is read from the UDP payload; for TLS over TCP use %q",
					r.Name, r.Match.Payload, r.Match.Proto, StaticPayloadTLSClientHello)
			}
		default:
			return DataplaneSettings{}, fmt.Errorf(
				"dataplane.static_rules[%q].match.payload must be %s or %s, got %q",
				r.Name, StaticPayloadTLSClientHello, StaticPayloadQUICInitial, r.Match.Payload)
		}

		switch r.Action {
		case StaticActionPass, StaticActionDrop:
			if r.Profile != "" {
				return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q]: profile is only valid with the %q action", r.Name, StaticActionRateLimit)
			}
		case StaticActionRateLimit:
			if r.Profile == "" {
				return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q]: the %q action requires profile", r.Name, StaticActionRateLimit)
			}
			if _, ok := profiles[r.Profile]; !ok {
				return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q]: profile %q is not declared in dataplane.ratelimit_profiles", r.Name, r.Profile)
			}
			referenced[r.Profile] = struct{}{}
		case "":
			return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q]: action is required (%s|%s|%s)", r.Name, StaticActionPass, StaticActionDrop, StaticActionRateLimit)
		default:
			return DataplaneSettings{}, fmt.Errorf("dataplane.static_rules[%q].action must be %s|%s|%s, got %q", r.Name, StaticActionPass, StaticActionDrop, StaticActionRateLimit, r.Action)
		}
	}

	if d.Limits.MaxDynamicRules == 0 {
		d.Limits.MaxDynamicRules = defaultMaxDynamicRules
	}
	if d.Limits.MaxStaticRules == 0 {
		d.Limits.MaxStaticRules = defaultMaxStaticRules
	}
	if d.Limits.MaxRatelimitSources == 0 {
		d.Limits.MaxRatelimitSources = defaultMaxRatelimitSources
	}
	if d.Limits.MaxDynamicRules < 1 {
		return DataplaneSettings{}, fmt.Errorf("dataplane.limits.max_dynamic_rules must be > 0, got %d", d.Limits.MaxDynamicRules)
	}
	if d.Limits.MaxStaticRules < 1 {
		return DataplaneSettings{}, fmt.Errorf("dataplane.limits.max_static_rules must be > 0, got %d", d.Limits.MaxStaticRules)
	}
	if d.Limits.MaxRatelimitSources < 1 {
		return DataplaneSettings{}, fmt.Errorf("dataplane.limits.max_ratelimit_sources must be > 0, got %d", d.Limits.MaxRatelimitSources)
	}
	if n := len(d.StaticRules); n > d.Limits.MaxStaticRules {
		return DataplaneSettings{}, fmt.Errorf("dataplane: %d static_rules exceed limits.max_static_rules (%d)", n, d.Limits.MaxStaticRules)
	}
	if err := validateFingerprint(&d.Fingerprint); err != nil {
		return DataplaneSettings{}, err
	}
	return DataplaneSettings{
		Enabled:              true,
		Interfaces:           strings.Join(d.Interfaces, ","),
		XDPMode:              d.XDPMode,
		PinPath:              d.PinPath,
		OnExit:               d.OnExit,
		MaxDynamicRules:      d.Limits.MaxDynamicRules,
		MaxStaticRules:       d.Limits.MaxStaticRules,
		MaxRatelimitSources:  d.Limits.MaxRatelimitSources,
		FingerprintEnabled:   d.Fingerprint.Enabled,
		FingerprintSamplePPS: d.Fingerprint.SamplePPS,
	}, nil
}

// validateFingerprint checks and defaults the fingerprint-plane block. It runs
// only when the data plane is enabled (its caller has already returned for a
// disabled block), and is a no-op when the plane itself is off so a disabled
// block with stray values never blocks startup.
func validateFingerprint(fp *DataplaneFingerprint) error {
	if !fp.Enabled {
		// Zero the kernel-affecting knob so a cosmetic edit to sample_pps on a
		// disabled plane never trips the restart-required diff — it has no effect
		// while the plane is off (mirrors how a disabled dataplane block resolves
		// to the zero DataplaneSettings).
		fp.SamplePPS = 0
		return nil
	}
	if fp.SamplePPS == 0 {
		fp.SamplePPS = defaultFingerprintSamplePPS
	}
	if fp.BlockTTLSeconds == 0 {
		fp.BlockTTLSeconds = defaultFingerprintBlockTTLSeconds
	}
	if fp.BlockTTLSeconds < 1 || fp.BlockTTLSeconds > maxFingerprintBlockTTLSeconds {
		return fmt.Errorf("dataplane.fingerprint.block_ttl_seconds must be within [1, %d], got %d",
			maxFingerprintBlockTTLSeconds, fp.BlockTTLSeconds)
	}
	seen := make(map[string]struct{}, len(fp.JA4Blocklist))
	for i, j := range fp.JA4Blocklist {
		if !looksLikeJA4(j) {
			return fmt.Errorf("dataplane.fingerprint.ja4_blocklist[%d]: %q is not a JA4 fingerprint "+
				"(want a_b_c, e.g. t13d1516h2_8daaf6152771_e5627efa2ab1)", i, j)
		}
		if _, dup := seen[j]; dup {
			return fmt.Errorf("dataplane.fingerprint.ja4_blocklist[%d]: duplicate entry %q", i, j)
		}
		seen[j] = struct{}{}
	}
	return nil
}

// looksLikeJA4 accepts the canonical JA4 shape a_b_c where b and c are the two
// 12-hex-char hashes. It is a typo guard, not a full grammar for JA4's variants
// (this build only ever matches against the canonical form it computes).
func looksLikeJA4(s string) bool {
	parts := strings.Split(s, "_")
	if len(parts) != 3 || parts[0] == "" {
		return false
	}
	return isHex12(parts[1]) && isHex12(parts[2])
}

func isHex12(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DataplaneEnabled reports whether the in-kernel filter is configured and on.
func (c *Config) DataplaneEnabled() bool { return c.DataplaneCfg.Enabled }

// requireDataplane rejects a ladder that drops in the kernel while the
// dataplane block is missing or switched off — the mitigator would have
// nowhere to install its rules and would silently fall back on every attack.
func (c *Config) requireDataplane(group string) error {
	switch {
	case c.Dataplane == nil:
		return fmt.Errorf("group %q: the %q action requires a dataplane block", group, EscalateDataplane)
	case !c.DataplaneCfg.Enabled:
		return fmt.Errorf("group %q: the %q action requires dataplane.enabled: true", group, EscalateDataplane)
	}
	return nil
}

// validateAPITokens resolves the API credential set into API.TokenSpecs. A
// lone token_env is a single operator token (back-compat); a tokens list is
// role-based and supersedes it; setting both is an error. An empty result
// leaves the API open (safe only on a trusted listener).
func (c *Config) validateAPITokens() error {
	a := &c.API
	a.TokenSpecs = nil

	if len(a.Tokens) > 0 {
		if a.TokenEnv != "" {
			return fmt.Errorf("api: set either token_env (single token) or tokens (role-based list), not both")
		}
		// Tenant labels actually in use, to reject a token scoped to a tenant
		// that owns no prefixes (a typo would silently see nothing).
		tenants := make(map[string]bool)
		for _, g := range c.Groups {
			if g.Tenant != "" {
				tenants[g.Tenant] = true
			}
		}
		names := make(map[string]bool, len(a.Tokens))
		for i, tk := range a.Tokens {
			if tk.Name == "" {
				return fmt.Errorf("api.tokens[%d]: name is required", i)
			}
			if names[tk.Name] {
				return fmt.Errorf("api.tokens[%d]: duplicate name %q", i, tk.Name)
			}
			names[tk.Name] = true
			if !envNameRe.MatchString(tk.TokenEnv) {
				return fmt.Errorf("api.tokens[%q]: token_env %q is not a valid environment variable name", tk.Name, tk.TokenEnv)
			}
			role := Role(tk.Role)
			if role != RoleViewer && role != RoleOperator && role != RoleAgent {
				return fmt.Errorf("api.tokens[%q]: role must be %q, %q or %q, got %q", tk.Name, RoleViewer, RoleOperator, RoleAgent, tk.Role)
			}
			// An agent token is refused a tenant OUTRIGHT rather than ignored
			// with one: the rules document it reads is unscoped (it spans every
			// tenant), so a tenant here would promise a scoping that nothing
			// enforces. When per-node scoping lands (the fleet milestone), it
			// will be by hostgroup, and this rule can be relaxed deliberately.
			if role == RoleAgent && tk.Tenant != "" {
				return fmt.Errorf("api.tokens[%q]: an agent token cannot be tenant-scoped (the rules feed is deployment-wide)", tk.Name)
			}
			if tk.Tenant != "" && !tenants[tk.Tenant] {
				return fmt.Errorf("api.tokens[%q]: tenant %q is not used by any hostgroup", tk.Name, tk.Tenant)
			}
			a.TokenSpecs = append(a.TokenSpecs, TokenSpec{Name: tk.Name, Env: tk.TokenEnv, Role: role, Tenant: tk.Tenant})
		}
		return nil
	}

	if a.TokenEnv != "" {
		if !envNameRe.MatchString(a.TokenEnv) {
			return fmt.Errorf("api.token_env %q is not a valid environment variable name", a.TokenEnv)
		}
		a.TokenSpecs = []TokenSpec{{Name: "default", Env: a.TokenEnv, Role: RoleOperator}}
	}
	return nil
}

// validateNotify checks the optional notification channels and applies the
// exec hook's default timeout.
func (c *Config) validateNotify() error {
	n := &c.Notify
	if n.Slack.WebhookURL != "" {
		u, err := url.ParseRequestURI(n.Slack.WebhookURL)
		if err != nil {
			return fmt.Errorf("notify.slack.webhook_url: invalid URL %q", n.Slack.WebhookURL)
		}
		// Slack webhooks are https-only and the path is a bearer secret;
		// plain http would leak it. The loopback exception exists for
		// local relays and tests.
		if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
			return fmt.Errorf("notify.slack.webhook_url must be https (or http to a loopback address), got %q", n.Slack.WebhookURL)
		}
	}

	if n.Email.SMTPHost != "" {
		host, portStr, err := net.SplitHostPort(n.Email.SMTPHost)
		if err != nil || host == "" {
			return fmt.Errorf("notify.email.smtp_host must be host:port, got %q", n.Email.SMTPHost)
		}
		if port, err := strconv.Atoi(portStr); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("notify.email.smtp_host: bad port %q", portStr)
		}
		if n.Email.From == "" {
			return fmt.Errorf("notify.email.from is required when smtp_host is set")
		}
		if len(n.Email.To) == 0 {
			return fmt.Errorf("notify.email.to needs at least one recipient when smtp_host is set")
		}
		for i, rcpt := range n.Email.To {
			if rcpt == "" {
				return fmt.Errorf("notify.email.to[%d] is empty", i)
			}
		}
	}

	if n.Exec.Command != "" {
		if !filepath.IsAbs(n.Exec.Command) {
			return fmt.Errorf("notify.exec.command must be an absolute path, got %q", n.Exec.Command)
		}
		// Fail at config load, not at the first attack: a typo'd hook
		// path discovered mid-incident means silently lost notifications.
		fi, err := statFile(n.Exec.Command)
		switch {
		case errors.Is(err, errStatDeferred):
			// browser/wasm build: cannot stat; the server verifies at load.
		case err != nil:
			return fmt.Errorf("notify.exec.command: %w", err)
		case fi.IsDir() || fi.Mode()&0o111 == 0:
			return fmt.Errorf("notify.exec.command %q is not an executable file", n.Exec.Command)
		}
	}
	switch n.Exec.Format {
	case "":
		n.Exec.Format = ExecFormatKapkan
	case ExecFormatKapkan, ExecFormatFastNetMon:
	default:
		return fmt.Errorf("notify.exec.format must be %q or %q, got %q", ExecFormatKapkan, ExecFormatFastNetMon, n.Exec.Format)
	}
	if n.Exec.TimeoutSeconds == 0 {
		n.Exec.TimeoutSeconds = 10
	}
	if n.Exec.TimeoutSeconds < 1 || n.Exec.TimeoutSeconds > 300 {
		return fmt.Errorf("notify.exec.timeout_seconds must be in 1..300, got %d", n.Exec.TimeoutSeconds)
	}
	return nil
}

// parseCommunities parses a non-empty list of "ASN:value" communities into
// their wire values plus a space-joined display string.
func parseCommunities(list []string) ([]uint32, string, error) {
	if len(list) == 0 {
		return nil, "", fmt.Errorf("at least one community is required")
	}
	vals := make([]uint32, len(list))
	for i, s := range list {
		v, err := ParseCommunity(s)
		if err != nil {
			return nil, "", err
		}
		vals[i] = v
	}
	return vals, strings.Join(list, " "), nil
}

// hasV6Networks reports whether any protected network is IPv6.
func (c *Config) hasV6Networks() bool {
	for _, p := range c.NetworkPrefixes {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

// validateDivertTarget checks that a group whose ladder diverts has somewhere
// to divert to: an IPv4 target always, plus an IPv6 target when the group
// protects IPv6 space (there is no safe discard-style fallback for diversion —
// traffic must reach a real scrubber). A target is either the scalar
// scrubbing.next_hop or a managed scrubbing.nodes entry THAT SERVES THIS GROUP
// (a node restricted to other hostgroups does not count).
func validateDivertTarget(group string, scrub resolvedBGP, nodes *Scrubbing, hasV6 bool) error {
	if scrub.nextHop == "" && !nodes.hasNodeTargetFor(group, false) {
		return fmt.Errorf("group %q: divert requires scrubbing.next_hop or a scrubbing.nodes entry with next_hop that serves this group (the scrubbing center's IPv4 next-hop)", group)
	}
	if hasV6 && scrub.nextHop6 == "" && !nodes.hasNodeTargetFor(group, true) {
		return fmt.Errorf("group %q: divert requires scrubbing.next_hop6 or a scrubbing.nodes entry with next_hop6 that serves this group because the group protects IPv6 space", group)
	}
	return nil
}

// resolvedBGP is a group's resolved BGP attribute set (blackhole or scrubbing).
type resolvedBGP struct {
	nextHop, nextHop6, commStr string
	communities                []uint32
	localPref                  uint32
}

// defaults returns the global blackhole attribute set as a resolution default.
func (b *BGP) defaults() resolvedBGP {
	return resolvedBGP{
		nextHop: b.NextHop, nextHop6: b.NextHop6,
		commStr: b.CommunityStr, communities: b.CommunityValues, localPref: b.LocalPref,
	}
}

// defaults returns the global scrubbing attribute set as a resolution default.
func (s *Scrubbing) defaults() resolvedBGP {
	return resolvedBGP{
		nextHop: s.NextHop, nextHop6: s.NextHop6,
		commStr: s.CommunityStr, communities: s.CommunityValues, localPref: s.LocalPref,
	}
}

// resolveBGPAttrs resolves a group's BGP attributes, inheriting any field the
// override leaves unset from the (already-validated) default set. A nil
// override inherits everything. Used for both the blackhole and scrubbing
// attribute sets.
func resolveBGPAttrs(ov *BGPOverride, def resolvedBGP) (resolvedBGP, error) {
	r := def
	if ov == nil {
		return r, nil
	}
	if ov.NextHop != "" {
		a, err := netip.ParseAddr(ov.NextHop)
		if err != nil || !a.Is4() {
			return resolvedBGP{}, fmt.Errorf("next_hop must be a valid IPv4 address, got %q", ov.NextHop)
		}
		r.nextHop = ov.NextHop
	}
	if ov.NextHop6 != "" {
		a, err := netip.ParseAddr(ov.NextHop6)
		if err != nil || !a.Is6() || a.Is4In6() {
			return resolvedBGP{}, fmt.Errorf("next_hop6 must be a valid IPv6 address, got %q", ov.NextHop6)
		}
		r.nextHop6 = ov.NextHop6
	}
	// An omitted communities key (nil) inherits the global set. An explicit but
	// empty list is a mistake — reject it rather than silently inherit, so the
	// operator does not believe an ineffective override took effect.
	if ov.Communities != nil {
		if len(ov.Communities) == 0 {
			return resolvedBGP{}, fmt.Errorf("communities: provide at least one community, or omit the field to inherit the global set")
		}
		vals, str, err := parseCommunities(ov.Communities)
		if err != nil {
			return resolvedBGP{}, fmt.Errorf("communities: %w", err)
		}
		r.communities, r.commStr = vals, str
	}
	if ov.LocalPref != nil {
		r.localPref = *ov.LocalPref
	}
	return r, nil
}

// ParseCommunity parses an "ASN:value" BGP community string into its uint32
// wire representation.
func ParseCommunity(s string) (uint32, error) {
	hi, lo, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("community %q must have form ASN:value", s)
	}
	h, err := strconv.ParseUint(hi, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("community %q: bad ASN part: %w", s, err)
	}
	l, err := strconv.ParseUint(lo, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("community %q: bad value part: %w", s, err)
	}
	return uint32(h)<<16 | uint32(l), nil
}

// InNetworks reports whether addr falls inside any protected prefix.
func (c *Config) InNetworks(addr netip.Addr) bool {
	for _, p := range c.NetworkPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// resolveBoundary parses sampling.boundary into the lookup-ready c.boundary
// map. It rejects malformed exporter addresses, empty interface lists and
// duplicate exporter entries.
func (c *Config) resolveBoundary() error {
	c.boundary = nil
	if len(c.Sampling.Boundary) == 0 {
		return nil
	}
	c.boundary = make(map[netip.Addr]exporterBoundary, len(c.Sampling.Boundary))
	for i := range c.Sampling.Boundary {
		eb := &c.Sampling.Boundary[i]
		addr, err := netip.ParseAddr(eb.Exporter)
		if err != nil {
			return fmt.Errorf("sampling.boundary[%d].exporter: invalid IP %q: %w", i, eb.Exporter, err)
		}
		addr = addr.Unmap()
		if _, dup := c.boundary[addr]; dup {
			return fmt.Errorf("sampling.boundary: duplicate exporter %q", eb.Exporter)
		}
		if len(eb.ExternalIfindexes) == 0 {
			return fmt.Errorf("sampling.boundary[%d] (%s): external_ifindexes must list at least one interface", i, eb.Exporter)
		}
		ext := make(map[uint32]struct{}, len(eb.ExternalIfindexes))
		for _, idx := range eb.ExternalIfindexes {
			ext[idx] = struct{}{}
		}
		c.boundary[addr] = exporterBoundary{external: ext, egress: eb.EgressSampling}
	}
	return nil
}

// BoundaryDebugEnabled reports whether the boundary-discovery metric is on.
func (c *Config) BoundaryDebugEnabled() bool { return c.Sampling.BoundaryDebug }

// InboundRate decides whether a sample from exporter arriving on input
// interface inIf should be counted toward a protected destination, and at what
// effective sampling rate. Without a boundary entry for the exporter it returns
// (rate, true) — legacy behavior, every sample counted. With an entry it counts
// only samples entering on an external interface, halving the rate when that
// exporter also samples on egress (each boundary-crossing packet is then seen
// twice, so halving restores the true volume).
func (c *Config) InboundRate(exporter netip.Addr, inIf uint32, rate uint64) (uint64, bool) {
	return c.boundaryRate(exporter, inIf, rate)
}

// OutboundRate is the egress-direction counterpart of InboundRate: it gates a
// sample by its output interface (traffic leaving a protected source crosses
// the boundary on egress).
func (c *Config) OutboundRate(exporter netip.Addr, outIf uint32, rate uint64) (uint64, bool) {
	return c.boundaryRate(exporter, outIf, rate)
}

func (c *Config) boundaryRate(exporter netip.Addr, iface uint32, rate uint64) (uint64, bool) {
	b, ok := c.boundary[exporter.Unmap()]
	if !ok {
		return rate, true // exporter not classified: count every sample
	}
	if _, external := b.external[iface]; !external {
		return 0, false // internal/transit/peer-link sample: a duplicate, drop it
	}
	if b.egress && rate > 1 {
		rate /= 2
	}
	return rate, true
}

// ProtectedAddrs returns the total number of addresses in the protected
// networks of addr's family, as a float64 (an IPv6 range exceeds uint64). The
// mitigator's blast-radius fraction guard divides active bans by this.
func (c *Config) ProtectedAddrs(is6 bool) float64 {
	if is6 {
		return c.protectedAddrs6
	}
	return c.protectedAddrs4
}

// IsWhitelisted reports whether addr must never be banned.
func (c *Config) IsWhitelisted(addr netip.Addr) bool {
	for _, a := range c.WhitelistAddrs {
		if a == addr {
			return true
		}
	}
	return false
}

// DataplaneAllowlistContains reports whether addr falls inside any
// dataplane.allowlist entry. The datapath passes allowlisted sources before
// evaluating any rule (precedence 1), so a dynamic rule aimed at one would be
// installed and then silently never match — callers refuse up front instead.
func (c *Config) DataplaneAllowlistContains(addr netip.Addr) bool {
	a := addr.Unmap()
	for _, p := range c.DataplaneAllowlist {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// PrefixContainsWhitelisted reports whether p covers any whitelisted address.
// A prefix-scoped mitigation (carpet) cannot exempt a single member, so a
// prefix containing a whitelisted address must be refused outright — the
// whitelist guarantee is absolute.
func (c *Config) PrefixContainsWhitelisted(p netip.Prefix) bool {
	for _, a := range c.WhitelistAddrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// PrefixInNetworks reports whether p is fully contained in a protected prefix
// (so a prefix-scoped ban never announces a route for space we do not own).
func (c *Config) PrefixInNetworks(p netip.Prefix) bool {
	for _, np := range c.NetworkPrefixes {
		if np.Contains(p.Addr()) && np.Bits() <= p.Bits() {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether host names the local machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// normalizeListen turns ":6343" into a parseable "0.0.0.0:6343".
func normalizeListen(s string) string {
	if strings.HasPrefix(s, ":") {
		return "0.0.0.0" + s
	}
	return s
}

// Store holds the current configuration snapshot and supports atomic
// replacement on SIGHUP-driven reload.
type Store struct {
	path string
	cur  atomic.Pointer[Config]
	// changed is the closed-channel broadcast behind Changed(): a pointer to
	// the channel handed to current waiters, swapped for nil and closed on
	// every successful Reload. Lock-free so the hot path (Get) stays a plain
	// atomic load and a burst of reloads costs one close per burst, not per
	// waiter. Nil until the first Changed() call.
	changed atomic.Pointer[chan struct{}]
}

// NewStore creates a Store serving cfg, remembering path for Reload.
func NewStore(path string, cfg *Config) *Store {
	s := &Store{path: path}
	s.cur.Store(cfg)
	return s
}

// Get returns the current configuration snapshot. The returned value is
// immutable; callers must not modify it.
func (s *Store) Get() *Config { return s.cur.Load() }

// Reload re-reads the config file. On any error the previous configuration
// stays active and the error is returned. Listen addresses and BGP identity
// cannot change at runtime; a reload that alters them is rejected.
func (s *Store) Reload() (*Config, error) {
	next, err := Load(s.path)
	if err != nil {
		return nil, err
	}
	prev := s.cur.Load()
	if next.Listen != prev.Listen {
		return nil, fmt.Errorf("reload: listen addresses cannot change at runtime (restart required)")
	}
	if next.BGP.LocalASN != prev.BGP.LocalASN || next.BGP.RouterID != prev.BGP.RouterID {
		return nil, fmt.Errorf("reload: bgp identity (local_asn, router_id) cannot change at runtime (restart required)")
	}
	if next.API.Listen != prev.API.Listen {
		return nil, fmt.Errorf("reload: api.listen cannot change at runtime (restart required)")
	}
	if next.SampleCfg != prev.SampleCfg {
		return nil, fmt.Errorf("reload: samples settings cannot change at runtime (restart required)")
	}
	if next.StorageCfg != prev.StorageCfg {
		return nil, fmt.Errorf("reload: storage settings cannot change at runtime (restart required)")
	}
	if next.GeoIPCfg != prev.GeoIPCfg {
		return nil, fmt.Errorf("reload: geoip settings cannot change at runtime (restart required)")
	}
	// Static policy (allowlist, static rules, profiles) hot-reloads through a
	// shadow-map flip; attachment and map sizing cannot change under a loaded
	// program, and DataplaneSettings holds exactly those fields.
	if next.DataplaneCfg != prev.DataplaneCfg {
		return nil, fmt.Errorf("reload: dataplane attachment settings (interfaces, xdp_mode, pin_path, limits, fingerprint enabled/sample_pps) cannot change at runtime (restart required)")
	}
	s.cur.Store(next)
	s.notifyChanged()
	return next, nil
}

// Changed returns a channel that is closed on the next successful Reload, so a
// component can block until the configuration it serves from may have moved —
// the edge zones long-poll (api/edge.go) is the first consumer. Call it again
// for a fresh channel after a wake: the classic closed-channel broadcast, so
// any number of waiters share one channel and one close. A wake means "the
// store was replaced", not "the part you care about differs" — re-read and
// compare, exactly as Mitigator.RulesChanged waiters do.
func (s *Store) Changed() <-chan struct{} {
	for {
		if p := s.changed.Load(); p != nil {
			return *p
		}
		ch := make(chan struct{})
		if s.changed.CompareAndSwap(nil, &ch) {
			return ch
		}
		// Lost the race to another first subscriber; use theirs.
	}
}

// notifyChanged wakes every Changed waiter. The Swap makes the close
// exactly-once even under concurrent reloads: only the caller that swapped the
// pointer out closes it; the next Changed call lazily creates a fresh channel.
func (s *Store) notifyChanged() {
	if p := s.changed.Swap(nil); p != nil {
		close(*p)
	}
}

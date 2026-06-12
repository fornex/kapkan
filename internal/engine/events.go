package engine

import (
	"net/netip"
	"time"
)

// Metric identifies which configured threshold a measurement is compared
// against.
type Metric string

// Threshold metrics evaluated once per second for every destination host.
// The per-protocol metrics mirror the per-protocol threshold keys.
const (
	MetricPPS        Metric = "pps"
	MetricMbps       Metric = "mbps"
	MetricFPS        Metric = "flows_per_sec"
	MetricTCPPPS     Metric = "tcp_pps"
	MetricTCPMbps    Metric = "tcp_mbps"
	MetricUDPPPS     Metric = "udp_pps"
	MetricUDPMbps    Metric = "udp_mbps"
	MetricICMPPPS    Metric = "icmp_pps"
	MetricICMPMbps   Metric = "icmp_mbps"
	MetricTCPSYNPPS  Metric = "tcp_syn_pps"
	MetricTCPSYNMbps Metric = "tcp_syn_mbps"
	MetricFragPPS    Metric = "frag_pps"
	MetricFragMbps   Metric = "frag_mbps"
)

// Metrics lists every defined threshold metric in evaluation order. Used by
// consumers that need the complete set (schema checks, future UI/API).
func Metrics() []Metric {
	out := make([]Metric, len(metricTable))
	for i := range metricTable {
		out[i] = metricTable[i].metric
	}
	return out
}

// Direction distinguishes traffic toward a protected host from traffic the
// host originates. Outgoing detection catches compromised machines inside
// the protected networks.
type Direction string

// Traffic directions.
const (
	DirIncoming Direction = "incoming"
	DirOutgoing Direction = "outgoing"
)

// Internal direction indexes (bucket and state arrays).
const (
	dirIn  = 0
	dirOut = 1
)

// dirName maps an internal direction index to its public name.
func dirName(d int) Direction {
	if d == dirOut {
		return DirOutgoing
	}
	return DirIncoming
}

// Rates is one sampling-corrected per-second measurement for a single
// destination host (one direction), averaged over the engine's sliding
// window. Per-protocol components omit zeros in JSON.
type Rates struct {
	PPS         float64 `json:"pps"`
	Mbps        float64 `json:"mbps"`
	FlowsPerSec float64 `json:"flows_per_sec"`

	TCPPPS     float64 `json:"tcp_pps,omitempty"`
	TCPMbps    float64 `json:"tcp_mbps,omitempty"`
	UDPPPS     float64 `json:"udp_pps,omitempty"`
	UDPMbps    float64 `json:"udp_mbps,omitempty"`
	ICMPPPS    float64 `json:"icmp_pps,omitempty"`
	ICMPMbps   float64 `json:"icmp_mbps,omitempty"`
	TCPSYNPPS  float64 `json:"tcp_syn_pps,omitempty"`
	TCPSYNMbps float64 `json:"tcp_syn_mbps,omitempty"`
	FragPPS    float64 `json:"frag_pps,omitempty"`
	FragMbps   float64 `json:"frag_mbps,omitempty"`
}

// Scope distinguishes per-host attacks from hostgroup-total attacks.
type Scope string

// Attack scopes.
const (
	// ScopeHost is an attack on a single destination host.
	ScopeHost Scope = "host"
	// ScopeGroup is an attack on the summed traffic of a hostgroup with
	// calculation method "total". Group events carry no Target and never
	// trigger automatic mitigation.
	ScopeGroup Scope = "group"
)

// EventKind distinguishes attack lifecycle events.
type EventKind int

// Attack lifecycle events emitted by the engine.
const (
	AttackStarted EventKind = iota
	AttackEnded
)

// String returns the event kind name used in logs and notifications.
func (k EventKind) String() string {
	if k == AttackStarted {
		return "attack_started"
	}
	return "attack_ended"
}

// Event is an attack lifecycle notification emitted on the engine's event
// channel. For AttackStarted, Metric/Rate/Threshold describe the first
// threshold that was crossed; Rates is the full measurement at that moment.
// For AttackEnded, Rates is the last measurement before the attack was
// declared over.
type Event struct {
	Kind EventKind `json:"kind"`
	// Scope says what is under attack: a single host (Target) or a
	// hostgroup's total traffic (Group). Target is invalid for ScopeGroup.
	Scope  Scope      `json:"scope"`
	Target netip.Addr `json:"target"`
	// Direction is incoming for attacks ON the target, outgoing when the
	// target itself originates the attack (compromised host).
	Direction Direction `json:"direction"`
	// Group is the owning hostgroup's name. It is always set: the implicit
	// "global" group when no configured hostgroup matched the target.
	Group string `json:"group"`
	// BanEnabled reports whether the owning group's policy permits automatic
	// mitigation. The zero value is the safe value: mitigation must never
	// act on an event that does not explicitly carry permission.
	BanEnabled bool      `json:"ban_enabled"`
	Metric     Metric    `json:"metric"`
	Rate       float64   `json:"rate"`
	Threshold  float64   `json:"threshold"`
	Rates      Rates     `json:"rates"`
	At         time.Time `json:"at"`
	// StartedAt is set on AttackEnded so consumers can compute duration.
	StartedAt time.Time `json:"started_at"`
	// Sample is attached to AttackStarted when the traffic buffer is
	// enabled: dominant sources/ports/protocols plus raw flow records
	// captured in the window before the threshold tripped.
	Sample *AttackSample `json:"sample,omitempty"`
}

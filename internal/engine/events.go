package engine

import (
	"net/netip"
	"time"
)

// Metric identifies which configured threshold a measurement is compared
// against.
type Metric string

// Threshold metrics evaluated once per second for every destination host.
const (
	MetricPPS  Metric = "pps"
	MetricMbps Metric = "mbps"
	MetricFPS  Metric = "flows_per_sec"
)

// Rates is one sampling-corrected per-second measurement for a single
// destination host, averaged over the engine's sliding window.
type Rates struct {
	PPS         float64 `json:"pps"`
	Mbps        float64 `json:"mbps"`
	FlowsPerSec float64 `json:"flows_per_sec"`
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
}

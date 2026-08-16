package dataplane

// Health, statistics and the reload report: what the Manager tells the rest of
// the process about itself.
//
// Untagged, because /healthz, the API and the console all render these types and
// several of those are compiled and tested on hosts where no program can load.
//
// THE DESIGN RULE for everything here: a data plane that is not enforcing must
// be VISIBLE, and visible in a way a machine can act on. kapkan's other
// optional components degrade quietly and that is right for them — a missing
// GeoIP database costs an attack some attribution. This one is different: the
// operator moved a customer's traffic behind a filter that is not there. So an
// interface that is not attached is a degraded condition on /healthz and a
// metric, not a line in a log that scrolled past at boot.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors the Manager returns that a caller is expected to branch on.
var (
	// ErrUnsupported is returned by Open on a non-Linux host. It exists so
	// internal/app can compile and be tested on macOS: the stub Manager is a
	// real type with a real Open that always fails this way, rather than a
	// build-tagged hole in the wiring.
	ErrUnsupported = errors.New("dataplane: the XDP data plane requires Linux")

	// ErrKernelTooOld is returned when the running kernel is below the
	// supported floor. Wrapped in a message naming the version found and the
	// version needed.
	ErrKernelTooOld = errors.New("dataplane: kernel too old")

	// ErrMissingCapability is returned when the process lacks one of the three
	// capabilities the program needs. Wrapped in a message naming which.
	ErrMissingCapability = errors.New("dataplane: missing capability")

	// ErrPinPathUnsafe is returned when the pin directory is not on a bpffs, or
	// is owned by someone else, or is writable by group or other. A pin
	// directory a local user can write is a pin directory in which they can
	// pre-create a program that this process would then ADOPT, so this is a
	// refusal and never a warning.
	ErrPinPathUnsafe = errors.New("dataplane: pin path is not safe to use")

	// ErrRestartRequired is returned by Reload when the new Options differ in a
	// field that cannot change under a running, attached program.
	ErrRestartRequired = errors.New("dataplane: change requires a restart")

	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("dataplane: manager is closed")

	// ErrNoPolicySlots is returned by Installer.Install when every policy id is
	// in use. It is separate from a plain error so a caller can tell "the data
	// plane is full" from "the data plane is broken": the first means the
	// operator's own dataplane.limits are the binding constraint, the second
	// means something is wrong with the kernel side. The mitigator degrades to
	// its configured fallback either way.
	ErrNoPolicySlots = errors.New("dataplane: no free policy slots")

	// ErrNoProfileSlots is returned when the dynamic rate-limit profile band
	// (DynamicProfileBase..MaxProfiles) is exhausted.
	ErrNoProfileSlots = errors.New("dataplane: no free rate-limit profile slots")
)

// ConditionKind names a degraded state. Stable strings: they are a Prometheus
// label and a /healthz body line.
type ConditionKind string

// The condition kinds. Each is something an operator can act on, which is the
// bar for being here at all — "unattached" tells you to look at the NIC,
// "pins_rebuilt" tells you dynamic rules were lost on this restart.
const (
	// CondUnattached: a configured interface has no live XDP attachment.
	CondUnattached ConditionKind = "unattached"
	// CondInterfaceMissing: a configured interface does not exist right now.
	CondInterfaceMissing ConditionKind = "interface_missing"
	// CondModeDowngraded: auto mode fell back from native to the generic (skb)
	// path on this interface. Not a failure, but it costs roughly an order of
	// magnitude of capacity and the operator should know which NIC did it.
	CondModeDowngraded ConditionKind = "mode_downgraded"
	// CondPinsRebuilt: an existing pinned set was found and REJECTED, so it was
	// torn down and rebuilt. Dynamic rules from the previous process are gone;
	// static policy is not, it comes from the config file.
	CondPinsRebuilt ConditionKind = "pins_rebuilt"
	// CondPolicyShadowed: a static rule can never fire, because the allowlist
	// now covers everything it matches or an earlier static rule already takes
	// every packet it selects. It persists until a reload fixes the config,
	// which is the point: the defect's only other symptom is a rule counter
	// that never moves.
	CondPolicyShadowed ConditionKind = "policy_shadowed"
)

// Condition is one degraded or noteworthy state, with the moment it began so a
// dashboard can show "unattached for 4m" rather than a bare boolean.
type Condition struct {
	Kind ConditionKind `json:"kind"`
	// Interface is the NIC the condition is about, or "" for process-wide.
	Interface string `json:"interface,omitempty"`
	// Message is one human sentence. It is the thing an operator reads first,
	// so it names the remedy where there is one.
	Message string    `json:"message"`
	Since   time.Time `json:"since"`
}

func (c Condition) String() string {
	if c.Interface != "" {
		return fmt.Sprintf("%s[%s]: %s", c.Kind, c.Interface, c.Message)
	}
	return fmt.Sprintf("%s: %s", c.Kind, c.Message)
}

// InterfaceStatus is the attachment state of one configured NIC.
type InterfaceStatus struct {
	Name string `json:"interface"`
	// Index is the ifindex currently attached to, 0 when not attached. It is
	// reported because a flapping veth or a renamed NIC comes back with a
	// different index, and "attached to ifindex 7 but the NIC is now 9" is the
	// shape of the bug this field catches.
	Index int `json:"ifindex"`
	// Mode is config.XDPModeNative or XDPModeGeneric — the mode actually in
	// force, which under xdp_mode: auto is not knowable from the config.
	Mode string `json:"mode,omitempty"`
	// Attached is the ground truth: the kernel still reports this link bound to
	// a live netdevice.
	Attached bool `json:"attached"`
	// Attempts counts consecutive failed attach attempts, reset on success.
	Attempts int `json:"attach_attempts,omitempty"`
	// LastError is the most recent attach failure, "" when attached.
	LastError string `json:"last_error,omitempty"`
	// Since is when Attached last changed.
	Since time.Time `json:"since"`
}

// Health is the /healthz-consumable state of the data plane.
//
// Degraded is deliberately NOT "anything is imperfect": a native-to-generic
// downgrade is a condition but not degradation, because the filter is enforcing.
// Degraded means at least one configured interface is not filtering, which is
// the only state where a packet the operator asked to drop gets through.
type Health struct {
	// Enabled is false for the stub manager and for a nil Manager, so a caller
	// can render health without a nil check.
	Enabled bool `json:"enabled"`
	// Degraded is true when any configured interface is not attached.
	Degraded bool `json:"degraded"`
	// Adopted reports whether this process re-adopted a pinned program from a
	// previous one (so dynamic rules survived) or built a fresh one.
	Adopted    bool              `json:"adopted"`
	Interfaces []InterfaceStatus `json:"interfaces,omitempty"`
	Conditions []Condition       `json:"conditions,omitempty"`
}

// Summary renders Health as one line, which is what /healthz writes when
// degraded. Machine-readable enough to grep, short enough to page.
func (h Health) Summary() string {
	if !h.Enabled {
		return "dataplane: disabled"
	}
	attached := 0
	for _, i := range h.Interfaces {
		if i.Attached {
			attached++
		}
	}
	state := "ok"
	if h.Degraded {
		state = "DEGRADED"
	}
	parts := []string{fmt.Sprintf("dataplane: %s (%d/%d interfaces attached)",
		state, attached, len(h.Interfaces))}
	for _, c := range h.Conditions {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "; ")
}

// MapStatus is one map's size and cost, so an operator can see what their
// limits bought. Bytes comes from the kernel's own footprint estimate in
// /proc/self/fdinfo (the memlock field), which matched the cgroup delta to
// within 1% when it was measured — see deploy/dataplane-operations.md §2.
type MapStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	MaxEntries uint32 `json:"max_entries"`
	Bytes      uint64 `json:"bytes,omitempty"`
}

// Snapshot is a point-in-time read of the whole data plane: what it is
// enforcing, what it has seen, and what it cost.
type Snapshot struct {
	Health Health `json:"health"`
	// Counters is kapkan_stats, summed across CPUs, indexed by Stat. Remember
	// that Stat.IsObservation counters co-occur with a terminal one, so summing
	// every index over-counts.
	Counters [StatMax]Counter `json:"-"`
	// Verdicts is Counters keyed by the counters' stable names, which is the
	// form the API and console want.
	Verdicts map[string]Counter `json:"verdicts"`
	// Generation is the live half of the double buffer, and StaticCount the
	// number of static rules it holds.
	Generation  uint32 `json:"generation"`
	StaticCount uint32 `json:"static_rules"`
	// SchemaVersion is what is stamped in kapkan_cfg[0]; it equals
	// MapSchemaVersion for a program this binary created or adopted.
	SchemaVersion uint32 `json:"map_schema_version"`
	// Sizing is the resolved map sizing, and Maps the per-map cost.
	Sizing MapSizing   `json:"sizing"`
	Maps   []MapStatus `json:"maps,omitempty"`
	// MapBytes is the total of Maps[].Bytes.
	MapBytes uint64 `json:"map_bytes"`
}

// ReloadReport says what a static-policy reload actually did. Every field is
// something the operator cannot infer from the config diff alone, which is the
// test for whether it belongs here.
type ReloadReport struct {
	// Generation is the half that was built and published.
	Generation uint32 `json:"generation"`
	// StaticRules is how many ENCODED rules were installed, which exceeds the
	// number of config rules whenever one of them names no source prefix (see
	// StaticExpansion).
	StaticRules int `json:"static_rules"`
	// Profiles is how many rate-limit profiles were written.
	Profiles int `json:"profiles"`
	// AllowAdded/AllowRemoved and ProtectedAdded/ProtectedRemoved are the trie
	// reconciliation: the tries are not double-buffered (an LPM trie cannot be
	// swapped atomically), so they are driven toward the desired set by diff
	// and these are the deltas actually applied.
	AllowAdded       []string `json:"allow_added,omitempty"`
	AllowRemoved     []string `json:"allow_removed,omitempty"`
	ProtectedAdded   []string `json:"protected_added,omitempty"`
	ProtectedRemoved []string `json:"protected_removed,omitempty"`
	// ShadowedStatics names static rules that can never fire — because the
	// allowlist covers every source they match, or because an earlier static
	// rule already takes every packet they select (first match wins). Each
	// entry names the rule and what takes its packets. See shadow.go.
	ShadowedStatics []string `json:"shadowed_statics,omitempty"`
	// ShadowedDynamicRules counts rules the MITIGATOR has installed whose
	// source is now covered by an allowlist entry. Those rules stop dropping
	// the instant the trie entry lands — precedence 1 is checked before
	// anything else, in the kernel — so this is reported, not repaired.
	ShadowedDynamicRules int `json:"shadowed_dynamic_rules,omitempty"`
	// MirroredPolicyBlocks counts the occupied dynamic-rule blocks carried from
	// the outgoing generation into the published one. kapkan_policies shares the
	// generation counter with kapkan_statics, so a static-policy reload has to
	// bring the mitigator's rules with it or the flip would un-mitigate every
	// live attack; this is the proof it happened.
	MirroredPolicyBlocks int `json:"mirrored_policy_blocks,omitempty"`
}

// Summary renders the report as one log line.
func (r ReloadReport) Summary() string {
	parts := []string{fmt.Sprintf("published generation %d with %d static rules and %d profiles",
		r.Generation, r.StaticRules, r.Profiles)}
	if n := len(r.AllowAdded) + len(r.AllowRemoved); n > 0 {
		parts = append(parts, fmt.Sprintf("allowlist +%d/-%d", len(r.AllowAdded), len(r.AllowRemoved)))
	}
	if n := len(r.ProtectedAdded) + len(r.ProtectedRemoved); n > 0 {
		parts = append(parts, fmt.Sprintf("protected +%d/-%d", len(r.ProtectedAdded), len(r.ProtectedRemoved)))
	}
	if len(r.ShadowedStatics) > 0 {
		parts = append(parts, "shadowed static rules: "+strings.Join(r.ShadowedStatics, ","))
	}
	if r.MirroredPolicyBlocks > 0 {
		parts = append(parts, fmt.Sprintf("carried %d dynamic-rule block(s) across the flip",
			r.MirroredPolicyBlocks))
	}
	if r.ShadowedDynamicRules > 0 {
		parts = append(parts, fmt.Sprintf("%d active dynamic rules now covered by the allowlist",
			r.ShadowedDynamicRules))
	}
	return strings.Join(parts, "; ")
}

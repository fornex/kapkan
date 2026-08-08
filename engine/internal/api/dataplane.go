package api

// The API's view of the XDP data plane.
//
// WHY THESE TYPES EXIST AT ALL, given internal/dataplane already has a perfectly
// good Health and Snapshot: this package must not import internal/dataplane.
//
// Two reasons, and the second is the one that bites.
//
//  1. Build surface. internal/api compiles and is tested on the macOS
//     development host and, through cmd/kapkan-validate, to wasm. The dataplane
//     package does keep an untagged half (health.go, options.go) plus a !linux
//     stub Manager precisely so app.go can be host-compiled, so an import would
//     in fact still build today — which is exactly what makes it a trap. It
//     would build until the day someone moves one field behind //go:build linux,
//     and then the breakage lands in the HTTP layer, far from the change.
//
//  2. The API contract is the thing docs and the console are written against,
//     and it must not be a re-export of an internal struct that a kernel-side
//     refactor is free to reshape. Naming the fields here means a change to
//     dataplane.Snapshot fails to compile in the adapter (internal/app) instead
//     of silently renaming a JSON key that five locales and a Grafana panel key
//     off. The duplication IS the contract.
//
// So: api declares the shape, internal/app owns the translation (it imports
// both), and the Manager is reached only through DataplaneReporter.

// DataplaneReporter is what internal/app installs so the API can describe the
// data plane. Split in two because the two callers have different costs: a
// supervisor polls /healthz and must not pay for a map walk.
type DataplaneReporter interface {
	// DataplaneSummary is the one-line state for /healthz. Cheap by contract:
	// no bpf(2) map reads, so it stays safe on a hot liveness probe.
	DataplaneSummary() string
	// DataplaneStatus is the full block for /api/v1/status.
	DataplaneStatus() DataplaneStatus
}

// DataplaneInterface is one configured NIC's attachment state.
type DataplaneInterface struct {
	Name string `json:"interface"`
	// Index is the ifindex currently attached to, 0 when not attached. A
	// flapping veth or a renamed NIC comes back with a different index, so
	// "attached to 7 while the NIC is now 9" is a state worth being able to see.
	Index int `json:"ifindex"`
	// Mode is the mode actually in force ("native"|"generic"), which under
	// xdp_mode: auto is not knowable from the config. "" when not attached.
	Mode string `json:"mode,omitempty"`
	// Attached is ground truth from the kernel, not intent from the config.
	Attached bool `json:"attached"`
	// Attempts counts consecutive failed attach attempts, 0 when attached.
	Attempts int `json:"attach_attempts"`
	// LastError is the most recent attach failure, "" when attached.
	LastError string `json:"last_error,omitempty"`
}

// DataplaneCondition is one degraded or noteworthy state, already rendered to a
// sentence. RFC3339 for Since, like every other timestamp the API emits.
type DataplaneCondition struct {
	Kind      string `json:"kind"`
	Interface string `json:"interface,omitempty"`
	Message   string `json:"message"`
	Since     string `json:"since"`
}

// DataplaneStatus is the `dataplane` object on /api/v1/status.
//
// ADMIN-ONLY, and the reason is Interfaces: a NIC list is topology. It says how
// many links the box filters on and what they are called, which is not a scoped
// tenant's business. The one field a viewer does get is DryRun, lifted out by
// the handler as the flat `dataplane_dry_run` scalar — a boolean cannot leak a
// topology and the console needs it to be honest about whether what it is
// showing is being enforced.
type DataplaneStatus struct {
	// Enabled is false when dataplane.enabled is off or absent, in which case
	// every other field is zero. The console keys its whole section off this.
	Enabled bool `json:"enabled"`
	// DryRun is what the DATAPATH is doing, read back from kapkan_cfg — not what
	// the config asked for. The two can disagree across an adoption, and the
	// disagreement is the whole reason this is reported separately from the
	// global dry_run.
	DryRun bool `json:"dry_run"`
	// Degraded is true when at least one configured interface is not filtering.
	Degraded bool `json:"degraded"`
	// Adopted is true when this process re-adopted a previous process's pinned
	// program (so its dynamic rules survived the restart) rather than rebuilding.
	Adopted bool `json:"adopted"`
	// Mode is the effective mode across all interfaces: "native", "generic",
	// "mixed" when they disagree, or "" when nothing is attached. Interfaces
	// carries the per-NIC truth; this is the scalar a badge renders.
	Mode string `json:"mode"`
	// Attached and Configured are the counts behind Degraded, so a console can
	// render "1/2" without walking Interfaces.
	Attached   int                  `json:"attached"`
	Configured int                  `json:"configured"`
	Interfaces []DataplaneInterface `json:"interfaces"`
	// StaticRules is the number of ENCODED static rules live in the kernel,
	// which exceeds the number of config rules whenever one names no source
	// prefix (the datapath is family-strict, so such a rule compiles to one
	// kernel rule per family).
	StaticRules int `json:"static_rules"`
	// DynamicRules is the mitigator-installed count. Always 0 until the
	// data-plane mitigation backend lands; reported now so the field's absence
	// never has to be special-cased by a console that ships before it.
	DynamicRules int `json:"dynamic_rules"`
	// Generation is the live half of the double-buffered policy.
	Generation int `json:"generation"`
	// MapSchemaVersion is what is stamped in kapkan_cfg[0].
	MapSchemaVersion int `json:"map_schema_version"`
	// MapBytes is the kernel's own footprint estimate for the whole map set,
	// which is what dataplane.limits actually bought.
	MapBytes int64 `json:"map_bytes"`
	// Verdicts maps a terminal verdict or observation name to its counters.
	// Absent when the counters could not be read.
	Verdicts   map[string]DataplaneCounter `json:"verdicts,omitempty"`
	Conditions []DataplaneCondition        `json:"conditions,omitempty"`
	// Error is set when the data plane is up but its counters could not be read
	// this poll. Reported rather than swallowed: a status block that quietly
	// showed stale numbers would be worse than one that says it is stale.
	Error string `json:"error,omitempty"`
}

// DataplaneCounter is one {packets, bytes} pair from kapkan_stats.
type DataplaneCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

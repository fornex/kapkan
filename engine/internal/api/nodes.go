package api

// POST /api/v1/dataplane/nodes/{name}/report — a scrub node's self-report
// (plan task M4.4, freeze point F7).
//
// REPORTS ARE ADVISORY. That is the load-bearing sentence of this file. A
// report is written with the agent token, and the agent token lives on the
// least-guarded box in the deployment; everything in a report — load, drop
// counters, versions — must be treated as "what the node CLAIMS", rendered to
// operators as such, and never fed into a decision. Above all it is NOT a
// liveness signal: a compromised token that could keep a dead node "up" by
// posting reports would keep attracting a victim's diverted traffic into a
// black hole. Liveness is the rules poll and only the rules poll, recorded in
// internal/mitigate — a package this store is structurally invisible to
// (mitigate cannot import api), so the rule cannot erode quietly.
//
// The store is in-memory and ephemeral, like the liveness map: a report is a
// claim about now, and nothing here is worth surviving a restart.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// maxNodeReportBytes bounds a report body. 64 KiB is the plan-frozen limit —
// two orders of magnitude above a sane report, small enough that a stuck agent
// cannot feed the decoder forever.
const maxNodeReportBytes = 64 << 10

// NodesDoc is the GET /api/v1/dataplane/nodes response: every configured
// scrubbing node with what the brain KNOWS (config, poll liveness, how many
// bans divert to it) joined with what the node CLAIMS (its last advisory
// report, clearly separated under `report`).
type NodesDoc struct {
	// NodesTotal mirrors the scalar on /api/v1/status so a consumer holding
	// this document never needs the other call to interpret it.
	NodesTotal int `json:"nodes_total"`
	// StaleAfterSeconds is the liveness contract the `alive` field was judged
	// against, so a console can render "lost after Ns" without hardcoding it.
	StaleAfterSeconds int          `json:"stale_after_seconds"`
	Nodes             []NodeStatus `json:"nodes"`
}

// NodeStatus is one node in NodesDoc.
type NodeStatus struct {
	Name         string   `json:"name"`
	NextHop      string   `json:"next_hop,omitempty"`
	NextHop6     string   `json:"next_hop6,omitempty"`
	CapacityMbps uint64   `json:"capacity_mbps,omitempty"`
	Hostgroups   []string `json:"hostgroups,omitempty"`
	// Alive is the brain's judgment from the rules poll — THE liveness truth,
	// never influenced by reports. Holding means a poll is parked open right
	// now (the healthy steady state).
	Alive   bool `json:"alive"`
	Holding bool `json:"holding"`
	// LastSeen is the last completed poll, RFC3339; empty when the node has
	// never polled this process (a string, not time.Time, because a zero
	// time.Time survives omitempty and would render as year 1).
	LastSeen string `json:"last_seen,omitempty"`
	// ActiveBans counts the active divert bans currently frozen to this node.
	ActiveBans int `json:"active_bans"`
	// Report is the node's last self-report, VERBATIM and advisory (see the
	// file comment); ReportedAt is when it arrived. Absent when it never did.
	Report     *NodeReport `json:"report,omitempty"`
	ReportedAt string      `json:"reported_at,omitempty"`
}

// handleDataplaneNodes serves the node inventory for the console's Nodes view.
//
// Unscoped tokens only, same reasoning as the status handler's dataplane
// block: node names, next-hops and hostgroup claims are deployment topology,
// not a scoped tenant's business (the fleet milestone replaces this refusal
// with a per-tenant filtered view). The count alone — enough for the console
// to show or hide node affordances — rides on /api/v1/status for every role.
func (s *Server) handleDataplaneNodes(w http.ResponseWriter, r *http.Request) {
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "the node inventory is restricted to unscoped tokens")
		return
	}
	cfg := s.store.Get()
	staleAfter := time.Duration(cfg.Scrubbing.StaleAfterSeconds) * time.Second
	bansByNode := map[string]int{}
	for _, b := range s.mit.ActiveBans() {
		if b.Node != "" && b.Method == config.MitigateDivert {
			bansByNode[b.Node]++
		}
	}
	doc := NodesDoc{
		NodesTotal:        len(cfg.Scrubbing.Nodes),
		StaleAfterSeconds: cfg.Scrubbing.StaleAfterSeconds,
		Nodes:             []NodeStatus{},
	}
	for i := range cfg.Scrubbing.Nodes {
		n := &cfg.Scrubbing.Nodes[i]
		lastSeen, holding := s.mit.NodeSeen(n.Name)
		ns := NodeStatus{
			Name:         n.Name,
			NextHop:      n.NextHop,
			NextHop6:     n.NextHop6,
			CapacityMbps: n.CapacityMbps,
			Hostgroups:   n.Hostgroups,
			Alive:        s.mit.NodeAlive(n.Name, staleAfter),
			Holding:      holding,
			ActiveBans:   bansByNode[n.Name],
		}
		if !lastSeen.IsZero() {
			ns.LastSeen = lastSeen.UTC().Format(time.RFC3339)
		}
		if rep, at, ok := s.nodeReports.get(n.Name); ok {
			r := rep
			ns.Report = &r
			ns.ReportedAt = at.UTC().Format(time.RFC3339)
		}
		doc.Nodes = append(doc.Nodes, ns)
	}
	writeJSON(w, http.StatusOK, doc)
}

// NodeReport is what a scrub node says about itself. THE JSON CONTRACT IS
// FROZEN HERE (F7); the agent (`kapkan scrub`) and the console Nodes view are
// written against these key names. Every field is a CLAIM (see the file
// comment), and every field is optional — an agent reports what it knows.
type NodeReport struct {
	// Version is the agent's kapkan version, for skew visibility in the
	// console ("brain 1.6, node 1.5").
	Version string `json:"version,omitempty"`
	// XDPMode is the mode actually in force on the node's dirty interface(s):
	// "native", "generic", or "mixed" — same vocabulary as this box's own
	// dataplane status block.
	XDPMode string `json:"xdp_mode,omitempty"`
	// DryRun is the NODE-side watch-only flag. A node that counts but does not
	// drop must say so, or the operator reads a scrubbing setup into numbers
	// that no packet ever experienced.
	DryRun bool `json:"dry_run,omitempty"`
	// LoadMbps / LoadPPS is the traffic rate currently arriving at the node's
	// dirty side. The least_loaded selection mode (fleet milestone) will NOT
	// read this — selection trusts only what the brain measures.
	LoadMbps float64 `json:"load_mbps,omitempty"`
	LoadPPS  float64 `json:"load_pps,omitempty"`
	// DroppedPackets / DroppedBytes are lifetime totals since agent start.
	DroppedPackets uint64 `json:"dropped_packets,omitempty"`
	DroppedBytes   uint64 `json:"dropped_bytes,omitempty"`
	// RulesETag is the ETag of the rules document the node is currently
	// enforcing, so an operator can see a node lagging the brain.
	RulesETag string `json:"rules_etag,omitempty"`
}

// nodeReportStore holds the last report per node. Advisory data only; the
// console's Nodes view (M4.6) is its one consumer.
type nodeReportStore struct {
	mu      sync.Mutex
	reports map[string]storedNodeReport
}

type storedNodeReport struct {
	report NodeReport
	at     time.Time
}

func (st *nodeReportStore) put(name string, r NodeReport, at time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reports == nil {
		st.reports = make(map[string]storedNodeReport)
	}
	st.reports[name] = storedNodeReport{report: r, at: at}
}

func (st *nodeReportStore) get(name string) (NodeReport, time.Time, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.reports[name]
	return s.report, s.at, ok
}

// configuredNode returns the scrubbing.nodes entry with this name, or nil.
func configuredNode(cfg *config.Config, name string) *config.ScrubNode {
	for i := range cfg.Scrubbing.Nodes {
		if cfg.Scrubbing.Nodes[i].Name == name {
			return &cfg.Scrubbing.Nodes[i]
		}
	}
	return nil
}

// handleNodeReport stores a node's self-report. 404 for a node the config does
// not declare: the report store must not be growable by whoever holds an agent
// token (an unknown name is either a typo the operator wants surfaced loudly,
// or an attacker probing), and a node absent from scrubbing.nodes[] can never
// receive diverted traffic anyway, so there is nothing true to report about it.
func (s *Server) handleNodeReport(w http.ResponseWriter, r *http.Request) {
	// Same tenant rule as the rules feed, same reason: the node namespace is
	// deployment-wide, so only unscoped tokens may touch it.
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "node reports are restricted to unscoped tokens")
		return
	}
	name := r.PathValue("name")
	if configuredNode(s.store.Get(), name) == nil {
		writeError(w, http.StatusNotFound, "unknown scrubbing node")
		return
	}
	var rep NodeReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNodeReportBytes)).Decode(&rep); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "report exceeds 64 KiB")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	// Stored, never acted on. Specifically NOT recorded as a poll: a report
	// must not extend a node's liveness by a single millisecond.
	s.nodeReports.put(name, rep, time.Now())
	w.WriteHeader(http.StatusNoContent)
}

package api

import (
	"net/http"
	"sort"
	"time"
)

// GET /api/v1/edge/zones/status (E4.5): the zones the ALIVE edge nodes
// report, merged across them — the console's Edge view and the acceptance
// rig's "who would be challenged" set (edge-spec §8: a dry-run pass must show
// who would have been challenged before any zone turns the rung on). Built
// from the nodes' advisory self-reports, so it is what the nodes claim; the
// brain sums and unions, never acts on it.

// EdgeZonesStatusDoc is the response.
type EdgeZonesStatusDoc struct {
	// NodesReporting counts the alive nodes whose last report carried zones.
	NodesReporting int              `json:"nodes_reporting"`
	Zones          []EdgeZoneStatus `json:"zones"`
}

// EdgeZoneStatus is one zone across the alive nodes.
type EdgeZoneStatus struct {
	Zone string `json:"zone"`
	// Nodes counts the alive nodes reporting the zone.
	Nodes int `json:"nodes"`
	// The window figures summed across those nodes (each node's last window;
	// the windows are not aligned, so this is a fleet-wide rate to the
	// nearest window, not an exact one).
	RPS            float64 `json:"rps"`
	Requests       uint64  `json:"requests,omitempty"`
	Decided        uint64  `json:"decided,omitempty"`
	Denied         uint64  `json:"denied,omitempty"`
	Challenged     uint64  `json:"challenged,omitempty"`
	Cleared        uint64  `json:"cleared,omitempty"`
	WouldDeny      uint64  `json:"would_deny,omitempty"`
	WouldChallenge uint64  `json:"would_challenge,omitempty"`
	// WatchOnly names the nodes on which the zone is watch-only (the node's
	// dry_run or the zone's policy.dry_run): where the rung would not bite.
	WatchOnly []string `json:"watch_only,omitempty"`
	// ChallengeActive names the nodes with a zone-wide challenge in force.
	ChallengeActive []EdgeZoneChallengeNode `json:"challenge_active,omitempty"`
	// WouldBe is the union, across nodes, of the sources the nodes previewed
	// a deny or a challenge for — the would-be set. The busiest first,
	// bounded to 20 per reporting node; WouldBeTruncated counts the rest.
	WouldBe          []EdgeZoneWouldBe `json:"would_be,omitempty"`
	WouldBeTruncated int               `json:"would_be_truncated,omitempty"`
}

// EdgeZoneChallengeNode is one node's zone-wide challenge.
type EdgeZoneChallengeNode struct {
	Node   string    `json:"node"`
	Reason string    `json:"reason,omitempty"`
	Until  time.Time `json:"until"`
}

// EdgeZoneWouldBe is one source of the would-be set.
type EdgeZoneWouldBe struct {
	Source string `json:"source"`
	// State is would-deny or would-challenge — the stronger of what the
	// nodes previewed.
	State    string   `json:"state"`
	Requests uint64   `json:"requests"`
	Nodes    []string `json:"nodes"`
}

// wouldBePerNode bounds the would-be set: the aggregator names at most this
// many sources per window, so more than this per node cannot be known.
const wouldBePerNode = 20

// handleEdgeZonesStatus serves the merged zone status. Unscoped tokens only,
// like the inventory: node names are topology.
func (s *Server) handleEdgeZonesStatus(w http.ResponseWriter, r *http.Request) {
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "the edge zone status names nodes and is restricted to unscoped tokens")
		return
	}
	cfg := s.store.Get()
	staleAfter := edgeStaleAfter(cfg)
	reports := make(map[string]EdgeReport)
	if cfg.Edge != nil {
		for i := range cfg.Edge.Nodes {
			name := cfg.Edge.Nodes[i].Name
			if !s.edgePresence.alive(name, staleAfter) {
				continue
			}
			if rep, _, ok := s.edgeReports.get(name); ok {
				reports[name] = rep
			}
		}
	}
	writeJSON(w, http.StatusOK, mergeEdgeZones(reports))
}

// mergeEdgeZones folds the alive nodes' reports into one status per zone.
// Deterministic: zones by name, nodes by name, the would-be set by requests
// then source.
func mergeEdgeZones(reports map[string]EdgeReport) EdgeZonesStatusDoc {
	doc := EdgeZonesStatusDoc{Zones: []EdgeZoneStatus{}}
	names := make([]string, 0, len(reports))
	for name := range reports {
		names = append(names, name)
	}
	sort.Strings(names)
	type wouldBe struct {
		state    string
		requests uint64
		nodes    []string
	}
	zones := make(map[string]*EdgeZoneStatus)
	sets := make(map[string]map[string]*wouldBe)
	for _, name := range names {
		rep := reports[name]
		if len(rep.Zones) == 0 {
			continue
		}
		doc.NodesReporting++
		for _, z := range rep.Zones {
			zs := zones[z.Zone]
			if zs == nil {
				zs = &EdgeZoneStatus{Zone: z.Zone}
				zones[z.Zone] = zs
				sets[z.Zone] = make(map[string]*wouldBe)
			}
			zs.Nodes++
			zs.RPS += z.RPS
			zs.Requests += z.Requests
			zs.Decided += z.Decided
			zs.Denied += z.Denied
			zs.Challenged += z.Challenged
			zs.Cleared += z.Cleared
			zs.WouldDeny += z.WouldDeny
			zs.WouldChallenge += z.WouldChallenge
			if z.DryRun {
				zs.WatchOnly = append(zs.WatchOnly, name)
			}
			if z.ChallengeActive != nil {
				zs.ChallengeActive = append(zs.ChallengeActive, EdgeZoneChallengeNode{Node: name, Reason: z.ChallengeActive.Reason, Until: z.ChallengeActive.Until})
			}
			for _, src := range z.TopSources {
				if src.State != SourceStateWouldDeny && src.State != SourceStateWouldChallenge {
					continue
				}
				wb := sets[z.Zone][src.Source]
				if wb == nil {
					wb = &wouldBe{state: src.State}
					sets[z.Zone][src.Source] = wb
				}
				if src.State == SourceStateWouldDeny {
					wb.state = SourceStateWouldDeny
				}
				wb.requests += src.Requests
				wb.nodes = append(wb.nodes, name)
			}
		}
	}
	for _, zs := range zones {
		set := sets[zs.Zone]
		all := make([]EdgeZoneWouldBe, 0, len(set))
		for src, wb := range set {
			all = append(all, EdgeZoneWouldBe{Source: src, State: wb.state, Requests: wb.requests, Nodes: wb.nodes})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].Requests != all[j].Requests {
				return all[i].Requests > all[j].Requests
			}
			return all[i].Source < all[j].Source
		})
		if limit := wouldBePerNode * zs.Nodes; len(all) > limit {
			zs.WouldBeTruncated = len(all) - limit
			all = all[:limit]
		}
		if len(all) > 0 {
			zs.WouldBe = all
		}
		doc.Zones = append(doc.Zones, *zs)
	}
	sort.Slice(doc.Zones, func(i, j int) bool { return doc.Zones[i].Zone < doc.Zones[j].Zone })
	return doc
}

package api

import (
	"net/http"
	"sort"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// GET /api/v1/edge/zones/status (E4.5): the zones the ALIVE edge nodes
// report, merged across them — the console's Edge view and the acceptance
// rig's "who would be challenged" set (edge-spec §8: a dry-run pass must show
// who would have been challenged before any zone turns the rung on). Built
// from the nodes' advisory self-reports, so it is what the nodes claim; the
// brain sums and unions, never acts on it. Since E6.2 every zone of the zones
// file has a row too (the brain's word: its mode and file challenge, its
// certificates as the alive nodes report them), and a tenant-scoped token
// gets exactly its own zones (edge_tenant.go).

// EdgeZonesStatusDoc is the response.
type EdgeZonesStatusDoc struct {
	// NodesAlive counts the alive edge nodes; NodesReporting those among them
	// whose last report carried zones (a node whose zones are all in observe
	// mode is alive and reports none).
	NodesAlive     int              `json:"nodes_alive"`
	NodesReporting int              `json:"nodes_reporting"`
	Zones          []EdgeZoneStatus `json:"zones"`
	// ZonesTruncated sums the zone entries the alive nodes cut from their
	// reports to fit the size limit: those zones are missing or undercounted
	// here, and a consumer must say so rather than show a shorter fleet.
	// CertsTruncated does the same for the certificates behind the rows'
	// certs (E6.2): a short list is "what survived the node's cap", not
	// "nothing held".
	ZonesTruncated int `json:"zones_truncated,omitempty"`
	CertsTruncated int `json:"certs_truncated,omitempty"`
}

// EdgeZoneStatus is one zone across the alive nodes.
type EdgeZoneStatus struct {
	Zone string `json:"zone"`
	// Tenant is the zone's ownership label from the zones file (E6.2), for
	// unscoped callers only: a scoped caller's rows are all its own, and the
	// label would say nothing it does not know.
	Tenant string `json:"tenant,omitempty"`
	// Mode is the zones file's policy.mode (decide or none) and FileChallenge
	// its policy.challenge — the brain's word, present for every zone in the
	// file, while Challenge below is what the nodes report they apply. A zone
	// reported or levered but gone from the file has neither.
	Mode          string `json:"mode,omitempty"`
	FileChallenge string `json:"file_challenge,omitempty"`
	// Nodes counts the alive nodes reporting the zone.
	Nodes int `json:"nodes"`
	// Challenge is the zone's challenge mode as the nodes apply it (off,
	// manual, auto) — the same on every node, from the one document.
	Challenge string `json:"challenge,omitempty"`
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
	// RungWatchOnly names the nodes on which the RUNG previews rather than
	// bites: the watch-only ones, plus those where the rung's own
	// challenge_options.dry_run holds. A manual or auto zone challenges for
	// real on the nodes not named here.
	RungWatchOnly []string `json:"rung_watch_only,omitempty"`
	// ChallengeActive names the nodes with a zone-wide challenge in force.
	ChallengeActive []EdgeZoneChallengeNode `json:"challenge_active,omitempty"`
	// Override is the operator's lever in force on the zone (E4.6), if any.
	Override *edgedoc.ChallengeOverride `json:"override,omitempty"`
	// WouldBe is the union, across nodes, of the sources the nodes previewed
	// a deny or a challenge for — the would-be set. The busiest first,
	// bounded to 20 per reporting node; WouldBeTruncated counts the rest.
	// Partial says at least one node's would-be sources did not all fit its
	// report — its per-window bound, or a report that had to shrink — so the
	// set is what survived, not everyone.
	WouldBe          []EdgeZoneWouldBe `json:"would_be,omitempty"`
	WouldBeTruncated int               `json:"would_be_truncated,omitempty"`
	Partial          bool              `json:"partial,omitempty"`
	// H3 is the zone's HTTP/3 across the alive nodes (E5): present when the
	// zones file asks for it or a node reports it.
	H3 *EdgeZoneH3 `json:"h3,omitempty"`
	// Certs lists the certificate each alive node holds for the zone, from
	// its report (E6.2) — the zone's expiry without the inventory. Public
	// metadata only, never a key: the report type forbids it.
	Certs []EdgeZoneCert `json:"certs,omitempty"`
	// Placement is where the zones file puts the zone (E6.3): its hostgroup
	// (global when it names none), the configured nodes whose scope covers it
	// and which of them are alive. Present for every zone of the file;
	// Unserved says the zone has nodes but none alive — the operator's alarm
	// (a zone with no node at all shows nodes: [] and is a -check-config
	// warning, not an alarm here).
	Placement *EdgeZonePlacement `json:"placement,omitempty"`
	Unserved  bool               `json:"unserved,omitempty"`
}

// EdgeZonePlacement is a zone's placement across the fleet.
type EdgeZonePlacement struct {
	Hostgroup string   `json:"hostgroup"`
	Nodes     []string `json:"nodes"`
	Alive     []string `json:"alive"`
}

// EdgeZoneH3 is one zone's HTTP/3 across the alive nodes.
type EdgeZoneH3 struct {
	// Enabled is the zones file's tls.h3 as the brain holds it now.
	Enabled bool `json:"enabled"`
	// Serving names the alive nodes whose live generation listens over QUIC
	// for the zone; Unsupported those where the zone asked and is served over
	// TCP (the node's terminator.h3.state says why).
	Serving     []string `json:"serving,omitempty"`
	Unsupported []string `json:"unsupported,omitempty"`
	// Requests sums the nodes' last-window requests that arrived over HTTP/3.
	Requests uint64 `json:"requests,omitempty"`
}

// EdgeZoneChallengeNode is one node's zone-wide challenge. DryRun says the
// flip previews on that node (would-challenge marks) rather than bites.
type EdgeZoneChallengeNode struct {
	Node   string    `json:"node"`
	Reason string    `json:"reason,omitempty"`
	Until  time.Time `json:"until"`
	DryRun bool      `json:"dry_run,omitempty"`
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

// EdgeZoneCert is one alive node's certificate for the zone, as reported.
type EdgeZoneCert struct {
	Node     string    `json:"node"`
	NotAfter time.Time `json:"not_after"`
	Issuer   string    `json:"issuer,omitempty"`
}

// wouldBePerNode bounds the would-be set: the aggregator names at most this
// many sources per window, so more than this per node cannot be known.
const wouldBePerNode = 20

// handleEdgeZonesStatus serves the merged zone status at viewer rank. An
// unscoped token sees every zone; a tenant-scoped one (E6.2) exactly the
// file's zones labelled with its tenant — another tenant's hostname appears
// in no row, no would-be set and no HTTP/3 list, and the tenant field is left
// out. Node names are visible to a tenant (edge-spec §8, D3): where its zones
// are served is its business; the addresses and hostgroups stay in the
// inventory, which stays unscoped.
func (s *Server) handleEdgeZonesStatus(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	cfg := s.store.Get()
	visible := func(zone string) bool { return visibleZone(c, cfg, zone) }
	// A node's claims about a zone its placement does not cover are not
	// merged (E6.3): the report is stored verbatim for the inventory, but the
	// zone's status is the word of the nodes that serve it. A zone outside the
	// file has no placement and is shown as before.
	serves := func(node, zone string) bool {
		z := zoneInFile(cfg, zone)
		return z == nil || cfg.EdgeNodeServes(node, z)
	}
	staleAfter := edgeStaleAfter(cfg)
	reports := make(map[string]EdgeReport)
	aliveNodes := make(map[string]bool)
	alive := 0
	if cfg.Edge != nil {
		for i := range cfg.Edge.Nodes {
			name := cfg.Edge.Nodes[i].Name
			if !s.edgePresence.alive(name, staleAfter) {
				continue
			}
			alive++
			aliveNodes[name] = true
			if rep, _, ok := s.edgeReports.get(name); ok {
				reports[name] = rep
			}
		}
	}
	doc := mergeEdgeZonesServed(reports, visible, serves)
	doc.NodesAlive = alive
	rows := make(map[string]int, len(doc.Zones))
	for i := range doc.Zones {
		rows[doc.Zones[i].Zone] = i
	}
	// row returns the zone's row, adding an empty one (nodes: 0) when no
	// alive node reported it. Indices stay valid across appends; a returned
	// pointer is used before the next append.
	row := func(zone string) *EdgeZoneStatus {
		if i, ok := rows[zone]; ok {
			return &doc.Zones[i]
		}
		doc.Zones = append(doc.Zones, EdgeZoneStatus{Zone: zone})
		rows[zone] = len(doc.Zones) - 1
		return &doc.Zones[len(doc.Zones)-1]
	}
	// The operator's lever is brain state: it shows for its zone whether or
	// not a node has reported the zone yet — on a zone a reload has since
	// removed from the file too, for the unscoped tokens that can clear it.
	for zone, o := range s.edgeLever.live(time.Now()) {
		if !visible(zone) {
			continue
		}
		ov := o
		row(zone).Override = &ov
	}
	// The zones file's word, brain state: every zone in it has a row — a
	// mode: none zone, or one no alive node has reported yet, with nodes: 0 —
	// carrying its mode and file challenge, whether it asks for HTTP/3 (which
	// nodes serve it is theirs) and, for unscoped callers, its tenant.
	if cfg.ZonesCfg != nil {
		for j := range cfg.ZonesCfg.Zones {
			z := &cfg.ZonesCfg.Zones[j]
			if !visible(z.Name) {
				continue
			}
			zs := row(z.Name)
			zs.Mode = z.Policy.Mode
			zs.FileChallenge = z.Policy.Challenge
			if c.unscoped() {
				zs.Tenant = z.Tenant
			}
			if z.TLS.H3 {
				if zs.H3 == nil {
					zs.H3 = &EdgeZoneH3{}
				}
				zs.H3.Enabled = true
			}
			// Placement (E6.3): the nodes the file puts the zone on and which
			// of them are alive. Node names are visible to a tenant (D3).
			pl := &EdgeZonePlacement{Hostgroup: config.EdgePlacement(z), Nodes: []string{}, Alive: []string{}}
			for _, name := range cfg.EdgeNodesServing(z) {
				pl.Nodes = append(pl.Nodes, name)
				if aliveNodes[name] {
					pl.Alive = append(pl.Alive, name)
				}
			}
			zs.Placement = pl
			zs.Unserved = len(pl.Nodes) > 0 && len(pl.Alive) == 0
		}
	}
	// Two more passes over the alive reports, nodes in name order, for the
	// rows that exist (rows hold visible zones only, so nothing foreign can
	// enter here). First the live QUIC listeners from terminator.h3: a
	// mode: none zone is not in a report's zones section, so the merge could
	// not mark it as serving/unsupported — this can. Then the certificates
	// the nodes hold for the rows; a certificate for a zone without a row
	// (gone from the file, reported by nobody, no lever) is not a zone to show.
	names := make([]string, 0, len(reports))
	for name := range reports {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rep := reports[name]
		doc.CertsTruncated += rep.CertsTruncated
		if rep.Terminator != nil && rep.Terminator.H3 != nil {
			for _, zone := range rep.Terminator.H3.Serving {
				if i, ok := rows[zone]; ok && serves(name, zone) {
					h3 := rowH3(&doc.Zones[i])
					h3.Serving = appendUnique(h3.Serving, name)
				}
			}
			for _, zone := range rep.Terminator.H3.Unsupported {
				if i, ok := rows[zone]; ok && serves(name, zone) {
					h3 := rowH3(&doc.Zones[i])
					h3.Unsupported = appendUnique(h3.Unsupported, name)
				}
			}
		}
		for _, cert := range rep.Certs {
			i, ok := rows[cert.Zone]
			if !ok || !serves(name, cert.Zone) {
				continue
			}
			doc.Zones[i].Certs = append(doc.Zones[i].Certs, EdgeZoneCert{Node: name, NotAfter: cert.NotAfter, Issuer: cert.Issuer})
		}
	}
	sort.Slice(doc.Zones, func(i, j int) bool { return doc.Zones[i].Zone < doc.Zones[j].Zone })
	writeJSON(w, http.StatusOK, doc)
}

// rowH3 returns the row's h3 block, creating it.
func rowH3(zs *EdgeZoneStatus) *EdgeZoneH3 {
	if zs.H3 == nil {
		zs.H3 = &EdgeZoneH3{}
	}
	return zs.H3
}

// appendUnique appends s unless the list already holds it (the merge may have
// named the node for a deciding zone before the terminator pass runs).
func appendUnique(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// mergeEdgeZones folds the alive nodes' reports into one status per zone,
// every zone visible and every node's claim taken.
func mergeEdgeZones(reports map[string]EdgeReport) EdgeZonesStatusDoc {
	return mergeEdgeZonesServed(reports, func(string) bool { return true }, func(string, string) bool { return true })
}

// mergeEdgeZonesServed is the merge under both predicates: visible per zone
// (the caller's tenant, E6.2) and serves per (node, zone) (the node's
// placement, E6.3) — a node's claim about a zone it does not serve is not
// merged. Deterministic: zones by name, nodes by name, the would-be set by
// requests then source.
func mergeEdgeZonesServed(reports map[string]EdgeReport, visible func(zone string) bool, serves func(node, zone string) bool) EdgeZonesStatusDoc {
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
	// h3 lists a node's serving/unsupported zones by zone, so a zone the node
	// reports can be marked as it is looped over below.
	h3 := func(rep EdgeReport, zone string) (serving, unsupported bool) {
		if rep.Terminator == nil || rep.Terminator.H3 == nil {
			return false, false
		}
		for _, z := range rep.Terminator.H3.Serving {
			if z == zone {
				serving = true
			}
		}
		for _, z := range rep.Terminator.H3.Unsupported {
			if z == zone {
				unsupported = true
			}
		}
		return serving, unsupported
	}
	for _, name := range names {
		rep := reports[name]
		doc.ZonesTruncated += rep.ZonesTruncated
		if len(rep.Zones) == 0 {
			continue
		}
		doc.NodesReporting++
		for _, z := range rep.Zones {
			if !visible(z.Zone) || !serves(name, z.Zone) {
				continue
			}
			zs := zones[z.Zone]
			if zs == nil {
				zs = &EdgeZoneStatus{Zone: z.Zone}
				zones[z.Zone] = zs
				sets[z.Zone] = make(map[string]*wouldBe)
			}
			zs.Nodes++
			if serving, unsupported := h3(rep, z.Zone); serving || unsupported || z.H3Requests > 0 {
				if zs.H3 == nil {
					zs.H3 = &EdgeZoneH3{}
				}
				if serving {
					zs.H3.Serving = append(zs.H3.Serving, name)
				}
				if unsupported {
					zs.H3.Unsupported = append(zs.H3.Unsupported, name)
				}
				zs.H3.Requests += z.H3Requests
			}
			if zs.Challenge == "" {
				zs.Challenge = z.Challenge
			}
			if z.SourcesTruncated > 0 {
				zs.Partial = true
			}
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
			if z.RungDryRun {
				zs.RungWatchOnly = append(zs.RungWatchOnly, name)
			}
			if z.ChallengeActive != nil {
				zs.ChallengeActive = append(zs.ChallengeActive, EdgeZoneChallengeNode{Node: name, Reason: z.ChallengeActive.Reason, Until: z.ChallengeActive.Until, DryRun: z.ChallengeActive.DryRun})
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

package node

import (
	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// keepWindow is the aggregator's OnWindow: the last closed window per zone,
// top-N sources included, kept for the next self-report.
func (n *Node) keepWindow(w rollup.WindowStats) {
	n.mu.Lock()
	if n.windows == nil {
		n.windows = make(map[string]rollup.WindowStats)
	}
	n.windows[w.Zone] = w
	n.mu.Unlock()
}

// reportZones is the self-report's zones section (E4.5): one entry per zone
// the LIVE generation serves in decide mode, with its last window (if one
// closed yet), whether a zone-wide challenge is in force and whether the zone
// is watch-only here. The document's order (by name) is kept. Caller holds
// n.mu.
func (n *Node) reportZones() []api.EdgeReportZone {
	if n.renderedDoc == nil {
		return nil
	}
	var out []api.EdgeReportZone
	for i := range n.renderedDoc.Zones {
		z := &n.renderedDoc.Zones[i]
		if z.Policy.Mode != edgedoc.ModeDecide {
			continue
		}
		rz := api.EdgeReportZone{Zone: z.Name, DryRun: n.opt.DryRun || z.Policy.DryRun}
		if w, ok := n.windows[z.Name]; ok {
			fillReportZone(&rz, w)
		}
		if on, until, why := n.svc.ZoneChallenge(z.Name); on {
			rz.ChallengeActive = &api.EdgeReportChallenge{Reason: why, Until: until}
		}
		out = append(out, rz)
	}
	return out
}

// fillReportZone copies a closed window into the report's shape.
func fillReportZone(rz *api.EdgeReportZone, w rollup.WindowStats) {
	rz.At = w.Start.Add(w.Elapsed)
	rz.WindowSeconds = w.Elapsed.Seconds()
	rz.RPS = w.RPS
	rz.Requests, rz.Decided, rz.Denied = w.Requests, w.Decided, w.Denied
	rz.Challenged, rz.Cleared = w.Challenged, w.Cleared
	rz.WouldDeny, rz.WouldChallenge = w.WouldDeny, w.WouldChallenge
	rz.Status2xx, rz.Status3xx, rz.Status4xx, rz.Status5xx = w.Status2xx, w.Status3xx, w.Status4xx, w.Status5xx
	if len(w.Sources) > 0 {
		rz.TopSources = make([]api.EdgeReportSource, 0, len(w.Sources))
		for _, s := range w.Sources {
			rz.TopSources = append(rz.TopSources, api.EdgeReportSource{Source: s.Src.String(), RPS: s.RPS, Requests: s.Requests, State: sourceState(s)})
		}
	}
}

// sourceState is the strongest thing the node did to a source in the window
// (api.SourceState*): a table verdict that refused it, the rung, a dry-run
// preview of either, a clearance, a mark, or nothing. A rate deny is not a
// state — a busy client over its ceiling is still an allowed client.
func sourceState(s rollup.SourceStats) string {
	switch {
	case s.DeniedTable > 0:
		return api.SourceStateDenied
	case s.Challenged > 0:
		return api.SourceStateChallenged
	case s.WouldDeny > 0:
		return api.SourceStateWouldDeny
	case s.WouldChallenge > 0:
		return api.SourceStateWouldChallenge
	case s.Cleared > 0:
		return api.SourceStateCleared
	case s.Marked > 0:
		return api.SourceStateMarked
	}
	return api.SourceStateAllow
}

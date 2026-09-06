package node

import (
	"time"

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

// staleWindowAfter is how long a zone's last window stands for "now": two
// aggregator windows. The aggregator closes windows only for zones that saw
// traffic, so a zone that went quiet would otherwise report its last busy
// window as current for as long as it stays quiet.
func (n *Node) staleWindowAfter() time.Duration {
	w := n.agg.Window
	if w <= 0 {
		w = rollup.DefaultWindow
	}
	return 2 * w
}

// reportZones is the self-report's zones section (E4.5): one entry per zone
// the LIVE generation serves in decide mode, with its last window (if one
// closed recently — an older one reads as a quiet zone: zeros), whether a
// zone-wide challenge is in force and whether it bites, and whether the zone
// is watch-only here. The zone LIST is the rendered document's (what the
// terminator serves); the policy flags are the ACCEPTED document's, the one
// the decision service enforces — they differ while a document the renderer
// refused is still being retried. The document's order (by name) is kept.
// Caller holds n.mu.
func (n *Node) reportZones(now time.Time) []api.EdgeReportZone {
	if n.renderedDoc == nil {
		return nil
	}
	accepted := make(map[string]*edgedoc.Zone, len(n.renderedDoc.Zones))
	if n.doc != nil {
		for i := range n.doc.Zones {
			accepted[n.doc.Zones[i].Name] = &n.doc.Zones[i]
		}
	}
	stale := n.staleWindowAfter()
	var out []api.EdgeReportZone
	for i := range n.renderedDoc.Zones {
		z := &n.renderedDoc.Zones[i]
		if z.Policy.Mode != edgedoc.ModeDecide {
			continue
		}
		az, ok := accepted[z.Name]
		if !ok {
			az = z
		}
		pol := az.Policy
		// The mode is the EFFECTIVE one — the brain's lever included — as the
		// decision service applies it, not the file's word: under a manual
		// lever the zone challenges everyone, and the report must say so.
		// DryRun is the zone's watch-only state here (the node's or the zone's
		// own); RungDryRun the rung's — those two, or the rung's own switch —
		// so a consumer can tell an enforcing rung from one that only previews
		// without guessing from a window's counters.
		watchOnly := n.opt.DryRun || pol.DryRun
		rz := api.EdgeReportZone{Zone: z.Name, DryRun: watchOnly, RungDryRun: watchOnly || pol.ChallengeDryRun(), Challenge: az.EffectiveChallenge(now)}
		if w, ok := n.windows[z.Name]; ok && now.Sub(w.Start.Add(w.Elapsed)) <= stale {
			fillReportZone(&rz, w)
		}
		if on, until, why := n.svc.ZoneChallenge(z.Name); on {
			rz.ChallengeActive = &api.EdgeReportChallenge{Reason: why, Until: until, DryRun: rz.RungDryRun}
		}
		out = append(out, rz)
	}
	return out
}

// pruneWindows forgets the kept windows of zones the document no longer has:
// the per-zone stores follow the document, this one like the others, so a
// fleet that adds and removes zones for years does not keep every departed
// zone's last window. Caller holds n.mu.
func (n *Node) pruneWindows(names []string) {
	if len(n.windows) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(names))
	for _, name := range names {
		keep[name] = struct{}{}
	}
	for name := range n.windows {
		if _, ok := keep[name]; !ok {
			delete(n.windows, name)
		}
	}
}

// fillReportZone copies a closed window into the report's shape.
func fillReportZone(rz *api.EdgeReportZone, w rollup.WindowStats) {
	rz.At = w.Start.Add(w.Elapsed)
	rz.WindowSeconds = w.Elapsed.Seconds()
	// The aggregator's own bound counts here too: a would-be source it cut is
	// one the set lacks, and the brain must say "partial", not "nobody". A
	// refused or challenged source it cut is not in the set and not counted.
	rz.SourcesTruncated = w.WouldBeTruncated
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

// telling reports whether a source's state is one the brain's would-be set
// or an operator's eye needs: what the node did or would do to it. An allowed,
// marked or cleared source is the first to go when the report must shrink.
func telling(state string) bool {
	switch state {
	case api.SourceStateDenied, api.SourceStateChallenged, api.SourceStateWouldDeny, api.SourceStateWouldChallenge:
		return true
	}
	return false
}

// shedByLimit counts the would-be sources the body limit made the report
// shed: per zone still in the trimmed report, what its count grew by over the
// untrimmed one. A zone dropped whole is ZonesTruncated's to tell, not this.
func shedByLimit(raw, trimmed api.EdgeReport) int {
	before := make(map[string]int, len(raw.Zones))
	for _, z := range raw.Zones {
		before[z.Zone] = z.SourcesTruncated
	}
	n := 0
	for _, z := range trimmed.Zones {
		if d := z.SourcesTruncated - before[z.Zone]; d > 0 {
			n += d
		}
	}
	return n
}

// shedSources sums the per-source entries the report shed across its zones.
func shedSources(rep api.EdgeReport) int {
	n := 0
	for _, z := range rep.Zones {
		n += z.SourcesTruncated
	}
	return n
}

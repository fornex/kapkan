package api

// The edge history's write path (edge-spec §8, milestone E6.5): the brain
// turns each accepted node report into edge_windows / edge_sources rows and
// the transitions it can see between two reports into edge_events, and a
// presence ticker turns the poll-based liveness into node_alive / node_lost.
//
// Everything here is map work and non-blocking enqueues — never I/O, never an
// error: a report was accepted (204) before observe runs and stays accepted
// whatever the history makes of it; the storage writer drops on a full queue
// and counts the drop. The rules, each counted in
// kapkan_edge_history_dropped_total{reason} when they skip something:
//
//   - a window's zone must be in the live zones file (unknown_zone) — the
//     history is keyed by the file's zones, and a node cannot make it grow;
//   - a window needs a close time (no_at);
//   - a window is written once: the same (node, zone, at) again is a report
//     the node re-sent (duplicate) — six copies of one report are one row;
//   - `ts` is the node's `at` when it is within historyClockBehind behind or
//     historyClockAhead ahead of the brain's clock (D11); otherwise the brain's
//     clock is written instead, `received_at` is always the brain's, and one
//     clock_skew event marks each transition into and out of skew — the data
//     is kept, the TTL is not broken, the finding is visible;
//   - sources are written only in the telling states (denied, challenged,
//     would-deny, would-challenge — D14), must parse as an address (the /64
//     key is an address, bad_source), and at most EdgeSourcesPerWindow per
//     window (source_cap).
//
// Events come from the difference between a node's previous report on THIS
// brain and the new one; the first report after a brain start sets the
// baseline silently — no fleet-wide burst of cert_issued after a restart.
// No tenant is written anywhere (D12): ownership is the zones file's at read
// time. Rows are claims, like the reports they come from.

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/storage"
)

const (
	// The node-clock gate (D11): a window close this far behind the brain's
	// clock is still the node's (a report interval plus a slow poll), this far
	// ahead is not (nothing legitimate is in the future by more than a skew).
	historyClockBehind = 10 * time.Minute
	historyClockAhead  = time.Minute
	// presenceTickMax bounds the presence ticker's period; the period is
	// min(stale_after/2, this), so a lost node is noticed within its window.
	presenceTickMax = 5 * time.Second
	// historyTimeLayout is ClickHouse's DateTime literal (UTC), the layout
	// every row carries.
	historyTimeLayout = "2006-01-02 15:04:05"
	// maxEventDetail bounds the free text an event carries; the sources are
	// bounded report fields, the bound is belt and braces.
	maxEventDetail = 200
)

// The event kinds edge_events carries.
const (
	EventNodeAlive           = "node_alive"
	EventNodeLost            = "node_lost"
	EventVersion             = "version"
	EventDryRun              = "dry_run"
	EventDocumentRendered    = "document_rendered"
	EventGenerationInstalled = "generation_installed"
	EventGenerationRefused   = "generation_refused"
	EventTerminatorAlive     = "terminator_alive"
	EventH3State             = "h3_state"
	EventCertIssued          = "cert_issued"
	EventCertRenewed         = "cert_renewed"
	EventCertGone            = "cert_gone"
	EventChallengeStarted    = "challenge_started"
	EventChallengeEnded      = "challenge_ended"
	EventClockSkew           = "clock_skew"
	EventReportTruncated     = "report_truncated"
)

// edgeHistory is the Server's write-path state: the writer, the last window
// close written per (node, zone) for the dedup rule, each node's clock-skew
// state, and the presence the ticker last observed per node.
type edgeHistory struct {
	mu     sync.Mutex
	w      storage.Writer
	lastAt map[string]map[string]time.Time
	skewed map[string]bool
	alive  map[string]bool
}

func (h *edgeHistory) setWriter(w storage.Writer) {
	h.mu.Lock()
	h.w = w
	h.mu.Unlock()
}

func (h *edgeHistory) writer() storage.Writer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.w
}

func historyDrop(reason string) { metrics.EdgeHistoryDropped.WithLabelValues(reason).Inc() }

func historyTime(t time.Time) string { return t.UTC().Format(historyTimeLayout) }

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// tellingState says whether a source's state is a finding worth keeping —
// something a node did or would have done to it — rather than a visitor.
func tellingState(state string) bool {
	switch state {
	case SourceStateDenied, SourceStateChallenged, SourceStateWouldDeny, SourceStateWouldChallenge:
		return true
	}
	return false
}

// validSourceKey accepts the accounting key as the node writes it: an
// address (an IPv6 /64 is its masked address, edgedoc.SourceKey).
func validSourceKey(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.IsValid() && a.Zone() == ""
}

func clip(s string) string {
	if len(s) <= maxEventDetail {
		return s
	}
	return s[:maxEventDetail]
}

func historyEvent(at time.Time, node, zone, kind, detail string) storage.EdgeEventRow {
	return storage.EdgeEventRow{EventTime: historyTime(at), Node: node, Zone: zone, Kind: kind, Detail: clip(detail)}
}

// observe turns one accepted report into rows and events and enqueues them.
// prev is the node's previous report on this brain (nil for the first since
// start, the silent baseline); now is when the brain took the report.
func (h *edgeHistory) observe(cfg *config.Config, node string, prev *EdgeReport, rep EdgeReport, now time.Time) {
	w := h.writer()
	if w == nil {
		return
	}
	received := historyTime(now)
	var (
		windows  []storage.EdgeWindowRow
		sources  []storage.EdgeSourceRow
		events   []storage.EdgeEventRow
		measured bool          // at least one window had a close time
		skewNow  bool          // …and at least one of them was outside the gate
		skewBy   time.Duration // the largest offset seen, for the event's detail
	)
	h.mu.Lock()
	if h.lastAt == nil {
		h.lastAt = make(map[string]map[string]time.Time)
	}
	if h.skewed == nil {
		h.skewed = make(map[string]bool)
	}
	byZone := h.lastAt[node]
	if byZone == nil {
		byZone = make(map[string]time.Time)
		h.lastAt[node] = byZone
	}
	for _, z := range rep.Zones {
		if zoneInFile(cfg, z.Zone) == nil {
			historyDrop("unknown_zone")
			continue
		}
		if z.At.IsZero() {
			historyDrop("no_at")
			continue
		}
		if last, ok := byZone[z.Zone]; ok && last.Equal(z.At) {
			historyDrop("duplicate")
			continue
		}
		byZone[z.Zone] = z.At
		measured = true
		ts := z.At
		if off := z.At.Sub(now); off < -historyClockBehind || off > historyClockAhead {
			ts = now
			skewNow = true
			if abs := off; abs < 0 {
				abs = -abs
				if abs > skewBy {
					skewBy = -off
				}
			} else if abs > skewBy {
				skewBy = off
			}
		}
		tsStr := historyTime(ts)
		row := storage.EdgeWindowRow{
			TS: tsStr, ReceivedAt: received, WindowSeconds: z.WindowSeconds, Zone: z.Zone, Node: node,
			Challenge: z.Challenge, DryRun: b2u8(z.DryRun), RungDryRun: b2u8(z.RungDryRun),
			Requests: z.Requests, Decided: z.Decided, Denied: z.Denied, Challenged: z.Challenged, Cleared: z.Cleared,
			WouldDeny: z.WouldDeny, WouldChallenge: z.WouldChallenge,
			Status2xx: z.Status2xx, Status3xx: z.Status3xx, Status4xx: z.Status4xx, Status5xx: z.Status5xx,
			H3Requests: z.H3Requests, SourcesTruncated: uint32(min(z.SourcesTruncated, 1<<31-1)),
		}
		if z.ChallengeActive != nil {
			row.ChallengeActive = 1
			row.ChallengeReason = z.ChallengeActive.Reason
		}
		windows = append(windows, row)
		kept := 0
		for _, src := range z.TopSources {
			if !tellingState(src.State) {
				continue
			}
			if !validSourceKey(src.Source) {
				historyDrop("bad_source")
				continue
			}
			if kept >= storage.EdgeSourcesPerWindow {
				historyDrop("source_cap")
				continue
			}
			kept++
			sources = append(sources, storage.EdgeSourceRow{TS: tsStr, Zone: z.Zone, Node: node, Source: src.Source, State: src.State, Requests: src.Requests, RPS: src.RPS})
		}
	}
	if measured && skewNow != h.skewed[node] {
		h.skewed[node] = skewNow
		detail := "recovered: the node's window clock is within the gate again"
		if skewNow {
			detail = fmt.Sprintf("node clock off by %s; its windows are stamped with the brain's clock (received_at)", skewBy.Round(time.Second))
		}
		events = append(events, historyEvent(now, node, "", EventClockSkew, detail))
	}
	h.mu.Unlock()

	if prev != nil {
		events = append(events, diffReports(node, *prev, rep, now)...)
	}
	if len(windows) > 0 {
		w.WriteEdgeWindows(windows)
	}
	if len(sources) > 0 {
		w.WriteEdgeSources(sources)
	}
	for _, e := range events {
		w.WriteEdgeEvent(e)
	}
}

// diffReports lists the transitions between a node's previous report and its
// new one, each exactly once per change and never for an identical repeat.
// Deterministic: zones in name order.
func diffReports(node string, prev, rep EdgeReport, now time.Time) []storage.EdgeEventRow {
	var out []storage.EdgeEventRow
	ev := func(zone, kind, detail string) {
		out = append(out, historyEvent(now, node, zone, kind, detail))
	}
	if rep.Version != "" && rep.Version != prev.Version {
		ev("", EventVersion, rep.Version)
	}
	if rep.DryRun != prev.DryRun {
		ev("", EventDryRun, map[bool]string{true: "on", false: "off"}[rep.DryRun])
	}
	if rep.ZonesETag != "" && rep.ZonesETag != prev.ZonesETag {
		ev("", EventDocumentRendered, "etag "+rep.ZonesETag)
	}
	if rt := rep.Terminator; rt != nil {
		pt := prev.Terminator
		if rt.Generation > 0 && (pt == nil || pt.Generation != rt.Generation) {
			ev("", EventGenerationInstalled, fmt.Sprintf("generation %d (%s %s)", rt.Generation, rt.Kind, rt.Version))
		}
		if !rt.TestOK && rt.TestError != "" && (pt == nil || pt.TestOK || pt.TestError != rt.TestError) {
			ev("", EventGenerationRefused, rt.TestError)
		}
		if rt.Alive != nil && (pt == nil || pt.Alive == nil || *pt.Alive != *rt.Alive) {
			ev("", EventTerminatorAlive, map[bool]string{true: "alive", false: "not running"}[*rt.Alive])
		}
		if rt.H3 != nil && (pt == nil || pt.H3 == nil || pt.H3.State != rt.H3.State) {
			ev("", EventH3State, rt.H3.State)
		}
	}
	// Certificates by zone.
	prevCerts := make(map[string]EdgeReportCert, len(prev.Certs))
	for _, c := range prev.Certs {
		prevCerts[c.Zone] = c
	}
	newCerts := make(map[string]EdgeReportCert, len(rep.Certs))
	for _, c := range rep.Certs {
		newCerts[c.Zone] = c
	}
	for _, zone := range sortedKeys(newCerts) {
		c := newCerts[zone]
		detail := "not_after=" + c.NotAfter.UTC().Format(time.RFC3339)
		if c.Issuer != "" {
			detail += " issuer=" + c.Issuer
		}
		p, had := prevCerts[zone]
		switch {
		case !had:
			ev(zone, EventCertIssued, detail)
		case !p.NotAfter.Equal(c.NotAfter):
			ev(zone, EventCertRenewed, detail)
		}
	}
	for _, zone := range sortedKeys(prevCerts) {
		if _, still := newCerts[zone]; !still {
			ev(zone, EventCertGone, "")
		}
	}
	// Zone-wide challenges by zone.
	prevChal := make(map[string]*EdgeReportChallenge, len(prev.Zones))
	for _, z := range prev.Zones {
		prevChal[z.Zone] = z.ChallengeActive
	}
	newChal := make(map[string]*EdgeReportChallenge, len(rep.Zones))
	for _, z := range rep.Zones {
		newChal[z.Zone] = z.ChallengeActive
	}
	for _, zone := range sortedKeys(newChal) {
		c := newChal[zone]
		p := prevChal[zone]
		switch {
		case c != nil && p == nil:
			detail := "until " + c.Until.UTC().Format(time.RFC3339)
			if c.Reason != "" {
				detail = c.Reason + "; " + detail
			}
			if c.DryRun {
				detail += " (preview)"
			}
			ev(zone, EventChallengeStarted, detail)
		case c == nil && p != nil:
			ev(zone, EventChallengeEnded, "")
		}
	}
	for _, zone := range sortedKeys(prevChal) {
		if _, still := newChal[zone]; !still && prevChal[zone] != nil {
			ev(zone, EventChallengeEnded, "zone left the report")
		}
	}
	// Truncation: a report that had to shrink, once per transition into it.
	if t := truncation(rep); t != "" && truncation(prev) == "" {
		ev("", EventReportTruncated, t)
	}
	return out
}

// truncation summarises what a report cut to fit the body limit, "" when
// nothing was cut.
func truncation(r EdgeReport) string {
	srcs := 0
	for _, z := range r.Zones {
		srcs += z.SourcesTruncated
	}
	if r.ZonesTruncated == 0 && r.CertsTruncated == 0 && srcs == 0 {
		return ""
	}
	return fmt.Sprintf("zones=%d certs=%d sources=%d", r.ZonesTruncated, r.CertsTruncated, srcs)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// runEdgePresence is the presence ticker: node_alive / node_lost on every
// transition, as an event when storage is on and as an INFO line always —
// "edge node lost" reaches the brain's log for the first time here. Started
// by ListenAndServe; the period is min(stale_after/2, presenceTickMax),
// re-read from the store each tick.
func (s *Server) runEdgePresence(ctx context.Context) {
	for {
		cfg := s.store.Get()
		s.edgePresenceTick(cfg, time.Now())
		period := min(edgeStaleAfter(cfg)/2, presenceTickMax)
		if period < time.Second {
			period = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(period):
		}
	}
}

// edgePresenceTick is one tick of the presence ticker at now. The first
// observation of a node is its baseline (recorded, not announced); from then
// on every change is one event and one log line. A lost node's event is
// stamped when it was lost — lastSeen + stale_after — not when the tick
// noticed it.
func (s *Server) edgePresenceTick(cfg *config.Config, now time.Time) {
	if cfg.Edge == nil {
		return
	}
	stale := edgeStaleAfter(cfg)
	w := s.edgeHist.writer()
	for i := range cfg.Edge.Nodes {
		name := cfg.Edge.Nodes[i].Name
		last, holding := s.edgePresence.seen(name)
		alive := holding || (!last.IsZero() && now.Sub(last) <= stale)
		s.edgeHist.mu.Lock()
		if s.edgeHist.alive == nil {
			s.edgeHist.alive = make(map[string]bool)
		}
		prev, known := s.edgeHist.alive[name]
		s.edgeHist.alive[name] = alive
		s.edgeHist.mu.Unlock()
		if !known || prev == alive {
			continue
		}
		if alive {
			s.log.Info("edge node alive", "node", name)
			if w != nil {
				w.WriteEdgeEvent(historyEvent(now, name, "", EventNodeAlive, ""))
			}
			continue
		}
		lostAt := last.Add(stale)
		s.log.Info("edge node lost: no poll within stale_after", "node", name, "last_seen", last.UTC().Format(time.RFC3339), "lost_at", lostAt.UTC().Format(time.RFC3339))
		if w != nil {
			w.WriteEdgeEvent(historyEvent(lostAt, name, "", EventNodeLost, "last_seen="+last.UTC().Format(time.RFC3339)))
		}
	}
}

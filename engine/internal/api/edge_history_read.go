package api

// The edge history's read side (edge-spec §8, milestone E6.6): three viewer-
// rank endpoints over the tables E6.4 shaped and E6.5 fills.
//
//   GET /api/v1/edge/history?zone=&[node=]&from&to&step
//       a zone's windows summed into step-second buckets — the client derives
//       rps as requests/window_seconds and the HTTP/3 share as
//       h3_requests/requests;
//   GET /api/v1/edge/history/sources?zone=&from&to[&state=]
//       the zone's telling sources over the range, the strongest state each
//       node gave a source, the busiest first — the §8 question "who would
//       have been challenged" over a period rather than a ten-second window;
//   GET /api/v1/edge/events?[node][zone][kind]&from&to
//       the transitions the brain saw, newest first.
//
// Range parsing is the one the traffic and audit endpoints use (parseRange):
// RFC 3339, an hour by default, at most 31 days, at most maxHistoryBuckets
// buckets. No querier (storage off) answers {available:false}, never an error,
// like /api/v1/traffic; a failed query is 502.
//
// Scope (E6.2's predicate, D12): a tenant-scoped token reads the history of
// its OWN zones — ownership from the live zones file, never from a column —
// and gets one uniform 403 for a zone that is not its own, whether the zone
// is another tenant's, unlabelled, gone from the file or nonexistent (no
// existence oracle). `node=` and /events name nodes and stay unscoped: a
// tenant gets `nodes` as a count in the buckets, never the names' history.

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kapkan-io/kapkan/internal/storage"
)

const (
	// The range rules shared with /traffic and /audit.
	defaultRange = time.Hour
	maxRange     = 31 * 24 * time.Hour
	// maxHistoryBuckets bounds a bucketed read: a wide range with a tiny step
	// raises the step rather than the row count.
	maxHistoryBuckets = 5000
	// maxHistoryStep is the widest bucket, a day — the storage query clamps
	// to the same, so the step the response reports is the step the buckets
	// were built with.
	maxHistoryStep = 86400
	// historyQueryTimeout bounds one storage read.
	historyQueryTimeout = 10 * time.Second
)

// parseRange reads from/to (RFC 3339; the last hour by default) and applies
// the shared rules: to after from, at most maxRange. The error is the 400
// message, "" when the range is good.
func parseRange(q url.Values, now time.Time) (from, to time.Time, errMsg string) {
	to = now
	from = to.Add(-defaultRange)
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, "invalid from (expected RFC3339)"
		}
		from = t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, "invalid to (expected RFC3339)"
		}
		to = t
	}
	if !to.After(from) {
		return from, to, "to must be after from"
	}
	if to.Sub(from) > maxRange {
		return from, to, "time range too large (max 31 days)"
	}
	return from, to, ""
}

// parseStep reads step (positive integer seconds, 60 by default), raises it
// so the range holds at most maxHistoryBuckets buckets, and caps it at a day.
// The result is the step the query runs with, so a response may echo it.
func parseStep(q url.Values, from, to time.Time) (int, string) {
	step := 60
	if v := q.Get("step"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return 0, "invalid step (positive integer seconds)"
		}
		step = n
	}
	if span := int(to.Sub(from).Seconds()); span/step > maxHistoryBuckets {
		step = (span + maxHistoryBuckets - 1) / maxHistoryBuckets
	}
	if step > maxHistoryStep {
		step = maxHistoryStep
	}
	return step, ""
}

// EdgeHistoryDoc is the GET /api/v1/edge/history response. Zone and Node
// echo the request (Node only when the filter was given); StepSeconds is the
// step the buckets were built with, after the raise and the cap. With
// storage off only Available and an empty Points are present.
type EdgeHistoryDoc struct {
	Available   bool                       `json:"available"`
	Zone        string                     `json:"zone,omitempty"`
	Node        string                     `json:"node,omitempty"`
	StepSeconds int                        `json:"step_seconds,omitempty"`
	Points      []storage.EdgeHistoryPoint `json:"points"`
}

// EdgeHistorySourcesDoc is the GET /api/v1/edge/history/sources response.
// State echoes the state= filter and is absent without one; each source
// carries its own state.
type EdgeHistorySourcesDoc struct {
	Available bool                    `json:"available"`
	Zone      string                  `json:"zone,omitempty"`
	State     string                  `json:"state,omitempty"`
	Sources   []storage.EdgeSourceAgg `json:"sources"`
}

// EdgeEventsDoc is the GET /api/v1/edge/events response.
type EdgeEventsDoc struct {
	Available bool                   `json:"available"`
	Events    []storage.EdgeEventRow `json:"events"`
}

// historyZone resolves the zone parameter under the caller's scope: 400
// without one; for an unscoped caller 404 when the file lacks it; for a
// scoped caller one uniform 403 for anything but its own zones. The name is
// folded like the file folds its own (lower case, trimmed) and like the
// lever folds its path — so a tenant's own `A.example` is its zone, not a
// counted refusal. It returns false after writing the error.
func (s *Server) historyZone(w http.ResponseWriter, r *http.Request) (zone string, ok bool) {
	zone = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("zone")))
	if zone == "" {
		writeError(w, http.StatusBadRequest, "missing zone")
		return "", false
	}
	c := callerFrom(r)
	cfg := s.store.Get()
	if !c.unscoped() {
		if !visibleZone(c, cfg, zone) {
			s.logZoneRefusal(c, zone, "edge_history", r)
			writeError(w, http.StatusForbidden, "zone is outside your tenant")
			return "", false
		}
		return zone, true
	}
	if zoneInFile(cfg, zone) == nil {
		writeError(w, http.StatusNotFound, "unknown zone")
		return "", false
	}
	return zone, true
}

// handleEdgeHistory serves a zone's bucketed windows.
func (s *Server) handleEdgeHistory(w http.ResponseWriter, r *http.Request) {
	if s.querier == nil {
		writeJSON(w, http.StatusOK, EdgeHistoryDoc{Available: false, Points: []storage.EdgeHistoryPoint{}})
		return
	}
	zone, ok := s.historyZone(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	c := callerFrom(r)
	node := q.Get("node")
	if node != "" {
		// Node names are topology: a tenant reads the fleet's sum for its
		// zone, never one node's history.
		if !c.unscoped() {
			writeError(w, http.StatusForbidden, "the node filter is restricted to unscoped tokens")
			return
		}
		if configuredEdgeNode(s.store.Get(), node) == nil {
			writeError(w, http.StatusNotFound, "unknown edge node")
			return
		}
	}
	from, to, errMsg := parseRange(q, time.Now())
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}
	step, errMsg := parseStep(q, from, to)
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), historyQueryTimeout)
	defer cancel()
	pts, err := s.querier.QueryEdgeHistory(ctx, zone, node, from, to, step)
	if err != nil {
		s.log.Warn("edge history query failed", "zone", zone, "node", node, "err", err)
		writeError(w, http.StatusBadGateway, "edge history query failed")
		return
	}
	if pts == nil {
		pts = []storage.EdgeHistoryPoint{}
	}
	writeJSON(w, http.StatusOK, EdgeHistoryDoc{Available: true, Zone: zone, Node: node, StepSeconds: step, Points: pts})
}

// handleEdgeHistorySources serves a zone's telling sources over a range.
func (s *Server) handleEdgeHistorySources(w http.ResponseWriter, r *http.Request) {
	if s.querier == nil {
		writeJSON(w, http.StatusOK, EdgeHistorySourcesDoc{Available: false, Sources: []storage.EdgeSourceAgg{}})
		return
	}
	zone, ok := s.historyZone(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	if state != "" && !tellingState(state) {
		writeError(w, http.StatusBadRequest, "invalid state (denied|challenged|would-deny|would-challenge)")
		return
	}
	from, to, errMsg := parseRange(q, time.Now())
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), historyQueryTimeout)
	defer cancel()
	srcs, err := s.querier.QueryEdgeSources(ctx, storage.EdgeSourceFilter{Zone: zone, State: state, From: from, To: to})
	if err != nil {
		s.log.Warn("edge source history query failed", "zone", zone, "err", err)
		writeError(w, http.StatusBadGateway, "edge history query failed")
		return
	}
	if srcs == nil {
		srcs = []storage.EdgeSourceAgg{}
	}
	writeJSON(w, http.StatusOK, EdgeHistorySourcesDoc{Available: true, Zone: zone, State: state, Sources: srcs})
}

// edgeEventKindList is the closed set of kinds the write path emits
// (edge_history.go) and a kind filter may name — the sixteen api.mdx lists,
// in the order it lists them. The test pins the count against the docs.
var edgeEventKindList = []string{
	EventNodeAlive, EventNodeLost, EventVersion, EventDryRun, EventDocumentRendered,
	EventGenerationInstalled, EventGenerationRefused, EventTerminatorAlive, EventH3State,
	EventCertIssued, EventCertRenewed, EventCertGone, EventChallengeStarted, EventChallengeEnded,
	EventClockSkew, EventReportTruncated,
}

var edgeEventKinds = func() map[string]bool {
	m := make(map[string]bool, len(edgeEventKindList))
	for _, k := range edgeEventKindList {
		m[k] = true
	}
	return m
}()

// handleEdgeEvents serves the transitions, newest first. Unscoped tokens
// only: the events name nodes and the fleet's changes.
func (s *Server) handleEdgeEvents(w http.ResponseWriter, r *http.Request) {
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "the edge events name nodes and are restricted to unscoped tokens")
		return
	}
	if s.querier == nil {
		writeJSON(w, http.StatusOK, EdgeEventsDoc{Available: false, Events: []storage.EdgeEventRow{}})
		return
	}
	q := r.URL.Query()
	f := storage.EdgeEventFilter{Node: q.Get("node"), Zone: q.Get("zone"), Kind: q.Get("kind")}
	if f.Kind != "" && !edgeEventKinds[f.Kind] {
		writeError(w, http.StatusBadRequest, "invalid kind")
		return
	}
	var errMsg string
	f.From, f.To, errMsg = parseRange(q, time.Now())
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), historyQueryTimeout)
	defer cancel()
	evs, err := s.querier.QueryEdgeEvents(ctx, f)
	if err != nil {
		s.log.Warn("edge events query failed", "err", err)
		writeError(w, http.StatusBadGateway, "edge events query failed")
		return
	}
	if evs == nil {
		evs = []storage.EdgeEventRow{}
	}
	writeJSON(w, http.StatusOK, EdgeEventsDoc{Available: true, Events: evs})
}

package api

// The operator's lever on a zone's rung (E4.6, edge-spec §5): POST
// /api/v1/edge/zones/{name}/challenge sets the zone's challenge mode to
// manual or auto for a bounded time, DELETE (or mode "off") clears it. The
// override travels in the zones document as Zone.ChallengeOverride with a
// FIXED until — so the document's bytes and ETag move exactly when an
// operator acts (and once more when the override lapses, when the next
// snapshot drops it) — and every node applies the effective mode on its
// fast path: a policy change, never a reload. In-memory, like the ACME
// coordinator: a lever is an incident's tool, and the brain restarting mid-
// incident is rare enough that re-pulling it is the honest recovery.
//
// The brain's own dry_run does not gate the lever (D12): it is a policy
// edit; whether it BITES is the node's and the zone's watch-only state,
// which the response lists per alive node so the operator sees it.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

const (
	// The override's lifetime bounds, the source-block ones: long enough for
	// an incident, short enough that a forgotten lever ends by itself.
	minLeverTTL    = 60 * time.Second
	maxLeverTTL    = 24 * time.Hour
	maxLeverReason = 200
)

// challengeLever holds the live overrides per zone.
type challengeLever struct {
	mu      sync.Mutex
	byZone  map[string]edgedoc.ChallengeOverride
	changed atomic.Pointer[chan struct{}]
}

func newChallengeLever() *challengeLever {
	return &challengeLever{byZone: make(map[string]edgedoc.ChallengeOverride)}
}

// Changed returns a channel closed on the next set or clear — the
// Store.Changed idiom the zones long-poll selects on.
func (l *challengeLever) Changed() <-chan struct{} {
	for {
		if p := l.changed.Load(); p != nil {
			return *p
		}
		ch := make(chan struct{})
		if l.changed.CompareAndSwap(nil, &ch) {
			return ch
		}
	}
}

func (l *challengeLever) notify() {
	if p := l.changed.Swap(nil); p != nil {
		close(*p)
	}
}

// set installs or replaces the zone's override and wakes the polls.
func (l *challengeLever) set(zone string, o edgedoc.ChallengeOverride) {
	l.mu.Lock()
	l.byZone[zone] = o
	l.mu.Unlock()
	l.notify()
}

// clear removes the zone's override; false when there was none live.
func (l *challengeLever) clear(zone string, now time.Time) bool {
	l.mu.Lock()
	o, ok := l.byZone[zone]
	delete(l.byZone, zone)
	l.mu.Unlock()
	if ok {
		l.notify()
	}
	return ok && now.Before(o.Until)
}

// live returns every override in force at now, by zone.
func (l *challengeLever) live(now time.Time) map[string]edgedoc.ChallengeOverride {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]edgedoc.ChallengeOverride, len(l.byZone))
	for zone, o := range l.byZone {
		if now.Before(o.Until) {
			out[zone] = o
		}
	}
	return out
}

// get returns the zone's live override.
func (l *challengeLever) get(zone string, now time.Time) (edgedoc.ChallengeOverride, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	o, ok := l.byZone[zone]
	if !ok || !now.Before(o.Until) {
		return edgedoc.ChallengeOverride{}, false
	}
	return o, true
}

// fill attaches the live overrides to the document's zones and forgets the
// lapsed ones. Deterministic for a given now and lever state; a lapse changes
// the document exactly once, at the first snapshot after it.
func (l *challengeLever) fill(doc *edgedoc.Doc, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for zone, o := range l.byZone {
		if !now.Before(o.Until) {
			delete(l.byZone, zone)
		}
	}
	if len(l.byZone) == 0 {
		return
	}
	for i := range doc.Zones {
		if o, ok := l.byZone[doc.Zones[i].Name]; ok {
			c := o
			doc.Zones[i].ChallengeOverride = &c
		}
	}
}

// untilNextChange is how long the overrides stay as they are: until the
// earliest lapse, or a day when none is set — what a parked poll must wake
// for, so the document that drops a lapsed override goes out on time.
func (l *challengeLever) untilNextChange(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := now.Add(maxLeverTTL)
	for _, o := range l.byZone {
		if o.Until.Before(next) {
			next = o.Until
		}
	}
	d := next.Sub(now)
	if d < time.Second {
		d = time.Second
	}
	return d
}

// EdgeChallengeLeverRequest is the body of POST /api/v1/edge/zones/{name}/challenge.
type EdgeChallengeLeverRequest struct {
	// Mode is manual, auto or off (off clears the override, like DELETE).
	Mode string `json:"mode"`
	// TTLSeconds is how long the override lasts, 60..86400; required unless
	// Mode is off.
	TTLSeconds int `json:"ttl_seconds"`
	// Reason is for the log, the audit row and the console (200 characters).
	Reason string `json:"reason"`
}

// EdgeChallengeLeverResponse says what is now in force and where it bites.
type EdgeChallengeLeverResponse struct {
	Zone string `json:"zone"`
	// Mode is the override in force, or "" when the zone follows its file.
	Mode   string     `json:"mode,omitempty"`
	Until  *time.Time `json:"until,omitempty"`
	Reason string     `json:"reason,omitempty"`
	// FileMode is policy.challenge as the zones file has it — empty for a zone
	// a reload has since removed from the file (whose lever can be cleared,
	// never set); ZoneWatchOnly and RungWatchOnly are false there too.
	FileMode string `json:"file_mode"`
	// ZoneWatchOnly is the zone's policy.dry_run; RungWatchOnly its
	// challenge_options.dry_run — on either, the lever previews rather than
	// bites, on every node.
	ZoneWatchOnly bool `json:"zone_watch_only"`
	RungWatchOnly bool `json:"rung_watch_only"`
	// Nodes lists every configured edge node with what the brain knows: alive
	// (from its poll) and, from its last report, whether it is in dry-run —
	// a node that only counts must say so, and the operator must see it
	// before trusting the lever.
	Nodes []EdgeLeverNode `json:"nodes"`
}

// EdgeLeverNode is one node's bearing on the lever.
type EdgeLeverNode struct {
	Name  string `json:"name"`
	Alive bool   `json:"alive"`
	// DryRun is the node's reported watch-only flag; nil when it has not
	// reported.
	DryRun *bool `json:"dry_run,omitempty"`
}

// handleEdgeChallengeLever serves POST (set or, with mode off, clear) and
// DELETE (clear). Operator rank by the route; unscoped tokens only, since the
// zones file spans every tenant's zones.
func (s *Server) handleEdgeChallengeLever(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !c.unscoped() {
		writeError(w, http.StatusForbidden, "the challenge lever is restricted to unscoped tokens")
		return
	}
	zone := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	cfg := s.store.Get()
	var fileZone *edgedocZoneView
	if cfg.ZonesCfg != nil {
		for i := range cfg.ZonesCfg.Zones {
			if z := &cfg.ZonesCfg.Zones[i]; z.Name == zone {
				fileZone = &edgedocZoneView{mode: z.Policy.Mode, challenge: z.Policy.Challenge, zoneDry: z.Policy.DryRun, rungDry: z.Policy.ChallengeOptions.DryRun == nil || *z.Policy.ChallengeOptions.DryRun}
				break
			}
		}
	}
	now := time.Now()
	var req EdgeChallengeLeverRequest
	if r.Method != http.MethodDelete {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed body: "+err.Error())
			return
		}
		req.Reason = strings.TrimSpace(req.Reason)
		if utf8.RuneCountInString(req.Reason) > maxLeverReason || strings.ContainsFunc(req.Reason, func(r rune) bool { return unicode.IsControl(r) }) {
			writeError(w, http.StatusBadRequest, "reason must be at most 200 characters without control characters")
			return
		}
	}
	clearing := r.Method == http.MethodDelete || req.Mode == edgedoc.ChallengeOff
	if fileZone == nil {
		// A zone gone from the file (removed or renamed by a reload) may still
		// carry a lever set before that: clearing it needs no file entry, so
		// the operator is never left with a row nothing can retire. Setting
		// one does need the zone.
		if _, live := s.edgeLever.get(zone, now); !clearing || !live {
			writeError(w, http.StatusNotFound, "unknown zone")
			return
		}
		fileZone = &edgedocZoneView{}
	}
	switch r.Method {
	case http.MethodDelete:
		was := s.edgeLever.clear(zone, now)
		s.log.Info("edge challenge override cleared", "zone", zone, "was_live", was, "operator", c.token)
		s.writeAudit(auditRow(c, "edge_challenge", "cleared", zone, "zone", "", "", false))
	default:
		switch req.Mode {
		case edgedoc.ChallengeOff:
			was := s.edgeLever.clear(zone, now)
			s.log.Info("edge challenge override cleared", "zone", zone, "was_live", was, "operator", c.token, "reason", req.Reason)
			s.writeAudit(auditRow(c, "edge_challenge", "cleared", zone, "zone", req.Reason, "", false))
		case edgedoc.ChallengeManual, edgedoc.ChallengeAuto:
			ttl := time.Duration(req.TTLSeconds) * time.Second
			if ttl < minLeverTTL || ttl > maxLeverTTL {
				writeError(w, http.StatusBadRequest, "ttl_seconds must be 60..86400")
				return
			}
			if fileZone.mode != edgedoc.ModeDecide {
				writeError(w, http.StatusConflict, "the zone is not in decide mode; nothing challenges there")
				return
			}
			o := edgedoc.ChallengeOverride{Mode: req.Mode, Until: now.Add(ttl).Truncate(time.Second), Reason: req.Reason}
			s.edgeLever.set(zone, o)
			s.log.Info("edge challenge override set", "zone", zone, "mode", o.Mode, "until", o.Until.UTC().Format(time.RFC3339), "operator", c.token, "reason", o.Reason)
			s.writeAudit(auditRow(c, "edge_challenge", "set", zone, "zone", o.Mode+" until "+o.Until.UTC().Format(time.RFC3339)+"; "+o.Reason, "", false))
		default:
			writeError(w, http.StatusBadRequest, "mode must be manual, auto or off")
			return
		}
	}
	writeJSON(w, http.StatusOK, s.leverResponse(zone, fileZone, now))
}

// edgedocZoneView is what the lever needs to know of the zones file's entry.
type edgedocZoneView struct {
	mode, challenge  string
	zoneDry, rungDry bool
}

// leverResponse describes the zone's rung as it now stands and every node's
// bearing on it.
func (s *Server) leverResponse(zone string, fz *edgedocZoneView, now time.Time) EdgeChallengeLeverResponse {
	resp := EdgeChallengeLeverResponse{Zone: zone, FileMode: fz.challenge, ZoneWatchOnly: fz.zoneDry, RungWatchOnly: fz.rungDry, Nodes: []EdgeLeverNode{}}
	if o, ok := s.edgeLever.get(zone, now); ok {
		u := o.Until
		resp.Mode, resp.Until, resp.Reason = o.Mode, &u, o.Reason
	}
	cfg := s.store.Get()
	if cfg.Edge != nil {
		staleAfter := edgeStaleAfter(cfg)
		for i := range cfg.Edge.Nodes {
			name := cfg.Edge.Nodes[i].Name
			n := EdgeLeverNode{Name: name, Alive: s.edgePresence.alive(name, staleAfter)}
			if rep, _, ok := s.edgeReports.get(name); ok {
				dry := rep.DryRun
				n.DryRun = &dry
			}
			resp.Nodes = append(resp.Nodes, n)
		}
		sort.Slice(resp.Nodes, func(i, j int) bool { return resp.Nodes[i].Name < resp.Nodes[j].Name })
	}
	return resp
}

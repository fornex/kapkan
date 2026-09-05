package rollup

import (
	"net/netip"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// Sink is where the rules' verdicts go: the decision service implements it.
type Sink interface {
	Deny(zone string, src netip.Addr, ttl time.Duration, reason string) bool
	Mark(zone string, src netip.Addr, mark string, ttl time.Duration) bool
	// Denied reports whether src is already under a live deny in zone — such
	// a source's 403s are the table's own work, not new evidence.
	Denied(zone string, src netip.Addr) bool
	// Challenge installs a challenge verdict: src must clear the rung on its
	// next request (E4.4, the rung between the ceiling and the block).
	Challenge(zone string, src netip.Addr, ttl time.Duration, reason string) bool
	// Challenged reports whether src is under a live challenge verdict — a
	// source that keeps flooding through one has failed the rung.
	Challenged(zone string, src netip.Addr) bool
	// SetZoneChallenge flips the zone-wide challenge (every source of an auto
	// zone) on until `until`, or off.
	SetZoneChallenge(zone string, on bool, until time.Time, reason string) bool
}

// ZoneRule is what the rules need to know about one zone's rung: whether it
// is automatic, and the zone-wide trigger.
type ZoneRule struct {
	// Auto is policy.challenge: auto — the flood rule challenges before it
	// denies, and the zone-wide trigger below applies.
	Auto bool
	// ZoneRPS is the zone-wide rate (this node's window) at which every
	// source is challenged; 0 = no zone-wide trigger.
	ZoneRPS float64
	// Hold is how long the zone-wide challenge stays on after a window that
	// tripped it.
	Hold time.Duration
}

// ZoneRulesFromDoc reads the per-zone rung settings the rules act on.
func ZoneRulesFromDoc(doc *edgedoc.Doc) map[string]ZoneRule {
	out := make(map[string]ZoneRule, len(doc.Zones))
	for _, z := range doc.Zones {
		if z.Policy.Mode != edgedoc.ModeDecide {
			continue
		}
		out[z.Name] = ZoneRule{
			Auto:    z.Policy.Challenge == edgedoc.ChallengeAuto,
			ZoneRPS: float64(z.Policy.AutoZoneRPS()),
			Hold:    z.Policy.AutoHold(),
		}
	}
	return out
}

// Rules are the node-local thresholds that turn a window into verdicts
// (edge-spec §5: "local policy thresholds produce local verdicts; sources that
// stay hostile get promoted"). Two rules in E3.3, both about what the
// decision service already saw of the source, and the rung's ladder in E4.4:
//
//   - flood: a source that ran over its ceiling (a rate or concurrency
//     denial — or, in dry-run, a would-deny for one) at least FloodMinDenied
//     times in the window, and for at least FloodDeniedShare of its DECIDED
//     requests, is not a client that had a busy second — it is pushing
//     through its ceiling for the whole window (at twice the ceiling the
//     bucket refuses about 45 % once its burst is spent). In a zone whose
//     rung is AUTO it is first CHALLENGED for ChallengeTTL (edge-spec §5: the
//     rung between the ceiling and the block; D9) — a browser clears and is
//     rate-limited like anyone, a bot cannot; a source that floods on while
//     challenged, or that had already cleared the rung and floods anyway, is
//     DENIED. In any other zone, and for those, it is denied outright for
//     DenyTTL, doubling on every repeat up to MaxDenyTTL, so the per-request
//     bucket stops being consulted for it (and the XDP plane can take over,
//     E4.10). A source the table already denies is skipped: its 403s are the
//     deny at work, and re-promoting on them would escalate a one-time
//     offence into a never-expiring ban. A repeat therefore means a flood
//     AFTER the previous deny expired.
//   - zone-wide (auto zones with challenge_options.auto.zone_rps): when the
//     whole zone runs at or over that rate on this node — a flood spread over
//     so many sources that none trips its own ceiling — every source is
//     challenged for the hold; each window still over the rate extends it.
//     Node-local by design: per-request decisions are local, and the
//     fleet-wide view is the brain's (E6).
//   - errors: a source with at least ErrorMinRequests requests of which
//     ErrorShare or more were 4xx/5xx from the origin (the decider's own
//     answers excluded) is MARKED "errors" for MarkTTL — a scanner or a broken
//     client, for the origin to judge; never denied by this rule. The rule
//     stands down when the zone as a whole is erroring at that share: that is
//     an origin or decider outage, not a source.
//
// Dry-run is not the rules' business: a challenge or a deny the decision
// service is not allowed to enforce becomes a would-challenge / would-deny
// mark there, so the ladder previews itself unchanged.
//
// Rules run over EVERY source of the window (OnWindowFull), not the report's
// top-N. The thresholds are fixed here for E3.3; the per-zone rung settings
// come from the document (SetZones). Zero fields take the defaults.
type Rules struct {
	FloodMinDenied   uint64
	FloodDeniedShare float64
	DenyTTL          time.Duration
	MaxDenyTTL       time.Duration
	ErrorMinRequests uint64
	ErrorShare       float64
	MarkTTL          time.Duration
	// ChallengeTTL is how long a flooding source in an auto zone is
	// challenged before its next flood is a deny.
	ChallengeTTL time.Duration
	// MaxRepeats bounds the escalation memory (per (zone, source)).
	MaxRepeats int
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	repeats map[repeatKey]*repeat
	zones   map[string]ZoneRule
}

// SetZones replaces the per-zone rung settings (from the document, on every
// new one). A zone the map does not name is treated as not automatic.
func (r *Rules) SetZones(zones map[string]ZoneRule) {
	r.mu.Lock()
	r.zones = zones
	r.mu.Unlock()
}

type repeatKey struct {
	zone string
	src  netip.Addr
}

type repeat struct {
	n    int
	last time.Time
}

// Defaults.
const (
	DefaultFloodMinDenied   = 20
	DefaultFloodDeniedShare = 0.3
	DefaultDenyTTL          = time.Minute
	DefaultMaxDenyTTL       = 10 * time.Minute
	DefaultErrorMinRequests = 50
	DefaultErrorShare       = 0.9
	DefaultMarkTTL          = time.Minute
	DefaultChallengeTTL     = 5 * time.Minute
	DefaultMaxRepeats       = 64 << 10
	// repeatMemory is how long an escalation level is remembered after the
	// source's last promotion.
	repeatMemory = time.Hour
)

func (r *Rules) defaults() {
	if r.FloodMinDenied == 0 {
		r.FloodMinDenied = DefaultFloodMinDenied
	}
	if r.FloodDeniedShare == 0 {
		r.FloodDeniedShare = DefaultFloodDeniedShare
	}
	if r.DenyTTL == 0 {
		r.DenyTTL = DefaultDenyTTL
	}
	if r.MaxDenyTTL == 0 {
		r.MaxDenyTTL = DefaultMaxDenyTTL
	}
	if r.ErrorMinRequests == 0 {
		r.ErrorMinRequests = DefaultErrorMinRequests
	}
	if r.ErrorShare == 0 {
		r.ErrorShare = DefaultErrorShare
	}
	if r.MarkTTL == 0 {
		r.MarkTTL = DefaultMarkTTL
	}
	if r.ChallengeTTL == 0 {
		r.ChallengeTTL = DefaultChallengeTTL
	}
	if r.MaxRepeats == 0 {
		r.MaxRepeats = DefaultMaxRepeats
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.repeats == nil {
		r.repeats = make(map[repeatKey]*repeat)
	}
}

// Applied is what one window produced, for logs and the report.
type Applied struct {
	Denied int
	Marked int
	// Challenged counts sources sent to the rung by the flood rule.
	Challenged int
	// Skipped counts sources the table already denied.
	Skipped int
	// ZoneChallenge is true when the zone-wide trigger fired (or was extended)
	// for this window.
	ZoneChallenge bool
}

// Apply evaluates one closed window (with every source) and installs its
// verdicts in sink.
func (r *Rules) Apply(w WindowStats, sink Sink) Applied {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaults()
	now := r.Now()
	zr := r.zones[w.Zone]
	// Forget stale escalation first, so a source quiet for repeatMemory starts
	// again at the base TTL rather than at its old level.
	r.forget(now)
	var out Applied
	// The zone-wide trigger: the whole zone over its rate on this node.
	if zr.Auto && zr.ZoneRPS > 0 && w.RPS >= zr.ZoneRPS {
		if sink.SetZoneChallenge(w.Zone, true, now.Add(zr.Hold), "zone-rps") {
			out.ZoneChallenge = true
		}
	}
	// Origin-side errors across the zone: when the zone itself is failing at
	// the error share, no source is to blame. The decider's own answers — a
	// denial's 403/429, a challenge page's status — are not the origin's.
	zoneErrors := int64(w.Status4xx+w.Status5xx) - int64(w.Denied+w.Challenged)
	if zoneErrors < 0 {
		zoneErrors = 0
	}
	zoneErroring := w.Requests >= r.ErrorMinRequests && float64(zoneErrors)/float64(w.Requests) >= r.ErrorShare
	for _, s := range w.Sources {
		if s.Requests == 0 {
			continue
		}
		if sink.Denied(w.Zone, s.Src) {
			out.Skipped++
			continue
		}
		over := s.DeniedRate + s.WouldDenyRate
		if over >= r.FloodMinDenied && s.Decided > 0 && float64(over)/float64(s.Decided) >= r.FloodDeniedShare {
			// The ladder (D9): in an auto zone a first flood earns a challenge;
			// a source that floods on while challenged, or that had cleared
			// the rung and floods anyway (a browser or a solver farm — either
			// way not a client the rung can sort out), is denied.
			if zr.Auto && s.Cleared == 0 && !sink.Challenged(w.Zone, s.Src) {
				if sink.Challenge(w.Zone, s.Src, r.ChallengeTTL, "flood") {
					out.Challenged++
				}
				continue
			}
			ttl := r.escalate(repeatKey{zone: w.Zone, src: s.Src}, now)
			if sink.Deny(w.Zone, s.Src, ttl, "flood") {
				out.Denied++
			}
			continue
		}
		if zoneErroring {
			continue
		}
		errs := s.Errors4xx + s.Errors5xx
		if s.Requests >= r.ErrorMinRequests && float64(errs)/float64(s.Requests) >= r.ErrorShare {
			if sink.Mark(w.Zone, s.Src, "errors", r.MarkTTL) {
				out.Marked++
			}
		}
	}
	return out
}

// escalate returns the deny TTL for this promotion: DenyTTL doubled per
// remembered repeat, capped at MaxDenyTTL.
func (r *Rules) escalate(k repeatKey, now time.Time) time.Duration {
	rep := r.repeats[k]
	if rep == nil {
		if len(r.repeats) >= r.MaxRepeats {
			return r.DenyTTL
		}
		rep = &repeat{}
		r.repeats[k] = rep
	}
	ttl := r.DenyTTL
	for i := 0; i < rep.n && ttl < r.MaxDenyTTL; i++ {
		ttl *= 2
	}
	if ttl > r.MaxDenyTTL {
		ttl = r.MaxDenyTTL
	}
	rep.n++
	rep.last = now
	return ttl
}

// forget drops escalation memory older than repeatMemory.
func (r *Rules) forget(now time.Time) {
	for k, rep := range r.repeats {
		if now.Sub(rep.last) > repeatMemory {
			delete(r.repeats, k)
		}
	}
}

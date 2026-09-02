package rollup

import (
	"net/netip"
	"sync"
	"time"
)

// Sink is where the rules' verdicts go: the decision service implements it.
type Sink interface {
	Deny(zone string, src netip.Addr, ttl time.Duration, reason string) bool
	Mark(zone string, src netip.Addr, mark string, ttl time.Duration) bool
}

// Rules are the node-local thresholds that turn a window into verdicts
// (edge-spec §5: "local policy thresholds produce local verdicts; sources that
// stay hostile get promoted"). Two rules in E3.3, both relative to what the
// decision service already did to the source:
//
//   - flood: a source that was DENIED at least FloodMinDenied times in the
//     window, and whose denials were at least FloodDeniedShare of its
//     requests, is not a client that had a busy second — it is pushing
//     through its rate ceiling for the whole window (at twice the ceiling
//     the bucket refuses about 45 % once its burst is spent). It is denied
//     outright for
//     DenyTTL, doubling on every repeat up to MaxDenyTTL, so the per-request
//     bucket stops being consulted for it (and, in E4, the XDP plane can
//     take over).
//   - errors: a source with at least ErrorMinRequests requests of which
//     ErrorShare or more were 4xx/5xx from the origin (the decider's own 403s
//     excluded) is MARKED "errors" for MarkTTL — a scanner or a broken
//     client, for the origin to judge; never denied by this rule.
//
// The thresholds are fixed here for E3.3; the zones schema wave (E3.6) makes
// them per-zone knobs. Zero fields take the defaults.
type Rules struct {
	FloodMinDenied   uint64
	FloodDeniedShare float64
	DenyTTL          time.Duration
	MaxDenyTTL       time.Duration
	ErrorMinRequests uint64
	ErrorShare       float64
	MarkTTL          time.Duration
	// MaxRepeats bounds the escalation memory (per (zone, source)).
	MaxRepeats int
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu      sync.Mutex
	repeats map[repeatKey]*repeat
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
}

// Apply evaluates one closed window and installs its verdicts in sink.
func (r *Rules) Apply(w WindowStats, sink Sink) Applied {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaults()
	now := r.Now()
	// Forget stale escalation first, so a source quiet for repeatMemory starts
	// again at the base TTL rather than at its old level.
	r.forget(now)
	var out Applied
	for _, s := range w.Sources {
		if s.Requests == 0 {
			continue
		}
		if s.Denied >= r.FloodMinDenied && float64(s.Denied)/float64(s.Requests) >= r.FloodDeniedShare {
			ttl := r.escalate(repeatKey{zone: w.Zone, src: s.Src}, now)
			if sink.Deny(w.Zone, s.Src, ttl, "flood") {
				out.Denied++
			}
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

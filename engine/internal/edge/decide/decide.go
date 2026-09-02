// Package decide is the per-node decision service of the edge (edge-spec §5,
// milestone E3.3): the thing nginx's auth_request asks, once per request in a
// decide-mode zone, over a unix socket.
//
// THE CONTRACT is what the renderer emits (internal/edge/render): GET /decide
// with X-Kapkan-Zone (the zone name, literal in the rendered config — trusted),
// X-Kapkan-Client (the remote address), X-Kapkan-Method / -URI / -User-Agent
// and the original Host; never a body. The answer is 200 (allow, optionally an
// X-Kapkan-Mark header the origin receives) or 403 (deny) — nothing else, ever:
// auth_request would turn anything else into a failed decision, which the
// zone's failure_mode then handles in nginx. Denial as 429 is a renderer
// mapping for a later milestone.
//
// WHAT IT ENFORCES. First, the zone's policy.rate — the per-source ceiling
// edge-spec §2.2 assigns to the decision service so that tightening it under
// attack is never a terminator reload: a token bucket per (zone, source)
// refilling at rps with one second of burst, and an approximate in-flight
// count per (zone, source) for concurrency (every decision opens one request,
// every access-log line for a decided request closes one; see Complete).
// Second, a verdict table: deny or mark entries with a TTL, per zone or for
// all zones, fed by the rollup rules (a source that keeps flooding through its
// denials, internal/edge/rollup) and, later, by policy the brain ships. In
// dry-run every deny is answered as an allow carrying X-Kapkan-Mark
// "would-deny:<reason>", and counted as such: the edge analog of the data
// plane's watch-only mode, so an operator sees exactly what would have been
// refused before turning enforcement on.
//
// WHAT IT NEVER DOES. It never asks the brain anything — a node keeps deciding
// with the brain gone (edge-spec §2.4, C6) — and it never reads request
// content (§7: no WAF): a verdict is a function of zone, source, rate and
// reputation only. When its own tables are full it passes rather than guesses
// (default-PASS), and counts that it did.
//
// Every table is bounded (MaxSources per table) and swept: an entry untouched
// for idleAfter is dropped, so a rotating attacker occupies memory once, not
// forever, and a rate change or a zones change never needs a restart — SetZones
// replaces the policies in place.
package decide

import (
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// DefaultMaxSources bounds each per-(zone, source) table: the rate buckets,
	// the in-flight counters and the verdict table. 64Ki entries is the
	// exporter's figure for the same reason (an IPv6 /64 rotates addresses).
	DefaultMaxSources = 64 << 10

	// idleAfter is how long an untouched bucket or in-flight counter lives;
	// also the bound on how far an in-flight count can drift.
	idleAfter = 60 * time.Second

	// sweepEvery bounds how often the tables are walked.
	sweepEvery = 10 * time.Second

	// MaxMarkLen bounds a mark; marks travel to origins as a header value.
	MaxMarkLen = 64
)

// Reasons a verdict carries. Stable words: they are metric labels and the
// dry-run mark's suffix.
const (
	ReasonAllow       = "allow"
	ReasonRate        = "rate"
	ReasonConcurrency = "concurrency"
	ReasonTable       = "table"
	ReasonUnknownZone = "unknown-zone"
	ReasonModeNone    = "mode-none"
	ReasonUntracked   = "untracked"
)

// Verdict is one decision.
type Verdict struct {
	// Allow is the answer: 200 or 403.
	Allow bool
	// Mark is the X-Kapkan-Mark the origin receives ("" for none).
	Mark string
	// Reason says what decided it (a Reason* constant, or "table:<reason>").
	Reason string
	// DryRun is true when a deny was answered as an allow because the service
	// is in dry-run; Reason still names the deny.
	DryRun bool
}

// Options configures a Service.
type Options struct {
	// DryRun answers every deny as an allow marked would-deny.
	DryRun bool
	// MaxSources bounds each table; 0 means DefaultMaxSources.
	MaxSources int
	Logger     *slog.Logger
	// Now is the clock; nil means time.Now. Tests inject one.
	Now func() time.Time
}

type key struct {
	zone string
	src  netip.Addr
}

type bucket struct {
	tokens float64
	last   time.Time
}

type inflight struct {
	n    int64
	last time.Time
}

// Service decides. Safe for concurrent use.
type Service struct {
	mu        sync.Mutex
	zones     map[string]edgedoc.Policy
	buckets   map[key]*bucket
	inflight  map[key]*inflight
	table     *table
	max       int
	dryRun    bool
	now       func() time.Time
	log       *slog.Logger
	lastSweep time.Time
}

// New returns a Service with no zones: every request is answered allow with
// ReasonUnknownZone until SetZones runs.
func New(opts Options) *Service {
	if opts.MaxSources <= 0 {
		opts.MaxSources = DefaultMaxSources
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Service{
		zones:    map[string]edgedoc.Policy{},
		buckets:  make(map[key]*bucket),
		inflight: make(map[key]*inflight),
		table:    newTable(opts.MaxSources),
		max:      opts.MaxSources,
		dryRun:   opts.DryRun,
		now:      opts.Now,
		log:      opts.Logger.With("component", "edge-decide"),
	}
}

// SetZones replaces the per-zone policies with the document's. Buckets and
// counters of zones no longer present are dropped by the next sweep; a
// changed rate takes effect on the next decision — no restart, no reload.
func (s *Service) SetZones(doc *edgedoc.Doc) {
	zones := make(map[string]edgedoc.Policy, len(doc.Zones))
	for _, z := range doc.Zones {
		zones[z.Name] = z.Policy
	}
	s.mu.Lock()
	s.zones = zones
	s.mu.Unlock()
}

// SetDryRun switches watch-only mode.
func (s *Service) SetDryRun(on bool) {
	s.mu.Lock()
	s.dryRun = on
	s.mu.Unlock()
}

// Decide answers one request from src in zone.
func (s *Service) Decide(zone string, src netip.Addr) Verdict {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeSweep(now)

	pol, ok := s.zones[zone]
	if !ok {
		metrics.EdgeDecisionsTotal.WithLabelValues("unknown", "unknown_zone").Inc()
		return Verdict{Allow: true, Reason: ReasonUnknownZone}
	}
	if pol.Mode != edgedoc.ModeDecide {
		metrics.EdgeDecisionsTotal.WithLabelValues(zone, "allow").Inc()
		return Verdict{Allow: true, Reason: ReasonModeNone}
	}

	k := key{zone: zone, src: src}
	v := Verdict{Allow: true, Reason: ReasonAllow}
	result := "allow"
	if e := s.table.lookup(k, now); e != nil {
		if e.deny {
			v = Verdict{Reason: ReasonTable + ":" + e.reason}
			result = "deny_table"
		} else {
			v.Mark = e.mark
			result = "allow_marked"
		}
	}
	if v.Allow && pol.Rate.RPS > 0 {
		switch s.take(k, pol.Rate.RPS, now) {
		case takeDenied:
			v = Verdict{Reason: ReasonRate}
			result = "deny_rate"
		case takeUntracked:
			v = Verdict{Allow: true, Reason: ReasonUntracked}
			result = "untracked"
		}
	}
	if v.Allow && pol.Rate.Concurrency > 0 {
		if f := s.inflight[k]; f != nil && f.n >= int64(pol.Rate.Concurrency) {
			v = Verdict{Reason: ReasonConcurrency}
			result = "deny_concurrency"
		}
	}
	// Every decision — allow or deny — becomes one request nginx will log, and
	// that log line is what closes it (Complete).
	s.open(k, now)

	if !v.Allow && s.dryRun {
		v.DryRun = true
		v.Allow = true
		v.Mark = "would-deny:" + v.Reason
		result = "would_deny"
	}
	metrics.EdgeDecisionsTotal.WithLabelValues(zone, result).Inc()
	return v
}

// Complete records that a decided request for (zone, src) was logged by the
// terminator, closing one in-flight slot. The rollup calls it for every
// access-log line whose decision field says the decider answered (200 or
// 403); undecided requests never opened a slot.
func (s *Service) Complete(zone string, src netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.inflight[key{zone: zone, src: src}]; f != nil && f.n > 0 {
		f.n--
		f.last = s.now()
	}
}

// Deny installs a deny verdict for src in zone ("" = every zone) until ttl
// passes. reason is a stable word for metrics and the report.
func (s *Service) Deny(zone string, src netip.Addr, ttl time.Duration, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := s.table.set(key{zone: zone, src: src}, entry{deny: true, reason: sanitizeMark(reason), until: s.now().Add(ttl)}, s.now())
	if ok {
		s.log.Info("deny installed", "zone", zone, "src", src.String(), "ttl", ttl.String(), "reason", reason)
	} else {
		s.log.Warn("verdict table full; deny not installed", "zone", zone, "src", src.String(), "reason", reason)
	}
	return ok
}

// Mark installs a mark for src in zone ("" = every zone) until ttl passes;
// the origin receives it as X-Kapkan-Mark. Marks are sanitised to header-safe
// characters and MaxMarkLen bytes.
func (s *Service) Mark(zone string, src netip.Addr, mark string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.table.set(key{zone: zone, src: src}, entry{mark: sanitizeMark(mark), until: s.now().Add(ttl)}, s.now())
}

// Clear removes any verdict for src in zone.
func (s *Service) Clear(zone string, src netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table.clear(key{zone: zone, src: src})
}

// Stats is a snapshot for the node's report.
type Stats struct {
	Zones        int
	Sources      int
	Inflight     int
	TableEntries int
	DryRun       bool
}

// Stats reports table sizes.
func (s *Service) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Zones: len(s.zones), Sources: len(s.buckets), Inflight: len(s.inflight), TableEntries: s.table.len(), DryRun: s.dryRun}
}

type takeResult int

const (
	takeAllowed takeResult = iota
	takeDenied
	takeUntracked
)

// take spends one token from (zone, src)'s bucket, creating it full. A bucket
// that cannot be created because the table is full means the request passes
// untracked — the service does not guess.
func (s *Service) take(k key, rps uint64, now time.Time) takeResult {
	cap := float64(rps)
	b := s.buckets[k]
	if b == nil {
		if len(s.buckets) >= s.max {
			s.sweep(now)
			if len(s.buckets) >= s.max {
				return takeUntracked
			}
		}
		b = &bucket{tokens: cap, last: now}
		s.buckets[k] = b
	} else if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * cap
		if b.tokens > cap {
			b.tokens = cap
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return takeAllowed
	}
	return takeDenied
}

// open counts one in-flight request for (zone, src). When the table is full
// the request is simply not tracked for concurrency.
func (s *Service) open(k key, now time.Time) {
	f := s.inflight[k]
	if f == nil {
		if len(s.inflight) >= s.max {
			return
		}
		f = &inflight{}
		s.inflight[k] = f
	}
	f.n++
	f.last = now
}

func (s *Service) maybeSweep(now time.Time) {
	if now.Sub(s.lastSweep) >= sweepEvery {
		s.sweep(now)
	}
}

// sweep drops idle buckets and counters, expired verdicts, and everything
// belonging to a zone that is no longer configured.
func (s *Service) sweep(now time.Time) {
	s.lastSweep = now
	for k, b := range s.buckets {
		if _, ok := s.zones[k.zone]; !ok || now.Sub(b.last) > idleAfter {
			delete(s.buckets, k)
		}
	}
	for k, f := range s.inflight {
		if _, ok := s.zones[k.zone]; !ok || now.Sub(f.last) > idleAfter {
			delete(s.inflight, k)
		}
	}
	s.table.sweep(now)
}

// sanitizeMark keeps a mark header-safe: printable ASCII without separators
// or spaces, at most MaxMarkLen bytes.
func sanitizeMark(m string) string {
	var b strings.Builder
	for _, r := range m {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == ':', r == '/':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= MaxMarkLen {
			break
		}
	}
	return b.String()
}

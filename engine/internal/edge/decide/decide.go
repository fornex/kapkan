// Package decide is the per-node decision service of the edge (edge-spec §5,
// milestone E3.3): the thing nginx's auth_request asks, once per request in a
// decide-mode zone, over a unix socket.
//
// THE CONTRACT is what the renderer emits (internal/edge/render): GET /decide
// with X-Kapkan-Zone (the zone name, literal in the rendered config — trusted),
// X-Kapkan-Client (the remote address), X-Kapkan-Method / -URI and the
// original Host; the client's own headers are NOT forwarded
// (proxy_pass_request_headers off), so nothing a client sends can push the
// subrequest off the contract. The answer is 200 (allow, optionally an
// X-Kapkan-Mark header the origin receives) or 403 (deny) with X-Kapkan-Reason
// naming why — rate, concurrency, or table:<reason>. Nothing else, ever:
// auth_request would turn anything else into a failed decision, which the
// zone's failure_mode then handles in nginx. The renderer maps a rate or
// concurrency denial to 429 (+ Retry-After) and keeps 403 for a table denial,
// and logs the reason, so the rollup can tell a client that ran over its
// ceiling from one already denied.
//
// WHAT IT ENFORCES. First, the zone's policy.rate — the per-source ceiling
// edge-spec §2.2 assigns to the decision service so that tightening it under
// attack is never a terminator reload: a token bucket per (zone, source)
// refilling at rps with one second of burst, and an approximate in-flight
// count per (zone, source) for concurrency (every decision opens one, every
// access-log line for a decided request closes one; see Complete). Second, a
// verdict table: deny or mark entries with a TTL, per zone or for all zones,
// fed by the rollup rules (a source that keeps flooding through its denials,
// internal/edge/rollup) and, later, by policy the brain ships. In dry-run
// every deny is answered as an allow carrying X-Kapkan-Mark
// "would-deny:<reason>" (and the reason header), and counted as such: the edge
// analog of the data plane's watch-only mode, so an operator sees exactly what
// would have been refused before turning enforcement on.
//
// A SOURCE IS A KEY, NOT AN ADDRESS: edgedoc.SourceKey — an IPv4 address, or
// an IPv6 /64. Every table here and in the rollup is keyed by it, so an IPv6
// client cannot buy a fresh bucket per address, and a verdict the rollup asks
// for lands on the bucket the decider consults.
//
// WHAT IT NEVER DOES. It never asks the brain anything — a node keeps deciding
// with the brain gone (edge-spec §2.4, C6) — and it never reads request
// content (§7: no WAF): a verdict is a function of zone, source, rate and
// reputation only. When its tables are full it passes rather than guesses
// (default-PASS), counts that it did, and does NOT stop to make room: the
// on-full sweep is paced (fullSweepEvery), because a rotating attacker who
// could make every fresh request walk the tables would take the decider —
// and with it every zone on the node — out with a few thousand addresses.
//
// Every table is bounded — MaxSources for the node, and a per-zone quota of
// it, so one zone's flood cannot switch off rate limiting for another's
// clients — and swept: an entry untouched for idleAfter is dropped.
//
// CONCURRENCY IS APPROXIMATE, AND SAYS SO. An in-flight slot is the time a
// decision was made; a completion closes the newest (the count is the same
// whichever it was); a slot older than inflightMaxAge is treated as closed
// whether or not its log line arrived — so a lost datagram is a phantom slot
// for half a minute, not forever, and a request that runs longer is
// undercounted, which errs toward passing. A key
// that keeps opening slots but has seen no completion at all for idleAfter
// has a dead log stream: its concurrency ceiling is not enforced (default-
// PASS) until a completion arrives again, and the event is counted
// (kapkan_edge_inflight_resets_total). A rate change or a zones change never
// needs a restart — SetZones replaces the policies in place.
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
	// DefaultMaxSources bounds each per-(zone, source) table across the node:
	// the rate buckets, the in-flight counters and the verdict table. 64Ki
	// entries is the exporter's figure for the same reason (a /64 rotates).
	DefaultMaxSources = 64 << 10

	// minZoneQuota is the least share of MaxSources any one zone may use for
	// its buckets, however many zones the node has.
	minZoneQuota = 1024

	// idleAfter is how long an untouched bucket or in-flight counter lives,
	// and how long a busy source may go without a completion before its log
	// stream is considered dead and its concurrency ceiling suspended.
	idleAfter = 60 * time.Second

	// inflightMaxAge is how long an in-flight slot may stay open without a
	// completion before it counts as closed: the lifetime of a phantom slot
	// left by a lost log datagram. Requests that genuinely run longer are
	// undercounted from then on, which errs toward passing.
	inflightMaxAge = 30 * time.Second

	// maxInflightTracked bounds one key's slot ring; beyond it opens are not
	// recorded (the ceiling that matters is far below).
	maxInflightTracked = 4096

	// sweepEvery bounds how often the periodic sweep walks the tables;
	// fullSweepEvery how often a full table may trigger one on a miss.
	sweepEvery     = 10 * time.Second
	fullSweepEvery = time.Second

	// MaxMarkLen bounds a mark; marks travel to origins as a header value.
	MaxMarkLen = 64
)

// Reasons a verdict carries. Stable words: they are metric labels, the
// X-Kapkan-Reason header, and the dry-run mark's suffix.
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
	// Mark is the X-Kapkan-Mark the origin receives ("" for none). In dry-run
	// a would-deny mark replaces any reputation mark for that request.
	Mark string
	// Reason says what decided it (a Reason* constant, or "table:<reason>").
	Reason string
	// DryRun is true when a deny was answered as an allow because the service
	// is in dry-run; Reason still names the deny.
	DryRun bool
}

// Denied reports whether the verdict is a denial (enforced or dry-run).
func (v Verdict) Denied() bool {
	return !v.Allow || v.DryRun
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
	// opens are the open slots' decision times, oldest first.
	opens    []time.Time
	lastOpen time.Time
	// lastClose is the last completion (or the creation): the baseline for
	// declaring the stream dead.
	lastClose time.Time
	// dead: no completion for idleAfter while slots kept opening; the
	// ceiling is suspended until one arrives.
	dead bool
}

// count is the number of slots open now, phantoms older than inflightMaxAge
// aged out.
func (f *inflight) count(now time.Time) int {
	cut := now.Add(-inflightMaxAge)
	i := 0
	for i < len(f.opens) && f.opens[i].Before(cut) {
		i++
	}
	if i > 0 {
		f.opens = append(f.opens[:0], f.opens[i:]...)
	}
	return len(f.opens)
}

// Service decides. Safe for concurrent use.
type Service struct {
	mu        sync.Mutex
	zones     map[string]edgedoc.Policy
	buckets   map[key]*bucket
	perZone   map[string]int
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
		perZone:  make(map[string]int),
		inflight: make(map[key]*inflight),
		table:    newTable(opts.MaxSources),
		max:      opts.MaxSources,
		dryRun:   opts.DryRun,
		now:      opts.Now,
		log:      opts.Logger.With("component", "edge-decide"),
	}
}

// SetZones replaces the per-zone policies with the document's. Tables of
// zones no longer present are dropped by the next sweep; a changed rate takes
// effect on the next decision — no restart, no reload.
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
	k := key{zone: zone, src: edgedoc.SourceKey(src)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeSweep(now)

	pol, ok := s.zones[zone]
	if !ok {
		metrics.EdgeDecisionsTotal.WithLabelValues("unknown", "unknown_zone").Inc()
		return Verdict{Allow: true, Reason: ReasonUnknownZone}
	}
	if pol.Mode != edgedoc.ModeDecide {
		metrics.EdgeDecisionsTotal.WithLabelValues(zone, "mode_none").Inc()
		return Verdict{Allow: true, Reason: ReasonModeNone}
	}

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
			// Passing untracked keeps the reputation mark: the table was
			// consulted, only the bucket could not be.
			v.Reason = ReasonUntracked
			result = "untracked"
		}
	}
	if v.Allow && pol.Rate.Concurrency > 0 {
		if f := s.inflight[k]; f != nil && !f.dead && f.count(now) >= int(pol.Rate.Concurrency) {
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
		v.Mark = clipMark("would-deny:" + v.Reason)
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
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.inflight[key{zone: zone, src: edgedoc.SourceKey(src)}]; f != nil {
		// Close the NEWEST slot: whichever request this line was for, the count
		// is the same, and what is left to age out is then the oldest — the
		// phantoms of lost lines and the genuinely long-running.
		if n := len(f.opens); n > 0 {
			f.opens = f.opens[:n-1]
		}
		f.lastClose = now
		f.dead = false
	}
}

// Deny installs a deny verdict for src in zone ("" = every zone) until ttl
// passes. reason is a stable word for metrics, the reason header and the
// report. A deny outranks any mark for the same source.
func (s *Service) Deny(zone string, src netip.Addr, ttl time.Duration, reason string) bool {
	now := s.now()
	k := key{zone: zone, src: edgedoc.SourceKey(src)}
	s.mu.Lock()
	ok := s.table.setDeny(k, sanitizeMark(reason), now.Add(ttl), now)
	s.mu.Unlock()
	// Logging outside the lock: a stalled stderr must not stall decisions.
	if ok {
		s.log.Info("deny installed", "zone", zone, "src", k.src.String(), "ttl", ttl.String(), "reason", reason)
	} else {
		s.log.Warn("verdict table full; deny not installed", "zone", zone, "src", k.src.String(), "reason", reason)
	}
	return ok
}

// Denied reports whether src is under a live deny in zone (the every-zone
// wildcard included). The rollup asks before counting a source's 403s as
// evidence of a new flood.
func (s *Service) Denied(zone string, src netip.Addr) bool {
	now := s.now()
	k := key{zone: zone, src: edgedoc.SourceKey(src)}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.table.lookup(k, now)
	return e != nil && e.deny
}

// Mark installs a mark for src in zone ("" = every zone) until ttl passes;
// the origin receives it as X-Kapkan-Mark. Marks are sanitised to header-safe
// characters and MaxMarkLen bytes. A mark never displaces a live deny.
func (s *Service) Mark(zone string, src netip.Addr, mark string, ttl time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.table.setMark(key{zone: zone, src: edgedoc.SourceKey(src)}, sanitizeMark(mark), now.Add(ttl), now)
}

// Clear removes any verdict (deny and mark) for src in zone.
func (s *Service) Clear(zone string, src netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table.clear(key{zone: zone, src: edgedoc.SourceKey(src)})
}

// DryRun reports whether the service is in watch-only mode.
func (s *Service) DryRun() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dryRun
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

// zoneQuota is how many buckets one zone may hold: an equal share of the node
// cap, never below minZoneQuota, never above the cap.
func (s *Service) zoneQuota() int {
	n := len(s.zones)
	if n < 1 {
		n = 1
	}
	q := s.max / n
	if q < minZoneQuota {
		q = minZoneQuota
	}
	if q > s.max {
		q = s.max
	}
	return q
}

// take spends one token from (zone, src)'s bucket, creating it full. A bucket
// that cannot be created — the node cap or the zone's quota is reached, and a
// paced sweep freed nothing — means the request passes untracked: the service
// does not guess, and does not walk its tables for every miss.
func (s *Service) take(k key, rps uint64, now time.Time) takeResult {
	capacity := float64(rps)
	b := s.buckets[k]
	if b == nil {
		if s.bucketsFull(k.zone) {
			if now.Sub(s.lastSweep) >= fullSweepEvery {
				s.sweep(now)
			}
			if s.bucketsFull(k.zone) {
				return takeUntracked
			}
		}
		b = &bucket{tokens: capacity, last: now}
		s.buckets[k] = b
		s.perZone[k.zone]++
	} else if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * capacity
		if b.tokens > capacity {
			b.tokens = capacity
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return takeAllowed
	}
	return takeDenied
}

func (s *Service) bucketsFull(zone string) bool {
	return len(s.buckets) >= s.max || s.perZone[zone] >= s.zoneQuota()
}

// open records one in-flight request for (zone, src). A key with open slots
// that has had no completion for idleAfter while requests kept coming has a
// dead log stream: its slots are dropped, its ceiling suspended, and the
// event counted. When the table is full the request is not tracked.
func (s *Service) open(k key, now time.Time) {
	f := s.inflight[k]
	if f == nil {
		if len(s.inflight) >= s.max {
			return
		}
		f = &inflight{lastClose: now}
		s.inflight[k] = f
	} else if !f.dead && len(f.opens) > 0 && now.Sub(f.lastClose) > idleAfter {
		f.opens = f.opens[:0]
		f.dead = true
		metrics.EdgeInflightResetsTotal.Inc()
	}
	if len(f.opens) < maxInflightTracked {
		f.opens = append(f.opens, now)
	}
	f.lastOpen = now
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
			if s.perZone[k.zone]--; s.perZone[k.zone] <= 0 {
				delete(s.perZone, k.zone)
			}
		}
	}
	for k, f := range s.inflight {
		if _, ok := s.zones[k.zone]; !ok || now.Sub(f.lastOpen) > idleAfter {
			delete(s.inflight, k)
		}
	}
	s.table.sweep(now, s.zones)
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

// clipMark bounds a composed mark to MaxMarkLen.
func clipMark(m string) string {
	if len(m) > MaxMarkLen {
		return m[:MaxMarkLen]
	}
	return m
}

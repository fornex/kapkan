// Package decide is the per-node decision service of the edge (edge-spec §5,
// milestone E3.3): the thing nginx's auth_request asks, once per request in a
// decide-mode zone, over a unix socket.
//
// THE CONTRACT is what the renderer emits (internal/edge/render): GET /decide
// with X-Kapkan-Zone (the zone name, literal in the rendered config — trusted),
// X-Kapkan-Client (the remote address), X-Kapkan-Method / -URI, the original
// Host, and — the ONE client-controlled value, since E4.2 — X-Kapkan-Clearance,
// the kapkan_clr cookie's value alone, bounded and verified here, never
// trusted; the client's other headers are NOT forwarded
// (proxy_pass_request_headers off), so nothing else a client sends can push
// the subrequest off the contract. The answer is 200 (allow, optionally an
// X-Kapkan-Mark header the origin receives), 403 (deny) or 401 (challenge:
// the client must clear the proof-of-work rung first), the last two with
// X-Kapkan-Reason naming why — rate, concurrency, table:<reason>,
// challenge:<why>. Nothing else, ever: auth_request honours exactly 2xx, 401
// and 403 from the subrequest and turns anything else into a failed
// decision, which the zone's failure_mode then handles in nginx. The renderer
// maps a rate or concurrency denial to 429 (+ Retry-After), keeps 403 for a
// table denial, sends a 401 to the clearance page, and logs the reason, so
// the rollup can tell a client that ran over its ceiling from one already
// denied or one asked to clear.
//
// THE RUNG (edge-spec §5, E4). A zone with policy.challenge manual challenges
// every request that carries no valid clearance; one with auto challenges a
// source the verdict table says to (Challenge, fed by the rollup — E4.4) or
// everyone while the zone is flipped (SetZoneChallenge — E4.4/E4.6). A valid
// clearance (a cookie the node or any node of the fleet signed under the
// zone's keys, bound to this zone and this source key) passes with the mark
// "cleared" (or "cleared:nojs"); rate and concurrency still apply to cleared
// clients. Paths under challenge_options.exempt_paths are never challenged —
// the one place a request path is read, for an exemption only. The rung has
// its own dry-run per zone (challenge_options.dry_run, default true): a
// challenge is then answered as an allow marked "would-challenge:<why>", as
// it is under the node's dry-run, so an operator sees who would have been
// asked before any zone asks anyone. Precedence: a table deny beats a
// challenge, which beats a mark.
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
	"encoding/base64"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
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
	// ReasonChallenge prefixes a challenge's why: "challenge:manual",
	// "challenge:zone:<reason>" (the zone is flipped), "challenge:table:<reason>"
	// (this source is under a challenge verdict).
	ReasonChallenge = "challenge"

	// MarkCleared is the mark a request with a valid clearance carries to the
	// origin; a no-JS clearance carries MarkClearedNoJS.
	MarkCleared     = "cleared"
	MarkClearedNoJS = "cleared:nojs"

	// maxClearance bounds the cookie value the service will look at; the
	// clearance package refuses anything longer without work.
	maxClearance = 512
)

// Verdict is one decision.
type Verdict struct {
	// Allow is the answer: 200, or (Challenge) 401, or 403.
	Allow bool
	// Challenge is true when the client must clear the rung first: a 401 the
	// renderer sends to the clearance page. In dry-run it is answered as an
	// allow marked would-challenge:<why>, with DryRun set.
	Challenge bool
	// Mark is the X-Kapkan-Mark the origin receives ("" for none). In dry-run
	// a would-deny or would-challenge mark replaces any reputation mark for
	// that request; a valid clearance marks "cleared".
	Mark string
	// Reason says what decided it (a Reason* constant, "table:<reason>" or
	// "challenge:<why>").
	Reason string
	// DryRun is true when a deny or a challenge was answered as an allow
	// because the service — or, for a challenge, the zone — is in dry-run;
	// Reason still names what would have happened.
	DryRun bool
}

// Denied reports whether the verdict is a denial or a challenge (enforced or
// dry-run): the cases that carry a reason.
func (v Verdict) Denied() bool {
	return !v.Allow || v.DryRun
}

// Request is what one decision is about.
type Request struct {
	Zone string
	Src  netip.Addr
	// Path is the request path as the terminator NORMALISED it (X-Kapkan-Path
	// = nginx's $uri: dot segments merged, percent-decoding done, no query) —
	// consulted ONLY against challenge_options.exempt_paths, never for a
	// verdict of its own. The raw request target is not used: an origin
	// resolves "/healthz/../admin" to /admin, and a prefix test on the raw
	// form would exempt it.
	Path string
	// Clearance is the kapkan_clr cookie's value ("" for none): the one
	// client-controlled value the subrequest carries. Verified against the
	// zone's keys, never trusted.
	Clearance string
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

// zoneState is what the service holds per zone: the policy, the clearance
// keys it verifies with (the document's, or the node's own ephemeral key when
// the document carries none), and the zone-wide challenge flip.
type zoneState struct {
	name   string
	pol    edgedoc.Policy
	keys   []clearance.Key
	exempt []string
	// dryRun is challenge_options.dry_run: the rung is watch-only for this
	// zone whatever the node's own dry-run says.
	dryRun bool
	// flipOn until flipUntil challenges every source of an auto zone (E4.4's
	// zone-rps trigger, E4.6's override); flipWhy names the reason.
	flipOn    bool
	flipUntil time.Time
	flipWhy   string
}

// Service decides. Safe for concurrent use.
type Service struct {
	mu        sync.Mutex
	zones     map[string]*zoneState
	buckets   map[key]*bucket
	perZone   map[string]int
	inflight  map[key]*inflight
	table     *table
	max       int
	dryRun    bool
	now       func() time.Time
	log       *slog.Logger
	lastSweep time.Time
	// localMaster derives the ephemeral per-zone key a zone gets when its
	// document carries no clearance keys (an older brain): valid on this node
	// alone, for the life of the process.
	localMaster []byte
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
	s := &Service{
		zones:    map[string]*zoneState{},
		buckets:  make(map[key]*bucket),
		perZone:  make(map[string]int),
		inflight: make(map[key]*inflight),
		table:    newTable(opts.MaxSources),
		max:      opts.MaxSources,
		dryRun:   opts.DryRun,
		now:      opts.Now,
		log:      opts.Logger.With("component", "edge-decide"),
	}
	if m, err := clearance.NewSecret(); err == nil {
		s.localMaster = m
	} else {
		s.log.Error("no entropy for a local clearance key; zones without keys from the brain cannot challenge", "err", err)
	}
	return s
}

// SetZones replaces the per-zone policies with the document's. Tables of
// zones no longer present are dropped by the next sweep; a changed rate or
// challenge mode takes effect on the next decision — no restart, no reload. A
// zone-wide challenge flip survives the replacement while the zone stays an
// auto zone; any other mode makes it inert, so it is dropped and its gauge
// cleared.
func (s *Service) SetZones(doc *edgedoc.Doc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	zones := make(map[string]*zoneState, len(doc.Zones))
	for i := range doc.Zones {
		z := &doc.Zones[i]
		st := &zoneState{name: z.Name, pol: z.Policy, keys: s.keysFor(z), exempt: z.Policy.ExemptPaths(), dryRun: z.Policy.ChallengeDryRun()}
		if old := s.zones[z.Name]; old != nil && old.flipOn {
			if z.Policy.Challenge == edgedoc.ChallengeAuto {
				st.flipOn, st.flipUntil, st.flipWhy = old.flipOn, old.flipUntil, old.flipWhy
			} else {
				metrics.EdgeChallengeActive.WithLabelValues(z.Name).Set(0)
			}
		}
		zones[z.Name] = st
	}
	for name := range s.zones {
		if _, still := zones[name]; !still {
			metrics.EdgeChallengeActive.DeleteLabelValues(name)
		}
	}
	s.zones = zones
}

// LocalKeyID names the key a node derives for itself: last in every zone's
// key list, so a clearance the node issued under it (when the document's
// keys were absent or dead) verifies on this node alone, and the page issues
// under a document key whenever one is live.
const LocalKeyID = "local"

// keysFor decodes a zone's clearance keys from the document and appends the
// node's own ephemeral key, so a zone whose document carries no keys — or
// only keys that have since expired, with the brain gone (edge-spec §2.4) —
// can still challenge and clear on its own instead of walling everyone out.
func (s *Service) keysFor(z *edgedoc.Zone) []clearance.Key {
	keys := make([]clearance.Key, 0, len(z.ClearanceKeys)+1)
	for _, ck := range z.ClearanceKeys {
		secret, err := base64.RawURLEncoding.DecodeString(ck.Secret)
		if err != nil || len(secret) != clearance.SecretLen || ck.ID == "" || ck.ID == LocalKeyID {
			continue
		}
		keys = append(keys, clearance.Key{ID: ck.ID, Secret: secret, NotBefore: ck.NotBefore, NotAfter: ck.NotAfter})
	}
	if s.localMaster != nil {
		if secret, err := clearance.DeriveZoneKey(s.localMaster, z.Name); err == nil {
			keys = append(keys, clearance.Key{ID: LocalKeyID, Secret: secret, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<40, 0)})
		}
	}
	return keys
}

// anyLive reports whether one of the keys may verify at now.
func anyLive(keys []clearance.Key, now time.Time) bool {
	for _, k := range keys {
		if len(k.Secret) == clearance.SecretLen && k.ID != "" && !now.Before(k.NotBefore) && now.Before(k.NotAfter) {
			return true
		}
	}
	return false
}

// Keys returns a copy of the clearance keys the service verifies zone's
// cookies with — what the clearance page signs with (E4.3): the document's
// keys first, the node's own last. Nil for an unknown zone.
func (s *Service) Keys(zone string) []clearance.Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	zs := s.zones[zone]
	if zs == nil {
		return nil
	}
	out := make([]clearance.Key, len(zs.keys))
	for i, k := range zs.keys {
		out[i] = k
		out[i].Secret = append([]byte(nil), k.Secret...)
	}
	return out
}

// SetDryRun switches watch-only mode.
func (s *Service) SetDryRun(on bool) {
	s.mu.Lock()
	s.dryRun = on
	s.mu.Unlock()
}

// Decide answers one request from src in zone that carries no clearance and
// no path — the E3 shape, kept for callers that have nothing more to say.
func (s *Service) Decide(zone string, src netip.Addr) Verdict {
	return s.DecideRequest(Request{Zone: zone, Src: src})
}

// DecideRequest answers one request.
func (s *Service) DecideRequest(req Request) Verdict {
	now := s.now()
	zone := req.Zone
	k := key{zone: zone, src: edgedoc.SourceKey(req.Src)}
	s.mu.Lock()
	s.maybeSweep(now)
	zs, ok := s.zones[zone]
	if !ok {
		s.mu.Unlock()
		metrics.EdgeDecisionsTotal.WithLabelValues("unknown", "unknown_zone").Inc()
		return Verdict{Allow: true, Reason: ReasonUnknownZone}
	}
	if zs.pol.Mode != edgedoc.ModeDecide {
		s.mu.Unlock()
		metrics.EdgeDecisionsTotal.WithLabelValues(zone, "mode_none").Inc()
		return Verdict{Allow: true, Reason: ReasonModeNone}
	}
	// The clearance is verified OUTSIDE the lock: an HMAC per request must
	// not serialise every zone on the node. The key slice is never mutated
	// once set, so the snapshot is safe to read unlocked.
	keys, rung := zs.keys, zs.pol.Challenge != edgedoc.ChallengeOff
	s.mu.Unlock()
	cleared := ""
	if rung && req.Clearance != "" && len(req.Clearance) <= maxClearance && len(keys) > 0 {
		if kind, ok := clearance.Verify(keys, zone, k.src.String(), req.Clearance, now); ok {
			cleared = kind
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The zones may have been replaced meanwhile; a verdict on a token under
	// the keys of a moment ago is what any node a moment ago would have given.
	if zs, ok = s.zones[zone]; !ok || zs.pol.Mode != edgedoc.ModeDecide {
		metrics.EdgeDecisionsTotal.WithLabelValues("unknown", "unknown_zone").Inc()
		return Verdict{Allow: true, Reason: ReasonUnknownZone}
	}
	pol := zs.pol

	v := Verdict{Allow: true, Reason: ReasonAllow}
	result := "allow"
	e := s.table.lookup(k, now)
	switch {
	case e != nil && e.deny:
		v = Verdict{Reason: ReasonTable + ":" + e.reason}
		result = "deny_table"
	default:
		if e != nil && e.mark != "" {
			v.Mark = e.mark
			result = "allow_marked"
		}
		why := zs.challengeWhy(e, now)
		if why != "" && pathExempt(zs.exempt, req.Path) {
			why = ""
		}
		if why == "" && e != nil && e.challenge {
			// A challenge verdict that is not in force (the rung off, the
			// path exempt) must not swallow the mark beneath it.
			if m := s.table.lookupMark(k, now); m != nil {
				v.Mark = m.mark
				result = "allow_marked"
			}
		}
		switch {
		case cleared != "":
			// A valid clearance passes the rung, whether or not one is in
			// force right now, and tells the origin so.
			v.Mark = MarkCleared
			if cleared == clearance.KindNoJS {
				v.Mark = MarkClearedNoJS
			}
			result = "allow_cleared"
		case why != "" && (zs.dryRun || s.dryRun):
			v.Challenge, v.DryRun = true, true
			v.Reason = ReasonChallenge + ":" + why
			v.Mark = clipMark("would-challenge:" + why)
			result = "would_challenge"
		case why != "":
			v = Verdict{Challenge: true, Reason: ReasonChallenge + ":" + why}
			result = "challenge"
		}
	}
	// The ceiling applies to a challenged request too: a flood without
	// cookies must not turn into a flood of challenge pages — the rate deny
	// (a 429) is the cheaper answer and the one the flood rule counts.
	if (v.Allow || v.Challenge) && pol.Rate.RPS > 0 {
		switch s.take(k, pol.Rate.RPS, now) {
		case takeDenied:
			v = Verdict{Reason: ReasonRate}
			result = "deny_rate"
		case takeUntracked:
			if v.Allow && !v.Challenge {
				// Passing untracked keeps the reputation mark: the table was
				// consulted, only the bucket could not be.
				v.Reason = ReasonUntracked
				result = "untracked"
			}
		}
	}
	if (v.Allow || v.Challenge) && pol.Rate.Concurrency > 0 {
		if f := s.inflight[k]; f != nil && !f.dead && f.count(now) >= int(pol.Rate.Concurrency) {
			v = Verdict{Reason: ReasonConcurrency}
			result = "deny_concurrency"
		}
	}
	// Every decision — allow, deny or challenge — becomes one request nginx
	// will log, and that log line is what closes it (Complete).
	s.open(k, now)

	if !v.Allow && !v.Challenge && s.dryRun {
		v.DryRun = true
		v.Allow = true
		v.Mark = clipMark("would-deny:" + v.Reason)
		result = "would_deny"
	}
	metrics.EdgeDecisionsTotal.WithLabelValues(zone, result).Inc()
	return v
}

// challengeWhy says whether the rung is in force for this request and why:
// "" (no), "manual", "zone:<reason>" (the zone is flipped) or
// "table:<reason>" (a challenge verdict for this source). A zone with no LIVE
// key cannot verify a clearance, so it cannot challenge either — nobody would
// ever get through. Caller holds the mutex; a lapsed flip is retired here,
// so the gauge does not wait for a sweep on an idle zone.
func (zs *zoneState) challengeWhy(e *entry, now time.Time) string {
	if zs.flipOn && !now.Before(zs.flipUntil) {
		zs.flipOn = false
		metrics.EdgeChallengeActive.WithLabelValues(zs.name).Set(0)
	}
	if !anyLive(zs.keys, now) {
		return ""
	}
	switch zs.pol.Challenge {
	case edgedoc.ChallengeManual:
		return "manual"
	case edgedoc.ChallengeAuto:
		if zs.flipOn {
			return "zone:" + zs.flipWhy
		}
		if e != nil && e.challenge {
			return "table:" + e.reason
		}
	}
	return ""
}

// pathExempt reports whether the request's normalised path starts with one
// of the exempt prefixes. The path is nginx's $uri — dot segments already
// merged — but a form that still carries one, a backslash or an encoded
// byte is refused rather than trusted: the origin might read it differently.
func pathExempt(exempt []string, path string) bool {
	if len(exempt) == 0 || path == "" || path[0] != '/' {
		return false
	}
	path, _, _ = strings.Cut(path, "?")
	if strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") || strings.Contains(path, "/./") ||
		strings.HasSuffix(path, "/.") || strings.ContainsAny(path, "\\%") {
		return false
	}
	for _, p := range exempt {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Challenge installs a challenge verdict for src in zone ("" = every zone)
// until ttl passes: the source must clear the rung on its next request. A
// live deny outranks it; it outranks a mark. In effect only for zones whose
// policy.challenge is auto.
func (s *Service) Challenge(zone string, src netip.Addr, ttl time.Duration, reason string) bool {
	now := s.now()
	k := key{zone: zone, src: edgedoc.SourceKey(src)}
	s.mu.Lock()
	ok := s.table.setChallenge(k, sanitizeMark(reason), now.Add(ttl), now)
	s.mu.Unlock()
	if ok {
		s.log.Info("challenge installed", "zone", zone, "src", k.src.String(), "ttl", ttl.String(), "reason", reason)
	} else {
		s.log.Warn("verdict table full; challenge not installed", "zone", zone, "src", k.src.String(), "reason", reason)
	}
	return ok
}

// Challenged reports whether src is under a live challenge verdict in zone
// (the every-zone wildcard included) — and not under a deny, which outranks it.
func (s *Service) Challenged(zone string, src netip.Addr) bool {
	now := s.now()
	k := key{zone: zone, src: edgedoc.SourceKey(src)}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.table.lookup(k, now)
	return e != nil && e.challenge
}

// SetZoneChallenge flips a zone-wide challenge on until `until` (or off) with
// a reason for the log and the report: every request of the zone is then
// challenged. Only an auto zone takes a flip — the rung is off or already
// unconditional otherwise — and only an `until` still ahead; the call
// returns false when nothing was flipped.
func (s *Service) SetZoneChallenge(zone string, on bool, until time.Time, reason string) bool {
	now := s.now()
	s.mu.Lock()
	zs := s.zones[zone]
	if zs == nil || (on && (zs.pol.Challenge != edgedoc.ChallengeAuto || !until.After(now))) {
		s.mu.Unlock()
		return false
	}
	zs.flipOn, zs.flipUntil, zs.flipWhy = on, until, sanitizeMark(reason)
	active := 0.0
	if on {
		active = 1
	}
	metrics.EdgeChallengeActive.WithLabelValues(zone).Set(active)
	s.mu.Unlock()
	if on {
		s.log.Info("zone-wide challenge on", "zone", zone, "until", until.UTC().Format(time.RFC3339), "reason", reason)
	} else {
		s.log.Info("zone-wide challenge off", "zone", zone)
	}
	return true
}

// ZoneChallenge reports the zone-wide flip: on, until when, why. A lapsed
// flip is retired here too.
func (s *Service) ZoneChallenge(zone string) (on bool, until time.Time, reason string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	zs := s.zones[zone]
	if zs == nil || !zs.flipOn {
		return false, time.Time{}, ""
	}
	if !now.Before(zs.flipUntil) {
		zs.flipOn = false
		metrics.EdgeChallengeActive.WithLabelValues(zone).Set(0)
		return false, time.Time{}, ""
	}
	return true, zs.flipUntil, zs.flipWhy
}

// Complete records that a decided request for (zone, src) was logged by the
// terminator, closing one in-flight slot. The rollup calls it for every
// access-log line whose decision field says the decider answered (200, 401
// or 403); undecided requests never opened a slot.
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

// sweep drops idle buckets and counters, expired verdicts and zone flips, and
// everything belonging to a zone that is no longer configured.
func (s *Service) sweep(now time.Time) {
	s.lastSweep = now
	for name, zs := range s.zones {
		if zs.flipOn && !now.Before(zs.flipUntil) {
			zs.flipOn = false
			metrics.EdgeChallengeActive.WithLabelValues(name).Set(0)
		}
	}
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

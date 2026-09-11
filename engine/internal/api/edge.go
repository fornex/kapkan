package api

// The edge-node channel (edge-spec §2.3; milestone E3.1). A box running
// `kapkan edge` long-polls GET /api/v1/edge/zones for the zone document it
// renders into its terminator, posts an advisory self-report to
// POST /api/v1/edge/nodes/{name}/report, and the console reads the inventory
// from GET /api/v1/edge/nodes. The three mirror the scrub-node channel in
// rules.go / nodes.go deliberately — same protocol (content-hash ETag, held
// If-None-Match poll, 304 on deadline, capped holds), same trust rules (the
// poll is liveness, a report never is), same tenant rule (unscoped only) — so
// an operator who understands one channel understands both, and the agent's
// poll loop is the same code generalised over the document type.
//
// What differs, and why: the document is derived from the CONFIG STORE (the
// zones file), not the ban table, so the wake signal is Store.Changed() — a
// successful reload — rather than Mitigator.RulesChanged(); and edge-node
// presence is tracked HERE, in the api package, not in mitigate: edge nodes are
// not ScrubNodes, nothing routes a victim's traffic by their liveness, and
// mitigate's import direction ("reports never influence routing") must stay
// exactly as narrow as it is.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

const (
	// edgeDocVersion versions the document shape, like ruleDocVersion. An agent
	// refuses a version it does not know rather than guessing at fields. The
	// number is owned by the wire-contract package both ends import.
	edgeDocVersion = edgedoc.Version

	// maxEdgeReportBytes bounds a report body, same figure and reasoning as
	// maxNodeReportBytes.
	maxEdgeReportBytes = 64 << 10

	// defaultEdgeStaleAfter is the liveness window used when no edge block is
	// configured (there are then no nodes to judge, but the inventory document
	// still states the contract it would apply).
	defaultEdgeStaleAfter = 15 * time.Second
)

// The document types live in internal/edge/edgedoc — the leaf package both the
// brain and the node import — and are aliased here so the brain-side code and
// its tests keep the Edge* names. THE JSON CONTRACT IS FROZEN THERE (version 1);
// see that package's doc for the extension rule.
type (
	EdgeDoc          = edgedoc.Doc
	EdgeDocZone      = edgedoc.Zone
	EdgeDocTLS       = edgedoc.TLS
	EdgeDocPolicy    = edgedoc.Policy
	EdgeDocRate      = edgedoc.Rate
	EdgeDocChallenge = edgedoc.Challenge
	EdgeDocGrant     = edgedoc.Grant
)

// buildEdgeDoc derives the whole document from a loaded zones file. Pure — no
// clock, no server — so the doc-shape tests are tables. A nil zones file (no
// edge block, or the brain has not loaded one) yields the empty document, not
// an error: an edge with nothing to serve is a valid state.
func buildEdgeDoc(z *config.Zones) EdgeDoc { return buildEdgeDocServed(z, nil) }

// buildEdgeDocServed is buildEdgeDoc over the zones serves says so for — one
// node's document (E6.3: a node gets exactly the zones its placement scope
// covers). A nil serves keeps every zone: the whole document, which is what
// an operator's bare GET and a fleet without scopes receive, byte for byte
// as before. The placement itself never enters the document.
func buildEdgeDocServed(z *config.Zones, serves func(*config.Zone) bool) EdgeDoc {
	doc := EdgeDoc{
		Version:        edgeDocVersion,
		Zones:          []EdgeDocZone{},
		ACMEChallenges: []EdgeDocChallenge{},
		IssuanceGrants: []EdgeDocGrant{},
	}
	if z == nil {
		return doc
	}
	for i := range z.Zones {
		zn := &z.Zones[i]
		if serves != nil && !serves(zn) {
			continue
		}
		// Origins keep the file's order: an operator may order upstreams on
		// purpose, and the file is already the deterministic source.
		origins := make([]string, len(zn.Origins))
		copy(origins, zn.Origins)
		doc.Zones = append(doc.Zones, EdgeDocZone{
			Name:          zn.Name,
			Origins:       origins,
			TLS:           EdgeDocTLS{MinVersion: zn.TLS.MinVersion, H3: zn.TLS.H3, H3Options: h3Options(zn.TLS)},
			ACMEDirectory: zn.ACME.Directory,
			ACMEFallback:  zn.ACME.Fallback,
			Policy: EdgeDocPolicy{
				Mode:             zn.Policy.Mode,
				FailureMode:      zn.Policy.FailureMode,
				Challenge:        zn.Policy.Challenge,
				Rate:             EdgeDocRate{RPS: zn.Policy.Rate.RPS, Concurrency: zn.Policy.Rate.Concurrency},
				DryRun:           zn.Policy.DryRun,
				ChallengeOptions: challengeOptions(zn.Policy.ChallengeOptions),
			},
			ExtraDirectivesFile: zn.ExtraDirectivesFile,
		})
	}
	// Names are unique (the zones file rejects duplicates), so this order is total.
	sort.Slice(doc.Zones, func(i, j int) bool { return doc.Zones[i].Name < doc.Zones[j].Name })
	return doc
}

// h3Options resolves the zones file's HTTP/3 options for the document: nil at
// the defaults (announce, a day) and for a zone without h3 — so a zones file
// written before E5 yields the bytes it always did — and only the departures
// otherwise. The node fills the defaults back in.
func h3Options(tls config.ZoneTLS) *edgedoc.H3Options {
	if !tls.H3 {
		return nil
	}
	o := tls.H3Options
	advertise := o.Advertise == nil || *o.Advertise
	if advertise && (o.AltSvcMaxAgeSeconds == 0 || o.AltSvcMaxAgeSeconds == edgedoc.DefaultAltSvcMaxAge) {
		return nil
	}
	out := &edgedoc.H3Options{}
	if !advertise {
		f := false
		out.Advertise = &f
	}
	if o.AltSvcMaxAgeSeconds != 0 && o.AltSvcMaxAgeSeconds != edgedoc.DefaultAltSvcMaxAge {
		out.AltSvcMaxAgeSeconds = o.AltSvcMaxAgeSeconds
	}
	return out
}

// challengeOptions resolves the zones file's rung options for the document:
// nil for the defaults (watch-only, nothing exempt) — so a zones file written
// before E4 yields the bytes it always did — and the resolved object
// otherwise.
func challengeOptions(o config.ZoneChallengeOptions) *edgedoc.ChallengeOptions {
	dry := o.DryRun == nil || *o.DryRun
	difficulty, ttl := o.Difficulty, o.CookieTTLSeconds
	if difficulty == edgedoc.DefaultChallengeDifficulty {
		difficulty = 0
	}
	if ttl == edgedoc.DefaultCookieTTLSeconds {
		ttl = 0
	}
	var auto *edgedoc.AutoChallenge
	if hold := o.Auto.HoldSeconds; o.Auto.ZoneRPS != 0 || (hold != 0 && hold != edgedoc.DefaultChallengeHoldSeconds) {
		if hold == edgedoc.DefaultChallengeHoldSeconds {
			hold = 0
		}
		auto = &edgedoc.AutoChallenge{ZoneRPS: o.Auto.ZoneRPS, HoldSeconds: hold}
	}
	if dry && len(o.ExemptPaths) == 0 && difficulty == 0 && ttl == 0 && auto == nil {
		return nil
	}
	paths := make([]string, len(o.ExemptPaths))
	copy(paths, o.ExemptPaths)
	return &edgedoc.ChallengeOptions{DryRun: dry, ExemptPaths: paths, Difficulty: difficulty, CookieTTLSeconds: ttl, Auto: auto}
}

// edgeDocBytes encodes the document once and derives its ETag from those same
// bytes — the ruleDocBytes scheme (sha256, truncated hex, quoted) — so the
// header can never disagree with the body it was computed for.
func edgeDocBytes(doc EdgeDoc) (body []byte, etag string, err error) {
	body, err = json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// edgeSnapshotFor builds the current document for one node: the zones from
// the config store, plus the live issuance slots and fanned-out challenges
// (edge_acme.go) and each zone's clearance keys (edge_clearance.go).
// buildEdgeDoc stays pure; the coordinator adds only entries whose times are
// fixed for their lifetime and the keyring's keys change only at an epoch
// boundary, so the ETag moves exactly when there is news.
//
// It is the document as that node receives it: the zones its
// placement scope covers (E6.3), and — because every fill below keys on
// doc.Zones — only the issuance grants, fanned-out challenges, clearance keys
// and levers of those zones; the ETag is per node for free. An empty node
// (an operator's bare GET) is the whole document. A NAMED node the
// configuration does not have serves nothing — an empty document, never the
// whole file: a node a reload has just removed may still be parked in a
// hold, and the answer that ends its service must not hand it every zone's
// keys (the hold re-checks the name and answers 404; this is the floor
// under it).
func (s *Server) edgeSnapshotFor(node string) ([]byte, string, error) {
	cfg := s.store.Get()
	var serves func(*config.Zone) bool
	if node != "" {
		serves = func(*config.Zone) bool { return false }
		if n := configuredEdgeNode(cfg, node); n != nil {
			serves = n.Serves
		}
	}
	doc := buildEdgeDocServed(cfg.ZonesCfg, serves)
	now := time.Now()
	s.edgeIssuance.fill(&doc, now)
	if cfg.Edge != nil {
		s.edgeClearance.setPath(cfg.Edge.StateFile)
	}
	s.edgeClearance.fill(&doc, now)
	s.edgeLever.fill(&doc, now)
	return edgeDocBytes(doc)
}

// configuredEdgeNode returns the edge.nodes entry with this name, or nil.
func configuredEdgeNode(cfg *config.Config, name string) *config.EdgeNode {
	if cfg.Edge == nil {
		return nil
	}
	for i := range cfg.Edge.Nodes {
		if cfg.Edge.Nodes[i].Name == name {
			return &cfg.Edge.Nodes[i]
		}
	}
	return nil
}

// edgeStaleAfter is the configured liveness window, or the default when no
// edge block exists.
func edgeStaleAfter(cfg *config.Config) time.Duration {
	if cfg.Edge == nil || cfg.Edge.StaleAfterSeconds <= 0 {
		return defaultEdgeStaleAfter
	}
	return time.Duration(cfg.Edge.StaleAfterSeconds) * time.Second
}

// handleEdgeZones serves the zone document, long-polling per the protocol
// described in rules.go. Unscoped tokens only: a node's document lists every
// tenant's zones its placement covers (E6.3) and the bare GET the whole file,
// so a scoped operator would otherwise learn other tenants' hostnames from
// one GET.
func (s *Server) handleEdgeZones(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !c.unscoped() {
		writeError(w, http.StatusForbidden, "the edge zones document is restricted to unscoped tokens")
		return
	}
	// ?node=<name> is the agent's identity and THIS REQUEST is its liveness
	// signal — the one and only one (a self-report never is). Same rules as the
	// scrub channel: a sighting needs a real credential (this is a
	// side-effectful GET outside the POST-only CSRF gate), the name must be a
	// configured edge node (a typo must fail loudly, not leave a node polling
	// diligently while the brain counts it dead), a token bound to a node may
	// only act as that node (node_binding.go — checked BEFORE any side effect),
	// and presence is stamped only by AGENT tokens: an operator's ?node= is a
	// preview of that node's document and moves no liveness.
	node := r.URL.Query().Get("node")
	if _, ok := s.nodeActor(w, r, node, "edge_zones"); !ok {
		return
	}
	if node != "" {
		if c.token == "" {
			writeError(w, http.StatusForbidden, "node identity requires an API token (configure api.tokens)")
			return
		}
		if configuredEdgeNode(s.store.Get(), node) == nil {
			writeError(w, http.StatusNotFound, "unknown edge node")
			return
		}
		if stampsPresence(c) {
			s.edgePresence.pollStarted(node, c.token)
			defer s.edgePresence.pollEnded(node)
		}
	}
	// The hold gate's total scales with the fleet: every node polls on its own
	// token once bound, so the fixed total the scrub channel uses would become
	// the visible ceiling of an edge fleet.
	if cfg := s.store.Get(); cfg.Edge != nil {
		s.edgeHolds.setTotal(max(maxRuleHoldsTotal, 2*len(cfg.Edge.Nodes)))
	}
	// The document is the node's (E6.3): its placement scope's zones, or the
	// whole file for an operator's bare GET.
	body, etag, err := s.edgeSnapshotFor(node)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding zones document failed")
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm == "" || !etagMatches(inm, etag) {
		writeRuleDoc(w, body, etag)
		return
	}

	// The caller already has the current document: hold until it changes. The
	// edge channel has its OWN hold gate (same caps as the scrub channel's), so
	// an edge fleet's parked polls can never starve scrub nodes of theirs.
	release, ok := s.edgeHolds.acquire(c.token)
	if !ok {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "too many concurrent zone holds")
		return
	}
	defer release()
	deadline := time.NewTimer(s.rulesHold)
	defer deadline.Stop()
	for {
		// Subscribe BEFORE re-reading, or a reload landing in between would
		// sleep here for a full hold despite having news. Store.Changed fires on
		// ANY successful reload, not only a zones change: the loop re-hashes and
		// keeps holding when the document is unchanged.
		changed := s.store.Changed()
		acmeChanged := s.edgeIssuance.Changed()
		keysChanged := s.edgeClearance.Changed()
		leverChanged := s.edgeLever.Changed()
		// A reload may have removed this node (E6.3), removed the token or
		// moved its binding (E6.1) while the poll was parked: the answer that
		// ends the hold is the one a first poll would now get — never a
		// document, the whole file least of all.
		if code, msg := s.edgeHoldStillValid(c, node); code != 0 {
			writeError(w, code, msg)
			return
		}
		body, cur, err := s.edgeSnapshotFor(node)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encoding zones document failed")
			return
		}
		if cur != etag {
			writeRuleDoc(w, body, cur)
			return
		}
		// A clearance epoch begins at a fixed instant (UTC midnight) and no
		// goroutine owns the keyring, so a parked poll wakes itself for it:
		// the snapshot it then takes is what rotates the keys and notifies
		// every other holder.
		// Likewise a challenge override lapses at a fixed instant: the poll
		// that wakes for it takes the snapshot that drops it.
		rotate := time.NewTimer(min(s.edgeClearance.untilNextChange(time.Now()), s.edgeLever.untilNextChange(time.Now())))
		select {
		case <-r.Context().Done():
			rotate.Stop()
			return
		case <-s.quit:
			// Shutting down: answer NOW so Shutdown is not stalled behind a
			// parked poll. Verified, not assumed — a reload may have landed.
			rotate.Stop()
			s.endEdgeHold(w, c, node, etag)
			return
		case <-deadline.C:
			rotate.Stop()
			s.endEdgeHold(w, c, node, etag)
			return
		case <-changed:
			// Woken by a reload; loop to rebuild and compare.
			rotate.Stop()
		case <-acmeChanged:
			// Woken by a slot or challenge; a CA may be validating within
			// seconds, so this must not wait for the deadline.
			rotate.Stop()
		case <-keysChanged:
			// Woken by a clearance rotation another snapshot performed.
			rotate.Stop()
		case <-leverChanged:
			// Woken by an operator's lever: a mode change must reach the
			// nodes within a poll, not a hold.
			rotate.Stop()
		case <-rotate.C:
			// An epoch boundary or a lever's lapse; the next snapshot
			// rotates the keys or drops the override.
		}
	}
}

// edgeHoldStillValid is what a parked edge poll re-checks before it answers:
// the node it named still exists (a reload may have cut it out of the fleet —
// 404, as a first poll would get) and the token may still act as it
// (holdStillAuthorized: removed → 401, rebound → 403).
func (s *Server) edgeHoldStillValid(c caller, node string) (int, string) {
	if node != "" && configuredEdgeNode(s.store.Get(), node) == nil {
		return http.StatusNotFound, "unknown edge node"
	}
	return s.holdStillAuthorized(c, node)
}

// endEdgeHold answers a hold that ended on the deadline or on shutdown with one
// final look at the store, for the same reason endHold does: "nothing changed"
// is verified, so a 304 never names a superseded ETag.
func (s *Server) endEdgeHold(w http.ResponseWriter, c caller, node, etag string) {
	if code, msg := s.edgeHoldStillValid(c, node); code != 0 {
		writeError(w, code, msg)
		return
	}
	if body, cur, err := s.edgeSnapshotFor(node); err == nil && cur != etag {
		writeRuleDoc(w, body, cur)
		return
	}
	writeRuleNotModified(w, etag)
}

// EdgeReport is what an edge node says about itself. THE JSON CONTRACT IS
// FROZEN HERE at version 1; the agent (`kapkan edge`) and the console are
// written against these key names. Every field is a CLAIM (see nodes.go's file
// comment — the same trust posture applies word for word), every field is
// optional, and no field may ever carry key material: a test greps for it.
type EdgeReport struct {
	// Version is the agent's kapkan version, for skew visibility.
	Version string `json:"version,omitempty"`
	// DryRun is the NODE-side watch-only flag: decisions counted, none
	// enforced. A node that only counts must say so.
	DryRun bool `json:"dry_run,omitempty"`
	// ZonesETag is the ETag of the zones document the node has rendered, so an
	// operator can see a node lagging the brain.
	ZonesETag string `json:"zones_etag,omitempty"`
	// Terminator is the node's view of the nginx/Angie it orchestrates.
	Terminator *EdgeReportTerminator `json:"terminator,omitempty"`
	// Certs lists the certificates the node currently holds, one per zone.
	// CertsTruncated counts entries the node dropped to keep the report under
	// the body limit (the list is zone-sorted; the tail went).
	Certs          []EdgeReportCert `json:"certs,omitempty"`
	CertsTruncated int              `json:"certs_truncated,omitempty"`
	// Zones is the node's last closed rollup window for every zone it serves
	// in decide mode (E4.5): what it saw and did in the last window, its
	// busiest sources and what it did to each, whether a zone-wide challenge
	// is in force, whether the zone is watch-only there. A zone without
	// traffic still appears, so its state is visible. ZonesTruncated counts
	// zones the node dropped to fit the body limit (zone-sorted; the tail
	// went — after every zone's per-source detail and the certificates).
	Zones          []EdgeReportZone `json:"zones,omitempty"`
	ZonesTruncated int              `json:"zones_truncated,omitempty"`
}

// The report's zone-level challenge mode, as the zones file (or the brain)
// set it: what the challenge column reads before it looks at counters.
// (Values are edgedoc.ChallengeOff / Manual / Auto.)

// EdgeReportZone is one zone's last rollup window on one node. Advisory, like
// the rest of the report: the brain sums and merges, never acts on it.
type EdgeReportZone struct {
	Zone string `json:"zone"`
	// At is when the window closed; WindowSeconds its REAL length. A consumer
	// judges freshness by At, not by the report's arrival. Both zero when the
	// node has not closed a window for the zone yet.
	At            time.Time `json:"at,omitzero"`
	WindowSeconds float64   `json:"window_seconds,omitempty"`
	// DryRun is the zone's EFFECTIVE watch-only state on this node: the node's
	// own dry_run or the zone's policy.dry_run (E4.7). RungDryRun is the
	// rung's: DryRun, or the rung's own challenge_options.dry_run — where it
	// is set, a challenge previews (would-challenge) rather than bites, so a
	// consumer can tell an enforcing rung from a watching one by state, not
	// by a window's counters.
	DryRun     bool `json:"dry_run,omitempty"`
	RungDryRun bool `json:"rung_dry_run,omitempty"`
	// Challenge is the zone's challenge mode (policy.challenge as the node
	// applies it): off, manual or auto.
	Challenge string `json:"challenge,omitempty"`
	// RPS is requests over the window's real length.
	RPS            float64 `json:"rps,omitempty"`
	Requests       uint64  `json:"requests,omitempty"`
	Decided        uint64  `json:"decided,omitempty"`
	Denied         uint64  `json:"denied,omitempty"`
	Challenged     uint64  `json:"challenged,omitempty"`
	Cleared        uint64  `json:"cleared,omitempty"`
	WouldDeny      uint64  `json:"would_deny,omitempty"`
	WouldChallenge uint64  `json:"would_challenge,omitempty"`
	Status2xx      uint64  `json:"status_2xx,omitempty"`
	Status3xx      uint64  `json:"status_3xx,omitempty"`
	Status4xx      uint64  `json:"status_4xx,omitempty"`
	Status5xx      uint64  `json:"status_5xx,omitempty"`
	// H3Requests counts the window's requests that arrived over HTTP/3 (the
	// log's proto field, E5); whether the zone speaks h3 on this node at all
	// is terminator.h3.serving.
	H3Requests uint64 `json:"h3_requests,omitempty"`
	// ChallengeActive is set while a zone-wide challenge is in force on this
	// node (the local trigger, E4.4; the brain's lever, E4.6).
	ChallengeActive *EdgeReportChallenge `json:"challenge_active,omitempty"`
	// TopSources are the window's busiest sources (the aggregator's top-N),
	// each with the strongest thing the node did to it — the would-be sources
	// first (a challenge or a deny previewed), then the refused and challenged
	// ones, then the busiest of the rest. SourcesTruncated counts the WOULD-BE
	// sources missing from this list: the ones the node's per-window bound
	// left out, and the ones a report too big for the body limit shed (the
	// sources that tell nothing go first and uncounted — they are not in the
	// set) — so an empty list with a count is "short", not "nobody".
	TopSources       []EdgeReportSource `json:"top_sources,omitempty"`
	SourcesTruncated int                `json:"sources_truncated,omitempty"`
}

// EdgeReportChallenge is a zone-wide challenge in force.
type EdgeReportChallenge struct {
	Reason string    `json:"reason,omitempty"`
	Until  time.Time `json:"until"`
	// DryRun says the flip is a PREVIEW on this node: the rung's own
	// watch-only switch (challenge_options.dry_run, true by default) or the
	// node's dry_run means every request it would challenge is answered as
	// an allow marked would-challenge.
	DryRun bool `json:"dry_run,omitempty"`
}

// The states EdgeReportSource.State takes, strongest first.
const (
	SourceStateDenied         = "denied"
	SourceStateChallenged     = "challenged"
	SourceStateWouldDeny      = "would-deny"
	SourceStateWouldChallenge = "would-challenge"
	SourceStateCleared        = "cleared"
	SourceStateMarked         = "marked"
	SourceStateAllow          = "allow"
)

// EdgeReportSource is one of a window's busiest sources.
type EdgeReportSource struct {
	// Source is the accounting key: an IPv4 address or an IPv6 /64.
	Source   string  `json:"source"`
	RPS      float64 `json:"rps,omitempty"`
	Requests uint64  `json:"requests"`
	// State is the strongest thing the node did to the source in the window:
	// denied (a table verdict refused it), challenged, would-deny,
	// would-challenge (previewed under dry-run), cleared, marked, allow.
	State string `json:"state"`
}

// EdgeReportTerminator is the state of the orchestrated terminator.
type EdgeReportTerminator struct {
	// Kind is "nginx" or "angie"; Version its reported version string.
	Kind    string `json:"kind,omitempty"`
	Version string `json:"version,omitempty"`
	// Generation is the rendered configuration generation currently live.
	Generation uint64 `json:"generation,omitempty"`
	// TestOK reports whether the last candidate passed the config test; when
	// it did not, TestError carries the tester's message and the previous
	// generation stayed live (edge-spec §2.4).
	TestOK    bool   `json:"test_ok,omitempty"`
	TestError string `json:"test_error,omitempty"`
	// Alive is the node's pid-file liveness check of the terminator; absent
	// when the node has no pid file configured to check.
	Alive *bool `json:"alive,omitempty"`
	// H3 is what the node's probe of the binary (`nginx -V`) says about
	// HTTP/3 (edge-spec §8, E5.1); absent from reports of nodes older than
	// E5.1.
	H3 *EdgeReportH3 `json:"h3,omitempty"`
}

// EdgeReportH3 is a node's HTTP/3 readiness, from the terminator probe and
// the node's own quic.h3 switch. The renderer emits QUIC only on a node whose
// state is ready; the other states say why a zone asking for h3 is served
// over TCP there.
type EdgeReportH3 struct {
	// State: ready (module present, quic.h3 auto), no_module (the binary was
	// built without --with-http_v3_module), node_off (edge.yaml quic.h3: off),
	// unknown (the probe failed — treated as no_module by the renderer, which
	// never guesses).
	State string `json:"state"`
	// Module reports --with-http_v3_module in the configure arguments.
	Module bool `json:"module"`
	// TLSLibrary is the library the binary runs with ("OpenSSL 3.5.7").
	TLSLibrary string `json:"tls_library,omitempty"`
	// EarlyDataCapable says the build could do 0-RTT over QUIC if asked;
	// recorded for the inventory, nothing renders it (0-RTT is off by policy).
	EarlyDataCapable bool `json:"early_data_capable"`
	// Advisory names a published QUIC advisory whose affected range holds
	// the build's nginx core — advice, not a verdict: distributions backport
	// fixes without moving the version. Empty when none applies.
	Advisory string `json:"advisory,omitempty"`
	// Serving lists the zones this node renders a QUIC listener for;
	// Unsupported the zones that asked for HTTP/3 and are served over TCP here
	// (the state above says why). Both from the LIVE generation (E5.3).
	// ServingTruncated / UnsupportedTruncated count entries a report too big
	// for the brain's body limit shed from the tail of each list (the lists
	// grow with the h3 zone count; a huge fleet must not push the whole report
	// past the limit).
	Serving              []string `json:"serving,omitempty"`
	Unsupported          []string `json:"unsupported,omitempty"`
	ServingTruncated     int      `json:"serving_truncated,omitempty"`
	UnsupportedTruncated int      `json:"unsupported_truncated,omitempty"`
	// Listening says something on the box holds UDP :443 (read from
	// /proc/net/udp) while the live generation has QUIC listeners — the local
	// half of "is HTTP/3 reachable?"; whether the port is open from outside
	// is the operator's firewall. Absent when nothing listens over QUIC or
	// the box has no /proc.
	Listening *bool `json:"listening,omitempty"`
}

// The states EdgeReportH3.State takes.
const (
	H3StateReady    = "ready"
	H3StateNoModule = "no_module"
	H3StateNodeOff  = "node_off"
	H3StateUnknown  = "unknown"
)

// EdgeReportCert is one held certificate. Public metadata only — never a key.
type EdgeReportCert struct {
	Zone     string    `json:"zone"`
	NotAfter time.Time `json:"not_after"`
	Issuer   string    `json:"issuer,omitempty"`
}

// edgeReportStore holds the last report per edge node. Advisory only.
type edgeReportStore struct {
	mu      sync.Mutex
	reports map[string]storedEdgeReport
}

type storedEdgeReport struct {
	report EdgeReport
	at     time.Time
}

// put stores the node's report and returns the one it replaces (the history's
// diff base, E6.5), with had false for the node's first report on this brain.
func (st *edgeReportStore) put(name string, r EdgeReport, at time.Time) (prev EdgeReport, had bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reports == nil {
		st.reports = make(map[string]storedEdgeReport)
	}
	old, had := st.reports[name]
	st.reports[name] = storedEdgeReport{report: r, at: at}
	return old.report, had
}

func (st *edgeReportStore) get(name string) (EdgeReport, time.Time, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.reports[name]
	return s.report, s.at, ok
}

// handleEdgeNodeReport stores an edge node's self-report. 404 for a node the
// config does not declare, for nodes.go's reasons: the store must not be
// growable by whoever holds an agent token. Stored, never acted on, and
// specifically NOT recorded as presence.
func (s *Server) handleEdgeNodeReport(w http.ResponseWriter, r *http.Request) {
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "edge node reports are restricted to unscoped tokens")
		return
	}
	name := r.PathValue("name")
	// The binding first: a bound token reporting as another node is refused
	// before anything is stored (node_binding.go).
	if _, ok := s.nodeActor(w, r, name, "edge_report"); !ok {
		return
	}
	if configuredEdgeNode(s.store.Get(), name) == nil {
		writeError(w, http.StatusNotFound, "unknown edge node")
		return
	}
	var rep EdgeReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEdgeReportBytes)).Decode(&rep); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "report exceeds 64 KiB")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	now := time.Now()
	prev, had := s.edgeReports.put(name, rep, now)
	// The history (edge_history.go): rows and events from this report, after
	// it is stored and before the 204 — map work and non-blocking enqueues,
	// never I/O, so the answer does not depend on storage.
	var base *EdgeReport
	if had {
		base = &prev
	}
	s.edgeHist.observe(s.store.Get(), name, base, rep, now)
	w.WriteHeader(http.StatusNoContent)
}

// edgePresence records edge-node sightings from the zones poll — the api-side
// twin of the mitigator's scrub-node liveness map, kept here because nothing in
// mitigation routes by an edge node's presence and mitigate must not learn to.
// The semantics are the same: a completed poll stamps lastSeen, and a poll
// parked in a hold counts as present for as long as it is parked.
type edgePresence struct {
	mu    sync.Mutex
	nodes map[string]*edgeNodeState
}

type edgeNodeState struct {
	lastSeen time.Time
	holding  int
	// lastToken is the NAME of the token that last polled as this node — the
	// inventory shows it so an operator migrating a fleet from a shared token
	// to bound ones can see which node has switched (E6.1).
	lastToken string
}

func (p *edgePresence) state(name string) *edgeNodeState {
	if p.nodes == nil {
		p.nodes = make(map[string]*edgeNodeState)
	}
	st := p.nodes[name]
	if st == nil {
		st = &edgeNodeState{}
		p.nodes[name] = st
	}
	return st
}

// pollStarted stamps a sighting by the named token (an agent's; see
// stampsPresence) and opens a hold.
func (p *edgePresence) pollStarted(name, token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.state(name)
	st.holding++
	st.lastSeen = time.Now()
	st.lastToken = token
}

// lastToken returns the name of the token that last polled as the node.
func (p *edgePresence) lastTokenOf(name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if st, ok := p.nodes[name]; ok {
		return st.lastToken
	}
	return ""
}

func (p *edgePresence) pollEnded(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.state(name)
	if st.holding > 0 {
		st.holding--
	}
	st.lastSeen = time.Now()
}

// seen returns the last sighting and whether a poll is parked right now.
func (p *edgePresence) seen(name string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.nodes[name]
	if !ok {
		return time.Time{}, false
	}
	return st.lastSeen, st.holding > 0
}

// alive is the brain's judgment: parked in a hold, or seen within staleAfter.
func (p *edgePresence) alive(name string, staleAfter time.Duration) bool {
	last, holding := p.seen(name)
	if holding {
		return true
	}
	return !last.IsZero() && time.Since(last) <= staleAfter
}

// EdgeNodesDoc is the GET /api/v1/edge/nodes response: every configured edge
// node with what the brain KNOWS (config, poll presence) joined with what the
// node CLAIMS (its last advisory report, clearly separated under `report`).
type EdgeNodesDoc struct {
	NodesTotal        int              `json:"nodes_total"`
	StaleAfterSeconds int              `json:"stale_after_seconds"`
	Nodes             []EdgeNodeStatus `json:"nodes"`
	// UnboundAgentTokens names the agent tokens without api.tokens[].node
	// while nodes are configured — each a fleet-wide credential the operator
	// should bind (edge-spec §9 risk 6). Absent when every agent is bound.
	UnboundAgentTokens []string `json:"unbound_agent_tokens,omitempty"`
}

// EdgeNodeStatus is one node in EdgeNodesDoc.
type EdgeNodeStatus struct {
	Name string `json:"name"`
	// Alive is the brain's judgment from the zones poll — never influenced by
	// reports. Holding means a poll is parked open right now.
	Alive    bool   `json:"alive"`
	Holding  bool   `json:"holding"`
	LastSeen string `json:"last_seen,omitempty"`
	// Tokens names the agent tokens bound to this node (api.tokens[].node);
	// LastToken the token that last polled as it — together they show a
	// fleet's migration from a shared token node by node.
	Tokens    []string `json:"tokens,omitempty"`
	LastToken string   `json:"last_token,omitempty"`
	// Hostgroups is the node's effective placement scope (E6.3): its
	// edge.nodes[].hostgroups, or ["global"] when it lists none; ZonesPlaced
	// counts the zones of the file that scope covers — what the node's
	// document holds.
	Hostgroups  []string `json:"hostgroups"`
	ZonesPlaced int      `json:"zones_placed"`
	// Report is the node's last self-report, VERBATIM and advisory.
	Report     *EdgeReport `json:"report,omitempty"`
	ReportedAt string      `json:"reported_at,omitempty"`
}

// handleEdgeNodes serves the edge-node inventory. Unscoped tokens only, as the
// scrub inventory: node names are deployment topology, not a tenant's business.
func (s *Server) handleEdgeNodes(w http.ResponseWriter, r *http.Request) {
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "the edge node inventory is restricted to unscoped tokens")
		return
	}
	cfg := s.store.Get()
	staleAfter := edgeStaleAfter(cfg)
	doc := EdgeNodesDoc{StaleAfterSeconds: int(staleAfter / time.Second), Nodes: []EdgeNodeStatus{}}
	// Named whenever there are nodes to bind to — scrubbing ones included, so a
	// scrub-only fleet reads it here too, as the authentication guide promises.
	doc.UnboundAgentTokens = cfg.UnboundAgentTokens()
	if cfg.Edge != nil {
		doc.NodesTotal = len(cfg.Edge.Nodes)
		for i := range cfg.Edge.Nodes {
			n := &cfg.Edge.Nodes[i]
			lastSeen, holding := s.edgePresence.seen(n.Name)
			ns := EdgeNodeStatus{
				Name:       n.Name,
				Alive:      s.edgePresence.alive(n.Name, staleAfter),
				Holding:    holding,
				LastToken:  s.edgePresence.lastTokenOf(n.Name),
				Hostgroups: n.Scope(),
			}
			if cfg.ZonesCfg != nil {
				for j := range cfg.ZonesCfg.Zones {
					if n.Serves(&cfg.ZonesCfg.Zones[j]) {
						ns.ZonesPlaced++
					}
				}
			}
			for _, tk := range cfg.API.TokenSpecs {
				if tk.Node == n.Name {
					ns.Tokens = append(ns.Tokens, tk.Name)
				}
			}
			if !lastSeen.IsZero() {
				ns.LastSeen = lastSeen.UTC().Format(time.RFC3339)
			}
			if rep, at, ok := s.edgeReports.get(n.Name); ok {
				rr := rep
				ns.Report = &rr
				ns.ReportedAt = at.UTC().Format(time.RFC3339)
			}
			doc.Nodes = append(doc.Nodes, ns)
		}
	}
	writeJSON(w, http.StatusOK, doc)
}

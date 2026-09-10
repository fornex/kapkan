package api

// GET /api/v1/dataplane/rules — the scrub-node channel (plan task M4.3, freeze
// point F7). A box running `kapkan scrub` long-polls this endpoint and enforces
// what it returns; the poll itself is the node's liveness signal, so this
// handler is deliberately boring and allocation-light — it must stay correct
// while the deployment is under the exact load it exists for.
//
// Protocol: a plain GET returns the current document with a content-hash ETag
// (the dashboard's hashing scheme — see registerDashboard). A GET whose
// If-None-Match names the current ETag is HELD until the ban table changes, the
// hold budget elapses, or the server shuts down; the two latter cases return
// 304 and the client simply polls again. Holds are capped per token and
// globally (429 beyond the cap) so a misbehaving agent cannot pin every serving
// goroutine to a 25-second sleep.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

const (
	// ruleDocVersion versions the document shape, mirroring persistVersion's
	// role for the state file. An agent refuses a version it does not know
	// rather than guessing at fields.
	ruleDocVersion = 1

	// rulesHoldMax is how long a matching If-None-Match poll is held. The
	// DOCUMENTED channel contract is "up to 30 seconds" (api.mdx, and the
	// reverse-proxy guidance that proxy read timeouts must be ≥60s); holding a
	// little under it means a client or proxy sized exactly to the contract
	// never sees us exceed it.
	rulesHoldMax = 25 * time.Second

	// Concurrent-hold caps. A held poll is a parked goroutine plus an open
	// connection, and agents are few: one per scrub node, each holding ONE poll.
	// Four per token forgives a restarting agent whose old holds have not timed
	// out yet; eight overall bounds the whole feature's footprint no matter how
	// many tokens exist. Instant (non-held) responses are never counted.
	maxRuleHoldsPerToken = 4
	maxRuleHoldsTotal    = 8

	// ruleExpiryQuantum coarsens ExpiresAt in the document. Every attack
	// heartbeat moves the live ban's TTL (~1 Hz), and an exact timestamp would
	// make that a new document — turning the long-poll into a 1 Hz firehose for
	// the whole duration of an attack. Truncating to 10s bounds the churn while
	// costing the node at most 10s of mirrored TTL, always in the fail-open
	// direction (its rules lapse slightly EARLIER than the brain's, never
	// later), against a poll that refreshes the document every ≤30s anyway.
	ruleExpiryQuantum = 10 * time.Second
)

// RuleDoc is the versioned document served to scrub nodes. THE JSON CONTRACT IS
// FROZEN HERE (F7): docs and the agent are written against these key names.
// The document must be deterministic — same ban table, same bytes — because the
// ETag is a hash of the encoding; nothing volatile (counters, "generated at"
// timestamps) may ever be added to it.
type RuleDoc struct {
	Version int `json:"version"`
	// Bans is every ban a scrub node may need to enforce, sorted by prefix.
	// Always present (empty array, not null), so an agent can range over it
	// without an existence check.
	Bans []RuleDocBan `json:"bans"`
}

// RuleDocBan is one diverted victim: the prefix whose traffic is (or, dry-run,
// would be) steered to a scrub node, the rules narrowing what to drop there,
// and the TTL the node mirrors. The vocabulary is the state file's banSnapshot
// (target/prefix/method/flowspec/expires_at) — the two describe the same thing
// from two sides of the wire, and giving them different names would be a
// glossary bug waiting for a translator.
type RuleDocBan struct {
	Target netip.Addr   `json:"target"`
	Prefix netip.Prefix `json:"prefix"`
	// Method is always "divert" today; carried anyway so an operator curling
	// the endpoint sees the same word the bans table shows, and so a future
	// method that also belongs here does not need a shape change.
	Method config.MitigationMethod `json:"method"`
	// DryRun mirrors the ban's frozen flag, and its enforcement semantics are
	// frozen with the shape: a node MUST NOT drop or rate-limit for a dry_run
	// entry — count-only, ever. The entry is served (not omitted) so the trial
	// window shows on the node exactly what it shows on the brain. The
	// distinction matters beyond BGP topologies: a dry-run divert announces no
	// route, but on an L2/static insertion the node sees the victim's traffic
	// anyway, and an agent that enforced there would silently turn the brain's
	// watch-only trial into real packet loss.
	DryRun bool `json:"dry_run,omitempty"`
	// ExpiresAt is the ban's TTL, quantized (see ruleExpiryQuantum). The node
	// holds the rules no longer than this even if the brain dies mid-attack.
	ExpiresAt time.Time `json:"expires_at"`
	// FlowSpec is the ban's rule set, the same IR the bans API exposes. A ban
	// diverting to a MANAGED node carries the narrowing rules the node
	// enforces (config.DivertGeneratesRules); it is empty only for a divert
	// that no node claims — an unmanaged scalar next-hop, a third-party
	// scrubber deciding its own policy — in which case the node has nothing to
	// install and the datapath's charter default (PASS) applies.
	FlowSpec []mitigate.FlowSpecRule `json:"flowspec,omitempty"`
}

// buildRuleDoc derives the document from a ban snapshot. Pure — no clock, no
// config, no server — so the doc-shape tests are tables, not fixtures. Only
// ACTIVE bans currently on the divert rung are included: divert is the rung
// whose traffic arrives at a scrub node, while dataplane (this box's own NIC)
// and the pure-BGP rungs are some other machine's job by definition.
func buildRuleDoc(bans []mitigate.Ban) RuleDoc {
	doc := RuleDoc{Version: ruleDocVersion, Bans: []RuleDocBan{}}
	for _, b := range bans {
		if b.State != mitigate.BanActive || b.Method != config.MitigateDivert {
			continue
		}
		doc.Bans = append(doc.Bans, RuleDocBan{
			Target:    b.Target,
			Prefix:    b.Prefix,
			Method:    b.Method,
			DryRun:    b.DryRun,
			ExpiresAt: b.ExpiresAt.UTC().Truncate(ruleExpiryQuantum),
			FlowSpec:  b.FlowSpec,
		})
	}
	sort.Slice(doc.Bans, func(i, j int) bool {
		return doc.Bans[i].Prefix.String() < doc.Bans[j].Prefix.String()
	})
	return doc
}

// ruleDocBytes encodes the document once and derives its ETag from those same
// bytes (sha256, truncated hex, quoted — the dashboard-asset scheme), so the
// header can never disagree with the body it was computed for.
func ruleDocBytes(doc RuleDoc) (body []byte, etag string, err error) {
	body, err = json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, `"` + hex.EncodeToString(sum[:16]) + `"`, nil
}

// ruleSnapshot builds the current document straight from the mitigator.
func (s *Server) ruleSnapshot() ([]byte, string, error) {
	return ruleDocBytes(buildRuleDoc(s.mit.ActiveBans()))
}

// handleDataplaneRules serves the document, long-polling per the protocol
// described at the top of this file.
func (s *Server) handleDataplaneRules(w http.ResponseWriter, r *http.Request) {
	// The document is UNSCOPED: every diverted victim across every tenant, by
	// design — a scrub node filters for the whole deployment (per-node and
	// per-hostgroup scoping is the M5 fleet milestone). So only unscoped tokens
	// may read it; a tenant-scoped operator would otherwise learn every other
	// tenant's victims from one GET. Same rule, same reason as handleReload.
	c := callerFrom(r)
	if !c.unscoped() {
		writeError(w, http.StatusForbidden, "dataplane rules are restricted to unscoped tokens")
		return
	}
	// ?node=<name> is the agent's identity, and THIS REQUEST is the node's
	// liveness signal — the one and only one (a self-report never is; see
	// nodes.go). The name must be a configured scrubbing node: a typo in the
	// agent's controller.name must fail loudly here, not leave a node that
	// polls diligently while the brain counts it dead and re-announces its
	// victims elsewhere. Optional, so an operator's bare curl still works.
	node := r.URL.Query().Get("node")
	// The token↔node binding, before any side effect: a token bound to one node
	// may only poll as that node (node_binding.go; the same helper guards the
	// report path and the edge channel).
	if _, ok := s.nodeActor(w, r, node, "dataplane_rules"); !ok {
		return
	}
	if node != "" {
		// A sighting requires a REAL credential. This is the API's one
		// side-effectful GET, which the POST-only CSRF gate (see guard) does
		// not cover: in token-less open mode, any browser on the operator's
		// machine could otherwise forge presence for a dead node with a
		// cross-origin <img> pointed at the localhost listener. Refused
		// loudly rather than silently unrecorded, so a node polling an
		// open-mode brain reads as a setup error, not as mysteriously dead.
		if c.token == "" {
			writeError(w, http.StatusForbidden, "node identity requires an API token (configure api.tokens)")
			return
		}
		if configuredNode(s.store.Get(), node) == nil {
			writeError(w, http.StatusNotFound, "unknown scrubbing node")
			return
		}
		// Presence is an AGENT's to stamp: an operator polling with ?node= is
		// previewing what that node sees and must not make a dead node look
		// alive (E6.1).
		if stampsPresence(c) {
			s.mit.NodePollStarted(node)
			defer s.mit.NodePollEnded(node)
		}
	}
	body, etag, err := s.ruleSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding rules document failed")
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm == "" || !etagMatches(inm, etag) {
		writeRuleDoc(w, body, etag)
		return
	}

	// The caller already has the current document: hold until it changes.
	release, ok := s.holds.acquire(callerFrom(r).token)
	if !ok {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "too many concurrent rule holds")
		return
	}
	defer release()
	deadline := time.NewTimer(s.rulesHold)
	defer deadline.Stop()
	for {
		// Grab the change channel BEFORE re-reading the table: a change landing
		// between the read and the select must find us already subscribed, or
		// it would sleep here for a full hold despite having news.
		changed := s.mit.RulesChanged()
		body, cur, err := s.ruleSnapshot()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encoding rules document failed")
			return
		}
		if cur != etag {
			writeRuleDoc(w, body, cur)
			return
		}
		select {
		case <-r.Context().Done():
			// Client gone; nothing useful can be written.
			return
		case <-s.quit:
			// Server shutting down: answer NOW so Shutdown is not stalled
			// behind a parked poll. The agent's normal re-poll lands on
			// whoever is up next.
			s.endHold(w, etag)
			return
		case <-deadline.C:
			s.endHold(w, etag)
			return
		case <-changed:
			// Woken; loop to rebuild. The new table may still hash identically
			// (e.g. a change to a non-divert ban), in which case we keep
			// holding out the same deadline rather than returning a spurious
			// "nothing changed" early.
		}
	}
}

// endHold answers a hold that ended for a reason other than a wake (deadline
// or shutdown) with one final look at the table. "Nothing changed" must be
// VERIFIED here, not assumed: TTL heartbeats move a live ban's expiry without a
// broadcast (the wake signal is throttled alongside the persist write), so
// during a sustained attack the document routinely differs by the time the
// deadline fires — and a 304 naming a superseded ETag would cost the agent a
// wasted extra round trip to discover it. On a snapshot error 304 is the safe
// answer: the client re-polls and hits the normal error path.
func (s *Server) endHold(w http.ResponseWriter, etag string) {
	if body, cur, err := s.ruleSnapshot(); err == nil && cur != etag {
		writeRuleDoc(w, body, cur)
		return
	}
	writeRuleNotModified(w, etag)
}

func writeRuleDoc(w http.ResponseWriter, body []byte, etag string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writeRuleNotModified(w http.ResponseWriter, etag string) {
	h := w.Header()
	// The same Cache-Control the 200 carries: RFC 9110 §15.4.5 requires a 304
	// to repeat the metadata the full response would have sent, so a proxy
	// between agent and brain (an anticipated deployment) never "freshens" a
	// stored copy into something more cacheable than we ever offered.
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", etag)
	w.WriteHeader(http.StatusNotModified)
}

// holdGate caps concurrent long-poll holds, per token and overall. It exists
// because a held poll is the one place this API parks a goroutine on purpose,
// and anything parked on purpose needs a bound an attacker doesn't choose.
type holdGate struct {
	mu       sync.Mutex
	perToken int
	total    int
	byToken  map[string]int
	held     int
}

func newHoldGate(perToken, total int) *holdGate {
	return &holdGate{perToken: perToken, total: total, byToken: make(map[string]int)}
}

// setTotal resizes the overall cap (the edge channel scales it with the fleet:
// once every node polls on its own token, a fixed total would be the visible
// ceiling on fleet size). Holds already parked are never evicted; a total below
// the current count simply refuses new holds until releases catch up.
func (g *holdGate) setTotal(total int) {
	g.mu.Lock()
	g.total = total
	g.mu.Unlock()
}

// acquire reserves a hold slot for the given token name ("" in token-less
// open mode — all open-mode callers then share one per-token budget, which is
// fine on a trusted listener). The returned release is idempotent.
func (g *holdGate) acquire(token string) (release func(), ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.held >= g.total || g.byToken[token] >= g.perToken {
		return nil, false
	}
	g.held++
	g.byToken[token]++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.held--
			if g.byToken[token]--; g.byToken[token] <= 0 {
				delete(g.byToken, token) // don't accrue a key per retired token
			}
		})
	}, true
}

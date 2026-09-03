package api

// The brain's half of per-node ACME (edge-spec §3; milestone E3.4): the
// ISSUANCE COORDINATOR. Nodes hold their own keys and run their own ACME
// clients; the brain only (a) serialises issuance per zone — one node orders
// at a time, so a fleet does not burn the CA's duplicate-certificate ceiling
// in one afternoon — and (b) fans a node's pending HTTP-01 challenge out to
// every node through the zones document, so the CA's validation may land on
// any of them.
//
// Both are ADVISORY and IN MEMORY. A slot is a lease with a deadline: a node
// that dies holding it loses it when the deadline passes, a brain that
// restarts forgets every lease and nodes simply ask again, and a node that
// cannot reach the brain orders anyway after a bounded wait (the node side
// documents that). Challenges live ChallengeTTL and then drop out of the
// document. Nothing here touches the config store: the document is DERIVED —
// buildEdgeDoc stays pure and fill() adds the live coordinator state, so the
// content-hash ETag changes exactly when there is news, and the coordinator's
// own broadcast wakes parked long-polls the way Store.Changed does for a
// reload.
//
// TRUST, STATED PLAINLY. An agent token is a certificate-issuing credential:
// a holder can publish a key authorization for any zone the fleet serves,
// and every node will answer it, so the holder's own ACME account can
// validate HTTP-01 for that zone. Binding tokens to nodes is the fleet
// milestone (E6); until then the coordinator narrows what one token can do
// and makes every use visible: a challenge is published only by the node
// that holds the zone's slot, an existing live challenge is never overwritten
// by a different key authorization (first writer wins), each node has a small
// quota of live challenges, and every slot and challenge call is logged with
// the node, the zone and the token's prefix. Rotate the agent token on any
// node compromise.

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

const (
	// issuanceSlotTTL is a slot's lease: long enough for an order with a
	// slow CA, short enough that a dead node does not block its zone for long.
	issuanceSlotTTL = 10 * time.Minute
	// edgeChallengeTTL is how long a fanned-out challenge is served. A CA
	// validates within seconds of Accept.
	edgeChallengeTTL = 10 * time.Minute
	// maxFannedChallenges bounds the table across the fleet; per-node quotas
	// below keep one node from filling it.
	maxFannedChallenges = 1024
	// maxChallengesPerNode is one node's share of live challenges: one order
	// at a time per zone means a handful at most.
	maxChallengesPerNode = 16
	// maxEdgeACMEBodyBytes bounds a slot or challenge request body.
	maxEdgeACMEBodyBytes = 4 << 10
)

var (
	// acmeTokenRe is an ACME token (base64url, no padding); acmeKeyAuthRe a
	// key authorization: token '.' thumbprint.
	acmeTokenRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	acmeKeyAuthRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}\.[A-Za-z0-9_-]{16,256}$`)
)

type issuanceGrant struct {
	node  string
	until time.Time
}

type fannedKey struct {
	zone, token string
}

type fannedChallenge struct {
	node    string
	keyAuth string
	until   time.Time
}

// publishResult is what publish decided.
type publishResult int

const (
	publishOK publishResult = iota
	publishNoSlot
	publishConflict
	publishQuota
	publishFull
)

// issuanceCoordinator is the in-memory slot and challenge table.
type issuanceCoordinator struct {
	mu         sync.Mutex
	grants     map[string]issuanceGrant
	challenges map[fannedKey]fannedChallenge
	changed    atomic.Pointer[chan struct{}]
}

func newIssuanceCoordinator() *issuanceCoordinator {
	return &issuanceCoordinator{grants: make(map[string]issuanceGrant), challenges: make(map[fannedKey]fannedChallenge)}
}

// Changed returns a channel closed on the next change — the Store.Changed
// idiom, so the zones long-poll can select on both.
func (c *issuanceCoordinator) Changed() <-chan struct{} {
	for {
		if p := c.changed.Load(); p != nil {
			return *p
		}
		ch := make(chan struct{})
		if c.changed.CompareAndSwap(nil, &ch) {
			return ch
		}
	}
}

func (c *issuanceCoordinator) notify() {
	if p := c.changed.Swap(nil); p != nil {
		close(*p)
	}
}

// acquire grants zone's slot to node, or reports who holds it. The holder
// re-acquiring extends its lease.
func (c *issuanceCoordinator) acquire(zone, node string, now time.Time) (granted bool, holder string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	if g, ok := c.grants[zone]; ok && g.node != node {
		return false, g.node, g.until
	}
	g := issuanceGrant{node: node, until: now.Add(issuanceSlotTTL).Truncate(time.Second)}
	c.grants[zone] = g
	c.notify()
	return true, node, g.until
}

// release returns zone's slot if node holds it.
func (c *issuanceCoordinator) release(zone, node string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.grants[zone]
	if !ok || g.node != node {
		return false
	}
	delete(c.grants, zone)
	c.notify()
	return true
}

// publish fans out a challenge from node. The node must hold the zone's
// slot; a live challenge for the same (zone, token) with a different key
// authorization is never overwritten; a node may hold maxChallengesPerNode
// live entries; the fleet table is bounded.
func (c *issuanceCoordinator) publish(zone, token, keyAuth, node string, now time.Time) publishResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	if g, ok := c.grants[zone]; !ok || g.node != node {
		return publishNoSlot
	}
	k := fannedKey{zone, token}
	if existing, ok := c.challenges[k]; ok {
		if existing.keyAuth != keyAuth || existing.node != node {
			return publishConflict
		}
		// Idempotent re-publish: refresh the deadline.
		existing.until = now.Add(edgeChallengeTTL).Truncate(time.Second)
		c.challenges[k] = existing
		return publishOK
	}
	mine := 0
	for _, ch := range c.challenges {
		if ch.node == node {
			mine++
		}
	}
	if mine >= maxChallengesPerNode {
		return publishQuota
	}
	if len(c.challenges) >= maxFannedChallenges {
		return publishFull
	}
	c.challenges[k] = fannedChallenge{node: node, keyAuth: keyAuth, until: now.Add(edgeChallengeTTL).Truncate(time.Second)}
	c.notify()
	return publishOK
}

// fill adds the live grants and challenges of the document's zones to it.
// Times are whole seconds and never recomputed, so the encoding — and the
// ETag — is stable while an entry lives.
func (c *issuanceCoordinator) fill(doc *edgedoc.Doc, now time.Time) {
	zones := make(map[string]bool, len(doc.Zones))
	for _, z := range doc.Zones {
		zones[z.Name] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	for k, ch := range c.challenges {
		if !zones[k.zone] {
			continue
		}
		doc.ACMEChallenges = append(doc.ACMEChallenges, edgedoc.Challenge{Zone: k.zone, Token: k.token, KeyAuthorization: ch.keyAuth, ExpiresAt: ch.until})
	}
	sort.Slice(doc.ACMEChallenges, func(i, j int) bool {
		a, b := doc.ACMEChallenges[i], doc.ACMEChallenges[j]
		if a.Zone != b.Zone {
			return a.Zone < b.Zone
		}
		return a.Token < b.Token
	})
	for zone, g := range c.grants {
		if !zones[zone] {
			continue
		}
		doc.IssuanceGrants = append(doc.IssuanceGrants, edgedoc.Grant{Zone: zone, Node: g.node, ExpiresAt: g.until})
	}
	sort.Slice(doc.IssuanceGrants, func(i, j int) bool { return doc.IssuanceGrants[i].Zone < doc.IssuanceGrants[j].Zone })
}

func (c *issuanceCoordinator) sweepLocked(now time.Time) {
	for zone, g := range c.grants {
		if !now.Before(g.until) {
			delete(c.grants, zone)
		}
	}
	for k, ch := range c.challenges {
		if !now.Before(ch.until) {
			delete(c.challenges, k)
		}
	}
}

// edgeACMEZoneKnown reports whether the zones document has this zone.
func (s *Server) edgeACMEZoneKnown(zone string) bool {
	z := s.store.Get().ZonesCfg
	if z == nil {
		return false
	}
	for _, zz := range z.Zones {
		if zz.Name == zone {
			return true
		}
	}
	return false
}

// EdgeSlotRequest is the body of POST /api/v1/edge/nodes/{name}/acme/slot.
type EdgeSlotRequest struct {
	Zone string `json:"zone"`
	// Release gives the slot back instead of asking for it.
	Release bool `json:"release,omitempty"`
}

// EdgeSlotResponse is the answer to a slot request.
type EdgeSlotResponse struct {
	Granted bool `json:"granted"`
	// Holder and RetryAfterSeconds are set when not granted.
	Holder            string `json:"holder,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	// ExpiresAt is the lease deadline when granted; absent otherwise.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// handleEdgeACMESlot serialises issuance per zone.
func (s *Server) handleEdgeACMESlot(w http.ResponseWriter, r *http.Request) {
	name, ok := s.edgeACMECaller(w, r)
	if !ok {
		return
	}
	var req EdgeSlotRequest
	if !decodeEdgeACMEBody(w, r, &req) {
		return
	}
	if req.Release {
		// A release touches only the caller's own grant and is idempotent, so
		// it is honoured even for a zone removed since — a lingering grant
		// would otherwise sit in the document until its lease ran out.
		released := s.edgeIssuance.release(req.Zone, name)
		s.log.Info("edge acme slot released", "node", name, "zone", req.Zone, "held", released)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.edgeACMEZoneKnown(req.Zone) {
		writeError(w, http.StatusNotFound, "unknown zone")
		return
	}
	now := time.Now()
	granted, holder, until := s.edgeIssuance.acquire(req.Zone, name, now)
	resp := EdgeSlotResponse{Granted: granted}
	if granted {
		u := until
		resp.ExpiresAt = &u
	} else {
		resp.Holder = holder
		retry := int(until.Sub(now).Seconds()) + 1
		if retry > 60 {
			retry = 60
		}
		if retry < 1 {
			retry = 1
		}
		resp.RetryAfterSeconds = retry
	}
	s.log.Info("edge acme slot requested", "node", name, "zone", req.Zone, "granted", granted, "holder", holder)
	writeJSON(w, http.StatusOK, resp)
}

// EdgeChallengeRequest is the body of POST /api/v1/edge/nodes/{name}/acme/challenges.
type EdgeChallengeRequest struct {
	Zone             string `json:"zone"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"key_authorization"`
}

// handleEdgeACMEChallenge fans a pending HTTP-01 challenge out to the fleet.
func (s *Server) handleEdgeACMEChallenge(w http.ResponseWriter, r *http.Request) {
	name, ok := s.edgeACMECaller(w, r)
	if !ok {
		return
	}
	var req EdgeChallengeRequest
	if !decodeEdgeACMEBody(w, r, &req) {
		return
	}
	if !s.edgeACMEZoneKnown(req.Zone) {
		writeError(w, http.StatusNotFound, "unknown zone")
		return
	}
	if !acmeTokenRe.MatchString(req.Token) || !acmeKeyAuthRe.MatchString(req.KeyAuthorization) {
		writeError(w, http.StatusBadRequest, "token and key_authorization must be ACME base64url values")
		return
	}
	res := s.edgeIssuance.publish(req.Zone, req.Token, req.KeyAuthorization, name, time.Now())
	tokenPrefix := req.Token
	if len(tokenPrefix) > 8 {
		tokenPrefix = tokenPrefix[:8]
	}
	s.log.Info("edge acme challenge published", "node", name, "zone", req.Zone, "token", tokenPrefix+"…", "result", res)
	switch res {
	case publishOK:
		w.WriteHeader(http.StatusNoContent)
	case publishNoSlot:
		writeError(w, http.StatusConflict, "this node does not hold the zone's issuance slot; acquire it first")
	case publishConflict:
		writeError(w, http.StatusConflict, "a live challenge with this token already exists with a different key authorization")
	case publishQuota:
		writeError(w, http.StatusTooManyRequests, "this node has too many live challenges; let them expire")
	default:
		writeError(w, http.StatusServiceUnavailable, "challenge table is full; retry shortly")
	}
}

// String names a publishResult for logs.
func (p publishResult) String() string {
	switch p {
	case publishOK:
		return "ok"
	case publishNoSlot:
		return "no_slot"
	case publishConflict:
		return "conflict"
	case publishQuota:
		return "quota"
	default:
		return "full"
	}
}

// edgeACMECaller applies the edge channel's rules to an ACME request: unscoped
// token, configured node. It returns the node name.
func (s *Server) edgeACMECaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	if c := callerFrom(r); !c.unscoped() {
		writeError(w, http.StatusForbidden, "edge ACME coordination is restricted to unscoped tokens")
		return "", false
	}
	name := r.PathValue("name")
	if configuredEdgeNode(s.store.Get(), name) == nil {
		writeError(w, http.StatusNotFound, "unknown edge node")
		return "", false
	}
	return name, true
}

func decodeEdgeACMEBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEdgeACMEBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request exceeds 4 KiB")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

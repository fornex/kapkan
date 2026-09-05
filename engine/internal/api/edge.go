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

// buildEdgeDoc derives the document from a loaded zones file. Pure — no clock,
// no server — so the doc-shape tests are tables. A nil zones file (no edge
// block, or the brain has not loaded one) yields the empty document, not an
// error: an edge with nothing to serve is a valid state.
func buildEdgeDoc(z *config.Zones) EdgeDoc {
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
		// Origins keep the file's order: an operator may order upstreams on
		// purpose, and the file is already the deterministic source.
		origins := make([]string, len(zn.Origins))
		copy(origins, zn.Origins)
		doc.Zones = append(doc.Zones, EdgeDocZone{
			Name:          zn.Name,
			Origins:       origins,
			TLS:           EdgeDocTLS{MinVersion: zn.TLS.MinVersion, H3: zn.TLS.H3},
			ACMEDirectory: zn.ACME.Directory,
			ACMEFallback:  zn.ACME.Fallback,
			Policy: EdgeDocPolicy{
				Mode:             zn.Policy.Mode,
				FailureMode:      zn.Policy.FailureMode,
				Challenge:        zn.Policy.Challenge,
				Rate:             EdgeDocRate{RPS: zn.Policy.Rate.RPS, Concurrency: zn.Policy.Rate.Concurrency},
				ChallengeOptions: challengeOptions(zn.Policy.ChallengeOptions),
			},
			ExtraDirectivesFile: zn.ExtraDirectivesFile,
		})
	}
	// Names are unique (the zones file rejects duplicates), so this order is total.
	sort.Slice(doc.Zones, func(i, j int) bool { return doc.Zones[i].Name < doc.Zones[j].Name })
	return doc
}

// challengeOptions resolves the zones file's rung options for the document:
// nil for the defaults (watch-only, nothing exempt) — so a zones file written
// before E4 yields the bytes it always did — and the resolved object
// otherwise.
func challengeOptions(o config.ZoneChallengeOptions) *edgedoc.ChallengeOptions {
	dry := o.DryRun == nil || *o.DryRun
	if dry && len(o.ExemptPaths) == 0 {
		return nil
	}
	paths := make([]string, len(o.ExemptPaths))
	copy(paths, o.ExemptPaths)
	return &edgedoc.ChallengeOptions{DryRun: dry, ExemptPaths: paths}
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

// edgeSnapshot builds the current document: the zones from the config store,
// plus the live issuance slots and fanned-out challenges (edge_acme.go) and
// each zone's clearance keys (edge_clearance.go). buildEdgeDoc stays pure; the
// coordinator adds only entries whose times are fixed for their lifetime and
// the keyring's keys change only at an epoch boundary, so the ETag moves
// exactly when there is news.
func (s *Server) edgeSnapshot() ([]byte, string, error) {
	cfg := s.store.Get()
	doc := buildEdgeDoc(cfg.ZonesCfg)
	now := time.Now()
	s.edgeIssuance.fill(&doc, now)
	if cfg.Edge != nil {
		s.edgeClearance.setPath(cfg.Edge.StateFile)
	}
	s.edgeClearance.fill(&doc, now)
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
// described in rules.go. Unscoped tokens only: the document lists every
// tenant's zones (per-node zone scoping is the fleet milestone), so a scoped
// operator would otherwise learn every other tenant's hostnames from one GET.
func (s *Server) handleEdgeZones(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !c.unscoped() {
		writeError(w, http.StatusForbidden, "the edge zones document is restricted to unscoped tokens")
		return
	}
	// ?node=<name> is the agent's identity and THIS REQUEST is its liveness
	// signal — the one and only one (a self-report never is). Same three rules
	// as the scrub channel: a sighting needs a real credential (this is a
	// side-effectful GET outside the POST-only CSRF gate), the name must be a
	// configured edge node (a typo must fail loudly, not leave a node polling
	// diligently while the brain counts it dead), and token↔node binding is
	// deliberately not enforced yet (fleet milestone — bind BOTH the poll and
	// the report path when it lands).
	if node := r.URL.Query().Get("node"); node != "" {
		if c.token == "" {
			writeError(w, http.StatusForbidden, "node identity requires an API token (configure api.tokens)")
			return
		}
		if configuredEdgeNode(s.store.Get(), node) == nil {
			writeError(w, http.StatusNotFound, "unknown edge node")
			return
		}
		s.edgePresence.pollStarted(node)
		defer s.edgePresence.pollEnded(node)
	}
	body, etag, err := s.edgeSnapshot()
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
		body, cur, err := s.edgeSnapshot()
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
		rotate := time.NewTimer(s.edgeClearance.untilNextChange(time.Now()))
		select {
		case <-r.Context().Done():
			rotate.Stop()
			return
		case <-s.quit:
			// Shutting down: answer NOW so Shutdown is not stalled behind a
			// parked poll. Verified, not assumed — a reload may have landed.
			rotate.Stop()
			s.endEdgeHold(w, etag)
			return
		case <-deadline.C:
			rotate.Stop()
			s.endEdgeHold(w, etag)
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
		case <-rotate.C:
			// An epoch boundary; the next snapshot rotates the keys.
		}
	}
}

// endEdgeHold answers a hold that ended on the deadline or on shutdown with one
// final look at the store, for the same reason endHold does: "nothing changed"
// is verified, so a 304 never names a superseded ETag.
func (s *Server) endEdgeHold(w http.ResponseWriter, etag string) {
	if body, cur, err := s.edgeSnapshot(); err == nil && cur != etag {
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
}

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

func (st *edgeReportStore) put(name string, r EdgeReport, at time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.reports == nil {
		st.reports = make(map[string]storedEdgeReport)
	}
	st.reports[name] = storedEdgeReport{report: r, at: at}
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
	s.edgeReports.put(name, rep, time.Now())
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

func (p *edgePresence) pollStarted(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.state(name)
	st.holding++
	st.lastSeen = time.Now()
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
}

// EdgeNodeStatus is one node in EdgeNodesDoc.
type EdgeNodeStatus struct {
	Name string `json:"name"`
	// Alive is the brain's judgment from the zones poll — never influenced by
	// reports. Holding means a poll is parked open right now.
	Alive    bool   `json:"alive"`
	Holding  bool   `json:"holding"`
	LastSeen string `json:"last_seen,omitempty"`
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
	if cfg.Edge != nil {
		doc.NodesTotal = len(cfg.Edge.Nodes)
		for i := range cfg.Edge.Nodes {
			n := &cfg.Edge.Nodes[i]
			lastSeen, holding := s.edgePresence.seen(n.Name)
			ns := EdgeNodeStatus{
				Name:    n.Name,
				Alive:   s.edgePresence.alive(n.Name, staleAfter),
				Holding: holding,
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

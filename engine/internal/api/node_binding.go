package api

// Token↔node binding (edge-spec §9 risk 6, milestone E6.1). An agent token that
// carries api.tokens[].node is the credential of ONE node, and every route where
// a caller names a node checks the two agree — before the route does anything
// with the name (presence, a stored report, a granted slot, a published key
// authorization). The routes are the six node-identified ones on both
// channels: the edge zones poll (?node=), the edge report, the ACME slot and
// challenge publication, the dataplane rules poll (?node=) and the scrub
// report. A refusal is uniform and quiet — 403 that never names the bound node
// (an existence oracle for the topology otherwise), a rate-limited Warn so a
// misconfigured fleet is one line a minute per token and not a flood, and a
// counter the operator can alert on; never an audit row, which is for actions
// taken, not refused.
//
// Presence is stamped only by AGENT tokens. An operator who polls with ?node=X
// is previewing X's document — useful, and the dry-run of a placement change —
// but must not make a dead node look alive; each poll route applies that rule
// after nodeActor.
//
// An unbound agent token keeps today's behaviour (it may act as any configured
// node) so a fleet migrates at its own pace; the token is named in -check-config,
// in the daemon's log at start and on every reload, and in the edge inventory
// under unbound_agent_tokens, and a hard requirement is scheduled for a MAJOR
// release. There is deliberately no switch to make it hard today.

import (
	"net/http"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// bindingRefusalLogInterval bounds the Warn log to one line per (token,
// presented node) per interval.
const bindingRefusalLogInterval = time.Minute

// nodeActor applies the binding to a request that names node `name` on route
// `route` (a short label for the log and the metric). It returns the caller and
// whether the route may proceed; on refusal it has already written the 403.
//
// The rules: a bound token acting as another node is refused; a bound token on
// a poll that names no node is refused too (the binding says which node it is,
// so a nameless poll from it is a misconfiguration, not an operator's bare curl
// — operators are never bound); an unbound token passes unchanged.
func (s *Server) nodeActor(w http.ResponseWriter, r *http.Request, name, route string) (caller, bool) {
	c := callerFrom(r)
	if c.node == "" {
		return c, true
	}
	if name == "" {
		s.logBindingRefusal(c, "", route, r)
		writeError(w, http.StatusForbidden, "this token is bound to a node; identify as it (?node=<name>)")
		return c, false
	}
	if name != c.node {
		s.logBindingRefusal(c, name, route, r)
		// Never name the bound node: a leaked token must not read the fleet's
		// topology out of the refusal.
		writeError(w, http.StatusForbidden, "this token is bound to another node")
		return c, false
	}
	return c, true
}

// stampsPresence reports whether a caller's poll counts as the node's liveness:
// agent tokens only (bound and matching, or unbound in grace). An operator's
// ?node= is a preview, and in token-less open mode there is no agent at all.
func stampsPresence(c caller) bool {
	return c.role == config.RoleAgent && c.token != ""
}

// logBindingRefusal is the rate-limited Warn plus the counter.
func (s *Server) logBindingRefusal(c caller, presented, route string, r *http.Request) {
	metrics.APINodeBindingRefused.WithLabelValues(route).Inc()
	key := c.token + "\x00" + presented
	now := time.Now()
	s.bindingMu.Lock()
	if s.bindingWarned == nil {
		s.bindingWarned = make(map[string]time.Time)
	}
	last, seen := s.bindingWarned[key]
	if seen && now.Sub(last) < bindingRefusalLogInterval {
		s.bindingMu.Unlock()
		return
	}
	s.bindingWarned[key] = now
	// Keep the map from accruing a key per probing attempt: drop entries older
	// than the interval whenever it grows past a modest size.
	if len(s.bindingWarned) > 256 {
		for k, t := range s.bindingWarned {
			if now.Sub(t) >= bindingRefusalLogInterval {
				delete(s.bindingWarned, k)
			}
		}
	}
	s.bindingMu.Unlock()
	s.log.Warn("node binding refused: the token is bound to another node",
		"token", c.token, "bound", c.node, "presented", presented, "route", route, "remote", r.RemoteAddr)
}

// bindingState is the Server's rate-limiter state for refusal logs.
type bindingState struct {
	bindingMu     sync.Mutex
	bindingWarned map[string]time.Time
}

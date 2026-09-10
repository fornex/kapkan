package api

// Token↔node binding (edge-spec §9 risk 6, milestone E6.1). An agent token that
// carries api.tokens[].node is the credential of ONE node, and every route where
// a caller names a node checks the two agree — before the route does anything
// with the name (presence, a stored report, a granted slot, a published key
// authorization). The routes are the six node-identified ones on both
// channels: the edge zones poll (?node=), the edge report, the ACME slot and
// challenge publication, the dataplane rules poll (?node=) and the scrub
// report. A refusal is uniform and quiet — 403 that never names the bound node
// (an existence oracle for the topology otherwise), a Warn rate-limited per
// TOKEN so a misconfigured or leaked token is one line a minute and never a
// flood, whatever names it presents, and a counter the operator can alert on;
// never an audit row, which is for actions taken, not refused.
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
	"unicode/utf8"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// bindingRefusalLogInterval bounds the Warn log to one line per token per
	// interval. The key is the token — a configured, bounded set — and never
	// the presented name, which the request chooses: a leaked token varying
	// the name must not turn the log into a flood or the limiter into a sink.
	bindingRefusalLogInterval = time.Minute
	// maxBindingWarnedTokens is the limiter map's hard ceiling. The key set is
	// the configured tokens', so it is not reached in practice; it is here so
	// nothing about this map is unbounded.
	maxBindingWarnedTokens = 256
	// maxLoggedNodeName truncates the presented name in the Warn line: node
	// names are short identifiers, and the request's is untrusted input.
	maxLoggedNodeName = 64
)

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

// logBindingRefusal is the counter plus the per-token rate-limited Warn. The
// line says which of the two refusals it was (reason no_node / other_node) and
// carries the presented name truncated.
func (s *Server) logBindingRefusal(c caller, presented, route string, r *http.Request) {
	metrics.APINodeBindingRefused.WithLabelValues(route).Inc()
	now := time.Now()
	s.bindingMu.Lock()
	if s.bindingWarned == nil {
		s.bindingWarned = make(map[string]time.Time)
	}
	last, seen := s.bindingWarned[c.token]
	if seen && now.Sub(last) < bindingRefusalLogInterval {
		s.bindingMu.Unlock()
		return
	}
	if !seen && len(s.bindingWarned) >= maxBindingWarnedTokens {
		// At the ceiling: drop the entries past their interval, and the oldest
		// one if none is, so the map never grows past the cap.
		var oldestKey string
		oldest := now
		for k, t := range s.bindingWarned {
			if now.Sub(t) >= bindingRefusalLogInterval {
				delete(s.bindingWarned, k)
				continue
			}
			if t.Before(oldest) {
				oldest, oldestKey = t, k
			}
		}
		if len(s.bindingWarned) >= maxBindingWarnedTokens && oldestKey != "" {
			delete(s.bindingWarned, oldestKey)
		}
	}
	s.bindingWarned[c.token] = now
	s.bindingMu.Unlock()

	msg, reason := "node binding refused: the token is bound to another node", "other_node"
	if presented == "" {
		msg, reason = "node binding refused: the bound token polled without a node name", "no_node"
	}
	if len(presented) > maxLoggedNodeName {
		cut := maxLoggedNodeName
		for cut > 0 && !utf8.RuneStart(presented[cut]) {
			cut--
		}
		presented = presented[:cut] + "…"
	}
	s.log.Warn(msg, "token", c.token, "bound", c.node, "presented", presented, "reason", reason, "route", route, "remote", r.RemoteAddr)
}

// bindingState is the Server's rate-limiter state for refusal logs.
type bindingState struct {
	bindingMu     sync.Mutex
	bindingWarned map[string]time.Time
}

package api

// POST /api/v1/dataplane/sources — the source-block channel. Whoever already
// terminates the victim's traffic (an nginx, a log exporter, an operator)
// hands Kapkan a source to drop in the XDP data plane, with a TTL. This is
// HTTP awareness without parsing HTTP: the decision is made where the
// requests are visible, the enforcement happens at the cheapest layer.
//
// The enforcement semantics, the anchor choice and every policy refusal live
// in mitigate/sources.go; this file is the HTTP shape around them — parsing,
// tenant scoping, status mapping, audit. The ban guarantees are visible in
// the mapping: a policy refusal is 409 and AUDITED (a refused block is itself
// an operator action), an input mistake is 400, a cross-tenant victim is the
// same uniform 403 the ban endpoints give (no cross-tenant oracle), and an
// unblock miss is 404.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// maxSourceBlockBytes caps the request body, mirroring the node report's cap.
const maxSourceBlockBytes = 1 << 16

type sourceBlockRequest struct {
	// Victim is the protected destination the block is scoped to. Required —
	// it is what tenant scoping binds to, and a victimless "drop this source
	// everywhere" is a broader policy than one caller's evidence supports.
	Victim string `json:"victim"`
	// Source is the address to drop.
	Source string `json:"source"`
	// TTLSeconds is how long the block lives; required for a block (bounded
	// by mitigate.MinSourceBlockTTL/MaxSourceBlockTTL), ignored on unblock.
	TTLSeconds int64 `json:"ttl_seconds"`
	// Reason is an optional caller note, carried into the audit trail.
	Reason string `json:"reason"`
}

// parseSourceBlockBody decodes and address-validates the shared body shape.
func (s *Server) parseSourceBlockBody(w http.ResponseWriter, r *http.Request) (req sourceBlockRequest, victim, source netip.Addr, ok bool) {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSourceBlockBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return req, victim, source, false
	}
	var err error
	if victim, err = netip.ParseAddr(req.Victim); err != nil {
		writeError(w, http.StatusBadRequest, "invalid victim: "+err.Error())
		return req, victim, source, false
	}
	if source, err = netip.ParseAddr(req.Source); err != nil {
		writeError(w, http.StatusBadRequest, "invalid source: "+err.Error())
		return req, victim, source, false
	}
	return req, victim, source, true
}

func (s *Server) handleSourceBlock(w http.ResponseWriter, r *http.Request) {
	req, victim, source, ok := s.parseSourceBlockBody(w, r)
	if !ok {
		return
	}
	c := callerFrom(r)
	// The victim is what a tenant's token is scoped to; uniform refusal, as on
	// /ban — no cross-tenant existence oracle.
	if !visibleAddr(c, s.store.Get(), victim) {
		s.log.Warn("cross-tenant source block refused", "tenant", c.tenant, "victim", victim.String())
		writeError(w, http.StatusForbidden, "victim is outside your tenant")
		return
	}

	sb, err := s.mit.BlockSource(victim, source, time.Duration(req.TTLSeconds)*time.Second, req.Reason)
	if err != nil {
		status := http.StatusConflict // policy refusal — well-formed, refused
		if errors.Is(err, mitigate.ErrSourceBlockInput) {
			status = http.StatusBadRequest
		}
		// A refused block is an auditable operator action, like a refused ban.
		s.writeAudit(auditRow(c, "source_block", "rejected",
			sourceBlockTarget(source, victim), "source", err.Error(), "", false))
		writeError(w, status, err.Error())
		return
	}
	s.writeAudit(auditRow(c, "source_block", "blocked",
		sourceBlockTarget(source, victim), "source", req.Reason, "", sb.DryRun))
	writeJSON(w, http.StatusOK, sb)
}

func (s *Server) handleSourceUnblock(w http.ResponseWriter, r *http.Request) {
	_, victim, source, ok := s.parseSourceBlockBody(w, r)
	if !ok {
		return
	}
	// Tenant check BEFORE the mitigator, so an out-of-tenant pair 403s whether
	// or not it exists — the /unban discipline.
	c := callerFrom(r)
	if !visibleAddr(c, s.store.Get(), victim) {
		s.log.Warn("cross-tenant source unblock refused", "tenant", c.tenant, "victim", victim.String())
		writeError(w, http.StatusForbidden, "victim is outside your tenant")
		return
	}
	sb, err := s.mit.UnblockSource(victim, source)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.writeAudit(auditRow(c, "source_unblock", "removed",
		sourceBlockTarget(source, victim), "source", "", "", sb.DryRun))
	writeJSON(w, http.StatusOK, sb)
}

// sourceBlockTarget renders the pair as one audit target: the source is the
// acted-on object, the victim is the scope it was acted on for.
func sourceBlockTarget(source, victim netip.Addr) string {
	return source.String() + "->" + victim.String()
}

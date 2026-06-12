// Package api exposes the kapkan REST API and Prometheus metrics endpoint.
// It is read-mostly: status, active and recent attacks, and metrics; plus
// guarded mutating endpoints for manual ban/unban and config reload.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/mitigate"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// maxRecentAttacks bounds the in-memory ring of ended attacks.
const maxRecentAttacks = 100

// Attack is the API view of one detected attack (active or historical).
// Group-scoped attacks (a hostgroup's total traffic) carry no target.
type Attack struct {
	Scope     engine.Scope      `json:"scope"`
	Target    netip.Addr        `json:"target"`
	Group     string            `json:"group,omitempty"`
	Direction engine.Direction  `json:"direction"`
	Metric    engine.Metric     `json:"metric"`
	Rate      float64           `json:"rate"`
	Threshold float64           `json:"threshold"`
	Rates     engine.Rates      `json:"rates"`
	Active    bool              `json:"active"`
	BanState  mitigate.BanState `json:"ban_state,omitempty"`
	Route     string            `json:"route,omitempty"`
	DryRun    bool              `json:"dry_run"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   time.Time         `json:"ended_at,omitempty"`
	// Sample is the flow sample captured when the attack was detected.
	Sample *engine.AttackSample `json:"sample,omitempty"`
}

// attackKey identifies an attack in the active table: host attacks by
// address, group attacks by group name (so simultaneous group attacks never
// collide on the invalid target address), each per direction (a host can be
// attacked and attacking at once).
func attackKey(ev engine.Event) string {
	k := ev.Target.String()
	if ev.Scope == engine.ScopeGroup {
		k = "group:" + ev.Group
	}
	return k + "|" + string(ev.Direction)
}

// Server serves the REST API and tracks attack history.
type Server struct {
	store *config.Store
	eng   *engine.Engine
	mit   *mitigate.Mitigator
	log   *slog.Logger
	start time.Time

	mu     sync.Mutex
	active map[string]*Attack // keyed by attackKey
	recent []Attack           // ring of the most recent ended attacks (newest last)
}

// New creates the API server.
func New(store *config.Store, eng *engine.Engine, mit *mitigate.Mitigator, log *slog.Logger) *Server {
	return &Server{
		store:  store,
		eng:    eng,
		mit:    mit,
		log:    log.With("component", "api"),
		start:  time.Now(),
		active: make(map[string]*Attack),
	}
}

// RecordAttackStarted records a newly detected attack for the attacks
// endpoint. ban may be nil.
func (s *Server) RecordAttackStarted(ev engine.Event, ban *mitigate.Ban) {
	a := &Attack{
		Scope:     ev.Scope,
		Target:    ev.Target,
		Group:     ev.Group,
		Direction: ev.Direction,
		Metric:    ev.Metric,
		Rate:      ev.Rate,
		Threshold: ev.Threshold,
		Rates:     ev.Rates,
		Active:    true,
		StartedAt: ev.At,
		Sample:    ev.Sample,
	}
	if ban != nil {
		a.BanState = ban.State
		a.Route = ban.Route
		a.DryRun = ban.DryRun
	} else {
		a.DryRun = s.store.Get().DryRun
	}
	s.mu.Lock()
	s.active[attackKey(ev)] = a
	s.mu.Unlock()
}

// RecordAttackEnded moves an attack from active to the recent ring.
func (s *Server) RecordAttackEnded(ev engine.Event, ban *mitigate.Ban) {
	key := attackKey(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.active[key]
	if a == nil {
		// Defensive path: an AttackEnded arrived without a recorded start
		// (e.g. after an API restart). Populate every field from the event
		// so the recent ring is not left with zero rate/threshold/dry-run.
		a = &Attack{
			Scope:     ev.Scope,
			Target:    ev.Target,
			Group:     ev.Group,
			Direction: ev.Direction,
			Metric:    ev.Metric,
			Rate:      ev.Rate,
			Threshold: ev.Threshold,
			StartedAt: ev.StartedAt,
			DryRun:    s.store.Get().DryRun,
		}
	}
	a.Active = false
	a.EndedAt = ev.At
	a.Rates = ev.Rates
	if ban != nil {
		a.BanState = ban.State
	}
	delete(s.active, key)
	s.recent = append(s.recent, *a)
	if len(s.recent) > maxRecentAttacks {
		s.recent = s.recent[len(s.recent)-maxRecentAttacks:]
	}
}

// Handler builds the HTTP routes. Exposed for httptest-based testing.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/attacks", s.handleAttacks)
	mux.HandleFunc("POST /api/v1/ban", s.handleBan)
	mux.HandleFunc("POST /api/v1/unban", s.handleUnban)
	mux.HandleFunc("POST /api/v1/config/reload", s.handleReload)
	mux.Handle("GET /metrics", promhttp.Handler())
	return mux
}

// ListenAndServe runs the HTTP server until ctx is cancelled, then shuts it
// down gracefully.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.store.Get().API.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		s.log.Info("api listening", "addr", srv.Addr)
		err := srv.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		} else {
			errc <- nil
		}
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errc:
		return err
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.Get()
	s.mu.Lock()
	activeCount := len(s.active)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run":        cfg.DryRun,
		"uptime_seconds": int64(time.Since(s.start).Seconds()),
		"networks":       cfg.Networks,
		"active_attacks": activeCount,
		"active_bans":    len(s.mit.ActiveBans()),
		"thresholds":     cfg.Thresholds,
		"hostgroups":     cfg.Groups,
	})
}

func (s *Server) handleAttacks(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	active := make([]Attack, 0, len(s.active))
	for _, a := range s.active {
		active = append(active, *a)
	}
	// Copy recent newest-first.
	recent := make([]Attack, 0, len(s.recent))
	for i := len(s.recent) - 1; i >= 0; i-- {
		recent = append(recent, s.recent[i])
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"active": active,
		"recent": recent,
	})
}

type ipRequest struct {
	IP string `json:"ip"`
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.parseIPBody(w, r)
	if !ok {
		return
	}
	ban, err := s.mit.ManualBan(addr)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusOK
	if ban.State == mitigate.BanRejected {
		status = http.StatusConflict
	}
	s.log.Warn("manual ban requested", "target", addr.String(), "state", string(ban.State))
	writeJSON(w, status, ban)
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.parseIPBody(w, r)
	if !ok {
		return
	}
	ban, err := s.mit.ManualUnban(addr)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.log.Warn("manual unban requested", "target", addr.String())
	writeJSON(w, http.StatusOK, ban)
}

func (s *Server) handleReload(w http.ResponseWriter, _ *http.Request) {
	cfg, err := s.store.Reload()
	if err != nil {
		s.log.Error("config reload via API failed", "err", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("config reloaded via API")
	writeJSON(w, http.StatusOK, map[string]any{
		"reloaded":   true,
		"dry_run":    cfg.DryRun,
		"thresholds": cfg.Thresholds,
	})
}

// parseIPBody decodes {"ip": "..."} and validates the address.
func (s *Server) parseIPBody(w http.ResponseWriter, r *http.Request) (netip.Addr, bool) {
	var req ipRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ip: "+err.Error())
		return netip.Addr{}, false
	}
	return addr, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

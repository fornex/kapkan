// Package api exposes the kapkan REST API and Prometheus metrics endpoint.
// It is read-mostly: status, active and recent attacks, and metrics; plus
// guarded mutating endpoints for manual ban/unban and config reload.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kapkan-io/kapkan/internal/buildinfo"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/internal/storage"
	"github.com/kapkan-io/kapkan/internal/update"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// maxRecentAttacks bounds the in-memory ring of ended attacks.
const maxRecentAttacks = 100

// Attack is the API view of one detected attack (active or historical).
// Group-scoped attacks (a hostgroup's total traffic) carry no target.
type Attack struct {
	Scope  engine.Scope `json:"scope"`
	Target netip.Addr   `json:"target"`
	Group  string       `json:"group,omitempty"`
	// Tenant is the owning group's tenant, stamped at serialization for
	// attribution (admin views); empty when the group is unlabeled.
	Tenant    string                  `json:"tenant,omitempty"`
	Direction engine.Direction        `json:"direction"`
	Metric    engine.Metric           `json:"metric"`
	Rate      float64                 `json:"rate"`
	Threshold float64                 `json:"threshold"`
	Rates     engine.Rates            `json:"rates"`
	Active    bool                    `json:"active"`
	BanState  mitigate.BanState       `json:"ban_state,omitempty"`
	Method    config.MitigationMethod `json:"method,omitempty"`
	Route     string                  `json:"route,omitempty"`
	// FlowSpec holds the generated FlowSpec rules when the method is flowspec.
	FlowSpec  []mitigate.FlowSpecRule `json:"flowspec,omitempty"`
	DryRun    bool                    `json:"dry_run"`
	StartedAt time.Time               `json:"started_at"`
	EndedAt   time.Time               `json:"ended_at,omitempty"`
	// Sample is the flow sample captured when the attack was detected.
	Sample *engine.AttackSample `json:"sample,omitempty"`
	// Classification is the attack vector inferred at detection time.
	Classification *engine.Classification `json:"classification,omitempty"`
	// Reason explains why the detection fired (threshold provenance, warm-up,
	// protocol shares) — attached at AttackStarted.
	Reason *engine.Reason `json:"reason,omitempty"`
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
	store   *config.Store
	eng     *engine.Engine
	mit     *mitigate.Mitigator
	log     *slog.Logger
	querier storage.Querier
	auditW  storage.Writer  // persists audit records; nil until wired (handlers nil-guard)
	updchk  *update.Checker // optional update-availability source; nil = disabled
	start   time.Time
	ready   atomic.Bool // flipped true once the daemon is fully started (drives /healthz)

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

// SetQuerier attaches the storage read path used by the traffic-history
// endpoint. A nil querier (storage disabled) makes the endpoint report
// history as unavailable rather than failing.
func (s *Server) SetQuerier(q storage.Querier) { s.querier = q }

// SetAuditWriter attaches the storage writer used to persist the audit trail
// (operator-attributed mutations). A no-op writer (storage disabled) is fine;
// handlers also nil-guard so an unset writer never panics.
func (s *Server) SetAuditWriter(w storage.Writer) { s.auditW = w }

// SetUpdateChecker attaches the opt-in update checker whose latest result feeds
// the update_available/latest_version fields on /api/v1/status. Nil (the
// default, when update_check is disabled) reports no update.
func (s *Server) SetUpdateChecker(c *update.Checker) { s.updchk = c }

// writeAudit persists one audit record (best-effort, never blocks) and logs it.
// caller identity, action, and outcome are stamped by the handler.
func (s *Server) writeAudit(row storage.AuditRow) {
	s.log.Info("audit", "action", row.Action, "result", row.Result,
		"operator", row.Operator, "tenant", row.Tenant, "target", row.Target, "reason", row.Reason)
	if s.auditW != nil {
		s.auditW.WriteAudit(row)
	}
}

// auditRow builds an audit record stamped with the caller's identity, the
// current time, and source="api". dryRun marks whether a ban was simulated.
func auditRow(c caller, action, result, target, targetType, reason, banState string, dryRun bool) storage.AuditRow {
	var dr uint8
	if dryRun {
		dr = 1
	}
	return storage.AuditRow{
		EventTime:  time.Now().UTC().Format("2006-01-02 15:04:05"),
		Action:     action,
		Result:     result,
		Operator:   c.token,
		Role:       string(c.role),
		Tenant:     c.tenant,
		Target:     target,
		TargetType: targetType,
		Reason:     reason,
		Source:     "api",
		BanState:   banState,
		DryRun:     dr,
	}
}

// RecordAttackStarted records a newly detected attack for the attacks
// endpoint. ban may be nil.
func (s *Server) RecordAttackStarted(ev engine.Event, ban *mitigate.Ban) {
	a := &Attack{
		Scope:          ev.Scope,
		Target:         ev.Target,
		Group:          ev.Group,
		Direction:      ev.Direction,
		Metric:         ev.Metric,
		Rate:           ev.Rate,
		Threshold:      ev.Threshold,
		Rates:          ev.Rates,
		Active:         true,
		StartedAt:      ev.At,
		Sample:         ev.Sample,
		Classification: ev.Classification,
		Reason:         ev.Reason,
	}
	if ban != nil {
		a.BanState = ban.State
		a.Method = ban.Method
		a.Route = ban.Route
		a.FlowSpec = ban.FlowSpec
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
//
// Read routes require the viewer role, mutating routes the operator role; both
// pass through requireRole, which enforces the configured tokens. /metrics
// (Prometheus scraping) and the dashboard assets (the HTML shell is not secret;
// the data it loads is, via the guarded API) are served without a token.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	read := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.requireRole(config.RoleViewer, h))
	}
	write := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.requireRole(config.RoleOperator, h))
	}
	read("GET /api/v1/status", s.handleStatus)
	read("GET /api/v1/attacks", s.handleAttacks)
	read("GET /api/v1/hosts", s.handleHosts)
	read("GET /api/v1/bans", s.handleBans)
	read("GET /api/v1/traffic", s.handleTraffic)
	read("GET /api/v1/audit", s.handleAudit)
	write("POST /api/v1/ban", s.handleBan)
	write("POST /api/v1/unban", s.handleUnban)
	write("POST /api/v1/config/reload", s.handleReload)
	mux.Handle("GET /metrics", promhttp.Handler())
	// Liveness/readiness probe — unauthenticated (it leaks nothing) so an updater
	// or supervisor can confirm the daemon is fully up after a restart. 503 until
	// every component has started; the API listener only accepts once started, so
	// any 200 here means "config parsed, components up, serving".
	mux.Handle("GET /healthz", http.HandlerFunc(s.handleHealthz))
	s.registerDashboard(mux)
	return mux
}

// SetReady marks the daemon fully started; /healthz returns 200 thereafter.
func (s *Server) SetReady() { s.ready.Store(true) }

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// requireRole enforces the configured API tokens and the route's minimum role.
// When no tokens are configured the API is open (safe only on a trusted
// listener such as the default 127.0.0.1 bind). Otherwise the presented bearer
// token is matched (constant-time) against every configured token's current env
// value — an empty value never matches, so the API fails closed — and the
// highest matching role is taken: no match is 401, a role below the route's
// requirement is 403. Tokens and roles are read per request, so a reload takes
// effect without a restart.
//
// For mutating methods an application/json content type is also required: a
// cross-site request cannot set that header without a CORS preflight (never
// granted), so token-in-header plus JSON closes CSRF.
func (s *Server) requireRole(required config.Role, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens := s.store.Get().API.TokenSpecs
		// No tokens configured: open API (trusted-listener mode), caller is an
		// unscoped admin — identical to pre-RBAC behavior.
		cl := caller{role: config.RoleOperator, tenant: ""}
		if len(tokens) > 0 {
			// Require the exact "Bearer " scheme; a raw header value must not
			// authenticate. Compare against every token without an early exit,
			// taking the highest matching role and its tenant scope.
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			var match config.TokenSpec
			matched := false
			ambiguous := false
			if ok {
				for _, tk := range tokens {
					want := os.Getenv(tk.Env)
					if want == "" {
						continue // env unset/empty → never matches (fail closed)
					}
					if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
						continue
					}
					switch {
					case !matched:
						match, matched = tk, true
					case tk.Role != match.Role || tk.Tenant != match.Tenant:
						// The same bearer matches tokens of DIFFERENT role or
						// tenant (a reused secret): which principal is this?
						// Fail closed rather than pick one — a reuse must never
						// silently widen access. Checked against ALL matches, so
						// a higher-rank token cannot clear the ambiguity.
						ambiguous = true
					}
				}
			}
			if !matched || ambiguous {
				if ambiguous {
					s.log.Error("ambiguous API token: one secret matches tokens of differing role/tenant; refusing")
				}
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
			if match.Role.Rank() < required.Rank() {
				writeError(w, http.StatusForbidden, "this token's role may not perform this action")
				return
			}
			cl = caller{role: match.Role, tenant: match.Tenant, token: match.Name}
		}
		if r.Method == http.MethodPost {
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, cl)))
	})
}

// caller is the authenticated principal for a request: its role and its tenant
// scope ("" = unscoped admin / all tenants). It is derived once in requireRole
// and carried in the request context, so every handler shares one source of
// truth for who is asking.
type caller struct {
	role   config.Role
	tenant string
	// token is the matched API token's Name (for audit attribution); "" in
	// open/token-less mode.
	token string
}

// unscoped reports whether the caller sees and may act on every tenant.
func (c caller) unscoped() bool { return c.tenant == "" }

type callerKey struct{}

// callerFrom returns the caller established by requireRole. Every /api/v1 route
// passes through requireRole, so this is always populated; the zero value (an
// unscoped admin) is only a defensive fallback.
func callerFrom(r *http.Request) caller {
	c, _ := r.Context().Value(callerKey{}).(caller)
	return c
}

// visibleAddr reports whether the caller may see/act on data owned by addr. An
// unscoped caller sees everything; a scoped caller sees an address only when
// its owning group (longest-prefix-match, the same lookup the engine and
// mitigator trust) carries the caller's tenant — default-deny.
func visibleAddr(c caller, cfg *config.Config, addr netip.Addr) bool {
	return c.unscoped() || cfg.GroupFor(addr).Tenant == c.tenant
}

// visibleGroupName reports whether the caller may see a group-scoped item
// (e.g. a total-group attack, which has no single address) identified by group
// name. Unknown group → deny for a scoped caller.
func visibleGroupName(c caller, cfg *config.Config, group string) bool {
	if c.unscoped() {
		return true
	}
	for i := range cfg.Groups {
		if cfg.Groups[i].Name == group {
			return cfg.Groups[i].Tenant == c.tenant
		}
	}
	return false
}

// visibleAttack applies the right predicate by attack scope: host attacks by
// address, group (total) attacks by group name.
func visibleAttack(c caller, cfg *config.Config, a Attack) bool {
	if a.Scope == engine.ScopeGroup {
		return visibleGroupName(c, cfg, a.Group)
	}
	return visibleAddr(c, cfg, a.Target)
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	cfg := s.store.Get()

	// Hostgroups visible to the caller (all for an admin; only matching ones
	// for a scoped tenant — so a tenant never learns another's prefixes,
	// thresholds or BGP posture). The implicit global/fallback group carries
	// deployment-wide config (global thresholds, default BGP attributes), so it
	// is admin-only even when labeled with a tenant.
	groups := make([]config.Group, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		switch {
		case c.unscoped():
			groups = append(groups, g)
		case g.Name == config.GlobalGroup:
			// deployment-wide config — never shown to a scoped token
		case g.Tenant == c.tenant:
			groups = append(groups, g)
		}
	}

	// Counts recomputed over the caller's visible attacks/bans.
	s.mu.Lock()
	activeAttacks := 0
	for _, a := range s.active {
		if visibleAttack(c, cfg, *a) {
			activeAttacks++
		}
	}
	s.mu.Unlock()
	activeBans := 0
	for _, b := range s.mit.ActiveBans() {
		if visibleAddr(c, cfg, b.Target) {
			activeBans++
		}
	}

	resp := map[string]any{
		"dry_run":        cfg.DryRun,
		"uptime_seconds": int64(time.Since(s.start).Seconds()),
		"active_attacks": activeAttacks,
		"active_bans":    activeBans,
		"hostgroups":     groups,
		// role lets the dashboard gate operator-only affordances; unscoped marks
		// an admin token (which also receives networks/thresholds below).
		"role":     string(c.role),
		"unscoped": c.unscoped(),
		// version is build info (not sensitive); shown in Settings to all roles.
		"version": buildVersion(),
	}
	// Update availability (only meaningful when the opt-in check is enabled).
	// Defaults to "no update" so the console can render unconditionally.
	if s.updchk != nil {
		u := s.updchk.Status()
		resp["update_available"] = u.Available
		resp["latest_version"] = u.LatestVersion
		resp["latest_is_security"] = u.Security
		resp["latest_url"] = u.URL
	} else {
		resp["update_available"] = false
	}
	// Global protected networks, thresholds and the deployment's BGP/notify
	// posture describe the whole deployment; reveal them only to an unscoped
	// admin. The dashboard's Settings view renders these (read-only).
	if c.unscoped() {
		resp["networks"] = cfg.Networks
		resp["thresholds"] = cfg.Thresholds
		bgpCommunity := cfg.BGP.CommunityStr
		if bgpCommunity == "" {
			bgpCommunity = cfg.BGP.Community
		}
		neighbors := make([]string, 0, len(cfg.BGP.Neighbors))
		for _, n := range cfg.BGP.Neighbors {
			neighbors = append(neighbors, n.Address)
		}
		resp["bgp"] = map[string]any{
			"local_asn": cfg.BGP.LocalASN, "router_id": cfg.BGP.RouterID,
			"next_hop": cfg.BGP.NextHop, "next_hop6": cfg.BGP.NextHop6,
			"community": bgpCommunity, "local_pref": cfg.BGP.LocalPref, "neighbors": neighbors,
		}
		scrubCommunity := cfg.Scrubbing.CommunityStr
		if scrubCommunity == "" {
			scrubCommunity = cfg.Scrubbing.Community
		}
		resp["scrubbing"] = map[string]any{
			"next_hop": cfg.Scrubbing.NextHop, "next_hop6": cfg.Scrubbing.NextHop6, "community": scrubCommunity,
		}
		// Notify exposes only WHICH channels are enabled, never tokens/URLs.
		resp["notify"] = map[string]any{
			"telegram": cfg.Notify.Telegram.ChatID != "" || cfg.Notify.Telegram.TokenEnv != "",
			"webhook":  cfg.Notify.Webhook.URL != "",
			"slack":    cfg.Notify.Slack.WebhookURL != "",
			"email":    cfg.Notify.Email.SMTPHost != "",
			"exec":     cfg.Notify.Exec.Command != "",
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	cfg := s.store.Get()
	stamp := func(a Attack) Attack {
		if a.Scope == engine.ScopeGroup {
			a.Tenant = groupTenant(cfg, a.Group)
		} else {
			a.Tenant = cfg.GroupFor(a.Target).Tenant
		}
		return a
	}
	s.mu.Lock()
	active := make([]Attack, 0, len(s.active))
	for _, a := range s.active {
		if visibleAttack(c, cfg, *a) {
			active = append(active, stamp(*a))
		}
	}
	// Copy recent newest-first.
	recent := make([]Attack, 0, len(s.recent))
	for i := len(s.recent) - 1; i >= 0; i-- {
		if visibleAttack(c, cfg, s.recent[i]) {
			recent = append(recent, stamp(s.recent[i]))
		}
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"active": active,
		"recent": recent,
	})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	cfg := s.store.Get()
	all := s.eng.Snapshot()
	hosts := make([]engine.HostStat, 0, len(all))
	for _, h := range all {
		if visibleAddr(c, cfg, h.Target) {
			hosts = append(hosts, h)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	cfg := s.store.Get()
	all := s.mit.Snapshot()
	bans := make([]mitigate.Ban, 0, len(all))
	for _, b := range all {
		if visibleAddr(c, cfg, b.Target) {
			bans = append(bans, b)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bans": bans})
}

// handleTraffic serves persisted per-host rate history for the Traffic/Reports
// view. When storage is disabled it returns available:false (not an error), so
// the dashboard shows its extension-point panel instead of breaking.
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if s.querier == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "points": []storage.TrafficPoint{}})
		return
	}
	q := r.URL.Query()
	addr, err := netip.ParseAddr(q.Get("key"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing or invalid key (expected a host address)")
		return
	}
	if c := callerFrom(r); !visibleAddr(c, s.store.Get(), addr) {
		writeError(w, http.StatusForbidden, "target is outside your tenant")
		return
	}
	to := time.Now()
	from := to.Add(-time.Hour)
	if v := q.Get("from"); v != "" {
		t, e := time.Parse(time.RFC3339, v)
		if e != nil {
			writeError(w, http.StatusBadRequest, "invalid from (expected RFC3339)")
			return
		}
		from = t
	}
	if v := q.Get("to"); v != "" {
		t, e := time.Parse(time.RFC3339, v)
		if e != nil {
			writeError(w, http.StatusBadRequest, "invalid to (expected RFC3339)")
			return
		}
		to = t
	}
	if !to.After(from) {
		writeError(w, http.StatusBadRequest, "to must be after from")
		return
	}
	const maxRange = 31 * 24 * time.Hour
	if to.Sub(from) > maxRange {
		writeError(w, http.StatusBadRequest, "time range too large (max 31 days)")
		return
	}
	step := 60
	if v := q.Get("step"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "invalid step (positive integer seconds)")
			return
		}
		step = n
	}
	// Bound the bucket count so a wide range with a tiny step can't force an
	// oversized GROUP BY / response: raise step to keep buckets <= maxBuckets.
	const maxBuckets = 5000
	if span := int(to.Sub(from).Seconds()); span/step > maxBuckets {
		step = (span + maxBuckets - 1) / maxBuckets
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pts, err := s.querier.QueryTraffic(ctx, addr.String(), from, to, step)
	if err != nil {
		s.log.Warn("traffic query failed", "target", addr.String(), "err", err)
		writeError(w, http.StatusBadGateway, "traffic history query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "points": pts})
}

// handleAudit serves the operator-attributed audit trail (who banned/unbanned/
// reloaded, when, and the outcome). It is tenant-scoped server-side: a scoped
// caller sees only its own tenant's records, regardless of any client param.
// Storage disabled → available:false (not an error), like handleTraffic.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.querier == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "events": []storage.AuditRow{}})
		return
	}
	q := r.URL.Query()
	to := time.Now()
	from := to.Add(-time.Hour)
	if v := q.Get("from"); v != "" {
		t, e := time.Parse(time.RFC3339, v)
		if e != nil {
			writeError(w, http.StatusBadRequest, "invalid from (expected RFC3339)")
			return
		}
		from = t
	}
	if v := q.Get("to"); v != "" {
		t, e := time.Parse(time.RFC3339, v)
		if e != nil {
			writeError(w, http.StatusBadRequest, "invalid to (expected RFC3339)")
			return
		}
		to = t
	}
	if !to.After(from) {
		writeError(w, http.StatusBadRequest, "to must be after from")
		return
	}
	const maxRange = 31 * 24 * time.Hour
	if to.Sub(from) > maxRange {
		writeError(w, http.StatusBadRequest, "time range too large (max 31 days)")
		return
	}
	f := storage.AuditFilter{From: from, To: to}
	if a := q.Get("action"); a != "" {
		switch a {
		case "ban", "unban", "config_reload":
			f.Action = a
		default:
			writeError(w, http.StatusBadRequest, "invalid action (ban|unban|config_reload)")
			return
		}
	}
	c := callerFrom(r)
	if t := q.Get("target"); t != "" {
		addr, err := netip.ParseAddr(t)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid target (expected an IP)")
			return
		}
		if !visibleAddr(c, s.store.Get(), addr) {
			writeError(w, http.StatusForbidden, "target is outside your tenant")
			return
		}
		f.Target = addr.String()
	}
	// Tenant scope is enforced server-side: a scoped caller only ever sees its
	// own tenant's rows; the client cannot widen this.
	if !c.unscoped() {
		f.Tenant = c.tenant
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.querier.QueryAudit(ctx, f)
	if err != nil {
		s.log.Warn("audit query failed", "err", err)
		writeError(w, http.StatusBadGateway, "audit query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "events": rows})
}

// groupTenant returns the tenant of the named group, or "" if not found.
func groupTenant(cfg *config.Config, name string) string {
	for i := range cfg.Groups {
		if cfg.Groups[i].Name == name {
			return cfg.Groups[i].Tenant
		}
	}
	return ""
}

type ipRequest struct {
	IP string `json:"ip"`
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.parseIPBody(w, r)
	if !ok {
		return
	}
	c := callerFrom(r)
	if !visibleAddr(c, s.store.Get(), addr) {
		// Uniform refusal: never reveal whether addr is banned, or even in a
		// configured network, to a scoped operator targeting another tenant.
		s.log.Warn("cross-tenant ban refused", "tenant", c.tenant, "target", addr.String())
		writeError(w, http.StatusForbidden, "target is outside your tenant")
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
	// Audit BOTH success and policy rejection — a refused ban is itself an
	// auditable operator action.
	s.writeAudit(auditRow(c, "ban", string(ban.State), addr.String(), "host", ban.Reason, string(ban.State), ban.DryRun))
	writeJSON(w, status, ban)
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	addr, ok := s.parseIPBody(w, r)
	if !ok {
		return
	}
	// Check tenant ownership BEFORE consulting the mitigator, so an
	// out-of-tenant target returns the same 403 whether or not a ban exists —
	// no cross-tenant existence oracle on unban.
	c := callerFrom(r)
	if !visibleAddr(c, s.store.Get(), addr) {
		s.log.Warn("cross-tenant unban refused", "tenant", c.tenant, "target", addr.String())
		writeError(w, http.StatusForbidden, "target is outside your tenant")
		return
	}
	ban, err := s.mit.ManualUnban(addr)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.writeAudit(auditRow(c, "unban", "withdrawn", addr.String(), "host", "", string(ban.State), ban.DryRun))
	writeJSON(w, http.StatusOK, ban)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	// A reload swaps the whole config — every tenant's policy and the token set
	// itself — so it is admin-only; a scoped operator must not be able to
	// disrupt other tenants or rewrite the tenant/token mapping.
	c := callerFrom(r)
	if !c.unscoped() {
		writeError(w, http.StatusForbidden, "config reload is restricted to unscoped (admin) tokens")
		return
	}
	cfg, err := s.store.Reload()
	if err != nil {
		s.log.Error("config reload via API failed", "err", err)
		s.writeAudit(auditRow(c, "config_reload", "error", "", "global", err.Error(), "", false))
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeAudit(auditRow(c, "config_reload", "ok", "", "global", "", "", false))
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

// buildVersion is the human version shown in /api/v1/status and the console
// Settings view: the release version plus the short VCS revision when known.
// The underlying values come from internal/buildinfo (link-time -X injection
// for releases, build-info fallback otherwise).
var buildVersion = sync.OnceValue(func() string {
	v := buildinfo.Version()
	if c := buildinfo.Commit(); c != "" && !strings.Contains(v, c) {
		return v + " · " + c
	}
	return v
})

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Package mitigate announces and withdraws RTBH (remotely-triggered
// blackhole) routes via an embedded gobgp speaker. It enforces the project's
// non-negotiable safety rules: dry-run by default (nothing is sent), a TTL on
// every announcement (no permanent bans), a hard cap on simultaneous bans,
// and an absolute refusal to ever blackhole a whitelisted address.
package mitigate

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"

	"log/slog"
)

// BanState is the lifecycle state of a blackhole ban.
type BanState string

// Ban lifecycle states.
const (
	// BanActive means the route is announced (or, in dry-run, virtually so).
	BanActive BanState = "active"
	// BanWithdrawn means the route has been withdrawn.
	BanWithdrawn BanState = "withdrawn"
	// BanRejected means the ban was refused (cap reached or whitelisted).
	BanRejected BanState = "rejected"
)

// Ban records one blackhole decision and its lifecycle. It is the unit shared
// with the API and notifications.
type Ban struct {
	Target      netip.Addr    `json:"target"`
	Prefix      netip.Prefix  `json:"prefix"`
	Metric      engine.Metric `json:"metric,omitempty"`
	Rate        float64       `json:"rate,omitempty"`
	Threshold   float64       `json:"threshold,omitempty"`
	NextHop     string        `json:"next_hop"`
	Community   string        `json:"community"`
	Route       string        `json:"route"`
	State       BanState      `json:"state"`
	DryRun      bool          `json:"dry_run"`
	Manual      bool          `json:"manual"`
	StartedAt   time.Time     `json:"started_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	WithdrawnAt time.Time     `json:"withdrawn_at,omitempty"`
	Reason      string        `json:"reason,omitempty"`
}

// announcer is the subset of BGP behavior the mitigator needs. It is an
// interface so tests can substitute a recorder for the real gobgp speaker.
type announcer interface {
	Announce(ctx context.Context, prefix netip.Prefix, nextHop string, community uint32) error
	Withdraw(ctx context.Context, prefix netip.Prefix) error
}

// Mitigator owns the ban table and the BGP speaker.
type Mitigator struct {
	store   *config.Store
	log     *slog.Logger
	bgp     announcer
	speaker *bgpSpeaker // nil when an external announcer was injected

	mu   sync.Mutex
	bans map[netip.Addr]*Ban

	now    func() time.Time
	ctx    context.Context
	cancel context.CancelFunc
}

// Option configures a Mitigator.
type Option func(*Mitigator)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(m *Mitigator) {
		if now != nil {
			m.now = now
		}
	}
}

// withAnnouncer injects a custom announcer, bypassing the real speaker
// (tests).
func withAnnouncer(a announcer) Option {
	return func(m *Mitigator) { m.bgp = a }
}

// New constructs a Mitigator and its BGP speaker (unless an announcer was
// injected). The speaker is not started until Start is called.
func New(store *config.Store, log *slog.Logger, opts ...Option) (*Mitigator, error) {
	m := &Mitigator{
		store: store,
		log:   log.With("component", "mitigate"),
		bans:  make(map[netip.Addr]*Ban),
		now:   time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	if m.bgp == nil {
		sp, err := newBGPSpeaker(store.Get(), log)
		if err != nil {
			return nil, fmt.Errorf("create bgp speaker: %w", err)
		}
		m.speaker = sp
		m.bgp = sp
	}
	return m, nil
}

// Start brings up the BGP speaker (peering with neighbors) and launches the
// TTL expiry sweeper. Peering happens even in dry-run so operators can verify
// session establishment before going live; only route announcements are
// gated on dry_run.
func (m *Mitigator) Start(ctx context.Context) error {
	m.ctx, m.cancel = context.WithCancel(ctx)
	if m.speaker != nil {
		if err := m.speaker.start(m.ctx); err != nil {
			return fmt.Errorf("start bgp speaker: %w", err)
		}
	}
	go m.sweepLoop(m.ctx)
	return nil
}

// Stop withdraws nothing (peers are torn down by the speaker, which sends
// CEASE) and stops the speaker and sweeper.
func (m *Mitigator) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.speaker != nil {
		m.speaker.stop()
	}
}

// OnAttackStarted is called when the engine reports a new attack. It returns
// the resulting ban (including a rejected ban when the cap is hit or the
// target is whitelisted), or nil when the event's policy forbids automatic
// mitigation: group-scoped events have no single host to blackhole, and an
// event must explicitly carry BanEnabled — never ban on the zero value.
func (m *Mitigator) OnAttackStarted(ev engine.Event) *Ban {
	if ev.Scope == engine.ScopeGroup || !ev.BanEnabled {
		m.log.Info("automatic ban disabled by policy; alert only",
			"target", ev.Target.String(), "group", ev.Group, "scope", string(ev.Scope))
		return nil
	}
	return m.ban(ev.Target, banOpts{
		metric:    ev.Metric,
		rate:      ev.Rate,
		threshold: ev.Threshold,
		manual:    false,
	})
}

// OnAttackEnded is called when the engine reports an attack ended. It
// withdraws any active ban for the target and returns its final state. The
// withdrawal is NOT gated on BanEnabled: a reload may have disabled banning
// for a group while one of its hosts holds an active ban, and that route
// must still come down when the attack ends.
func (m *Mitigator) OnAttackEnded(ev engine.Event) *Ban {
	if ev.Scope == engine.ScopeGroup {
		return nil
	}
	return m.unban(ev.Target, "attack ended", false)
}

// ManualBan bans target by operator request, respecting the whitelist and the
// cap. It returns an error only for invalid input; policy refusals come back
// as a Ban with State BanRejected.
func (m *Mitigator) ManualBan(target netip.Addr) (*Ban, error) {
	if !target.IsValid() {
		return nil, fmt.Errorf("invalid target address")
	}
	return m.ban(target, banOpts{manual: true}), nil
}

// ManualUnban withdraws a ban by operator request.
func (m *Mitigator) ManualUnban(target netip.Addr) (*Ban, error) {
	if !target.IsValid() {
		return nil, fmt.Errorf("invalid target address")
	}
	b := m.unban(target, "manual unban", true)
	if b == nil {
		return nil, fmt.Errorf("no active ban for %s", target)
	}
	return b, nil
}

type banOpts struct {
	metric    engine.Metric
	rate      float64
	threshold float64
	manual    bool
}

func (m *Mitigator) ban(target netip.Addr, opts banOpts) *Ban {
	cfg := m.store.Get()
	now := m.now()

	// SAFETY RULE: whitelisted addresses are never banned, ever.
	if cfg.IsWhitelisted(target) {
		m.log.Error("refusing to ban whitelisted address",
			"target", target.String(), "manual", opts.manual)
		return &Ban{Target: target, State: BanRejected, Reason: "whitelisted", DryRun: cfg.DryRun}
	}

	// SAFETY RULE: only blackhole inside the configured networks. We must
	// never announce a route for address space we are not responsible for —
	// detection already enforces this, but a manual ban must not bypass it.
	if !cfg.InNetworks(target) {
		m.log.Error("refusing to ban address outside configured networks",
			"target", target.String(), "manual", opts.manual)
		return &Ban{Target: target, State: BanRejected, Reason: "outside configured networks", DryRun: cfg.DryRun}
	}

	prefix := hostPrefix(target)
	nextHop := cfg.BGP.NextHop
	if target.Is6() {
		nextHop = ipv6NextHop(cfg)
	}
	community := cfg.BGP.Community
	route := fmt.Sprintf("%s next-hop %s community %s", prefix, nextHop, community)

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.bans[target]; ok && existing.State == BanActive {
		// Already banned: refresh the TTL while the attack persists so the
		// route is not withdrawn out from under an ongoing attack, but never
		// beyond a fresh TTL from now (still bounded, no permanent ban).
		existing.ExpiresAt = now.Add(cfg.Ban.TTL())
		return copyBan(existing)
	}

	// SAFETY RULE: hard cap on simultaneous bans.
	if m.activeCountLocked() >= cfg.Ban.MaxActiveBans {
		metrics.BansRejectedTotal.Inc()
		m.log.Error("BAN CAP REACHED: refusing new ban to avoid blackholing half the network",
			"target", target.String(), "active", m.activeCountLocked(),
			"max_active_bans", cfg.Ban.MaxActiveBans)
		return &Ban{Target: target, Prefix: prefix, State: BanRejected,
			Reason: "max_active_bans reached", DryRun: cfg.DryRun}
	}

	b := &Ban{
		Target:    target,
		Prefix:    prefix,
		Metric:    opts.metric,
		Rate:      opts.rate,
		Threshold: opts.threshold,
		NextHop:   nextHop,
		Community: community,
		Route:     route,
		State:     BanActive,
		DryRun:    cfg.DryRun,
		Manual:    opts.manual,
		StartedAt: now,
		ExpiresAt: now.Add(cfg.Ban.TTL()),
	}

	if cfg.DryRun {
		m.log.Warn("DRY-RUN: would announce blackhole route (not sent)",
			"route", route, "target", target.String(),
			"metric", string(opts.metric), "manual", opts.manual)
	} else {
		if err := m.bgp.Announce(m.ctx, prefix, nextHop, cfg.BGP.CommunityValue); err != nil {
			m.log.Error("BGP announce failed", "route", route, "err", err)
			b.State = BanRejected
			b.Reason = "bgp announce failed: " + err.Error()
			return b
		}
		m.log.Warn("announced blackhole route", "route", route, "target", target.String())
	}

	m.bans[target] = b
	m.updateGaugeLocked(cfg.DryRun)
	return copyBan(b)
}

func (m *Mitigator) unban(target netip.Addr, reason string, manual bool) *Ban {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bans[target]
	if !ok || b.State != BanActive {
		return nil
	}
	m.withdrawLocked(b, reason, manual)
	return copyBan(b)
}

// copyBan returns a snapshot copy of b. Callers (API, notifications) receive
// copies so they can read ban fields without holding m.mu while the TTL
// sweeper mutates the live ban in the map under the lock.
func copyBan(b *Ban) *Ban {
	c := *b
	return &c
}

// withdrawLocked withdraws a ban. The caller holds m.mu.
func (m *Mitigator) withdrawLocked(b *Ban, reason string, manual bool) {
	if !b.DryRun {
		if err := m.bgp.Withdraw(m.ctx, b.Prefix); err != nil {
			// Log but proceed to mark withdrawn; leaving it "active" would
			// misreport state and block re-bans. Operators are alerted.
			m.log.Error("BGP withdraw failed", "route", b.Route, "err", err)
		} else {
			m.log.Info("withdrew blackhole route", "route", b.Route, "reason", reason)
		}
	} else {
		m.log.Warn("DRY-RUN: would withdraw blackhole route (not sent)",
			"route", b.Route, "reason", reason)
	}
	b.State = BanWithdrawn
	b.WithdrawnAt = m.now()
	b.Reason = reason
	b.Manual = b.Manual || manual
	m.updateGaugeLocked(b.DryRun)
}

// sweepLoop withdraws bans whose TTL has expired (no permanent bans, ever).
func (m *Mitigator) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sweepExpired()
		}
	}
}

func (m *Mitigator) sweepExpired() {
	now := m.now()
	cfg := m.store.Get()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.bans {
		if b.State != BanActive {
			continue
		}
		if !b.ExpiresAt.IsZero() && now.After(b.ExpiresAt) {
			m.log.Warn("ban TTL expired; auto-withdrawing", "route", b.Route,
				"target", b.Target.String())
			m.withdrawLocked(b, "ttl expired", false)
			continue
		}
		// A config reload may have shrunk the networks out from under an
		// active ban (e.g. a manual ban whose prefix was later removed).
		// Withdraw it rather than leave a route up for space we no longer
		// protect; the ban TTL alone would keep it far too long.
		if !cfg.InNetworks(b.Target) {
			m.log.Warn("ban target no longer in configured networks; auto-withdrawing",
				"route", b.Route, "target", b.Target.String())
			m.withdrawLocked(b, "target left configured networks", false)
		}
	}
}

func (m *Mitigator) activeCountLocked() int {
	n := 0
	for _, b := range m.bans {
		if b.State == BanActive {
			n++
		}
	}
	return n
}

func (m *Mitigator) updateGaugeLocked(dryRun bool) {
	mode := "real"
	if dryRun {
		mode = "dry_run"
	}
	metrics.AnnouncedRoutes.WithLabelValues(mode).Set(float64(m.activeCountLocked()))
}

// ActiveBans returns the currently active bans, sorted by target.
func (m *Mitigator) ActiveBans() []Ban {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Ban
	for _, b := range m.bans {
		if b.State == BanActive {
			out = append(out, *b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target.Less(out[j].Target) })
	return out
}

// Snapshot returns a copy of every ban (active and historical), sorted by
// most recent activity first.
func (m *Mitigator) Snapshot() []Ban {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Ban, 0, len(m.bans))
	for _, b := range m.bans {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// DryRun reports whether mitigation is currently in dry-run mode.
func (m *Mitigator) DryRun() bool { return m.store.Get().DryRun }

// hostPrefix returns the /32 or /128 host prefix for addr.
func hostPrefix(addr netip.Addr) netip.Prefix {
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	return netip.PrefixFrom(addr, 128)
}

// ipv6NextHop returns the configured IPv6 blackhole next-hop, falling back to
// the RFC 6666 discard prefix (100::/64) when unset.
func ipv6NextHop(cfg *config.Config) string {
	if cfg.BGP.NextHop6 != "" {
		return cfg.BGP.NextHop6
	}
	return "100::1"
}

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
	"strings"
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
	LocalPref   uint32        `json:"local_pref,omitempty"`
	Route       string        `json:"route"`
	State       BanState      `json:"state"`
	DryRun      bool          `json:"dry_run"`
	Manual      bool          `json:"manual"`
	StartedAt   time.Time     `json:"started_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	WithdrawnAt time.Time     `json:"withdrawn_at,omitempty"`
	Reason      string        `json:"reason,omitempty"`

	// Method is the mitigation method currently applied to this ban; it
	// changes as the escalation ladder advances ("" while at an alert-only
	// stage).
	Method config.MitigationMethod `json:"method"`
	// FlowSpec holds the generated FlowSpec rules for this ban's flowspec
	// stage(s). They are announced while Method is flowspec.
	FlowSpec []FlowSpecRule `json:"flowspec,omitempty"`
	// Escalation is the resolved ladder and EscalationStep the current rung;
	// for a simple single-method ban the ladder has one rung at 0s.
	Escalation     []config.EscalationStage `json:"escalation,omitempty"`
	EscalationStep int                      `json:"escalation_step"`

	// FellBackFrom records the method whose announce the peer rejected, causing
	// this ban to degrade to its fallback (blackhole); empty when no fallback
	// occurred. FellBackReason is its human-readable cause. Surfaced so the API
	// and notifications make a silent FlowSpec-unsupported upstream visible.
	FellBackFrom   config.MitigationMethod `json:"fell_back_from,omitempty"`
	FellBackReason string                  `json:"fell_back_reason,omitempty"`

	// dirMask tracks which attack directions hold this ban (one mitigation
	// covers both). An incoming and an outgoing attack on the same host
	// share the ban; it is withdrawn only when the last direction ends.
	// Zero for manual bans.
	dirMask uint8
	// bhAttrs and divAttrs are the blackhole and divert (scrubbing) BGP
	// attribute sets, frozen at ban time and only populated for the actions the
	// ladder actually uses. Freezing them (next-hop, community set, local-pref
	// together) means a config reload between this ban's creation and a later
	// rung cannot announce a stale mix of attributes. The exported
	// NextHop/Community/LocalPref mirror the CURRENTLY-applied rung's set.
	bhAttrs  blackholeAttrs
	divAttrs blackholeAttrs
}

// dirBit maps an event direction to its mask bit. Events without a
// direction (older consumers, manual paths) count as incoming.
func dirBit(d engine.Direction) uint8 {
	if d == engine.DirOutgoing {
		return 2
	}
	return 1
}

// blackholeAttrs are the BGP path attributes for one host-route announcement
// (blackhole or divert). They are frozen on the ban at creation so a config
// reload cannot change a live ban's route (see the Ban fields below). commStr
// is the human-readable community set for the route string / API; the BGP
// speaker uses only nextHop, communities, and localPref.
type blackholeAttrs struct {
	nextHop     string
	communities []uint32
	commStr     string
	localPref   uint32 // 0 = omit the LOCAL_PREF attribute
}

// announcer is the subset of BGP behavior the mitigator needs. It is an
// interface so tests can substitute a recorder for the real gobgp speaker.
type announcer interface {
	Announce(ctx context.Context, prefix netip.Prefix, attrs blackholeAttrs) error
	Withdraw(ctx context.Context, prefix netip.Prefix) error
	AnnounceFlowSpec(ctx context.Context, rule FlowSpecRule) error
	WithdrawFlowSpec(ctx context.Context, rule FlowSpecRule) error
}

// Mitigator owns the ban table and the BGP speaker.
type Mitigator struct {
	store   *config.Store
	log     *slog.Logger
	bgp     announcer
	speaker *bgpSpeaker // nil when an external announcer was injected

	mu   sync.Mutex
	bans map[netip.Addr]*Ban

	// banWindowStart / bansInWindow implement the ban.max_bans_per_window storm
	// guard as a fixed window. Guarded by mu.
	banWindowStart time.Time
	bansInWindow   int

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
		metric:         ev.Metric,
		rate:           ev.Rate,
		threshold:      ev.Threshold,
		dirMask:        dirBit(ev.Direction),
		direction:      ev.Direction,
		classification: ev.Classification,
		sample:         ev.Sample,
		manual:         false,
	})
}

// OnAttackEnded is called when the engine reports an attack ended. It
// releases the ending direction's hold on the ban and withdraws the route
// once no direction holds it (a host attacked and attacking at once keeps
// its ban until both attacks end). The withdrawal is NOT gated on
// BanEnabled: a reload may have disabled banning for a group while one of
// its hosts holds an active ban, and that route must still come down.
func (m *Mitigator) OnAttackEnded(ev engine.Event) *Ban {
	if ev.Scope == engine.ScopeGroup {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bans[ev.Target]
	if !ok || b.State != BanActive {
		return nil
	}
	b.dirMask &^= dirBit(ev.Direction)
	if b.dirMask != 0 {
		m.log.Info("attack ended in one direction; ban held by the other",
			"target", ev.Target.String(), "ended", string(ev.Direction))
		return copyBan(b)
	}
	if b.Manual {
		// A manual ban is held by the operator, not by traffic. An automatic
		// attack that overlapped it (and set a direction bit on the shared
		// ban) ending must not release it — only ManualUnban or the TTL does.
		m.log.Info("automatic attack ended but ban is manual; keeping it until manual unban or TTL",
			"target", ev.Target.String(), "ended", string(ev.Direction))
		return copyBan(b)
	}
	m.withdrawLocked(b, "attack ended", false)
	return copyBan(b)
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
	metric         engine.Metric
	rate           float64
	threshold      float64
	dirMask        uint8
	direction      engine.Direction
	classification *engine.Classification
	sample         *engine.AttackSample
	manual         bool
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
	group := cfg.GroupFor(target)

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.bans[target]; ok && existing.State == BanActive {
		// Already banned: refresh the TTL while the attack persists so the
		// route/rules are not withdrawn out from under an ongoing attack, but
		// never beyond a fresh TTL from now (still bounded, no permanent ban).
		// A second attack direction adds its hold on the shared mitigation.
		existing.ExpiresAt = now.Add(cfg.Ban.TTL())
		existing.dirMask |= opts.dirMask
		return copyBan(existing)
	}

	// SAFETY RULE: hard cap on simultaneous bans.
	if m.activeCountLocked() >= cfg.Ban.MaxActiveBans {
		metrics.BansRejectedTotal.WithLabelValues("max_active_bans").Inc()
		m.log.Error("BAN CAP REACHED: refusing new ban to avoid blackholing half the network",
			"target", target.String(), "active", m.activeCountLocked(),
			"max_active_bans", cfg.Ban.MaxActiveBans)
		return &Ban{Target: target, Prefix: prefix, State: BanRejected,
			Reason: "max_active_bans reached", DryRun: cfg.DryRun}
	}

	// SAFETY RULE: blast radius (fraction). Never blackhole more than a
	// configured share of our OWN address space — even when every ban is under
	// the count cap, a poisoned baseline or spoofed-source storm could otherwise
	// null-route a large fraction of the network one /32 at a time.
	if cfg.Ban.MaxBannedFraction > 0 {
		if total := cfg.ProtectedAddrs(target.Is6()); total > 0 {
			banned := float64(m.activeCountByFamilyLocked(target.Is6()))
			if (banned+1)/total > cfg.Ban.MaxBannedFraction {
				metrics.BansRejectedTotal.WithLabelValues("blast_radius_fraction").Inc()
				m.log.Error("BLAST-RADIUS CAP: refusing new ban; would exceed max_banned_fraction of protected space",
					"target", target.String(), "family", famLabel(target),
					"banned", int(banned), "protected_addrs", total,
					"max_banned_fraction", cfg.Ban.MaxBannedFraction)
				return &Ban{Target: target, Prefix: prefix, State: BanRejected,
					Reason: "max_banned_fraction reached", DryRun: cfg.DryRun}
			}
		}
	}

	// SAFETY RULE: blast radius (rate). Bound how FAST new bans accrue so a
	// runaway storm is contained even before it reaches the count cap.
	if cfg.Ban.MaxBansPerWindow > 0 {
		win := cfg.Ban.BanWindow()
		if m.banWindowStart.IsZero() || now.Sub(m.banWindowStart) >= win {
			m.banWindowStart = now
			m.bansInWindow = 0
		}
		if m.bansInWindow >= cfg.Ban.MaxBansPerWindow {
			metrics.BansRejectedTotal.WithLabelValues("blast_radius_rate").Inc()
			m.log.Error("BLAST-RADIUS RATE: refusing new ban; max_bans_per_window reached",
				"target", target.String(), "bans_in_window", m.bansInWindow,
				"max_bans_per_window", cfg.Ban.MaxBansPerWindow, "window", win)
			return &Ban{Target: target, Prefix: prefix, State: BanRejected,
				Reason: "max_bans_per_window reached", DryRun: cfg.DryRun}
		}
	}

	b := &Ban{
		Target:     target,
		Prefix:     prefix,
		Metric:     opts.metric,
		Rate:       opts.rate,
		Threshold:  opts.threshold,
		State:      BanActive,
		DryRun:     cfg.DryRun,
		Manual:     opts.manual,
		StartedAt:  now,
		ExpiresAt:  now.Add(cfg.Ban.TTL()),
		dirMask:    opts.dirMask,
		Escalation: group.Escalation,
	}
	// Precompute and FREEZE the announcement inputs for whatever stages the
	// ladder uses: the blackhole and/or divert attribute sets (from the group's
	// resolved BGP/scrubbing attributes, which inherit the global blocks) and
	// the generated FlowSpec rules if any rung is flowspec. A ladder that never
	// uses an action carries no attributes for it.
	// Freeze the blackhole attribute set when any rung blackholes OR when the
	// fallback policy may degrade a failed flowspec/divert announce to blackhole
	// (so the fallback has frozen attributes to announce, like any other rung).
	fallbackToBlackhole := cfg.Ban.FallbackMethod() != ""
	if ladderUsesBlackhole(group.Escalation) ||
		(fallbackToBlackhole && (ladderUsesFlowSpec(group.Escalation) || ladderUsesDivert(group.Escalation))) {
		b.bhAttrs = groupBlackholeAttrs(group, target)
	}
	if ladderUsesDivert(group.Escalation) {
		b.divAttrs = groupDivertAttrs(group, target)
	}
	if ladderUsesFlowSpec(group.Escalation) {
		b.FlowSpec = generateRules(target, opts.direction, opts.classification, opts.sample,
			group.FlowSpecAction, group.FlowSpecRateBps, group.FlowSpecSourceAnchored, group.FlowSpecMinConcentration)
	}

	// Apply the first rung. On announce failure (after any fallback) the ban is
	// rejected.
	if err := m.applyStageLocked(b, 0, cfg); err != nil {
		b.State = BanRejected
		b.Reason = "bgp announce failed: " + err.Error()
		return b
	}

	if cfg.Ban.MaxBansPerWindow > 0 {
		m.bansInWindow++
	}
	m.bans[target] = b
	m.updateGaugeLocked()
	return copyBan(b)
}

// ladderUsesFlowSpec reports whether any rung announces FlowSpec.
func ladderUsesFlowSpec(stages []config.EscalationStage) bool {
	for _, s := range stages {
		if s.Action == config.EscalateFlowSpec {
			return true
		}
	}
	return false
}

// ladderUsesBlackhole reports whether any rung announces an RTBH route.
func ladderUsesBlackhole(stages []config.EscalationStage) bool {
	for _, s := range stages {
		if s.Action == config.EscalateBlackhole {
			return true
		}
	}
	return false
}

// ladderUsesDivert reports whether any rung diverts to a scrubbing center.
func ladderUsesDivert(stages []config.EscalationStage) bool {
	for _, s := range stages {
		if s.Action == config.EscalateDivert {
			return true
		}
	}
	return false
}

// groupBlackholeAttrs builds the frozen blackhole attribute set for target from
// the group's resolved attributes, picking the next-hop by address family.
func groupBlackholeAttrs(g *config.Group, target netip.Addr) blackholeAttrs {
	nh := g.BlackholeNextHop
	if target.Is6() {
		nh = groupNextHop6(g)
	}
	return blackholeAttrs{
		nextHop:     nh,
		communities: g.BlackholeCommunities,
		commStr:     g.BlackholeCommunityStr,
		localPref:   g.LocalPref,
	}
}

// groupDivertAttrs builds the frozen divert (scrubbing) attribute set for
// target. Config validation guarantees the scrubbing next-hop for target's
// family is present whenever the ladder diverts.
func groupDivertAttrs(g *config.Group, target netip.Addr) blackholeAttrs {
	nh := g.ScrubNextHop
	if target.Is6() {
		nh = g.ScrubNextHop6
	}
	return blackholeAttrs{
		nextHop:     nh,
		communities: g.ScrubCommunities,
		commStr:     g.ScrubCommunityStr,
		localPref:   g.ScrubLocalPref,
	}
}

// stageView is everything needed to apply and announce one ladder stage,
// computed without mutating the ban (so an escalation can evaluate the next
// rung before committing to it). attrs is the zero value for none/flowspec.
type stageView struct {
	method config.MitigationMethod
	route  string
	attrs  blackholeAttrs
}

// route families group the methods by the NLRI they announce, so an escalation
// knows whether switching rungs needs an explicit withdraw of the old NLRI.
const (
	rfNone = iota
	rfFlowSpec
	rfUnicast // blackhole and divert share the host-route /32-/128 NLRI
)

func routeFamilyOf(method config.MitigationMethod) int {
	switch method {
	case config.MitigateFlowSpec:
		return rfFlowSpec
	case config.MitigateBlackhole, config.MitigateDivert:
		return rfUnicast
	default:
		return rfNone
	}
}

// stageView maps a ladder stage to its method, route string, and frozen BGP
// attribute set. EscalateNone maps to the empty method (alert only).
func (m *Mitigator) stageView(b *Ban, stage config.EscalationStage) stageView {
	switch stage.Action {
	case config.EscalateFlowSpec:
		return stageView{method: config.MitigateFlowSpec, route: flowSpecSummary(b.FlowSpec)}
	case config.EscalateBlackhole:
		return stageView{method: config.MitigateBlackhole, route: unicastRoute("blackhole", b.Prefix, b.bhAttrs), attrs: b.bhAttrs}
	case config.EscalateDivert:
		return stageView{method: config.MitigateDivert, route: unicastRoute("divert", b.Prefix, b.divAttrs), attrs: b.divAttrs}
	default: // EscalateNone
		return stageView{route: "alert only"}
	}
}

// unicastRoute renders the host-route summary for a blackhole/divert rung.
func unicastRoute(verb string, prefix netip.Prefix, a blackholeAttrs) string {
	route := fmt.Sprintf("%s %s next-hop %s", verb, prefix, a.nextHop)
	if a.commStr != "" {
		route += " community " + a.commStr
	}
	if a.localPref > 0 {
		route += fmt.Sprintf(" local-pref %d", a.localPref)
	}
	return route
}

// setActiveStage records the applied rung on the ban and mirrors its BGP
// attributes onto the exported fields (for the API and notifications).
func setActiveStage(b *Ban, idx int, v stageView) {
	b.EscalationStep = idx
	b.Method = v.method
	b.Route = v.route
	b.NextHop = v.attrs.nextHop
	b.Community = v.attrs.commStr
	b.LocalPref = v.attrs.localPref
}

// applyStageLocked installs the initial ladder rung (idx, with no prior rung
// to withdraw): it announces the stage's action and, only on success, records
// the rung on the ban. A "none" rung announces nothing. The caller holds m.mu.
func (m *Mitigator) applyStageLocked(b *Ban, idx int, cfg *config.Config) error {
	v := m.stageView(b, b.Escalation[idx])
	applied, fellBack, err := m.announceStageLocked(b, v, cfg)
	if err != nil {
		return err
	}
	setActiveStage(b, idx, applied)
	if fellBack {
		b.FellBackFrom = v.method
		b.FellBackReason = "primary announce rejected by peer"
	}
	return nil
}

// announceStageLocked announces stage v for ban b, honoring the configured
// fallback policy: if v's primary method is rejected by the peer and a fallback
// applies (flowspec/divert -> blackhole, unless ban.fallback is "none"), it
// announces the fallback instead — make-before-break is preserved because the
// fallback comes up before any caller withdraws the old rung. It returns the
// stageView actually applied (which the caller records on the ban) and whether a
// fallback was used. On failure of both primary and fallback it returns the
// primary error and leaves b's recorded stage unchanged. The caller holds m.mu.
func (m *Mitigator) announceStageLocked(b *Ban, v stageView, cfg *config.Config) (applied stageView, fellBack bool, err error) {
	if e := m.announceMethodLocked(b, v.method, v.route, v.attrs, cfg); e == nil {
		return v, false, nil
	} else {
		err = e
	}
	if fallbackFor(v.method, cfg) == "" {
		return v, false, err // no fallback for this method (blackhole/alert) or disabled
	}
	fv := m.blackholeStageView(b)
	if e := m.announceMethodLocked(b, fv.method, fv.route, fv.attrs, cfg); e != nil {
		m.log.Error("primary AND fallback announce failed; victim left undefended",
			"target", b.Target.String(), "primary", string(v.method),
			"fallback", string(fv.method), "primary_err", err, "fallback_err", e)
		return v, false, err // report the primary error; ban will be rejected/held
	}
	metrics.MitigateFallbackTotal.WithLabelValues(string(v.method), string(fv.method)).Inc()
	m.log.Warn("primary announce rejected by peer; fell back to blackhole",
		"target", b.Target.String(), "from", string(v.method), "to", string(fv.method), "err", err)
	return fv, true, nil
}

// fallbackFor returns the method to try when primary's announce is rejected, or
// "" when no fallback applies. Only the surgical methods (flowspec, divert)
// degrade; blackhole and alert-only have no fallback. ban.fallback="none"
// disables it entirely.
func fallbackFor(primary config.MitigationMethod, cfg *config.Config) config.MitigationMethod {
	fb := cfg.Ban.FallbackMethod()
	if fb == "" {
		return ""
	}
	if primary == config.MitigateFlowSpec || primary == config.MitigateDivert {
		return fb
	}
	return ""
}

// blackholeStageView builds the stageView for a blackhole fallback from the
// frozen blackhole attributes (populated at ban time whenever a fallback is
// possible).
func (m *Mitigator) blackholeStageView(b *Ban) stageView {
	return stageView{
		method: config.MitigateBlackhole,
		route:  unicastRoute("blackhole", b.Prefix, b.bhAttrs),
		attrs:  b.bhAttrs,
	}
}

// flowSpecSummary renders a one-line summary of a rule set for the Route
// field, logs and notifications.
func flowSpecSummary(rules []FlowSpecRule) string {
	parts := make([]string, 0, len(rules))
	for _, r := range rules {
		parts = append(parts, r.String())
	}
	return "flowspec: " + strings.Join(parts, "; ")
}

// announceMethodLocked installs the given mitigation method for a ban,
// honoring dry-run (log only, never send). It takes the method, route, and
// attribute set explicitly rather than reading b.*, so an escalation can
// announce the next rung while the ban still records the current (working) one
// — make-before-break. Blackhole and divert share this host-route path; only
// the frozen attribute set differs. The caller holds m.mu. On the FlowSpec
// path a partial failure withdraws the rules already installed so the RIB is
// not left half-mitigated.
func (m *Mitigator) announceMethodLocked(b *Ban, method config.MitigationMethod, route string, attrs blackholeAttrs, cfg *config.Config) error {
	if method == "" { // alert-only rung: nothing to announce
		m.log.Info("escalation: alert-only stage (no route announced)",
			"target", b.Target.String())
		return nil
	}
	if cfg.DryRun {
		m.log.Warn("DRY-RUN: would announce mitigation (not sent)",
			"method", string(method), "route", route, "target", b.Target.String(),
			"metric", string(b.Metric), "manual", b.Manual)
		return nil
	}
	if method == config.MitigateFlowSpec {
		for i, r := range b.FlowSpec {
			if err := m.bgp.AnnounceFlowSpec(m.ctx, r); err != nil {
				m.log.Error("FlowSpec announce failed; rolling back", "rule", r.String(), "err", err)
				// Best-effort rollback of every rule already installed. Keep
				// going past a failed withdraw (stopping would orphan the
				// remaining rules), but never swallow it: a failed rollback
				// leaves a rule on the RIB that ban state no longer tracks, so
				// the operator must see it.
				for _, done := range b.FlowSpec[:i] {
					if werr := m.bgp.WithdrawFlowSpec(m.ctx, done); werr != nil {
						m.log.Error("FlowSpec rollback withdraw failed; rule may be orphaned on the RIB",
							"rule", done.String(), "err", werr)
					}
				}
				return err
			}
		}
		m.log.Warn("announced flowspec rules", "route", route, "target", b.Target.String())
		return nil
	}
	// Blackhole or divert: a host route carrying the rung's frozen attributes.
	if err := m.bgp.Announce(m.ctx, b.Prefix, attrs); err != nil {
		m.log.Error("BGP announce failed", "method", string(method), "route", route, "err", err)
		return err
	}
	m.log.Warn("announced host route", "method", string(method), "route", route, "target", b.Target.String())
	return nil
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

// withdrawMethodLocked removes the routes announced by the given method
// without changing ban state. It takes the method explicitly (rather than
// reading b.Method) so an escalation can withdraw the old rung after the new
// one is already up — make-before-break. A "" (alert-only) method or dry-run
// announced nothing, so there is nothing to remove. The caller holds m.mu.
func (m *Mitigator) withdrawMethodLocked(b *Ban, method config.MitigationMethod, route, reason string) {
	switch {
	case method == "":
		// Alert-only rung: nothing was announced.
	case b.DryRun:
		m.log.Warn("DRY-RUN: would withdraw mitigation (not sent)",
			"method", string(method), "route", route, "reason", reason)
	case method == config.MitigateFlowSpec:
		// Withdraw every rule; log but proceed on error (a stuck "active"
		// would misreport state and block re-bans).
		for _, r := range b.FlowSpec {
			if err := m.bgp.WithdrawFlowSpec(m.ctx, r); err != nil {
				m.log.Error("FlowSpec withdraw failed", "rule", r.String(), "err", err)
			}
		}
		m.log.Info("withdrew flowspec rules", "route", route, "reason", reason)
	default: // blackhole or divert: a single host route, withdrawn by prefix
		if err := m.bgp.Withdraw(m.ctx, b.Prefix); err != nil {
			m.log.Error("BGP withdraw failed", "method", string(method), "route", route, "err", err)
		} else {
			m.log.Info("withdrew host route", "method", string(method), "route", route, "reason", reason)
		}
	}
}

// withdrawLocked ends a ban: removes its currently-announced routes and marks
// it withdrawn. The caller holds m.mu.
func (m *Mitigator) withdrawLocked(b *Ban, reason string, manual bool) {
	m.withdrawMethodLocked(b, b.Method, b.Route, reason)
	b.State = BanWithdrawn
	b.WithdrawnAt = m.now()
	b.Reason = reason
	b.Manual = b.Manual || manual
	m.updateGaugeLocked()
}

// escalateLocked advances a still-active ban up its ladder. It jumps straight
// to the highest rung whose delay has elapsed (skipping any intermediate rungs
// so a long-running attack does not waste a tick announcing a rung it would
// immediately supersede) and switches to it make-before-break: the new rung is
// announced FIRST, and only once that succeeds is the old rung withdrawn and
// the step advanced. If the announce fails the ban stays on its current
// (working) rung and the next tick retries. The caller holds m.mu.
func (m *Mitigator) escalateLocked(b *Ban, now time.Time, cfg *config.Config) {
	// Highest rung that is due now.
	target := b.EscalationStep
	elapsed := now.Sub(b.StartedAt)
	for next := b.EscalationStep + 1; next < len(b.Escalation); next++ {
		if elapsed < time.Duration(b.Escalation[next].AfterSeconds)*time.Second {
			break
		}
		target = next
	}
	if target == b.EscalationStep {
		return // nothing new is due
	}

	v := m.stageView(b, b.Escalation[target])
	if v.method == b.Method {
		// Same method as the current rung (e.g. two flowspec rungs): the
		// route is identical, so there is nothing to re-announce or withdraw.
		// Just record that we've climbed to the higher rung.
		b.EscalationStep = target
		return
	}

	// Make-before-break: bring the new rung up before tearing the old one down
	// so the victim is never briefly unprotected during the switch. If the new
	// rung's primary announce is rejected, the configured fallback is applied
	// (and `applied` reflects what actually went up).
	applied, fellBack, err := m.announceStageLocked(b, v, cfg)
	if err != nil {
		m.log.Error("escalation announce failed; staying on current rung",
			"target", b.Target.String(), "from", string(b.Method),
			"to", string(v.method), "step", target, "err", err)
		return
	}
	// Withdraw the old rung only if it lives on a DIFFERENT NLRI family than what
	// was actually applied. A same-family unicast transition (divert→blackhole,
	// or a flowspec-rung that fell back to blackhole over a unicast rung) was
	// already replaced atomically by the announce above (gobgp implicit-withdraw
	// on the shared host-route NLRI), so withdrawing by prefix now would tear
	// down the route we just installed.
	oldMethod, oldRoute := b.Method, b.Route
	if oldMethod != "" && routeFamilyOf(oldMethod) != routeFamilyOf(applied.method) {
		m.withdrawMethodLocked(b, oldMethod, oldRoute, "escalation")
	}
	setActiveStage(b, target, applied)
	if fellBack {
		b.FellBackFrom = v.method
		b.FellBackReason = "primary announce rejected by peer during escalation"
	}
	m.log.Warn("escalated mitigation", "target", b.Target.String(),
		"step", target, "from", string(oldMethod), "method", string(applied.method), "route", applied.route)
	m.updateGaugeLocked()
}

// sweepLoop advances escalation ladders and withdraws bans whose TTL has
// expired (no permanent bans, ever).
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
			continue
		}
		// Still active and protected: advance its escalation ladder if a
		// later rung's delay has now elapsed.
		m.escalateLocked(b, now, cfg)
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

// activeCountByFamilyLocked counts active bans whose target is in the given
// address family, for the blast-radius fraction guard (which is per-family).
func (m *Mitigator) activeCountByFamilyLocked(is6 bool) int {
	n := 0
	for _, b := range m.bans {
		if b.State == BanActive && b.Target.Is6() == is6 {
			n++
		}
	}
	return n
}

// famLabel renders an address family for logs/metrics.
func famLabel(a netip.Addr) string {
	if a.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

// updateGaugeLocked recomputes the announced-route and FlowSpec-rule gauges.
// Each ban is counted into its OWN mode bucket (real|dry_run) using the DryRun
// frozen on it at creation — never a caller-supplied mode — so a config reload
// that flips dry_run cannot misfile a live ban, and a mix of real and dry-run
// bans (possible across such a reload) is reported correctly. Both buckets are
// always set so a flip leaves no stale value behind.
func (m *Mitigator) updateGaugeLocked() {
	var realBans, realFS, dryBans, dryFS int
	for _, b := range m.bans {
		if b.State != BanActive || b.Method == "" {
			// Withdrawn/rejected bans and alert-only rungs announce no route.
			continue
		}
		// Count rules only for bans CURRENTLY on FlowSpec; a ban that merely
		// precomputed rules for a future rung has not announced them yet.
		fs := 0
		if b.Method == config.MitigateFlowSpec {
			fs = len(b.FlowSpec)
		}
		if b.DryRun {
			dryBans++
			dryFS += fs
		} else {
			realBans++
			realFS += fs
		}
	}
	metrics.AnnouncedRoutes.WithLabelValues("real").Set(float64(realBans))
	metrics.AnnouncedRoutes.WithLabelValues("dry_run").Set(float64(dryBans))
	// FlowSpec bans can each carry several rules; surface the real RIB
	// footprint so operators can alert before an upstream's rule limit.
	metrics.FlowSpecRules.WithLabelValues("real").Set(float64(realFS))
	metrics.FlowSpecRules.WithLabelValues("dry_run").Set(float64(dryFS))
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

// groupNextHop6 returns the group's resolved IPv6 blackhole next-hop, falling
// back to the RFC 6666 discard prefix (100::/64) when neither the group nor the
// global bgp block configured one.
func groupNextHop6(g *config.Group) string {
	if g.BlackholeNextHop6 != "" {
		return g.BlackholeNextHop6
	}
	return "100::1"
}

// Package engine is the detection core. It consumes normalized flows on a
// performance-critical hot path, accumulates sampling-corrected per-second
// counters per destination host in sharded maps, and once per second
// evaluates a sliding window against the configured thresholds, emitting
// AttackStarted / AttackEnded events.
//
// Sampling correction: every flow contributes f.Bytes*rate bytes,
// f.Packets*rate packets, and rate flows, where rate is the flow's
// sampling rate. This makes all downstream rates estimates of the real
// (unsampled) traffic, per the project's sampling policy.
package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// numShards is the fixed shard count. Power of two so the index is a mask.
const numShards = 256

// bucket is one second of sampling-corrected traffic for a host. epoch is
// the Unix second it represents; a bucket whose epoch does not match the
// second being read is stale and counts as empty.
type bucket struct {
	epoch   int64
	bytes   uint64
	packets uint64
	flows   uint64
}

// hostState tracks the rolling counters and attack lifecycle for one
// destination host. It is only accessed under its owning shard's lock.
type hostState struct {
	ring       []bucket
	lastSeen   int64 // Unix second of the most recent flow
	inAttack   bool
	metric     Metric
	startedAt  time.Time
	belowSince time.Time // zero while currently above any threshold
	lastRates  Rates
}

type shard struct {
	mu    sync.Mutex
	hosts map[netip.Addr]*hostState
}

// groupState tracks the attack lifecycle of one calculation:total hostgroup.
// The threshold crossed at attack start is stored so the ended event stays
// truthful even if a reload changed (or removed) the group mid-attack.
type groupState struct {
	inAttack   bool
	metric     Metric
	threshold  float64
	startedAt  time.Time
	belowSince time.Time
	lastRates  Rates
}

// Engine is the detection core. Construct with New, feed flows with Process
// or ProcessBatch, drive evaluation with Run, and consume Events.
type Engine struct {
	store     *config.Store
	shards    [numShards]*shard
	windowSec int64
	ringSize  int

	// groups holds total-group attack state. It is touched only by evalTick,
	// which runs on the single Run goroutine, so it needs no lock.
	groups map[string]*groupState

	events chan Event
	now    func() time.Time
	log    *slog.Logger
}

// Option configures an Engine.
type Option func(*Engine)

// WithWindow sets the sliding window length in seconds (default 5).
func WithWindow(seconds int) Option {
	return func(e *Engine) {
		if seconds > 0 {
			e.windowSec = int64(seconds)
		}
	}
}

// WithClock overrides the time source. Used by tests for deterministic
// simulated time.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// WithEventBuffer sets the event channel buffer size (default 256).
func WithEventBuffer(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.events = make(chan Event, n)
		}
	}
}

// WithLogger sets the structured logger (default slog.Default).
func WithLogger(l *slog.Logger) Option {
	return func(e *Engine) {
		if l != nil {
			e.log = l
		}
	}
}

// New creates an Engine reading thresholds and policy from store.
func New(store *config.Store, opts ...Option) *Engine {
	e := &Engine{
		store:     store,
		windowSec: 5,
		groups:    make(map[string]*groupState),
		events:    make(chan Event, 256),
		now:       time.Now,
		log:       slog.Default(),
	}
	for _, o := range opts {
		o(e)
	}
	e.ringSize = int(e.windowSec) + 1
	for i := range e.shards {
		e.shards[i] = &shard{hosts: make(map[netip.Addr]*hostState)}
	}
	return e
}

// Events returns the channel on which attack lifecycle events are emitted.
// The engine never closes it; consumers should select on ctx.Done too.
func (e *Engine) Events() <-chan Event { return e.events }

// shardFor returns the shard owning addr. The hash is an FNV-1a over the
// 16-byte address form, computed without heap allocation.
func (e *Engine) shardFor(addr netip.Addr) *shard {
	b := addr.As16()
	var h uint32 = 2166136261
	for i := 0; i < 16; i++ {
		h ^= uint32(b[i])
		h *= 16777619
	}
	return e.shards[h&(numShards-1)]
}

// Process records a single flow. It is safe for concurrent use and is the
// hot path: no allocation occurs for an already-tracked destination.
//
// Only the destination matters for detection, and only destinations inside
// the configured networks are tracked at all; everything else returns
// immediately so unmonitored traffic costs nothing beyond the lookup.
func (e *Engine) Process(f flow.Flow) {
	dst := f.DstAddr
	if !dst.IsValid() {
		return
	}
	cfg := e.store.Get()
	if !cfg.InNetworks(dst) {
		return
	}
	rate := f.SamplingRate
	if rate == 0 {
		rate = 1
	}
	epoch := e.now().Unix()

	sh := e.shardFor(dst)
	sh.mu.Lock()
	hs := sh.hosts[dst]
	if hs == nil {
		hs = &hostState{ring: make([]bucket, e.ringSize)}
		sh.hosts[dst] = hs
	}
	b := &hs.ring[epoch%int64(e.ringSize)]
	if b.epoch != epoch {
		b.epoch = epoch
		b.bytes = 0
		b.packets = 0
		b.flows = 0
	}
	b.bytes += f.Bytes * rate
	b.packets += f.Packets * rate
	b.flows += rate
	hs.lastSeen = epoch
	sh.mu.Unlock()
}

// ProcessBatch records a batch of flows and observes the batch processing
// latency. Prefer it over per-flow Process from the ingest fan-out.
func (e *Engine) ProcessBatch(flows []flow.Flow) {
	if len(flows) == 0 {
		return
	}
	start := e.now()
	for i := range flows {
		e.Process(flows[i])
	}
	metrics.ProcessLatency.Observe(e.now().Sub(start).Seconds())
}

// Run drives once-per-second evaluation until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.evalTick(e.now())
		}
	}
}

// windowedRates sums the window's completed seconds [now-window, now-1] for
// host hs and returns the sampling-corrected per-second averages. The
// current (in-progress) second is excluded so a partially filled bucket
// never dilutes the average. ok is false when the window holds no data.
func (e *Engine) windowedRates(hs *hostState, nowSec int64) (Rates, bool) {
	var sumBytes, sumPackets, sumFlows uint64
	var any bool
	for s := nowSec - e.windowSec; s <= nowSec-1; s++ {
		b := &hs.ring[s%int64(e.ringSize)]
		if b.epoch == s {
			sumBytes += b.bytes
			sumPackets += b.packets
			sumFlows += b.flows
			any = true
		}
	}
	w := float64(e.windowSec)
	return Rates{
		PPS:         float64(sumPackets) / w,
		Mbps:        float64(sumBytes) * 8 / 1e6 / w,
		FlowsPerSec: float64(sumFlows) / w,
	}, any
}

// evalTick evaluates every tracked host once. now is the wall clock at the
// top of the current second; the window covers the completed seconds before
// it. Quiet, non-attacking hosts are evicted to bound memory. Hosts owned by
// a calculation:total group feed the group's summed rates instead of being
// evaluated individually; the group totals are evaluated after the host scan.
func (e *Engine) evalTick(now time.Time) {
	cfg := e.store.Get()
	hysteresis := cfg.Ban.UnbanHysteresis()
	nowSec := now.Unix()
	staleBefore := nowSec - e.windowSec

	// Running sums for total groups, indexed like cfg.Groups. Built fresh
	// each tick — once per second, not on the hot path.
	totals := make([]Rates, len(cfg.Groups))

	var active int
	var tracked int
	for _, sh := range e.shards {
		sh.mu.Lock()
		for addr, hs := range sh.hosts {
			rates, ok := e.windowedRates(hs, nowSec)
			hs.lastRates = rates

			evictOrTrack := func() {
				if !hs.inAttack && !ok && hs.lastSeen < staleBefore {
					delete(sh.hosts, addr)
				} else {
					tracked++
				}
			}

			// Hosts that left the monitored networks after a reload are
			// never acted on; end a mid-attack state explicitly so
			// mitigation withdraws the route instead of waiting for TTL.
			if !cfg.InNetworks(addr) {
				if hs.inAttack {
					e.endAttack(addr, hs, rates, cfg.GroupFor(addr), now, "policy change")
				}
				evictOrTrack()
				continue
			}

			gi := cfg.GroupIndexFor(addr)
			g := &cfg.Groups[gi]

			// Members of a total group only feed the group's sum — including
			// whitelisted hosts, since group totals are informational and
			// never ban. A host mid-attack that a reload moved into a total
			// group has its per-host attack closed out.
			if g.Calc == config.CalcTotal {
				totals[gi].PPS += rates.PPS
				totals[gi].Mbps += rates.Mbps
				totals[gi].FlowsPerSec += rates.FlowsPerSec
				if hs.inAttack {
					e.endAttack(addr, hs, rates, g, now, "policy change")
				}
				evictOrTrack()
				continue
			}

			// Whitelisted hosts are never acted on (safety rule), even when
			// a reload whitelists one mid-attack.
			if cfg.IsWhitelisted(addr) {
				if hs.inAttack {
					e.endAttack(addr, hs, rates, g, now, "policy change")
				}
				evictOrTrack()
				continue
			}

			metric, rate, threshold, exceeded := evaluate(rates, g.Thresholds)

			if exceeded {
				if !hs.inAttack {
					hs.inAttack = true
					hs.metric = metric
					hs.startedAt = now
					active++
					metrics.AttacksTotal.Inc()
					e.log.Warn("attack detected",
						"target", addr.String(), "group", g.Name,
						"metric", string(metric),
						"rate", rate, "threshold", threshold,
						"pps", rates.PPS, "mbps", rates.Mbps,
						"flows_per_sec", rates.FlowsPerSec)
					e.emit(Event{
						Kind:       AttackStarted,
						Scope:      ScopeHost,
						Target:     addr,
						Group:      g.Name,
						BanEnabled: g.BanEnabled,
						Metric:     metric,
						Rate:       rate,
						Threshold:  threshold,
						Rates:      rates,
						At:         now,
					})
				} else {
					active++
				}
				hs.belowSince = time.Time{}
			} else if hs.inAttack {
				if hs.belowSince.IsZero() {
					hs.belowSince = now
				}
				if now.Sub(hs.belowSince) >= hysteresis {
					e.endAttack(addr, hs, rates, g, now, "below threshold")
				} else {
					active++ // still considered active during hysteresis
				}
			}

			evictOrTrack()
		}
		sh.mu.Unlock()
	}

	active += e.evalGroups(cfg, totals, hysteresis, now)

	metrics.ActiveAttacks.Set(float64(active))
	metrics.TrackedHosts.Set(float64(tracked))
}

// evalGroups runs the attack lifecycle for every calculation:total group on
// its summed rates and closes out state for groups a reload removed. It
// returns the number of currently active group attacks.
func (e *Engine) evalGroups(cfg *config.Config, totals []Rates, hysteresis time.Duration, now time.Time) int {
	var active int
	current := make(map[string]bool, len(e.groups))
	for gi := range cfg.Groups {
		g := &cfg.Groups[gi]
		if g.Calc != config.CalcTotal {
			continue
		}
		current[g.Name] = true
		gs := e.groups[g.Name]
		if gs == nil {
			gs = &groupState{}
			e.groups[g.Name] = gs
		}
		rates := totals[gi]
		gs.lastRates = rates

		metric, rate, threshold, exceeded := evaluate(rates, g.Thresholds)
		if exceeded {
			if !gs.inAttack {
				gs.inAttack = true
				gs.metric = metric
				gs.threshold = threshold
				gs.startedAt = now
				metrics.AttacksTotal.Inc()
				e.log.Warn("group attack detected",
					"group", g.Name, "metric", string(metric),
					"rate", rate, "threshold", threshold,
					"pps", rates.PPS, "mbps", rates.Mbps,
					"flows_per_sec", rates.FlowsPerSec)
				e.emit(Event{
					Kind:      AttackStarted,
					Scope:     ScopeGroup,
					Group:     g.Name,
					Metric:    metric,
					Rate:      rate,
					Threshold: threshold,
					Rates:     rates,
					At:        now,
				})
			}
			gs.belowSince = time.Time{}
			active++
		} else if gs.inAttack {
			if gs.belowSince.IsZero() {
				gs.belowSince = now
			}
			if now.Sub(gs.belowSince) >= hysteresis {
				e.endGroupAttack(g.Name, gs, rates, now, "below threshold")
			} else {
				active++
			}
		}
	}

	// Groups removed (or switched to per_host) by a reload: close out any
	// attack in flight so consumers see an end event, then drop the state.
	for name, gs := range e.groups {
		if current[name] {
			continue
		}
		if gs.inAttack {
			e.endGroupAttack(name, gs, gs.lastRates, now, "policy change")
		}
		delete(e.groups, name)
	}
	return active
}

// endGroupAttack clears one total group's attack state and emits AttackEnded.
func (e *Engine) endGroupAttack(name string, gs *groupState, rates Rates, now time.Time, reason string) {
	gs.inAttack = false
	gs.belowSince = time.Time{}
	e.log.Info("group attack ended",
		"group", name, "metric", string(gs.metric),
		"reason", reason, "duration", now.Sub(gs.startedAt).String(),
		"pps", rates.PPS, "mbps", rates.Mbps, "flows_per_sec", rates.FlowsPerSec)
	e.emit(Event{
		Kind:      AttackEnded,
		Scope:     ScopeGroup,
		Group:     name,
		Metric:    gs.metric,
		Rate:      rateFor(rates, gs.metric),
		Threshold: gs.threshold,
		Rates:     rates,
		At:        now,
		StartedAt: gs.startedAt,
	})
}

// endAttack clears the attack state of one host and emits AttackEnded
// carrying the last measurement, the original trigger metric, and the
// owning group's configured threshold. Callers hold the owning shard's lock.
func (e *Engine) endAttack(addr netip.Addr, hs *hostState, rates Rates, g *config.Group, now time.Time, reason string) {
	hs.inAttack = false
	hs.belowSince = time.Time{}
	e.log.Info("attack ended",
		"target", addr.String(), "group", g.Name, "metric", string(hs.metric),
		"reason", reason, "duration", now.Sub(hs.startedAt).String(),
		"pps", rates.PPS, "mbps", rates.Mbps, "flows_per_sec", rates.FlowsPerSec)
	e.emit(Event{
		Kind:       AttackEnded,
		Scope:      ScopeHost,
		Target:     addr,
		Group:      g.Name,
		BanEnabled: g.BanEnabled,
		Metric:     hs.metric,
		Rate:       rateFor(rates, hs.metric),
		Threshold:  thresholdFor(g.Thresholds, hs.metric),
		Rates:      rates,
		At:         now,
		StartedAt:  hs.startedAt,
	})
}

// rateFor returns the component of r selected by m.
func rateFor(r Rates, m Metric) float64 {
	switch m {
	case MetricMbps:
		return r.Mbps
	case MetricFPS:
		return r.FlowsPerSec
	default:
		return r.PPS
	}
}

// thresholdFor returns the configured threshold selected by m.
func thresholdFor(th config.Thresholds, m Metric) float64 {
	switch m {
	case MetricMbps:
		return float64(th.Mbps)
	case MetricFPS:
		return float64(th.FlowsPerSec)
	default:
		return float64(th.PPS)
	}
}

// evaluate compares rates against thresholds and reports the first metric
// crossed (pps, then mbps, then flows_per_sec). A zero threshold is treated
// as disabled, though validation forbids that in practice.
func evaluate(r Rates, th config.Thresholds) (Metric, float64, float64, bool) {
	if th.PPS > 0 && r.PPS > float64(th.PPS) {
		return MetricPPS, r.PPS, float64(th.PPS), true
	}
	if th.Mbps > 0 && r.Mbps > float64(th.Mbps) {
		return MetricMbps, r.Mbps, float64(th.Mbps), true
	}
	if th.FlowsPerSec > 0 && r.FlowsPerSec > float64(th.FlowsPerSec) {
		return MetricFPS, r.FlowsPerSec, float64(th.FlowsPerSec), true
	}
	return "", 0, 0, false
}

// emit delivers an event without blocking the evaluation loop. If the
// consumer has fallen a full buffer behind, the event is dropped with an
// error log: a stalled evaluator would freeze detection for every host,
// which is worse than one lost notification.
func (e *Engine) emit(ev Event) {
	select {
	case e.events <- ev:
	default:
		e.log.Error("engine event channel full, dropping event",
			"kind", ev.Kind.String(), "target", ev.Target.String())
	}
}

// HostStat is a read-only snapshot of one tracked host for the API.
type HostStat struct {
	Target   netip.Addr `json:"target"`
	Group    string     `json:"group"`
	Rates    Rates      `json:"rates"`
	InAttack bool       `json:"in_attack"`
	Metric   Metric     `json:"metric,omitempty"`
}

// Snapshot returns the current windowed rates for every tracked host. It is
// O(tracked hosts) and intended for the API, not the hot path.
func (e *Engine) Snapshot() []HostStat {
	cfg := e.store.Get()
	nowSec := e.now().Unix()
	var out []HostStat
	for _, sh := range e.shards {
		sh.mu.Lock()
		for addr, hs := range sh.hosts {
			rates, _ := e.windowedRates(hs, nowSec)
			st := HostStat{
				Target:   addr,
				Group:    cfg.GroupFor(addr).Name,
				Rates:    rates,
				InAttack: hs.inAttack,
			}
			if hs.inAttack {
				st.Metric = hs.metric
			}
			out = append(out, st)
		}
		sh.mu.Unlock()
	}
	return out
}

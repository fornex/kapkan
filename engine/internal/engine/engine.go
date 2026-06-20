// Package engine is the detection core. It consumes normalized flows on a
// performance-critical hot path, accumulates sampling-corrected per-second
// counters per host in sharded maps — split by direction (incoming/outgoing)
// and protocol class (total/tcp/udp/icmp/tcp-syn/fragments) — and once per
// second evaluates a sliding window against the configured thresholds,
// emitting AttackStarted / AttackEnded events.
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
	"github.com/kapkan-io/kapkan/internal/geoip"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// numShards is the fixed shard count. Power of two so the index is a mask.
const numShards = 256

// protoClass indexes the per-protocol counter arrays. clTotal aggregates
// everything; the others are carved out by IP protocol (plus the pure-SYN
// and fragment signatures, which overlap their base class).
type protoClass int

// Counter classes.
const (
	clTotal protoClass = iota
	clTCP
	clUDP
	clICMP
	clTCPSYN
	clFrag
	numClasses
)

// counters is one second of sampling-corrected traffic for one direction.
// Flows are counted for the total class only; per-protocol thresholds are
// expressed in pps/mbps, mirroring the config.
type counters struct {
	bytes   [numClasses]uint64
	packets [numClasses]uint64
	flows   uint64
}

// add accumulates o into c.
func (c *counters) add(o *counters) {
	for i := range c.bytes {
		c.bytes[i] += o.bytes[i]
		c.packets[i] += o.packets[i]
	}
	c.flows += o.flows
}

// rates converts window-summed counters into per-second averages over a
// window of w seconds.
func (c *counters) rates(w float64) Rates {
	pps := func(i protoClass) float64 { return float64(c.packets[i]) / w }
	mbps := func(i protoClass) float64 { return float64(c.bytes[i]) * 8 / 1e6 / w }
	return Rates{
		PPS:         pps(clTotal),
		Mbps:        mbps(clTotal),
		FlowsPerSec: float64(c.flows) / w,
		TCPPPS:      pps(clTCP),
		TCPMbps:     mbps(clTCP),
		UDPPPS:      pps(clUDP),
		UDPMbps:     mbps(clUDP),
		ICMPPPS:     pps(clICMP),
		ICMPMbps:    mbps(clICMP),
		TCPSYNPPS:   pps(clTCPSYN),
		TCPSYNMbps:  mbps(clTCPSYN),
		FragPPS:     pps(clFrag),
		FragMbps:    mbps(clFrag),
	}
}

// bucket is one second of traffic for a host, both directions. epoch is the
// Unix second it represents; a bucket whose epoch does not match the second
// being read is stale and counts as empty.
type bucket struct {
	epoch int64
	dirs  [2]counters
}

// attackState is the lifecycle of one (host or group, direction) attack.
// The threshold crossed at attack start is stored so the ended event stays
// truthful even if a reload changed the thresholds mid-attack.
type attackState struct {
	inAttack  bool
	metric    Metric
	threshold float64
	// effThresholds is the full effective threshold set frozen at attack
	// start and used for the whole attack's end decision. Freezing it
	// keeps the lifecycle consistent: an attack that began on the static
	// thresholds (baseline not yet warmed) is not silently re-tightened to
	// the learned thresholds when warm-up elapses mid-attack.
	effThresholds config.Thresholds
	startedAt     time.Time
	belowSince    time.Time // zero while currently above any threshold
}

// hostState tracks the rolling counters, per-direction attack lifecycle and
// learned baselines for one host. It is only accessed under its owning
// shard's lock. Eviction discards the baselines with the rest of the state;
// a returning host re-warms up.
type hostState struct {
	ring      []bucket
	lastSeen  int64 // Unix second of the most recent flow
	attacks   [2]attackState
	baselines [2]baselineState
}

// inAnyAttack reports whether either direction is mid-attack.
func (hs *hostState) inAnyAttack() bool {
	return hs.attacks[dirIn].inAttack || hs.attacks[dirOut].inAttack
}

type shard struct {
	mu    sync.Mutex
	hosts map[netip.Addr]*hostState
	// ring buffers the most recent flows recorded in this shard so an
	// attack sample is ready the moment a threshold trips. nil when
	// sampling is disabled. pos is the next write slot.
	ring []sampleEntry
	pos  int
}

// groupState tracks the per-direction attack lifecycle and learned
// baselines of one calculation:total hostgroup.
type groupState struct {
	attacks   [2]attackState
	baselines [2]baselineState
	lastRates [2]Rates
}

// carpetState tracks the attack lifecycle of one carpet-bombing aggregation
// prefix. Carpet detection is incoming-only and static-threshold-only (no
// baseline), so it needs a single attackState.
type carpetState struct {
	attack    attackState
	lastRates Rates
	lastHosts int
}

// carpetAccum is one aggregation prefix's summed incoming rates and fan-out
// (distinct contributing hosts), built fresh each tick like the total-group
// sums.
type carpetAccum struct {
	rates Rates
	hosts int
}

// carpetKey returns the aggregation prefix addr belongs to, per the configured
// per-family supernet length.
func carpetKey(addr netip.Addr, c *config.Carpet) netip.Prefix {
	bits := c.AggregationPrefixV4
	if addr.Is6() {
		bits = c.AggregationPrefixV6
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.PrefixFrom(addr, addr.BitLen()) // unreachable: bits validated
	}
	return p
}

// Engine is the detection core. Construct with New, feed flows with Process
// or ProcessBatch, drive evaluation with Run, and consume Events.
type Engine struct {
	store     *config.Store
	shards    [numShards]*shard
	windowSec int64
	ringSize  int
	// sampleFlows caps raw flow records per attack sample (0 = sampling
	// disabled). Sample buffer sizing is fixed at construction; changing it
	// requires a restart, which config reload enforces.
	sampleFlows int

	// groups holds total-group attack state. It is touched only by evalTick,
	// which runs on the single Run goroutine, so it needs no lock.
	groups map[string]*groupState

	// carpets holds carpet-bombing (per aggregation-prefix) attack state. Like
	// groups it is touched only by evalTick, so it needs no lock. Entries exist
	// only for prefixes currently in (or ending) a carpet attack.
	carpets map[netip.Prefix]*carpetState

	// geo optionally attributes sample sources to ASN/country. nil disables
	// enrichment; the resolver is read-only and safe for concurrent use.
	geo geoip.Resolver

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

// WithGeoIP attaches a GeoIP/ASN resolver used to enrich attack samples with
// per-source ASN/country attribution. A nil resolver leaves enrichment off.
func WithGeoIP(r geoip.Resolver) Option {
	return func(e *Engine) {
		// Guard against a typed-nil resolver (a nil *geoip.DB wrapped in the
		// interface) so callers can pass the result of an optional open
		// unconditionally without the engine treating it as enabled.
		if db, ok := r.(*geoip.DB); ok && db == nil {
			return
		}
		e.geo = r
	}
}

// New creates an Engine reading thresholds and policy from store.
func New(store *config.Store, opts ...Option) *Engine {
	e := &Engine{
		store:     store,
		windowSec: 5,
		groups:    make(map[string]*groupState),
		carpets:   make(map[netip.Prefix]*carpetState),
		events:    make(chan Event, 256),
		now:       time.Now,
		log:       slog.Default(),
	}
	for _, o := range opts {
		o(e)
	}
	e.ringSize = int(e.windowSec) + 1
	sampleCfg := store.Get().SampleCfg
	perShard := 0
	if sampleCfg.Enabled {
		e.sampleFlows = sampleCfg.FlowsPerAttack
		// Round up so the actual total capacity is never below the
		// configured buffer_flows.
		perShard = (sampleCfg.BufferFlows + numShards - 1) / numShards
	}
	for i := range e.shards {
		sh := &shard{hosts: make(map[netip.Addr]*hostState)}
		if perShard > 0 {
			sh.ring = make([]sampleEntry, perShard)
		}
		e.shards[i] = sh
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
// hot path: no allocation occurs for an already-tracked host.
//
// A flow is recorded as incoming for its destination when the destination is
// inside the configured networks, and additionally as outgoing for its
// source when outgoing detection is enabled and the source is inside the
// networks. Everything else returns immediately so unmonitored traffic costs
// nothing beyond the prefix lookups.
func (e *Engine) Process(f flow.Flow) {
	cfg := e.store.Get()
	rate := f.SamplingRate
	if rate == 0 {
		rate = 1
	}
	epoch := e.now().Unix()

	if f.DstAddr.IsValid() && cfg.InNetworks(f.DstAddr) {
		e.record(f.DstAddr, dirIn, f, rate, epoch)
	}
	if cfg.OutgoingEnabled && f.SrcAddr.IsValid() && cfg.InNetworks(f.SrcAddr) {
		e.record(f.SrcAddr, dirOut, f, rate, epoch)
	}
}

// record accumulates one flow into addr's bucket for the given direction.
func (e *Engine) record(addr netip.Addr, dir int, f flow.Flow, rate uint64, epoch int64) {
	sh := e.shardFor(addr)
	sh.mu.Lock()
	hs := sh.hosts[addr]
	if hs == nil {
		hs = &hostState{ring: make([]bucket, e.ringSize)}
		sh.hosts[addr] = hs
	}
	b := &hs.ring[epoch%int64(e.ringSize)]
	if b.epoch != epoch {
		*b = bucket{epoch: epoch}
	}
	c := &b.dirs[dir]
	bytes := f.Bytes * rate
	packets := f.Packets * rate
	c.bytes[clTotal] += bytes
	c.packets[clTotal] += packets
	c.flows += rate
	switch f.IPProto {
	case 6: // TCP
		c.bytes[clTCP] += bytes
		c.packets[clTCP] += packets
		// Pure SYN (SYN set, ACK clear): the classic flood signature.
		if f.TCPFlags&0x12 == 0x02 {
			c.bytes[clTCPSYN] += bytes
			c.packets[clTCPSYN] += packets
		}
	case 17: // UDP
		c.bytes[clUDP] += bytes
		c.packets[clUDP] += packets
	case 1, 58: // ICMP, ICMPv6
		c.bytes[clICMP] += bytes
		c.packets[clICMP] += packets
	}
	if f.Fragment {
		c.bytes[clFrag] += bytes
		c.packets[clFrag] += packets
	}
	if sh.ring != nil {
		sh.ring[sh.pos] = sampleEntry{f: f, epoch: epoch, dir: int8(dir)}
		sh.pos++
		if sh.pos == len(sh.ring) {
			sh.pos = 0
		}
	}
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
// host hs and returns the sampling-corrected per-second averages for both
// directions. The current (in-progress) second is excluded so a partially
// filled bucket never dilutes the average. ok is false when the window holds
// no data.
func (e *Engine) windowedRates(hs *hostState, nowSec int64) (in, out Rates, ok bool) {
	var cin, cout counters
	for s := nowSec - e.windowSec; s <= nowSec-1; s++ {
		b := &hs.ring[s%int64(e.ringSize)]
		if b.epoch == s {
			cin.add(&b.dirs[dirIn])
			cout.add(&b.dirs[dirOut])
			ok = true
		}
	}
	w := float64(e.windowSec)
	return cin.rates(w), cout.rates(w), ok
}

// thresholdsFor returns the group's threshold set for a direction; nil means
// detection is disabled for that direction.
func thresholdsFor(g *config.Group, dir int) *config.Thresholds {
	if dir == dirOut {
		return g.OutThresholds
	}
	return &g.Thresholds
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

	// Running per-direction sums for total groups, indexed like cfg.Groups.
	// Built fresh each tick — once per second, not on the hot path.
	totals := make([][2]Rates, len(cfg.Groups))

	// Per aggregation-prefix incoming sums + fan-out for carpet-bombing
	// detection, built fresh each tick. nil (and zero cost) when disabled.
	var carpetAgg map[netip.Prefix]*carpetAccum
	if cfg.Carpet != nil {
		carpetAgg = make(map[netip.Prefix]*carpetAccum)
	}

	var active int
	var tracked int
	for _, sh := range e.shards {
		sh.mu.Lock()
		for addr, hs := range sh.hosts {
			in, out, ok := e.windowedRates(hs, nowSec)
			rates := [2]Rates{in, out}

			evictOrTrack := func() {
				if !hs.inAnyAttack() && !ok && hs.lastSeen < staleBefore {
					delete(sh.hosts, addr)
				} else {
					tracked++
				}
			}

			// endBoth closes out any mid-attack state in both directions —
			// used when policy no longer applies to the host at all.
			endBoth := func(g *config.Group) {
				for d := range hs.attacks {
					if hs.attacks[d].inAttack {
						e.endAttack(addr, hs, d, rates[d], g, now, "policy change")
					}
				}
			}

			// Hosts that left the monitored networks after a reload are
			// never acted on; end mid-attack state explicitly so mitigation
			// withdraws the route instead of waiting for TTL.
			if !cfg.InNetworks(addr) {
				endBoth(cfg.GroupFor(addr))
				evictOrTrack()
				continue
			}

			gi := cfg.GroupIndexFor(addr)
			g := &cfg.Groups[gi]

			// Members of a total group only feed the group's sums — including
			// whitelisted hosts, since group totals are informational and
			// never ban. A host mid-attack that a reload moved into a total
			// group has its per-host attacks closed out.
			if g.Calc == config.CalcTotal {
				totals[gi][dirIn] = addRates(totals[gi][dirIn], in)
				totals[gi][dirOut] = addRates(totals[gi][dirOut], out)
				endBoth(g)
				evictOrTrack()
				continue
			}

			// Whitelisted hosts are never acted on (safety rule), even when
			// a reload whitelists one mid-attack.
			if cfg.IsWhitelisted(addr) {
				endBoth(g)
				evictOrTrack()
				continue
			}

			// Fold this host's incoming rates into its aggregation prefix for
			// carpet-bombing detection (subnet-spread attacks that stay under
			// every per-host threshold). Only hosts with traffic this window
			// count toward the fan-out.
			if carpetAgg != nil && ok && in.PPS > 0 {
				key := carpetKey(addr, cfg.Carpet)
				acc := carpetAgg[key]
				if acc == nil {
					acc = &carpetAccum{}
					carpetAgg[key] = acc
				}
				acc.rates = addRates(acc.rates, in)
				acc.hosts++
			}

			for d := range hs.attacks {
				st := &hs.attacks[d]
				th := thresholdsFor(g, d)
				if th == nil {
					// Direction disabled (e.g. outgoing block removed by a
					// reload mid-attack).
					if st.inAttack {
						e.endAttack(addr, hs, d, rates[d], g, now, "policy change")
					}
					continue
				}

				// While an attack is active its end is judged against the
				// thresholds frozen at its start; otherwise against the
				// current (possibly baseline-tightened) thresholds.
				eff := st.effThresholds
				if !st.inAttack {
					eff = effectiveThresholds(*th, &hs.baselines[d], g.Baseline, nowSec)
				}
				metric, rate, threshold, exceeded := evaluate(rates[d], eff)
				if exceeded {
					if !st.inAttack {
						st.inAttack = true
						st.metric = metric
						st.threshold = threshold
						st.effThresholds = eff
						st.startedAt = now
						metrics.AttacksTotal.Inc()
						sample := e.collectHostSample(sh, addr, d, nowSec-e.windowSec)
						cls := classify(rates[d], sample)
						e.log.Warn("attack detected",
							"target", addr.String(), "group", g.Name,
							"direction", string(dirName(d)), "metric", string(metric),
							"type", clsType(cls),
							"rate", rate, "threshold", threshold,
							"pps", rates[d].PPS, "mbps", rates[d].Mbps,
							"flows_per_sec", rates[d].FlowsPerSec)
						e.emit(Event{
							Kind:           AttackStarted,
							Scope:          ScopeHost,
							Target:         addr,
							Group:          g.Name,
							Direction:      dirName(d),
							BanEnabled:     g.BanEnabled,
							Metric:         metric,
							Rate:           rate,
							Threshold:      threshold,
							Rates:          rates[d],
							At:             now,
							Sample:         sample,
							Classification: cls,
						})
					}
					st.belowSince = time.Time{}
					active++
				} else if st.inAttack {
					if st.belowSince.IsZero() {
						st.belowSince = now
					}
					if now.Sub(st.belowSince) >= hysteresis {
						e.endAttack(addr, hs, d, rates[d], g, now, "below threshold")
					} else {
						active++ // still considered active during hysteresis
					}
				}

				// Learn only outside attacks (including the hysteresis tail,
				// where st.inAttack is still true) and only from a real
				// observation: a direction with no traffic this window must
				// not train its baseline toward zero, and warm-up must not
				// advance on empty seconds.
				if g.Baseline != nil && !st.inAttack && rates[d].PPS > 0 {
					hs.baselines[d].learn(rates[d], g.Baseline, nowSec)
				}
			}

			evictOrTrack()
		}
		sh.mu.Unlock()
	}

	active += e.evalGroups(cfg, totals, hysteresis, now)

	if cfg.Carpet != nil {
		active += e.evalCarpets(cfg, carpetAgg, hysteresis, now)
	} else if len(e.carpets) > 0 {
		// Carpet detection was disabled by a reload: close out any in-flight
		// carpet attacks so consumers see an end event, then drop the state.
		e.closeAllCarpets(now)
	}

	metrics.ActiveAttacks.Set(float64(active))
	metrics.TrackedHosts.Set(float64(tracked))
}

// evalGroups runs the per-direction attack lifecycle for every
// calculation:total group on its summed rates and closes out state for
// groups a reload removed. It returns the number of currently active group
// attacks.
func (e *Engine) evalGroups(cfg *config.Config, totals [][2]Rates, hysteresis time.Duration, now time.Time) int {
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
		gs.lastRates = totals[gi]

		for d := range gs.attacks {
			st := &gs.attacks[d]
			th := thresholdsFor(g, d)
			if th == nil {
				if st.inAttack {
					e.endGroupAttack(g.Name, gs, d, totals[gi][d], now, "policy change")
				}
				continue
			}

			eff := st.effThresholds
			if !st.inAttack {
				eff = effectiveThresholds(*th, &gs.baselines[d], g.Baseline, now.Unix())
			}
			metric, rate, threshold, exceeded := evaluate(totals[gi][d], eff)
			if exceeded {
				if !st.inAttack {
					st.inAttack = true
					st.metric = metric
					st.threshold = threshold
					st.effThresholds = eff
					st.startedAt = now
					metrics.AttacksTotal.Inc()
					// evalGroups runs outside all shard locks, which
					// collectGroupSample requires.
					sample := e.collectGroupSample(cfg, gi, d, now.Unix()-e.windowSec)
					cls := classify(totals[gi][d], sample)
					e.log.Warn("group attack detected",
						"group", g.Name, "direction", string(dirName(d)),
						"metric", string(metric),
						"type", clsType(cls),
						"rate", rate, "threshold", threshold,
						"pps", totals[gi][d].PPS, "mbps", totals[gi][d].Mbps,
						"flows_per_sec", totals[gi][d].FlowsPerSec)
					e.emit(Event{
						Kind:           AttackStarted,
						Scope:          ScopeGroup,
						Group:          g.Name,
						Direction:      dirName(d),
						Metric:         metric,
						Rate:           rate,
						Threshold:      threshold,
						Rates:          totals[gi][d],
						At:             now,
						Sample:         sample,
						Classification: cls,
					})
				}
				st.belowSince = time.Time{}
				active++
			} else if st.inAttack {
				if st.belowSince.IsZero() {
					st.belowSince = now
				}
				if now.Sub(st.belowSince) >= hysteresis {
					e.endGroupAttack(g.Name, gs, d, totals[gi][d], now, "below threshold")
				} else {
					active++
				}
			}

			// Learn only outside attacks and only when the group actually
			// carried traffic this tick: an empty (zero-member) total group
			// must not warm up on empty seconds and pin its baseline at
			// zero, which would floor-collapse its threshold and false-alert
			// the first time members scale in.
			if g.Baseline != nil && !st.inAttack && totals[gi][d].PPS > 0 {
				gs.baselines[d].learn(totals[gi][d], g.Baseline, now.Unix())
			}
		}
	}

	// Groups removed (or switched to per_host) by a reload: close out any
	// attack in flight so consumers see an end event, then drop the state.
	for name, gs := range e.groups {
		if current[name] {
			continue
		}
		for d := range gs.attacks {
			if gs.attacks[d].inAttack {
				e.endGroupAttack(name, gs, d, gs.lastRates[d], now, "policy change")
			}
		}
		delete(e.groups, name)
	}
	return active
}

// endAttack clears the attack state of one (host, direction) and emits
// AttackEnded carrying the last measurement, the original trigger metric and
// the threshold recorded at attack start. Callers hold the owning shard's
// lock.
func (e *Engine) endAttack(addr netip.Addr, hs *hostState, dir int, rates Rates, g *config.Group, now time.Time, reason string) {
	st := &hs.attacks[dir]
	st.inAttack = false
	st.belowSince = time.Time{}
	e.log.Info("attack ended",
		"target", addr.String(), "group", g.Name,
		"direction", string(dirName(dir)), "metric", string(st.metric),
		"reason", reason, "duration", now.Sub(st.startedAt).String(),
		"pps", rates.PPS, "mbps", rates.Mbps, "flows_per_sec", rates.FlowsPerSec)
	e.emit(Event{
		Kind:       AttackEnded,
		Scope:      ScopeHost,
		Target:     addr,
		Group:      g.Name,
		Direction:  dirName(dir),
		BanEnabled: g.BanEnabled,
		Metric:     st.metric,
		Rate:       rateFor(rates, st.metric),
		Threshold:  st.threshold,
		Rates:      rates,
		At:         now,
		StartedAt:  st.startedAt,
	})
}

// endGroupAttack clears one (total group, direction) attack state and emits
// AttackEnded.
func (e *Engine) endGroupAttack(name string, gs *groupState, dir int, rates Rates, now time.Time, reason string) {
	st := &gs.attacks[dir]
	st.inAttack = false
	st.belowSince = time.Time{}
	e.log.Info("group attack ended",
		"group", name, "direction", string(dirName(dir)),
		"metric", string(st.metric), "reason", reason,
		"duration", now.Sub(st.startedAt).String(),
		"pps", rates.PPS, "mbps", rates.Mbps, "flows_per_sec", rates.FlowsPerSec)
	e.emit(Event{
		Kind:      AttackEnded,
		Scope:     ScopeGroup,
		Group:     name,
		Direction: dirName(dir),
		Metric:    st.metric,
		Rate:      rateFor(rates, st.metric),
		Threshold: st.threshold,
		Rates:     rates,
		At:        now,
		StartedAt: st.startedAt,
	})
}

// evalCarpets runs the carpet-bombing attack lifecycle. A carpet attack fires
// for an aggregation prefix only when its summed incoming rates cross the
// carpet thresholds AND the traffic is spread across at least MinHosts distinct
// hosts — the fan-out gate that separates a real subnet-spread flood from one
// heavy host already caught per-host. It also drives the end of any in-flight
// carpet attack whose prefix went quiet. Carpet attacks are alert-only
// (BanEnabled false). Runs on the Run goroutine outside all shard locks, which
// collectPrefixSample requires. Returns the active carpet-attack count.
func (e *Engine) evalCarpets(cfg *config.Config, agg map[netip.Prefix]*carpetAccum, hysteresis time.Duration, now time.Time) int {
	var active int
	th := cfg.Carpet.Thresholds
	minHosts := cfg.Carpet.MinHosts
	seen := make(map[netip.Prefix]bool, len(agg))

	for prefix, acc := range agg {
		seen[prefix] = true
		metric, rate, threshold, over := evaluate(acc.rates, th)
		exceeded := over && acc.hosts >= minHosts
		cs := e.carpets[prefix]

		if exceeded {
			if cs == nil {
				cs = &carpetState{}
				e.carpets[prefix] = cs
			}
			cs.lastRates = acc.rates
			cs.lastHosts = acc.hosts
			st := &cs.attack
			if !st.inAttack {
				st.inAttack = true
				st.metric = metric
				st.threshold = threshold
				st.effThresholds = th
				st.startedAt = now
				metrics.AttacksTotal.Inc()
				sample := e.collectPrefixSample(prefix, dirIn, now.Unix()-e.windowSec)
				cls := classify(acc.rates, sample)
				e.log.Warn("carpet-bomb attack detected",
					"prefix", prefix.String(), "hosts", acc.hosts,
					"metric", string(metric), "type", clsType(cls),
					"rate", rate, "threshold", threshold,
					"pps", acc.rates.PPS, "mbps", acc.rates.Mbps,
					"flows_per_sec", acc.rates.FlowsPerSec)
				e.emit(Event{
					Kind:           AttackStarted,
					Scope:          ScopePrefix,
					Target:         prefix.Addr(),
					Prefix:         prefix.String(),
					Hosts:          acc.hosts,
					Direction:      DirIncoming,
					Group:          cfg.GroupFor(prefix.Addr()).Name,
					BanEnabled:     false, // carpet attacks are alert-only
					Metric:         metric,
					Rate:           rate,
					Threshold:      threshold,
					Rates:          acc.rates,
					At:             now,
					Sample:         sample,
					Classification: cls,
				})
			}
			st.belowSince = time.Time{}
			active++
		} else if cs != nil && cs.attack.inAttack {
			cs.lastRates = acc.rates
			cs.lastHosts = acc.hosts
			if cs.attack.belowSince.IsZero() {
				cs.attack.belowSince = now
			}
			if now.Sub(cs.attack.belowSince) >= hysteresis {
				e.endCarpet(prefix, cs, acc.rates, now, "below threshold")
			} else {
				active++
			}
		}
	}

	// In-flight carpet attacks whose prefix carried no traffic this tick: drive
	// their end (with zero rates) through the same hysteresis.
	for prefix, cs := range e.carpets {
		if seen[prefix] || !cs.attack.inAttack {
			continue
		}
		if cs.attack.belowSince.IsZero() {
			cs.attack.belowSince = now
		}
		if now.Sub(cs.attack.belowSince) >= hysteresis {
			e.endCarpet(prefix, cs, Rates{}, now, "below threshold")
		} else {
			active++
		}
	}
	return active
}

// endCarpet clears one carpet attack's state, emits AttackEnded, and drops the
// prefix from the carpet table (carpet state is ephemeral, unlike groups).
func (e *Engine) endCarpet(prefix netip.Prefix, cs *carpetState, rates Rates, now time.Time, reason string) {
	st := &cs.attack
	st.inAttack = false
	st.belowSince = time.Time{}
	e.log.Info("carpet-bomb attack ended",
		"prefix", prefix.String(), "metric", string(st.metric),
		"reason", reason, "duration", now.Sub(st.startedAt).String(),
		"pps", rates.PPS, "mbps", rates.Mbps, "flows_per_sec", rates.FlowsPerSec)
	e.emit(Event{
		Kind:      AttackEnded,
		Scope:     ScopePrefix,
		Target:    prefix.Addr(),
		Prefix:    prefix.String(),
		Hosts:     cs.lastHosts,
		Direction: DirIncoming,
		Group:     e.store.Get().GroupFor(prefix.Addr()).Name,
		Metric:    st.metric,
		Rate:      rateFor(rates, st.metric),
		Threshold: st.threshold,
		Rates:     rates,
		At:        now,
		StartedAt: st.startedAt,
	})
	delete(e.carpets, prefix)
}

// closeAllCarpets ends every in-flight carpet attack — carpet detection was
// disabled by a reload — and clears the table.
func (e *Engine) closeAllCarpets(now time.Time) {
	for prefix, cs := range e.carpets {
		if cs.attack.inAttack {
			e.endCarpet(prefix, cs, cs.lastRates, now, "policy change")
		} else {
			delete(e.carpets, prefix)
		}
	}
}

// metricTable defines the evaluation order: total metrics first (matching
// the original pps → mbps → flows_per_sec order), then per-protocol pairs.
// A zero threshold disables its metric.
var metricTable = []struct {
	metric Metric
	rate   func(*Rates) float64
	limit  func(*config.Thresholds) uint64
}{
	{MetricPPS, func(r *Rates) float64 { return r.PPS }, func(t *config.Thresholds) uint64 { return t.PPS }},
	{MetricMbps, func(r *Rates) float64 { return r.Mbps }, func(t *config.Thresholds) uint64 { return t.Mbps }},
	{MetricFPS, func(r *Rates) float64 { return r.FlowsPerSec }, func(t *config.Thresholds) uint64 { return t.FlowsPerSec }},
	{MetricTCPPPS, func(r *Rates) float64 { return r.TCPPPS }, func(t *config.Thresholds) uint64 { return t.TCPPPS }},
	{MetricTCPMbps, func(r *Rates) float64 { return r.TCPMbps }, func(t *config.Thresholds) uint64 { return t.TCPMbps }},
	{MetricUDPPPS, func(r *Rates) float64 { return r.UDPPPS }, func(t *config.Thresholds) uint64 { return t.UDPPPS }},
	{MetricUDPMbps, func(r *Rates) float64 { return r.UDPMbps }, func(t *config.Thresholds) uint64 { return t.UDPMbps }},
	{MetricICMPPPS, func(r *Rates) float64 { return r.ICMPPPS }, func(t *config.Thresholds) uint64 { return t.ICMPPPS }},
	{MetricICMPMbps, func(r *Rates) float64 { return r.ICMPMbps }, func(t *config.Thresholds) uint64 { return t.ICMPMbps }},
	{MetricTCPSYNPPS, func(r *Rates) float64 { return r.TCPSYNPPS }, func(t *config.Thresholds) uint64 { return t.TCPSYNPPS }},
	{MetricTCPSYNMbps, func(r *Rates) float64 { return r.TCPSYNMbps }, func(t *config.Thresholds) uint64 { return t.TCPSYNMbps }},
	{MetricFragPPS, func(r *Rates) float64 { return r.FragPPS }, func(t *config.Thresholds) uint64 { return t.FragPPS }},
	{MetricFragMbps, func(r *Rates) float64 { return r.FragMbps }, func(t *config.Thresholds) uint64 { return t.FragMbps }},
}

// evaluate compares rates against thresholds and reports the first metric
// crossed in metricTable order. A zero threshold is disabled.
func evaluate(r Rates, th config.Thresholds) (Metric, float64, float64, bool) {
	for i := range metricTable {
		m := &metricTable[i]
		lim := m.limit(&th)
		if lim == 0 {
			continue
		}
		if rate := m.rate(&r); rate > float64(lim) {
			return m.metric, rate, float64(lim), true
		}
	}
	return "", 0, 0, false
}

// rateFor returns the component of r selected by m.
func rateFor(r Rates, m Metric) float64 {
	for i := range metricTable {
		if metricTable[i].metric == m {
			return metricTable[i].rate(&r)
		}
	}
	return r.PPS
}

// addRates returns the field-wise sum of two measurements.
func addRates(a, b Rates) Rates {
	return Rates{
		PPS:         a.PPS + b.PPS,
		Mbps:        a.Mbps + b.Mbps,
		FlowsPerSec: a.FlowsPerSec + b.FlowsPerSec,
		TCPPPS:      a.TCPPPS + b.TCPPPS,
		TCPMbps:     a.TCPMbps + b.TCPMbps,
		UDPPPS:      a.UDPPPS + b.UDPPPS,
		UDPMbps:     a.UDPMbps + b.UDPMbps,
		ICMPPPS:     a.ICMPPPS + b.ICMPPPS,
		ICMPMbps:    a.ICMPMbps + b.ICMPMbps,
		TCPSYNPPS:   a.TCPSYNPPS + b.TCPSYNPPS,
		TCPSYNMbps:  a.TCPSYNMbps + b.TCPSYNMbps,
		FragPPS:     a.FragPPS + b.FragPPS,
		FragMbps:    a.FragMbps + b.FragMbps,
	}
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

// HostStat is a read-only snapshot of one tracked host for the API. Rates
// are incoming; OutRates are only nonzero when outgoing detection is on.
// Metric/Direction describe the active attack (incoming reported first when
// both directions are under attack).
type HostStat struct {
	Target    netip.Addr `json:"target"`
	Group     string     `json:"group"`
	Rates     Rates      `json:"rates"`
	OutRates  Rates      `json:"rates_out"`
	InAttack  bool       `json:"in_attack"`
	Metric    Metric     `json:"metric,omitempty"`
	Direction Direction  `json:"direction,omitempty"`
	// Baseline / OutBaseline are the learned normal levels (base trio
	// only), present once the host has been observed with baselines on.
	Baseline    *Rates `json:"baseline,omitempty"`
	OutBaseline *Rates `json:"baseline_out,omitempty"`
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
			in, outRates, _ := e.windowedRates(hs, nowSec)
			g := cfg.GroupFor(addr)
			st := HostStat{
				Target:   addr,
				Group:    g.Name,
				Rates:    in,
				OutRates: outRates,
				InAttack: hs.inAnyAttack(),
			}
			// Only surface learned baselines while baselines are actually
			// configured for the host's group; otherwise the values are
			// stale leftovers from before a reload disabled them.
			if g.Baseline != nil {
				st.Baseline = hs.baselines[dirIn].rates()
				st.OutBaseline = hs.baselines[dirOut].rates()
			}
			for d := range hs.attacks {
				if hs.attacks[d].inAttack {
					st.Metric = hs.attacks[d].metric
					st.Direction = dirName(d)
					break
				}
			}
			out = append(out, st)
		}
		sh.mu.Unlock()
	}
	return out
}

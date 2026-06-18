package engine

import (
	"math"

	"github.com/kapkan-io/kapkan/internal/config"
)

// baselineState is the continuously learned normal traffic level of one
// (host or total group, direction). It is only touched on the evaluation
// tick, under the same protection as the owning state.
type baselineState struct {
	pps, mbps, fps float64
	// firstSeen is the Unix second of the first learning sample; baseline
	// gating activates only warmup_seconds after it.
	firstSeen int64
	valid     bool
}

// learn folds one per-second measurement into the EWMA. Two poisoning
// bounds apply: callers must not invoke learn while the subject is under
// attack, and each input is clamped to baseline*factor so a slow attacker
// ramp can raise the baseline at most geometrically with the half-life
// period — never instantly.
func (b *baselineState) learn(r Rates, bc *config.BaselineSettings, nowSec int64) {
	if !b.valid {
		b.pps, b.mbps, b.fps = r.PPS, r.Mbps, r.FlowsPerSec
		b.firstSeen = nowSec
		b.valid = true
		return
	}
	up := func(cur, sample float64) float64 {
		if cap := cur * bc.Factor; cap > 0 && sample > cap {
			sample = cap
		}
		return cur + bc.Alpha*(sample-cur)
	}
	b.pps = up(b.pps, r.PPS)
	b.mbps = up(b.mbps, r.Mbps)
	b.fps = up(b.fps, r.FlowsPerSec)
}

// warmedUp reports whether the baseline has observed enough history to
// gate detection.
func (b *baselineState) warmedUp(bc *config.BaselineSettings, nowSec int64) bool {
	return b.valid && nowSec-b.firstSeen >= int64(bc.WarmupSeconds)
}

// rates exposes the learned normal for the API (base trio only).
func (b *baselineState) rates() *Rates {
	if !b.valid {
		return nil
	}
	return &Rates{PPS: b.pps, Mbps: b.mbps, FlowsPerSec: b.fps}
}

// effectiveThresholds tightens the base trio of th to the learned
// baseline*factor, bounded below by the configured floor and above by the
// static thresholds (the ceiling: a poisoned or fast-grown baseline can
// never raise the bar past the operator's static limit). Per-protocol
// thresholds are returned untouched. Before warm-up the static thresholds
// apply unchanged.
func effectiveThresholds(th config.Thresholds, b *baselineState, bc *config.BaselineSettings, nowSec int64) config.Thresholds {
	if bc == nil || !b.warmedUp(bc, nowSec) {
		return th
	}
	adj := func(static uint64, base float64, floor uint64) uint64 {
		// Clamp in float space before the uint64 conversion: a non-finite
		// or overflowing base*factor would otherwise convert
		// implementation-dependently (0 on arm64, 1<<63 on amd64).
		prod := base * bc.Factor
		switch {
		case math.IsNaN(prod) || prod >= float64(static):
			// Broken factor or above the ceiling: the static limit wins —
			// never collapse a misconfiguration to the hair-trigger floor.
			return static
		case prod < float64(floor):
			return floorClampedToStatic(floor, static)
		default:
			return uint64(prod)
		}
	}
	th.PPS = adj(th.PPS, b.pps, bc.Floor.PPS)
	th.Mbps = adj(th.Mbps, b.mbps, bc.Floor.Mbps)
	th.FlowsPerSec = adj(th.FlowsPerSec, b.fps, bc.Floor.FlowsPerSec)
	return th
}

// floorClampedToStatic returns the floor but never above the static
// ceiling, preserving "static always wins" even if an operator misconfigures
// the floor above a static threshold.
func floorClampedToStatic(floor, static uint64) uint64 {
	if floor > static {
		return static
	}
	return floor
}

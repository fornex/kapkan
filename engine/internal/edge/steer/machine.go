package steer

import (
	"errors"
	"fmt"
	"time"
)

// The bounds Config documents beyond its defaults (types.go), and the cap on
// the flap count.
const (
	autoMinInterval     = time.Second
	autoMaxInterval     = 10 * time.Second
	autoMaxFailWindow   = 60
	autoMinRecoverAfter = 3
	autoMaxRecoverAfter = 120
	autoMinHoldDown     = time.Second
	autoMinLevelReset   = time.Second
	autoMaxLevelReset   = 24 * time.Hour
	// autoMaxLevel caps the flap count. Every allowed ladder has saturated
	// long before it (1 s doubled ten times passes the 600 s ceiling), so the
	// cap changes no hold-down; it keeps Level+1 from overflowing, whatever a
	// hand-edited state.json says.
	autoMaxLevel = 64
)

// AsOf is the verdict as a reader at now must take it: unchanged while
// now-At is at most staleAfter (Config.StaleAfter), and past that — or when
// At is zero — StateUnknown with ReasonStale, Since At, and no RejoinAt or
// Warning. So a sampler that stopped reads as unknown after three intervals,
// never as withdraw.
func (v Verdict) AsOf(now time.Time, staleAfter time.Duration) Verdict {
	if !v.At.IsZero() && now.Sub(v.At) <= staleAfter {
		return v
	}
	return Verdict{State: StateUnknown, Reason: ReasonStale, Since: v.At, At: v.At}
}

// Validate refuses a configuration outside the bounds Config documents, after
// filling zero fields with their defaults — what E7.2's edge.yaml check
// reports as a PROBLEM. It names every bound it finds broken, not only the
// first.
func (c Config) Validate() error {
	c = c.withDefaults()
	var errs []error
	if c.Interval < autoMinInterval || c.Interval > autoMaxInterval {
		errs = append(errs, fmt.Errorf("steer: interval %v is outside %v..%v", c.Interval, autoMinInterval, autoMaxInterval))
	}
	if c.FailWindow > autoMaxFailWindow {
		errs = append(errs, fmt.Errorf("steer: fail_window %d is outside 1..%d", c.FailWindow, autoMaxFailWindow))
	}
	if c.FailAfter > c.FailWindow {
		errs = append(errs, fmt.Errorf("steer: fail_after %d exceeds fail_window %d", c.FailAfter, c.FailWindow))
	}
	if c.RecoverAfter < autoMinRecoverAfter || c.RecoverAfter > autoMaxRecoverAfter {
		errs = append(errs, fmt.Errorf("steer: recover_after %d is outside %d..%d", c.RecoverAfter, autoMinRecoverAfter, autoMaxRecoverAfter))
	}
	if c.HoldDownMin < autoMinHoldDown {
		errs = append(errs, fmt.Errorf("steer: hold_down min %v is below %v", c.HoldDownMin, autoMinHoldDown))
	}
	if c.HoldDownMin > c.HoldDownMax {
		errs = append(errs, fmt.Errorf("steer: hold_down min %v exceeds hold_down max %v", c.HoldDownMin, c.HoldDownMax))
	}
	if c.HoldDownMax > HoldDownCeiling {
		errs = append(errs, fmt.Errorf("steer: hold_down max %v exceeds the %v ceiling", c.HoldDownMax, HoldDownCeiling))
	}
	if c.LevelReset < autoMinLevelReset || c.LevelReset > autoMaxLevelReset {
		errs = append(errs, fmt.Errorf("steer: level reset %v is outside %v..%v", c.LevelReset, autoMinLevelReset, autoMaxLevelReset))
	}
	return errors.Join(errs...)
}

// normalized fills zero fields with their defaults and clamps the rest into
// their bounds, so an automaton is safe with any Config (I3); Validate is
// where an out-of-range value is reported.
func (c Config) normalized() Config {
	c = c.withDefaults()
	c.Interval = min(max(c.Interval, autoMinInterval), autoMaxInterval)
	c.FailWindow = min(c.FailWindow, autoMaxFailWindow)
	c.FailAfter = min(c.FailAfter, c.FailWindow)
	c.RecoverAfter = min(max(c.RecoverAfter, autoMinRecoverAfter), autoMaxRecoverAfter)
	c.HoldDownMax = min(max(c.HoldDownMax, autoMinHoldDown), HoldDownCeiling)
	c.HoldDownMin = min(max(c.HoldDownMin, autoMinHoldDown), c.HoldDownMax)
	c.LevelReset = min(max(c.LevelReset, autoMinLevelReset), autoMaxLevelReset)
	return c
}

// withDefaults gives each zero or negative field its default.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.FailAfter <= 0 {
		c.FailAfter = d.FailAfter
	}
	if c.FailWindow <= 0 {
		c.FailWindow = d.FailWindow
	}
	if c.RecoverAfter <= 0 {
		c.RecoverAfter = d.RecoverAfter
	}
	if c.HoldDownMin <= 0 {
		c.HoldDownMin = d.HoldDownMin
	}
	if c.HoldDownMax <= 0 {
		c.HoldDownMax = d.HoldDownMax
	}
	if c.LevelReset <= 0 {
		c.LevelReset = d.LevelReset
	}
	return c
}

// HoldDown is the hold-down at a level: 0 at level 0 (or below), HoldDownMin
// at 1, doubling per level and saturating at HoldDownMax — for any level,
// without overflow.
func (c Config) HoldDown(level int) time.Duration {
	if level <= 0 {
		return 0
	}
	c = c.normalized()
	d := c.HoldDownMin
	// The doubling stops at the cap, so the loop is a few turns long and d
	// never overflows, however high the level.
	for i := 1; i < level && d < c.HoldDownMax; i++ {
		d *= 2
	}
	return min(d, c.HoldDownMax)
}

// StaleAfter is how old a verdict may be before AsOf reads it as unknown:
// StaleIntervals intervals.
func (c Config) StaleAfter() time.Duration {
	return StaleIntervals * c.normalized().Interval
}

// Automaton is one target's damped verdict. Not safe for concurrent use: one
// goroutine — the sampler's — steps it, and publishes the verdicts.
//
// I2 IS A SHAPE. The code that enters StateWithdraw or StateDrain sits in one
// unexported method whose inputs are a Triggers value, the time and — to name
// a drain, never to cause one — the drain's reason; gates, the probe class and
// the report reach the join path and nothing else. The method is out, the
// join path is join, and a test reads this file to keep it so. The window is
// the one thing both touch: out enters the hard samples, join the ok ones,
// and an ok sample can only push a hard one out of the window — so what join
// reads may delay a withdrawal and never brings one about.
type Automaton struct {
	cfg Config

	state  State
	reason Reason
	// since is when state was entered; zero until the first Step.
	since time.Time
	// window holds the last FailWindow decisive samples, oldest first: true
	// for a hard one, false for an ok one.
	window []bool
	// streak counts the ok samples in a row.
	streak int
	// level counts the flaps LevelReset has not yet forgiven; until is when
	// the running hold-down ends, zero when none runs.
	level int
	until time.Time
}

// NewAutomaton returns a target's automaton in StateUnknown, its hold-down
// restored from saved (Store.Load has already capped Until; a negative Level
// counts as 0). cfg is normalized: zero fields take their defaults.
func NewAutomaton(cfg Config, saved Saved) *Automaton {
	cfg = cfg.normalized()
	return &Automaton{
		cfg:    cfg,
		reason: ReasonStarting,
		window: make([]bool, 0, cfg.FailWindow),
		level:  min(max(saved.Level, 0), autoMaxLevel),
		until:  saved.Until,
	}
}

// Step feeds one tick's inputs and returns the verdict. In order:
//
//  1. Drain. While in.Triggers.Drained, the state is StateDrain (entered at
//     once, reason ReasonNewNode when in.Drain.Reason is NewNodeReason, else
//     ReasonDrained), the level and the hold-down are left as they are, and
//     nothing is sampled. On the first tick without it, the target re-enters
//     StateUnknown (ReasonStarting) with the window and the streak cleared,
//     as at a start, and that tick goes on to step 2.
//  2. Sample. A tick with in.Triggers.Hard() is a hard sample; one without,
//     whose in.Probe is ClassOK, is an ok sample; both enter the window (the
//     last FailWindow of them). Anything else — soft, blind, none, a refusal
//     with a listener behind it — does not. A hard sample resets the streak
//     and an ok one extends it; of the rest, ClassBlind and ClassNone leave it
//     as it is and every other class resets it.
//  3. Out. Not withdrawn, and FailAfter hard samples in the window: enter
//     StateWithdraw with this tick's trigger as the reason (ReasonUnbound,
//     then ReasonRefused, then ReasonNotTLS). From StateAnnounce that is a
//     flap: Level+1, and the hold-down runs until now+HoldDown(Level). From
//     StateUnknown neither moves; a hold-down already running still applies.
//  4. In. StateUnknown or StateWithdraw, a streak of at least RecoverAfter,
//     fewer than FailAfter hard samples in the window, in.Gates.Holding() ==
//     "", and now not before the hold-down's end: enter StateAnnounce
//     (ReasonOK). Nothing but step 3 leaves StateAnnounce (and step 1 drains
//     it): a gate that closes on an announced target is a Warning, not a way
//     out. The window clause costs nothing under the defaults — ten ok
//     samples in a row have pushed every hard one out of a window of five —
//     but with RecoverAfter set below the window it keeps a target out
//     exactly as long as its window says so, instead of joining one hard
//     sample away from the next withdrawal.
//  5. Level reset. LevelReset or longer in StateAnnounce: Level and the
//     hold-down return to zero.
//
// The verdict carries Since (when State was entered; the first Step's now for
// the initial StateUnknown), RejoinAt (the hold-down's end while it runs and
// the state is StateUnknown or StateWithdraw), At = now, and Warning =
// in.Gates.Holding() outside StateDrain. in.Report is never read.
func (a *Automaton) Step(in Inputs, now time.Time) Verdict {
	if a.since.IsZero() {
		a.since = now // the initial StateUnknown dates from the first tick
	}
	if !a.until.IsZero() && !now.Before(a.until) {
		a.until = time.Time{} // over: no longer a hold-down, nor in Saved
	}
	if !a.out(in.Triggers, in.Drain.Reason, now) {
		a.join(in.Triggers.Hard(), in.Probe, in.Gates, now)
		a.forgive(now)
	}
	return a.verdict(now, in.Gates.Holding())
}

// out is step 1 and the hard half of steps 2 and 3 — the one way out of
// service, and I2 in code: nothing else enters StateDrain or StateWithdraw.
// It reads a Triggers value and the time, and the drain's reason only to name
// a drain the trigger has set. It reports whether the target is drained:
// nothing is sampled under a drain, so the tick ends there.
func (a *Automaton) out(t Triggers, drainReason string, now time.Time) (drained bool) {
	if t.Drained {
		// At once and unwindowed — the operator's command, or the new node's
		// first entry — and without growing the hold-down: a drain is no flap.
		a.enter(StateDrain, autoDrainReason(drainReason), now)
		return true
	}
	if a.state == StateDrain {
		// Lifted: start over, as at a start. What the window saw before the
		// drain is not evidence about the box now; only the ladder carries on.
		a.window, a.streak = a.window[:0], 0
		a.enter(StateUnknown, ReasonStarting, now)
	}
	if !t.Hard() {
		return false
	}
	a.sample(true)
	if a.state == StateWithdraw || a.hardSamples() < a.cfg.FailAfter {
		return false
	}
	if a.state == StateAnnounce {
		// A flap: each one keeps the address out longer, so a crash-looping
		// terminator does not re-hash the survivors' flows every few seconds.
		a.level = min(a.level+1, autoMaxLevel)
		a.until = now.Add(a.cfg.HoldDown(a.level))
	}
	a.enter(StateWithdraw, autoWithdrawReason(t), now)
	return false
}

// join is the ok half of step 2, and step 4: the way back in. The probe class
// and the gates reach this method and nothing else, and it can enter
// StateAnnounce only — so whatever they say may delay a join and never takes
// an address out. hard says the tick was a hard sample, which out has
// already counted.
func (a *Automaton) join(hard bool, probe Class, g Gates, now time.Time) {
	switch {
	case hard:
		a.streak = 0
	case probe == ClassOK:
		a.sample(false)
		a.streak++
	case probe == ClassBlind || probe == ClassNone:
		// The probe could not look, or did not run: no evidence either way,
		// so the run neither grows nor breaks.
	default:
		// Soft, or a refusal with a listener behind it: the box did not
		// answer TLS this tick, and a join needs an unbroken run of answers.
		a.streak = 0
	}
	if a.state == StateAnnounce || a.streak < a.cfg.RecoverAfter ||
		a.hardSamples() >= a.cfg.FailAfter || g.Holding() != "" || now.Before(a.until) {
		return
	}
	a.enter(StateAnnounce, ReasonOK, now)
}

// forgive is step 5: a target that stayed announced for LevelReset has shown
// the trouble is over, and its next flap starts the ladder again (D8).
func (a *Automaton) forgive(now time.Time) {
	if a.state == StateAnnounce && now.Sub(a.since) >= a.cfg.LevelReset {
		a.level, a.until = 0, time.Time{}
	}
}

// enter puts the target in state s for reason r. Since moves only with the
// state: a drain whose reason changes is still the same drain.
func (a *Automaton) enter(s State, r Reason, now time.Time) {
	if a.state != s {
		a.state, a.since = s, now
	}
	a.reason = r
}

// sample enters one decisive sample — true for a hard one — into the window,
// which keeps the last FailWindow of them.
func (a *Automaton) sample(hard bool) {
	if len(a.window) == a.cfg.FailWindow {
		a.window = append(a.window[:0], a.window[1:]...)
	}
	a.window = append(a.window, hard)
}

// hardSamples counts the hard samples in the window.
func (a *Automaton) hardSamples() int {
	n := 0
	for _, hard := range a.window {
		if hard {
			n++
		}
	}
	return n
}

// verdict is the automaton's answer at now; warning is the closed join gate,
// if any, which a drain does not carry.
func (a *Automaton) verdict(now time.Time, warning Reason) Verdict {
	v := Verdict{State: a.state, Reason: a.reason, Since: a.since, At: now}
	if a.state == StateDrain {
		return v
	}
	if a.state != StateAnnounce && now.Before(a.until) {
		v.RejoinAt = a.until
	}
	v.Warning = warning
	return v
}

// Evaluate is the undamped verdict on one sample, with this automaton's
// hold-down and nothing else of its history; it changes nothing. It is what
// `kapkan edge -steer` answers when the daemon does not (E7.2), and the live
// evaluation `-check` prints. A binary checker has no "hold", so the answer is
// always definite:
//
//  1. in.Triggers.Drained: StateDrain, the reason as in Step.
//  2. in.Triggers.Hard(): StateWithdraw, the trigger's reason as in Step.
//  3. A hold-down still running: StateWithdraw, ReasonHoldDown, RejoinAt its
//     end — the tail of an earlier trigger's withdraw.
//  4. Otherwise StateAnnounce, ReasonUnmanaged, with Warning =
//     in.Gates.Holding(): a gate may not take an address out, and without a
//     history Evaluate cannot tell a join from a stay — so a closed gate
//     announces, named.
//
// Since and At are now. A withdraw carries RejoinAt while a hold-down runs,
// and every answer but a drain carries the Warning, as in Step.
func (a *Automaton) Evaluate(in Inputs, now time.Time) Verdict {
	v := Verdict{Since: now, At: now}
	t := in.Triggers
	switch {
	case t.Drained:
		v.State, v.Reason = StateDrain, autoDrainReason(in.Drain.Reason)
		return v
	case t.Hard():
		v.State, v.Reason = StateWithdraw, autoWithdrawReason(t)
	case now.Before(a.until):
		v.State, v.Reason = StateWithdraw, ReasonHoldDown
	default:
		v.State, v.Reason = StateAnnounce, ReasonUnmanaged
	}
	if v.State == StateWithdraw && now.Before(a.until) {
		v.RejoinAt = a.until
	}
	v.Warning = in.Gates.Holding()
	return v
}

// Saved is what state.json should hold for this target now.
func (a *Automaton) Saved() Saved {
	return Saved{Level: a.level, Until: a.until}
}

// ResetHoldDown forgets the level and any running hold-down — E7.2's `-s
// reset-holddown`, for the return after a fleet-wide incident (D8). A
// withdrawn target with a full streak and open gates announces on the next
// Step.
func (a *Automaton) ResetHoldDown() {
	a.level, a.until = 0, time.Time{}
}

// autoWithdrawReason names the trigger behind a hard sample: unbound first
// (an address the kernel does not hold is not probed, so it explains any
// other), then refused, then not_tls.
func autoWithdrawReason(t Triggers) Reason {
	switch {
	case t.Unbound:
		return ReasonUnbound
	case t.Refused:
		return ReasonRefused
	}
	return ReasonNotTLS
}

// autoDrainReason names a drain by its file's reason: the new-node drain lifts
// by itself and an operator's does not, so the two must read apart.
func autoDrainReason(reason string) Reason {
	if reason == NewNodeReason {
		return ReasonNewNode
	}
	return ReasonDrained
}

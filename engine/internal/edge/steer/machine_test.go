package steer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// autoT0 is the tests' clock origin: a plain wall time without a monotonic
// reading, so a test's time arithmetic is exactly the automaton's.
var autoT0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// autoOpen is every join gate open.
var autoOpen = Gates{GenerationLive: true, Zones: 1}

// autoTick spells one tick's inputs, every gate open:
//
//	O  ok: the probe answered TLS
//	R  refused with no listener: Triggers.Refused
//	T  not TLS: Triggers.NotTLS
//	U  unbound: Triggers.Unbound (no probe ran)
//	r  refused with a listener behind it (a firewall): no trigger
//	s  soft, b blind, n none: no trigger, no answer
//	D  the operator's drain, N the new-node drain
func autoTick(c byte) Inputs {
	in := Inputs{Gates: autoOpen}
	switch c {
	case 'O':
		in.Probe = ClassOK
	case 'R':
		in.Triggers.Refused, in.Probe = true, ClassRefused
	case 'T':
		in.Triggers.NotTLS, in.Probe = true, ClassNotTLS
	case 'U':
		in.Triggers.Unbound = true
	case 'r':
		in.Probe = ClassRefused
	case 's':
		in.Probe = ClassSoft
	case 'b':
		in.Probe = ClassBlind
	case 'n':
		in.Probe = ClassNone
	case 'D':
		in.Triggers.Drained, in.Drain = true, Drain{Reason: "maintenance"}
	case 'N':
		in.Triggers.Drained, in.Drain = true, Drain{Reason: NewNodeReason}
	default:
		panic("autoTick: no tick is spelled " + string(c))
	}
	return in
}

// autoRun steps a through ticks one second apart, the first at at; it returns
// every verdict and the time of the tick after the last.
func autoRun(a *Automaton, at time.Time, ticks string) ([]Verdict, time.Time) {
	vs := make([]Verdict, 0, len(ticks))
	for i := range len(ticks) {
		vs = append(vs, a.Step(autoTick(ticks[i]), at))
		at = at.Add(time.Second)
	}
	return vs, at
}

// autoStates spells verdicts one letter each: u unknown, A announce,
// W withdraw, D drain.
func autoStates(vs []Verdict) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteByte("uAWD"[v.State])
	}
	return b.String()
}

func autoOK(n int) string { return strings.Repeat("O", n) }

// autoAnnounced is an automaton that has just joined, and its next tick.
func autoAnnounced(t *testing.T, cfg Config) (*Automaton, time.Time) {
	t.Helper()
	a := NewAutomaton(cfg, Saved{})
	vs, at := autoRun(a, autoT0, autoOK(cfg.normalized().RecoverAfter))
	if v := vs[len(vs)-1]; v.State != StateAnnounce {
		t.Fatalf("after a full streak of ok: %+v, want announce", v)
	}
	return a, at
}

// autoFlap takes an announced automaton out with three refusals and returns
// the withdraw verdict and the next tick.
func autoFlap(t *testing.T, a *Automaton, at time.Time) (Verdict, time.Time) {
	t.Helper()
	vs, at := autoRun(a, at, "RRR")
	if got := autoStates(vs); got != "AAW" {
		t.Fatalf("an announced target, three refusals: states %s, want AAW", got)
	}
	return vs[2], at
}

func autoSame(a, b Verdict) bool {
	return a.State == b.State && a.Reason == b.Reason && a.Since.Equal(b.Since) &&
		a.RejoinAt.Equal(b.RejoinAt) && a.At.Equal(b.At) && a.Warning == b.Warning
}

func TestAutomatonStartsUnknown(t *testing.T) {
	a := NewAutomaton(Config{}, Saved{})
	got := a.Step(autoTick('O'), autoT0)
	want := Verdict{State: StateUnknown, Reason: ReasonStarting, Since: autoT0, At: autoT0}
	if !autoSame(got, want) {
		t.Fatalf("first verdict %+v, want %+v", got, want)
	}
	if got := a.Step(autoTick('O'), autoT0.Add(time.Second)); !got.Since.Equal(autoT0) {
		t.Fatalf("second verdict %+v: Since moved without a state change", got)
	}
}

// TestAutomatonWindow is the withdraw window, 3 hard of the last 5 decisive
// samples (the DESIGN-NOTES' W1–W6), with the reason and Since it carries.
func TestAutomatonWindow(t *testing.T) {
	tests := []struct {
		name, ticks, want string
		reason            Reason // the withdrawal's, when want has one
	}{
		{"W1 three hard in a row", "RRR", "uuW", ReasonRefused},
		{"W1 the tipping tick names the reason", "RUT", "uuW", ReasonNotTLS},
		{"W2 three of five", "ROROU", "uuuuW", ReasonUnbound},
		{"W3 the window keeps five", "RROOOR", "uuuuuu", ""},
		{"W3 an old hard sample drops out", "RROOOOR", "uuuuuuu", ""},
		{"W4 soft is not decisive", "RsRsR", "uuuuW", ReasonRefused},
		{"W5 blind is not decisive", "RRbbb", "uuuuu", ""},
		{"W5 none is not decisive", "RRnnn", "uuuuu", ""},
		{"soft never withdraws", "RR" + strings.Repeat("s", 9), strings.Repeat("u", 11), ""},
		{"a refusal with a listener is not decisive", "RRrrrR", "uuuuuW", ReasonRefused},
		{"W6 a restart shorter than two ticks", "RR" + autoOK(10), strings.Repeat("u", 11) + "A", ""},
		{"a withdrawal stays while the window holds", "RRRRRRR", "uuWWWWW", ReasonRefused},
		{"a withdrawal keeps the reason that tipped it", "RRRUUU", "uuWWWW", ReasonRefused},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAutomaton(DefaultConfig(), Saved{})
			vs, _ := autoRun(a, autoT0, tc.ticks)
			if got := autoStates(vs); got != tc.want {
				t.Fatalf("ticks %s: states %s, want %s", tc.ticks, got, tc.want)
			}
			out := strings.IndexByte(tc.want, 'W')
			if out < 0 {
				return
			}
			last := vs[len(vs)-1]
			if last.Reason != tc.reason || !last.Since.Equal(vs[out].At) {
				t.Fatalf("withdrawal %+v, want reason %s since tick %d (%v)", last, tc.reason, out+1, vs[out].At)
			}
			if !last.RejoinAt.IsZero() || a.Saved().Level != 0 {
				t.Fatalf("withdrawal from unknown %+v, saved %+v: it is no flap, so no hold-down", last, a.Saved())
			}
		})
	}
}

func TestAutomatonWithdrawReasonPrecedence(t *testing.T) {
	tests := []struct {
		t    Triggers
		want Reason
	}{
		{Triggers{Unbound: true, Refused: true, NotTLS: true}, ReasonUnbound},
		{Triggers{Unbound: true, NotTLS: true}, ReasonUnbound},
		{Triggers{Refused: true, NotTLS: true}, ReasonRefused},
		{Triggers{NotTLS: true}, ReasonNotTLS},
	}
	for _, tc := range tests {
		a := NewAutomaton(DefaultConfig(), Saved{})
		var v Verdict
		for i := range 3 {
			v = a.Step(Inputs{Triggers: tc.t, Gates: autoOpen}, autoT0.Add(time.Duration(i)*time.Second))
		}
		if v.State != StateWithdraw || v.Reason != tc.want {
			t.Errorf("%+v three times: %+v, want withdraw for %s", tc.t, v, tc.want)
		}
		if e := a.Evaluate(Inputs{Triggers: tc.t}, autoT0); e.Reason != tc.want {
			t.Errorf("%+v: Evaluate names %s, want %s as Step does", tc.t, e.Reason, tc.want)
		}
	}
}

// TestAutomatonJoinStreak is the join: RecoverAfter ok samples in a row (the
// DESIGN-NOTES' S1–S3), broken by anything but blind and none.
func TestAutomatonJoinStreak(t *testing.T) {
	tests := []struct {
		name, ticks string
		join        int // the tick that announces, from 1
	}{
		{"S1 ten ok", autoOK(10), 10},
		{"S2 soft restarts the run", autoOK(9) + "s" + autoOK(10), 20},
		{"S3 blind leaves the run as it is", autoOK(5) + "b" + autoOK(5), 11},
		{"S3 none leaves the run as it is", autoOK(5) + "n" + autoOK(5), 11},
		{"a refusal with a listener restarts the run", autoOK(5) + "r" + autoOK(10), 16},
		{"a hard sample restarts the run", autoOK(5) + "R" + autoOK(10), 16},
		{"an unbound tick restarts the run", autoOK(5) + "U" + autoOK(10), 16},
		{"after a withdrawal, a full run again", "RRR" + autoOK(10), 13},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAutomaton(DefaultConfig(), Saved{})
			vs, _ := autoRun(a, autoT0, tc.ticks)
			states := autoStates(vs)
			join := strings.IndexByte(states, 'A')
			if join+1 != tc.join || strings.Trim(states[join:], "A") != "" {
				t.Fatalf("ticks %s: states %s, want the join at tick %d and announce after it", tc.ticks, states, tc.join)
			}
			if v := vs[join]; v.Reason != ReasonOK || !v.Since.Equal(v.At) || !v.RejoinAt.IsZero() || v.Warning != "" {
				t.Fatalf("join verdict %+v, want announce for ok since its own tick", v)
			}
		})
	}
}

// TestAutomatonGatesHoldTheJoin is S4: a closed gate keeps a full streak out,
// names itself, and the join comes on the first tick every gate is open.
func TestAutomatonGatesHoldTheJoin(t *testing.T) {
	tests := []struct {
		name    string
		closed  Gates
		warning Reason
	}{
		{"generation not live", Gates{Zones: 3}, ReasonGenerationNotLive},
		{"no zones", Gates{GenerationLive: true}, ReasonNoZones},
		{"both, the generation named first", Gates{}, ReasonGenerationNotLive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, start := range []string{"", "RRR"} { // from unknown, and from withdraw
				a := NewAutomaton(DefaultConfig(), Saved{})
				_, now := autoRun(a, autoT0, start)
				for range 15 {
					v := a.Step(Inputs{Probe: ClassOK, Gates: tc.closed}, now)
					if v.State == StateAnnounce || v.Warning != tc.warning {
						t.Fatalf("after %q, a full streak behind a closed gate: %+v, want held with warning %s", start, v, tc.warning)
					}
					now = now.Add(time.Second)
				}
				v := a.Step(Inputs{Probe: ClassOK, Gates: autoOpen}, now)
				if v.State != StateAnnounce || v.Warning != "" || !v.Since.Equal(now) {
					t.Fatalf("after %q, the gate opens: %+v, want the join at once", start, v)
				}
			}
		})
	}
}

// TestAutomatonKeepsAnAnnouncedTargetWhenAGateCloses is G1: a lost gate on an
// announced target is a warning, never a way out.
func TestAutomatonKeepsAnAnnouncedTargetWhenAGateCloses(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	since := at.Add(-time.Second)
	for _, g := range []struct {
		gates   Gates
		warning Reason
	}{
		{Gates{Zones: 4}, ReasonGenerationNotLive},   // a `nginx -t` in progress
		{Gates{GenerationLive: true}, ReasonNoZones}, // the document emptied
		{Gates{}, ReasonGenerationNotLive},
		{autoOpen, ""},
	} {
		for _, probe := range []Class{ClassOK, ClassSoft, ClassBlind} {
			v := a.Step(Inputs{Probe: probe, Gates: g.gates}, at)
			if v.State != StateAnnounce || v.Reason != ReasonOK || !v.Since.Equal(since) || v.Warning != g.warning {
				t.Fatalf("announced, gates %+v, probe %s: %+v, want announce since %v with warning %q", g.gates, probe, v, since, g.warning)
			}
			at = at.Add(time.Second)
		}
	}
}

// TestAutomatonHoldDownHoldsTheRejoin is L1: a flap withdraws, arms 10 s, and
// a full streak waits for its end.
func TestAutomatonHoldDownHoldsTheRejoin(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	w, _ := autoFlap(t, a, at)
	end := w.At.Add(10 * time.Second)
	if w.Reason != ReasonRefused || !w.RejoinAt.Equal(end) || !a.Saved().Equal(Saved{Level: 1, Until: end}) {
		t.Fatalf("flap: %+v, saved %+v, want refused, level 1, rejoin at %v", w, a.Saved(), end)
	}
	// Ok every half second: the streak is full after five seconds, and the
	// hold-down still holds until ten.
	for now := w.At.Add(500 * time.Millisecond); ; now = now.Add(500 * time.Millisecond) {
		v := a.Step(autoTick('O'), now)
		if now.Before(end) {
			if v.State != StateWithdraw || !v.RejoinAt.Equal(end) || !v.Since.Equal(w.Since) {
				t.Fatalf("%v into the hold-down: %+v, want withdraw until %v", now.Sub(w.At), v, end)
			}
			continue
		}
		if v.State != StateAnnounce || !v.Since.Equal(end) || !v.RejoinAt.IsZero() {
			t.Fatalf("at the hold-down's end: %+v, want the join", v)
		}
		break
	}
	if !a.Saved().Equal(Saved{Level: 1}) {
		t.Fatalf("after the join, saved %+v: the level stays until LevelReset, the hold-down is over", a.Saved())
	}
}

// TestAutomatonHoldDownLadder is L2: the hold-down doubles per flap from 10 s
// to the cap.
func TestAutomatonHoldDownLadder(t *testing.T) {
	s := time.Second
	tests := []struct {
		name string
		cfg  Config
		want []time.Duration
	}{
		{"default cap 60 s", DefaultConfig(), []time.Duration{10 * s, 20 * s, 40 * s, 60 * s, 60 * s}},
		{"cap raised to 600 s", Config{HoldDownMax: 600 * s}, []time.Duration{10 * s, 20 * s, 40 * s, 80 * s, 160 * s, 320 * s, 600 * s, 600 * s}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, at := autoAnnounced(t, tc.cfg)
			for i, want := range tc.want {
				w, _ := autoFlap(t, a, at)
				if got := w.RejoinAt.Sub(w.At); got != want || a.Saved().Level != i+1 {
					t.Fatalf("flap %d: hold-down %v at level %d, want %v at level %d", i+1, got, a.Saved().Level, want, i+1)
				}
				// A full streak that ends on the hold-down's last second.
				vs, next := autoRun(a, w.RejoinAt.Add(-9*time.Second), autoOK(10))
				if got := autoStates(vs); got != "WWWWWWWWWA" || !vs[9].Since.Equal(w.RejoinAt) {
					t.Fatalf("flap %d: rejoin states %s, joined %v, want the join at %v", i+1, got, vs[9].Since, w.RejoinAt)
				}
				at = next
			}
		})
	}
}

// TestAutomatonLevelResetsAfterLevelResetAnnounced is L3: 600 s announced
// forgives the ladder, 599 s does not, and each join restarts that count.
func TestAutomatonLevelResetsAfterLevelResetAnnounced(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	w, _ := autoFlap(t, a, at)
	vs, _ := autoRun(a, w.RejoinAt.Add(-9*time.Second), autoOK(10))
	joined := vs[9].Since

	// A second flap 300 s in: level 2, and the count starts over at its join.
	w, _ = autoFlap(t, a, joined.Add(300*time.Second))
	if a.Saved().Level != 2 || w.RejoinAt.Sub(w.At) != 20*time.Second {
		t.Fatalf("second flap: saved %+v, hold-down %v, want level 2 and 20 s", a.Saved(), w.RejoinAt.Sub(w.At))
	}
	vs, _ = autoRun(a, w.RejoinAt.Add(-9*time.Second), autoOK(10))
	rejoined := vs[9].Since
	a.Step(autoTick('O'), joined.Add(600*time.Second))
	if a.Saved().Level != 2 {
		t.Fatalf("600 s after the first join, %v after the second: level %d, want still 2", joined.Add(600*time.Second).Sub(rejoined), a.Saved().Level)
	}
	a.Step(autoTick('O'), rejoined.Add(599*time.Second))
	if a.Saved().Level != 2 {
		t.Fatalf("599 s announced: level %d, want still 2", a.Saved().Level)
	}
	a.Step(autoTick('O'), rejoined.Add(600*time.Second))
	if !a.Saved().Equal(Saved{}) {
		t.Fatalf("600 s announced: saved %+v, want the ladder forgiven", a.Saved())
	}
	w, _ = autoFlap(t, a, rejoined.Add(601*time.Second))
	if a.Saved().Level != 1 || w.RejoinAt.Sub(w.At) != 10*time.Second {
		t.Fatalf("the flap after the reset: saved %+v, hold-down %v, want the first rung again", a.Saved(), w.RejoinAt.Sub(w.At))
	}
}

// TestAutomatonWithdrawFromUnknownIsNoFlap is L4: a target that was never in
// is taken out without a rung on the ladder, but a restored hold-down holds.
func TestAutomatonWithdrawFromUnknownIsNoFlap(t *testing.T) {
	a := NewAutomaton(DefaultConfig(), Saved{})
	vs, at := autoRun(a, autoT0, "RRR")
	if v := vs[2]; v.State != StateWithdraw || !v.RejoinAt.IsZero() || !a.Saved().Equal(Saved{}) {
		t.Fatalf("withdraw from unknown: %+v, saved %+v, want no level and no hold-down", v, a.Saved())
	}
	if vs, _ = autoRun(a, at, autoOK(10)); vs[9].State != StateAnnounce {
		t.Fatalf("a full streak after it: %+v, want the join with nothing to wait for", vs[9])
	}

	until := autoT0.Add(30 * time.Second)
	b := NewAutomaton(DefaultConfig(), Saved{Level: 2, Until: until})
	vs, at = autoRun(b, autoT0, "RRR")
	if v := vs[0]; v.State != StateUnknown || !v.RejoinAt.Equal(until) {
		t.Fatalf("restored hold-down, first tick: %+v, want unknown with rejoin at %v", v, until)
	}
	if v := vs[2]; v.State != StateWithdraw || !v.RejoinAt.Equal(until) || !b.Saved().Equal(Saved{Level: 2, Until: until}) {
		t.Fatalf("restored hold-down, withdraw from unknown: %+v, saved %+v, want the ladder untouched", v, b.Saved())
	}
	for now := at; ; now = now.Add(time.Second) {
		v := b.Step(autoTick('O'), now)
		if now.Before(until) != (v.State == StateWithdraw) {
			t.Fatalf("at %v: %+v, want withdraw before %v and the join at it", now.Sub(autoT0), v, until)
		}
		if v.State == StateAnnounce {
			break
		}
	}
}

// TestAutomatonDrainWinsAndSamplesNothing is D1: a drain beats the triggers,
// samples nothing while it lasts, and grows no hold-down.
func TestAutomatonDrainWinsAndSamplesNothing(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	first := at
	for range 3 {
		in := autoTick('R')
		in.Triggers.Drained, in.Drain = true, Drain{Reason: "maintenance"}
		v := a.Step(in, at)
		if v.State != StateDrain || v.Reason != ReasonDrained || !v.Since.Equal(first) || !v.RejoinAt.IsZero() || v.Warning != "" {
			t.Fatalf("drained and refused: %+v, want drain since %v", v, first)
		}
		at = at.Add(time.Second)
	}
	if !a.Saved().Equal(Saved{}) {
		t.Fatalf("a drain over an announced target: saved %+v, want no flap", a.Saved())
	}
	vs, at := autoRun(a, at, "RR")
	if got := autoStates(vs); got != "uu" || vs[0].Reason != ReasonStarting || !vs[0].Since.Equal(vs[0].At) {
		t.Fatalf("lifted, two refusals: %s %+v, want unknown/starting — the refusals under the drain were never counted", got, vs[0])
	}
	if vs, _ = autoRun(a, at, "R"); vs[0].State != StateWithdraw || !a.Saved().Equal(Saved{}) {
		t.Fatalf("the third refusal: %+v, saved %+v, want withdraw, and from unknown no flap", vs[0], a.Saved())
	}
}

// TestAutomatonDrainLiftStartsOver is D2: a drain takes an announced target
// out at once; the lift clears the window and the streak, and the way back is
// a full streak with no hold-down.
func TestAutomatonDrainLiftStartsOver(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	_, at = autoRun(a, at, "RR") // two hard samples in the window, still in
	if v := a.Step(autoTick('D'), at); v.State != StateDrain || !v.Since.Equal(at) {
		t.Fatalf("drained: %+v, want drain at once", v)
	}
	lift := at.Add(time.Second)
	vs, at := autoRun(a, lift, "R"+autoOK(5))
	if v := vs[0]; v.State != StateUnknown || v.Reason != ReasonStarting || !v.Since.Equal(lift) {
		t.Fatalf("lifted on a refusal: %+v, want unknown/starting since the lift — the window was cleared", v)
	}
	a.Step(autoTick('D'), at)
	vs, _ = autoRun(a, at.Add(time.Second), autoOK(10))
	if got := autoStates(vs); got != "uuuuuuuuuA" {
		t.Fatalf("five ok, a drain, then ten ok: states %s, want the join on the tenth — the streak was cleared", got)
	}
	if v := vs[9]; !v.RejoinAt.IsZero() || !a.Saved().Equal(Saved{}) {
		t.Fatalf("the join after a drain: %+v, saved %+v, want no hold-down", v, a.Saved())
	}
}

// TestAutomatonDrainReasons is D3 and D4: the new-node drain reads apart from
// an operator's, a change of reason is the same drain, and the very first
// tick may already be drained.
func TestAutomatonDrainReasons(t *testing.T) {
	a := NewAutomaton(DefaultConfig(), Saved{})
	steps := []struct {
		in   Inputs
		want Reason
	}{
		{autoTick('N'), ReasonNewNode},
		{autoTick('D'), ReasonDrained},
		{Inputs{Triggers: Triggers{Drained: true}}, ReasonDrained}, // an empty drain file
		{autoTick('N'), ReasonNewNode},
	}
	for i, s := range steps {
		now := autoT0.Add(time.Duration(i) * time.Second)
		v := a.Step(s.in, now)
		if v.State != StateDrain || v.Reason != s.want || !v.Since.Equal(autoT0) {
			t.Fatalf("step %d: %+v, want drain for %s since the first tick", i, v, s.want)
		}
	}
}

// TestAutomatonDrainKeepsARunningHoldDown: a drain over a withdrawn target
// leaves its hold-down as it is, and the lift still waits for it.
func TestAutomatonDrainKeepsARunningHoldDown(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	w, at := autoFlap(t, a, at)
	saved := a.Saved()
	_, at = autoRun(a, at, "DDDD")
	if !a.Saved().Equal(saved) {
		t.Fatalf("drained during a hold-down: saved %+v, want %+v", a.Saved(), saved)
	}
	vs, _ := autoRun(a, at, autoOK(10))
	for _, v := range vs {
		if v.At.Before(w.RejoinAt) && (v.State == StateAnnounce || !v.RejoinAt.Equal(w.RejoinAt)) {
			t.Fatalf("lifted before the hold-down's end: %+v, want held until %v", v, w.RejoinAt)
		}
	}
	if v := vs[9]; v.State != StateAnnounce || v.At.Before(w.RejoinAt) {
		t.Fatalf("a full streak after the hold-down: %+v, want the join", v)
	}
}

func TestAutomatonSavedTracksTheLadder(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	if !a.Saved().Equal(Saved{}) {
		t.Fatalf("never flapped: saved %+v", a.Saved())
	}
	w, _ := autoFlap(t, a, at)
	if !a.Saved().Equal(Saved{Level: 1, Until: w.RejoinAt}) {
		t.Fatalf("flapped: saved %+v, want level 1 until %v", a.Saved(), w.RejoinAt)
	}
	a.Step(autoTick('s'), w.RejoinAt)
	if !a.Saved().Equal(Saved{Level: 1}) {
		t.Fatalf("the hold-down ran out: saved %+v, want level 1 and no Until — state.json records no hold-down that is over", a.Saved())
	}
}

func TestAutomatonRestoresTheLadder(t *testing.T) {
	until := autoT0.Add(15 * time.Second)
	tests := []struct {
		name        string
		saved, want Saved
	}{
		{"as saved", Saved{Level: 2, Until: until}, Saved{Level: 2, Until: until}},
		{"a negative level is 0", Saved{Level: -3}, Saved{}},
		{"a huge level is capped", Saved{Level: math.MaxInt}, Saved{Level: autoMaxLevel}},
	}
	for _, tc := range tests {
		if got := NewAutomaton(DefaultConfig(), tc.saved).Saved(); !got.Equal(tc.want) {
			t.Errorf("%s: NewAutomaton(%+v).Saved() = %+v, want %+v", tc.name, tc.saved, got, tc.want)
		}
	}

	// At the cap a flap neither overflows nor shortens the hold-down.
	a := NewAutomaton(DefaultConfig(), Saved{Level: math.MaxInt})
	_, at := autoRun(a, autoT0, autoOK(10))
	w, _ := autoFlap(t, a, at)
	if a.Saved().Level != autoMaxLevel || w.RejoinAt.Sub(w.At) != DefaultHoldDownMax {
		t.Fatalf("a flap at the capped level: saved %+v, hold-down %v, want the cap and %v", a.Saved(), w.RejoinAt.Sub(w.At), DefaultHoldDownMax)
	}
}

// TestAutomatonResetHoldDown: the operator's reset lets a withdrawn target
// with a full streak join on the next tick; its twin without the reset waits.
func TestAutomatonResetHoldDown(t *testing.T) {
	var twins [2]*Automaton
	var w Verdict
	for i := range twins {
		a, at := autoAnnounced(t, DefaultConfig())
		w, _ = autoFlap(t, a, at)
		for k := 1; k <= 10; k++ {
			a.Step(autoTick('O'), w.At.Add(time.Duration(k)*500*time.Millisecond))
		}
		twins[i] = a
	}
	twins[0].ResetHoldDown()
	if !twins[0].Saved().Equal(Saved{}) {
		t.Fatalf("after ResetHoldDown: saved %+v, want nothing", twins[0].Saved())
	}
	next := w.At.Add(5500 * time.Millisecond)
	if v := twins[0].Step(autoTick('O'), next); v.State != StateAnnounce {
		t.Fatalf("reset, full streak: %+v, want the join", v)
	}
	if v := twins[1].Step(autoTick('O'), next); v.State != StateWithdraw || !v.RejoinAt.Equal(w.RejoinAt) {
		t.Fatalf("not reset: %+v, want still held until %v", v, w.RejoinAt)
	}
}

func TestVerdictAsOf(t *testing.T) {
	at := autoT0.Add(5 * time.Second)
	v := Verdict{State: StateWithdraw, Reason: ReasonRefused, Since: autoT0, RejoinAt: autoT0.Add(10 * time.Second), At: at, Warning: ReasonNoZones}
	stale := Verdict{State: StateUnknown, Reason: ReasonStale, Since: at, At: at}
	tests := []struct {
		name string
		now  time.Time
		want Verdict
	}{
		{"fresh", at, v},
		{"three intervals old", at.Add(3 * time.Second), v},
		{"past three intervals", at.Add(3*time.Second + time.Nanosecond), stale},
		{"long stopped", at.Add(time.Hour), stale},
	}
	for _, tc := range tests {
		if got := v.AsOf(tc.now, DefaultConfig().StaleAfter()); !autoSame(got, tc.want) {
			t.Errorf("%s: AsOf = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if got := (Verdict{State: StateAnnounce, Reason: ReasonOK}).AsOf(at, time.Hour); !autoSame(got, Verdict{State: StateUnknown, Reason: ReasonStale}) {
		t.Errorf("a verdict never evaluated: AsOf = %+v, want unknown/stale", got)
	}

	// A sampler that stopped on a withdrawal: its readers hold, they never
	// keep withdrawing on its last word.
	a := NewAutomaton(DefaultConfig(), Saved{})
	vs, at := autoRun(a, autoT0, "RRR")
	if got := vs[2].AsOf(at.Add(DefaultConfig().StaleAfter()), DefaultConfig().StaleAfter()); got.State != StateUnknown {
		t.Errorf("a stopped sampler's withdrawal, read late: %+v, want unknown", got)
	}
}

// TestEvaluate is the undamped one-shot (the DESIGN-NOTES' E1–E4).
func TestEvaluate(t *testing.T) {
	now := autoT0.Add(time.Minute)
	until := now.Add(7 * time.Second)
	idle := NewAutomaton(DefaultConfig(), Saved{})
	holding := NewAutomaton(DefaultConfig(), Saved{Level: 1, Until: until})
	over := NewAutomaton(DefaultConfig(), Saved{Level: 3, Until: now})
	tests := []struct {
		name string
		a    *Automaton
		in   Inputs
		want Verdict
	}{
		{"E1 drained beats refused", holding, Inputs{Triggers: Triggers{Drained: true, Refused: true}, Drain: Drain{Reason: "maintenance"}},
			Verdict{State: StateDrain, Reason: ReasonDrained, Since: now, At: now}},
		{"E1 the new-node drain", idle, Inputs{Triggers: Triggers{Drained: true}, Drain: Drain{Reason: NewNodeReason}},
			Verdict{State: StateDrain, Reason: ReasonNewNode, Since: now, At: now}},
		{"E2 hard", idle, Inputs{Triggers: Triggers{Refused: true}, Probe: ClassRefused, Gates: autoOpen},
			Verdict{State: StateWithdraw, Reason: ReasonRefused, Since: now, At: now}},
		{"E2 hard during a hold-down", holding, Inputs{Triggers: Triggers{Unbound: true}, Gates: Gates{}},
			Verdict{State: StateWithdraw, Reason: ReasonUnbound, Since: now, RejoinAt: until, At: now, Warning: ReasonGenerationNotLive}},
		{"E3 a running hold-down", holding, Inputs{Probe: ClassOK, Gates: autoOpen},
			Verdict{State: StateWithdraw, Reason: ReasonHoldDown, Since: now, RejoinAt: until, At: now}},
		{"E3 a hold-down that ends now is over", over, Inputs{Probe: ClassOK, Gates: autoOpen},
			Verdict{State: StateAnnounce, Reason: ReasonUnmanaged, Since: now, At: now}},
		{"E4 ok", idle, Inputs{Probe: ClassOK, Gates: autoOpen},
			Verdict{State: StateAnnounce, Reason: ReasonUnmanaged, Since: now, At: now}},
		{"E4 soft announces", idle, Inputs{Probe: ClassSoft, Gates: autoOpen},
			Verdict{State: StateAnnounce, Reason: ReasonUnmanaged, Since: now, At: now}},
		{"E4 a refusal with a listener announces", idle, Inputs{Probe: ClassRefused, Gates: autoOpen},
			Verdict{State: StateAnnounce, Reason: ReasonUnmanaged, Since: now, At: now}},
		{"E4 a closed gate announces, named", idle, Inputs{Probe: ClassOK, Gates: Gates{GenerationLive: true}},
			Verdict{State: StateAnnounce, Reason: ReasonUnmanaged, Since: now, At: now, Warning: ReasonNoZones}},
	}
	for _, tc := range tests {
		if got := tc.a.Evaluate(tc.in, now); !autoSame(got, tc.want) {
			t.Errorf("%s: Evaluate = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestEvaluateChangesNothing is E5: twins stepped through one script, one of
// them evaluating every tick's inputs — and some others — first, answer the
// same at every tick and save the same.
func TestEvaluateChangesNothing(t *testing.T) {
	saved := Saved{Level: 1, Until: autoT0.Add(5 * time.Second)}
	a, b := NewAutomaton(DefaultConfig(), saved), NewAutomaton(DefaultConfig(), saved)
	script := autoOK(10) + "RRR" + autoOK(12) + "DDN" + "RsRbR" + autoOK(10) + "UUU" + autoOK(3)
	now := autoT0
	for i := range len(script) {
		in := autoTick(script[i])
		before := b.Saved()
		for _, e := range []Inputs{in, autoTick('R'), autoTick('D'), autoTick('O'), {}} {
			b.Evaluate(e, now)
		}
		if !b.Saved().Equal(before) {
			t.Fatalf("tick %d: Evaluate moved saved from %+v to %+v", i, before, b.Saved())
		}
		if va, vb := a.Step(in, now), b.Step(in, now); !autoSame(va, vb) {
			t.Fatalf("tick %d (%c): stepped %+v, with Evaluate before %+v", i, script[i], va, vb)
		}
		now = now.Add(time.Second)
	}
}

func TestConfigDefaults(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() = %v", err)
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("Config{}.Validate() = %v: a zero field is its default", err)
	}
	if got := (Config{}).normalized(); got != DefaultConfig() {
		t.Fatalf("Config{}.normalized() = %+v, want %+v", got, DefaultConfig())
	}
	neg := Config{Interval: -1, FailAfter: -1, FailWindow: -1, RecoverAfter: -1, HoldDownMin: -1, HoldDownMax: -1, LevelReset: -1}
	if err := neg.Validate(); err != nil || neg.normalized() != DefaultConfig() {
		t.Fatalf("negative fields: Validate %v, normalized %+v; a negative field is its default", err, neg.normalized())
	}
}

func TestConfigValidate(t *testing.T) {
	s := time.Second
	tests := []struct {
		name string
		cfg  Config
		bad  []string // what the error names, one entry per broken bound
	}{
		{"interval at its bounds", Config{Interval: 10 * s}, nil},
		{"interval below 1 s", Config{Interval: 500 * time.Millisecond}, []string{"interval"}},
		{"interval above 10 s", Config{Interval: 11 * s}, []string{"interval"}},
		{"window at its bound", Config{FailWindow: 60, FailAfter: 60}, nil},
		{"window above 60", Config{FailWindow: 61}, []string{"fail_window"}},
		{"fail_after above the window", Config{FailAfter: 6}, []string{"fail_after"}},
		{"a window below the default fail_after", Config{FailWindow: 2}, []string{"fail_after"}},
		{"recover_after at its bounds", Config{RecoverAfter: 3}, nil},
		{"recover_after below 3", Config{RecoverAfter: 2}, []string{"recover_after"}},
		{"recover_after above 120", Config{RecoverAfter: 121}, []string{"recover_after"}},
		{"hold-down at the ceiling", Config{HoldDownMin: s, HoldDownMax: 600 * s}, nil},
		{"hold-down min below 1 s", Config{HoldDownMin: 500 * time.Millisecond}, []string{"hold_down min"}},
		{"hold-down max below the default min", Config{HoldDownMax: 5 * s}, []string{"exceeds hold_down max"}},
		{"hold-down max above the ceiling", Config{HoldDownMax: 601 * s}, []string{"ceiling"}},
		{"level reset at its bounds", Config{LevelReset: 24 * time.Hour}, nil},
		{"level reset below 1 s", Config{LevelReset: time.Millisecond}, []string{"level reset"}},
		{"level reset above 24 h", Config{LevelReset: 25 * time.Hour}, []string{"level reset"}},
		{"every broken bound is named", Config{Interval: time.Minute, FailWindow: 99, RecoverAfter: 1000, HoldDownMax: time.Hour},
			[]string{"interval", "fail_window", "recover_after", "ceiling"}},
	}
	for _, tc := range tests {
		err := tc.cfg.Validate()
		if len(tc.bad) == 0 {
			if err != nil {
				t.Errorf("%s: Validate = %v, want nil", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: Validate = nil, want an error naming %q", tc.name, tc.bad)
			continue
		}
		lines := strings.Split(err.Error(), "\n")
		if len(lines) != len(tc.bad) {
			t.Errorf("%s: Validate = %q, want %d problems", tc.name, err, len(tc.bad))
			continue
		}
		for i, want := range tc.bad {
			if !strings.Contains(lines[i], want) {
				t.Errorf("%s: problem %d is %q, want it to name %q", tc.name, i, lines[i], want)
			}
		}
		if err := tc.cfg.normalized().Validate(); err != nil {
			t.Errorf("%s: the normalized config does not validate: %v", tc.name, err)
		}
	}
}

func TestConfigNormalized(t *testing.T) {
	s := time.Second
	tests := []struct {
		name string
		cfg  Config
		want Config
	}{
		{"everything past its bounds",
			Config{Interval: time.Millisecond, FailAfter: 99, FailWindow: 100, RecoverAfter: 1000, HoldDownMin: time.Millisecond, HoldDownMax: time.Hour, LevelReset: 48 * time.Hour},
			Config{Interval: s, FailAfter: 60, FailWindow: 60, RecoverAfter: 120, HoldDownMin: s, HoldDownMax: 600 * s, LevelReset: 24 * time.Hour}},
		{"a long interval", Config{Interval: time.Minute},
			Config{Interval: 10 * s, FailAfter: 3, FailWindow: 5, RecoverAfter: 10, HoldDownMin: 10 * s, HoldDownMax: 60 * s, LevelReset: 600 * s}},
		{"fail_after follows a short window", Config{FailWindow: 2},
			Config{Interval: s, FailAfter: 2, FailWindow: 2, RecoverAfter: 10, HoldDownMin: 10 * s, HoldDownMax: 60 * s, LevelReset: 600 * s}},
		{"min follows a lower max", Config{HoldDownMin: 30 * s, HoldDownMax: 20 * s},
			Config{Interval: s, FailAfter: 3, FailWindow: 5, RecoverAfter: 10, HoldDownMin: 20 * s, HoldDownMax: 20 * s, LevelReset: 600 * s}},
		{"recover_after below 3", Config{RecoverAfter: 1},
			Config{Interval: s, FailAfter: 3, FailWindow: 5, RecoverAfter: 3, HoldDownMin: 10 * s, HoldDownMax: 60 * s, LevelReset: 600 * s}},
	}
	for _, tc := range tests {
		got := tc.cfg.normalized()
		if got != tc.want {
			t.Errorf("%s: normalized = %+v, want %+v", tc.name, got, tc.want)
		}
		if again := got.normalized(); again != got {
			t.Errorf("%s: normalized twice = %+v, want %+v", tc.name, again, got)
		}
	}
}

func TestConfigHoldDown(t *testing.T) {
	s := time.Second
	tests := []struct {
		name string
		cfg  Config
		want map[int]time.Duration
	}{
		{"default", DefaultConfig(), map[int]time.Duration{
			math.MinInt: 0, -1: 0, 0: 0, 1: 10 * s, 2: 20 * s, 3: 40 * s, 4: 60 * s, 5: 60 * s, 1e6: 60 * s, math.MaxInt: 60 * s}},
		{"zero config takes the defaults", Config{}, map[int]time.Duration{1: 10 * s, 3: 40 * s, 4: 60 * s}},
		{"cap 600 s", Config{HoldDownMax: 600 * s}, map[int]time.Duration{
			4: 80 * s, 5: 160 * s, 6: 320 * s, 7: 600 * s, 62: 600 * s, math.MaxInt: 600 * s}},
		{"the widest ladder", Config{HoldDownMin: s, HoldDownMax: 600 * s}, map[int]time.Duration{
			1: s, 10: 512 * s, 11: 600 * s, math.MaxInt: 600 * s}},
		{"an odd ladder", Config{HoldDownMin: 7 * s, HoldDownMax: 50 * s}, map[int]time.Duration{
			1: 7 * s, 2: 14 * s, 3: 28 * s, 4: 50 * s, 5: 50 * s}},
	}
	for _, tc := range tests {
		for level, want := range tc.want {
			if got := tc.cfg.HoldDown(level); got != want {
				t.Errorf("%s: HoldDown(%d) = %v, want %v", tc.name, level, got, want)
			}
		}
	}
}

func TestConfigStaleAfter(t *testing.T) {
	s := time.Second
	for _, tc := range []struct {
		cfg  Config
		want time.Duration
	}{
		{DefaultConfig(), 3 * s},
		{Config{}, 3 * s},
		{Config{Interval: 2 * s}, 6 * s},
		{Config{Interval: time.Minute}, 30 * s},
		{Config{Interval: 100 * time.Millisecond}, 3 * s},
	} {
		if got := tc.cfg.StaleAfter(); got != tc.want {
			t.Errorf("%+v: StaleAfter = %v, want %v", tc.cfg, got, tc.want)
		}
	}
}

// TestAutomatonOnlyOutTakesATargetOut reads machine.go and pins I2's shape
// (Automaton's doc comment): StateDrain and StateWithdraw are entered in out
// and nowhere else, out takes a Triggers value, the drain's reason and the
// time — nothing a gate, the probe class or the report could steer — and the
// state field is assigned in enter alone. A second way out of service fails
// here, whether or not a behavioural test happens to walk it.
func TestAutomatonOnlyOutTakesATargetOut(t *testing.T) {
	const rule = "\nI2: withdraw is reachable only from Triggers. The code that enters StateWithdraw or StateDrain\n" +
		"sits in one unexported method, out, whose inputs are a Triggers value, the drain's reason and\n" +
		"the time; gates, the probe class and the report reach the join path and nothing else."
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "machine.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var outs []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if name == "out" {
			var params []string
			for _, f := range fn.Type.Params.List {
				for range max(len(f.Names), 1) {
					params = append(params, types.ExprString(f.Type))
				}
			}
			if want := []string{"Triggers", "string", "time.Time"}; !slices.Equal(params, want) {
				t.Errorf("out takes (%s), want (%s)%s", strings.Join(params, ", "), strings.Join(want, ", "), rule)
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "state" && name != "enter" {
						t.Errorf("%s: %s assigns the automaton's state; only enter may%s", fset.Position(n.Pos()), name, rule)
					}
				}
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "enter" || len(n.Args) == 0 {
					return true
				}
				id, ok := n.Args[0].(*ast.Ident)
				if !ok {
					t.Errorf("%s: %s calls enter with a computed state, which this pin cannot read; name it%s", fset.Position(n.Pos()), name, rule)
					return true
				}
				if id.Name == "StateDrain" || id.Name == "StateWithdraw" {
					outs = append(outs, name+":"+id.Name)
				}
			}
			return true
		})
	}
	slices.Sort(outs)
	if want := []string{"out:StateDrain", "out:StateWithdraw"}; !slices.Equal(outs, want) {
		t.Errorf("the calls that enter StateDrain or StateWithdraw are %v, want exactly %v%s", outs, want, rule)
	}
}

// T3 (DESIGN-NOTES §5.4): no non-trigger input changes a withdrawal. Per tick,
// the triggers and whether the probe answered TLS are held fixed; the gates,
// the report, the drain content without the drain and the class of a probe
// that did not answer TLS vary.
var (
	autoGateChoices = []Gates{
		autoOpen, {GenerationLive: true, Zones: 5}, {GenerationLive: true}, {Zones: 5}, {},
		{GenerationLive: true, Zones: -1},
	}
	autoReportChoices = []Report{
		{},
		{Terminator: Process{State: PIDGone}},
		{Terminator: Process{State: PIDAlive, Frozen: true}},
		{Listening: TriYes, ProbeErr: "dial tcp 192.0.2.10:443: connect: connection refused"},
		{Listening: TriNo, ProbeErr: "read tcp: i/o timeout"},
		{ProcErr: "open net/tcp: permission denied"},
		{DrainErr: "drain: unexpected end of JSON input"},
		{LogProgress: TriNo},
		{LogProgress: TriYes},
	}
	autoDrainChoices = []Drain{{}, {Reason: NewNodeReason}, {Reason: "maintenance", Since: autoT0}}
	// autoNonOK are the classes of a probe that did not answer TLS, the last
	// one a class nobody named.
	autoNonOK = []Class{ClassSoft, ClassBlind, ClassNone, ClassRefused, ClassNotTLS, Class(200)}
)

// autoPair is what T3 holds fixed at one tick: the triggers, whether the
// probe answered TLS, and the time to the next tick.
type autoPair struct {
	t  Triggers
	ok bool
	dt time.Duration
}

// autoScript draws one T3 sequence: runs of ok ticks, hard ticks, ticks that
// are neither and drained ticks — runs long enough that joins, withdrawals,
// flaps and drains all happen — with now and then a gap long enough for a
// hold-down to run out.
func autoScript(r *rand.Rand) []autoPair {
	n := 20 + r.IntN(41)
	seq := make([]autoPair, 0, n)
	for len(seq) < n {
		kind, run := r.IntN(10), 1+r.IntN(4)
		if kind < 4 {
			run = 1 + r.IntN(14)
		}
		for i := 0; i < run && len(seq) < n; i++ {
			p := autoPair{dt: time.Second}
			switch {
			case kind < 4:
				p.ok = true
			case kind < 7:
				// A hard tick is hard whatever the probe says.
				p.t, p.ok = autoHard(r), r.IntN(6) == 0
			case kind < 9:
				// Neither: no trigger, and no TLS answer.
			default:
				if r.IntN(2) == 0 {
					p.t = autoHard(r)
				}
				p.t.Drained = true
			}
			if r.IntN(12) == 0 {
				p.dt = time.Duration(2+r.IntN(90)) * time.Second
			}
			seq = append(seq, p)
		}
	}
	return seq
}

// autoHard draws a hard trigger set: at least one of Refused, NotTLS, Unbound.
func autoHard(r *rand.Rand) Triggers {
	for {
		t := Triggers{Refused: r.IntN(2) == 0, NotTLS: r.IntN(3) == 0, Unbound: r.IntN(4) == 0}
		if t.Hard() {
			return t
		}
	}
}

// autoWindowSays is T3's oracle, computed from the fixed pairs alone and never
// from the automaton: at each tick, whether FailAfter of the last FailWindow
// decisive samples since the start or the last drain are hard.
func autoWindowSays(seq []autoPair, cfg Config) []bool {
	says := make([]bool, len(seq))
	var window []bool
	for i, p := range seq {
		switch {
		case p.t.Drained:
			window = nil
			continue
		case p.t.Hard():
			window = append(window, true)
		case p.ok:
			window = append(window, false)
		}
		if len(window) > cfg.FailWindow {
			window = window[1:]
		}
		n := 0
		for _, hard := range window {
			if hard {
				n++
			}
		}
		says[i] = n >= cfg.FailAfter
	}
	return says
}

// autoVary builds T3 variation k's inputs for one tick over the fixed pair p.
// Variation 0 is the reference — every gate open, nothing in the report or the
// drain content, soft for a probe that did not answer TLS; the others draw all
// of that, odd ones the gates afresh each tick, even ones in stretches.
func autoVary(r *rand.Rand, k int, p autoPair, gates *Gates) Inputs {
	in := Inputs{Triggers: p.t, Probe: ClassSoft, Gates: autoOpen}
	if p.ok {
		in.Probe = ClassOK
	}
	if k == 0 {
		return in
	}
	if !p.ok {
		in.Probe = autoNonOK[r.IntN(len(autoNonOK))]
	}
	if k%2 == 1 || r.IntN(10) == 0 {
		*gates = autoGateChoices[r.IntN(len(autoGateChoices))]
	}
	in.Gates = *gates
	in.Report = autoReportChoices[r.IntN(len(autoReportChoices))]
	in.Drain = autoDrainChoices[r.IntN(len(autoDrainChoices))]
	return in
}

// autoT3Counts shows the variations walked what they claim to leave alone.
type autoT3Counts struct{ entries, flaps, joins, drains, differs int }

// autoRunT3 steps one variation through seq and asserts, at every tick: a
// drain is exactly the drain trigger; where the oracle's window has tipped the
// state is withdraw; and an entry into withdraw happens only on a hard tick
// that tips the oracle's window. It returns the states.
func autoRunT3(t *testing.T, cfg Config, seq []autoPair, says []bool, input func(autoPair) Inputs, n *autoT3Counts) []State {
	t.Helper()
	a := NewAutomaton(cfg, Saved{})
	now, prev := autoT0, StateUnknown
	states := make([]State, len(seq))
	for i, p := range seq {
		v := a.Step(input(p), now)
		states[i] = v.State
		entered := v.State != prev
		switch {
		case p.t.Drained != (v.State == StateDrain):
			t.Errorf("tick %d: drained %v, verdict %+v: a drain is the drain trigger, and nothing else", i, p.t.Drained, v)
		case says[i] && v.State != StateWithdraw:
			t.Errorf("tick %d: the triggers' window has tipped, and the verdict is %+v, not withdraw", i, v)
		case entered && v.State == StateWithdraw && (!says[i] || !p.t.Hard()):
			t.Errorf("tick %d: entered withdraw (%s) on no hard sample that tipped the triggers' window", i, v.Reason)
		}
		if t.Failed() {
			return states
		}
		if entered {
			switch v.State {
			case StateWithdraw:
				n.entries++
				if prev == StateAnnounce {
					n.flaps++
				}
			case StateAnnounce:
				n.joins++
			case StateDrain:
				n.drains++
			}
		}
		prev, now = v.State, now.Add(p.dt)
	}
	return states
}

// autoSpell writes a T3 sequence down for a failure message: O ok, H hard,
// K hard with an ok probe, - neither, D drained; +Ns a gap.
func autoSpell(seq []autoPair) string {
	var b strings.Builder
	for _, p := range seq {
		switch {
		case p.t.Drained:
			b.WriteByte('D')
		case p.t.Hard() && p.ok:
			b.WriteByte('K')
		case p.t.Hard():
			b.WriteByte('H')
		case p.ok:
			b.WriteByte('O')
		default:
			b.WriteByte('-')
		}
		if p.dt != time.Second {
			b.WriteString("+" + p.dt.String())
		}
	}
	return b.String()
}

// TestNonTriggerInputsNeverMoveAWithdrawal is T3 over random sequences: 1000
// per configuration, six variations each, under the defaults and two damping
// shapes the defaults never reach — RecoverAfter below the window, and a
// window of one.
func TestNonTriggerInputsNeverMoveAWithdrawal(t *testing.T) {
	configs := []Config{
		DefaultConfig(),
		{FailAfter: 2, FailWindow: 9, RecoverAfter: 3, HoldDownMin: 2 * time.Second, HoldDownMax: 8 * time.Second},
		{FailAfter: 1, FailWindow: 1, RecoverAfter: 3},
	}
	r := rand.New(rand.NewPCG(2026, 1112))
	var n autoT3Counts
	for _, cfg := range configs {
		cfg = cfg.normalized()
		for range 1000 {
			seq := autoScript(r)
			says := autoWindowSays(seq, cfg)
			var ref []State
			for k := range 6 {
				var gates Gates
				states := autoRunT3(t, cfg, seq, says, func(p autoPair) Inputs { return autoVary(r, k, p, &gates) }, &n)
				if t.Failed() {
					t.Fatalf("config %+v, variation %d, sequence %s", cfg, k, autoSpell(seq))
				}
				if k == 0 {
					ref = states
					continue
				}
				for i := range states {
					if states[i] != ref[i] {
						n.differs++
					}
				}
			}
		}
	}
	// Not vacuous: the sequences withdrew, flapped, joined and drained, and
	// the variations moved joins — which they may — without moving a single
	// withdrawal.
	t.Logf("T3 walked %+v", n)
	if n.entries < 3000 || n.flaps < 1000 || n.joins < 3000 || n.drains < 3000 || n.differs < 3000 {
		t.Fatalf("T3 walked too little to prove anything: %+v", n)
	}
}

// TestNonTriggerInputsKeepAnAnnouncedTargetIn is T3 from announce: with no
// trigger, no gate, probe class, report or drain content (without the drain)
// moves an announced target — and the triggers, each alone, do.
func TestNonTriggerInputsKeepAnAnnouncedTargetIn(t *testing.T) {
	for _, probe := range append([]Class{ClassOK}, autoNonOK...) {
		for _, gates := range autoGateChoices {
			for _, rep := range autoReportChoices {
				for _, d := range autoDrainChoices {
					a, at := autoAnnounced(t, DefaultConfig())
					since := at.Add(-time.Second)
					for range 20 {
						v := a.Step(Inputs{Probe: probe, Gates: gates, Report: rep, Drain: d}, at)
						if v.State != StateAnnounce || v.Reason != ReasonOK || !v.Since.Equal(since) || !a.Saved().Equal(Saved{}) {
							t.Fatalf("announced; probe %s, gates %+v, report %+v, drain content %+v: %+v, saved %+v; only Triggers take an address out",
								probe, gates, rep, d, v, a.Saved())
						}
						at = at.Add(time.Second)
					}
				}
			}
		}
	}
	for _, c := range "RTUD" {
		a, at := autoAnnounced(t, DefaultConfig())
		vs, _ := autoRun(a, at, strings.Repeat(string(c), 3))
		want := map[rune]string{'R': "AAW", 'T': "AAW", 'U': "AAW", 'D': "DDD"}[c]
		if got := autoStates(vs); got != want {
			t.Errorf("announced, then %c three times: states %s, want %s", c, got, want)
		}
	}
}

// TestNonTriggerInputsKeepAWithdrawalAsItIs is T3 from withdraw: after a flap,
// with no trigger, no variation drains the target, re-enters or renames its
// withdrawal, moves its rejoin time or its ladder; the one way on is a join,
// and only once the hold-down is over.
func TestNonTriggerInputsKeepAWithdrawalAsItIs(t *testing.T) {
	for _, probe := range append([]Class{ClassOK}, autoNonOK...) {
		for _, gates := range autoGateChoices {
			for _, rep := range autoReportChoices {
				for _, d := range autoDrainChoices {
					a, at := autoAnnounced(t, DefaultConfig())
					w, at := autoFlap(t, a, at)
					for range 15 {
						v := a.Step(Inputs{Probe: probe, Gates: gates, Report: rep, Drain: d}, at)
						switch v.State {
						case StateWithdraw:
							rejoin := w.RejoinAt
							if !at.Before(rejoin) {
								rejoin = time.Time{}
							}
							if v.Reason != w.Reason || !v.Since.Equal(w.Since) || !v.RejoinAt.Equal(rejoin) || a.Saved().Level != 1 {
								t.Fatalf("withdrawn; probe %s, gates %+v, report %+v, drain content %+v: %+v, saved %+v, want %+v as it was",
									probe, gates, rep, d, v, a.Saved(), w)
							}
						case StateAnnounce:
							if at.Before(w.RejoinAt) || probe != ClassOK || gates.Holding() != "" {
								t.Fatalf("withdrawn; probe %s, gates %+v: joined at %v, hold-down until %v", probe, gates, at, w.RejoinAt)
							}
						default:
							t.Fatalf("withdrawn; probe %s, gates %+v, report %+v, drain content %+v: %+v; no trigger, so no way but in",
								probe, gates, rep, d, v)
						}
						at = at.Add(time.Second)
					}
				}
			}
		}
	}
}

// TestNonTriggerInputsCoverEveryField keeps T3 honest as the types grow: Inputs
// has the five fields T3 knows how to hold or vary, and T3's choices set every
// field of the gates, the report and the drain somewhere. A new input is
// either a trigger — a design round — or something T3 must vary.
func TestNonTriggerInputsCoverEveryField(t *testing.T) {
	var names []string
	for i := range reflect.TypeOf(Inputs{}).NumField() {
		names = append(names, reflect.TypeOf(Inputs{}).Field(i).Name)
	}
	if want := []string{"Triggers", "Probe", "Gates", "Drain", "Report"}; !slices.Equal(names, want) {
		t.Errorf("Inputs has the fields %v, T3 knows %v: hold a new one fixed if it is a trigger (a design round), vary it if not", names, want)
	}
	covered := map[string]bool{}
	for _, g := range autoGateChoices {
		autoMarkSet(reflect.ValueOf(g), "Gates", covered)
	}
	for _, r := range autoReportChoices {
		autoMarkSet(reflect.ValueOf(r), "Report", covered)
	}
	for _, d := range autoDrainChoices {
		autoMarkSet(reflect.ValueOf(d), "Drain", covered)
	}
	var missing []string
	for _, root := range []any{Gates{}, Report{}, Drain{}} {
		for _, leaf := range autoLeaves(reflect.TypeOf(root), reflect.TypeOf(root).Name()) {
			if !covered[leaf] {
				missing = append(missing, leaf)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("T3 never varies %v: add a choice that sets each", missing)
	}
}

// autoMarkSet records which leaf fields of v hold a non-zero value.
func autoMarkSet(v reflect.Value, path string, set map[string]bool) {
	if v.Kind() == reflect.Struct && v.Type() != reflect.TypeOf(time.Time{}) {
		for i := range v.NumField() {
			autoMarkSet(v.Field(i), path+"."+v.Type().Field(i).Name, set)
		}
		return
	}
	if !v.IsZero() {
		set[path] = true
	}
}

// autoLeaves lists the leaf fields of a struct type, as autoMarkSet names them.
func autoLeaves(typ reflect.Type, path string) []string {
	if typ.Kind() != reflect.Struct || typ == reflect.TypeOf(time.Time{}) {
		return []string{path}
	}
	var out []string
	for i := range typ.NumField() {
		out = append(out, autoLeaves(typ.Field(i).Type, path+"."+typ.Field(i).Name)...)
	}
	return out
}

// TestObservationTriggersIsTheRefusalRule is the trigger rules as one table
// over Observation.Triggers: a refusal is Refused only beside a listener table
// that shows nothing covering the address — a listener behind it (a
// firewall's REJECT) or a table that could not be read holds; Unbound needs
// the kernel's no, not its silence; and no other class triggers anything.
func TestObservationTriggersIsTheRefusalRule(t *testing.T) {
	tests := []struct {
		name    string
		o       Observation
		drained bool
		want    Triggers
	}{
		{"refused, no listener", Observation{Local: TriYes, Probe: ClassRefused, Listening: TriNo}, false, Triggers{Refused: true}},
		{"refused, a listener behind it", Observation{Local: TriYes, Probe: ClassRefused, Listening: TriYes}, false, Triggers{}},
		{"refused, the table unread", Observation{Local: TriYes, Probe: ClassRefused, Listening: TriUnknown}, false, Triggers{}},
		{"not TLS", Observation{Local: TriYes, Probe: ClassNotTLS}, false, Triggers{NotTLS: true}},
		{"not held", Observation{Local: TriNo}, false, Triggers{Unbound: true}},
		{"not known to be held", Observation{Local: TriUnknown}, false, Triggers{}},
		{"ok", Observation{Local: TriYes, Probe: ClassOK}, false, Triggers{}},
		{"soft, beside an empty table", Observation{Local: TriYes, Probe: ClassSoft, Listening: TriNo}, false, Triggers{}},
		{"blind, beside an empty table", Observation{Local: TriYes, Probe: ClassBlind, Listening: TriNo}, false, Triggers{}},
		{"none", Observation{Local: TriYes, Probe: ClassNone, Listening: TriNo}, false, Triggers{}},
		{"drained and ok", Observation{Local: TriYes, Probe: ClassOK}, true, Triggers{Drained: true}},
		{"drained and not held", Observation{Local: TriNo}, true, Triggers{Unbound: true, Drained: true}},
	}
	for _, tc := range tests {
		if got := tc.o.Triggers(tc.drained); got != tc.want {
			t.Errorf("%s: %+v.Triggers(%v) = %+v, want %+v", tc.name, tc.o, tc.drained, got, tc.want)
		}
	}
}

// TestEnumNamesRoundTrip: every enum travels by name (E7.2's /steer body, the
// metric labels), and a name nobody knows reads as the zero value — unknown,
// which holds — beside an error.
func TestEnumNamesRoundTrip(t *testing.T) {
	type enum interface {
		String() string
		MarshalText() ([]byte, error)
	}
	check := func(kind string, names []string, value func(i int) enum, parse func(b []byte) (int, error)) {
		t.Helper()
		for i, name := range names {
			v := value(i)
			b, err := v.MarshalText()
			if err != nil || string(b) != name || v.String() != name {
				t.Errorf("%s %d: MarshalText = (%q, %v), String = %q, want %q", kind, i, b, err, v.String(), name)
			}
			if back, err := parse([]byte(name)); err != nil || back != i {
				t.Errorf("%s %q: UnmarshalText = (%d, %v), want %d", kind, name, back, err, i)
			}
		}
		beyond := value(len(names))
		if _, err := beyond.MarshalText(); err == nil || !strings.Contains(beyond.String(), "(") {
			t.Errorf("%s %d: MarshalText error %v, String %q; want an error and a numbered name", kind, len(names), err, beyond.String())
		}
		if back, err := parse([]byte("withdrawn-ish")); err == nil || back != 0 {
			t.Errorf("%s: an unknown name reads as (%d, %v), want the zero value and an error", kind, back, err)
		}
	}
	check("Class", classNames, func(i int) enum { return Class(i) }, func(b []byte) (int, error) {
		c := ClassOK // a stale value must not survive a failed read
		err := c.UnmarshalText(b)
		return int(c), err
	})
	check("Tri", triNames, func(i int) enum { return Tri(i) }, func(b []byte) (int, error) {
		v := TriYes
		err := v.UnmarshalText(b)
		return int(v), err
	})
	check("PIDState", pidNames, func(i int) enum { return PIDState(i) }, func(b []byte) (int, error) {
		v := PIDAlive
		err := v.UnmarshalText(b)
		return int(v), err
	})
	check("State", stateNames, func(i int) enum { return State(i) }, func(b []byte) (int, error) {
		v := StateWithdraw
		err := v.UnmarshalText(b)
		return int(v), err
	})
}

// TestAutomatonSurvivesAnyClass: a class nobody named, or drain content
// without the drain, neither panics nor takes an announced target out (I3).
func TestAutomatonSurvivesAnyClass(t *testing.T) {
	a, at := autoAnnounced(t, DefaultConfig())
	for c := range 256 {
		v := a.Step(Inputs{Probe: Class(c), Drain: Drain{Reason: strings.Repeat("x", 1<<12)}}, at)
		if v.State != StateAnnounce {
			t.Fatalf("class %d: %+v", c, v)
		}
		at = at.Add(time.Second)
	}
}

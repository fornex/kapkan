package steer

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/apply"
)

// Triggers is the closed set of inputs that may take an address out of
// service (package doc, THE CLOSED TRIGGER SET). It has exactly these four
// fields, and a reflection test fails — quoting the review rule — the day a
// fifth appears: a new way out is a design round, not a field.
type Triggers struct {
	// Refused: the probe's connect returned ECONNREFUSED and the kernel lists
	// no LISTEN socket on :443 covering the probed address.
	Refused bool
	// NotTLS: the first byte of the answer was neither 0x15 nor 0x16.
	NotTLS bool
	// Unbound: the kernel does not hold the address.
	Unbound bool
	// Drained: a drain file is known to apply — the operator's, or the
	// new-node drain (Store.DrainFor's TriYes). A drain that cannot be read is
	// not one: it closes Gates.DrainKnown, which holds a join and takes
	// nothing out.
	Drained bool
}

// Hard reports a sample that counts against the address in the withdraw
// window. Drained is not one: it drains at once, unwindowed.
func (t Triggers) Hard() bool { return t.Refused || t.NotTLS || t.Unbound }

// Class is what one probe attempt saw (probe.go). Its ok feeds the join
// streak and the window's good samples; it never takes an address out by
// itself — a refusal counts only through Triggers.Refused, which asks the
// kernel for a listener first. That is why Class has no Hard method.
type Class uint8

const (
	// ClassNone: no probe ran this tick — the kernel does not hold the
	// address (Unbound decides) or could not say (unknown holds).
	ClassNone Class = iota
	// ClassOK: the first byte of the answer was 0x15 or 0x16.
	ClassOK
	// ClassRefused: connect returned ECONNREFUSED, that errno and no other.
	ClassRefused
	// ClassNotTLS: a first byte arrived, and it was neither 0x15 nor 0x16.
	ClassNotTLS
	// ClassSoft: the attempt reached the stack and got no TLS answer — a
	// connect or first-byte timeout, EOF or a reset before any byte, an
	// unreachable, any error not named elsewhere. Load looks like this.
	ClassSoft
	// ClassBlind: the attempt could not be made — EMFILE, ENFILE, ENOBUFS,
	// EADDRINUSE, EADDRNOTAVAIL, a failed socket or bind: this process or the
	// local stack, not the listener.
	ClassBlind
)

var classNames = []string{
	ClassNone: "none", ClassOK: "ok", ClassRefused: "refused",
	ClassNotTLS: "not_tls", ClassSoft: "soft", ClassBlind: "blind",
}

// String is the class's name, as metrics label it (E7.2's
// kapkan_edge_steer_probe_total{result}).
func (c Class) String() string { return enumString(classNames, c, "Class") }

// MarshalText makes a Class travel by name.
func (c Class) MarshalText() ([]byte, error) { return enumText(classNames, c, "class") }

// UnmarshalText reads a Class by name.
func (c *Class) UnmarshalText(b []byte) (err error) {
	*c, err = enumParse[Class](classNames, b, "class")
	return err
}

// Tri is a fact the kernel may fail to tell. The zero value is TriUnknown, so
// a fact nobody read holds, like every unknown in this package.
type Tri uint8

const (
	TriUnknown Tri = iota
	TriYes
	TriNo
)

var triNames = []string{TriUnknown: "unknown", TriYes: "yes", TriNo: "no"}

func (t Tri) String() string               { return enumString(triNames, t, "Tri") }
func (t Tri) MarshalText() ([]byte, error) { return enumText(triNames, t, "tri") }
func (t *Tri) UnmarshalText(b []byte) (err error) {
	*t, err = enumParse[Tri](triNames, b, "tri")
	return err
}

// PIDState is the terminator master's liveness as /proc/<pid>/stat tells it
// (Proc.Process). Report-only: a pid is not a listener.
type PIDState uint8

const (
	// PIDUnknown: no pid to look at, or its stat file could not be read.
	PIDUnknown PIDState = iota
	// PIDAlive: /proc/<pid> exists (Process.Frozen says whether it runs).
	PIDAlive
	// PIDGone: /proc/<pid> does not exist, or shows the dead state X.
	PIDGone
)

var pidNames = []string{PIDUnknown: "unknown", PIDAlive: "alive", PIDGone: "gone"}

func (s PIDState) String() string               { return enumString(pidNames, s, "PIDState") }
func (s PIDState) MarshalText() ([]byte, error) { return enumText(pidNames, s, "pid state") }
func (s *PIDState) UnmarshalText(b []byte) (err error) {
	*s, err = enumParse[PIDState](pidNames, b, "pid state")
	return err
}

// NodeKey names the node's implicit verdict — the one target when
// steering.vips is empty (D6) — in state.json, in E7.2's /steer and, for its
// drain, the node-wide drain file. A VIP's key is VIPTarget's: its canonical
// text, unmapped and without a zone.
const NodeKey = "node"

// Target is what one verdict is about: a VIP, or the node itself.
type Target struct {
	// Key names the verdict (NodeKey, or VIPTarget's key for the VIP).
	Key string
	// Addrs are what the probe tries: the VIP alone, or the loopback pair.
	Addrs []netip.Addr
}

// VIPTarget is the target for one steering.vips entry. An IPv4-mapped IPv6
// address is the IPv4 address it maps, and a zone is dropped, as Locals.Has
// and Listeners.Covers drop it: the kernel holds a global address whatever
// zone the text names. So every spelling of one address is one target with
// one key — the name of its drain file — and no key carries a zone's free
// text, a "/" or a "..", into a path.
func VIPTarget(vip netip.Addr) Target {
	vip = vip.Unmap().WithZone("")
	return Target{Key: vip.String(), Addrs: []netip.Addr{vip}}
}

// NodeTarget is the node's implicit target: 127.0.0.1 and, unless the node
// renders no IPv6 (disable_ipv6), ::1. Its addresses are not the operator's to
// lose, so it is never Unbound (Prober.Observe).
func NodeTarget(ipv6 bool) Target {
	t := Target{Key: NodeKey, Addrs: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}}
	if ipv6 {
		t.Addrs = append(t.Addrs, netip.IPv6Loopback())
	}
	return t
}

// Observation is one tick's evidence about one target before the trigger
// rules: what the kernel and the probe said. Prober.Observe makes it.
type Observation struct {
	// Local: the kernel holds the address. Only TriYes is probed.
	Local Tri
	// Probe is the attempt's class; ClassNone when none ran.
	Probe Class
	// Listening: a LISTEN socket on the probed port covers the address. It is
	// asked only after a refusal, and is TriUnknown otherwise or when the
	// table could not be read.
	Listening Tri
	// ProbeErr is the error behind a refused, soft or blind class, for the
	// report.
	ProbeErr string
}

// Triggers applies the trigger rules to the observation; drained is whether
// the drain files show a drain (Store.DrainFor's TriYes), the one trigger the
// kernel does not give — an unknown drain is not one, and closes
// Gates.DrainKnown instead. The refusal rule lives here: a refused probe
// counts only when the kernel lists no listener covering the address — a
// listener behind the refusal (a firewall's REJECT) or a table that could not
// be read (TriUnknown) is not Refused.
func (o Observation) Triggers(drained bool) Triggers {
	return Triggers{
		Refused: o.Probe == ClassRefused && o.Listening == TriNo,
		NotTLS:  o.Probe == ClassNotTLS,
		Unbound: o.Local == TriNo,
		Drained: drained,
	}
}

// Gates may hold an address out — delay its join — and never take one out
// (I2). Each is closed at its zero value, as every unknown here holds. The
// other two join gates live elsewhere: the first entry is a drain
// (Triggers.Drained, reason new_node), and the hold-down is the automaton's
// own.
type Gates struct {
	// GenerationLive: `live` names a generation of ours that passed `nginx -t`
	// (ReadGenerationLive). False through every apply's test window.
	GenerationLive bool
	// Zones is the number of zones in the node's live document; none holds a
	// join.
	Zones int
	// DrainKnown: the drain files' existence was established this tick —
	// Store.DrainFor answered TriYes or TriNo, not TriUnknown. A drain that
	// cannot be read is no drain, so it takes nothing out; nor is it a lift,
	// so it holds a join: a standing drain the disk stopped showing does not
	// let the address back in.
	DrainKnown bool
}

// Holding names the first gate that holds a join, "" when every gate is open.
func (g Gates) Holding() Reason {
	switch {
	case !g.GenerationLive:
		return ReasonGenerationNotLive
	case g.Zones <= 0:
		return ReasonNoZones
	case !g.DrainKnown:
		return ReasonDrainUnknown
	}
	return ""
}

// ReadGenerationLive is the generation gate, read from disk without the
// Applier's lock (apply.ReadLive): the generation `live` under confRoot names
// is one of ours and passed its test. Any failure to read reads closed — a
// gate that only delays a join may fail closed.
func ReadGenerationLive(confRoot string) bool {
	gen, tested, err := apply.ReadLive(confRoot)
	return err == nil && gen != 0 && tested
}

// Report holds one tick's report-only facts. They go to E7.2's /steer body,
// the metrics and the brain's inventory (E7.4); nothing in this package reads
// them to decide. They are what an operator needs to tell a wedged nginx from
// a loaded one — alike from the box, which is why neither withdraws (D3).
type Report struct {
	// Terminator is the master's /proc state (Proc.Process).
	Terminator Process
	// Listening is the observation's listener answer: TriYes beside a refused
	// probe is a firewall rule, held.
	Listening Tri
	// ProbeErr is why the probe classed refused, soft or blind.
	ProbeErr string
	// ProcErr is why a /proc read failed (Tick.Err); DrainErr why a drain file
	// could not be read (Store.DrainFor).
	ProcErr, DrainErr string
	// LogProgress: the access log moved since the previous tick. A soft probe
	// with progress is load; without it, silence.
	LogProgress Tri
}

// Inputs is everything Step and Evaluate read for one target at one tick.
type Inputs struct {
	// Triggers are the only input that takes an address out.
	Triggers Triggers
	// Probe is this tick's class: ClassOK (with no hard trigger) extends the
	// join streak, is the window's good sample, and is the only class a join
	// is made on; ClassBlind and ClassNone are skipped — they neither extend
	// nor break the run, and complete no join; any other class breaks the
	// streak — and a hard trigger breaks it whatever the class (an Unbound
	// tick has ClassNone). Nothing else of it is read.
	Probe Class
	// Gates may hold a join.
	Gates Gates
	// Drain is the drain behind Triggers.Drained, read only for its reason
	// (ReasonNewNode or ReasonDrained) and only while Triggers.Drained is set.
	Drain Drain
	// Report is never read by Step or Evaluate.
	Report Report
}

// State is a verdict: what the operator's speaker should do with the address.
// The zero value is StateUnknown, which holds.
type State uint8

const (
	// StateUnknown: no verdict — at start, after a drain lifts, or when the
	// last one is stale. The consumer holds whatever it last applied.
	StateUnknown State = iota
	// StateAnnounce: carry the address.
	StateAnnounce
	// StateWithdraw: do not carry it — reached from Triggers alone (I2).
	StateWithdraw
	// StateDrain: do not carry it — the operator's drain, or the new-node one.
	StateDrain
)

var stateNames = []string{
	StateUnknown: "unknown", StateAnnounce: "announce",
	StateWithdraw: "withdraw", StateDrain: "drain",
}

func (s State) String() string               { return enumString(stateNames, s, "State") }
func (s State) MarshalText() ([]byte, error) { return enumText(stateNames, s, "state") }
func (s *State) UnmarshalText(b []byte) (err error) {
	*s, err = enumParse[State](stateNames, b, "state")
	return err
}

// Reason says why a verdict is what it is, or — as Verdict.Warning — which
// join gate is closed. A short, stable token: it labels metrics (E7.2) and
// events (E7.4).
type Reason string

const (
	// StateWithdraw: the trigger of the hard sample that tipped the window.
	ReasonRefused Reason = "refused"
	ReasonNotTLS  Reason = "not_tls"
	ReasonUnbound Reason = "unbound"
	// StateDrain: an operator's drain file, or the new-node drain.
	ReasonDrained Reason = "drained"
	ReasonNewNode Reason = "new_node"
	// StateAnnounce, from Step.
	ReasonOK Reason = "ok"
	// StateUnknown: not decided since the start or since a drain lifted
	// (starting); the last verdict is older than StaleAfter (stale, from
	// Verdict.AsOf only).
	ReasonStarting Reason = "starting"
	ReasonStale    Reason = "stale"
	// Evaluate only: a withdraw held by a hold-down still running, and an
	// announce made without the daemon's damping.
	ReasonHoldDown  Reason = "hold_down"
	ReasonUnmanaged Reason = "unmanaged"
	// Gates (Gates.Holding, Verdict.Warning).
	ReasonGenerationNotLive Reason = "generation_not_live"
	ReasonNoZones           Reason = "no_zones"
	ReasonDrainUnknown      Reason = "drain_unknown"
)

// Verdict is one target's answer at one tick.
type Verdict struct {
	State  State
	Reason Reason
	// Since is when the target entered State.
	Since time.Time
	// RejoinAt is when the hold-down lets an unknown or withdrawn target join;
	// zero when no hold-down is running (and always in StateAnnounce and
	// StateDrain).
	RejoinAt time.Time
	// At is when the verdict was evaluated: what AsOf ages.
	At time.Time
	// Warning names a closed join gate (Gates.Holding), "" when all are open
	// and always in StateDrain. On an announced target it is the design's
	// warning — the target stays in; on an unknown or withdrawn one it is what
	// holds the join once the streak and the hold-down allow it.
	Warning Reason
}

// The damping defaults (D8) and their bounds. E7.2's edge.yaml keys
// (steering.interval_seconds, fail_after, fail_window, recover_after,
// hold_down.{min,max}_seconds) map onto Config one to one.
const (
	DefaultInterval     = time.Second
	DefaultFailAfter    = 3
	DefaultFailWindow   = 5
	DefaultRecoverAfter = 10
	DefaultHoldDownMin  = 10 * time.Second
	DefaultHoldDownMax  = 60 * time.Second
	// HoldDownCeiling is as far as hold_down.max may be raised. The cap only
	// delays a return — real trouble withdraws at once — and at 600 s a
	// fleet-wide query-of-death already costs ten more minutes of outage
	// after the fix.
	HoldDownCeiling = 600 * time.Second
	// DefaultLevelReset is how long a target stays announced before its
	// hold-down level drops back to zero.
	DefaultLevelReset = 600 * time.Second
	// StaleIntervals is how many intervals old a verdict may be before a
	// reader takes it as unknown.
	StaleIntervals = 3
)

// Config is the automaton's damping. A zero or negative field means its
// default; each comment gives the default, then the bounds Validate enforces
// and normalized clamps into.
type Config struct {
	// Interval is the sampling tick: 1 s, within 1..10 s.
	Interval time.Duration
	// FailAfter hard samples among the last FailWindow decisive ones, taken
	// within the last 2×FailWindow ticks, withdraw: 3 of 5 within 10, with
	// FailWindow within 1..60 and FailAfter within 1..FailWindow.
	FailAfter, FailWindow int
	// RecoverAfter ok samples in a row (with the gates open and the hold-down
	// over) announce: 10, within 3..120.
	RecoverAfter int
	// HoldDownMin is the first flap's hold-down (10 s, within 1 s..HoldDownMax),
	// doubling per flap up to HoldDownMax (60 s, within
	// HoldDownMin..HoldDownCeiling).
	HoldDownMin, HoldDownMax time.Duration
	// LevelReset is how long a target stays announced before its hold-down
	// level resets: 600 s, within 1 s..24 h.
	LevelReset time.Duration
}

// DefaultConfig is the damping with every default spelled out.
func DefaultConfig() Config {
	return Config{
		Interval:     DefaultInterval,
		FailAfter:    DefaultFailAfter,
		FailWindow:   DefaultFailWindow,
		RecoverAfter: DefaultRecoverAfter,
		HoldDownMin:  DefaultHoldDownMin,
		HoldDownMax:  DefaultHoldDownMax,
		LevelReset:   DefaultLevelReset,
	}
}

// Saved is what one target's automaton keeps across a restart: the hold-down
// ladder. Its state is not kept — a restart starts unknown, which holds — and
// neither is the level-reset clock: a restart restarts it, which can only
// delay.
type Saved struct {
	// Level is the number of flaps not yet forgiven by LevelReset.
	Level int `json:"level,omitempty"`
	// Until is when the running hold-down ends; zero when none runs.
	Until time.Time `json:"until,omitzero"`
}

// Equal reports whether two records say the same, so the caller writes
// state.json only when one changed.
func (s Saved) Equal(o Saved) bool { return s.Level == o.Level && s.Until.Equal(o.Until) }

// enumString, enumText and enumParse give the package's small enums their
// names: in JSON (E7.2's /steer body), and as metric labels.
func enumString[T ~uint8](names []string, v T, kind string) string {
	if int(v) < len(names) {
		return names[v]
	}
	return kind + "(" + strconv.Itoa(int(v)) + ")"
}

func enumText[T ~uint8](names []string, v T, kind string) ([]byte, error) {
	if int(v) >= len(names) {
		return nil, fmt.Errorf("steer: %s %d has no name", kind, v)
	}
	return []byte(names[v]), nil
}

// enumParse returns the zero value — unknown, for every enum here — beside
// its error, so a name it does not know reads as one that holds.
func enumParse[T ~uint8](names []string, b []byte, kind string) (T, error) {
	for i, n := range names {
		if n == string(b) {
			return T(i), nil
		}
	}
	return 0, fmt.Errorf("steer: unknown %s %q", kind, b)
}

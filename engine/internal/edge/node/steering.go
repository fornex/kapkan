package node

// STEERING (E7.2) is the node's testimony about itself: for each address in
// edge.yaml's steering.vips — or for the node itself when it names none — a
// damped verdict on whether this box should carry it now, computed by
// internal/edge/steer and served on status_listen as GET /steer. Kapkan never
// speaks BGP here and never names a prefix: the operator's speaker, on this
// box, reads the verdict and announces or withdraws.
//
// The sampler is one goroutine of Run that never ends it: every failure is a
// value that holds (unknown, 425), and a panic — at its start, in a tick, or
// in the kernel readings steer runs in goroutines of its own — is recovered,
// logged, and publishes nothing, so the last verdict ages to unknown. The
// brain's document reaches the verdict only as data (the zones' names and
// the render's :443 zones), and no route writes: the CLI drains through
// steer's files and asks for a hold-down reset through a request file the
// sampler takes by renaming it.
//
// LOCKS. Every section under n.mu or readsMu is a small method that unlocks
// with defer: a panic that net/http or a tick recovers with a lock held would
// wedge a live node, and systemd never restarts a live process. Nothing is
// encoded under readsMu. The order is n.mu before readsMu, never the other
// way (E7.4's report holds n.mu and reads SteeringStatus), and the sampler
// never takes renderMu, which is held through `nginx -t`.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/kapkan-io/kapkan/internal/edge/steer"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

const (
	// steerMaxTargets bounds the targets, as edge.yaml bounds steering.vips:
	// each is a probe per tick and a metric series, and the status object
	// promises its lists are bounded.
	steerMaxTargets = 64
	// steerMaxReaders is how many consumer names one target remembers.
	steerMaxReaders = 8
	// steerMaxMissing is how many zone names first_entry.missing carries.
	steerMaxMissing = 10
	// steerReasonMax and steerErrMax bound the free text on the wire (a drain's
	// reason, the report's errors): /steer must fit the CLI's 64 KiB read, and
	// E7.4 copies the status into a report the brain caps at 64 KiB.
	steerReasonMax = 256
	steerErrMax    = 512
	// steerVIPEchoMax bounds the vip a 400 echoes back.
	steerVIPEchoMax = 64
	// steerResetMax bounds what is read of a hold-down reset request.
	steerResetMax = 64 << 10
	// steerPIDMax bounds what is read of the terminator's pid file.
	steerPIDMax = 64
	// steerShutdownWait is how long shutdown waits for a tick still running: a
	// syscall stuck under RTNL must not hold Run's exit.
	steerShutdownWait = 2 * time.Second
	// steerSkipWarnEvery spaces the "tick skipped" warnings.
	steerSkipWarnEvery = time.Minute
	// steerTaken is the suffix a taken reset request carries until the tick
	// that took it has saved state.json.
	steerTaken = ".taken"
)

// steerConsumerRe is what a reader may call itself (?consumer=); any other
// name is stored as "invalid", and an absent one as "anonymous".
var steerConsumerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// steerStates are the four verdicts, as kapkan_edge_steer_verdict labels them.
var steerStates = [...]steer.State{steer.StateAnnounce, steer.StateWithdraw, steer.StateDrain, steer.StateUnknown}

// sampler is the node's steering: the targets, one automaton each, and what
// the last tick published. It exists only when edge.yaml turns steering on
// (n.steer is nil otherwise, and nothing of steering runs).
type sampler struct {
	n *Node

	// Fixed by New.
	cfg steer.Config
	// interval is cfg's normalized interval: the ticker's, and the one the
	// staleness counts in (staleAfter = StaleIntervals of it).
	interval, staleAfter time.Duration
	targets              []steer.Target // edge.yaml's order
	keys                 map[string]bool
	vips                 bool // VIPs are configured (else the node target)
	proc                 steer.Proc
	prober               steer.Prober
	joinRetry            time.Duration
	store                steer.Store

	// snap is the last tick's verdicts; immutable once stored.
	snap atomic.Pointer[steerSnapshot]

	// readsMu guards readers — each target's readers, newest first — and
	// latest, the newest stamp of any target.
	readsMu sync.Mutex
	readers map[string][]SteerReader
	latest  *SteerReader

	// The rest belongs to the start and then to one tick at a time: the
	// loop's busy flag orders them (an atomic, so a tick's writes happen
	// before the next tick's reads).
	file    steer.StateFile
	autos   map[string]*steer.Automaton
	saved   map[string]steer.Saved // what state.json holds, as loaded or last saved
	stepped map[string]steer.State // each target's last stepped state
	// drained and drains are the previous tick's drain, kept through a tick
	// whose drain files cannot be read.
	drained map[string]bool
	drains  map[string]steer.Drain
	// birthPending: state.json was missing and Birth has not succeeded yet;
	// every target is drained in memory (new_node) since bornAt, and nothing
	// is saved, so the next start is born again and keeps the first entry.
	birthPending bool
	bornAt       time.Time
	birthErr     string
	// joiner runs the first entry's handshakes while it is pending; fe is
	// what it last reported, kept for the status while the answer is unknown.
	joiner *steer.Joiner
	fe     *steer.FirstEntry
	// logSeen and logLast are the access-log count at the previous tick.
	logSeen bool
	logLast uint64
	// taken: a reset request was taken and its file still awaits removal.
	taken bool
	// saveErr, takeErr, removeErr and liftErr are the last errors logged, so
	// a failure that repeats every tick is logged once.
	saveErr, takeErr, removeErr, liftErr string
}

// steerSnapshot is what one tick published. Nothing in it changes once it is
// stored; readers copy what they hand out.
type steerSnapshot struct {
	// at is the tick's time.Now(), monotonic reading included.
	at      time.Time
	targets map[string]steerTargetSnap
	// nodeDrain is the node-wide drain (the operator's, or new_node); nil when
	// there is none.
	nodeDrain *SteerDrain
	// firstEntry is nil once the first entry is known done.
	firstEntry *SteerFirstEntry
}

// steerTargetSnap is one target at the tick: its verdict as Step gave it
// (AsOf ages it at each read), and the wire forms of its inputs and ladder,
// bounded.
type steerTargetSnap struct {
	verdict steer.Verdict
	inputs  SteerInputs
	hold    SteerHoldDown
}

// newSampler checks the steering options and builds the sampler, nothing on
// disk yet. It mirrors edge.yaml's rules (status_listen, omit_catch_all, the
// damping's bounds, the VIPs), so a caller that builds Options directly gets
// the guards the file gets; loopback is not refused here, as it is there.
func newSampler(n *Node, opt Options) (*sampler, error) {
	st := opt.Steering
	switch {
	case opt.StatusListen == "":
		return nil, errors.New("edge: steering needs status_listen")
	case opt.OmitCatchAll:
		// Without the catch-all, a document that leaves the node no zone with
		// a certificate leaves :443 refusing on every node at once.
		return nil, errors.New("edge: steering refuses omit_catch_all")
	}
	if err := st.Config.Validate(); err != nil {
		return nil, fmt.Errorf("edge: steering: %w", err)
	}
	if len(st.VIPs) > steerMaxTargets {
		return nil, fmt.Errorf("edge: steering lists %d VIPs; at most %d", len(st.VIPs), steerMaxTargets)
	}
	keys := make(map[string]bool, max(len(st.VIPs), 1))
	var targets []steer.Target
	for i, v := range st.VIPs {
		if !v.IsValid() {
			return nil, fmt.Errorf("edge: steering VIP #%d is not an address", i+1)
		}
		t := steer.VIPTarget(v)
		if a := t.Addrs[0]; a.Is6() && opt.DisableIPv6 {
			return nil, fmt.Errorf("edge: steering VIP %s is IPv6 and disable_ipv6 is set", a)
		}
		if keys[t.Key] {
			return nil, fmt.Errorf("edge: steering VIP %s listed twice", t.Key)
		}
		keys[t.Key] = true
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		t := steer.NodeTarget(!opt.DisableIPv6)
		keys[t.Key] = true
		targets = []steer.Target{t}
	}
	interval := st.Config.StaleAfter() / steer.StaleIntervals
	return &sampler{
		n:          n,
		cfg:        st.Config,
		interval:   interval,
		staleAfter: st.Config.StaleAfter(),
		targets:    targets,
		keys:       keys,
		vips:       len(st.VIPs) > 0,
		proc:       st.Proc,
		prober:     st.Prober,
		joinRetry:  st.JoinRetry,
		store:      steer.NewStore(opt.StateDir),
		readers:    make(map[string][]SteerReader),
		autos:      make(map[string]*steer.Automaton, len(targets)),
		saved:      make(map[string]steer.Saved),
		stepped:    make(map[string]steer.State, len(targets)),
		drained:    make(map[string]bool, len(targets)),
		drains:     make(map[string]steer.Drain, len(targets)),
	}, nil
}

// runSteering is Run's "steering" component. It returns nil on every path, a
// panic's included: steering never ends Run (I3). A start that panics has
// published nothing, so /steer answers 425 starting and every consumer holds.
func (n *Node) runSteering(ctx context.Context) (err error) {
	defer func() {
		if p := recover(); p != nil {
			n.log.Error("steering stopped: it panicked; every verdict holds (425) until kapkan edge restarts",
				"panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			err = nil
		}
	}()
	n.steer.start()
	n.steer.loop(ctx)
	return nil
}

// start loads state.json (or arms the first entry), builds the automata and
// applies a reset request a crash left half taken. It never fails: what it
// cannot read holds.
func (s *sampler) start() {
	log := s.n.log
	now := time.Now()
	f, born, err := s.store.Load(now, s.cfg.HoldDownMax)
	switch {
	case err != nil:
		// Not a birth: a corrupt file must not drain a node, let alone a fleet.
		log.Error("steering: state.json is unreadable; hold-downs start empty, and this is not a new node", "err", err)
		f = steer.StateFile{}
	case born:
		s.bornAt = now
		s.birth(now)
		f = s.file
	}
	s.file = f
	for _, t := range s.targets {
		s.autos[t.Key] = steer.NewAutomaton(s.cfg, f.Targets[t.Key])
	}
	for k, v := range f.Targets {
		s.saved[k] = v
	}
	// A request renamed .taken but never removed: a crash cut the take short
	// after the CLI had reported it taken. Apply it now; the first tick saves
	// the reset and removes the file.
	if taken := filepath.Join(s.store.Dir, ResetRequestFile+steerTaken); fileExists(taken) {
		log.Warn("steering: a hold-down reset was taken before the last stop and not finished; applying it now")
		s.applyReset(taken)
		s.taken = true
	}
	keys := make([]string, len(s.targets))
	for i, t := range s.targets {
		keys[i] = t.Key
		steerSetVerdict(t.Key, steer.StateUnknown)
	}
	log.Info("steering on", "targets", keys, "interval", s.interval)
}

// birth arms the first entry: state.json was missing. Until Birth succeeds
// (each tick retries it) every target is drained in memory and nothing is
// saved: a saved state.json would make the next start not born, and lose the
// first entry.
func (s *sampler) birth(now time.Time) {
	f, err := s.store.Birth(now)
	if err != nil {
		s.birthPending = true
		if msg := err.Error(); msg != s.birthErr {
			s.birthErr = msg
			s.n.log.Error("steering: this node is new, and its first entry could not be written; every target stays drained (new_node), and nothing is saved until it can", "err", err)
		}
		return
	}
	s.file, s.birthPending, s.birthErr = f, false, ""
	s.n.log.Info("steering: this node is new: it stays drained (new_node) until every zone answers TLS with its certificate")
}

// bornDrain is the in-memory new-node drain while Birth has not succeeded.
func (s *sampler) bornDrain() steer.Drain {
	return steer.Drain{Reason: steer.NewNodeReason, Since: s.bornAt}
}

// loop ticks until ctx ends. Each tick runs off the loop's goroutine, and at
// most one at a time: a tick still running when the next is due — a syscall
// stuck under RTNL contention — makes the next one skip, so goroutines never
// pile up, the published verdict ages to unknown (which holds), and shutdown
// waits for it at most steerShutdownWait.
func (s *sampler) loop(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	var wg sync.WaitGroup
	var busy atomic.Bool
	var warned time.Time
	for {
		select {
		case <-ctx.Done():
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(steerShutdownWait):
			}
			return
		case <-t.C:
			if !busy.CompareAndSwap(false, true) {
				if now := time.Now(); warned.IsZero() || now.Sub(warned) >= steerSkipWarnEvery {
					warned = now
					s.n.log.Warn("steering tick skipped: the previous one is still running; verdicts go stale and hold")
				}
				continue
			}
			wg.Go(func() {
				defer busy.Store(false)
				s.tick(ctx)
			})
		}
	}
}

// tick is one sample of every target: observe, step, save, publish. A tick
// that panics publishes nothing; the next one runs normally.
func (s *sampler) tick(ctx context.Context) {
	defer func() {
		if p := recover(); p != nil {
			value, stack := p, debug.Stack()
			if sp, ok := p.(steerPanic); ok {
				value, stack = sp.value, sp.stack
			}
			s.n.log.Error("steering tick panicked; nothing was published this tick, and verdicts go stale and hold",
				"panic", fmt.Sprint(value), "stack", string(stack))
		}
	}()
	// The deadline leaves the rest of the interval for the step, the save and
	// the publish; it fits the 300 + 600 ms probe at 1 s.
	tctx, cancel := context.WithTimeout(ctx, s.interval*9/10)
	defer cancel()
	now := time.Now()

	if s.birthPending {
		s.birth(now)
	}
	s.takeReset()

	// What the node knows. The document reaches steering as these two lists
	// of names, data for the gates and the joiner, and nothing else.
	zones, tlsZones, pidFile := s.n.steerDocFacts()
	slices.Sort(zones)
	gen := steer.ReadGenerationLive(s.n.files.confRoot)
	term := s.terminator(pidFile)
	logProgress := s.logProgress(s.n.logRecords.Load())

	// Observe every target, with the first entry beside them: on a box with a
	// full table a target that needs a route table reads until tctx ends, and
	// a joiner run after it would get an expired ctx every tick.
	kt := s.proc.Tick(tctx, s.prober.Port)
	k := &steerKernel{k: kt}
	pending := steer.TriYes
	if !s.birthPending {
		var err error
		if pending, err = s.store.FirstEntryPending(); err != nil {
			s.n.log.Debug("steering: whether the first entry is pending could not be read", "err", err)
		}
	}
	obs := make([]steer.Observation, len(s.targets))
	var fe *steer.FirstEntry
	var g steerGroup
	for i, t := range s.targets {
		g.Go(func() { obs[i] = s.prober.Observe(tctx, k, t) })
	}
	if pending == steer.TriYes && !s.birthPending {
		j := s.joinerFor()
		g.Go(func() {
			f := j.Check(tctx, zones, tlsZones, now)
			fe = &f
		})
	}
	g.wg.Wait()
	// A goroutine's panic first, then the kernel's: the tick's recover logs
	// it, and nothing is stepped, saved or published.
	if p := g.panics.get(); p != nil {
		panic(*p)
	}
	if p := k.panics.get(); p != nil {
		panic(*p)
	}
	if ctx.Err() != nil {
		return // shutdown: what this tick saw is not stepped
	}
	procErr := kt.Err()

	snap := &steerSnapshot{at: now, targets: make(map[string]steerTargetSnap, len(s.targets))}
	var nodeDrain steer.Drain
	nodeTri, nodeRead := steer.TriUnknown, false
	for i, t := range s.targets {
		key := t.Key
		d, tri, derr := s.store.DrainFor(key)
		if key == steer.NodeKey {
			nodeDrain, nodeTri, nodeRead = d, tri, true
		}
		drained := tri == steer.TriYes
		if tri == steer.TriUnknown && s.drained[key] {
			// One tick that cannot read a drain file standing
			// the tick before must not lift it.
			drained, d = true, s.drains[key]
		}
		if s.birthPending && tri != steer.TriYes {
			drained, d = true, s.bornDrain()
		}
		s.drained[key], s.drains[key] = drained, d
		o := obs[i]
		in := steer.Inputs{
			Triggers: o.Triggers(drained),
			Probe:    o.Probe,
			Gates:    steer.Gates{GenerationLive: gen, Zones: len(zones), DrainKnown: tri != steer.TriUnknown},
			Drain:    d,
			Report: steer.Report{
				Terminator: term, Listening: o.Listening, ProbeErr: o.ProbeErr,
				ProcErr: steerErrText(procErr), DrainErr: steerErrText(derr), LogProgress: logProgress,
			},
		}
		a := s.autos[key]
		v := a.Step(in, now)
		metrics.EdgeSteerProbeTotal.WithLabelValues(key, o.Probe.String()).Inc()
		if from := s.stepped[key]; v.State != from {
			s.stepped[key] = v.State
			metrics.EdgeSteerTransitionsTotal.WithLabelValues(key, v.State.String(), string(v.Reason)).Inc()
			s.logChange(key, from, v)
		}
		steerSetVerdict(key, v.State)
		snap.targets[key] = steerTargetSnap{verdict: v, inputs: steerWireInputs(in), hold: steerWireHold(a.Saved())}
	}

	// The node-wide drain, for the status: E7.4's report has one, and the
	// per-target fold cannot tell it apart.
	if !nodeRead {
		nodeDrain, nodeTri, _ = s.store.DrainFor(steer.NodeKey)
	}
	switch {
	case nodeTri == steer.TriYes:
		snap.nodeDrain = steerWireDrain(nodeDrain)
	case s.birthPending:
		snap.nodeDrain = steerWireDrain(s.bornDrain())
	}

	// The first entry.
	if s.birthPending {
		snap.firstEntry = &SteerFirstEntry{Pending: steer.TriYes}
	} else {
		switch pending {
		case steer.TriYes:
			s.fe = fe
			if fe != nil && fe.Done() {
				s.lift()
			}
		case steer.TriNo:
			s.joiner, s.fe = nil, nil
		}
		if s.fe != nil || pending != steer.TriNo {
			snap.firstEntry = steerWireFirstEntry(pending, s.fe)
		}
	}

	s.save()
	if s.taken {
		// After the save, even a failed one: the request was taken.
		s.removeTaken()
	}
	s.snap.Store(snap)
}

// joinerFor is the first entry's joiner, made on first need. Its handshakes
// go to 127.0.0.1, from 127.0.0.1: every zone server listens on the IPv4
// wildcard, so the leaf is the one any local address gets; it needs no IPv6
// source (which a sandbox refusing IP_FREEBIND on AF_INET6 fails), and
// nothing from this tick's observation, so it runs beside it.
func (s *sampler) joinerFor() *steer.Joiner {
	if s.joiner == nil {
		prober := s.prober
		loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		s.joiner = &steer.Joiner{
			Retry: s.joinRetry,
			Handshake: func(ctx context.Context, sni string) error {
				return prober.Handshake(ctx, loopback, sni)
			},
		}
	}
	return s.joiner
}

// lift ends the first entry once it is done: it removes the new-node drain.
// This tick's verdicts still say new_node; the next tick reads the lift. A
// failure is retried at the next tick, which runs the exit test again.
func (s *sampler) lift() {
	lifted, err := s.store.LiftNewNode()
	if err != nil {
		if msg := err.Error(); msg != s.liftErr {
			s.liftErr = msg
			s.n.log.Warn("steering: the first entry is complete, and the new-node drain could not be lifted; it is retried next tick", "err", err)
		}
		return
	}
	s.liftErr = ""
	if lifted {
		s.n.log.Info("steering: first entry complete; the new-node drain is lifted")
	}
}

// save writes state.json when a target's ladder changed since it was last
// written, or the target set did — never while Birth is pending. A failure
// is retried at the next tick and logged once per distinct message.
func (s *sampler) save() {
	if s.birthPending {
		return
	}
	next := steer.StateFile{Born: s.file.Born, Targets: make(map[string]steer.Saved, len(s.targets))}
	changed := len(s.saved) != len(s.targets)
	for _, t := range s.targets {
		sv := s.autos[t.Key].Saved()
		next.Targets[t.Key] = sv
		if old, ok := s.saved[t.Key]; !ok || !old.Equal(sv) {
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := s.store.Save(next); err != nil {
		if msg := err.Error(); msg != s.saveErr {
			s.saveErr = msg
			s.n.log.Warn("steering: state.json could not be saved; it is retried next tick, and a restart meanwhile restores the hold-downs it last saved", "err", err)
		}
		return
	}
	s.saved, s.saveErr = next.Targets, ""
}

// takeReset takes the operator's hold-down reset request, if one is
// waiting, by renaming it: the CLI cancels by removing it, and exactly one of
// the two finds the file.
func (s *sampler) takeReset() {
	path := filepath.Join(s.store.Dir, ResetRequestFile)
	taken := path + steerTaken
	if err := os.Rename(path, taken); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			if msg := err.Error(); msg != s.takeErr {
				s.takeErr = msg
				s.n.log.Warn("steering: a hold-down reset request could not be taken", "err", err)
			}
		}
		return
	}
	s.takeErr = ""
	s.taken = true
	s.applyReset(taken)
}

// applyReset forgets the hold-downs a taken request names. A malformed one
// resets nothing; its file is removed all the same.
func (s *sampler) applyReset(path string) {
	log := s.n.log
	req, err := readResetRequest(path)
	if err != nil {
		log.Warn("steering: the hold-down reset request is malformed; nothing was reset", "err", err)
		return
	}
	var reset, unknown []string
	switch {
	case req.All:
		for _, t := range s.targets {
			s.autos[t.Key].ResetHoldDown()
			reset = append(reset, t.Key)
		}
	case len(req.Keys) == 0:
		log.Warn("steering: the hold-down reset request names no target; nothing was reset")
		return
	default:
		for _, k := range req.Keys {
			// Any spelling of a steered address names it, as for its drain file.
			if a, err := netip.ParseAddr(k); err == nil {
				k = steer.VIPTarget(a).Key
			}
			if auto, ok := s.autos[k]; ok {
				auto.ResetHoldDown()
				reset = append(reset, k)
			} else {
				unknown = append(unknown, k)
			}
		}
	}
	if len(unknown) > 0 {
		log.Warn("steering: the hold-down reset request names keys this node does not steer; they are ignored", "keys", unknown)
	}
	if len(reset) > 0 {
		log.Info("steering: hold-down reset by the operator", "keys", reset)
	}
}

// readResetRequest reads a taken request, at most steerResetMax bytes of it.
// Anything but a regular file is malformed: opening a FIFO for reading would
// block the tick until a writer came.
func readResetRequest(path string) (ResetRequest, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return ResetRequest{}, err
	}
	if !fi.Mode().IsRegular() {
		return ResetRequest{}, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return ResetRequest{}, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	raw, err := io.ReadAll(io.LimitReader(f, steerResetMax+1))
	if err != nil {
		return ResetRequest{}, err
	}
	if len(raw) > steerResetMax {
		return ResetRequest{}, fmt.Errorf("%s is larger than %d bytes", path, steerResetMax)
	}
	var req ResetRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return ResetRequest{}, fmt.Errorf("%s: %w", path, err)
	}
	return req, nil
}

// removeTaken removes the taken request once its tick has saved. A failure
// is retried next tick: a .taken file left behind is applied again at the
// next start.
func (s *sampler) removeTaken() {
	err := os.Remove(filepath.Join(s.store.Dir, ResetRequestFile+steerTaken))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		if msg := err.Error(); msg != s.removeErr {
			s.removeErr = msg
			s.n.log.Warn("steering: the taken hold-down reset request could not be removed; it is retried next tick", "err", err)
		}
		return
	}
	s.taken, s.removeErr = false, ""
}

// terminator is the terminator master's /proc state from its pid file, for
// the report only; unknown without one.
func (s *sampler) terminator(pidFile string) steer.Process {
	if pidFile == "" {
		return steer.Process{}
	}
	f, err := os.Open(pidFile)
	if err != nil {
		return steer.Process{}
	}
	defer func() { _ = f.Close() }() // read-only
	raw, err := io.ReadAll(io.LimitReader(f, steerPIDMax))
	if err != nil {
		return steer.Process{}
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return steer.Process{}
	}
	return s.proc.Process(pid)
}

// logProgress says whether the access log moved since the previous tick:
// unknown on the first, which has nothing to compare with.
func (s *sampler) logProgress(count uint64) steer.Tri {
	seen, last := s.logSeen, s.logLast
	s.logSeen, s.logLast = true, count
	switch {
	case !seen:
		return steer.TriUnknown
	case count != last:
		return steer.TriYes
	}
	return steer.TriNo
}

// logChange logs a verdict change: Warn for a withdrawal, Info otherwise.
func (s *sampler) logChange(key string, from steer.State, v steer.Verdict) {
	attrs := []any{"target", key, "from", from.String(), "to", v.State.String(), "reason", string(v.Reason)}
	if !v.RejoinAt.IsZero() {
		attrs = append(attrs, "rejoin_at", v.RejoinAt.UTC())
	}
	level := slog.LevelInfo
	if v.State == steer.StateWithdraw {
		level = slog.LevelWarn
	}
	s.n.log.Log(context.Background(), level, "steering verdict changed", attrs...)
}

// steerSetVerdict sets kapkan_edge_steer_verdict for a target: 1 for the
// verdict it holds, 0 for the other three.
func steerSetVerdict(key string, state steer.State) {
	for _, st := range steerStates {
		v := 0.0
		if st == state {
			v = 1
		}
		metrics.EdgeSteerVerdict.WithLabelValues(key, st.String()).Set(v)
	}
}

// steerDocFacts copies what steering reads of the node: the rendered
// document's zone names (nil before the first render), the render's :443
// zones and the terminator's pid file. n.mu only, never renderMu.
func (n *Node) steerDocFacts() (zones, tlsZones []string, pidFile string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.renderedDoc != nil {
		zones = make([]string, len(n.renderedDoc.Zones))
		for i, z := range n.renderedDoc.Zones {
			zones[i] = z.Name
		}
	}
	return zones, slices.Clone(n.renderedInfo.TLSZones), n.opt.Terminator.PIDFile
}

// steerPanic is a panic carried from where it was recovered — a goroutine of
// the tick, or the kernel wrapper — to the tick's own recover, with the stack
// it was raised on.
type steerPanic struct {
	value any
	stack []byte
}

// steerPanics keeps the first panic of several goroutines.
type steerPanics struct {
	mu    sync.Mutex
	first *steerPanic
}

// keep records p unless a panic is kept already. It is called from a deferred
// recover, so the stack still shows where p was raised.
func (ps *steerPanics) keep(p any) {
	stack := debug.Stack()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.first == nil {
		ps.first = &steerPanic{value: p, stack: stack}
	}
}

func (ps *steerPanics) get() *steerPanic {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.first
}

// steerGroup runs a tick's concurrent work, each function under a recover
// that keeps the first panic for the tick to raise once all are done.
type steerGroup struct {
	wg     sync.WaitGroup
	panics steerPanics
}

func (g *steerGroup) Go(f func()) {
	g.wg.Go(func() {
		defer g.catch()
		f()
	})
}

func (g *steerGroup) catch() {
	if p := recover(); p != nil {
		g.panics.keep(p)
	}
}

// steerKernel is the tick's kernel as Observe asks it: steer's Tick, each
// answer behind a recover. The /proc parsers and the interface ioctl are the
// only code a tick runs that parses what it is handed, and steer reads the
// node target's two addresses in goroutines of its own, out of the tick's
// reach. Here a panic in a reading answers TriUnknown, which holds, and is
// kept for the tick to raise once its goroutines are done.
type steerKernel struct {
	k      steer.Kernel
	panics steerPanics
}

var _ steer.Kernel = (*steerKernel)(nil)

func (k *steerKernel) Local(addr netip.Addr) (t steer.Tri) {
	defer k.catch(&t)
	return k.k.Local(addr)
}

func (k *steerKernel) Listening(addr netip.Addr) (t steer.Tri) {
	defer k.catch(&t)
	return k.k.Listening(addr)
}

func (k *steerKernel) catch(t *steer.Tri) {
	if p := recover(); p != nil {
		k.panics.keep(p)
		*t = steer.TriUnknown
	}
}

// serveSteer is GET /steer[?vip=A][&consumer=NAME][&dry=1]: 200 announce, 503
// withdraw or drain, 425 unknown — and anything else, no answer included,
// means hold. It answers readers on this box only.
func (n *Node) serveSteer(w http.ResponseWriter, r *http.Request) {
	metrics.EdgeSteerReadsTotal.Inc()
	if !steerPeerLocal(r) {
		steerError(w, http.StatusForbidden, "GET /steer answers readers on this box only (loopback, or the listener's own address)")
		return
	}
	s := n.steer
	if s == nil {
		steerError(w, http.StatusNotFound, "steering is off on this node")
		return
	}
	q := r.URL.Query()
	key, code, msg := s.keyFor(q.Get("vip"))
	if msg != "" {
		steerError(w, code, msg)
		return
	}
	now := time.Now()
	ans := s.answer(s.snap.Load(), key, now)
	// The stamp records what this read delivered; it is taken, and readsMu
	// released, before a byte is written.
	s.stampReader(key, SteerReader{
		Consumer: steerConsumer(q), Dry: steerDry(q), At: now.UTC(),
		Verdict: ans.Verdict, Since: ans.Since,
	})
	steerWriteJSON(w, steerHTTPStatus(ans.Verdict), ans)
}

// keyFor is the target a ?vip= names, or the status and message that refuse
// it. An empty vip is an absent one: the node's verdict when no VIPs are
// configured (a consumer's ?vip=$VIP with an empty variable), and a 400 when
// some are.
func (s *sampler) keyFor(vip string) (key string, code int, msg string) {
	if vip == "" {
		if s.vips {
			return "", http.StatusBadRequest, "name the address: GET /steer?vip=<one of steering.vips>"
		}
		return steer.NodeKey, 0, ""
	}
	a, err := netip.ParseAddr(vip)
	if err != nil {
		return "", http.StatusBadRequest, fmt.Sprintf("vip %q is not an address", steerText(vip, steerVIPEchoMax))
	}
	key = steer.VIPTarget(a).Key
	if !s.keys[key] {
		return "", http.StatusNotFound, fmt.Sprintf("%s is not steered on this node", key)
	}
	return key, 0, ""
}

// steerPeerLocal reports whether a /steer request comes from this box: its
// peer, unmapped, is a loopback address or the connection's own local
// address. The kernel sends a connection to one of this box's addresses from
// that address, and a host elsewhere cannot complete a handshake from one of
// them (the SYN-ACK comes here), so a wildcard status_listen still answers
// the CLI and a speaker on this box, and nobody on the network.
func steerPeerLocal(r *http.Request) bool {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer := remote.Addr().Unmap()
	if peer.IsLoopback() {
		return true
	}
	var local netip.Addr
	switch la := r.Context().Value(http.LocalAddrContextKey).(type) {
	case *net.TCPAddr:
		local = la.AddrPort().Addr()
	case net.Addr:
		if ap, err := netip.ParseAddrPort(la.String()); err == nil {
			local = ap.Addr()
		}
	}
	return local.IsValid() && local.Unmap() == peer
}

// steerHTTPStatus is /steer's status for a verdict: 200 announce, 503 for
// both ways out, 425 for anything else, which holds.
func steerHTTPStatus(s steer.State) int {
	switch s {
	case steer.StateAnnounce:
		return http.StatusOK
	case steer.StateWithdraw, steer.StateDrain:
		return http.StatusServiceUnavailable
	}
	return http.StatusTooEarly
}

// steerConsumer is the reader's name: ?consumer= when it is one, "invalid"
// when it is not, "anonymous" when absent or empty.
func steerConsumer(q url.Values) string {
	name := q.Get("consumer")
	switch {
	case name == "":
		return "anonymous"
	case steerConsumerRe.MatchString(name):
		return name
	}
	return "invalid"
}

// steerDry reads ?dry=. Absent, or every value 0 or false in any case, is a
// live reader; anything else — ?dry, ?dry=, yes, on, TRUE, 2 — is dry: a
// spelling the node does not know errs toward "nothing enforces it", never
// toward "enforced".
func steerDry(q url.Values) bool {
	for _, v := range q["dry"] {
		if v != "0" && !strings.EqualFold(v, "false") {
			return true
		}
	}
	return false
}

// stampReader records one read of a target: the name's entry moves to the
// front with its latest read, and the oldest name beyond steerMaxReaders is
// forgotten.
func (s *sampler) stampReader(key string, rd SteerReader) {
	s.readsMu.Lock()
	defer s.readsMu.Unlock()
	out := make([]SteerReader, 1, steerMaxReaders)
	out[0] = rd
	for _, old := range s.readers[key] {
		if old.Consumer != rd.Consumer && len(out) < steerMaxReaders {
			out = append(out, old)
		}
	}
	s.readers[key] = out
	s.latest = &rd
}

// readersCopy copies every target's readers and the newest stamp.
func (s *sampler) readersCopy() (map[string][]SteerReader, *SteerReader) {
	s.readsMu.Lock()
	defer s.readsMu.Unlock()
	out := make(map[string][]SteerReader, len(s.readers))
	for k, v := range s.readers {
		out[k] = slices.Clone(v)
	}
	var latest *SteerReader
	if s.latest != nil {
		l := *s.latest
		latest = &l
	}
	return out, latest
}

// answer is a target's verdict as a reader at now takes it (Verdict.AsOf),
// for the wire: UTC, bounded, and never a zone name or a prefix. Before the
// first tick it is unknown, starting.
func (s *sampler) answer(snap *steerSnapshot, key string, now time.Time) SteerAnswer {
	a := SteerAnswer{Target: key, Verdict: steer.StateUnknown, Reason: steer.ReasonStarting}
	if snap == nil {
		return a
	}
	t, ok := snap.targets[key]
	if !ok {
		return a
	}
	v := t.verdict.AsOf(now, s.staleAfter)
	a.Verdict, a.Reason, a.Warning = v.State, v.Reason, v.Warning
	a.Since, a.RejoinAt, a.At = v.Since.UTC(), v.RejoinAt.UTC(), v.At.UTC()
	a.HoldDown = t.hold
	in := t.inputs
	if in.Drain != nil {
		d := *in.Drain
		in.Drain = &d
	}
	a.Inputs = &in
	return a
}

// SteeringStatus is /healthz's steering object, from the last tick's snapshot
// and the readers: {"enabled":false} when steering is off. Reading it stamps
// nothing, and it takes readsMu only — never n.mu — so a caller holding n.mu
// (E7.4's report) may call it.
func (n *Node) SteeringStatus() SteeringStatus {
	if n.steer == nil {
		return SteeringStatus{}
	}
	return n.steer.status(time.Now())
}

func (s *sampler) status(now time.Time) SteeringStatus {
	snap := s.snap.Load()
	readers, latest := s.readersCopy()
	st := SteeringStatus{Enabled: true, IntervalSeconds: int(s.interval / time.Second)}
	if snap != nil {
		st.At = snap.at.UTC()
		if snap.nodeDrain != nil {
			d := *snap.nodeDrain
			st.Drained = &d
		}
		if snap.firstEntry != nil {
			fe := *snap.firstEntry
			fe.Missing = slices.Clone(fe.Missing)
			st.FirstEntry = &fe
		}
	} else {
		// Before the first tick nothing is known of the first entry either.
		st.FirstEntry = &SteerFirstEntry{Pending: steer.TriUnknown}
	}
	st.Targets = make([]SteerAnswer, 0, len(s.targets))
	for _, t := range s.targets {
		a := s.answer(snap, t.Key, now)
		a.Readers = readers[t.Key]
		st.Targets = append(st.Targets, a)
	}
	if latest != nil {
		st.ConsumedAt, st.Consumer = latest.At, latest
	}
	return st
}

// steerWireInputs is a tick's inputs as the wire carries them, the free text
// bounded; the drain only while it is in force.
func steerWireInputs(in steer.Inputs) SteerInputs {
	w := SteerInputs{
		Triggers: SteerTriggers{
			Refused: in.Triggers.Refused, NotTLS: in.Triggers.NotTLS,
			Unbound: in.Triggers.Unbound, Drained: in.Triggers.Drained,
		},
		Probe: in.Probe,
		Gates: SteerGates{GenerationLive: in.Gates.GenerationLive, Zones: in.Gates.Zones, DrainKnown: in.Gates.DrainKnown},
		Report: SteerReport{
			Terminator: in.Report.Terminator.State, Frozen: in.Report.Terminator.Frozen,
			Listening: in.Report.Listening, LogProgress: in.Report.LogProgress,
			ProbeError: steerText(in.Report.ProbeErr, steerErrMax),
			ProcError:  steerText(in.Report.ProcErr, steerErrMax),
			DrainError: steerText(in.Report.DrainErr, steerErrMax),
		},
	}
	if in.Triggers.Drained {
		w.Drain = steerWireDrain(in.Drain)
	}
	return w
}

// steerWireDrain is a drain on the wire: its reason bounded, its time UTC.
func steerWireDrain(d steer.Drain) *SteerDrain {
	return &SteerDrain{Reason: steerText(d.Reason, steerReasonMax), Since: d.Since.UTC()}
}

// steerWireHold is a target's ladder on the wire.
func steerWireHold(sv steer.Saved) SteerHoldDown {
	return SteerHoldDown{Level: sv.Level, Until: sv.Until.UTC()}
}

// steerWireFirstEntry is the first entry's progress on the wire: the first
// steerMaxMissing missing zones and how many there are.
func steerWireFirstEntry(pending steer.Tri, fe *steer.FirstEntry) *SteerFirstEntry {
	w := &SteerFirstEntry{Pending: pending}
	if fe == nil {
		return w
	}
	w.Zones, w.Ready, w.MissingCount = fe.Zones, fe.Ready, len(fe.Missing)
	w.Missing = slices.Clone(fe.Missing[:min(len(fe.Missing), steerMaxMissing)])
	return w
}

// steerText is s cut to at most n bytes at a rune boundary, with "…" appended
// when it was longer.
func steerText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// steerErrText is an error's text for the report, "" for none.
func steerErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// steerError answers a /steer request that names no verdict.
func steerError(w http.ResponseWriter, code int, msg string) {
	steerWriteJSON(w, code, struct {
		Error string `json:"error"`
	}{msg})
}

// steerWriteJSON writes v with code. A verdict is never cached: each read is
// the answer now.
func steerWriteJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		code, body = http.StatusInternalServerError, []byte(`{"error":"the answer could not be encoded"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(append(body, '\n'))
}

// fileExists reports whether path exists (not following a final symlink).
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

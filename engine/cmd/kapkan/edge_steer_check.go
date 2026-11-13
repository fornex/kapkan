package main

// `kapkan edge -check`'s steering lines (E7.2): what the configuration says,
// what the node would answer now and why, and what on this box could keep a
// verdict from meaning what it should — a drain this user cannot read, an
// address only a slow route table knows, a probe a firewall or a sandbox
// refuses. Everything here is read-only: -check writes no drain, no state
// and no directory, and stamps no reader (it reads /healthz, never /steer).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/node"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// steeringPreflight is -check's steering section, appended to
// edgePreflight's slices: notes, warnings, and the one problem -check finds
// itself (a steering path that is not a directory). The configuration errors
// steering has — status_listen missing, omit_catch_all, an IPv6 VIP under
// disable_ipv6 — never reach here: edge.yaml does not load with them.
func steeringPreflight(ec *config.EdgeNodeConfig) (problems, warnings, notes []string) {
	s := ec.Steering
	if !s.Enabled {
		return nil, nil, []string{"steering: off (steering.enabled is false): this node testifies nothing; GET /steer answers 404"}
	}
	cfg := s.SteerConfig()
	interval := cfg.StaleAfter() / steer.StaleIntervals
	tickDeadline := interval * 9 / 10
	targets := steerTargets(ec)
	targetText := steerKeys(targets)
	if len(s.VIPAddrs) == 0 {
		targetText = "the node itself (127.0.0.1, ::1)"
		if ec.DisableIPv6 {
			targetText = "the node itself (127.0.0.1)"
		}
	}
	notes = append(notes, fmt.Sprintf("steering: on, every %ds: withdraw on %d hard samples of the last %d, announce after %d ok in a row, hold-down %ds doubling to %ds; targets: %s",
		steerSeconds(interval), cfg.FailAfter, cfg.FailWindow, cfg.RecoverAfter, steerSeconds(cfg.HoldDownMin), steerSeconds(cfg.HoldDownMax), targetText))

	now := edgeSteerNow()
	store := steer.NewStore(ec.StateDir)
	notDir := false
	if fi, err := os.Stat(store.Dir); err == nil && !fi.IsDir() {
		notDir = true
		problems = append(problems, fmt.Sprintf("steering: %s is not a directory: kapkan edge can keep no state there, and every drain reads unknown", store.Dir))
	}
	_, born, loadErr := store.Load(now, cfg.HoldDownMax)
	switch {
	case born:
		notes = append(notes, fmt.Sprintf("steering: %s has no state.json: kapkan edge will start this node drained (new_node) until every zone answers TLS with its own certificate; the first node of a new address joins with kapkan edge -s undrain -force", store.Dir))
	case loadErr != nil && !notDir:
		warnings = append(warnings, fmt.Sprintf("steering: this user cannot read %s/state.json (%s): without the daemon, kapkan edge -steer answers without the saved hold-down", store.Dir, oneLine(loadErr)))
	}
	if !notDir {
		// What -steer will see without the daemon: a steering directory this
		// user cannot list, or can list but not search (every Lstat inside
		// then fails while the listing succeeds), answers announce whatever
		// drain stands.
		var unread []string
		var first error
		keys := []string{steer.NodeKey}
		for _, t := range targets {
			if t.Key != steer.NodeKey {
				keys = append(keys, t.Key)
			}
		}
		for _, k := range keys {
			if _, tri, err := store.DrainFor(k); tri == steer.TriUnknown {
				unread = append(unread, k)
				if first == nil {
					first = err
				}
			}
		}
		if len(unread) > 0 {
			warnings = append(warnings, fmt.Sprintf("steering: this user cannot read or search the drain files in %s for %s (%s): without the daemon, kapkan edge -steer answers announce whatever drain stands; give the consumer's user read and search access (kapkan creates the directory 0755 and its files 0644, under a 0711 state_dir)",
				store.Dir, strings.Join(unread, ", "), oneLine(first)))
		}
	}
	if ec.ACME.Disabled {
		warnings = append(warnings, "steering: acme.disabled is true: no zone gets a certificate, so this node's first entry never completes by itself; lift it by hand with kapkan edge -s undrain -force once the node serves")
	}
	proc := edgeSteerProc()
	fsys := steerProcFS(proc)
	for _, family := range []string{"ipv4", "ipv6"} {
		if raw, err := fs.ReadFile(fsys, "sys/net/"+family+"/ip_nonlocal_bind"); err == nil && strings.TrimSpace(string(raw)) == "1" {
			warnings = append(warnings, fmt.Sprintf("steering: net.%s.ip_nonlocal_bind is 1: bind() accepts addresses this box does not hold, so only /proc says whether a VIP is here (kapkan reads /proc; a service's successful bind proves nothing)", family))
		}
	}

	// The live evaluation, every target at once under one deadline, beside
	// the daemon's own view (read from /healthz, so nothing is stamped).
	ctx, cancel := context.WithTimeout(context.Background(), edgeCheckTimeout)
	defer cancel()
	evs := make([]steerEval, len(targets))
	var st node.Status
	var stErr error
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() { evs[i] = steerEvaluate(ctx, ec, t, now, true) })
	}
	wg.Go(func() {
		var addr string
		if addr, stErr = steerDaemonAddr(ec.StatusListen); stErr == nil {
			st, stErr = readHealthz(addr)
		}
	})
	wg.Wait()

	for _, ev := range evs {
		notes = append(notes, steerCheckVerdict(ev, cfg, st, stErr))
		warnings = append(warnings, steerCheckKernel(ev, cfg, tickDeadline)...)
	}

	// What a full routing table costs on this box: one reading of each route
	// table a VIP needs, bounded by the daemon's own tick deadline.
	var v4, v6 bool
	for _, a := range s.VIPAddrs {
		v4, v6 = v4 || a.Is4(), v6 || a.Is6()
	}
	for _, table := range []struct {
		name string
		need bool
	}{{"fib_trie", v4}, {"ipv6_route", v6}} {
		if !table.need {
			continue
		}
		if finished, err := timedRead(fsys, "net/"+table.name, tickDeadline); !finished && errors.Is(err, context.DeadlineExceeded) {
			warnings = append(warnings, fmt.Sprintf("steering: one reading of /proc/net/%s takes longer than kapkan edge's tick allows (%dms): on this box an address that is not on an interface stays unknown, and a VIP removed from the box is never seen unbound; both hold, and nothing withdraws them. Keep every VIP on an interface (lo), and drain an address before you remove it",
				table.name, tickDeadline.Milliseconds()))
		}
	}
	return problems, warnings, notes
}

// steerCheckVerdict is a target's N4 line: what the node would answer now,
// what the daemon says, and the hold-down ladder.
func steerCheckVerdict(ev steerEval, cfg steer.Config, st node.Status, stErr error) string {
	v := ev.verdict
	line := fmt.Sprintf("steering %s: would %s now (%s)", ev.target.Key, v.State, v.Reason)
	if v.Warning != "" {
		line += ", warning " + string(v.Warning)
	}
	if !v.RejoinAt.IsZero() {
		line += ", rejoin at " + steerTime(v.RejoinAt)
	}
	line += "; " + steerDaemonView(ev.target.Key, st, stErr)
	if lvl := ev.saved.Level; lvl > 0 {
		line += fmt.Sprintf("; hold-down level %d (the next flap holds it out %ds)", lvl, steerSeconds(cfg.HoldDown(lvl+1)))
	}
	return line
}

// steerDaemonView is the daemon's verdict for key, as /healthz reports it.
func steerDaemonView(key string, st node.Status, stErr error) string {
	switch {
	case stErr != nil:
		return fmt.Sprintf("kapkan edge did not answer (%s): kapkan edge -steer answers this evaluation", oneLine(stErr))
	case st.Steering == nil || !st.Steering.Enabled:
		return "the running kapkan edge is not steering (steering off, or a version without it): kapkan edge -steer answers hold (102) until it restarts with this edge.yaml"
	}
	for _, a := range st.Steering.Targets {
		if a.Target != key {
			continue
		}
		view := fmt.Sprintf("kapkan edge says %s (%s)", a.Verdict, a.Reason)
		if !a.Since.IsZero() {
			view += " since " + steerTime(a.Since)
		}
		return view
	}
	return "the running kapkan edge does not steer it (edge.yaml changed since it started?): kapkan edge -steer answers hold (102) until it restarts"
}

// steerCheckKernel is a target's warnings about this box: the address held
// or not (W2–W4) and what the probe met (W6).
func steerCheckKernel(ev steerEval, cfg steer.Config, tickDeadline time.Duration) []string {
	if !ev.observed {
		return nil
	}
	var out []string
	key, o := ev.target.Key, ev.obs
	vip := key != steer.NodeKey && len(ev.target.Addrs) > 0
	switch o.Local {
	case steer.TriNo:
		out = append(out, fmt.Sprintf("steering %s: this box's kernel does not hold the address now: kapkan edge would withdraw it (unbound)", key))
	case steer.TriUnknown:
		if ev.cut || errors.Is(ev.procErr, context.DeadlineExceeded) {
			out = append(out, fmt.Sprintf("steering %s: whether this box holds the address could not be read within %ds; kapkan edge's tick allows %dms, so on this box the daemon will hold this address unknown (never announce, never withdraw) for as long as it is not an interface address",
				key, steerSeconds(edgeCheckTimeout), tickDeadline.Milliseconds()))
		} else {
			why := "no reading answered"
			if ev.procErr != nil {
				why = oneLine(ev.procErr)
			}
			out = append(out, fmt.Sprintf("steering %s: whether this box holds the address could not be read (%s): it holds until it can", key, why))
		}
	}
	// An address that is not on an interface sends every tick to a route
	// table, which a full routing table can make slower than the tick. The node's own loopback pair is always on
	// lo, and is never Unbound.
	if vip && ev.ifaceOnly != steer.TriYes && o.Local != steer.TriNo {
		table := "/proc/net/fib_trie"
		if ev.target.Addrs[0].Is6() {
			table = "/proc/net/ipv6_route"
		}
		out = append(out, fmt.Sprintf("steering %s: not an interface address (an AnyIP route, or not held): each tick reads %s for it, which takes seconds on a box carrying a full routing table, and a reading cut short at the tick's deadline leaves the address unknown, which holds; an address on lo is read instantly", key, table))
	}
	switch o.Probe {
	case steer.ClassRefused:
		switch o.Listening {
		case steer.TriYes:
			out = append(out, fmt.Sprintf("steering %s: the probe of :443 is refused while a listener covers it: a firewall rule REJECTs it; that holds, and nothing withdraws this address while the rule stands", key))
		case steer.TriNo:
			out = append(out, fmt.Sprintf("steering %s: the probe of :443 is refused and nothing listens there: kapkan edge would withdraw the address after %d such samples", key, cfg.FailAfter))
		default:
			out = append(out, fmt.Sprintf("steering %s: the probe of :443 is refused (%s) and the listener table could not be read: it holds", key, o.ProbeErr))
		}
	case steer.ClassNotTLS:
		out = append(out, fmt.Sprintf("steering %s: :443 answered, and not with TLS: kapkan edge would withdraw the address after %d such samples", key, cfg.FailAfter))
	case steer.ClassSoft:
		out = append(out, fmt.Sprintf("steering %s: the probe of :443 got no TLS answer (%s): load looks like this, and it holds", key, o.ProbeErr))
	case steer.ClassBlind:
		if steerHasIPv6(ev.target) && strings.Contains(o.ProbeErr, "setsockopt") {
			out = append(out, fmt.Sprintf("steering %s: the probe could not be made: the kernel refused IP_FREEBIND on an IPv6 socket (%s), as a sandbox rejecting SOL_IP options on AF_INET6 does; every IPv6 probe holds, so no probe can withdraw this address (the first entry's handshakes use 127.0.0.1 and are unaffected)", key, o.ProbeErr))
		} else {
			out = append(out, fmt.Sprintf("steering %s: the probe could not be made (%s): it holds", key, o.ProbeErr))
		}
	}
	return out
}

// steerHasIPv6 reports whether a target probes an IPv6 address.
func steerHasIPv6(t steer.Target) bool {
	for _, a := range t.Addrs {
		if a.Is6() {
			return true
		}
	}
	return false
}

// timedRead makes one reading of name, bounded by d the way the sampler's
// own readings are: the ctx is looked at before each read(), and the kernel
// serves these files a page per read(). finished is false with the error
// when the reading failed or was cut short (context.DeadlineExceeded); an
// absent file — a host without /proc — is fs.ErrNotExist.
func timedRead(fsys fs.FS, name string, d time.Duration) (finished bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	f, err := fsys.Open(name)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	if _, err := io.Copy(io.Discard, ctxReader{ctx: ctx, r: f}); err != nil {
		return false, err
	}
	return true, nil
}

// ctxReader is r, read only while ctx has not ended.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(b []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(b)
}

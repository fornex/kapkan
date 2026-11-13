package main

// `kapkan edge -steer` and `kapkan edge -s drain|undrain|reset-holddown`
// (E7.2, edge-spec §8): the node's steering verdict for a reader on this box,
// and the operator's levers over it.
//
// -steer is a binary checker's answer. Its exit code is the whole contract: 0
// announce, 100 withdraw, 101 drain, and EVERY other code holds — 102 (this
// command's own "hold": steering off, an address not steered, a daemon that
// disowns it), 1 (edge.yaml is broken and the daemon did not answer), 2 (a
// usage error, or a Go panic). So nothing on these paths recovers a panic:
// an unrecovered panic exits 2, which holds, and that is exactly right. A
// recover that turned one into any other code could announce or withdraw an
// address on a bug. TestEdgeSteerPanicExitsTwo pins the exit code through
// main(), and TestEdgeNoRecoverInCmdKapkan pins that no file of this package
// recovers.
//
// -s writes the operator's drain files itself (steer.Store), so a drain
// needs no daemon; reset-holddown leaves a request file the daemon takes on
// its next tick. Neither has a route, a signal or a pid file to the daemon:
// the status listener stays read-only, and an unprivileged reader of
// /steer can change nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/node"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// The seams tests replace. Production reads the host's kernel, probes the
// real :443, and waits as long as an operator would.
var (
	edgeSteerProc    = steer.HostProc
	edgeSteerProber  = func() steer.Prober { return steer.Prober{} }
	edgeSteerNow     = time.Now
	edgeWaitTimeout  = 30 * time.Second
	edgeWaitPoll     = 250 * time.Millisecond
	edgeCheckTimeout = 5 * time.Second
)

const (
	// steerDefaultConsumer is the reader name -steer uses unless -consumer
	// gives another: the speaker's healthcheck, by default.
	steerDefaultConsumer = "kapkan-edge-steer"
	// steerClientTimeout bounds every request to the daemon. A daemon that
	// cannot answer its own loopback in a second is one -steer evaluates
	// without.
	steerClientTimeout = time.Second
	// steerLocalTimeout bounds -steer's local evaluation: the interface
	// listing waits on RTNL whatever a ctx says, and a speaker loading a full
	// table holds RTNL for seconds.
	steerLocalTimeout = 2 * time.Second
	// steerBodyLimit and healthzBodyLimit bound what is read of an answer.
	// The node bounds /steer itself (reasons 256 bytes, errors 512); /healthz
	// grows with the zone count (the h3 lists) beside up to 64 targets with 8
	// readers each.
	steerBodyLimit   = 64 << 10
	healthzBodyLimit = 4 << 20
	// steerReasonMax bounds -reason: the drain file's free text reaches
	// /steer, /healthz and the brain's report.
	steerReasonMax = 256
	// steerResetPoll is how often reset-holddown looks whether the daemon
	// took its request.
	steerResetPoll = 100 * time.Millisecond
	// The names the node gives readers it cannot name (internal/edge/node):
	// no ?consumer=, or one that is not a name. -wait never counts them, and
	// -consumer may not take them.
	steerAnonymous = "anonymous"
	steerInvalid   = "invalid"
)

// steerConsumerRe is the node's reader-name pattern (?consumer=NAME on
// GET /steer): -consumer must be a name the node would record as given.
var steerConsumerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// steerFlags are the steering flags of `kapkan edge`, as parsed. A string
// flag is "given" when it was set on the command line, empty or not: an
// empty -vip from a wrapper's unset variable must not quietly mean the node.
type steerFlags struct {
	check       bool
	steer       bool
	signal      string
	signalSet   bool
	vip         string
	vipSet      bool
	reason      string
	reasonSet   bool
	wait        bool
	force       bool
	consumer    string
	consumerSet bool
}

// namesSteer reports whether the raw arguments name -steer, wherever they
// stand. `kapkan edge -steer -vip A -h`, from a wrapper that appends its own
// arguments, prints help and must not exit 0: for -steer, 0 is announce.
func namesSteer(args []string) bool {
	for _, a := range args {
		if a == "-steer" || a == "--steer" || strings.HasPrefix(a, "-steer=") || strings.HasPrefix(a, "--steer=") {
			return true
		}
	}
	return false
}

// usageError names the first rule the steering flags break, "" when none
// does. Every one is exit 2.
func (sf steerFlags) usageError() string {
	exiting := 0
	for _, on := range []bool{sf.check, sf.steer, sf.signalSet} {
		if on {
			exiting++
		}
	}
	switch {
	case exiting > 1:
		return "-check, -steer and -s each do one thing and exit; give one of them"
	case sf.signalSet && sf.signal != "drain" && sf.signal != "undrain" && sf.signal != "reset-holddown":
		return fmt.Sprintf("-s %q is not drain, undrain or reset-holddown", sf.signal)
	case sf.vipSet && !sf.steer && !sf.signalSet:
		return "-vip applies only with -steer or -s"
	case sf.reasonSet && (!sf.signalSet || sf.signal != "drain"):
		return "-reason applies only with -s drain"
	case sf.reasonSet && len(sf.reason) > steerReasonMax:
		return fmt.Sprintf("-reason is %d bytes; at most %d", len(sf.reason), steerReasonMax)
	case sf.reasonSet && sf.reason == steer.NewNodeReason:
		// steer names any drain with this reason the first entry: /steer, the
		// metrics and -s undrain would mistake the operator's drain for it.
		return "-reason new_node is reserved for the first entry"
	case sf.wait && sf.signal != "drain" && sf.signal != "undrain":
		return "-wait applies only with -s drain or -s undrain (reset-holddown changes no verdict by itself)"
	case sf.consumerSet && !sf.steer && !sf.wait:
		return "-consumer applies only with -steer or -wait"
	case sf.consumerSet && !steerConsumerRe.MatchString(sf.consumer):
		return fmt.Sprintf("-consumer %q is not a reader name: a letter or a digit, then up to 63 letters, digits, '.', '_' or '-'", sf.consumer)
	case sf.consumerSet && (sf.consumer == steerAnonymous || sf.consumer == steerInvalid):
		return fmt.Sprintf("-consumer %q is reserved: kapkan edge records an unnamed reader as anonymous and a badly named one as invalid", sf.consumer)
	case sf.force && (sf.signal != "undrain" || sf.vipSet):
		// new_node drains every target, so a per-address force would lift
		// all of them.
		return "-force applies only with -s undrain, for the node itself (never with -vip): the new-node drain drains every target"
	}
	return ""
}

// steerTargets are the node's steered targets in edge.yaml's order, as the
// daemon builds them: one per VIP, or the node itself.
func steerTargets(ec *config.EdgeNodeConfig) []steer.Target {
	if len(ec.Steering.VIPAddrs) == 0 {
		return []steer.Target{steer.NodeTarget(!ec.DisableIPv6)}
	}
	ts := make([]steer.Target, len(ec.Steering.VIPAddrs))
	for i, a := range ec.Steering.VIPAddrs {
		ts[i] = steer.VIPTarget(a)
	}
	return ts
}

// steerVIPKey is the target key of -vip when it is one of steering.vips.
func steerVIPKey(ec *config.EdgeNodeConfig, vip string) (string, bool) {
	a, err := netip.ParseAddr(vip)
	if err != nil {
		return "", false
	}
	key := steer.VIPTarget(a).Key
	for _, v := range ec.Steering.VIPAddrs {
		if steer.VIPTarget(v).Key == key {
			return key, true
		}
	}
	return "", false
}

// steerLabel names -vip on an output line: its key when it is an address,
// else the text quoted, so a line stays one token per field.
func steerLabel(vip string) string {
	if a, err := netip.ParseAddr(vip); err == nil {
		return steer.VIPTarget(a).Key
	}
	return fmt.Sprintf("%q", vip)
}

// steerDaemonAddr is where this box reaches its own status listener: a
// wildcard listen address is dialled on 127.0.0.1, anything else as written
// (it is this box's own address, which the node's /steer answers too). Every
// wildcard spelling, "[::]" included, is one socket in Go's net.Listen —
// dual-stack, or IPv4 alone on a host without IPv6 — so 127.0.0.1 reaches it
// on every host, while ::1 is gone wherever IPv6 is turned off.
func steerDaemonAddr(statusListen string) (string, error) {
	host, port, err := net.SplitHostPort(statusListen)
	if err != nil {
		return "", fmt.Errorf("status_listen %q is not host:port: %w", statusListen, err)
	}
	if a, err := netip.ParseAddr(host); host == "" || (err == nil && a.Unmap().IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// steerURL is the daemon's URL for path and query at addr. A zone in addr
// ("[fe80::1%eth0]:9102") is escaped once, as %25, which is how net/url
// reads it back; pasted into a string it does not parse at all.
func steerURL(addr, path, query string) string {
	return (&url.URL{Scheme: "http", Host: addr, Path: path, RawQuery: query}).String()
}

// steerClient talks to the daemon on this box: one second for the whole
// exchange, no proxy (an HTTP_PROXY in the environment must never carry a
// request for a private status listener off the box), no keep-alive, and no
// redirect followed.
func steerClient() *http.Client {
	return &http.Client{
		Timeout:   steerClientTimeout,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// steerReply is the daemon's answer to GET /steer. kapkan edge sends a 200 or
// a 503 only with its answer for the asked target in the body, so those
// decide only with that answer there: anything else answering on
// status_listen — another service holding the port while kapkan edge is
// down, or one an edited status_listen now names — is no answer, never a
// withdrawal and never an announce.
type steerReply struct {
	code int
	ans  node.SteerAnswer
	// ok: the body decoded as a SteerAnswer.
	ok bool
	// target and verdict are the body's "target" and "verdict", read apart
	// from ans: a value this binary does not know elsewhere in the body (a
	// newer daemon's, after a rollback) must not hide them.
	target, verdict string
	// msg is the daemon's own error text on a 4xx.
	msg string
}

// answers reports whether the body is kapkan edge's answer for key with one
// of the verdicts vs.
func (r steerReply) answers(key string, vs ...steer.State) bool {
	if r.target != key {
		return false
	}
	for _, v := range vs {
		if r.verdict == v.String() {
			return true
		}
	}
	return false
}

// askSteer reads key's verdict from the daemon at addr as reader consumer,
// never dry: -steer acts on nothing itself, and the wrapper that acts owns
// its dry mode. The node target is asked without vip=.
func askSteer(addr, key, consumer string) (steerReply, error) {
	q := "consumer=" + url.QueryEscape(consumer)
	if key != steer.NodeKey {
		q = "vip=" + url.QueryEscape(key) + "&" + q
	}
	resp, err := steerClient().Get(steerURL(addr, "/steer", q))
	if err != nil {
		return steerReply{}, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only: a close error loses nothing
	r := steerReply{code: resp.StatusCode}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, steerBodyLimit))
	if err != nil {
		// A body cut short names no target: whatever the status, no answer.
		return r, nil
	}
	// A node always names the target: a body without one is not an answer.
	r.ok = json.Unmarshal(raw, &r.ans) == nil && r.ans.Target != ""
	var head struct {
		Target  string `json:"target"`
		Verdict string `json:"verdict"`
	}
	if json.Unmarshal(raw, &head) == nil {
		r.target, r.verdict = head.Target, head.Verdict
	}
	var refusal struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &refusal) == nil {
		r.msg = refusal.Error
	}
	return r, nil
}

// readHealthz reads the daemon's /healthz. It stamps no reader. 503 is the
// node's health rule — no live generation, or a dead terminator: exactly
// when an operator drains — and not steering's, so its body is read as a
// 200's is. No answer is a transport error, any other status, or a body that
// does not decode.
func readHealthz(addr string) (node.Status, error) {
	resp, err := steerClient().Get(steerURL(addr, "/healthz", ""))
	if err != nil {
		return node.Status{}, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only: a close error loses nothing
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return node.Status{}, fmt.Errorf("GET /healthz answered %s", resp.Status)
	}
	var st node.Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, healthzBodyLimit)).Decode(&st); err != nil {
		return node.Status{}, fmt.Errorf("GET /healthz: %w", err)
	}
	return st, nil
}

// steerExit is -steer's exit code for a verdict: anything but announce,
// withdraw and drain holds.
func steerExit(s steer.State) int {
	switch s {
	case steer.StateAnnounce:
		return exitOK
	case steer.StateWithdraw:
		return exitSteerWithdraw
	case steer.StateDrain:
		return exitSteerDrain
	}
	return exitSteerHold
}

// steerLine is -steer's one stdout line: key, verdict, reason, then the
// warning and the rejoin time when set, then where the answer came from.
func steerLine(out io.Writer, key, verdict, reason string, warning steer.Reason, rejoin time.Time, source string) {
	warn, at := "", ""
	if warning != "" {
		warn = " warning=" + string(warning)
	}
	if !rejoin.IsZero() {
		at = " rejoin_at=" + steerTime(rejoin)
	}
	lineWriter{out}.printf("%s %s %s%s%s source=%s\n", key, verdict, reason, warn, at, source)
}

// oneLine is err's text on one line: errors.Join puts each error on a line
// of its own, and every message here is one line.
func oneLine(err error) string {
	if err == nil {
		return "no error"
	}
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}

// steerTime prints a wire time: RFC 3339, UTC.
func steerTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// steerSeconds prints a duration as whole seconds, rounded up, so a bound is
// never printed shorter than it is.
func steerSeconds(d time.Duration) int { return int(math.Ceil(d.Seconds())) }

// steerFromDaemon maps a definite daemon answer — a 200 or a 503 carrying
// kapkan edge's answer for key with the verdict its status means, or a 404
// or a 400 — to -steer's line and exit code. ok is false for anything else,
// which the daemon did not answer definitely.
func steerFromDaemon(out, errOut io.Writer, key string, r steerReply) (code int, ok bool) {
	reason := "unreadable"
	if r.ok && r.ans.Reason != "" {
		reason = string(r.ans.Reason)
	}
	switch r.code {
	case http.StatusOK:
		if !r.answers(key, steer.StateAnnounce) {
			return 0, false
		}
		steerLine(out, key, steer.StateAnnounce.String(), reason, r.ans.Warning, r.ans.RejoinAt, "daemon")
		return exitOK, true
	case http.StatusServiceUnavailable:
		switch {
		case r.answers(key, steer.StateDrain):
			steerLine(out, key, steer.StateDrain.String(), reason, "", time.Time{}, "daemon")
			return exitSteerDrain, true
		case r.answers(key, steer.StateWithdraw):
			steerLine(out, key, steer.StateWithdraw.String(), reason, r.ans.Warning, r.ans.RejoinAt, "daemon")
			return exitSteerWithdraw, true
		}
		return 0, false
	case http.StatusNotFound, http.StatusBadRequest:
		// An older daemon, or an edge.yaml changed and not restarted:
		// testifying past the daemon's own view would bypass it.
		msg := ""
		if r.msg != "" {
			msg = ": " + r.msg
		}
		lineWriter{errOut}.printf("kapkan edge -steer: kapkan edge answered %d%s; it does not steer %s (an older version, or edge.yaml changed since it started): hold\n", r.code, msg, key)
		steerLine(out, key, "hold", "daemon_disowns", "", time.Time{}, "daemon")
		return exitSteerHold, true
	}
	return 0, false
}

// steerWhy says why a daemon's reply was not a definite answer for key.
func steerWhy(key string, r steerReply, err error) string {
	if err != nil {
		return oneLine(err)
	}
	why := fmt.Sprintf("HTTP %d", r.code)
	switch {
	case r.code == http.StatusOK || r.code == http.StatusServiceUnavailable:
		// kapkan edge sends these only with its answer for the asked target.
		why += fmt.Sprintf(", not kapkan edge's answer for %s: is another service on status_listen?", key)
	case r.ok:
		why += fmt.Sprintf(", verdict %s (%s)", r.ans.Verdict, r.ans.Reason)
	}
	return why
}

// runSteer is `kapkan edge -steer [-vip A] [-consumer NAME]`: the daemon's
// verdict when it gives a definite one, else the local, undamped evaluation
// of the same inputs.
func runSteer(ec *config.EdgeNodeConfig, sf steerFlags, out, errOut io.Writer) int {
	now := edgeSteerNow()
	w := lineWriter{errOut}
	label := steer.NodeKey
	if sf.vipSet {
		label = steerLabel(sf.vip)
	}
	if !ec.Steering.Enabled {
		steerLine(out, label, "hold", "steering_off", "", time.Time{}, "none")
		return exitSteerHold
	}
	targets := steerTargets(ec)
	t := targets[0]
	vips := ec.Steering.VIPAddrs
	switch {
	case len(vips) > 0 && !sf.vipSet:
		w.printf("kapkan edge: -steer needs -vip: steering.vips lists %s; name the address to answer for\n", steerKeys(targets))
		return exitUsage
	case len(vips) == 0 && sf.vipSet:
		w.printf("kapkan edge -steer: steering.vips is empty, so this node answers for itself alone (omit -vip): %s is not steered\n", label)
		steerLine(out, label, "hold", "not_steered", "", time.Time{}, "none")
		return exitSteerHold
	case sf.vipSet:
		key, ok := steerVIPKey(ec, sf.vip)
		if !ok {
			w.printf("kapkan edge -steer: %s is not in steering.vips (%s): it is not steered\n", label, steerKeys(targets))
			steerLine(out, label, "hold", "not_steered", "", time.Time{}, "none")
			return exitSteerHold
		}
		a, _ := netip.ParseAddr(key)
		t = steer.VIPTarget(a)
	}
	consumer := steerDefaultConsumer
	if sf.consumerSet {
		consumer = sf.consumer
	}

	why := "status_listen is not set"
	if ec.StatusListen != "" {
		addr, err := steerDaemonAddr(ec.StatusListen)
		var r steerReply
		if err == nil {
			r, err = askSteer(addr, t.Key, consumer)
		}
		if err == nil {
			if code, ok := steerFromDaemon(out, errOut, t.Key, r); ok {
				return code
			}
		}
		why = steerWhy(t.Key, r, err)
	}

	w.printf("kapkan edge -steer: kapkan edge did not answer (%s); this is the local, undamped evaluation\n", why)
	ctx, cancel := context.WithTimeout(context.Background(), steerLocalTimeout)
	defer cancel()
	ev := evaluateLocally(ctx, ec, t, now)
	if ev.cut {
		w.printf("kapkan edge -steer: the kernel did not answer within %ds (the interface listing waits on RTNL); answering from the drain files and the saved hold-down\n", steerSeconds(steerLocalTimeout))
	}
	if ev.loadErr != nil {
		w.printf("kapkan edge -steer: warning: %s: answering without the saved hold-down\n", oneLine(ev.loadErr))
	}
	if !ev.born && !ev.gates.DrainKnown {
		w.printf("kapkan edge -steer: warning: the drain files could not be read (%s): answering as if no drain stood; give this user read and search access to %s, and search access to every directory above it\n", oneLine(ev.drainErr), steer.NewStore(ec.StateDir).Dir)
	}
	v := ev.verdict
	if v.Reason == steer.ReasonHoldDown {
		w.printf("kapkan edge -steer: withdraw because the hold-down kapkan edge saved runs until %s; kapkan edge itself, damping, might hold the address instead\n", steerTime(v.RejoinAt))
	}
	steerLine(out, t.Key, v.State.String(), string(v.Reason), v.Warning, v.RejoinAt, "local")
	return steerExit(v.State)
}

// steerKeys lists the targets' keys for a message.
func steerKeys(ts []steer.Target) string {
	keys := make([]string, len(ts))
	for i, t := range ts {
		keys[i] = t.Key
	}
	return strings.Join(keys, ", ")
}

// steerBrokenConfig is -steer when edge.yaml does not load. The running
// daemon still serves the configuration it started with, and a config push
// that broke the file on every node must not read as down on every binary
// checker at once — a shared cause withdrawing the fleet while nginx serves.
// So the daemon is asked, with status_listen read leniently
// (lenientStatusListen); a definite answer stands, and anything else is exit
// 1: no local evaluation is made from a file that does not load.
func steerBrokenConfig(path string, loadErr error, sf steerFlags, out, errOut io.Writer) int {
	w := lineWriter{errOut}
	listen := ""
	if raw, err := os.ReadFile(path); err == nil {
		listen = lenientStatusListen(raw)
	}
	if listen == "" {
		w.printf("kapkan edge: %v\n", loadErr)
		return exitError
	}
	addr, err := steerDaemonAddr(listen)
	if err != nil {
		w.printf("kapkan edge: %v\n", loadErr)
		return exitError
	}
	// oneLine: steer's Validate joins every broken bound, one per line, and
	// this note is one line.
	w.printf("kapkan edge -steer: edge.yaml does not load (%s); asking the running kapkan edge, which still runs the configuration it started with\n", oneLine(loadErr))
	key := steer.NodeKey
	if sf.vipSet {
		a, err := netip.ParseAddr(sf.vip)
		if err != nil {
			w.printf("kapkan edge -steer: -vip %s is not an address, so it is not steered\n", steerLabel(sf.vip))
			steerLine(out, steerLabel(sf.vip), "hold", "not_steered", "", time.Time{}, "none")
			return exitSteerHold
		}
		key = steer.VIPTarget(a).Key
	}
	consumer := steerDefaultConsumer
	if sf.consumerSet {
		consumer = sf.consumer
	}
	r, err := askSteer(addr, key, consumer)
	if err == nil {
		if code, ok := steerFromDaemon(out, errOut, key, r); ok {
			return code
		}
	}
	w.printf("kapkan edge -steer: kapkan edge did not answer either (%s); without an edge.yaml that loads there is no local evaluation\n", steerWhy(key, r, err))
	return exitError
}

// statusListenLine is a top-level status_listen key on a line of its own: a
// plain or quoted value, then at most a comment. It does not match what it
// cannot read for certain — an escape, a flow collection, text glued to a
// '#' — and a value it misreads otherwise only sends -steer to an address
// that cannot answer as kapkan edge does for the asked target, which is all
// -steer takes from it.
var statusListenLine = regexp.MustCompile(`(?m)^status_listen:[ \t]*(?:"([^"\\\n]*)"|'([^'\n]*)'|([^\s"'#\[\]{},]+))(?:[ \t]+#.*)?[ \t]*\r?$`)

// lenientStatusListen is edge.yaml's status_listen read as leniently as is
// safe: yaml.v3 without KnownFields while the file parses, so a key this
// binary does not know or a value that does not validate still yields it;
// and when it does not parse at all — a tab, a key indented one space too
// far, the commoner way a push breaks a file — the value of its top-level
// status_listen line. "" when the file names none, or names two that differ:
// which of them the daemon runs is then unknown.
func lenientStatusListen(raw []byte) string {
	var lenient struct {
		StatusListen string `yaml:"status_listen"`
	}
	if yaml.Unmarshal(raw, &lenient) == nil {
		return lenient.StatusListen
	}
	found := ""
	for i, m := range statusListenLine.FindAllSubmatch(raw, -1) {
		v := string(m[1]) + string(m[2]) + string(m[3])
		if i > 0 && v != found {
			return ""
		}
		found = v
	}
	return found
}

// steerEval is one target's local evaluation and what went into it.
type steerEval struct {
	target  steer.Target
	verdict steer.Verdict
	// born: no state.json, so the node starts drained (new_node).
	born bool
	// loadErr: state.json could not be read; saved is then empty.
	loadErr error
	saved   steer.Saved
	// The drain files as Store.DrainFor reads them for the target.
	drain    steer.Drain
	drainTri steer.Tri
	drainErr error
	// observed: the kernel and the probe were asked; obs is their answer,
	// or Observation{} (unknown, not probed) when cut.
	observed bool
	obs      steer.Observation
	// cut: the observation outlived ctx and was abandoned.
	cut bool
	// procErr is the tick's reading errors (steer.Tick.Err).
	procErr error
	// ifaceOnly is -check's interface-only answer for a VIP: whether the
	// address is on an interface (TriYes), read without the route tables.
	ifaceOnly steer.Tri
	gates     steer.Gates
}

// evaluateLocally is the verdict without the daemon: the same inputs the
// sampler reads, run once through Automaton.Evaluate with the saved
// hold-down and no other history. It is read-only — it never births, saves,
// drains or resets — and bounded by ctx even where the kernel is not (the
// interface listing waits on RTNL). Its answer is always definite: a binary
// checker has no "hold", and an unknown takes nothing out.
func evaluateLocally(ctx context.Context, ec *config.EdgeNodeConfig, t steer.Target, now time.Time) steerEval {
	return steerEvaluate(ctx, ec, t, now, false)
}

// steerEvaluate is evaluateLocally; forCheck also observes a new node and
// reads the interface-only answer, which -check reports and -steer does not
// need.
func steerEvaluate(ctx context.Context, ec *config.EdgeNodeConfig, t steer.Target, now time.Time, forCheck bool) steerEval {
	cfg := ec.Steering.SteerConfig()
	store := steer.NewStore(ec.StateDir)
	ev := steerEval{target: t}
	f, born, err := store.Load(now, cfg.HoldDownMax)
	ev.born, ev.loadErr, ev.saved = born, err, f.Targets[t.Key]
	ev.saved.Until = steerWrittenBound(store, ev.saved.Until, now, cfg.HoldDownMax)
	ev.drain, ev.drainTri, ev.drainErr = store.DrainFor(t.Key)
	if !born || forCheck {
		steerObserve(ctx, &ev, forCheck)
	}

	ev.gates = steer.Gates{
		GenerationLive: steer.ReadGenerationLive(node.ConfRoot(ec.StateDir)),
		DrainKnown:     ev.drainTri != steer.TriUnknown,
	}
	if n, err := node.LiveZones(ec.StateDir); err == nil {
		ev.gates.Zones = n
	}
	in := steer.Inputs{
		Triggers: ev.obs.Triggers(ev.drainTri == steer.TriYes),
		Probe:    ev.obs.Probe,
		Gates:    ev.gates,
		Drain:    ev.drain,
	}
	if born && ev.drainTri != steer.TriYes {
		// The daemon's first start here births the node drained: answer as it
		// will, without the probe, which a drain ignores anyway.
		in.Triggers.Drained = true
		in.Drain = steer.Drain{Reason: steer.NewNodeReason, Since: now}
	}
	ev.verdict = steer.NewAutomaton(cfg, ev.saved).Evaluate(in, now)
	return ev
}

// steerWrittenBound is a saved hold-down's end as an evaluation without
// memory may take it. Load caps the end at now+max, but that cap moves with
// each run's clock and no run ever reaches it: an end past it — a hand edit,
// a clock stepped back since the save — would withdraw on every run for as
// long as the daemon is down. The daemon saves state.json on the tick a
// hold-down starts, so a real one ends by the file's last write plus max:
// the end is cut there, at one fixed instant. A file written in this clock's
// future by more than this run's own asking and reading take (now is read
// before the daemon is asked, and a daemon may save meanwhile) means the
// clock stepped back since the save: no hold-down can be established from
// it, and an unknown takes nothing out.
func steerWrittenBound(store steer.Store, until, now time.Time, maxHold time.Duration) time.Time {
	if until.IsZero() {
		return until
	}
	// After Load: a save in between can only move the bound later.
	fi, err := os.Stat(filepath.Join(store.Dir, "state.json"))
	if err != nil {
		return until
	}
	written := fi.ModTime()
	if written.After(now.Add(steerClientTimeout + steerLocalTimeout)) {
		return time.Time{}
	}
	if maxHold <= 0 {
		maxHold = steer.DefaultHoldDownMax // as Load takes it
	}
	if limit := written.Add(min(maxHold, steer.HoldDownCeiling)); until.After(limit) {
		return limit
	}
	return until
}

// steerObservation is what the bounded goroutine hands back.
type steerObservation struct {
	obs       steer.Observation
	ifaceOnly steer.Tri
}

// steerObserve asks the kernel and probes, in a goroutine it waits for only
// until ctx ends. Proc.Tick bounds the file readings by ctx, and the probe
// is bounded by it, but the interface listing (SIOCGIFCONF) waits on RTNL
// whatever ctx says, and RTNL is busy while a speaker loads a full table.
// Past ctx the kernel's part is unknown and the goroutine is abandoned: the
// process exits next.
func steerObserve(ctx context.Context, ev *steerEval, forCheck bool) {
	proc, prober := edgeSteerProc(), edgeSteerProber()
	kt := proc.Tick(ctx, prober.Port)
	t := ev.target
	done := make(chan steerObservation, 1)
	go func() {
		var r steerObservation
		if forCheck && t.Key != steer.NodeKey && len(t.Addrs) > 0 {
			r.ifaceOnly = steerIfaceOnly(ctx, proc, t.Addrs[0])
		}
		r.obs = prober.Observe(ctx, kt, t)
		done <- r
	}()
	ev.observed = true
	select {
	case r := <-done:
		ev.obs, ev.ifaceOnly = r.obs, r.ifaceOnly
	case <-ctx.Done():
		ev.cut = true
	}
	ev.procErr = kt.Err()
}

// steerIfaceOnly is whether addr is an interface address: the tick's answer
// with the route tables hidden, so only the interface list (IPv4) or
// if_inet6 (IPv6) can say yes. An AnyIP range, which is a route, answers
// unknown here.
func steerIfaceOnly(ctx context.Context, p steer.Proc, addr netip.Addr) steer.Tri {
	return steer.Proc{FS: hideRouteTables{steerProcFS(p)}, Ifaddrs4: p.Ifaddrs4}.Tick(ctx, 0).Local(addr)
}

// steerProcFS is the Proc's /proc tree, the host's when it names none.
func steerProcFS(p steer.Proc) fs.FS {
	if p.FS == nil {
		return os.DirFS("/proc")
	}
	return p.FS
}

// hideRouteTables is a /proc tree without the two route tables, which a full
// table makes slow: what is left answers yes only for interface addresses.
type hideRouteTables struct{ fs.FS }

func (h hideRouteTables) Open(name string) (fs.File, error) {
	if name == "net/fib_trie" || name == "net/ipv6_route" {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return h.FS.Open(name)
}

// runSteerSignal is `kapkan edge -s drain|undrain|reset-holddown`.
func runSteerSignal(ec *config.EdgeNodeConfig, sf steerFlags, errOut io.Writer) int {
	w := lineWriter{errOut}
	now := edgeSteerNow()
	key := steer.NodeKey
	if sf.vipSet {
		k, ok := steerVIPKey(ec, sf.vip)
		if !ok {
			w.printf("kapkan edge: %s is not in steering.vips\n", sf.vip)
			return exitError
		}
		key = k
	}
	store := steer.NewStore(ec.StateDir)
	switch sf.signal {
	case "drain":
		return steerDrain(ec, store, key, sf, now, w)
	case "undrain":
		return steerUndrain(ec, store, key, sf, now, w)
	}
	return steerResetHoldDown(ec, store, key, sf, now, w)
}

// steerOffWarning says a drain file written while steering is off waits for
// steering to read it.
func steerOffWarning(ec *config.EdgeNodeConfig, w lineWriter) {
	if !ec.Steering.Enabled {
		w.line("kapkan edge: warning: steering is off in edge.yaml; this takes effect when it is on")
	}
}

// steerDrain is -s drain: the operator's drain file, written here. A drain
// takes effect at the daemon's next tick, needs no daemon to be written, and
// is never lost to a restart.
func steerDrain(ec *config.EdgeNodeConfig, store steer.Store, key string, sf steerFlags, now time.Time, w lineWriter) int {
	// Before the daemon's first start there may be no state_dir yet, and
	// steer's Store would make it under this command's umask.
	if err := steerMkdirKeep(filepath.Clean(ec.StateDir), 0o711); err != nil {
		w.printf("kapkan edge -s drain: %s\n", oneLine(err))
		return exitError
	}
	if err := store.SetDrain(key, steer.Drain{Reason: sf.reason, Since: now.UTC()}); err != nil {
		w.printf("kapkan edge -s drain: %s\n", oneLine(err))
		return exitError
	}
	msg := "kapkan edge: drained " + key
	if sf.reason != "" {
		msg += fmt.Sprintf(" (reason %q)", sf.reason)
	}
	w.line(msg)
	steerOffWarning(ec, w)
	if !sf.wait {
		return exitOK
	}
	keys := []string{key}
	if key == steer.NodeKey {
		keys = nil
		for _, t := range steerTargets(ec) {
			keys = append(keys, t.Key)
		}
	}
	return steerWait(ec, keys, steer.StateDrain, sf, w)
}

// steerMkdirKeep creates dir with mode, and each missing directory above it
// 0755, whatever this command's umask. Under a hardened one (027, 077) a
// state_dir made by MkdirAll would be 0750 or 0700, hiding every drain from a
// -steer run as the speaker's own user, which would then answer announce for
// the node the operator drained. mode is the unit's StateDirectoryMode,
// 0711. A directory already there keeps its mode: systemd's, or the
// operator's.
func steerMkdirKeep(dir string, mode fs.FileMode) error {
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		return err // there (nil), or not knowable: the write would fail alike
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := steerMkdirKeep(parent, 0o755); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, mode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil // made meanwhile by another writer: its mode is theirs
		}
		return err
	}
	return os.Chmod(dir, mode) // mkdir applied the umask; chmod does not
}

// steerUndrain is -s undrain: the operator's drain lifted, and with -force
// the first entry too. It exits 0 only when the target is then not drained:
// the exit code says whether the target is still out.
func steerUndrain(ec *config.EdgeNodeConfig, store steer.Store, key string, sf steerFlags, now time.Time, w lineWriter) int {
	if err := store.Undrain(key); err != nil {
		w.printf("kapkan edge -s undrain: %s\n", oneLine(err))
		return exitError
	}
	if sf.force {
		lifted, err := store.LiftNewNode()
		if err != nil {
			w.printf("kapkan edge -s undrain: %s\n", oneLine(err))
			return exitError
		}
		if lifted {
			w.line("kapkan edge: lifted the new-node drain by hand")
		}
	}
	d, tri, derr := store.DrainFor(key)
	switch tri {
	case steer.TriUnknown:
		w.printf("kapkan edge: %s: a drain file could not be read (%s); it holds\n", key, oneLine(derr))
		return exitError
	case steer.TriYes:
		// A drain is the first entry's only when its marker stands: a
		// hand-written drain file may carry the reason new_node too, and it
		// is the operator's.
		if pending, _ := store.FirstEntryPending(); d.Reason == steer.NewNodeReason && pending == steer.TriYes {
			w.printf("kapkan edge: %s stays drained: its first entry is pending: %s. It lifts by itself once every zone has one; kapkan edge -s undrain -force lifts it now (the first node of a new address)\n", key, steerFirstEntryCounts(ec))
			return exitError
		}
		w.printf("kapkan edge: %s stays drained: the node-wide drain stands (kapkan edge -s undrain lifts it)\n", key)
		return exitError
	}
	if ec.Steering.Enabled {
		// No state.json: kapkan edge births this node drained (new_node), a
		// drain held in its memory until Birth writes the marker, so no drain
		// file shows it yet — and -steer answers 101 for it.
		if _, born, _ := store.Load(now, ec.Steering.SteerConfig().HoldDownMax); born {
			w.printf("kapkan edge: %s stays drained: %s has no state.json, so kapkan edge starts this node drained (new_node) until every zone answers TLS with its own certificate; once it has started, kapkan edge -s undrain -force lifts that (the first node of a new address)\n", key, store.Dir)
			return exitError
		}
	}

	msg := "kapkan edge: undrained " + key
	waitKeys := []string{key}
	if key == steer.NodeKey && len(ec.Steering.VIPAddrs) > 0 {
		// The node's drain lifted; a VIP still drained by its own file stays
		// out, is named here, and is not waited on.
		waitKeys = nil
		var still, unknown []string
		for _, t := range steerTargets(ec) {
			switch _, vt, _ := store.DrainFor(t.Key); vt {
			case steer.TriNo:
				waitKeys = append(waitKeys, t.Key)
			case steer.TriYes:
				still = append(still, t.Key)
			default:
				unknown = append(unknown, t.Key)
			}
		}
		if len(still) > 0 {
			msg += "; still drained one by one: " + strings.Join(still, ", ")
		}
		if len(unknown) > 0 {
			msg += "; a drain file could not be read for " + strings.Join(unknown, ", ") + " (it holds)"
		}
	}
	w.line(msg)
	steerOffWarning(ec, w)
	if !sf.wait || (ec.Steering.Enabled && len(waitKeys) == 0) {
		return exitOK
	}
	return steerWait(ec, waitKeys, steer.StateAnnounce, sf, w)
}

// steerFirstEntryCounts is the first entry's progress as the daemon reports
// it — "N of M zones with a certificate", the missing ones named — or why it
// is unknown. Only the daemon knows: it reads the live document, which is
// 0600, and has made the handshakes.
func steerFirstEntryCounts(ec *config.EdgeNodeConfig) string {
	if ec.StatusListen == "" {
		return "zones with a certificate: unknown (status_listen is not set, so there is no kapkan edge to ask)"
	}
	addr, err := steerDaemonAddr(ec.StatusListen)
	var st node.Status
	if err == nil {
		st, err = readHealthz(addr)
	}
	switch {
	case err != nil:
		return fmt.Sprintf("zones with a certificate: unknown (kapkan edge did not answer: %s)", oneLine(err))
	case st.Steering == nil || !st.Steering.Enabled:
		return "zones with a certificate: unknown (the running kapkan edge is not steering)"
	case st.Steering.FirstEntry == nil:
		return "zones with a certificate: unknown (the running kapkan edge reports no first entry)"
	case st.Steering.FirstEntry.Pending == steer.TriUnknown && st.Steering.FirstEntry.Zones == 0:
		// The daemon's first interval, or a new_node marker it cannot look
		// at: it reports {"pending":"unknown"} and no counts, and "0 of 0"
		// would read as a node without zones.
		return "zones with a certificate: unknown (the running kapkan edge has not counted them yet: it has just started, or cannot read its new_node marker)"
	}
	fe := st.Steering.FirstEntry
	s := fmt.Sprintf("%d of %d zones with a certificate", fe.Ready, fe.Zones)
	if len(fe.Missing) > 0 {
		s += "; missing: " + strings.Join(fe.Missing, ", ")
		if fe.MissingCount > len(fe.Missing) {
			s += fmt.Sprintf(" (%d in all)", fe.MissingCount)
		}
	}
	return s
}

// steerResetHoldDown is -s reset-holddown: a request file the daemon takes
// on its next tick (renaming it, so a take and this command's cancel never
// both succeed). It takes effect now or not at all: a request nobody took,
// or one whose command was interrupted (SIGINT, SIGTERM, a hangup), is
// withdrawn rather than left to surprise a later start. Only SIGKILL, or
// SIGQUIT (left uncaught, so Ctrl-\ keeps Go's goroutine dump), still leaves
// it behind.
func steerResetHoldDown(ec *config.EdgeNodeConfig, store steer.Store, key string, sf steerFlags, now time.Time, w lineWriter) int {
	if !ec.Steering.Enabled {
		w.line("kapkan edge: nothing to reset: steering is off")
		return exitOK
	}
	// No state.json is no hold-down. Never create the directory here: one
	// made under an operator's umask could hide the drains from an
	// unprivileged -steer.
	if _, err := os.Lstat(filepath.Join(store.Dir, "state.json")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			w.printf("kapkan edge: nothing to reset: %s has no state.json\n", store.Dir)
			return exitOK
		}
		w.printf("kapkan edge -s reset-holddown: %s\n", oneLine(err))
		return exitError
	}
	// One request at a time. The daemon takes one name, so a second
	// command's request would replace a pending one, or its cancel remove
	// one, while both commands reported on it. Holding the lock until its
	// outcome is known, each command has the name to itself: gone means
	// taken, and a cancel withdraws only its own request.
	unlock, err := steerResetLock(store.Dir)
	if err != nil {
		w.printf("kapkan edge -s reset-holddown: %s\n", oneLine(err))
		return exitError
	}
	defer unlock()
	// Caught only once the lock is held: until then an interrupt ends the
	// command as it always did, with nothing written. A hangup (the terminal
	// or SSH session the command ran in went away) is an interrupt too.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	req := node.ResetRequest{All: !sf.vipSet, At: now.UTC()}
	what := "every target"
	if sf.vipSet {
		req.Keys, what = []string{key}, key
	}
	if err := node.WriteResetRequest(store.Dir, req); err != nil {
		w.printf("kapkan edge -s reset-holddown: %s\n", oneLine(err))
		return exitError
	}
	cfg := ec.Steering.SteerConfig()
	bound := cfg.StaleAfter() + time.Second // three ticks, and a second to spare
	deadline := time.Now().Add(bound)
	for ctx.Err() == nil {
		if pending, err := node.ResetRequestPending(store.Dir); err == nil && !pending {
			w.printf("kapkan edge: kapkan edge took the hold-down reset for %s\n", what)
			return exitOK
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(steerResetPoll):
		}
	}
	taken, err := node.CancelResetRequest(store.Dir)
	switch {
	case err != nil:
		w.printf("kapkan edge -s reset-holddown: could not withdraw the request: %s; kapkan edge may still take it\n", oneLine(err))
		return exitError
	case taken:
		w.printf("kapkan edge: kapkan edge took the hold-down reset for %s\n", what)
		return exitOK
	case ctx.Err() != nil:
		w.line("kapkan edge: interrupted; the request is withdrawn and nothing was reset")
		return exitError
	}
	w.printf("kapkan edge: kapkan edge did not take the request within %ds (is it running, with steering on?); nothing was reset\n", steerSeconds(bound))
	return exitError
}

// steerResetLock holds dir/reset-holddown.lock exclusively until unlock,
// waiting for another command that holds it — at most that command's own
// bound, unless that command is stopped. The daemon never reads the file, and it stays: removing it while
// another command opens it would let two commands lock two files.
func steerResetLock(dir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, node.ResetRequestFile+".lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", f.Name(), err)
	}
	return func() { _ = f.Close() }, nil // the close drops the lock
}

// steerWaitTarget is one waited target as -wait has seen it.
type steerWaitTarget struct {
	key string
	// last is the target at the last answered poll.
	last node.SteerAnswer
	// live is the first qualifying read by a consumer not in dry mode, once
	// seen.
	live *node.SteerReader
	// overruled is the newest qualifying live read -wait did not count:
	// without -consumer, another named reader of the target was reading in
	// dry mode beside it, and -wait cannot tell which of the two is the
	// speaker.
	overruled *node.SteerReader
	// dry is the newest qualifying read, all of them dry, and drySeen when
	// -wait first saw one.
	dry     *node.SteerReader
	drySeen time.Time
}

// steerQualifies reports whether r read this very episode of the awaited
// verdict: a named reader (and -consumer's, when given) served the awaited
// verdict with the target's current since. A read's time is never compared
// with since: the snapshot that carries a new verdict is published up to 0.9
// interval after its since, and a read in between was served the one before.
func steerQualifies(r node.SteerReader, consumer string, awaited steer.State, cur node.SteerAnswer) bool {
	if r.Consumer == steerAnonymous || r.Consumer == steerInvalid || (consumer != "" && r.Consumer != consumer) {
		return false
	}
	return cur.Verdict == awaited && !cur.Since.IsZero() && r.Verdict == awaited && r.Since.Equal(cur.Since)
}

// observe folds one answered poll into the target. Without -consumer any
// named reader may be the speaker, and a live read beside a reader reading
// in dry mode right now — a monitor's -steer, which is never dry, beside a
// speaker watching first — does not count: -wait cannot tell it from the
// speaker's, and counting it would let `drain -wait && systemctl stop nginx`
// go on while the speaker still announces. A dry name nobody has read under
// for grace blocks nothing.
func (t *steerWaitTarget) observe(awaited steer.State, consumer string, now time.Time, grace time.Duration) {
	if t.live != nil {
		return
	}
	dryBeside := consumer == "" && steerDryReading(t.last.Readers, now, grace)
	for i := range t.last.Readers {
		r := t.last.Readers[i]
		if !steerQualifies(r, consumer, awaited, t.last) {
			continue
		}
		switch {
		case !r.Dry && dryBeside:
			if t.overruled == nil || r.At.After(t.overruled.At) {
				t.overruled = &r
			}
		case !r.Dry:
			t.live = &r
			return
		case t.dry == nil || r.At.After(t.dry.At):
			t.dry = &r
		}
	}
	if t.dry != nil && t.drySeen.IsZero() {
		t.drySeen = now
	}
}

// steerDryReading reports whether a named reader read the target in dry mode
// within grace of now, whatever it was served: a consumer reading dry right
// now, and so perhaps the speaker.
func steerDryReading(readers []node.SteerReader, now time.Time, grace time.Duration) bool {
	for _, r := range readers {
		if r.Dry && r.Consumer != steerAnonymous && r.Consumer != steerInvalid && now.Sub(r.At) <= grace {
			return true
		}
	}
	return false
}

// decided reports whether the target needs no more polls: a live read, or
// only dry ones for longer than grace — the time a live reader gets to show
// up first.
func (t *steerWaitTarget) decided(now time.Time, grace time.Duration) bool {
	return t.live != nil || (t.dry != nil && now.Sub(t.drySeen) >= grace)
}

// steerWait is -wait: it polls /healthz (which stamps nothing) until a
// consumer has read the new verdict of every waited target, decided per
// target: read live, read only in dry mode, or unread at the bound. Without
// -consumer, a live read does not count while another named reader has read
// the target in dry mode within grace, because -wait cannot tell which of the
// two is the speaker: the target then ends dry if a reader in dry mode read
// the new verdict, and unread if none did. 0 when every target has a live
// read that counts; 10 when the rest were read only in dry mode, or live only
// beside a dry reader of the new verdict — nothing may act on it there, so
// `drain -wait && systemctl stop nginx` must not go on; and 1 when one is
// unread, which includes a live read that did not count. A read is
// all -wait can see, not the speaker's action: the shipped consumer acts on
// the answer it reads, while a checker with a rise and fall of its own
// (ExaBGP's healthcheck at its defaults) acts (rise or fall − 1) of its
// intervals later.
func steerWait(ec *config.EdgeNodeConfig, keys []string, awaited steer.State, sf steerFlags, w lineWriter) int {
	if !ec.Steering.Enabled {
		w.line("kapkan edge: -wait: steering is off in edge.yaml, so no consumer reads a verdict; the change is written and takes effect when it is on")
		return exitError
	}
	addr, err := steerDaemonAddr(ec.StatusListen)
	if err != nil {
		w.printf("kapkan edge: -wait: %v\n", err)
		return exitError
	}
	cfg := ec.Steering.SteerConfig()
	grace := cfg.StaleAfter()
	interval := grace / steer.StaleIntervals
	consumer := ""
	if sf.consumerSet {
		consumer = sf.consumer
	}
	bound := edgeWaitTimeout
	if awaited == steer.StateAnnounce {
		// An undrain waits for the join itself: recover_after ok ticks, and
		// the three a reader may wait for the snapshot.
		bound += time.Duration(cfg.RecoverAfter+steer.StaleIntervals) * interval
		w.printf("kapkan edge: waiting up to %ds (recover_after %d × %ds)\n", steerSeconds(bound), cfg.RecoverAfter, steerSeconds(interval))
	}
	targets := make([]*steerWaitTarget, len(keys))
	for i, k := range keys {
		targets[i] = &steerWaitTarget{key: k}
	}
	deadline := time.Now().Add(bound)
	// An undrain's bound waits for a hold-down still running too, taken once.
	leadTaken := awaited != steer.StateAnnounce
	answered := false
	for {
		if st, err := readHealthz(addr); err == nil {
			if st.Steering == nil || !st.Steering.Enabled {
				w.line("kapkan edge: the running kapkan edge is not steering (steering off, or a version without it); the change takes effect when it is")
				return exitError
			}
			for _, t := range targets {
				found := false
				for _, a := range st.Steering.Targets {
					if a.Target == t.key {
						t.last, found = a, true
						break
					}
				}
				if !found {
					w.printf("kapkan edge: the running kapkan edge does not steer %s (edge.yaml changed since it started?); restart it\n", t.key)
					return exitError
				}
			}
			answered = true
			if !leadTaken {
				// A hold-down still running keeps the target out until it ends.
				// The first answered poll comes before the daemon's next tick, so
				// it is mostly served the drain, which shows a hold-down only as
				// hold_down.until (rejoin_at belongs to unknown and withdraw), or,
				// right after a start, an answer from before any tick, which
				// shows none: such a poll leaves the lead to the next one.
				var lead time.Duration
				var until time.Time
				ticked := true
				wall := edgeSteerNow()
				for _, t := range targets {
					ticked = ticked && !t.last.At.IsZero()
					end := t.last.RejoinAt
					if t.last.HoldDown.Until.After(end) {
						end = t.last.HoldDown.Until
					}
					if d := end.Sub(wall); d > lead {
						lead, until = d, end
					}
				}
				leadTaken = lead > 0 || ticked
				if lead > 0 {
					bound += lead
					deadline = deadline.Add(lead)
					w.printf("kapkan edge: waiting up to %ds (recover_after %d × %ds, plus the hold-down until %s)\n", steerSeconds(bound), cfg.RecoverAfter, steerSeconds(interval), steerTime(until))
				}
			}
			now := time.Now()
			all := true
			for _, t := range targets {
				t.observe(awaited, consumer, now, grace)
				all = all && t.decided(now, grace)
			}
			if all {
				return steerWaitOutcome(targets, awaited, consumer, bound, w)
			}
		}
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		time.Sleep(min(edgeWaitPoll, left))
	}
	if !answered {
		w.printf("kapkan edge: kapkan edge did not answer on %s within %ds; the change is written and takes effect when it runs\n", addr, steerSeconds(bound))
		return exitError
	}
	return steerWaitOutcome(targets, awaited, consumer, bound, w)
}

// steerWaitOutcome prints one line per target — read live, read only in dry
// mode, or unread — and returns -wait's exit code. At the bound a target
// whose qualifying readers are all dry counts as dry, its grace over or not;
// one read live only beside a consumer reading dry counts as dry, or as
// unread, and its line says why.
func steerWaitOutcome(targets []*steerWaitTarget, awaited steer.State, consumer string, bound time.Duration, w lineWriter) int {
	const pin = "without -consumer, -wait cannot tell your speaker from a monitor; name the speaker's consumer with -consumer NAME"
	code := exitOK
	for _, t := range targets {
		switch {
		case t.live != nil:
			w.printf("kapkan edge: %s: %s read by %s at %s\n", t.key, awaited, t.live.Consumer, steerTime(t.live.At))
		case t.dry != nil && t.overruled != nil:
			w.printf("kapkan edge: %s: %s read in dry mode by %s at %s, which changes nothing, and live by %s at %s: %s\n",
				t.key, awaited, t.dry.Consumer, steerTime(t.dry.At), t.overruled.Consumer, steerTime(t.overruled.At), pin)
			if code == exitOK {
				code = exitNotEnforcing
			}
		case t.dry != nil:
			w.printf("kapkan edge: %s: %s read only by a consumer in dry mode (%s at %s): it logs what it would do and changes nothing\n", t.key, awaited, t.dry.Consumer, steerTime(t.dry.At))
			if code == exitOK {
				code = exitNotEnforcing
			}
		default:
			code = exitError
			rejoin := ""
			if !t.last.RejoinAt.IsZero() {
				rejoin = ", rejoin at " + steerTime(t.last.RejoinAt)
			}
			overruled := ""
			if t.overruled != nil {
				overruled = fmt.Sprintf("; not counted: %s's live read at %s, beside a consumer reading in dry mode (%s)", t.overruled.Consumer, steerTime(t.overruled.At), pin)
			}
			w.printf("kapkan edge: no consumer read %s's %s within %ds; it is %s (%s)%s; last read: %s%s%s\n",
				t.key, awaited, steerSeconds(bound), t.last.Verdict, t.last.Reason, rejoin, steerLastRead(t.last.Readers, consumer), steerIgnored(t.last.Readers, consumer), overruled)
		}
	}
	return code
}

// steerLastRead is the newest read -wait could have counted by its name,
// whatever it was served, or "never".
func steerLastRead(readers []node.SteerReader, consumer string) string {
	var last *node.SteerReader
	for i := range readers {
		r := &readers[i]
		if r.Consumer == steerAnonymous || r.Consumer == steerInvalid || (consumer != "" && r.Consumer != consumer) {
			continue
		}
		if last == nil || r.At.After(last.At) {
			last = r
		}
	}
	if last == nil {
		return "never"
	}
	return fmt.Sprintf("%s at %s, served %s", last.Consumer, steerTime(last.At), last.Verdict)
}

// steerIgnored names the reads -wait does not count by their name: unnamed
// readers always, and with -consumer every other name.
func steerIgnored(readers []node.SteerReader, consumer string) string {
	var unnamed, other []string
	for _, r := range readers {
		switch {
		case r.Consumer == steerAnonymous || r.Consumer == steerInvalid:
			unnamed = append(unnamed, r.Consumer+" at "+steerTime(r.At))
		case consumer != "" && r.Consumer != consumer:
			other = append(other, r.Consumer+" at "+steerTime(r.At))
		}
	}
	s := ""
	if len(unnamed) > 0 {
		s += "; ignored unnamed readers: " + strings.Join(unnamed, ", ")
	}
	if len(other) > 0 {
		s += "; ignored other readers: " + strings.Join(other, ", ")
	}
	return s
}

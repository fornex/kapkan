package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/edge/node"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// steerFibTrie is internal/edge/steer's whole fixture
// testdata/proc/net/fib_trie, copied: 192.0.2.10 is local (a /32 LOCAL in
// table local), and 192.0.2.11 is in no LOCAL entry of a whole Local:
// section, so the kernel does not hold it.
const steerFibTrie = `Id 100:
  +-- 203.0.113.0/28 2 0 2
     |-- 203.0.113.7
        /32 host LOCAL
     |-- 203.0.113.8
        /32 link UNICAST
Main:
  +-- 0.0.0.0/4 2 0 2
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.0.0/31 1 0 0
        |-- 10.0.0.0
           /24 link UNICAST
        |-- 10.0.0.1
           /32 link UNICAST tos=16
Local:
  +-- 0.0.0.0/0 3 0 5
     +-- 10.0.0.0/24 2 0 2
        |-- 10.0.0.5
           /32 host LOCAL
        |-- 10.0.0.255
           /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 192.0.0.0/5 2 0 2
        |-- 192.0.2.10
           /32 host LOCAL
        |-- 198.51.100.0
           /24 host LOCAL
`

// steerProc is these tests' /proc: the fixture and whatever a test adds, and
// no interface list, so every IPv4 answer is fib_trie's. The probe of
// 192.0.2.10 is blind here (its bind fails: EADDRNOTAVAIL), or soft under
// ip_nonlocal_bind=1; either way no trigger fires, and the tests assert exit
// codes, never that class.
func steerProc(extra fstest.MapFS) steer.Proc {
	fsys := fstest.MapFS{"net/fib_trie": {Data: []byte(steerFibTrie)}}
	maps.Copy(fsys, extra)
	return steer.Proc{FS: fsys}
}

// withSteerSeams points the CLI's kernel at proc for one test, and its probe
// at a loopback port nobody listens on — never this host's :443 — and puts
// every seam back when the test ends.
func withSteerSeams(t *testing.T, proc steer.Proc) {
	t.Helper()
	p, pr, now := edgeSteerProc, edgeSteerProber, edgeSteerNow
	wt, wp, ct := edgeWaitTimeout, edgeWaitPoll, edgeCheckTimeout
	t.Cleanup(func() {
		edgeSteerProc, edgeSteerProber, edgeSteerNow = p, pr, now
		edgeWaitTimeout, edgeWaitPoll, edgeCheckTimeout = wt, wp, ct
	})
	_, port, err := net.SplitHostPort(deadSteerAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	edgeSteerProc = func() steer.Proc { return proc }
	edgeSteerProber = func() steer.Prober { return steer.Prober{Port: uint16(n)} }
}

// steerYAMLBody is an edge.yaml with steering on over two VIPs, its status
// listener at listen and its state under state.
func steerYAMLBody(listen, state string) string {
	return fmt.Sprintf(`controller:
  url: "https://kapkan.example.net:8443"
  token_env: KAPKAN_TEST_EDGE_TOKEN
  name: edge-1
state_dir: %s
status_listen: %q
steering:
  enabled: true
  interval_seconds: 1
  recover_after: 3
  vips: [192.0.2.10, 192.0.2.11]
`, state, listen)
}

func steerYAML(t *testing.T, listen, state string) string {
	t.Helper()
	return writeEdgeYAML(t, steerYAMLBody(listen, state))
}

// steerYAMLOff is steerYAML with steering.enabled false.
func steerYAMLOff(t *testing.T, listen, state string) string {
	t.Helper()
	return writeEdgeYAML(t, strings.Replace(steerYAMLBody(listen, state), "enabled: true", "enabled: false", 1))
}

// seedSteerState writes state.json as a daemon that ran here would, so no
// new-node drain stands.
func seedSteerState(t *testing.T, state string, targets map[string]steer.Saved) steer.Store {
	t.Helper()
	store := steer.NewStore(state)
	if err := store.Save(steer.StateFile{Born: time.Now(), Targets: targets}); err != nil {
		t.Fatal(err)
	}
	return store
}

// deadSteerAddr is a loopback port nobody listens on.
func deadSteerAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// hungSteerAddr accepts connections and never writes a byte, until the test
// ends.
func hungSteerAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// fakeSteerd stands in for a running kapkan edge's status listener: GET
// /steer and GET /healthz answer what the test scripts, in the node's own
// wire types (node.SteerAnswer, node.Status), and every request is recorded.
type fakeSteerd struct {
	srv *httptest.Server

	mu        sync.Mutex
	steerCode int
	steerBody []byte
	health    func(poll int) (int, node.Status)
	polls     int
	reqs      []string
}

func newFakeSteerd(t *testing.T) *fakeSteerd {
	t.Helper()
	d := &fakeSteerd{steerCode: http.StatusNotFound}
	d.srv = httptest.NewServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeSteerd) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.reqs = append(d.reqs, r.Method+" "+r.URL.RequestURI())
	code, body := http.StatusNotFound, []byte(`{"error":"no such route"}`)
	health := d.health
	poll := 0
	switch r.URL.Path {
	case "/steer":
		code, body = d.steerCode, d.steerBody
	case "/healthz":
		d.polls++
		poll = d.polls
	}
	d.mu.Unlock()
	if r.URL.Path == "/healthz" && health != nil {
		var st node.Status
		code, st = health(poll)
		body, _ = json.Marshal(st)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (d *fakeSteerd) addr() string { return d.srv.Listener.Addr().String() }

func (d *fakeSteerd) answer(code int, body []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.steerCode, d.steerBody = code, body
}

func (d *fakeSteerd) serveHealth(fn func(poll int) (int, node.Status)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.health, d.polls = fn, 0
}

func (d *fakeSteerd) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.reqs...)
}

func steerBody(t *testing.T, a node.SteerAnswer) []byte {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// steerStatus is a steering daemon's /healthz with these targets.
func steerStatus(targets ...node.SteerAnswer) node.Status {
	return node.Status{Healthy: true, Steering: &node.SteeringStatus{Enabled: true, IntervalSeconds: 1, Targets: targets}}
}

// TestEdgeSteerAsksTheDaemon pins -steer's reading of a live daemon:
// the status decides — 200 announce, 503 withdraw or drain (the body only
// names which), 404 and 400 hold (102) — and the request is exactly
// ?vip=<key>&consumer=<name>, never dry.
func TestEdgeSteerAsksTheDaemon(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	d := newFakeSteerd(t)
	state := t.TempDir()
	seedSteerState(t, state, nil)
	cfg := steerYAML(t, d.addr(), state)
	since := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	ans := func(v steer.State, r steer.Reason) node.SteerAnswer {
		return node.SteerAnswer{Target: "192.0.2.10", Verdict: v, Reason: r, Since: since, At: since.Add(time.Second)}
	}
	withdraw := ans(steer.StateWithdraw, steer.ReasonRefused)
	withdraw.RejoinAt = since.Add(20 * time.Second)
	warned := ans(steer.StateAnnounce, steer.ReasonOK)
	warned.Warning = steer.ReasonNoZones
	announce := steerBody(t, ans(steer.StateAnnounce, steer.ReasonOK))
	cases := []struct {
		name      string
		code      int
		body      []byte
		vip       string
		consumer  string
		want      int
		line      string
		errorText string
	}{
		{name: "200 announce", code: 200, body: announce, want: exitOK, line: "192.0.2.10 announce ok source=daemon\n"},
		{name: "200 announce with a closed gate", code: 200, body: steerBody(t, warned), want: exitOK, line: "192.0.2.10 announce ok warning=no_zones source=daemon\n"},
		{name: "503 drain", code: 503, body: steerBody(t, ans(steer.StateDrain, steer.ReasonDrained)), want: exitSteerDrain, line: "192.0.2.10 drain drained source=daemon\n"},
		{name: "503 withdraw", code: 503, body: steerBody(t, withdraw), want: exitSteerWithdraw, line: "192.0.2.10 withdraw refused rejoin_at=2026-11-13T08:00:20Z source=daemon\n"},
		{name: "503 garbage", code: 503, body: []byte("<html>busy</html>"), want: exitSteerWithdraw, line: "192.0.2.10 withdraw unreadable source=daemon\n"},
		{name: "404", code: 404, body: []byte(`{"error":"steering is off on this node"}`), want: exitSteerHold, line: "192.0.2.10 hold daemon_disowns source=daemon\n", errorText: "steering is off on this node"},
		{name: "400", code: 400, body: []byte(`{"error":"name the address"}`), want: exitSteerHold, line: "192.0.2.10 hold daemon_disowns source=daemon\n", errorText: "name the address"},
		{name: "a monitor reads under its own name", code: 200, body: announce, consumer: "nagios", want: exitOK, line: "192.0.2.10 announce ok source=daemon\n"},
		{name: "a mapped spelling asks for the key", code: 200, body: announce, vip: "::ffff:192.0.2.10", want: exitOK, line: "192.0.2.10 announce ok source=daemon\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d.answer(c.code, c.body)
			vip, consumer := "192.0.2.10", steerDefaultConsumer
			if c.vip != "" {
				vip = c.vip
			}
			args := []string{"-config", cfg, "-steer", "-vip", vip}
			if c.consumer != "" {
				args, consumer = append(args, "-consumer", c.consumer), c.consumer
			}
			n := len(d.requests())
			code, stdout, stderr := runEdgeCLIOut(t, args...)
			if code != c.want || stdout != c.line {
				t.Fatalf("code=%d stdout=%q, want %d %q (stderr %q)", code, stdout, c.want, c.line, stderr)
			}
			if !strings.Contains(stderr, c.errorText) {
				t.Fatalf("stderr %q lacks the daemon's own text %q", stderr, c.errorText)
			}
			if want := "GET /steer?vip=192.0.2.10&consumer=" + consumer; !slices.Equal(d.requests()[n:], []string{want}) {
				t.Fatalf("the daemon saw %q, want exactly %q", d.requests()[n:], want)
			}
		})
	}

	t.Run("the node itself is asked without vip", func(t *testing.T) {
		body := strings.Replace(steerYAMLBody(d.addr(), state), "  vips: [192.0.2.10, 192.0.2.11]\n", "", 1)
		cfg := writeEdgeYAML(t, body)
		self := ans(steer.StateAnnounce, steer.ReasonOK)
		self.Target = steer.NodeKey
		d.answer(200, steerBody(t, self))
		n := len(d.requests())
		code, stdout, stderr := runEdgeCLIOut(t, "-config", cfg, "-steer")
		if code != exitOK || stdout != "node announce ok source=daemon\n" {
			t.Fatalf("code=%d stdout=%q (stderr %q)", code, stdout, stderr)
		}
		if want := "GET /steer?consumer=kapkan-edge-steer"; !slices.Equal(d.requests()[n:], []string{want}) {
			t.Fatalf("the daemon saw %q, want exactly %q", d.requests()[n:], want)
		}
	})
}

// TestEdgeSteerWithoutTheDaemon pins the local evaluation: a daemon
// that is dead, hung, unknown (425) or broken (500) gets the local, undamped
// answer from the same inputs — always definite, because a binary checker
// has no hold — and an interface listing stuck on RTNL cannot hold -steer
// past its bound.
func TestEdgeSteerWithoutTheDaemon(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	const unmanaged = "192.0.2.10 announce unmanaged warning=generation_not_live source=local\n"

	unknown := newFakeSteerd(t)
	unknown.answer(http.StatusTooEarly, steerBody(t, node.SteerAnswer{Target: "192.0.2.10", Reason: steer.ReasonStarting}))
	broken := newFakeSteerd(t)
	broken.answer(http.StatusInternalServerError, []byte("boom"))
	for _, c := range []struct {
		name, addr string
		hung       bool
	}{
		{name: "dead", addr: deadSteerAddr(t)},
		{name: "hung", addr: hungSteerAddr(t), hung: true},
		{name: "425", addr: unknown.addr()},
		{name: "500", addr: broken.addr()},
	} {
		t.Run(c.name, func(t *testing.T) {
			state := t.TempDir()
			seedSteerState(t, state, nil)
			cfg := steerYAML(t, c.addr, state)
			start := time.Now()
			code, stdout, stderr := runEdgeCLIOut(t, "-config", cfg, "-steer", "-vip", "192.0.2.10")
			elapsed := time.Since(start)
			if code != exitOK || stdout != unmanaged || !strings.Contains(stderr, "this is the local, undamped evaluation") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			// The client gives up after 1 s; the local evaluation is bounded
			// by 2 s more.
			if c.hung && (elapsed < time.Second || elapsed > 3500*time.Millisecond) {
				t.Fatalf("a hung daemon took %v; want between 1 s and 3.5 s", elapsed)
			}
		})
	}

	dead := deadSteerAddr(t)
	until := time.Now().Add(30 * time.Second).Truncate(time.Second).UTC()
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, state string)
		vip   string
		want  int
		line  string
		note  string
	}{
		{
			name:  "no state.json: a new node starts drained",
			setup: func(*testing.T, string) {},
			want:  exitSteerDrain, line: "192.0.2.10 drain new_node source=local\n",
		},
		{
			name: "the new-node drain",
			setup: func(t *testing.T, state string) {
				if _, err := steer.NewStore(state).Birth(time.Now()); err != nil {
					t.Fatal(err)
				}
			},
			want: exitSteerDrain, line: "192.0.2.10 drain new_node source=local\n",
		},
		{
			name: "the operator's drain",
			setup: func(t *testing.T, state string) {
				if err := seedSteerState(t, state, nil).SetDrain("192.0.2.10", steer.Drain{Reason: "maintenance", Since: time.Now()}); err != nil {
					t.Fatal(err)
				}
			},
			want: exitSteerDrain, line: "192.0.2.10 drain drained source=local\n",
		},
		{
			name:  "an address the kernel does not hold",
			setup: func(t *testing.T, state string) { seedSteerState(t, state, nil) },
			vip:   "192.0.2.11",
			want:  exitSteerWithdraw, line: "192.0.2.11 withdraw unbound warning=generation_not_live source=local\n",
		},
		{
			name: "a saved hold-down still running",
			setup: func(t *testing.T, state string) {
				seedSteerState(t, state, map[string]steer.Saved{"192.0.2.10": {Level: 1, Until: until}})
			},
			want: exitSteerWithdraw,
			line: "192.0.2.10 withdraw hold_down warning=generation_not_live rejoin_at=" + steerTime(until) + " source=local\n",
			note: "withdraw because the hold-down kapkan edge saved runs until " + steerTime(until) + "; kapkan edge itself, damping, might hold the address instead",
		},
		{
			name:  "otherwise: announce, unmanaged",
			setup: func(t *testing.T, state string) { seedSteerState(t, state, nil) },
			want:  exitOK, line: unmanaged,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			state := t.TempDir()
			c.setup(t, state)
			vip := "192.0.2.10"
			if c.vip != "" {
				vip = c.vip
			}
			code, stdout, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, dead, state), "-steer", "-vip", vip)
			if code != c.want || stdout != c.line || !strings.Contains(stderr, c.note) {
				t.Fatalf("code=%d stdout=%q stderr=%q; want %d %q with %q", code, stdout, stderr, c.want, c.line, c.note)
			}
		})
	}

	// A drain this user cannot see is no drain to the local
	// evaluation — it answers announce — so -steer says so on stderr and names
	// the directory to open.
	t.Run("drain files this user cannot read", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every mode")
		}
		state := t.TempDir()
		store := seedSteerState(t, state, nil)
		if err := store.SetDrain(steer.NodeKey, steer.Drain{Since: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(store.Dir, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(store.Dir, 0o755) })
		code, stdout, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, dead, state), "-steer", "-vip", "192.0.2.10")
		want := "kapkan edge -steer: warning: the drain files could not be read ("
		if code != exitOK || stdout != unmanaged || !strings.Contains(stderr, want) ||
			!strings.Contains(stderr, "answering as if no drain stood; give this user read and search access to "+store.Dir+"\n") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})

	// The interface listing waits on RTNL whatever ctx says: -steer answers
	// from the drain files and the saved hold-down once its bound passes.
	for _, drained := range []bool{false, true} {
		t.Run(fmt.Sprintf("RTNL held, drained %v", drained), func(t *testing.T) {
			block := make(chan struct{})
			proc := steerProc(nil)
			proc.Ifaddrs4 = func() ([]netip.Addr, error) {
				<-block
				return nil, nil
			}
			withSteerSeams(t, proc)
			t.Cleanup(func() { close(block) })
			state := t.TempDir()
			store := seedSteerState(t, state, nil)
			want, line := exitOK, unmanaged
			if drained {
				if err := store.SetDrain(steer.NodeKey, steer.Drain{Since: time.Now()}); err != nil {
					t.Fatal(err)
				}
				want, line = exitSteerDrain, "192.0.2.10 drain drained source=local\n"
			}
			start := time.Now()
			code, stdout, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, dead, state), "-steer", "-vip", "192.0.2.10")
			if elapsed := time.Since(start); elapsed > 3500*time.Millisecond {
				t.Fatalf("-steer waited %v on a kernel that does not answer", elapsed)
			}
			if code != want || stdout != line || !strings.Contains(stderr, "the kernel did not answer within 2s (the interface listing waits on RTNL)") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// TestEdgeSteerWildcardStatusListen pins steerDaemonAddr through -steer: a
// wildcard status_listen is dialled on loopback, of its own family.
func TestEdgeSteerWildcardStatusListen(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	state := t.TempDir()
	seedSteerState(t, state, nil)
	announce := steerBody(t, node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateAnnounce, Reason: steer.ReasonOK})
	d := newFakeSteerd(t)
	d.answer(200, announce)
	_, port, err := net.SplitHostPort(d.addr())
	if err != nil {
		t.Fatal(err)
	}
	for _, listen := range []string{":" + port, "0.0.0.0:" + port} {
		code, stdout, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, listen, state), "-steer", "-vip", "192.0.2.10")
		if code != exitOK || stdout != "192.0.2.10 announce ok source=daemon\n" {
			t.Fatalf("status_listen %q: code=%d stdout=%q stderr=%q", listen, code, stdout, stderr)
		}
	}

	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	d6 := &fakeSteerd{steerCode: 200, steerBody: announce}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(d6.serve)}}
	srv.Start()
	t.Cleanup(srv.Close)
	_, port6, _ := net.SplitHostPort(ln.Addr().String())
	code, stdout, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, "[::]:"+port6, state), "-steer", "-vip", "192.0.2.10")
	if code != exitOK || stdout != "192.0.2.10 announce ok source=daemon\n" || len(d6.requests()) != 1 {
		t.Fatalf("status_listen [::]:%s: code=%d stdout=%q stderr=%q requests=%q", port6, code, stdout, stderr, d6.requests())
	}

	for _, c := range []struct{ listen, want string }{
		{":9102", "127.0.0.1:9102"},
		{"0.0.0.0:9102", "127.0.0.1:9102"},
		{"[::]:9102", "[::1]:9102"},
		{"127.0.0.1:9102", "127.0.0.1:9102"},
		{"[2001:db8::1]:9102", "[2001:db8::1]:9102"},
		{"localhost:9102", "localhost:9102"},
	} {
		if got, err := steerDaemonAddr(c.listen); err != nil || got != c.want {
			t.Errorf("steerDaemonAddr(%q) = %q, %v; want %q", c.listen, got, err, c.want)
		}
	}
}

// TestEdgeSteerUsageAndHold pins -steer's usage errors (2), its own holds
// (102), help beside -steer (2: 0 is announce), the flags' usage rules, and a
// broken edge.yaml, which asks the running daemon and never evaluates
// locally.
func TestEdgeSteerUsageAndHold(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	d := newFakeSteerd(t)
	d.answer(200, steerBody(t, node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateAnnounce, Reason: steer.ReasonOK}))
	state := t.TempDir()
	seedSteerState(t, state, nil)
	cfg := steerYAML(t, d.addr(), state)
	off := steerYAMLOff(t, d.addr(), state)
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	long := strings.Repeat("x", 257)
	for _, c := range []struct {
		name   string
		args   []string
		want   int
		stdout string
		stderr string
	}{
		{"no -vip while VIPs are configured", []string{"-config", cfg, "-steer"}, exitUsage, "", "-steer needs -vip"},
		{"a VIP outside the list", []string{"-config", cfg, "-steer", "-vip", "192.0.2.99"}, exitSteerHold, "192.0.2.99 hold not_steered source=none\n", "not in steering.vips"},
		{"-vip that is no address", []string{"-config", cfg, "-steer", "-vip", "x"}, exitSteerHold, "\"x\" hold not_steered source=none\n", "not in steering.vips"},
		{"an empty -vip is given, and not steered", []string{"-config", cfg, "-steer", "-vip", ""}, exitSteerHold, "\"\" hold not_steered source=none\n", ""},
		{"-steer with -s", []string{"-config", cfg, "-steer", "-vip", "192.0.2.10", "-s", "drain"}, exitUsage, "", "give one of them"},
		{"-check with -steer", []string{"-config", cfg, "-check", "-steer"}, exitUsage, "", "give one of them"},
		{"-vip alone", []string{"-config", cfg, "-vip", "192.0.2.10"}, exitUsage, "", "-vip applies only with -steer or -s"},
		{"a stray argument", []string{"-config", cfg, "-steer", "-vip", "192.0.2.10", "extra"}, exitUsage, "", "unexpected argument"},
		{"a missing config", []string{"-config", missing, "-steer", "-vip", "192.0.2.10"}, exitError, "", "read edge config"},
		{"-h after -steer", []string{"-config", cfg, "-steer", "-vip", "192.0.2.10", "-h"}, exitUsage, "", "Usage:"},
		{"-h before -steer", []string{"-h", "-steer"}, exitUsage, "", "Usage:"},
		{"-h before --steer=true", []string{"-h", "--steer=true"}, exitUsage, "", "Usage:"},
		{"-h alone", []string{"-h"}, exitOK, "", "Usage:"},
		{"-s with an unknown action", []string{"-config", cfg, "-s", "drian"}, exitUsage, "", `-s "drian" is not drain, undrain or reset-holddown`},
		{"-reason new_node", []string{"-config", cfg, "-s", "drain", "-reason", "new_node"}, exitUsage, "", "-reason new_node is reserved for the first entry"},
		{"-reason with undrain", []string{"-config", cfg, "-s", "undrain", "-reason", "x"}, exitUsage, "", "-reason applies only with -s drain"},
		{"-reason too long", []string{"-config", cfg, "-s", "drain", "-reason", long}, exitUsage, "", "-reason is 257 bytes; at most 256"},
		{"-wait with -steer", []string{"-config", cfg, "-steer", "-vip", "192.0.2.10", "-wait"}, exitUsage, "", "-wait applies only with -s drain or -s undrain"},
		{"-consumer without -steer or -wait", []string{"-config", cfg, "-s", "drain", "-consumer", "x"}, exitUsage, "", "-consumer applies only with -steer or -wait"},
		{"-consumer anonymous", []string{"-config", cfg, "-steer", "-vip", "192.0.2.10", "-consumer", "anonymous"}, exitUsage, "", "reserved"},
		{"-consumer invalid", []string{"-config", cfg, "-s", "drain", "-wait", "-consumer", "invalid"}, exitUsage, "", "reserved"},
		{"-consumer 'a b'", []string{"-config", cfg, "-steer", "-vip", "192.0.2.10", "-consumer", "a b"}, exitUsage, "", "is not a reader name"},
		{"-force with -vip", []string{"-config", cfg, "-s", "undrain", "-vip", "192.0.2.10", "-force"}, exitUsage, "", "-force applies only with -s undrain"},
		{"-force with drain", []string{"-config", cfg, "-s", "drain", "-force"}, exitUsage, "", "-force applies only with -s undrain"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runEdgeCLIOut(t, c.args...)
			if code != c.want || stdout != c.stdout || !strings.Contains(stderr, c.stderr) {
				t.Fatalf("code=%d stdout=%q stderr=%q; want %d %q with %q", code, stdout, stderr, c.want, c.stdout, c.stderr)
			}
		})
	}

	t.Run("steering off holds and asks nobody", func(t *testing.T) {
		n := len(d.requests())
		code, stdout, stderr := runEdgeCLIOut(t, "-config", off, "-steer", "-vip", "192.0.2.10")
		if code != exitSteerHold || stdout != "192.0.2.10 hold steering_off source=none\n" {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if got := d.requests()[n:]; len(got) != 0 {
			t.Fatalf("steering off still asked the daemon: %q", got)
		}
	})

	// A config push that broke edge.yaml everywhere must not read as down on
	// every binary checker while every daemon still serves.
	t.Run("a broken edge.yaml asks the running daemon", func(t *testing.T) {
		broken := writeEdgeYAML(t, steerYAMLBody(d.addr(), state)+"no_such_key: 1\n")
		code, stdout, stderr := runEdgeCLIOut(t, "-config", broken, "-steer", "-vip", "192.0.2.10")
		if code != exitOK || stdout != "192.0.2.10 announce ok source=daemon\n" ||
			!strings.Contains(stderr, "edge.yaml does not load") || !strings.Contains(stderr, "no_such_key") {
			t.Fatalf("200: code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		d.answer(503, steerBody(t, node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateDrain, Reason: steer.ReasonDrained}))
		defer d.answer(200, steerBody(t, node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateAnnounce, Reason: steer.ReasonOK}))
		if code, stdout, stderr := runEdgeCLIOut(t, "-config", broken, "-steer", "-vip", "192.0.2.10"); code != exitSteerDrain || stdout != "192.0.2.10 drain drained source=daemon\n" {
			t.Fatalf("503 drain: code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		d.answer(http.StatusTooEarly, steerBody(t, node.SteerAnswer{Target: "192.0.2.10", Reason: steer.ReasonStale}))
		if code, stdout, stderr := runEdgeCLIOut(t, "-config", broken, "-steer", "-vip", "192.0.2.10"); code != exitError || stdout != "" {
			t.Fatalf("425 from a broken config: code=%d stdout=%q stderr=%q; want 1 and no evaluation", code, stdout, stderr)
		}
		gone := writeEdgeYAML(t, steerYAMLBody(deadSteerAddr(t), state)+"no_such_key: 1\n")
		if code, stdout, stderr := runEdgeCLIOut(t, "-config", gone, "-steer", "-vip", "192.0.2.10"); code != exitError || stdout != "" || !strings.Contains(stderr, "no local evaluation") {
			t.Fatalf("no daemon: code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		n := len(d.requests())
		garbled := writeEdgeYAML(t, "status_listen: "+d.addr()+"\nsteering: [unclosed\n")
		if code, stdout, stderr := runEdgeCLIOut(t, "-config", garbled, "-steer", "-vip", "192.0.2.10"); code != exitError || stdout != "" {
			t.Fatalf("a file that does not parse: code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if got := d.requests()[n:]; len(got) != 0 {
			t.Fatalf("a file that does not parse still asked the daemon: %q", got)
		}
	})
}

// TestEdgeSteerPanicExitsTwo pins a panic's exit code through the whole production path —
// main, runSubcommand, runEdgeCommand, runSteer — in a child process: a panic
// on it exits 2, which every consumer reads as hold. A recover added
// anywhere on it fails this test.
func TestEdgeSteerPanicExitsTwo(t *testing.T) {
	state := t.TempDir()
	seedSteerState(t, state, nil)
	cfg := steerYAML(t, deadSteerAddr(t), state)
	cmd := exec.Command(os.Args[0], "-test.run=^TestEdgeSteerPanicHelper$")
	cmd.Env = append(os.Environ(), "KAPKAN_STEER_PANIC_HELPER=1", "KAPKAN_STEER_PANIC_CONFIG="+cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != exitUsage {
		t.Fatalf("a panic on -steer's path exited %v; want 2\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "panic: injected") || !strings.Contains(stderr.String(), "goroutine ") {
		t.Fatalf("no panic and trace on stderr:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "source=") {
		t.Fatalf("a verdict line was printed before the panic:\n%s", stdout.String())
	}
}

// TestEdgeSteerPanicHelper is TestEdgeSteerPanicExitsTwo's child: it runs
// main() itself with a clock that panics.
func TestEdgeSteerPanicHelper(t *testing.T) {
	if os.Getenv("KAPKAN_STEER_PANIC_HELPER") != "1" {
		t.Skip("the child process of TestEdgeSteerPanicExitsTwo")
	}
	edgeSteerNow = func() time.Time { panic("injected") }
	os.Args = []string{"kapkan", "edge", "-config", os.Getenv("KAPKAN_STEER_PANIC_CONFIG"), "-steer", "-vip", "192.0.2.10"}
	main()
	t.Fatal("main returned")
}

// TestEdgeSignalDrainUndrain pins -s drain and -s undrain without -wait:
// the drain files are written without a daemon, the first entry is
// told apart from the operator's node-wide drain, and state.json is never
// written.
func TestEdgeSignalDrainUndrain(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	d := newFakeSteerd(t)
	state := t.TempDir()
	store := seedSteerState(t, state, map[string]steer.Saved{"192.0.2.10": {Level: 2}})
	stateJSON := filepath.Join(store.Dir, "state.json")
	before, err := os.ReadFile(stateJSON)
	if err != nil {
		t.Fatal(err)
	}
	cfg := steerYAML(t, d.addr(), state)
	run := func(t *testing.T, want int, wantErr string, args ...string) {
		t.Helper()
		code, stdout, stderr := runEdgeCLIOut(t, append([]string{"-config", cfg}, args...)...)
		if code != want || stdout != "" || !strings.Contains(stderr, wantErr) {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q; want %d with %q", args, code, stdout, stderr, want, wantErr)
		}
	}
	exists := func(name string) bool {
		_, err := os.Lstat(filepath.Join(store.Dir, name))
		return err == nil
	}

	run(t, exitOK, `kapkan edge: drained node (reason "kernel upgrade")`, "-s", "drain", "-reason", "kernel upgrade")
	raw, err := os.ReadFile(filepath.Join(store.Dir, "drain"))
	if err != nil {
		t.Fatal(err)
	}
	var dr steer.Drain
	if err := json.Unmarshal(raw, &dr); err != nil || dr.Reason != "kernel upgrade" || dr.Since.IsZero() {
		t.Fatalf("the drain file: %s (%v)", raw, err)
	}
	run(t, exitOK, "kapkan edge: drained 192.0.2.10", "-s", "drain", "-vip", "192.0.2.10")
	if !exists("drain.192.0.2.10") {
		t.Fatal("-s drain -vip wrote no drain.192.0.2.10")
	}
	// The VIP's own drain lifts, and the node-wide one keeps it out.
	run(t, exitError, "kapkan edge: 192.0.2.10 stays drained: the node-wide drain stands (kapkan edge -s undrain lifts it)", "-s", "undrain", "-vip", "192.0.2.10")
	if exists("drain.192.0.2.10") {
		t.Fatal("-s undrain -vip left drain.192.0.2.10")
	}
	run(t, exitOK, "", "-s", "drain", "-vip", "::ffff:192.0.2.11")
	run(t, exitOK, "kapkan edge: undrained node; still drained one by one: 192.0.2.11", "-s", "undrain")
	run(t, exitOK, "kapkan edge: undrained 192.0.2.11", "-s", "undrain", "-vip", "192.0.2.11")
	run(t, exitError, "kapkan edge: 192.0.2.99 is not in steering.vips", "-s", "drain", "-vip", "192.0.2.99")

	// A hand-written node drain that says new_node is still the operator's:
	// no marker stands behind it.
	if err := os.WriteFile(filepath.Join(store.Dir, "drain"), []byte(`{"reason":"new_node"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, exitError, "192.0.2.10 stays drained: the node-wide drain stands", "-s", "undrain", "-vip", "192.0.2.10")
	run(t, exitOK, "kapkan edge: undrained node", "-s", "undrain")
	if after, _ := os.ReadFile(stateJSON); !bytes.Equal(after, before) {
		t.Fatalf("state.json changed:\n%s\nwas\n%s", after, before)
	}

	// The first entry: a new node's undrain names its progress, as the
	// daemon reports it, and lifts it only with -force.
	t.Run("first entry", func(t *testing.T) {
		state := t.TempDir()
		store := steer.NewStore(state)
		if _, err := store.Birth(time.Now()); err != nil {
			t.Fatal(err)
		}
		stateJSON := filepath.Join(store.Dir, "state.json")
		born, err := os.ReadFile(stateJSON)
		if err != nil {
			t.Fatal(err)
		}
		cfg := steerYAML(t, d.addr(), state)
		undrain := func(t *testing.T, args ...string) (int, string) {
			t.Helper()
			code, stdout, stderr := runEdgeCLIOut(t, append([]string{"-config", cfg, "-s", "undrain"}, args...)...)
			if stdout != "" {
				t.Fatalf("stdout %q", stdout)
			}
			return code, stderr
		}
		entry := func(code, zones, ready int, missing []string, count int) func(int) (int, node.Status) {
			return func(int) (int, node.Status) {
				st := steerStatus()
				st.Healthy = code == http.StatusOK
				st.Steering.FirstEntry = &node.SteerFirstEntry{Pending: steer.TriYes, Zones: zones, Ready: ready, Missing: missing, MissingCount: count}
				return code, st
			}
		}
		const tail = ". It lifts by itself once every zone has one; kapkan edge -s undrain -force lifts it now (the first node of a new address)"
		for _, code := range []int{http.StatusOK, http.StatusServiceUnavailable} {
			d.serveHealth(entry(code, 3, 1, []string{"b.example", "c.example"}, 2))
			got, stderr := undrain(t)
			want := "kapkan edge: node stays drained: its first entry is pending: 1 of 3 zones with a certificate; missing: b.example, c.example" + tail
			if got != exitError || !strings.Contains(stderr, want) {
				t.Fatalf("/healthz %d: code=%d stderr=%q; want 1 with %q", code, got, stderr, want)
			}
		}
		var names []string
		for i := range 10 {
			names = append(names, fmt.Sprintf("z%02d.example", i))
		}
		d.serveHealth(entry(http.StatusOK, 25, 0, names, 25))
		if got, stderr := undrain(t); got != exitError || !strings.Contains(stderr, "z09.example (25 in all)"+tail) {
			t.Fatalf("25 missing: code=%d stderr=%q", got, stderr)
		}
		// A VIP's undrain is refused alike: new_node drains every target.
		if got, stderr := undrain(t, "-vip", "192.0.2.10"); got != exitError || !strings.Contains(stderr, "192.0.2.10 stays drained: its first entry is pending: 0 of 25") {
			t.Fatalf("a VIP under the first entry: code=%d stderr=%q", got, stderr)
		}
		// The daemon's first interval: it reports the first entry unknown and
		// counts nothing yet, which is not "0 of 0".
		d.serveHealth(func(int) (int, node.Status) {
			st := steerStatus()
			st.Steering.FirstEntry = &node.SteerFirstEntry{Pending: steer.TriUnknown}
			return http.StatusOK, st
		})
		if got, stderr := undrain(t); got != exitError || strings.Contains(stderr, "0 of 0") ||
			!strings.Contains(stderr, "its first entry is pending: zones with a certificate: unknown (the running kapkan edge has not counted them yet") {
			t.Fatalf("an unknown first entry: code=%d stderr=%q", got, stderr)
		}
		gone := steerYAML(t, deadSteerAddr(t), state)
		code, stdout, stderr := runEdgeCLIOut(t, "-config", gone, "-s", "undrain")
		if code != exitError || stdout != "" || !strings.Contains(stderr, "its first entry is pending: zones with a certificate: unknown (kapkan edge did not answer: ") {
			t.Fatalf("no daemon: code=%d stderr=%q", code, stderr)
		}
		if got, stderr := undrain(t, "-force"); got != exitOK || !strings.Contains(stderr, "kapkan edge: lifted the new-node drain by hand") || !strings.Contains(stderr, "kapkan edge: undrained node") {
			t.Fatalf("-force: code=%d stderr=%q", got, stderr)
		}
		if _, err := os.Lstat(filepath.Join(store.Dir, "new_node")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("-force left new_node: %v", err)
		}
		if after, _ := os.ReadFile(stateJSON); !bytes.Equal(after, born) {
			t.Fatalf("state.json changed:\n%s\nwas\n%s", after, born)
		}
	})

	t.Run("steering off still writes", func(t *testing.T) {
		state := t.TempDir()
		off := steerYAMLOff(t, d.addr(), state)
		code, _, stderr := runEdgeCLIOut(t, "-config", off, "-s", "drain")
		if code != exitOK || !strings.Contains(stderr, "kapkan edge: warning: steering is off in edge.yaml; this takes effect when it is on") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		if _, err := os.Lstat(filepath.Join(state, "steering", "drain")); err != nil {
			t.Fatalf("no drain file with steering off: %v", err)
		}
		code, _, stderr = runEdgeCLIOut(t, "-config", off, "-s", "undrain")
		if code != exitOK || !strings.Contains(stderr, "steering is off in edge.yaml") {
			t.Fatalf("undrain: code=%d stderr=%q", code, stderr)
		}
		if _, err := os.Lstat(filepath.Join(state, "steering", "state.json")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the CLI wrote state.json: %v", err)
		}
	})
}

// steerReader is a reader of a target's verdict as /healthz reports it.
func steerReader(name string, dry bool, at time.Time, v steer.State, since time.Time) node.SteerReader {
	return node.SteerReader{Consumer: name, Dry: dry, At: at, Verdict: v, Since: since}
}

// TestEdgeSignalWait pins -wait: a read counts only when a named
// reader was served this very episode of the new verdict, decided per
// target — enforced, dry, unread — and a daemon that is not steering, or
// does not steer the target, ends the wait at once.
func TestEdgeSignalWait(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	edgeWaitTimeout, edgeWaitPoll = 2*time.Second, 50*time.Millisecond
	S := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	drainAt := func(readers ...node.SteerReader) node.SteerAnswer {
		return node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateDrain, Reason: steer.ReasonDrained, Since: S, Readers: readers}
	}
	fixed := func(code int, st node.Status) func(int) (int, node.Status) {
		return func(int) (int, node.Status) { return code, st }
	}
	var h3 []string
	for size := 0; size < 100<<10; size += len(h3[len(h3)-1]) + 3 {
		h3 = append(h3, fmt.Sprintf("zone-%06d.example.com", len(h3)))
	}
	big := steerStatus(drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S)))
	big.H3 = &api.EdgeReportH3{State: "ready", Serving: h3}

	type waitCase struct {
		name     string
		health   func(int) (int, node.Status)
		args     []string // after -config
		yaml     func(t *testing.T, listen, state string) string
		drainVIP string // a drain file to stand before the undrain
		want     int
		atOnce   bool // decided before the bound
		minTime  time.Duration
		wantErr  []string
		noErr    []string
		noReqs   bool
	}
	drain := []string{"-s", "drain", "-vip", "192.0.2.10", "-wait"}
	undrain := []string{"-s", "undrain", "-vip", "192.0.2.10", "-wait"}
	cases := []waitCase{
		{
			name:    "a live reader served this drain",
			health:  fixed(200, steerStatus(drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S)))),
			args:    drain,
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"kapkan edge: 192.0.2.10: drain read by bird at 2026-11-13T08:00:01Z"},
		},
		{
			name:    "a read after the change that was served the snapshot before it",
			health:  fixed(200, steerStatus(drainAt(steerReader("bird", false, S.Add(500*time.Millisecond), steer.StateAnnounce, S.Add(-time.Hour))))),
			args:    drain,
			want:    exitError,
			minTime: 2 * time.Second,
			wantErr: []string{"kapkan edge: no consumer read 192.0.2.10's drain within 2s; it is drain (drained); last read: bird at 2026-11-13T08:00:00Z, served announce"},
		},
		{
			// Pins the served verdict alone: the since matches, the verdict
			// does not.
			name:    "a read served another verdict with this since",
			health:  fixed(200, steerStatus(drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateAnnounce, S)))),
			args:    drain,
			want:    exitError,
			minTime: 2 * time.Second,
			wantErr: []string{"no consumer read 192.0.2.10's drain within 2s; it is drain (drained); last read: bird at 2026-11-13T08:00:01Z, served announce"},
		},
		{
			name:    "a drain read in an earlier episode",
			health:  fixed(200, steerStatus(drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S.Add(-time.Minute))))),
			args:    drain,
			want:    exitError,
			minTime: 2 * time.Second,
			wantErr: []string{"no consumer read 192.0.2.10's drain within 2s"},
		},
		{
			name: "unnamed readers are ignored",
			health: fixed(200, steerStatus(drainAt(
				steerReader(steerAnonymous, false, S.Add(time.Second), steer.StateDrain, S),
				steerReader(steerInvalid, false, S.Add(2*time.Second), steer.StateDrain, S)))),
			args:    drain,
			want:    exitError,
			minTime: 2 * time.Second,
			wantErr: []string{"last read: never; ignored unnamed readers: anonymous at 2026-11-13T08:00:01Z, invalid at 2026-11-13T08:00:02Z"},
		},
		{
			name:    "-consumer pins the reader",
			health:  fixed(200, steerStatus(drainAt(steerReader("nagios", false, S.Add(time.Second), steer.StateDrain, S)))),
			args:    append(append([]string(nil), drain...), "-consumer", "bird"),
			want:    exitError,
			minTime: 2 * time.Second,
			wantErr: []string{"last read: never; ignored other readers: nagios at 2026-11-13T08:00:01Z"},
		},
		{
			name: "-consumer's own read",
			health: fixed(200, steerStatus(drainAt(
				steerReader("nagios", false, S.Add(time.Second), steer.StateDrain, S),
				steerReader("bird", false, S.Add(2*time.Second), steer.StateDrain, S)))),
			args:    append(append([]string(nil), drain...), "-consumer", "bird"),
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"192.0.2.10: drain read by bird"},
		},
		{
			name: "every target, one read only by a dry consumer: the bound decides it dry",
			health: fixed(200, steerStatus(
				drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S)),
				node.SteerAnswer{Target: "192.0.2.11", Verdict: steer.StateDrain, Reason: steer.ReasonDrained, Since: S,
					Readers: []node.SteerReader{steerReader("bird-dry", true, S.Add(time.Second), steer.StateDrain, S)}})),
			args:    []string{"-s", "drain", "-wait"},
			want:    exitNotEnforcing,
			minTime: 2 * time.Second,
			wantErr: []string{
				"kapkan edge: 192.0.2.10: drain read by bird at",
				"kapkan edge: 192.0.2.11: drain read only by a consumer in dry mode (bird-dry at 2026-11-13T08:00:01Z): it logs what it would do and changes nothing",
			},
		},
		{
			name: "every target read live",
			health: fixed(200, steerStatus(
				drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S)),
				node.SteerAnswer{Target: "192.0.2.11", Verdict: steer.StateDrain, Reason: steer.ReasonDrained, Since: S,
					Readers: []node.SteerReader{steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S)}})),
			args:    []string{"-s", "drain", "-wait"},
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"192.0.2.10: drain read by bird", "192.0.2.11: drain read by bird"},
		},
		{
			name:    "a 503 /healthz reads as a 200",
			health:  fixed(503, steerStatus(drainAt(steerReader("bird", false, S.Add(time.Second), steer.StateDrain, S)))),
			args:    drain,
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"192.0.2.10: drain read by bird"},
		},
		{
			name:    "a /healthz above 64 KiB",
			health:  fixed(200, big),
			args:    drain,
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"192.0.2.10: drain read by bird"},
		},
		{
			name:    "a daemon without steering",
			health:  fixed(200, node.Status{Healthy: true}),
			args:    drain,
			want:    exitError,
			atOnce:  true,
			wantErr: []string{"the running kapkan edge is not steering"},
		},
		{
			name:    "a daemon with steering off",
			health:  fixed(200, node.Status{Healthy: true, Steering: &node.SteeringStatus{}}),
			args:    drain,
			want:    exitError,
			atOnce:  true,
			wantErr: []string{"the running kapkan edge is not steering"},
		},
		{
			name:    "a daemon that does not steer the target",
			health:  fixed(200, steerStatus(node.SteerAnswer{Target: "192.0.2.11", Verdict: steer.StateDrain})),
			args:    drain,
			want:    exitError,
			atOnce:  true,
			wantErr: []string{"the running kapkan edge does not steer 192.0.2.10 (edge.yaml changed since it started?); restart it"},
		},
		{
			name:    "steering off in edge.yaml",
			yaml:    steerYAMLOff,
			args:    drain,
			want:    exitError,
			atOnce:  true,
			noReqs:  true,
			wantErr: []string{"kapkan edge: -wait: steering is off in edge.yaml"},
		},
		{
			name: "undrain waits through unknown for this announce",
			health: func(poll int) (int, node.Status) {
				if poll <= 3 {
					return 200, steerStatus(node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateUnknown, Reason: steer.ReasonStarting, Since: S,
						Readers: []node.SteerReader{steerReader("bird", false, S.Add(time.Second), steer.StateUnknown, S)}})
				}
				S2 := S.Add(time.Minute)
				return 200, steerStatus(node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateAnnounce, Reason: steer.ReasonOK, Since: S2,
					Readers: []node.SteerReader{steerReader("bird", false, S2.Add(time.Second), steer.StateAnnounce, S2)}})
			},
			args:    undrain,
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"kapkan edge: waiting up to 8s (recover_after 3 × 1s)", "192.0.2.10: announce read by bird at 2026-11-13T08:01:01Z"},
		},
		{
			name:     "a node undrain waits on the targets it lifted",
			drainVIP: "192.0.2.11",
			health: fixed(200, steerStatus(
				node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateAnnounce, Reason: steer.ReasonOK, Since: S,
					Readers: []node.SteerReader{steerReader("bird", false, S.Add(time.Second), steer.StateAnnounce, S)}},
				node.SteerAnswer{Target: "192.0.2.11", Verdict: steer.StateDrain, Reason: steer.ReasonDrained, Since: S})),
			args:    []string{"-s", "undrain", "-wait"},
			want:    exitOK,
			atOnce:  true,
			wantErr: []string{"kapkan edge: undrained node; still drained one by one: 192.0.2.11", "192.0.2.10: announce read by bird"},
			noErr:   []string{"192.0.2.11:"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := newFakeSteerd(t)
			if c.health != nil {
				d.serveHealth(c.health)
			}
			state := t.TempDir()
			store := seedSteerState(t, state, nil)
			if c.drainVIP != "" {
				if err := store.SetDrain(c.drainVIP, steer.Drain{Since: S}); err != nil {
					t.Fatal(err)
				}
			}
			yaml := steerYAML
			if c.yaml != nil {
				yaml = c.yaml
			}
			cfg := yaml(t, d.addr(), state)
			start := time.Now()
			code, stdout, stderr := runEdgeCLIOut(t, append([]string{"-config", cfg}, c.args...)...)
			elapsed := time.Since(start)
			if code != c.want || stdout != "" {
				t.Fatalf("code=%d stdout=%q, want %d; stderr:\n%s", code, stdout, c.want, stderr)
			}
			for _, w := range c.wantErr {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr lacks %q:\n%s", w, stderr)
				}
			}
			for _, w := range c.noErr {
				if strings.Contains(stderr, w) {
					t.Errorf("stderr carries %q:\n%s", w, stderr)
				}
			}
			if c.atOnce && elapsed > 1500*time.Millisecond {
				t.Errorf("took %v; want it decided at once", elapsed)
			}
			if elapsed < c.minTime {
				t.Errorf("took %v; want at least the bound, %v", elapsed, c.minTime)
			}
			if c.noReqs && len(d.requests()) != 0 {
				t.Errorf("asked the daemon: %q", d.requests())
			}
		})
	}

	// An undrain that stays out — withdrawn, with a hold-down running — is
	// reported at a bound that waits for the join and the hold-down too.
	t.Run("an undrain still withdrawn at the bound", func(t *testing.T) {
		t.Parallel()
		d := newFakeSteerd(t)
		rejoin := time.Now().Add(time.Second).Truncate(time.Second).Add(time.Second).UTC()
		d.serveHealth(fixed(200, steerStatus(node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateWithdraw, Reason: steer.ReasonRefused, Since: S, RejoinAt: rejoin,
			Readers: []node.SteerReader{steerReader("bird", false, S.Add(time.Second), steer.StateWithdraw, S)}})))
		state := t.TempDir()
		seedSteerState(t, state, nil)
		start := time.Now()
		code, _, stderr := runEdgeCLIOut(t, append([]string{"-config", steerYAML(t, d.addr(), state)}, undrain...)...)
		elapsed := time.Since(start)
		want := "it is withdraw (refused), rejoin at " + steerTime(rejoin) + "; last read: bird at 2026-11-13T08:00:01Z, served withdraw"
		if code != exitError || !strings.Contains(stderr, "no consumer read 192.0.2.10's announce within") || !strings.Contains(stderr, want) {
			t.Fatalf("code=%d stderr:\n%s\nwant 1 with %q", code, stderr, want)
		}
		if !strings.Contains(stderr, "plus the hold-down until "+steerTime(rejoin)) {
			t.Errorf("the bound does not name the hold-down:\n%s", stderr)
		}
		if elapsed < 8*time.Second || elapsed > 12*time.Second {
			t.Errorf("took %v; want the 8 s bound plus the hold-down's lead", elapsed)
		}
	})

	t.Run("a daemon that never answers", func(t *testing.T) {
		t.Parallel()
		state := t.TempDir()
		seedSteerState(t, state, nil)
		dead := deadSteerAddr(t)
		code, _, stderr := runEdgeCLIOut(t, append([]string{"-config", steerYAML(t, dead, state)}, drain...)...)
		if want := "kapkan edge: kapkan edge did not answer on " + dead + " within 2s; the change is written and takes effect when it runs"; code != exitError || !strings.Contains(stderr, want) {
			t.Fatalf("code=%d stderr:\n%s\nwant 1 with %q", code, stderr, want)
		}
	})
}

// TestEdgeSignalWaitDryGrace pins the dry grace: a target read only by a dry
// consumer is decided dry once a live reader has had StaleAfter (3
// intervals) to appear, before the bound.
func TestEdgeSignalWaitDryGrace(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	edgeWaitTimeout, edgeWaitPoll = 6*time.Second, 50*time.Millisecond
	S := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	d := newFakeSteerd(t)
	d.serveHealth(func(int) (int, node.Status) {
		return 200, steerStatus(node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateDrain, Reason: steer.ReasonDrained, Since: S,
			Readers: []node.SteerReader{steerReader("bird", true, S.Add(time.Second), steer.StateDrain, S)}})
	})
	state := t.TempDir()
	seedSteerState(t, state, nil)
	start := time.Now()
	code, _, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, d.addr(), state), "-s", "drain", "-vip", "192.0.2.10", "-wait")
	elapsed := time.Since(start)
	if code != exitNotEnforcing || !strings.Contains(stderr, "192.0.2.10: drain read only by a consumer in dry mode (bird at 2026-11-13T08:00:01Z)") {
		t.Fatalf("code=%d stderr:\n%s", code, stderr)
	}
	if elapsed < 3*time.Second || elapsed > 5*time.Second {
		t.Fatalf("decided after %v; want the 3 s grace, before the 6 s bound", elapsed)
	}
}

// TestEdgeSignalResetHoldDown pins -s reset-holddown: a request file
// the daemon takes by renaming it, and that the command withdraws when
// nobody does — it takes effect now or not at all.
func TestEdgeSignalResetHoldDown(t *testing.T) {
	withSteerSeams(t, steerProc(nil))
	d := newFakeSteerd(t)

	for _, vip := range []string{"", "192.0.2.10"} {
		t.Run("taken, vip "+vip, func(t *testing.T) {
			state := t.TempDir()
			store := seedSteerState(t, state, nil)
			path := filepath.Join(store.Dir, node.ResetRequestFile)
			took := make(chan node.ResetRequest, 1)
			go func() {
				// The daemon's take: a rename, a read, then the removal.
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := os.Lstat(path); err == nil {
						time.Sleep(300 * time.Millisecond)
						var req node.ResetRequest
						if err := os.Rename(path, path+".taken"); err == nil {
							raw, _ := os.ReadFile(path + ".taken")
							_ = json.Unmarshal(raw, &req)
							_ = os.Remove(path + ".taken")
						}
						took <- req
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				close(took)
			}()
			args := []string{"-config", steerYAML(t, d.addr(), state), "-s", "reset-holddown"}
			what := "every target"
			if vip != "" {
				args, what = append(args, "-vip", vip), vip
			}
			code, _, stderr := runEdgeCLIOut(t, args...)
			if code != exitOK || !strings.Contains(stderr, "kapkan edge: kapkan edge took the hold-down reset for "+what) {
				t.Fatalf("code=%d stderr=%q", code, stderr)
			}
			req, ok := <-took
			if !ok || req.At.IsZero() || (vip == "" && (!req.All || req.Keys != nil)) || (vip != "" && (req.All || !slices.Equal(req.Keys, []string{vip}))) {
				t.Fatalf("the request: %+v (taken %v)", req, ok)
			}
		})
	}

	t.Run("nobody takes it", func(t *testing.T) {
		state := t.TempDir()
		store := seedSteerState(t, state, nil)
		start := time.Now()
		code, _, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, d.addr(), state), "-s", "reset-holddown")
		if code != exitError || !strings.Contains(stderr, "kapkan edge: kapkan edge did not take the request within 4s (is it running, with steering on?); nothing was reset") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		if elapsed := time.Since(start); elapsed < 4*time.Second {
			t.Fatalf("gave up after %v; want 3 intervals and a second", elapsed)
		}
		if _, err := os.Lstat(filepath.Join(store.Dir, node.ResetRequestFile)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a request nobody took was left behind: %v", err)
		}
	})

	t.Run("no state.json", func(t *testing.T) {
		state := t.TempDir()
		code, _, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, d.addr(), state), "-s", "reset-holddown")
		if code != exitOK || !strings.Contains(stderr, "kapkan edge: nothing to reset: "+filepath.Join(state, "steering")+" has no state.json") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		if _, err := os.Lstat(filepath.Join(state, "steering")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("reset-holddown created the steering directory: %v", err)
		}
	})

	t.Run("steering off", func(t *testing.T) {
		state := t.TempDir()
		seedSteerState(t, state, nil)
		code, _, stderr := runEdgeCLIOut(t, "-config", steerYAMLOff(t, d.addr(), state), "-s", "reset-holddown")
		if code != exitOK || !strings.Contains(stderr, "kapkan edge: nothing to reset: steering is off") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})

	t.Run("-wait", func(t *testing.T) {
		code, _, stderr := runEdgeCLIOut(t, "-config", steerYAML(t, d.addr(), t.TempDir()), "-s", "reset-holddown", "-wait")
		if code != exitUsage || !strings.Contains(stderr, "-wait applies only with -s drain or -s undrain") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
}

// slowFS serves net/fib_trie one line per 100 ms, as a kernel walking a full
// table does: every read() waits. It has Open alone, so no fs helper reads
// the file around it.
type slowFS struct{ m fstest.MapFS }

func (s slowFS) Open(name string) (fs.File, error) {
	f, err := s.m.Open(name)
	if err != nil || name != "net/fib_trie" {
		return f, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return &slowFile{info: info, rest: raw}, nil
}

type slowFile struct {
	info fs.FileInfo
	rest []byte
}

func (f *slowFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *slowFile) Close() error               { return nil }
func (f *slowFile) Read(b []byte) (int, error) {
	if len(f.rest) == 0 {
		return 0, io.EOF
	}
	time.Sleep(100 * time.Millisecond)
	n := bytes.IndexByte(f.rest, '\n') + 1
	if n <= 0 {
		n = len(f.rest)
	}
	n = copy(b, f.rest[:n])
	f.rest = f.rest[n:]
	return n, nil
}

// TestEdgeCheckSteering pins -check's steering lines: the
// configuration, the live evaluation beside the daemon's view, and what on
// this box keeps a verdict from meaning what it should.
func TestEdgeCheckSteering(t *testing.T) {
	t.Setenv("KAPKAN_TEST_EDGE_TOKEN", "")
	withSteerSeams(t, steerProc(fstest.MapFS{"sys/net/ipv4/ip_nonlocal_bind": {Data: []byte("1\n")}}))
	S := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	d := newFakeSteerd(t)
	d.serveHealth(func(int) (int, node.Status) {
		return 200, steerStatus(
			node.SteerAnswer{Target: "192.0.2.10", Verdict: steer.StateAnnounce, Reason: steer.ReasonOK, Since: S},
			node.SteerAnswer{Target: "192.0.2.11", Verdict: steer.StateWithdraw, Reason: steer.ReasonUnbound, Since: S})
	})
	check := func(t *testing.T, cfg string, want int, wants, unwanted []string) string {
		t.Helper()
		n := len(d.requests())
		code, msg := runEdgeCLI(t, "-config", cfg, "-check")
		if code != want {
			t.Fatalf("-check: code=%d, want %d:\n%s", code, want, msg)
		}
		for _, w := range wants {
			if !strings.Contains(msg, w) {
				t.Errorf("-check lacks %q:\n%s", w, msg)
			}
		}
		for _, u := range unwanted {
			if strings.Contains(msg, u) {
				t.Errorf("-check carries %q:\n%s", u, msg)
			}
		}
		for _, r := range d.requests()[n:] {
			if !strings.HasPrefix(r, "GET /healthz") {
				t.Errorf("-check made %q: it reads /healthz alone, and stamps no reader", r)
			}
		}
		return msg
	}

	state := t.TempDir()
	store := seedSteerState(t, state, map[string]steer.Saved{"192.0.2.10": {Level: 1}})
	cfg := steerYAML(t, d.addr(), state)
	check(t, cfg, exitOK, []string{
		"note: steering: on, every 1s: withdraw on 3 hard samples of the last 5, announce after 3 ok in a row, hold-down 10s doubling to 60s; targets: 192.0.2.10, 192.0.2.11",
		"note: steering 192.0.2.10: would announce now (unmanaged), warning generation_not_live; kapkan edge says announce (ok) since 2026-11-13T08:00:00Z; hold-down level 1 (the next flap holds it out 20s)",
		"note: steering 192.0.2.11: would withdraw now (unbound), warning generation_not_live; kapkan edge says withdraw (unbound) since 2026-11-13T08:00:00Z",
		"warning: steering 192.0.2.11: this box's kernel does not hold the address now: kapkan edge would withdraw it (unbound)",
		"warning: steering 192.0.2.10: not an interface address (an AnyIP route, or not held): each tick reads /proc/net/fib_trie for it",
		"warning: steering: net.ipv4.ip_nonlocal_bind is 1: bind() accepts addresses this box does not hold",
		"is valid (node edge-1",
	}, []string{
		"takes longer than kapkan edge's tick allows",
		"steering 192.0.2.11: not an interface address",
		"net.ipv6.ip_nonlocal_bind",
		"has no state.json",
		"cannot read",
		"acme.disabled",
	})
	if _, err := os.Lstat(filepath.Join(store.Dir, "drain")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("-check wrote into the steering directory: %v", err)
	}

	t.Run("the node itself, no daemon", func(t *testing.T) {
		state := t.TempDir()
		body := strings.Replace(steerYAMLBody(deadSteerAddr(t), state), "  vips: [192.0.2.10, 192.0.2.11]\n", "", 1) + "disable_ipv6: true\n"
		check(t, writeEdgeYAML(t, body), exitOK, []string{
			"targets: the node itself (127.0.0.1)",
			"has no state.json: kapkan edge will start this node drained (new_node) until every zone answers TLS with its own certificate; the first node of a new address joins with kapkan edge -s undrain -force",
			"note: steering node: would drain now (new_node); kapkan edge did not answer (",
			"kapkan edge -steer answers this evaluation",
		}, []string{"not an interface address"})
	})

	t.Run("acme.disabled", func(t *testing.T) {
		check(t, writeEdgeYAML(t, steerYAMLBody(d.addr(), state)+"acme:\n  disabled: true\n"), exitOK, []string{
			"warning: steering: acme.disabled is true: no zone gets a certificate, so this node's first entry never completes by itself",
		}, nil)
	})

	t.Run("steering off", func(t *testing.T) {
		check(t, steerYAMLOff(t, d.addr(), state), exitOK, []string{
			"note: steering: off (steering.enabled is false): this node testifies nothing; GET /steer answers 404",
		}, []string{"steering: on", "steering 192.0.2.10"})
	})

	t.Run("omit_catch_all with steering", func(t *testing.T) {
		code, msg := runEdgeCLI(t, "-config", writeEdgeYAML(t, steerYAMLBody(d.addr(), state)+"omit_catch_all: true\n"), "-check")
		if code != exitError || !strings.Contains(msg, "steering.enabled refuses omit_catch_all: true in this release") {
			t.Fatalf("code=%d msg=%q", code, msg)
		}
	})

	t.Run("a steering path that is no directory", func(t *testing.T) {
		state := t.TempDir()
		if err := os.WriteFile(filepath.Join(state, "steering"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		check(t, steerYAML(t, d.addr(), state), exitError, []string{
			"kapkan edge: steering: " + filepath.Join(state, "steering") + " is not a directory: kapkan edge can keep no state there, and every drain reads unknown",
		}, []string{"cannot read"})
	})

	t.Run("drain files this user cannot read", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every mode")
		}
		for _, mode := range []fs.FileMode{0o644, 0o000} {
			state := t.TempDir()
			store := seedSteerState(t, state, nil)
			if err := os.Chmod(store.Dir, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(store.Dir, 0o755) })
			check(t, steerYAML(t, d.addr(), state), exitOK, []string{
				"warning: steering: this user cannot read or search the drain files in " + store.Dir + " for node, 192.0.2.10, 192.0.2.11 (",
				"without the daemon, kapkan edge -steer answers announce whatever drain stands",
			}, nil)
		}
		state := t.TempDir()
		store := seedSteerState(t, state, nil)
		if err := os.Chmod(filepath.Join(store.Dir, "state.json"), 0o000); err != nil {
			t.Fatal(err)
		}
		check(t, steerYAML(t, d.addr(), state), exitOK, []string{
			"warning: steering: this user cannot read " + store.Dir + "/state.json (",
			"without the daemon, kapkan edge -steer answers without the saved hold-down",
		}, []string{"cannot read or search the drain files"})
	})

	// A box carrying a full table: one reading of fib_trie outlasts both
	// -check's deadline and the daemon's tick.
	t.Run("a route table slower than the tick", func(t *testing.T) {
		withSteerSeams(t, steer.Proc{FS: slowFS{m: fstest.MapFS{"net/fib_trie": {Data: []byte(steerFibTrie)}}}})
		edgeCheckTimeout = time.Second
		state := t.TempDir()
		seedSteerState(t, state, nil)
		msg := check(t, steerYAML(t, deadSteerAddr(t), state), exitOK, []string{
			"warning: steering 192.0.2.10: whether this box holds the address could not be read within 1s; kapkan edge's tick allows 900ms, so on this box the daemon will hold this address unknown (never announce, never withdraw) for as long as it is not an interface address",
			"warning: steering 192.0.2.10: not an interface address",
			"warning: steering: one reading of /proc/net/fib_trie takes longer than kapkan edge's tick allows (900ms)",
		}, []string{"/proc/net/ipv6_route takes longer"})
		if n := strings.Count(msg, "takes longer than kapkan edge's tick allows"); n != 1 {
			t.Fatalf("the slow table is named %d times, want once:\n%s", n, msg)
		}
	})
}

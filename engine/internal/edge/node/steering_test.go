package node

// The steering tests (E7.2) run a whole node — brain, render,
// apply, the status listener — with steering on, against a /proc of fixtures
// and a TLS listener of their own on 127.0.0.1, so the announce, withdraw,
// drain and hold paths run on any OS; a few tick a node's sampler by hand.
//
// The metrics they move are the process's. The tests that read one
// (TestSteerReaders, TestSteerOffStartsNothing, TestSteerMetrics,
// TestSteerCountersStartAtZero) stay sequential and assert deltas; every
// other test that runs a node or ticks a sampler calls t.Parallel, and reads
// no metric. Go starts the parallel tests only once every sequential test has
// finished, so no other node moves a series while one is measured. A new
// metric assertion belongs in a sequential test.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// steerVIP is the harness's one VIP: loopback, which edge.yaml refuses and
// New does not, so the probe has an address this box certainly holds.
const steerVIP = "127.0.0.1"

// steerCert is a self-signed ECDSA leaf that names name.
func steerCert(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// steerTLS is the harness's :443: a TLS listener on 127.0.0.1 that serves a
// certificate for a switchable name whatever the ClientHello asks, handshakes
// every connection and closes it. The probe's ClientHello gets a ServerHello
// (0x16): ok. It can be closed (the probe is then refused) and reopened on
// the same port.
type steerTLS struct {
	port  uint16 // set by the first listen, before anything else reads it
	mu    sync.Mutex
	ln    net.Listener
	name  string
	certs map[string]*tls.Certificate
}

func newSteerTLS(t *testing.T) *steerTLS {
	t.Helper()
	l := &steerTLS{certs: map[string]*tls.Certificate{}}
	l.setName(t, "example.com")
	if err := l.listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.close)
	return l
}

// setName makes the listener serve a certificate for name from now on.
func (l *steerTLS) setName(t *testing.T, name string) {
	t.Helper()
	cert := steerCert(t, name)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.certs[name] == nil {
		l.certs[name] = cert
	}
	l.name = name
}

func (l *steerTLS) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.certs[l.name], nil
}

func (l *steerTLS) setListener(ln net.Listener) net.Listener {
	l.mu.Lock()
	defer l.mu.Unlock()
	old := l.ln
	l.ln = ln
	return old
}

func (l *steerTLS) listen(addr string) error {
	ln, err := tls.Listen("tcp", addr, &tls.Config{GetCertificate: l.getCertificate})
	if err != nil {
		return err
	}
	if l.port == 0 {
		l.port = uint16(ln.Addr().(*net.TCPAddr).Port)
	}
	l.setListener(ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	return nil
}

// close stops listening: the probe's connect is then refused.
func (l *steerTLS) close() {
	if ln := l.setListener(nil); ln != nil {
		_ = ln.Close()
	}
}

// reopen listens again on the same port.
func (l *steerTLS) reopen() error {
	return l.listen(fmt.Sprintf("127.0.0.1:%d", l.port))
}

// steerIfaddrs is the harness's interface list: 127.0.0.1 — or, switched, a
// call that blocks until released, or one that panics. It counts its calls,
// and the calls that returned.
type steerIfaddrs struct {
	calls, returned atomic.Int64
	mu              sync.Mutex
	mode            int
	release         chan struct{}
}

const (
	ifaddrsList = iota
	ifaddrsBlock
	ifaddrsPanic
)

func (f *steerIfaddrs) state() (int, chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode, f.release
}

func (f *steerIfaddrs) list() ([]netip.Addr, error) {
	f.calls.Add(1)
	defer f.returned.Add(1)
	switch mode, release := f.state(); mode {
	case ifaddrsBlock:
		<-release
	case ifaddrsPanic:
		panic("steering test: an injected panic in the interface listing")
	}
	return []netip.Addr{netip.MustParseAddr(steerVIP)}, nil
}

func (f *steerIfaddrs) set(mode int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mode == ifaddrsBlock && mode != ifaddrsBlock {
		close(f.release)
	}
	if mode == ifaddrsBlock && f.mode != ifaddrsBlock {
		f.release = make(chan struct{})
	}
	f.mode = mode
}

// steerLog is a captured log.
type steerLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *steerLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *steerLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// steerRig is one running node with steering on.
type steerRig struct {
	t       *testing.T
	n       *Node
	brain   *fakeBrain
	tester  *fakeTester
	state   string
	sockets string
	store   steer.Store
	tls     *steerTLS
	ifaddrs *steerIfaddrs
	logs    *steerLog
	addr    string
	// stop stops the node, releasing a blocked interface listing first;
	// stopStuck stops it beside the blocked listing. Either stops it once.
	stop, stopStuck func() error
	// gets counts the /steer requests the rig made.
	gets atomic.Int64
}

// steerNode builds a node on baseOptions with steering on — VIP 127.0.0.1,
// RecoverAfter 3, a 1-2 s hold-down, JoinRetry 1 s — a fixture /proc (empty
// listener tables, so a refused probe is Refused; the switchable interface
// list) and the rig's TLS listener as :443, and a state.json pre-seeded, so
// no new_node drain stands. mod runs before New, with nothing running: it may
// change the options and the files. The node runs until the test ends.
func steerNode(t *testing.T, mod func(*Options, *steerRig)) *steerRig {
	t.Helper()
	r, opt := steerSetup(t, mod)
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	r.n = n
	stop := run(t, n)
	var once sync.Once
	var stopErr error
	stopOnce := func(release bool) error {
		once.Do(func() {
			if release {
				// Not needed for Run to end — shutdown waits for a stuck tick
				// at most steerShutdownWait — but it keeps the stop quick.
				r.ifaddrs.set(ifaddrsList)
			}
			stopErr = stop()
		})
		return stopErr
	}
	r.stop = func() error { return stopOnce(true) }
	r.stopStuck = func() error { return stopOnce(false) }
	// A listing left blocked past the stop is released after it: the tick
	// stuck in it then ends, and publishes nothing.
	t.Cleanup(func() {
		_ = r.stop()
		r.ifaddrs.set(ifaddrsList)
	})
	r.addr = statusAddr(t, n)
	return r
}

// steerTicks builds the node steerNode runs, without running it, and starts
// its sampler: the test calls s.tick itself, one tick at a time, with no
// ticker, brain poll or status listener. A node that never ran has rendered
// nothing, so its gates hold every join; drains and panics work as on a
// running node.
func steerTicks(t *testing.T, mod func(*Options, *steerRig)) (*steerRig, *sampler) {
	t.Helper()
	r, opt := steerSetup(t, mod)
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	r.n = n
	n.steer.start()
	return r, n.steer
}

// steerSetup is the rig steerNode and steerTicks build on, and the options
// they give New, mod applied.
func steerSetup(t *testing.T, mod func(*Options, *steerRig)) (*steerRig, Options) {
	t.Helper()
	r := &steerRig{t: t, brain: &fakeBrain{}, tester: &fakeTester{}, tls: newSteerTLS(t), ifaddrs: &steerIfaddrs{}, logs: &steerLog{}}
	r.brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(r.brain)
	t.Cleanup(srv.Close)
	r.state, r.sockets = shortDirs(t)
	r.store = steer.NewStore(r.state)
	if err := r.store.Save(steer.StateFile{Born: time.Now()}); err != nil {
		t.Fatal(err)
	}
	opt := baseOptions(srv, r.state, r.sockets, r.tester, &fakeReloader{})
	opt.Logger = slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opt.Steering = Steering{
		Enabled:   true,
		VIPs:      []netip.Addr{netip.MustParseAddr(steerVIP)},
		JoinRetry: time.Second,
		Config:    steer.Config{RecoverAfter: 3, HoldDownMin: time.Second, HoldDownMax: 2 * time.Second},
		Proc:      steer.Proc{FS: fstest.MapFS{"net/tcp": {}, "net/tcp6": {}}, Ifaddrs4: r.ifaddrs.list},
		Prober:    steer.Prober{Port: r.tls.port},
	}
	if mod != nil {
		mod(&opt, r)
	}
	return r, opt
}

// steerGot is one /steer answer: the status, the verdict when it carries one
// (200, 503, 425), the body and the headers.
type steerGot struct {
	code int
	ans  SteerAnswer
	body string
	hdr  http.Header
}

func (g steerGot) String() string { return fmt.Sprintf("%d %s", g.code, strings.TrimSpace(g.body)) }

func (r *steerRig) get(query string) steerGot {
	r.t.Helper()
	r.gets.Add(1)
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + r.addr + "/steer" + query)
	if err != nil {
		r.t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		r.t.Fatal(err)
	}
	g := steerGot{code: resp.StatusCode, body: string(body), hdr: resp.Header}
	if g.code == http.StatusOK || g.code == http.StatusServiceUnavailable || g.code == http.StatusTooEarly {
		if err := json.Unmarshal(body, &g.ans); err != nil {
			r.t.Fatalf("/steer%s %d %q: %v", query, g.code, body, err)
		}
	}
	return g
}

// waitSteer polls /steer every 50 ms until cond holds, for at most within.
func (r *steerRig) waitSteer(what, query string, within time.Duration, cond func(steerGot) bool) steerGot {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for {
		g := r.get(query)
		if cond(g) {
			return g
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("waited %v for %s; /steer%s answers %s", within, what, query, g)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// watchSteer polls /steer every 50 ms for d and hands every answer to check.
func (r *steerRig) watchSteer(query string, d time.Duration, check func(steerGot)) {
	r.t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		check(r.get(query))
	}
}

// announced waits for the VIP's announce.
func (r *steerRig) announced(query string) steerGot {
	r.t.Helper()
	return r.waitSteer("announce", query, 10*time.Second, func(g steerGot) bool { return g.code == http.StatusOK })
}

func (r *steerRig) status() SteeringStatus {
	r.t.Helper()
	_, st, body := getHealthz(r.t, r.addr)
	if st.Steering == nil {
		r.t.Fatalf("/healthz carries no steering object: %s", body)
	}
	return *st.Steering
}

// wantTLSZones waits for the first render and checks that it names zones as
// its :443 zones (render.Info.TLSZones): the joiner learns which
// zones have a TLS server from that list alone, so the first-entry tests pin
// the render's half of the wiring as well as the sampler's.
func (r *steerRig) wantTLSZones(zones ...string) {
	r.t.Helper()
	var got []string
	rendered := func() bool {
		r.n.mu.Lock()
		defer r.n.mu.Unlock()
		got = slices.Clone(r.n.renderedInfo.TLSZones)
		return r.n.renderedDoc != nil
	}
	waitFor(r.t, "the first render", rendered)
	if !slices.Equal(got, zones) {
		r.t.Fatalf("the first render's :443 zones are %q, want %q", got, zones)
	}
}

// steerServe calls serveSteer directly, as a peer at remote.
func steerServe(n *Node, remote, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/steer"+query, nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	n.serveSteer(rec, req)
	return rec
}

// probes is kapkan_edge_steer_probe_total for a target, every class summed.
func probes(key string) float64 {
	sum := 0.0
	for _, c := range []steer.Class{steer.ClassNone, steer.ClassOK, steer.ClassRefused, steer.ClassNotTLS, steer.ClassSoft, steer.ClassBlind} {
		sum += testutil.ToFloat64(metrics.EdgeSteerProbeTotal.WithLabelValues(key, c.String()))
	}
	return sum
}

// sameReaders compares two reader lists field by field, times by instant.
func sameReaders(a, b []SteerReader) bool {
	return slices.EqualFunc(a, b, func(x, y SteerReader) bool {
		return x.Consumer == y.Consumer && x.Dry == y.Dry && x.Verdict == y.Verdict && x.At.Equal(y.At) && x.Since.Equal(y.Since)
	})
}

func readStateFile(t *testing.T, dir string) steer.StateFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f steer.StateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("state.json %q: %v", raw, err)
	}
	return f
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The codes, the keys and the peers of GET /steer.
func TestSteerEndpointCodes(t *testing.T) {
	t.Parallel()
	// The first tick blocks in the interface listing until released: until
	// then nothing can be published, so "before the first tick" is certain.
	r := steerNode(t, func(_ *Options, r *steerRig) { r.ifaddrs.set(ifaddrsBlock) })
	g := r.get("?vip=" + steerVIP)
	if g.code != http.StatusTooEarly || g.ans.Verdict != steer.StateUnknown || g.ans.Reason != steer.ReasonStarting ||
		!g.ans.At.IsZero() || g.ans.Inputs != nil || g.ans.Target != steerVIP {
		t.Fatalf("before the first tick: %s, want 425 unknown/starting with no time and no inputs", g)
	}
	r.ifaddrs.set(ifaddrsList)

	g = r.announced("?vip=" + steerVIP)
	if g.ans.Verdict != steer.StateAnnounce || g.ans.Reason != steer.ReasonOK || g.ans.Inputs == nil ||
		g.ans.Inputs.Probe != steer.ClassOK || g.ans.At.IsZero() || g.ans.Since.IsZero() {
		t.Fatalf("announced: %s", g)
	}
	if strings.Contains(g.body, "example.com") {
		t.Fatalf("/steer names a zone: %s", g)
	}
	for _, g := range []steerGot{g, r.get("?vip=192.0.2.99")} {
		if ct, cc := g.hdr.Get("Content-Type"), g.hdr.Get("Cache-Control"); ct != "application/json" || cc != "no-store" {
			t.Fatalf("/steer %d headers: Content-Type %q, Cache-Control %q", g.code, ct, cc)
		}
	}
	if g := r.get("?vip=::ffff:" + steerVIP); g.code != http.StatusOK || g.ans.Target != steerVIP {
		t.Fatalf("an IPv4-mapped spelling of the VIP: %s, want the VIP's 200", g)
	}
	for query, want := range map[string]int{
		"?vip=192.0.2.99": http.StatusNotFound,
		"":                http.StatusBadRequest,
		"?vip=":           http.StatusBadRequest,
		"?vip=x":          http.StatusBadRequest,
	} {
		if g := r.get(query); g.code != want || !strings.Contains(g.body, `"error"`) {
			t.Errorf("/steer%s: %s, want %d with an error", query, g, want)
		}
	}

	// A drain takes the address out at once; its lift starts over.
	if err := r.store.SetDrain(steerVIP, steer.Drain{Reason: "maintenance", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r.waitSteer("503 drain/drained", "?vip="+steerVIP, 2500*time.Millisecond, func(g steerGot) bool {
		return g.code == http.StatusServiceUnavailable && g.ans.Verdict == steer.StateDrain && g.ans.Reason == steer.ReasonDrained
	})
	if err := r.store.Undrain(steerVIP); err != nil {
		t.Fatal(err)
	}
	r.waitSteer("425 unknown/starting after the undrain", "?vip="+steerVIP, 2500*time.Millisecond, func(g steerGot) bool {
		return g.code == http.StatusTooEarly && g.ans.Verdict == steer.StateUnknown && g.ans.Reason == steer.ReasonStarting
	})
	r.announced("?vip=" + steerVIP)

	// Nothing listening on :443: refused, and the kernel lists no listener.
	r.tls.close()
	g = r.waitSteer("503 withdraw/refused", "?vip="+steerVIP, 4500*time.Millisecond, func(g steerGot) bool {
		return g.code == http.StatusServiceUnavailable
	})
	if g.ans.Verdict != steer.StateWithdraw || g.ans.Reason != steer.ReasonRefused || g.ans.Inputs == nil || !g.ans.Inputs.Triggers.Refused {
		t.Fatalf("after the listener closed: %s, want withdraw/refused", g)
	}

	// GET only.
	resp, err := http.Post("http://"+r.addr+"/steer?vip="+steerVIP, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /steer: %d, want 405", resp.StatusCode)
	}

	// Only this box reads the verdict, and a refused peer stamps nothing.
	if rec := steerServe(r.n, "203.0.113.7:40000", "?vip="+steerVIP+"&consumer=from-afar"); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "readers on this box only") {
		t.Fatalf("a remote peer: %d %s, want 403", rec.Code, rec.Body)
	}
	for _, rd := range r.status().Targets[0].Readers {
		if rd.Consumer == "from-afar" {
			t.Fatal("a refused remote read was stamped as a reader")
		}
	}
	if err := r.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Steering off: 404, from a node that never ran.
	brain := httptest.NewServer(&fakeBrain{})
	defer brain.Close()
	state, sockets := shortDirs(t)
	off, err := New(baseOptions(brain, state, sockets, &fakeTester{}, &fakeReloader{}))
	if err != nil {
		t.Fatal(err)
	}
	if rec := steerServe(off, "127.0.0.1:40000", "?vip="+steerVIP); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "steering is off") {
		t.Fatalf("steering off: %d %s, want 404", rec.Code, rec.Body)
	}

	// No VIPs: the node's own target. An empty ?vip= is an absent one.
	nr := steerNode(t, func(o *Options, _ *steerRig) {
		o.Steering.VIPs = nil
		o.DisableIPv6 = true
	})
	plain := nr.announced("")
	empty := nr.get("?vip=")
	if plain.ans.Target != steer.NodeKey || empty.code != plain.code || empty.ans.Target != plain.ans.Target ||
		empty.ans.Verdict != plain.ans.Verdict || !empty.ans.Since.Equal(plain.ans.Since) {
		t.Fatalf("no VIPs: ?vip= answers %s, no vip %s; want the same verdict of %q", empty, plain, steer.NodeKey)
	}
	if g := nr.get("?vip=" + steerVIP); g.code != http.StatusNotFound {
		t.Fatalf("no VIPs: ?vip=%s answers %s, want 404 (no address is steered)", steerVIP, g)
	}
}

// The peer rule: loopback, or the connection's own local address.
func TestSteerPeerLocal(t *testing.T) {
	for _, c := range []struct {
		remote, local string
		want          bool
	}{
		{"127.0.0.1:40000", "", true},
		{"[::1]:40000", "", true},
		{"[::ffff:127.0.0.1]:40000", "", true},
		{"127.0.0.2:40000", "", true},
		{"10.0.0.5:40000", "10.0.0.5:9102", true},
		{"10.0.0.5:40000", "[::ffff:10.0.0.5]:9102", true},
		{"[2001:db8::5]:40000", "[2001:db8::5]:9102", true},
		{"203.0.113.7:40000", "10.0.0.5:9102", false},
		{"10.0.0.6:40000", "10.0.0.5:9102", false},
		{"203.0.113.7:40000", "", false},
		{"10.0.0.5:40000", "", false},
		{"not an address", "127.0.0.1:9102", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/steer", nil)
		req.RemoteAddr = c.remote
		if c.local != "" {
			la, err := net.ResolveTCPAddr("tcp", c.local)
			if err != nil {
				t.Fatal(err)
			}
			req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, la))
		}
		if got := steerPeerLocal(req); got != c.want {
			t.Errorf("remote %s, local %q: steerPeerLocal = %v, want %v", c.remote, c.local, got, c.want)
		}
	}
}

// Only 200 and 503 are definite; anything else holds.
func TestSteerAnswerCodes(t *testing.T) {
	for s, want := range map[steer.State]int{
		steer.StateAnnounce: http.StatusOK,
		steer.StateWithdraw: http.StatusServiceUnavailable,
		steer.StateDrain:    http.StatusServiceUnavailable,
		steer.StateUnknown:  http.StatusTooEarly,
		steer.State(9):      http.StatusTooEarly,
	} {
		if got := steerHTTPStatus(s); got != want {
			t.Errorf("steerHTTPStatus(%v) = %d, want %d", s, got, want)
		}
	}
}

// Readers: who read which verdict, bounded, and nothing stamped by
// /healthz or by an answer that carried no verdict. Sequential: it reads a
// metric.
func TestSteerReaders(t *testing.T) {
	for q, want := range map[string]bool{
		"": false, "dry=0": false, "dry=false": false, "dry=FALSE": false, "dry=False": false,
		"dry=1": true, "dry=true": true, "dry=TRUE": true, "dry=yes": true, "dry=on": true, "dry=2": true,
		"dry": true, "dry=": true, "dry=0&dry=1": true,
	} {
		v, err := url.ParseQuery(q)
		if err != nil {
			t.Fatal(err)
		}
		if got := steerDry(v); got != want {
			t.Errorf("?%s: dry = %v, want %v", q, got, want)
		}
	}

	reads := testutil.ToFloat64(metrics.EdgeSteerReadsTotal)
	r := steerNode(t, func(_ *Options, r *steerRig) { r.ifaddrs.set(ifaddrsBlock) })
	readerOf := func(st SteeringStatus, name string) (SteerReader, bool) {
		for _, rd := range st.Targets[0].Readers {
			if rd.Consumer == name {
				return rd, true
			}
		}
		return SteerReader{}, false
	}

	// Before the first tick the read is served unknown, with no since.
	if g := r.get("?vip=" + steerVIP + "&consumer=early&dry=1"); g.code != http.StatusTooEarly {
		t.Fatalf("before the first tick: %s", g)
	}
	if rd, ok := readerOf(r.status(), "early"); !ok || !rd.Dry || rd.Verdict != steer.StateUnknown || !rd.Since.IsZero() || rd.At.IsZero() {
		t.Fatalf("the read before the first tick: %+v (found %v)", rd, ok)
	}
	r.ifaddrs.set(ifaddrsList)
	r.announced("?vip=" + steerVIP)

	if g := r.get("?vip=" + steerVIP + "&consumer=bird&dry=1"); g.code != http.StatusOK {
		t.Fatalf("bird's read: %s", g)
	}
	st := r.status()
	bird, ok := readerOf(st, "bird")
	if !ok || !bird.Dry || bird.Verdict != steer.StateAnnounce || !bird.Since.Equal(st.Targets[0].Since) || bird.Since.IsZero() {
		t.Fatalf("bird: %+v (found %v), target since %v", bird, ok, st.Targets[0].Since)
	}
	if st.Targets[0].Readers[0].Consumer != "bird" || st.Consumer == nil || st.Consumer.Consumer != "bird" || !st.ConsumedAt.Equal(bird.At) {
		t.Fatalf("the newest reader is not bird: readers %+v, consumer %+v at %v", st.Targets[0].Readers, st.Consumer, st.ConsumedAt)
	}
	// /healthz stamps nothing.
	before := r.status().Targets[0].Readers
	for range 5 {
		r.status()
	}
	if after := r.status().Targets[0].Readers; !sameReaders(before, after) {
		t.Fatalf("/healthz reads changed the readers:\n%+v\n%+v", before, after)
	}

	// Names: a bad one is "invalid", none is "anonymous", a live read is live.
	r.get("?vip=" + steerVIP + "&consumer=" + url.QueryEscape("a b"))
	r.get("?vip=" + steerVIP + "&consumer=live-one")
	r.get("?vip=" + steerVIP)
	st = r.status()
	for name, dry := range map[string]bool{"invalid": false, "live-one": false, "anonymous": false} {
		if rd, ok := readerOf(st, name); !ok || rd.Dry != dry {
			t.Errorf("reader %q: %+v (found %v), want dry %v", name, rd, ok, dry)
		}
	}
	if _, ok := readerOf(st, "a b"); ok {
		t.Error("an invalid name was stored as given")
	}

	// Answers without a verdict stamp nothing — no reader of any target, and
	// not the node's latest read: 400 and 404 here, 403 below.
	before = st.Targets[0].Readers
	if g := r.get("?consumer=no-vip-400"); g.code != http.StatusBadRequest {
		t.Fatalf("no vip: %s", g)
	}
	if g := r.get("?vip=192.0.2.99&consumer=unsteered-404"); g.code != http.StatusNotFound {
		t.Fatalf("an address not steered: %s", g)
	}
	if rec := steerServe(r.n, "203.0.113.7:40000", "?vip="+steerVIP+"&consumer=remote-403"); rec.Code != http.StatusForbidden {
		t.Fatalf("a remote peer: %d", rec.Code)
	}
	after := r.status()
	if !sameReaders(after.Targets[0].Readers, before) || after.Consumer == nil || st.Consumer == nil ||
		!sameReaders([]SteerReader{*after.Consumer}, []SteerReader{*st.Consumer}) || !after.ConsumedAt.Equal(st.ConsumedAt) {
		t.Fatalf("a 400, 404 or 403 stamped a read: readers %+v (were %+v), latest %+v (was %+v)",
			after.Targets[0].Readers, before, after.Consumer, st.Consumer)
	}

	// Eight names per target, newest first.
	for i := range 10 {
		r.get(fmt.Sprintf("?vip=%s&consumer=n%d", steerVIP, i))
	}
	got := r.status().Targets[0].Readers
	if len(got) != steerMaxReaders || got[0].Consumer != "n9" || got[steerMaxReaders-1].Consumer != "n2" {
		names := make([]string, len(got))
		for i, rd := range got {
			names[i] = rd.Consumer
		}
		t.Fatalf("after ten names the readers are %v, want n9 … n2", names)
	}

	// Every GET counted, the three refusals included.
	if delta := testutil.ToFloat64(metrics.EdgeSteerReadsTotal) - reads; delta != float64(r.gets.Load()+1) {
		t.Fatalf("kapkan_edge_steer_reads_total grew by %v, want %d", delta, r.gets.Load()+1)
	}
}

// A stopped sampler holds: its last verdict ages to 425 once three intervals
// old, never 503. Stopping the node beside the stuck tick waits for it at
// most steerShutdownWait, and that tick, released after Run returned,
// publishes and saves nothing.
func TestSteerStoppedSamplerHolds(t *testing.T) {
	t.Parallel()
	r := steerNode(t, nil)
	r.announced("?vip=" + steerVIP)
	r.ifaddrs.set(ifaddrsBlock)
	flip := time.Now()
	staleAfter := r.n.opt.Steering.Config.StaleAfter() // steer's rule, not the sampler's own field
	for i := 0; ; i++ {
		g := r.get("?vip=" + steerVIP)
		if g.code == http.StatusServiceUnavailable {
			t.Fatalf("a stopped sampler withdrew: %s", g)
		}
		if g.code == http.StatusTooEarly && g.ans.Reason == steer.ReasonStale {
			// The stale answer carries the last tick's time.
			if age := time.Since(g.ans.At); age < staleAfter-100*time.Millisecond {
				t.Fatalf("stale %v after the last tick, want three intervals (%v): %s", age, staleAfter, g)
			}
			break
		}
		if time.Since(flip) > 4500*time.Millisecond {
			t.Fatalf("no 425 stale within 4.5 s of the sampler stopping: %s", g)
		}
		if i%10 == 0 {
			if code, _, body := getHealthz(t, r.addr); code != http.StatusOK {
				t.Fatalf("/healthz %d while the sampler is stuck: %s", code, body)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code, _, body := getHealthz(t, r.addr); code != http.StatusOK {
		t.Fatalf("/healthz %d while the sampler is stuck: %s", code, body)
	}
	if !strings.Contains(r.logs.String(), "steering tick skipped") {
		t.Error("ticks due while one was stuck were not reported as skipped")
	}

	// Stopping beside the stuck tick: a listing that ignores every ctx, as
	// SIOCGIFCONF waiting on RTNL does.
	stateJSON := filepath.Join(r.store.Dir, "state.json")
	saved, err := os.ReadFile(stateJSON)
	if err != nil {
		t.Fatal(err)
	}
	snap := r.n.steer.snap.Load()
	start := time.Now()
	if err := r.stopStuck(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// An absolute bound: one counted from steerShutdownWait would let the
	// wait grow unnoticed.
	took := time.Since(start)
	if took > 3*time.Second {
		t.Fatalf("Run returned %v after the cancel beside a stuck tick; shutdown waits for a tick at most %v", took, steerShutdownWait)
	}
	t.Logf("Run returned %v after the cancel beside a stuck tick", took)
	r.ifaddrs.set(ifaddrsList)
	waitFor(t, "the stuck interface listing to return", func() bool { return r.ifaddrs.returned.Load() == r.ifaddrs.calls.Load() })
	time.Sleep(500 * time.Millisecond) // the rest of that tick: a probe on a cancelled ctx
	if r.n.steer.snap.Load() != snap {
		t.Fatal("the tick released after Run returned published")
	}
	if now, err := os.ReadFile(stateJSON); err != nil || !bytes.Equal(now, saved) {
		t.Fatalf("the tick released after Run returned changed state.json: %q, was %q (%v)", now, saved, err)
	}
}

// A published verdict reads as itself until three intervals old, then 425
// unknown/stale however old it grows: a sampler that stopped on any verdict
// holds, never sooner than three intervals and never with a 503.
func TestSteerStaleAgesToHold(t *testing.T) {
	t.Parallel()
	brain := httptest.NewServer(&fakeBrain{})
	defer brain.Close()
	state, sockets := shortDirs(t)
	opt := baseOptions(brain, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.Steering = Steering{Enabled: true, VIPs: []netip.Addr{netip.MustParseAddr(steerVIP)}}
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stale := opt.Steering.Config.StaleAfter() // steer's rule, not the sampler's own field
	interval := stale / steer.StaleIntervals
	for _, c := range []struct {
		state  steer.State
		reason steer.Reason
		code   int // while fresh
	}{
		{steer.StateAnnounce, steer.ReasonOK, http.StatusOK},
		{steer.StateWithdraw, steer.ReasonRefused, http.StatusServiceUnavailable},
		{steer.StateDrain, steer.ReasonDrained, http.StatusServiceUnavailable},
	} {
		for _, age := range []time.Duration{interval * 5 / 2, interval * 7 / 2, time.Hour, 30 * 24 * time.Hour} {
			at := time.Now().Add(-age)
			n.steer.snap.Store(&steerSnapshot{at: at, targets: map[string]steerTargetSnap{
				steerVIP: {verdict: steer.Verdict{State: c.state, Reason: c.reason, Since: at, At: at}},
			}})
			rec := steerServe(n, "127.0.0.1:40000", "?vip="+steerVIP)
			var ans SteerAnswer
			if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
				t.Fatalf("%s published %v ago: %d %q: %v", c.state, age, rec.Code, rec.Body, err)
			}
			code, reason := c.code, c.reason
			if age > stale {
				code, reason = http.StatusTooEarly, steer.ReasonStale
			}
			if rec.Code != code || ans.Reason != reason {
				t.Errorf("%s published %v ago: %d %s, want %d %s", c.state, age, rec.Code, ans.Reason, code, reason)
			}
		}
	}
}

// A panic in a tick is recovered: the node runs on, and the verdict ages
// to 425 — for a VIP, and for the node target, whose kernel readings steer
// runs in goroutines of its own; and for a panic outside the kernel
// readings, in the probe's dial, which only the tick's own goroutines catch.
func TestSteerPanicIsRecovered(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		vips  []netip.Addr
		v6off bool
		query string
		dial  bool // the probe's dial panics, not the interface listing
	}{
		{"vip", []netip.Addr{netip.MustParseAddr(steerVIP)}, false, "?vip=" + steerVIP, false},
		{"node target", nil, true, "", false},
		{"vip probe dial", []netip.Addr{netip.MustParseAddr(steerVIP)}, false, "?vip=" + steerVIP, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var dialPanics atomic.Bool
			r := steerNode(t, func(o *Options, _ *steerRig) {
				o.Steering.VIPs = c.vips
				o.DisableIPv6 = c.v6off
				if c.dial {
					o.Steering.Prober.Control = func(context.Context, string, string, syscall.RawConn) error {
						if dialPanics.Load() {
							panic("steering test: an injected panic in the probe's dial")
						}
						return nil
					}
				}
			})
			r.announced(c.query)
			want := "an injected panic in the interface listing"
			if c.dial {
				want = "an injected panic in the probe's dial"
				dialPanics.Store(true)
			} else {
				r.ifaddrs.set(ifaddrsPanic)
			}
			flip := time.Now()
			for {
				g := r.get(c.query)
				if g.code == http.StatusServiceUnavailable {
					t.Fatalf("a panicking tick withdrew: %s", g)
				}
				if g.code == http.StatusTooEarly {
					break
				}
				if time.Since(flip) > 4500*time.Millisecond {
					t.Fatalf("no 425 within 4.5 s of the ticks panicking: %s", g)
				}
				time.Sleep(50 * time.Millisecond)
			}
			waitFor(t, "the recovered panic in the log", func() bool {
				return strings.Contains(r.logs.String(), "steering tick panicked")
			})
			if !strings.Contains(r.logs.String(), want) {
				t.Errorf("the log does not carry the panic's own value, %q", want)
			}
			if st := r.n.Status(); st.Steering == nil || !st.Steering.Enabled || !st.Healthy {
				t.Fatalf("Status after the panics: %+v", st)
			}
			if code, _, body := getHealthz(t, r.addr); code != http.StatusOK {
				t.Fatalf("/healthz %d after the panics: %s", code, body)
			}
			conn, err := net.Dial("unix", filepath.Join(r.sockets, "edge-decide.sock"))
			if err != nil {
				t.Fatalf("the decide socket after the panics: %v", err)
			}
			_ = conn.Close()
			dialPanics.Store(false)
			if err := r.stop(); err != nil {
				t.Fatalf("Run: %v", err)
			}
		})
	}
}

// steerPanicOn is a log handler that panics on one message and hands every
// other record to the handler it wraps — a panic raised from inside the
// sampler's start, whose last act is to log "steering on".
type steerPanicOn struct {
	slog.Handler
	msg string
}

func (h steerPanicOn) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Message == h.msg {
		panic("steering test: an injected panic at " + h.msg)
	}
	return h.Handler.Handle(ctx, rec)
}

// WithAttrs and WithGroup keep the wrapper: the node logs through
// Logger.With("component", "edge").
func (h steerPanicOn) WithAttrs(attrs []slog.Attr) slog.Handler {
	return steerPanicOn{h.Handler.WithAttrs(attrs), h.msg}
}

func (h steerPanicOn) WithGroup(name string) slog.Handler {
	return steerPanicOn{h.Handler.WithGroup(name), h.msg}
}

// A panic at the sampler's start stops steering, not the node: Run serves
// on, and every verdict holds (425 starting) until kapkan edge restarts.
func TestSteerStartPanicIsRecovered(t *testing.T) {
	t.Parallel()
	r := steerNode(t, func(o *Options, _ *steerRig) {
		o.Logger = slog.New(steerPanicOn{o.Logger.Handler(), "steering on"})
	})
	waitFor(t, "the recovered start panic in the log", func() bool {
		return strings.Contains(r.logs.String(), "steering stopped: it panicked")
	})
	if !strings.Contains(r.logs.String(), "an injected panic at steering on") {
		t.Error("the log does not carry the panic's own value")
	}
	waitFor(t, "the first install", func() bool { return r.n.Status().Healthy })
	r.watchSteer("?vip="+steerVIP, 3500*time.Millisecond, func(g steerGot) {
		if g.code != http.StatusTooEarly || g.ans.Verdict != steer.StateUnknown || g.ans.Reason != steer.ReasonStarting {
			t.Fatalf("after a panic at the sampler's start: %s, want 425 unknown/starting throughout", g)
		}
	})
	if st := r.n.Status(); st.Steering == nil || !st.Steering.Enabled || !st.Healthy {
		t.Fatalf("Status after the start panic: %+v", st)
	}
	if code, _, body := getHealthz(t, r.addr); code != http.StatusOK {
		t.Fatalf("/healthz %d after the start panic: %s", code, body)
	}
	conn, err := net.Dial("unix", filepath.Join(r.sockets, "edge-decide.sock"))
	if err != nil {
		t.Fatalf("the decide socket after the start panic: %v", err)
	}
	_ = conn.Close()
	if err := r.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// steerLogLines are the captured log's lines that carry msg.
func steerLogLines(logs *steerLog, msg string) []string {
	var out []string
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, `msg="`+msg) {
			out = append(out, line)
		}
	}
	return out
}

// A tick that panics every time logs its panic, with the stack, once — then
// at most once a minute, with how many ticks panicked since — as the skip
// warning is spaced: each stack after the first says nothing new, and one a
// tick would rotate the node's other logs out of the journal.
func TestSteerPanicLogIsThrottled(t *testing.T) {
	t.Parallel()
	r, s := steerTicks(t, nil)
	ctx := context.Background()
	r.ifaddrs.set(ifaddrsPanic)
	const n = 5
	for range n {
		s.tick(ctx)
	}
	lines := steerLogLines(r.logs, "steering tick panicked")
	if len(lines) != 1 || !strings.Contains(lines[0], "an injected panic in the interface listing") ||
		!strings.Contains(lines[0], "stack=") || !strings.Contains(lines[0], " ticks=1 ") {
		t.Fatalf("%d panicking ticks logged %d lines, want one with the panic, its stack and ticks=1:\n%s", n, len(lines), strings.Join(lines, ""))
	}

	// A minute on, the next panicking tick logs again, counting every tick
	// that panicked since the last line, itself included.
	s.panicAt = s.panicAt.Add(-steerSkipWarnEvery - time.Second)
	s.tick(ctx)
	lines = steerLogLines(r.logs, "steering tick panicked")
	if want := fmt.Sprintf(" ticks=%d ", n); len(lines) != 2 || !strings.Contains(lines[1], want) || !strings.Contains(lines[1], "stack=") {
		t.Fatalf("a minute later the panicking tick logged %d lines in all, want 2, the second with%sand its stack:\n%s", len(lines), want, strings.Join(lines, ""))
	}

	// A healthy tick publishes, and logs no panic.
	r.ifaddrs.set(ifaddrsList)
	s.tick(ctx)
	if s.snap.Load() == nil {
		t.Fatal("the healthy tick after the panics published nothing")
	}
	if lines = steerLogLines(r.logs, "steering tick panicked"); len(lines) != 2 {
		t.Fatalf("a healthy tick logged a panic: %d lines", len(lines))
	}
}

// steerCountingFS counts the files opened through it.
type steerCountingFS struct {
	inner fs.FS
	opens atomic.Int64
}

func (c *steerCountingFS) Open(name string) (fs.File, error) {
	c.opens.Add(1)
	return c.inner.Open(name)
}

// Steering off starts nothing: no goroutine reads the kernel, no
// file is written, no metric moves. Sequential: it reads a metric.
func TestSteerOffStartsNothing(t *testing.T) {
	counting := &steerCountingFS{inner: fstest.MapFS{"net/tcp": {}, "net/tcp6": {}}}
	before := probes(steerVIP)
	r := steerNode(t, func(o *Options, r *steerRig) {
		if err := os.RemoveAll(r.store.Dir); err != nil {
			t.Fatal(err)
		}
		o.Steering.Enabled = false
		o.Steering.Proc = steer.Proc{FS: counting, Ifaddrs4: r.ifaddrs.list}
	})
	time.Sleep(2500 * time.Millisecond)
	if n, m := counting.opens.Load(), r.ifaddrs.calls.Load(); n != 0 || m != 0 {
		t.Fatalf("steering off read the kernel: %d opens, %d interface listings", n, m)
	}
	if r.n.steer != nil {
		t.Fatal("steering off, and a sampler exists")
	}
	// A steering goroutine leaves a line however it ends: "steering on" from
	// its start, or "steering stopped" from runSteering's recover, had it
	// started on a nil sampler and panicked — which no other check here sees.
	// The two messages and not the word: the node logs its directories'
	// paths, which may hold it.
	if logs := r.logs.String(); strings.Contains(logs, "steering on") || strings.Contains(logs, "steering stopped") {
		t.Fatalf("steering off, and a steering goroutine ran:\n%s", logs)
	}
	if _, err := os.Lstat(r.store.Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("steering off made %s: %v", r.store.Dir, err)
	}
	if g := r.get("?vip=" + steerVIP); g.code != http.StatusNotFound || !strings.Contains(g.body, "steering is off on this node") {
		t.Fatalf("/steer with steering off: %s", g)
	}
	if _, _, body := getHealthz(t, r.addr); !strings.Contains(body, `"steering":{"enabled":false}`) {
		t.Fatalf("/healthz with steering off: %s", body)
	}
	if after := probes(steerVIP); after != before {
		t.Fatalf("kapkan_edge_steer_probe_total{vip=%q} moved by %v with steering off", steerVIP, after-before)
	}
}

// A node without state.json is born drained (new_node), and the drain
// lifts once every zone's handshake shows its certificate.
func TestSteerBirthAndFirstEntry(t *testing.T) {
	t.Parallel()
	r := steerNode(t, func(o *Options, r *steerRig) {
		if err := os.RemoveAll(r.store.Dir); err != nil {
			t.Fatal(err)
		}
		o.ACME = ACME{Directory: "http://127.0.0.1:1/never"} // the held certificate is fresh: never contacted
		selfSignedSet(t, o.StateDir, "example.com")
		// The join handshake asks for example.com and is shown other.example:
		// the first entry holds until the test switches the name.
		r.tls.setName(t, "other.example")
	})
	r.wantTLSZones("example.com")
	query := "?vip=" + steerVIP
	newNode := filepath.Join(r.store.Dir, "new_node")
	var last string
	deadline := time.Now().Add(10 * time.Second)
	for {
		g := r.get(query)
		fe := r.status().FirstEntry
		if g.code == http.StatusServiceUnavailable && g.ans.Verdict == steer.StateDrain && g.ans.Reason == steer.ReasonNewNode &&
			exists(filepath.Join(r.store.Dir, "state.json")) && exists(newNode) &&
			fe != nil && fe.Pending == steer.TriYes && fe.Zones == 1 && fe.Ready == 0 &&
			slices.Equal(fe.Missing, []string{"example.com"}) && fe.MissingCount == 1 {
			break
		}
		last = fmt.Sprintf("%s; first entry %+v", g, fe)
		if time.Now().After(deadline) {
			t.Fatalf("no 503 new_node beside a pending first entry: %s", last)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(r.logs.String(), "this node is new") {
		t.Error("the birth was not logged")
	}

	r.tls.setName(t, "example.com")
	switched := time.Now()
	waitFor(t, "the new-node drain to lift", func() bool { return !exists(newNode) })
	// JoinRetry (1 s) and three ticks, with room for a loaded runner: what
	// this bounds is a retry that ignores JoinRetry (steer's default is 10 s).
	if took := time.Since(switched); took > 6*time.Second {
		t.Errorf("the drain lifted %v after the certificate named the zone, more than JoinRetry and a few ticks", took)
	}
	r.waitSteer("425 starting after the lift", query, 3*time.Second, func(g steerGot) bool {
		return g.code == http.StatusTooEarly && g.ans.Reason == steer.ReasonStarting
	})
	r.announced(query)
	if fe := r.status().FirstEntry; fe != nil {
		t.Fatalf("the first entry is done, and the status still carries it: %+v", fe)
	}
	if !strings.Contains(r.logs.String(), "first entry complete") {
		t.Error("the lift was not logged")
	}
}

// While Birth cannot write — a steering directory that refuses writes — every
// target is drained in memory (new_node) and nothing is saved, so the next
// start would be born again; the first tick that can write arms the first
// entry for real, and it completes as usual.
func TestSteerBirthRetried(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	r := steerNode(t, func(o *Options, r *steerRig) {
		if err := os.Remove(filepath.Join(r.store.Dir, "state.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(r.store.Dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(r.store.Dir, 0o755) }) // after the node stops, before the dirs go
		o.ACME = ACME{Directory: "http://127.0.0.1:1/never"}
		selfSignedSet(t, o.StateDir, "example.com")
	})
	r.wantTLSZones("example.com")
	query := "?vip=" + steerVIP
	stateJSON, newNode := filepath.Join(r.store.Dir, "state.json"), filepath.Join(r.store.Dir, "new_node")
	r.waitSteer("503 new_node while Birth fails", query, 3*time.Second, func(g steerGot) bool {
		return g.code == http.StatusServiceUnavailable && g.ans.Reason == steer.ReasonNewNode
	})
	st := r.status()
	if st.FirstEntry == nil || st.FirstEntry.Pending != steer.TriYes || st.Drained == nil || st.Drained.Reason != steer.NewNodeReason {
		t.Fatalf("while Birth fails: first entry %+v, node drain %+v; want pending yes and new_node", st.FirstEntry, st.Drained)
	}
	r.watchSteer(query, 1500*time.Millisecond, func(g steerGot) {
		if g.code != http.StatusServiceUnavailable || g.ans.Reason != steer.ReasonNewNode {
			t.Fatalf("while Birth fails: %s, want 503 new_node throughout", g)
		}
	})
	if exists(stateJSON) || exists(newNode) {
		t.Fatal("a file was written while Birth failed")
	}
	if !strings.Contains(r.logs.String(), "its first entry could not be written") {
		t.Error("the failed Birth was not logged")
	}

	if err := os.Chmod(r.store.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "Birth to succeed", func() bool { return exists(stateJSON) })
	waitFor(t, "the first entry to complete", func() bool { return !exists(newNode) && len(readStateFile(t, r.store.Dir).Targets) == 1 })
	r.announced(query)
}

// reset-holddown: the request file is taken, applied and saved; a
// malformed one resets nothing; one a crash left taken is applied at start.
func TestSteerResetHoldDown(t *testing.T) {
	t.Parallel()
	r := steerNode(t, func(o *Options, _ *steerRig) {
		o.Steering.Config.HoldDownMin, o.Steering.Config.HoldDownMax = 8*time.Second, 16*time.Second
	})
	query := "?vip=" + steerVIP
	request := filepath.Join(r.store.Dir, ResetRequestFile)
	taken := request + ".taken"
	r.announced(query)
	r.tls.close()
	g := r.waitSteer("withdraw", query, 4500*time.Millisecond, func(g steerGot) bool { return g.code == http.StatusServiceUnavailable })
	if g.ans.Verdict != steer.StateWithdraw || g.ans.HoldDown.Level != 1 || g.ans.RejoinAt.IsZero() {
		t.Fatalf("the withdrawal from announce: %s, want withdraw at level 1 with a rejoin time", g)
	}
	oldRejoin := g.ans.RejoinAt
	if err := r.tls.reopen(); err != nil {
		t.Skipf("reopening the listener on port %d: %v", r.tls.port, err)
	}
	if err := WriteResetRequest(r.store.Dir, ResetRequest{All: true, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	took := time.Now()
	waitFor(t, "the request to be taken and saved", func() bool {
		sv := readStateFile(t, r.store.Dir).Targets[steerVIP]
		return !exists(request) && !exists(taken) && sv.Level == 0 && sv.Until.IsZero()
	})
	if since := time.Since(took); since > 2500*time.Millisecond {
		t.Errorf("the request took %v to be applied, more than two ticks", since)
	}
	g = r.announced(query)
	if !g.ans.Since.Before(oldRejoin) {
		t.Fatalf("announced at %v, not before the reset hold-down's end %v", g.ans.Since, oldRejoin)
	}
	if !strings.Contains(r.logs.String(), "hold-down reset by the operator") {
		t.Error("the reset was not logged")
	}

	// A malformed request is removed, and resets nothing.
	r.tls.close()
	r.waitSteer("withdraw again", query, 4500*time.Millisecond, func(g steerGot) bool { return g.code == http.StatusServiceUnavailable })
	waitFor(t, "the flap to be saved", func() bool { return readStateFile(t, r.store.Dir).Targets[steerVIP].Level == 1 })
	saved, err := os.ReadFile(filepath.Join(r.store.Dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request, []byte(`{"all": tru`), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the malformed request to be removed", func() bool { return !exists(request) && !exists(taken) })
	if now, err := os.ReadFile(filepath.Join(r.store.Dir, "state.json")); err != nil || !bytes.Equal(now, saved) {
		t.Fatalf("a malformed request changed state.json:\n%s\n%s (%v)", saved, now, err)
	}
	if !strings.Contains(r.logs.String(), "malformed") {
		t.Error("the malformed request was not logged")
	}
	if err := r.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// A request a crash left taken is applied at the next start.
	r2 := steerNode(t, func(o *Options, r *steerRig) {
		f := steer.StateFile{Born: time.Now(), Targets: map[string]steer.Saved{steerVIP: {Level: 2, Until: time.Now().Add(time.Minute)}}}
		if err := r.store.Save(f); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r.store.Dir, ResetRequestFile+".taken"), []byte(`{"all":true,"at":"2026-11-13T00:00:00Z"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	waitFor(t, "the half-taken request to be applied and saved", func() bool {
		sv := readStateFile(t, r2.store.Dir).Targets[steerVIP]
		return !exists(filepath.Join(r2.store.Dir, ResetRequestFile+".taken")) && sv.Level == 0 && sv.Until.IsZero()
	})
	if !strings.Contains(r2.logs.String(), "taken before the last stop") {
		t.Error("the half-taken request was not logged")
	}
}

// swapSteeringDir puts a regular file where the steering directory is, so
// every drain file's Lstat fails (ENOTDIR — TriUnknown, under root too), and
// returns the function that puts the directory back.
func swapSteeringDir(t *testing.T, dir string) (restore func()) {
	t.Helper()
	aside := dir + ".aside"
	if err := os.Rename(dir, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	restore = func() {
		once.Do(func() {
			if err := os.Remove(dir); err != nil {
				t.Error(err)
			}
			if err := os.Rename(aside, dir); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

// A tick that cannot read the drain files keeps the drain
// that stood before it, and lifts nothing; an undrained target stays in.
func TestSteerKeepsDrainThroughAnUnreadableTick(t *testing.T) {
	t.Parallel()
	r := steerNode(t, nil)
	query := "?vip=" + steerVIP
	if err := r.store.SetDrain(steerVIP, steer.Drain{Reason: "maintenance", Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	g := r.waitSteer("drain", query, 2500*time.Millisecond, func(g steerGot) bool { return g.ans.Verdict == steer.StateDrain })
	since := g.ans.Since
	restore := swapSteeringDir(t, r.store.Dir)
	unread := false
	r.watchSteer(query, 2200*time.Millisecond, func(g steerGot) {
		if g.code != http.StatusServiceUnavailable || g.ans.Verdict != steer.StateDrain || !g.ans.Since.Equal(since) {
			t.Fatalf("drained since %v, then the drain files went unreadable: %s", since, g)
		}
		unread = unread || (g.ans.Inputs != nil && !g.ans.Inputs.Gates.DrainKnown)
	})
	if !unread {
		t.Fatal("no tick read the drain files as unknown: the swap was not seen")
	}
	restore()
	r.watchSteer(query, 1200*time.Millisecond, func(g steerGot) {
		if g.ans.Verdict != steer.StateDrain || !g.ans.Since.Equal(since) {
			t.Fatalf("after the drain files came back: %s, want the drain since %v", g, since)
		}
	})

	// The converse: an announced, undrained target stays in.
	if err := r.store.Undrain(steerVIP); err != nil {
		t.Fatal(err)
	}
	r.announced(query)
	restore = swapSteeringDir(t, r.store.Dir)
	warned := false
	r.watchSteer(query, 2200*time.Millisecond, func(g steerGot) {
		if g.code != http.StatusOK || g.ans.Verdict != steer.StateAnnounce {
			t.Fatalf("announced, then the drain files went unreadable: %s", g)
		}
		warned = warned || g.ans.Warning == steer.ReasonDrainUnknown
	})
	restore()
	if !warned {
		t.Fatal("an announced target with unreadable drain files carried no drain_unknown warning")
	}
}

// The node-wide drain the status shows is kept through a tick that cannot
// read the drain files, as every target's drain is — the targets it drains
// and the status never disagree — and only a tick that reads it gone lifts
// it: with VIPs (a read of its own) and for the node target (the target's).
func TestSteerKeepsNodeDrainThroughAnUnreadableTick(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		vips  []netip.Addr
		v6off bool
	}{
		{"vip", []netip.Addr{netip.MustParseAddr(steerVIP)}, false},
		{"node target", nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r, s := steerTicks(t, func(o *Options, _ *steerRig) {
				o.Steering.VIPs = c.vips
				o.DisableIPv6 = c.v6off
			})
			ctx := context.Background()
			since := time.Now().Add(-time.Hour)
			if err := r.store.SetDrain(steer.NodeKey, steer.Drain{Reason: "maintenance", Since: since}); err != nil {
				t.Fatal(err)
			}
			check := func(what string, drained, unread bool) {
				t.Helper()
				st := s.status(time.Now())
				d := st.Drained
				if drained != (d != nil) || (d != nil && (d.Reason != "maintenance" || !d.Since.Equal(since))) {
					t.Fatalf("%s: the node-wide drain is %+v, want drained %v (maintenance since %v)", what, d, drained, since)
				}
				for _, tg := range st.Targets {
					if (tg.Verdict == steer.StateDrain) != drained || tg.Inputs == nil || tg.Inputs.Gates.DrainKnown == unread {
						t.Fatalf("%s: target %s is %s/%s with inputs %+v; want drained %v, the drain files unreadable %v",
							what, tg.Target, tg.Verdict, tg.Reason, tg.Inputs, drained, unread)
					}
				}
			}
			s.tick(ctx)
			check("the node drained", true, false)
			restore := swapSteeringDir(t, r.store.Dir)
			for range 2 {
				s.tick(ctx)
				check("the node drained, then the drain files unreadable", true, true)
			}
			restore()
			if err := r.store.Undrain(steer.NodeKey); err != nil {
				t.Fatal(err)
			}
			s.tick(ctx)
			check("undrained", false, false)
			restore = swapSteeringDir(t, r.store.Dir)
			s.tick(ctx)
			check("undrained, then the drain files unreadable", false, true)
			restore()
		})
	}
}

// A state_dir/steering that is a regular file from the start: the node
// runs, healthy, and every verdict holds (425) — never 503.
func TestSteerBrokenStateDirHolds(t *testing.T) {
	t.Parallel()
	r := steerNode(t, func(_ *Options, r *steerRig) {
		if err := os.RemoveAll(r.store.Dir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.store.Dir, []byte("not a directory\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	waitFor(t, "the first install", func() bool { return r.n.Status().Healthy })
	i := 0
	r.watchSteer("?vip="+steerVIP, 5*time.Second, func(g steerGot) {
		if g.code != http.StatusTooEarly {
			t.Fatalf("with no steering directory: %s, want 425 throughout", g)
		}
		if i++; i%10 == 0 {
			if code, _, body := getHealthz(t, r.addr); code != http.StatusOK {
				t.Fatalf("/healthz %d: %s", code, body)
			}
		}
	})
	if g := r.get("?vip=" + steerVIP); g.ans.Warning != steer.ReasonDrainUnknown {
		t.Errorf("held for %q, want drain_unknown: %s", g.ans.Warning, g)
	}
	if !strings.Contains(r.logs.String(), "state.json is unreadable") {
		t.Error("the unreadable state.json was not logged")
	}
	if err := r.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// steerFile is one file of the steering directory: its bytes, and its
// identity — an atomic rewrite with the same bytes is a new file.
type steerFile struct {
	bytes string
	info  os.FileInfo
}

// steerDirSnapshot is the steering directory's listing and every file's
// bytes and identity.
func steerDirSnapshot(t *testing.T, dir string) map[string]steerFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]steerFile{}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = steerFile{bytes: string(raw), info: info}
	}
	return out
}

// sameSteerDir reports whether two snapshots list the same files, each with
// the same bytes and the same identity.
func sameSteerDir(a, b map[string]steerFile) bool {
	if len(a) != len(b) {
		return false
	}
	for name, fa := range a {
		fb, ok := b[name]
		if !ok || fa.bytes != fb.bytes || !os.SameFile(fa.info, fb.info) {
			return false
		}
	}
	return true
}

// No route writes (I3, I5): every method but GET is refused on every
// path, and no GET changes a file.
func TestSteerStatusAcceptsNoWrite(t *testing.T) {
	t.Parallel()
	r := steerNode(t, nil)
	r.announced("?vip=" + steerVIP)
	before := steerDirSnapshot(t, r.store.Dir)
	c := &http.Client{Timeout: 3 * time.Second}
	do := func(method, path string) int {
		req, err := http.NewRequest(method, "http://"+r.addr+path, strings.NewReader(`{"all":true}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, path := range []string{"/steer", "/steer?vip=" + steerVIP, "/healthz", "/metrics", "/", "/steer/x", "/reset-holddown"} {
			if code := do(method, path); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d, want 404 or 405", method, path, code)
			}
		}
	}
	for path, want := range map[string]int{
		"/reset-holddown":      http.StatusNotFound,
		"/steer/x":             http.StatusNotFound,
		"/steer?reset=1&all=1": http.StatusBadRequest,
	} {
		if code := do(http.MethodGet, path); code != want {
			t.Errorf("GET %s: %d, want %d", path, code, want)
		}
	}
	time.Sleep(2200 * time.Millisecond) // two ticks, which save nothing while the verdict holds still
	if after := steerDirSnapshot(t, r.store.Dir); !sameSteerDir(before, after) {
		t.Fatalf("the steering directory changed:\n%v\n%v", before, after)
	}
}

// Nothing the brain sends withdraws (I5): an empty document, one the
// renderer refuses, and one `nginx -t` refuses each at most warn.
func TestSteerDocumentNeverWithdraws(t *testing.T) {
	t.Parallel()
	r := steerNode(t, nil)
	query := "?vip=" + steerVIP
	r.announced(query)
	stays := func(what string) {
		t.Helper()
		r.watchSteer(query, 3500*time.Millisecond, func(g steerGot) {
			if g.code != http.StatusOK || g.ans.Verdict != steer.StateAnnounce {
				t.Fatalf("%s: %s, want announce throughout", what, g)
			}
			switch g.ans.Warning {
			case "", steer.ReasonNoZones, steer.ReasonGenerationNotLive:
			default:
				t.Fatalf("%s: warning %q", what, g.ans.Warning)
			}
		})
	}

	empty := edgedoc.Empty()
	r.brain.set(&empty, `"v2"`)
	waitFor(t, "the empty document to render", func() bool { return r.n.Status().ZonesETag == `"v2"` })
	r.waitSteer("the no_zones gate", query, 2500*time.Millisecond, func(g steerGot) bool {
		return g.ans.Inputs != nil && g.ans.Inputs.Gates.Zones == 0 && g.ans.Warning == steer.ReasonNoZones
	})
	stays("an empty document")

	bad := testDoc(10)
	bad.Zones[0].Origins = []string{"bad origin"}
	r.brain.set(bad, `"v3"`)
	waitFor(t, "the refused document", func() bool {
		st := r.n.Status()
		return st.AcceptedETag == `"v3"` && st.LastError != ""
	})
	stays("a document the renderer refuses")

	r.tester.failWith("nginx: [emerg] steering test")
	r.brain.set(testDoc(10), `"v4"`)
	waitFor(t, "the document nginx -t refuses", func() bool {
		st := r.n.Status()
		return st.AcceptedETag == `"v4"` && strings.Contains(st.LastError, "[emerg]")
	})
	stays("a document nginx -t refuses")
}

// steerSlowTester passes every test; once armed, its next one first takes d
// (or until ctx ends): `nginx -t` over a node with many zones.
type steerSlowTester struct {
	calls atomic.Int64
	mu    sync.Mutex
	d     time.Duration
	began chan struct{}
}

// arm makes the next test take d; the channel closes when it begins.
func (s *steerSlowTester) arm(d time.Duration) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d, s.began = d, make(chan struct{})
	return s.began
}

func (s *steerSlowTester) Test(ctx context.Context) error {
	s.calls.Add(1)
	s.mu.Lock()
	d, began := s.d, s.began
	s.d, s.began = 0, nil
	s.mu.Unlock()
	if began == nil {
		return nil
	}
	close(began)
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// The generation gate only holds (I5): while `nginx -t` runs over a new
// generation, `live` names one not yet tested — on every node at once, since
// one document reaches them all — and an announced target stays in, warned,
// through as many closed ticks as it takes hard samples to withdraw.
func TestSteerGenerationGateNeverWithdraws(t *testing.T) {
	t.Parallel()
	slow := &steerSlowTester{}
	r := steerNode(t, func(o *Options, _ *steerRig) { o.Tester = slow })
	query := "?vip=" + steerVIP
	r.announced(query)
	gen := r.n.Status().Generation
	began := slow.arm(6 * time.Second)
	// A new origin renders new bytes, so a new generation is tested; a new
	// rate alone takes the fast path, and nothing is tested.
	doc := testDoc(10)
	doc.Zones[0].Origins = []string{"10.0.0.2:8080"}
	r.brain.set(doc, `"v2"`)
	select {
	case <-began:
	case <-time.After(10 * time.Second):
		t.Fatal("the new document's test never began")
	}
	closed := map[int64]bool{} // the ticks that read the gate closed
	r.watchSteer(query, 5*time.Second, func(g steerGot) {
		if g.code != http.StatusOK || g.ans.Verdict != steer.StateAnnounce {
			t.Fatalf("while nginx -t runs over a new generation: %s, want announce throughout", g)
		}
		if g.ans.Inputs != nil && !g.ans.Inputs.Gates.GenerationLive {
			if g.ans.Warning != steer.ReasonGenerationNotLive {
				t.Fatalf("the generation gate is closed, and the warning is %q: %s", g.ans.Warning, g)
			}
			closed[g.ans.At.UnixNano()] = true
		}
	})
	// FailAfter (3) closed ticks: were the gate a hard sample, it would have
	// withdrawn the address.
	if len(closed) < 3 {
		t.Fatalf("the generation gate read closed at %d ticks, want at least 3", len(closed))
	}
	t.Logf("the generation gate read closed at %d ticks, every answer 200 announce", len(closed))
	waitFor(t, "the new generation to pass its test", func() bool { return r.n.Status().Generation > gen })
	r.waitSteer("the gate open again", query, 3*time.Second, func(g steerGot) bool {
		return g.code == http.StatusOK && g.ans.Inputs != nil && g.ans.Inputs.Gates.GenerationLive
	})
	if slow.calls.Load() < 2 {
		t.Fatalf("nginx -t ran %d times, want the first install's and the new generation's", slow.calls.Load())
	}
}

// The terminator's pid is report-only: a master that is gone — its workers
// may still serve — or one that is frozen takes nothing out, and the report
// says which.
func TestSteerTerminatorIsReportOnly(t *testing.T) {
	t.Parallel()
	var pidFile string
	r := steerNode(t, func(o *Options, r *steerRig) {
		pidFile = filepath.Join(r.state, "nginx.pid")
		o.Terminator.PIDFile = pidFile
		o.Steering.Proc.FS = fstest.MapFS{
			"net/tcp": {}, "net/tcp6": {},
			// pid 1 listed: the tree shows the whole process table, so a pid
			// without its stat is gone, not unknown.
			"1/stat":    {Data: []byte("1 (init) S 0 1 1 0 -1 0 0 0 0 0\n")},
			"4243/stat": {Data: []byte("4243 (nginx) T 1 4243 4243 0 -1 0 0 0 0 0\n")},
		}
		if err := os.WriteFile(pidFile, []byte("4242\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	query := "?vip=" + steerVIP
	report := func(g steerGot) SteerReport {
		if g.ans.Inputs == nil {
			return SteerReport{}
		}
		return g.ans.Inputs.Report
	}
	r.waitSteer("announce beside a master that is gone", query, 10*time.Second, func(g steerGot) bool {
		return g.code == http.StatusOK && report(g).Terminator == steer.PIDGone
	})
	r.watchSteer(query, 2500*time.Millisecond, func(g steerGot) {
		if g.code != http.StatusOK || report(g).Terminator != steer.PIDGone {
			t.Fatalf("the master gone: %s, want 200 announce with terminator gone throughout", g)
		}
	})

	// The pid file now names a stopped master.
	next := pidFile + ".next"
	if err := os.WriteFile(next, []byte("4243\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, pidFile); err != nil {
		t.Fatal(err)
	}
	r.waitSteer("announce beside a frozen master", query, 3*time.Second, func(g steerGot) bool {
		rep := report(g)
		return g.code == http.StatusOK && rep.Terminator == steer.PIDAlive && rep.Frozen
	})
	r.watchSteer(query, 2500*time.Millisecond, func(g steerGot) {
		if rep := report(g); g.code != http.StatusOK || rep.Terminator != steer.PIDAlive || !rep.Frozen {
			t.Fatalf("the master frozen: %s, want 200 announce with terminator alive and frozen throughout", g)
		}
	})
}

// The four metrics. Sequential: it reads them.
func TestSteerMetrics(t *testing.T) {
	ok := metrics.EdgeSteerProbeTotal.WithLabelValues(steerVIP, "ok")
	toAnnounce := metrics.EdgeSteerTransitionsTotal.WithLabelValues(steerVIP, "announce", "ok")
	toDrain := metrics.EdgeSteerTransitionsTotal.WithLabelValues(steerVIP, "drain", "drained")
	ok0, announce0, drain0 := testutil.ToFloat64(ok), testutil.ToFloat64(toAnnounce), testutil.ToFloat64(toDrain)
	gauge := func(verdict string) float64 {
		return testutil.ToFloat64(metrics.EdgeSteerVerdict.WithLabelValues(steerVIP, verdict))
	}
	r := steerNode(t, nil)
	r.announced("?vip=" + steerVIP)
	if d := testutil.ToFloat64(ok) - ok0; d < 3 {
		t.Errorf("probe_total{ok} grew by %v by the announce, want at least 3", d)
	}
	if d := testutil.ToFloat64(toAnnounce) - announce0; d != 1 {
		t.Errorf("transitions_total{announce,ok} grew by %v, want 1", d)
	}
	for v, want := range map[string]float64{"announce": 1, "withdraw": 0, "drain": 0, "unknown": 0} {
		if got := gauge(v); got != want {
			t.Errorf("verdict{%s} = %v after the announce, want %v", v, got, want)
		}
	}
	if err := r.store.SetDrain(steerVIP, steer.Drain{Since: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r.waitSteer("drain", "?vip="+steerVIP, 2500*time.Millisecond, func(g steerGot) bool { return g.ans.Verdict == steer.StateDrain })
	if d := testutil.ToFloat64(toDrain) - drain0; d != 1 {
		t.Errorf("transitions_total{drain,drained} grew by %v, want 1", d)
	}
	if gauge("drain") != 1 || gauge("announce") != 0 {
		t.Errorf("verdict{drain} = %v, verdict{announce} = %v after the drain", gauge("drain"), gauge("announce"))
	}
}

// Every counter series a target can move is there from the sampler's start,
// at zero: Prometheus takes a series' first sample as its baseline, so one
// born at 1 reads as no increase, and the first withdrawal after a restart
// would never show in increase() or rate(). Sequential: it reads metrics.
func TestSteerCountersStartAtZero(t *testing.T) {
	const vip = "192.0.2.77" // a target no other test steers
	steerTicks(t, func(o *Options, _ *steerRig) { o.Steering.VIPs = []netip.Addr{netip.MustParseAddr(vip)} })
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]float64{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["vip"] != vip {
				continue
			}
			if got[mf.GetName()] == nil {
				got[mf.GetName()] = map[string]float64{}
			}
			switch mf.GetName() {
			case "kapkan_edge_steer_transitions_total":
				got[mf.GetName()][labels["to"]+"/"+labels["reason"]] = m.GetCounter().GetValue()
			case "kapkan_edge_steer_probe_total":
				got[mf.GetName()][labels["result"]] = m.GetCounter().GetValue()
			}
		}
	}
	for name, want := range map[string][]string{
		// The changes a Step makes: into announce, the three ways out, the two
		// drains, and a drain's lift to unknown.
		"kapkan_edge_steer_transitions_total": {"announce/ok", "withdraw/refused", "withdraw/not_tls", "withdraw/unbound", "drain/drained", "drain/new_node", "unknown/starting"},
		"kapkan_edge_steer_probe_total":       {"none", "ok", "refused", "not_tls", "soft", "blind"},
	} {
		for _, k := range want {
			if v, ok := got[name][k]; !ok || v != 0 {
				t.Errorf("%s{vip=%q, %s} after the start: %v (present %v), want an explicit 0", name, vip, k, v, ok)
			}
		}
		if len(got[name]) != len(want) {
			t.Errorf("%s{vip=%q} has %d series after the start, want %d: %v", name, vip, len(got[name]), len(want), got[name])
		}
	}
}

// The access log's progress, report-only: unknown on the first tick, which
// has nothing to compare with; then yes when records arrived since the
// previous tick, and no when none did.
func TestSteerLogProgress(t *testing.T) {
	t.Parallel()
	var s sampler
	for i, c := range []struct {
		count uint64
		want  steer.Tri
	}{{0, steer.TriUnknown}, {0, steer.TriNo}, {3, steer.TriYes}, {3, steer.TriNo}, {4, steer.TriYes}} {
		if got := s.logProgress(c.count); got != c.want {
			t.Fatalf("tick %d with %d records: progress %v, want %v", i+1, c.count, got, c.want)
		}
	}

	// The records the access-log listener receives are what it counts.
	r := steerNode(t, nil)
	query := "?vip=" + steerVIP
	progress := func(g steerGot) steer.Tri {
		if g.ans.Inputs == nil {
			return steer.TriUnknown
		}
		return g.ans.Inputs.Report.LogProgress
	}
	r.waitSteer("no progress", query, 3*time.Second, func(g steerGot) bool { return progress(g) == steer.TriNo })
	conn, err := net.Dial("unixgram", filepath.Join(r.sockets, "edge-log.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(`{"ts":"2026-11-13T08:00:00Z","zone":"example.com","src":"198.51.100.7","status":200}`)); err != nil {
		t.Fatal(err)
	}
	r.waitSteer("progress", query, 3*time.Second, func(g steerGot) bool { return progress(g) == steer.TriYes })
	r.waitSteer("no progress again", query, 3*time.Second, func(g steerGot) bool { return progress(g) == steer.TriNo })
}

// steerSlowTrie is a /proc whose net/fib_trie is a table so large that a
// reading yields one line per `every` and never ends: a full routing table,
// as one tick sees it.
type steerSlowTrie struct {
	fstest.MapFS
	every time.Duration
}

func (f steerSlowTrie) Open(name string) (fs.File, error) {
	if name == "net/fib_trie" {
		return &steerSlowFile{every: f.every}, nil
	}
	return f.MapFS.Open(name)
}

type steerSlowFile struct {
	every time.Duration
	lines int
}

func (f *steerSlowFile) Stat() (fs.FileInfo, error) {
	return nil, errors.New("steering test: a /proc file has no size")
}

func (f *steerSlowFile) Read(b []byte) (int, error) {
	time.Sleep(f.every)
	f.lines++
	return copy(b, fmt.Sprintf("  |-- 10.%d.%d.%d\n", f.lines>>16&255, f.lines>>8&255, f.lines&255)), nil
}

func (f *steerSlowFile) Close() error { return nil }

// A full routing table and the first entry: a target whose locality reads a full table until
// every tick's deadline does not starve the first entry, which runs beside it,
// and leaves every verdict fresh.
func TestSteerFirstEntryBesideASlowRouteTable(t *testing.T) {
	t.Parallel()
	const slow = "192.0.2.20" // not on an interface: fib_trie must answer
	r := steerNode(t, func(o *Options, r *steerRig) {
		if err := os.RemoveAll(r.store.Dir); err != nil {
			t.Fatal(err)
		}
		o.ACME = ACME{Directory: "http://127.0.0.1:1/never"}
		selfSignedSet(t, o.StateDir, "example.com")
		o.Steering.VIPs = []netip.Addr{netip.MustParseAddr(steerVIP), netip.MustParseAddr(slow)}
		// A short read, so a reading cut at the deadline overruns it by
		// little: the freshness below is the deadline's, not the read's.
		o.Steering.Proc.FS = steerSlowTrie{MapFS: fstest.MapFS{"net/tcp": {}, "net/tcp6": {}}, every: 10 * time.Millisecond}
	})
	r.wantTLSZones("example.com")
	newNode := filepath.Join(r.store.Dir, "new_node")
	waitFor(t, "the birth", func() bool { return exists(newNode) })
	deadline := time.Now().Add(12 * time.Second)
	for exists(newNode) {
		if time.Now().After(deadline) {
			t.Fatalf("the new-node drain never lifted beside a slow route table: first entry %+v", r.status().FirstEntry)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The lift may come in the first tick, between the file's removal and the
	// first publish: wait for a tick that read it, not for any 425.
	g := r.waitSteer("425 after the lift", "?vip="+slow, 3*time.Second, func(g steerGot) bool {
		return g.code == http.StatusTooEarly && g.ans.Inputs != nil && !g.ans.Inputs.Triggers.Drained
	})
	if g.ans.Inputs == nil || g.ans.Inputs.Probe != steer.ClassNone || !strings.Contains(g.ans.Inputs.Report.ProcError, "fib_trie") {
		t.Fatalf("the slow VIP's reading was not cut at the deadline: %s", g)
	}
	never503 := func(g steerGot) {
		if g.code == http.StatusServiceUnavailable {
			t.Fatalf("after the lift: %s", g)
		}
	}
	deadline = time.Now().Add(12 * time.Second)
	for {
		never503(r.get("?vip=" + slow))
		g := r.get("?vip=" + steerVIP)
		never503(g)
		if g.code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never announced after the lift: %s", steerVIP, g)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The slow VIP's reading never ends, yet every tick ends at its deadline,
	// 0.9 of the interval, and publishes before the next is due: for longer
	// than stale_after, 127.0.0.1 answers 200 at every read, and the slow VIP
	// 425 that holds, never stale.
	r.watchSteer("?vip="+steerVIP, 4*time.Second, func(g steerGot) {
		if g.code != http.StatusOK {
			t.Fatalf("%s beside a slow route table: %s, want 200 at every read", steerVIP, g)
		}
		if g := r.get("?vip=" + slow); g.code != http.StatusTooEarly || g.ans.Reason == steer.ReasonStale {
			t.Fatalf("the slow VIP after the lift: %s, want 425, never stale", g)
		}
	})
}

// Free text on the wire is bounded: a hand-written drain reason of
// 200 KiB and a probe error of 10 KiB stay out of /steer and /healthz.
func TestSteerWireIsBounded(t *testing.T) {
	t.Parallel()
	r := steerNode(t, func(o *Options, r *steerRig) {
		raw, err := json.Marshal(steer.Drain{Reason: strings.Repeat("r", 200<<10), Since: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r.store.Dir, "drain"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		long := errors.New(strings.Repeat("e", 10<<10))
		o.Steering.Prober.Control = func(context.Context, string, string, syscall.RawConn) error { return long }
	})
	g := r.waitSteer("the drain with its inputs", "?vip="+steerVIP, 3*time.Second, func(g steerGot) bool {
		return g.ans.Inputs != nil && g.ans.Inputs.Drain != nil && g.ans.Inputs.Report.ProbeError != ""
	})
	if g.code != http.StatusServiceUnavailable || len(g.body) >= 8<<10 {
		t.Fatalf("/steer: %d, %d bytes", g.code, len(g.body))
	}
	cut := func(what, s string, n int) {
		t.Helper()
		if !strings.HasSuffix(s, "…") || len(strings.TrimSuffix(s, "…")) != n {
			t.Errorf("%s is %d bytes, ending %q; want %d bytes then …", what, len(s), s[max(len(s)-8, 0):], n)
		}
	}
	cut("the drain's reason", g.ans.Inputs.Drain.Reason, 256)
	cut("the probe's error", g.ans.Inputs.Report.ProbeError, 512)
	if g.ans.Inputs.Probe != steer.ClassBlind {
		t.Errorf("a failing Control hook probed %v, want blind", g.ans.Inputs.Probe)
	}

	_, st, body := getHealthz(t, r.addr)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatal(err)
	}
	if n := len(raw["steering"]); n == 0 || n >= 8<<10 {
		t.Fatalf("/healthz's steering object is %d bytes", n)
	}
	if st.Steering.Drained == nil {
		t.Fatal("/healthz shows no node-wide drain")
	}
	cut("/healthz's node drain reason", st.Steering.Drained.Reason, 256)
}

// The wire's other bounds: first_entry.missing keeps the first 10 names and
// counts them all, and the report's three errors are cut to 512 bytes.
func TestSteerWireBounds(t *testing.T) {
	var names []string
	for i := range 25 {
		names = append(names, fmt.Sprintf("z%02d.example", i))
	}
	fe := steerWireFirstEntry(steer.TriYes, &steer.FirstEntry{Zones: 30, Ready: 5, Missing: names})
	if fe.Pending != steer.TriYes || fe.Zones != 30 || fe.Ready != 5 || fe.MissingCount != 25 || !slices.Equal(fe.Missing, names[:steerMaxMissing]) {
		t.Errorf("first entry: %+v; want the first %d names of 25, and 25 counted", fe, steerMaxMissing)
	}
	long := strings.Repeat("e", 10<<10)
	w := steerWireInputs(steer.Inputs{
		Triggers: steer.Triggers{Drained: true},
		Drain:    steer.Drain{Reason: strings.Repeat("r", 200<<10)},
		Report:   steer.Report{ProbeErr: long, ProcErr: long, DrainErr: long},
	})
	if w.Drain == nil {
		t.Fatal("a drained target's inputs carry no drain")
	}
	for _, c := range []struct {
		what, s string
		n       int
	}{
		{"probe_error", w.Report.ProbeError, steerErrMax},
		{"proc_error", w.Report.ProcError, steerErrMax},
		{"drain_error", w.Report.DrainError, steerErrMax},
		{"the drain's reason", w.Drain.Reason, steerReasonMax},
	} {
		if !strings.HasSuffix(c.s, "…") || len(strings.TrimSuffix(c.s, "…")) != c.n {
			t.Errorf("%s is %d bytes; want %d bytes, then …", c.what, len(c.s), c.n)
		}
	}
}

// A drain file's time is its writer's free text, as its reason is: a since
// JSON cannot carry — its UTC year outside 0..9999 — is left off the wire, and
// the drain answers 503 all the same; the file's existence is the drain.
func TestSteerDrainSinceOutOfRange(t *testing.T) {
	t.Parallel()
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		since string
		kept  bool
	}{
		{"0000-01-01T00:00:00Z", true},
		{"9999-12-31T23:59:59Z", true},
		{"2026-11-13T08:00:00+03:00", true},
		{"0000-01-01T00:00:00+00:01", false}, // the year -1 in UTC
		{"9999-12-31T23:30:00-05:00", false}, // the year 10000 in UTC
	} {
		since := at(c.since)
		w := steerWireDrain(steer.Drain{Reason: "by hand", Since: since})
		if w.Reason != "by hand" || c.kept != !w.Since.IsZero() || (c.kept && (!w.Since.Equal(since) || w.Since.Location() != time.UTC)) {
			t.Errorf("a drain since %s on the wire: %+v; kept %v, want %v, in UTC", c.since, w, !w.Since.IsZero(), c.kept)
		}
		if _, err := json.Marshal(w); err != nil {
			t.Errorf("a drain since %s does not encode: %v", c.since, err)
		}
	}

	// A hand-written node drain dated the year -1 in UTC, through a tick, /steer
	// and /healthz.
	r, s := steerTicks(t, func(_ *Options, r *steerRig) {
		raw := []byte(`{"reason":"by hand","since":"0000-01-01T00:00:00+00:01"}`)
		if err := os.WriteFile(filepath.Join(r.store.Dir, "drain"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	})
	s.tick(context.Background())
	rec := steerServe(r.n, "127.0.0.1:40000", "?vip="+steerVIP+"&consumer=bird")
	var ans SteerAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
		t.Fatalf("/steer %d %q: %v", rec.Code, rec.Body, err)
	}
	if rec.Code != http.StatusServiceUnavailable || ans.Verdict != steer.StateDrain || ans.Inputs == nil || ans.Inputs.Drain == nil ||
		ans.Inputs.Drain.Reason != "by hand" || !ans.Inputs.Drain.Since.IsZero() {
		t.Fatalf("/steer beside a drain dated the year -1: %d %s, want 503 drain by hand with no since", rec.Code, rec.Body)
	}
	hz := httptest.NewRecorder()
	r.n.statusHandler().ServeHTTP(hz, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var st Status
	if err := json.Unmarshal(hz.Body.Bytes(), &st); err != nil {
		t.Fatalf("/healthz %d %q: %v", hz.Code, hz.Body, err)
	}
	if st.Steering == nil || st.Steering.Drained == nil || st.Steering.Drained.Reason != "by hand" || !st.Steering.Drained.Since.IsZero() {
		t.Fatalf("/healthz beside a drain dated the year -1: %s, want the node drain by hand with no since", hz.Body)
	}
}

// steerText cuts at a rune boundary.
func TestSteerText(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 8, "short"},
		{"exactly8", 8, "exactly8"},
		{"abcdefghij", 4, "abcd…"},
		{"ééé", 3, "é…"}, // é is two bytes: 3 would split the second
		{"ééé", 4, "éé…"},
	} {
		if got := steerText(c.in, c.n); got != c.want {
			t.Errorf("steerText(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// New mirrors edge.yaml's steering rules, so a caller that builds Options
// directly gets the file's guards; a refusal creates nothing on disk.
func TestSteerNewChecks(t *testing.T) {
	base, sockets := shortDirs(t)
	opts := func(mod func(*Options)) Options {
		o := Options{
			Brain: "http://b", Name: "e1", StateDir: filepath.Join(base, "state"), SocketsDir: sockets,
			ACME: ACME{Disabled: true}, StatusListen: "127.0.0.1:0", Steering: Steering{Enabled: true},
		}
		mod(&o)
		return o
	}
	vips := func(s ...string) []netip.Addr {
		out := make([]netip.Addr, len(s))
		for i, a := range s {
			out[i] = netip.MustParseAddr(a)
		}
		return out
	}
	many := make([]netip.Addr, 65)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	for _, c := range []struct {
		name string
		mod  func(*Options)
		want string
	}{
		{"no status_listen", func(o *Options) { o.StatusListen = "" }, "edge: steering needs status_listen"},
		{"omit_catch_all", func(o *Options) { o.OmitCatchAll = true }, "edge: steering refuses omit_catch_all"},
		{"out of bounds", func(o *Options) { o.Steering.Config.Interval = 11 * time.Second }, "edge: steering: steer: interval"},
		{"invalid VIP", func(o *Options) { o.Steering.VIPs = []netip.Addr{{}} }, "is not an address"},
		{"IPv6 without IPv6", func(o *Options) { o.Steering.VIPs = vips("2001:db8::10"); o.DisableIPv6 = true }, "edge: steering VIP 2001:db8::10 is IPv6 and disable_ipv6 is set"},
		{"twice", func(o *Options) { o.Steering.VIPs = vips("192.0.2.10", "::ffff:192.0.2.10") }, "edge: steering VIP 192.0.2.10 listed twice"},
		{"too many", func(o *Options) { o.Steering.VIPs = many }, "at most 64"},
	} {
		if _, err := New(opts(c.mod)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: New = %v, want %q", c.name, err, c.want)
		}
		if _, err := os.Lstat(filepath.Join(base, "state")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: a refused New created the state_dir: %v", c.name, err)
		}
	}

	keys := func(n *Node) []string {
		var out []string
		for _, tg := range n.steer.targets {
			out = append(out, tg.Key+"="+fmt.Sprint(tg.Addrs))
		}
		return out
	}
	for _, c := range []struct {
		name string
		mod  func(*Options)
		want []string
	}{
		{"loopback VIP", func(o *Options) { o.Steering.VIPs = vips("127.0.0.1") }, []string{"127.0.0.1=[127.0.0.1]"}},
		{"both families", func(o *Options) { o.Steering.VIPs = vips("192.0.2.10", "2001:db8::10") }, []string{"192.0.2.10=[192.0.2.10]", "2001:db8::10=[2001:db8::10]"}},
		{"a mapped VIP without IPv6", func(o *Options) { o.Steering.VIPs = vips("::ffff:192.0.2.10"); o.DisableIPv6 = true }, []string{"192.0.2.10=[192.0.2.10]"}},
		{"node", func(*Options) {}, []string{"node=[127.0.0.1 ::1]"}},
		{"node without IPv6", func(o *Options) { o.DisableIPv6 = true }, []string{"node=[127.0.0.1]"}},
	} {
		n, err := New(opts(c.mod))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := keys(n); !slices.Equal(got, c.want) {
			t.Errorf("%s: targets %v, want %v", c.name, got, c.want)
		}
		// Before the first render there is no document: no zones, not a panic.
		if zones, tlsZones, _ := n.steerDocFacts(); zones != nil || tlsZones != nil {
			t.Errorf("%s: before any render the node knows zones %v and :443 zones %v", c.name, zones, tlsZones)
		}
	}
	n, err := New(opts(func(o *Options) {
		o.Steering.Enabled, o.StatusListen, o.OmitCatchAll = false, "", true
		o.Steering.VIPs = vips("192.0.2.10", "192.0.2.10")
	}))
	if err != nil || n.steer != nil {
		t.Fatalf("steering off: New = %v, sampler %v; want nothing of steering checked or built", err, n != nil && n.steer != nil)
	}
	if raw, err := json.Marshal(n.SteeringStatus()); err != nil || string(raw) != `{"enabled":false}` {
		t.Fatalf("steering off: status %s (%v), want {\"enabled\":false}", raw, err)
	}
}

// The request file: written whole and readable, taken or cancelled — never
// both — and never into a directory it would have to create.
func TestSteerResetRequestFile(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	if err := WriteResetRequest(dir, ResetRequest{Keys: []string{"192.0.2.10"}, At: at}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ResetRequestFile)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("the request is %v, want 0644", fi.Mode().Perm())
	}
	req, err := readResetRequest(path)
	if err != nil || req.All || !slices.Equal(req.Keys, []string{"192.0.2.10"}) || !req.At.Equal(at) {
		t.Fatalf("read back: %+v, %v", req, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("the directory holds %d entries after a write, want the request alone", len(entries))
	}
	if pending, err := ResetRequestPending(dir); !pending || err != nil {
		t.Fatalf("pending = %v, %v after a write", pending, err)
	}
	// A second request replaces the first.
	if err := WriteResetRequest(dir, ResetRequest{All: true, At: at}); err != nil {
		t.Fatal(err)
	}
	if req, err := readResetRequest(path); err != nil || !req.All {
		t.Fatalf("the replacing request: %+v, %v", req, err)
	}
	// Cancelled before the daemon took it.
	if taken, err := CancelResetRequest(dir); taken || err != nil {
		t.Fatalf("cancel of a pending request: taken %v, %v", taken, err)
	}
	if pending, err := ResetRequestPending(dir); pending || err != nil {
		t.Fatalf("pending = %v, %v after a cancel", pending, err)
	}
	// Taken by the daemon (renamed away) before the cancel.
	if err := WriteResetRequest(dir, ResetRequest{All: true, At: at}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".taken"); err != nil {
		t.Fatal(err)
	}
	if taken, err := CancelResetRequest(dir); !taken || err != nil {
		t.Fatalf("cancel of a taken request: taken %v, %v", taken, err)
	}
	// The directory is never created.
	missing := filepath.Join(dir, "steering")
	if err := WriteResetRequest(missing, ResetRequest{All: true}); err == nil {
		t.Fatal("a request was written into a directory that does not exist")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("WriteResetRequest created %s: %v", missing, err)
	}
	// A request too large to be one is malformed.
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), steerResetMax+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readResetRequest(path); err == nil {
		t.Fatal("a request above 64 KiB was read")
	}
	// So is anything but a regular file: reading a FIFO would wait for a
	// writer, and hold the tick that took it.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readResetRequest(fifo); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a FIFO as a request: %v, want it refused", err)
	}
}

func TestSteerConfRootAndLiveZones(t *testing.T) {
	state := t.TempDir()
	if got := ConfRoot(state); got != filepath.Join(state, "conf") {
		t.Fatalf("ConfRoot = %s", got)
	}
	if n, err := LiveZones(state); n != 0 || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("before any install: %d, %v; want 0 and not-exist", n, err)
	}
	gen := filepath.Join(state, "conf", "gen-000001")
	if err := os.MkdirAll(gen, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kapkan_zone_a.example.conf", "kapkan_zone_b.example.conf", "kapkan_common.conf", ".kapkan-tested", "kapkan_zone_c.example.conf.tmp"} {
		if err := os.WriteFile(filepath.Join(gen, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("gen-000001", filepath.Join(state, "conf", "live")); err != nil {
		t.Fatal(err)
	}
	if n, err := LiveZones(state); n != 2 || err != nil {
		t.Fatalf("LiveZones = %d, %v; want the two zone files", n, err)
	}
}

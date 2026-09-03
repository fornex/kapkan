package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// fakeBrain serves the zone document with an ETag, holds polls briefly, and
// records reports, ACME coordination calls and what every poll presented.
type fakeBrain struct {
	mu        sync.Mutex
	doc       []byte
	etag      string
	reports   []api.EdgeReport
	acme      []string
	inm       []string // If-None-Match of every poll, in order
	polls     atomic.Int64
	delivered atomic.Int64 // 200s with a body
	notMod    atomic.Int64 // 304s
	// redirectReports answers the report route with a 307 to this URL.
	redirectReports string
}

func (b *fakeBrain) set(doc *edgedoc.Doc, etag string) {
	raw, _ := json.Marshal(doc)
	b.mu.Lock()
	b.doc, b.etag = raw, etag
	b.mu.Unlock()
}

func (b *fakeBrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer agent-secret" {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/edge/zones":
		b.polls.Add(1)
		b.mu.Lock()
		doc, etag := b.doc, b.etag
		b.inm = append(b.inm, r.Header.Get("If-None-Match"))
		b.mu.Unlock()
		if r.URL.Query().Get("node") != "e1" {
			http.Error(w, "unknown edge node", http.StatusNotFound)
			return
		}
		if r.Header.Get("If-None-Match") == etag {
			time.Sleep(50 * time.Millisecond)
			b.notMod.Add(1)
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		b.delivered.Add(1)
		w.Header().Set("ETag", etag)
		_, _ = w.Write(doc)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/report"):
		b.mu.Lock()
		redirect := b.redirectReports
		b.mu.Unlock()
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}
		var rep api.EdgeReport
		_ = json.NewDecoder(r.Body).Decode(&rep)
		b.mu.Lock()
		b.reports = append(b.reports, rep)
		b.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "POST" && strings.Contains(r.URL.Path, "/acme/"):
		b.mu.Lock()
		b.acme = append(b.acme, r.URL.Path)
		b.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (b *fakeBrain) lastReport() (api.EdgeReport, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.reports) == 0 {
		return api.EdgeReport{}, false
	}
	return b.reports[len(b.reports)-1], true
}

func (b *fakeBrain) firstINM() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.inm) == 0 {
		return "", false
	}
	return b.inm[0], true
}

// fakeTester passes unless a failure message is scripted.
type fakeTester struct {
	calls atomic.Int64
	fail  atomic.Pointer[string]
}

func (f *fakeTester) Test(context.Context) error {
	f.calls.Add(1)
	if msg := f.fail.Load(); msg != nil {
		return errors.New(*msg)
	}
	return nil
}

func (f *fakeTester) failWith(msg string) { f.fail.Store(&msg) }
func (f *fakeTester) pass()               { f.fail.Store(nil) }

type fakeReloader struct{ calls atomic.Int64 }

func (f *fakeReloader) Reload(context.Context) error { f.calls.Add(1); return nil }

func testDoc(rps uint64) *edgedoc.Doc {
	d := edgedoc.Empty()
	d.Zones = append(d.Zones, edgedoc.Zone{
		Name: "example.com", Origins: []string{"10.0.0.1:8080"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, Rate: edgedoc.Rate{RPS: rps}},
	})
	return &d
}

func shortDirs(t *testing.T) (state, sockets string) {
	t.Helper()
	// Unix socket paths are short (104 bytes on darwin); t.TempDir is long.
	base, err := os.MkdirTemp("", "kn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return filepath.Join(base, "s"), filepath.Join(base, "r")
}

func baseOptions(brain *httptest.Server, state, sockets string, tester *fakeTester, reloader *fakeReloader) Options {
	return Options{
		Brain: brain.URL, Token: "agent-secret", Name: "e1", DryRun: true,
		StateDir: state, SocketsDir: sockets,
		ACME:           ACME{Disabled: true},
		ReportInterval: 100 * time.Millisecond,
		RetryMin:       200 * time.Millisecond, RetryMax: 200 * time.Millisecond,
		StatusListen: "127.0.0.1:0",
		Logger:       slog.New(slog.DiscardHandler),
		Tester:       tester, Reloader: reloader,
		Prober: func(context.Context, string) (string, string, error) { return "nginx", "1.99.0", nil },
	}
}

func newNode(t *testing.T, brain *httptest.Server, state, sockets string, tester *fakeTester, reloader *fakeReloader) *Node {
	t.Helper()
	n, err := New(baseOptions(brain, state, sockets, tester, reloader))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// statusAddr waits for the status listener to bind and returns its address.
func statusAddr(t *testing.T, n *Node) string {
	t.Helper()
	waitFor(t, "the status listener", func() bool { return n.StatusAddr() != "" })
	return n.StatusAddr()
}

// run starts the node and returns a stop function that asserts Run's error.
func run(t *testing.T, n *Node) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not stop")
			return nil
		}
	}
}

func TestNodeInstallsDocumentReportsAndSkipsFastPathChanges(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	tester, reloader := &fakeTester{}, &fakeReloader{}
	n := newNode(t, srv, state, sockets, tester, reloader)
	stop := run(t, n)

	// The document is rendered and installed; the live generation carries it.
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	live := filepath.Join(state, "conf", "live", "kapkan_zone_example.com.conf")
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("rendered zone file: %v", err)
	}
	if tester.calls.Load() != 1 || reloader.calls.Load() != 1 {
		t.Fatalf("tester=%d reloader=%d after the first install", tester.calls.Load(), reloader.calls.Load())
	}
	// The sockets exist: decide and log group-restricted, the challenge
	// answerer world-connectable (it serves public tokens).
	for s, want := range map[string]os.FileMode{"edge-decide.sock": 0o660, "edge-challenge.sock": 0o666, "edge-log.sock": 0o660} {
		st, err := os.Lstat(filepath.Join(sockets, s))
		if err != nil {
			t.Fatalf("socket %s: %v", s, err)
		}
		if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != want {
			t.Fatalf("socket %s mode %v, want %v", s, st.Mode(), want)
		}
	}
	// The document and ETag are cached for a brain-less restart, 0600.
	if raw, err := os.ReadFile(filepath.Join(state, "zones.etag")); err != nil || strings.TrimSpace(string(raw)) != `"v1"` {
		t.Fatalf("cached etag: %q %v", raw, err)
	}
	for _, f := range []string{"zones.json", "zones.etag"} {
		if st, _ := os.Stat(filepath.Join(state, f)); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, st.Mode())
		}
	}
	// A report arrives with the RENDERED ETag, the dry-run flag and the probe.
	waitFor(t, "a report", func() bool { rep, ok := brain.lastReport(); return ok && rep.ZonesETag == `"v1"` })
	rep, _ := brain.lastReport()
	if !rep.DryRun || rep.Terminator == nil || rep.Terminator.Generation != 1 || !rep.Terminator.TestOK || rep.Terminator.Kind != "nginx" || rep.Terminator.Version != "1.99.0" {
		t.Fatalf("report: %+v %+v", rep, rep.Terminator)
	}
	if rep.Terminator.Alive != nil {
		t.Fatal("no pid file configured, yet the report carries a liveness verdict")
	}

	// FAST PATH. The decision service is in dry-run and knows the zone's
	// rate; a rate-only change reaches it without a render or a reload.
	if !n.svc.DryRun() {
		t.Fatal("decision service not in dry-run")
	}
	src := netip.MustParseAddr("198.51.100.7")
	tight := testDoc(1)
	tight.ACMEChallenges = []edgedoc.Challenge{{Zone: "example.com", Token: "tok_" + strings.Repeat("a", 24), KeyAuthorization: "tok_" + strings.Repeat("a", 24) + ".thumb_" + strings.Repeat("b", 20), ExpiresAt: time.Now().Add(time.Hour)}}
	brain.set(tight, `"v2"`)
	waitFor(t, "the second document", func() bool { return n.Status().ZonesETag == `"v2"` })
	first := n.svc.Decide("example.com", src)
	second := n.svc.Decide("example.com", src)
	if !first.Allow || first.Reason != decide.ReasonAllow {
		t.Fatalf("first decision: %+v", first)
	}
	if !second.Allow || !second.DryRun || second.Reason != decide.ReasonRate || !strings.HasPrefix(second.Mark, "would-deny:") {
		t.Fatalf("second decision at 1 rps in dry-run: %+v", second)
	}
	if _, ok := n.challenges.Lookup("example.com", tight.ACMEChallenges[0].Token); !ok {
		t.Fatal("fanned-out challenge not in the answerer's table")
	}
	time.Sleep(100 * time.Millisecond)
	if n.Status().Generation != 1 || tester.calls.Load() != 1 || reloader.calls.Load() != 1 {
		t.Fatalf("a rate change reloaded the terminator: gen=%d tester=%d reloader=%d", n.Status().Generation, tester.calls.Load(), reloader.calls.Load())
	}
	// Raising the rate makes the same source pass again — again without a render.
	brain.set(testDoc(1000), `"v3"`)
	waitFor(t, "the third document", func() bool { return n.Status().ZonesETag == `"v3"` })
	time.Sleep(20 * time.Millisecond)
	if v := n.svc.Decide("example.com", src); !v.Allow || v.Reason != decide.ReasonAllow {
		t.Fatalf("decision after the rate was raised: %+v", v)
	}
	if n.Status().Generation != 1 || reloader.calls.Load() != 1 {
		t.Fatal("a rate change reloaded the terminator")
	}

	// SLOW PATH. A zone change: a new generation, tested and reloaded.
	d := testDoc(1000)
	d.Zones = append(d.Zones, edgedoc.Zone{Name: "b.example.com", Origins: []string{"10.0.0.2:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeNone, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}})
	brain.set(d, `"v4"`)
	waitFor(t, "the fourth document", func() bool { return n.Status().Generation == 2 })
	if reloader.calls.Load() != 2 {
		t.Fatalf("reloader calls = %d after a zone change", reloader.calls.Load())
	}
	st := n.Status()
	if !st.Healthy || !st.Converged || st.Zones != 2 || st.BrainSeen.IsZero() || st.ZonesETag != `"v4"` || st.AcceptedETag != `"v4"` {
		t.Fatalf("status: %+v", st)
	}
	// /healthz and /metrics answer on the bound address.
	addr := n.StatusAddr()
	if addr == "" {
		t.Fatal("status listener bound no address")
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"healthy":true`) || !strings.Contains(string(body), `"generation":2`) {
		t.Fatalf("/healthz: %d %s", resp.StatusCode, body)
	}
	resp, err = http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "kapkan_") {
		t.Fatalf("/metrics: %d", resp.StatusCode)
	}

	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, s := range []string{"edge-decide.sock", "edge-challenge.sock", "edge-log.sock"} {
		if _, err := os.Lstat(filepath.Join(sockets, s)); err == nil {
			t.Fatalf("socket %s left behind", s)
		}
	}
}

// A candidate that fails `nginx -t` is never installed: the previous
// generation keeps serving, the node stays healthy but not converged, the
// report names the RENDERED document, and the document is retried locally
// until it applies.
func TestNodeKeepsServingWhenACandidateFailsTheTest(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	tester, reloader := &fakeTester{}, &fakeReloader{}
	n := newNode(t, srv, state, sockets, tester, reloader)
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })

	tester.failWith("nginx: [emerg] unknown directive \"bogus\" in /x/kapkan_zone_b.example.com.conf:3")
	d := testDoc(10)
	d.Zones = append(d.Zones, edgedoc.Zone{Name: "b.example.com", Origins: []string{"10.0.0.2:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeNone, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}})
	brain.set(d, `"v2"`)
	waitFor(t, "the refused document", func() bool { return n.Status().LastError != "" })
	st := n.Status()
	if st.Generation != 1 || st.TestOK || !strings.Contains(st.TestError, "[emerg]") || !strings.Contains(st.LastError, "[emerg]") {
		t.Fatalf("status after a failed test: %+v", st)
	}
	if !st.Healthy || st.Converged || st.ZonesETag != `"v1"` || st.AcceptedETag != `"v2"` || st.RetryAt.IsZero() {
		t.Fatalf("healthy/converged/etags after a failed test: %+v", st)
	}
	if reloader.calls.Load() != 1 {
		t.Fatalf("reloaded after a failed test: %d", reloader.calls.Load())
	}
	if _, err := os.Stat(filepath.Join(state, "conf", "live", "kapkan_zone_b.example.com.conf")); err == nil {
		t.Fatal("the refused zone's file is live")
	}
	// The fast path still took the new document.
	if st.Zones != 2 {
		t.Fatalf("fast path did not take the refused document: zones=%d", st.Zones)
	}
	// The report says v1 is rendered, with the failure; /healthz stays 200.
	waitFor(t, "a report with the failure", func() bool {
		rep, ok := brain.lastReport()
		return ok && rep.Terminator != nil && rep.Terminator.TestError != ""
	})
	rep, _ := brain.lastReport()
	if rep.ZonesETag != `"v1"` || rep.Terminator.Generation != 1 || rep.Terminator.TestOK {
		t.Fatalf("report after a failed test: %+v %+v", rep, rep.Terminator)
	}
	resp, err := http.Get("http://" + statusAddr(t, n) + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/healthz %d while generation 1 serves", resp.StatusCode)
	}
	// The poller parked on v2 (the brain sees the node alive) rather than
	// re-fetching; the retry is local.
	time.Sleep(300 * time.Millisecond)
	if brain.delivered.Load() > 3 {
		t.Fatalf("the refused document was re-fetched %d times", brain.delivered.Load())
	}
	// The operator fixes nginx: the local retry applies the document (as a
	// fresh generation — the failed candidate's number is spent).
	tester.pass()
	waitFor(t, "the retry to apply", func() bool { return n.Status().Generation > 1 })
	st = n.Status()
	if !st.Converged || st.ZonesETag != `"v2"` || st.LastError != "" || !st.RetryAt.IsZero() || !st.TestOK {
		t.Fatalf("status after the retry: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(state, "conf", "live", "kapkan_zone_b.example.com.conf")); err != nil {
		t.Fatalf("the retried zone's file is not live: %v", err)
	}
	if reloader.calls.Load() != 2 {
		t.Fatalf("reloader calls after the retry: %d", reloader.calls.Load())
	}
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestNodeStartsFromDiskWithTheBrainGone(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	_ = stop()
	srv.Close() // the brain is gone

	// A second process over the same state: renders from the cache, knows
	// the ETag, polls (and fails) without ever having seen the brain.
	tester, reloader := &fakeTester{}, &fakeReloader{}
	opt := baseOptions(srv, state, sockets, tester, reloader)
	opt.ReportInterval = time.Hour
	n2, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop2 := run(t, n2)
	waitFor(t, "start from disk", func() bool { st := n2.Status(); return st.Healthy && st.Zones == 1 })
	st := n2.Status()
	if st.ZonesETag != `"v1"` || st.AcceptedETag != `"v1"` || st.Generation != 1 || !st.Converged {
		t.Fatalf("status from disk: %+v", st)
	}
	// The same bytes render the same files: the live generation is unchanged
	// and nothing was reloaded — only Recover ran the tester... and Recover
	// had nothing to do, the generation was tested.
	if reloader.calls.Load() != 0 || tester.calls.Load() != 0 {
		t.Fatalf("restart re-tested (%d) or reloaded (%d) an unchanged, tested configuration", tester.calls.Load(), reloader.calls.Load())
	}
	_ = stop2()
}

// With the brain alive, a restarted node's first poll presents the cached
// ETag and is answered 304: the document is not delivered twice.
func TestNodeRestartPollsWithTheCachedETag(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	_ = stop()

	brain.mu.Lock()
	brain.inm = nil
	brain.mu.Unlock()
	brain.delivered.Store(0)
	brain.notMod.Store(0)
	n2 := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stop2 := run(t, n2)
	waitFor(t, "the brain to be seen", func() bool { return !n2.Status().BrainSeen.IsZero() })
	if inm, ok := brain.firstINM(); !ok || inm != `"v1"` {
		t.Fatalf("first poll after restart presented %q, want the cached ETag", inm)
	}
	if brain.delivered.Load() != 0 || brain.notMod.Load() == 0 {
		t.Fatalf("restart re-delivered the document: delivered=%d 304s=%d", brain.delivered.Load(), brain.notMod.Load())
	}
	_ = stop2()
}

// A predecessor that installed a generation but died before recording its
// test is recovered: the generation is tested at startup.
func TestNodeRecoversAnUntestedGeneration(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	_ = stop()
	marker := filepath.Join(state, "conf", "gen-000001", ".kapkan-tested")
	if err := os.Remove(marker); err != nil {
		t.Fatalf("marker: %v", err)
	}

	tester := &fakeTester{}
	n2 := newNode(t, srv, state, sockets, tester, &fakeReloader{})
	stop2 := run(t, n2)
	waitFor(t, "recovery", func() bool { return n2.Status().Generation == 1 && tester.calls.Load() >= 1 })
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker not rewritten after recovery: %v", err)
	}
	if st := n2.Status(); !st.Healthy || !st.TestOK {
		t.Fatalf("status after recovery: %+v", st)
	}
	_ = stop2()

	// The untested generation FAILS its test on recovery: nothing of ours is
	// live, the node is unhealthy, and the cached document is applied afresh
	// only when the tester passes.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	bad := &fakeTester{}
	bad.failWith("nginx: [emerg] broken")
	n3 := newNode(t, srv, state, sockets, bad, &fakeReloader{})
	stop3 := run(t, n3)
	waitFor(t, "failed recovery", func() bool { return bad.calls.Load() >= 1 && n3.Status().LastError != "" })
	if st := n3.Status(); st.Healthy || st.Generation != 0 {
		t.Fatalf("status after a failed recovery: %+v", st)
	}
	resp, err := http.Get("http://" + statusAddr(t, n3) + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/healthz %d with nothing tested live", resp.StatusCode)
	}
	_ = stop3()
}

// A component that cannot start ends Run with ITS error, however the
// shutdown is scheduled — never a silent nil.
func TestNodeComponentFailureIsReported(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	for i := 0; i < 10; i++ {
		state, sockets := shortDirs(t)
		if err := os.MkdirAll(sockets, 0o755); err != nil {
			t.Fatal(err)
		}
		// Another process already serves the decision socket.
		squatter, err := net.Listen("unix", filepath.Join(sockets, "edge-decide.sock"))
		if err != nil {
			t.Fatal(err)
		}
		n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
		err = n.Run(context.Background())
		_ = squatter.Close()
		if err == nil || !strings.Contains(err.Error(), "decision service") || !strings.Contains(err.Error(), "already served") {
			t.Fatalf("run %d: Run returned %v, want the decision service's bind error", i, err)
		}
	}
}

// Redirects from the brain are never followed — a redirect would re-send the
// bearer wherever Location points.
func TestNodeNeverFollowsRedirects(t *testing.T) {
	var leaked atomic.Int64
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer leak.Close()
	brain := &fakeBrain{redirectReports: leak.URL}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	time.Sleep(350 * time.Millisecond) // several report ticks
	_ = stop()
	if leaked.Load() != 0 {
		t.Fatalf("the report followed a redirect %d times", leaked.Load())
	}
}

// selfSignedSet writes a certificate set the ACME store accepts: a
// self-signed ECDSA leaf for zone under certs/<zone>/1/ with `current`
// pointing at it. Returns the serial as the store reports it.
func selfSignedSet(t *testing.T, state, zone string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 80))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: zone}, DNSNames: []string{zone},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	gen := filepath.Join(state, "certs", zone, "1")
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(filepath.Join(gen, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, "meta.json"), []byte(`{"zone":"`+zone+`","directory":"https://ca.example/dir","issued_at":"2026-09-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1", filepath.Join(state, "certs", zone, "current")); err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(serial.Text(16))
}

// With ACME on and a certificate on disk, the zone renders its TLS server
// from the store's paths with the serial as the generation marker, and the
// report lists the certificate (never a key).
func TestNodeRendersHeldCertificatesAndReportsThem(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	serial := selfSignedSet(t, state, "example.com")
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.ACME = ACME{Directory: "http://127.0.0.1:1/never"} // never contacted: the certificate is fresh
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	zoneFile, err := os.ReadFile(filepath.Join(state, "conf", "live", "kapkan_zone_example.com.conf"))
	if err != nil {
		t.Fatal(err)
	}
	conf := string(zoneFile)
	if !strings.Contains(conf, "ssl_certificate     "+filepath.Join(state, "certs", "example.com", "current", "fullchain.pem")) ||
		!strings.Contains(conf, "ssl_certificate_key "+filepath.Join(state, "certs", "example.com", "current", "privkey.pem")) {
		t.Fatalf("zone file does not name the held certificate:\n%s", conf)
	}
	if !strings.Contains(conf, "# certificate serial "+serial) {
		t.Fatalf("zone file lacks the serial marker %s:\n%s", serial, conf)
	}
	waitFor(t, "a report with the certificate", func() bool { rep, ok := brain.lastReport(); return ok && len(rep.Certs) == 1 })
	rep, _ := brain.lastReport()
	if rep.Certs[0].Zone != "example.com" || rep.Certs[0].NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("reported certificate: %+v", rep.Certs[0])
	}
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "privkey") {
		t.Fatalf("report carries key material or key paths: %s", raw)
	}
	// The certificate hook re-renders through the same serialised path and
	// converges on an unchanged generation.
	n.onCertificate("example.com")
	if st := n.Status(); st.Generation != 1 || !st.Converged {
		t.Fatalf("status after a redundant re-render: %+v", st)
	}
	_ = stop()
}

// The report is cut to the brain's body limit, and says how much was cut.
func TestReportCertificateListIsBounded(t *testing.T) {
	brain := &fakeBrain{}
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	// 2000 certificates would be ~150 KiB; report() must fit 60 KiB.
	rep := api.EdgeReport{}
	for i := 0; i < 2000; i++ {
		rep.Certs = append(rep.Certs, api.EdgeReportCert{Zone: strings.Repeat("z", 20) + string(rune('a'+i%26)), NotAfter: time.Now(), Issuer: "R11"})
	}
	n.certs = nil
	got := n.report()
	if got.CertsTruncated != 0 || len(got.Certs) != 0 {
		t.Fatalf("no certificates yet: %+v", got)
	}
	// Exercise the trimming loop directly through a report with a long list.
	trimmed := trimReport(rep)
	body, _ := json.Marshal(trimmed)
	if len(body) > maxReportBytes || trimmed.CertsTruncated == 0 || len(trimmed.Certs)+trimmed.CertsTruncated != 2000 {
		t.Fatalf("trimmed report: %d bytes, %d certs, %d truncated", len(body), len(trimmed.Certs), trimmed.CertsTruncated)
	}
}

// The terminator-liveness check follows the pid file.
func TestTerminatorLiveness(t *testing.T) {
	brain := &fakeBrain{}
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(state, "nginx.pid")
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.Terminator.PIDFile = pidFile
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	// No pid file: not alive. Our own pid: alive. A pid nobody has: not alive.
	if alive := n.terminatorAlive(); alive == nil || *alive {
		t.Fatalf("missing pid file reported alive: %v", alive)
	}
	if err := os.WriteFile(pidFile, []byte(strings.TrimSpace(strings.Repeat(" ", 2)+itoa(os.Getpid())+"\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if alive := n.terminatorAlive(); alive == nil || !*alive {
		t.Fatal("own pid reported dead")
	}
	if err := os.WriteFile(pidFile, []byte("4194303\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if alive := n.terminatorAlive(); alive == nil || *alive {
		t.Fatal("a pid nobody has reported alive")
	}
	// Without a pid file configured there is no verdict at all.
	n.opt.Terminator.PIDFile = ""
	if n.terminatorAlive() != nil {
		t.Fatal("verdict without a pid file")
	}
}

func itoa(i int) string { return big.NewInt(int64(i)).String() }

func TestNodeRefusesBadOptions(t *testing.T) {
	_, sockets := shortDirs(t)
	cases := []struct {
		name string
		opt  Options
		want string
	}{
		{"no brain", Options{Name: "e1", StateDir: "/tmp/x", SocketsDir: sockets}, "brain URL"},
		{"relative dirs", Options{Brain: "http://b", Name: "e1", StateDir: "x", SocketsDir: sockets}, "absolute"},
		{"signal without pid", Options{Brain: "http://b", Name: "e1", StateDir: filepath.Dir(sockets), SocketsDir: sockets, ACME: ACME{Disabled: true}, Terminator: Terminator{Reload: ReloadSignal}}, "pid_file"},
		{"unknown reload", Options{Brain: "http://b", Name: "e1", StateDir: filepath.Dir(sockets), SocketsDir: sockets, ACME: ACME{Disabled: true}, Terminator: Terminator{Reload: "magic"}}, "unknown terminator.reload"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.opt); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

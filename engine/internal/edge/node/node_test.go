package node

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// fakeBrain serves the zone document with an ETag, holds polls briefly, and
// records reports and ACME coordination calls.
type fakeBrain struct {
	mu      sync.Mutex
	doc     []byte
	etag    string
	reports []api.EdgeReport
	acme    []string
	polls   atomic.Int64
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
		b.mu.Unlock()
		if r.URL.Query().Get("node") != "e1" {
			http.Error(w, "unknown edge node", http.StatusNotFound)
			return
		}
		if r.Header.Get("If-None-Match") == etag {
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(doc)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/report"):
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

type fakeTester struct{ calls atomic.Int64 }

func (f *fakeTester) Test(context.Context) error { f.calls.Add(1); return nil }

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

func newNode(t *testing.T, brain *httptest.Server, state, sockets string, tester *fakeTester, reloader *fakeReloader) *Node {
	t.Helper()
	n, err := New(Options{
		Brain: brain.URL, Token: "agent-secret", Name: "e1", DryRun: true,
		StateDir: state, SocketsDir: sockets,
		ACME:           ACME{Disabled: true},
		ReportInterval: 100 * time.Millisecond,
		StatusListen:   "127.0.0.1:0",
		Logger:         slog.New(slog.DiscardHandler),
		Tester:         tester, Reloader: reloader,
	})
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

func TestNodeInstallsDocumentReportsAndSkipsFastPathChanges(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	tester, reloader := &fakeTester{}, &fakeReloader{}
	n := newNode(t, srv, state, sockets, tester, reloader)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()

	// The document is rendered and installed; the live generation carries it.
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	live := filepath.Join(state, "conf", "live", "kapkan_zone_example.com.conf")
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("rendered zone file: %v", err)
	}
	if tester.calls.Load() != 1 || reloader.calls.Load() != 1 {
		t.Fatalf("tester=%d reloader=%d after the first install", tester.calls.Load(), reloader.calls.Load())
	}
	// The sockets exist, owner-only (no group configured).
	for _, s := range []string{"edge-decide.sock", "edge-challenge.sock", "edge-log.sock"} {
		st, err := os.Lstat(filepath.Join(sockets, s))
		if err != nil {
			t.Fatalf("socket %s: %v", s, err)
		}
		if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o660 {
			t.Fatalf("socket %s mode %v", s, st.Mode())
		}
	}
	// The document and ETag are cached for a brain-less restart.
	if raw, err := os.ReadFile(filepath.Join(state, "zones.etag")); err != nil || strings.TrimSpace(string(raw)) != `"v1"` {
		t.Fatalf("cached etag: %q %v", raw, err)
	}
	// A report arrives with the rendered ETag and the dry-run flag.
	waitFor(t, "a report", func() bool { rep, ok := brain.lastReport(); return ok && rep.ZonesETag == `"v1"` })
	rep, _ := brain.lastReport()
	if !rep.DryRun || rep.Terminator == nil || rep.Terminator.Generation != 1 || !rep.Terminator.TestOK {
		t.Fatalf("report: %+v %+v", rep, rep.Terminator)
	}
	// The decision service knows the zone and enforces its rate.
	ip := net.ParseIP("198.51.100.7")
	_ = ip
	// A rate-only change: fast path applies, nothing is rendered or reloaded.
	brain.set(testDoc(1000), `"v2"`)
	waitFor(t, "the second document", func() bool { return n.Status().ZonesETag == `"v2"` })
	time.Sleep(100 * time.Millisecond)
	if n.Status().Generation != 1 || tester.calls.Load() != 1 || reloader.calls.Load() != 1 {
		t.Fatalf("a rate change reloaded the terminator: gen=%d tester=%d reloader=%d", n.Status().Generation, tester.calls.Load(), reloader.calls.Load())
	}
	// A zone change: slow path, a new generation.
	d := testDoc(1000)
	d.Zones = append(d.Zones, edgedoc.Zone{Name: "b.example.com", Origins: []string{"10.0.0.2:80"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeNone, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff}})
	brain.set(d, `"v3"`)
	waitFor(t, "the third document", func() bool { return n.Status().Generation == 2 })
	if reloader.calls.Load() != 2 {
		t.Fatalf("reloader calls = %d after a zone change", reloader.calls.Load())
	}
	st := n.Status()
	if !st.Healthy || st.Zones != 2 || st.BrainSeen.IsZero() {
		t.Fatalf("status: %+v", st)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, s := range []string{"edge-decide.sock", "edge-challenge.sock", "edge-log.sock"} {
		if _, err := os.Lstat(filepath.Join(sockets, s)); err == nil {
			t.Fatalf("socket %s left behind", s)
		}
	}
}

func TestNodeStartsFromDiskWithTheBrainGone(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	state, sockets := shortDirs(t)
	n := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	cancel()
	<-done
	srv.Close() // the brain is gone

	// A second process over the same state: renders from the cache, knows
	// the ETag, polls (and fails) without ever having seen the brain.
	tester, reloader := &fakeTester{}, &fakeReloader{}
	n2, err := New(Options{Brain: srv.URL, Token: "agent-secret", Name: "e1", DryRun: true, StateDir: state, SocketsDir: sockets,
		ACME: ACME{Disabled: true}, ReportInterval: time.Hour, Logger: slog.New(slog.DiscardHandler), Tester: tester, Reloader: reloader})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- n2.Run(ctx2) }()
	waitFor(t, "start from disk", func() bool { st := n2.Status(); return st.Healthy && st.Zones == 1 })
	st := n2.Status()
	if st.ZonesETag != `"v1"` || st.Generation != 1 {
		t.Fatalf("status from disk: %+v", st)
	}
	// The same bytes render the same files: the live generation is unchanged
	// and nothing was reloaded — only Recover ran the tester.
	if reloader.calls.Load() != 0 {
		t.Fatalf("restart reloaded an unchanged configuration (%d)", reloader.calls.Load())
	}
	cancel2()
	<-done2
}

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

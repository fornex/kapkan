package node

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// getHealthz fetches /healthz once: the status code, the status it carries
// and the raw body for failure messages.
func getHealthz(t *testing.T, addr string) (int, Status, string) {
	t.Helper()
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var st Status
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("/healthz %d %q: %v", resp.StatusCode, body, err)
	}
	return resp.StatusCode, st, strings.TrimSpace(string(body))
}

// deadPID is the pid of a child that has exited and been reaped: signal 0
// finds nobody there. A fixed number promises nothing of the kind — 4194303,
// which these tests used, is the last pid a Linux with pid_max 4194304
// (systemd's default) hands out. Pids are handed out in a rising cycle, so a
// reaped one comes back only after the whole range has wrapped, not within a
// test.
func deadPID(t *testing.T) int {
	t.Helper()
	child := exec.Command("true")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the reaped child's pid %d still answers signal 0: %v", pid, err)
	}
	return pid
}

// E7.0: the first /healthz a node answers has looked at the terminator. The
// pid used to be sampled first on the report tick, a whole report interval
// after the status listener came up, and /healthz answered 200 meanwhile on a
// box whose nginx was dead. Here the node is otherwise healthy before its
// listener exists — the cached document applies during start-from-disk, so
// the generation and the document are in place — and the pid file names a
// reaped child: the 503 can only be the terminator's.
//
// The first answer alone does not pin the order the fix rests on, the sample
// before the status listener: a sample taken just after the listener's
// spawn, or first thing on the liveness ticker's goroutine, still lands
// before a client's first GET. So the pid file starts as a FIFO, the first
// sample blocks reading it until the test writes the pid, and meanwhile no
// status listener may exist.
func TestFirstHealthzHasLookedAtTheTerminator(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	// A first process installs the document and caches it.
	first := newNode(t, srv, state, sockets, &fakeTester{}, &fakeReloader{})
	stopFirst := run(t, first)
	waitFor(t, "first install", func() bool { return first.Status().Generation == 1 })
	if err := stopFirst(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The restart. An hour's report interval: no report tick samples the pid
	// while the test runs.
	dead := []byte(strconv.Itoa(deadPID(t)) + "\n")
	pidFile := filepath.Join(state, "nginx.pid")
	if err := syscall.Mkfifo(pidFile, 0o600); err != nil {
		t.Fatal(err)
	}
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.Terminator.PIDFile = pidFile
	opt.ReportInterval = time.Hour
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	// A FIFO's write end opens only once a reader holds the other end: the
	// first sample is then under way, and it reads until the write end
	// closes.
	var w *os.File
	waitFor(t, "the first pid sample to open the pid file", func() bool {
		f, err := os.OpenFile(pidFile, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if errors.Is(err, syscall.ENXIO) {
			return false // no reader yet
		}
		if err != nil {
			t.Fatal(err)
		}
		w = f
		return true
	})
	defer func() { _ = w.Close() }() // before stop: a sample still reading gets its EOF
	// The first sample already holds the FIFO; every later one finds a
	// regular file naming the same pid, and never blocks.
	if err := os.WriteFile(pidFile+".next", dead, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pidFile+".next", pidFile); err != nil {
		t.Fatal(err)
	}
	// The first sample is parked on the FIFO. A status listener started
	// before it or beside it binds well within the 300 ms watched here; one
	// started after it cannot exist yet.
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if addr := n.StatusAddr(); addr != "" {
			code, _, body := getHealthz(t, addr)
			t.Fatalf("the status listener was up while the first pid sample was still reading the pid file: /healthz %d %s", code, body)
		}
	}
	if _, err := w.Write(dead); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	code, st, body := getHealthz(t, statusAddr(t, n))
	if code != http.StatusServiceUnavailable || st.Healthy || st.TerminatorAlive == nil || *st.TerminatorAlive {
		t.Fatalf("first /healthz with the terminator dead: %d %s; want 503 with terminator_alive:false", code, body)
	}
	if st.Generation != 1 || !st.TestOK || st.Zones != 1 || st.ZonesETag != `"v1"` {
		t.Fatalf("the node was not otherwise healthy at its first /healthz: %s", body)
	}
}

// E7.0: /healthz follows the terminator on a ticker of its own. The pid used
// to be sampled on the report tick, which waits on the report: a brain that
// never answers held a dead nginx at 200 for the client's 30 s timeout. Here
// the brain takes every report and answers none, the report interval is
// short so the report loop sits inside its first post, and the terminator — a
// real process the pid file names — is killed: /healthz must say 503 within
// 1.5 s.
func TestHealthzSeesTheTerminatorDieWhileAReportHangs(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(testDoc(10), `"v1"`)
	release := make(chan struct{})
	var held atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/report") {
			held.Add(1)
			// Never answered: held until the node hangs up or the test ends.
			// The body is read to its end first: net/http starts watching
			// the connection for the client hanging up only once the body is
			// consumed, so unread it would never cancel r.Context().
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		brain.ServeHTTP(w, r)
	}))
	defer srv.Close()
	defer close(release) // runs first: Close waits for the held handlers

	terminator := exec.Command("sleep", "60")
	if err := terminator.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = terminator.Process.Kill(); _ = terminator.Wait() }()
	state, sockets := shortDirs(t)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(state, "nginx.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(terminator.Process.Pid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.Terminator.PIDFile = pidFile
	opt.ReportInterval = 100 * time.Millisecond // the first report goes out at once, and hangs
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	defer func() {
		if err := stop(); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	addr := statusAddr(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	waitFor(t, "a report the brain holds", func() bool { return held.Load() > 0 })
	// The first answer is TestFirstHealthzHasLookedAtTheTerminator's; this
	// test starts from a node that has seen its terminator up.
	waitFor(t, "/healthz 200 with the terminator seen alive", func() bool {
		code, st, _ := getHealthz(t, addr)
		return code == http.StatusOK && st.TerminatorAlive != nil && *st.TerminatorAlive
	})

	// The terminator dies and its pid file stays behind, as after a crash.
	if err := terminator.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = terminator.Wait() // reaped, so signal 0 finds nobody
	died := time.Now()
	for {
		code, st, body := getHealthz(t, addr)
		if code == http.StatusServiceUnavailable {
			if st.TerminatorAlive == nil || *st.TerminatorAlive {
				t.Fatalf("503, but not for the terminator: %s", body)
			}
			t.Logf("/healthz 503 %v after the terminator died", time.Since(died).Round(time.Millisecond))
			break
		}
		if since := time.Since(died); since > 1500*time.Millisecond {
			t.Fatalf("/healthz still %d %v after the terminator died, %d report(s) held by the brain: %s", code, since.Round(time.Millisecond), held.Load(), body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The report loop never got past its first post, so the 503 is not a
	// report tick's doing.
	if h := held.Load(); h != 1 {
		t.Fatalf("the brain received %d reports; the report loop was not stuck in its first post", h)
	}
}

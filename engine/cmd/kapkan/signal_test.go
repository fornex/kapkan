package main

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPIDFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kapkan.pid")
	if err := writePIDFile(path); err != nil {
		t.Fatalf("writePIDFile: %v", err)
	}
	pid, err := readPIDFile(path)
	if err != nil {
		t.Fatalf("readPIDFile: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("round-trip pid = %d, want %d", pid, os.Getpid())
	}
	// No .tmp residue is left behind after the atomic rename.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file not cleaned up: stat err = %v", err)
	}
}

func TestReadPIDFileErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := readPIDFile(filepath.Join(dir, "absent.pid")); !os.IsNotExist(err) {
		t.Errorf("missing file err = %v, want IsNotExist", err)
	}

	for _, body := range []string{"abc", "", "-1", "0", "12x"} {
		p := filepath.Join(dir, "bad.pid")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPIDFile(p); err == nil {
			t.Errorf("readPIDFile(%q) = nil error, want malformed", body)
		}
	}
}

func TestProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Error("processAlive(self) = false, want true")
	}
	if alive := processAlive(deadPID(t)); alive {
		t.Error("processAlive(reaped child) = true, want false")
	}
}

func TestRunSignalCommandSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kapkan.pid")
	if err := writePIDFile(path); err != nil { // our own (live) pid
		t.Fatal(err)
	}

	var gotPID int
	var gotSig syscall.Signal
	orig := sendSignal
	sendSignal = func(pid int, sig syscall.Signal) error { gotPID, gotSig = pid, sig; return nil }
	t.Cleanup(func() { sendSignal = orig })

	cases := map[string]syscall.Signal{
		"reload": syscall.SIGHUP,
		"stop":   syscall.SIGTERM,
		"quit":   syscall.SIGTERM,
	}
	for name, want := range cases {
		gotPID, gotSig = 0, 0
		if err := runSignalCommand(name, path); err != nil {
			t.Errorf("runSignalCommand(%q) = %v", name, err)
			continue
		}
		if gotPID != os.Getpid() || gotSig != want {
			t.Errorf("runSignalCommand(%q) sent (pid=%d,sig=%v), want (pid=%d,sig=%v)",
				name, gotPID, gotSig, os.Getpid(), want)
		}
	}
}

func TestRunSignalCommandUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kapkan.pid")
	if err := writePIDFile(path); err != nil {
		t.Fatal(err)
	}
	err := runSignalCommand("restart", path)
	if err == nil || !strings.Contains(err.Error(), "unknown signal") {
		t.Errorf("runSignalCommand(unknown) = %v, want 'unknown signal' error", err)
	}
}

func TestRunSignalCommandNotRunning(t *testing.T) {
	// Missing pid file: the daemon is not running.
	err := runSignalCommand("reload", filepath.Join(t.TempDir(), "absent.pid"))
	if err == nil || !strings.Contains(err.Error(), "not appear to be running") {
		t.Errorf("no pid file: err = %v, want 'not appear to be running'", err)
	}

	// Stale pid file: a pid that no longer exists.
	path := filepath.Join(t.TempDir(), "stale.pid")
	if err := os.WriteFile(path, []byte(strconv.Itoa(deadPID(t))), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runSignalCommand("reload", path); err == nil || !strings.Contains(err.Error(), "stale pid file") {
		t.Errorf("stale pid: err = %v, want 'stale pid file'", err)
	}
}

// The roles' signal handling under each role's name: SIGHUP is logged and
// ignored, SIGTERM still stops the role, and a SIGHUP after that is still
// ignored until stop. Running scrub whole needs an XDP-capable host for its
// data plane, so scrub is checked here and, for a SIGHUP while that data plane
// loads, by TestScrubRoleIgnoresSIGHUPWhileTheDataPlaneLoads; edge and
// nginx-exporter are also run whole by their own tests.
func TestRoleSignalsIgnoreSIGHUP(t *testing.T) {
	for _, role := range []string{"scrub", "edge", "nginx-exporter"} {
		t.Run(role, func(t *testing.T) {
			var logs syncBuffer
			ctx, stop := roleSignals(role, slog.New(slog.NewTextHandler(&logs, nil)))
			defer stop()
			done := make(chan error, 1)
			go func() { <-ctx.Done(); done <- nil }()

			hupIgnored(t, role, &logs, done)
			termStops(t, role, done)
			// Cancelled but not yet stopped is where a role runs its own
			// shutdown (scrub's on_exit, the edge node's finish): a SIGHUP
			// there must still be ignored, not end the process.
			raise(t, syscall.SIGHUP)
			logs.waitFor(t, "SIGHUP ignored: the "+role+" role has no reload; restart the unit to change its configuration", 3)
			stop() // and again by the defer: stop is idempotent
		})
	}
}

// hupIgnored sends this test binary two SIGHUPs — real ones, so a role that
// left the signal unhandled kills the whole binary — and requires a line for
// each and a role still running after each: done, which carries the role's
// return, must stay silent.
func hupIgnored(t *testing.T, role string, logs *syncBuffer, done <-chan error) {
	t.Helper()
	line := "SIGHUP ignored: the " + role + " role has no reload; restart the unit to change its configuration"
	for n := 1; n <= 2; n++ {
		raise(t, syscall.SIGHUP)
		logs.waitFor(t, line, n)
		select {
		case err := <-done:
			t.Fatalf("the %s role returned after SIGHUP (err %v)", role, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// termStops sends this test binary SIGTERM and requires the role to return
// without an error.
func termStops(t *testing.T, role string, done <-chan error) {
	t.Helper()
	raise(t, syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the %s role failed on SIGTERM: %v", role, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the %s role did not stop on SIGTERM", role)
	}
}

func raise(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("raise %v: %v", sig, err)
	}
}

// syncBuffer collects a logger's output for a test that reads it while the
// role is still writing.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor waits until want has been written at least n times.
func (s *syncBuffer) waitFor(t *testing.T, want string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(s.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q ×%d; the log so far:\n%s", want, n, s.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// deadPID starts a short-lived child, waits for it to exit, and returns its now
// reaped (and therefore non-existent) pid — a deterministic stand-in for a
// stale pid file without racing on an arbitrary number.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	_ = cmd.Wait() // reap; ignores the expected "signal: killed" error
	return pid
}

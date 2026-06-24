package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
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

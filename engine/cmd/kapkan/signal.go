// nginx-style process control: `kapkan -s reload|stop|quit`. The running daemon
// records its pid in a file on startup (see run()); this side reads that file
// and delivers the signal the daemon already handles — SIGHUP hot-reloads the
// config, SIGTERM shuts down gracefully. It is a thin, local-only wrapper over
// kill(2): no network, no API token, works even if the REST API is down, and
// the muscle memory of `nginx -s reload` carries straight over.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// signalActions maps the -s argument to the signal kapkan handles in run().
// "stop" and "quit" are aliases: kapkan's shutdown is always graceful (it asks
// BGP peers to retain mitigation routes via Graceful Restart), so there is no
// separate fast-quit signal to distinguish them.
var signalActions = map[string]syscall.Signal{
	"reload": syscall.SIGHUP,
	"stop":   syscall.SIGTERM,
	"quit":   syscall.SIGTERM,
}

// signalNames is the stable, human-facing list of accepted -s arguments.
const signalNames = "reload|stop|quit"

// writePIDFile records the current process id at path so `kapkan -s` can find
// the running daemon. The write is atomic (temp file + rename) so a concurrent
// reader never observes a half-written or empty file.
func writePIDFile(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// readPIDFile reads and parses the pid stored at path.
func readPIDFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	raw := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("malformed pid file %s: %q", path, raw)
	}
	return pid, nil
}

// processAlive reports whether a process with the given pid currently exists.
// Signal 0 does the kernel's existence/permission check without delivering a
// signal: nil means alive; EPERM means alive but owned by another user; ESRCH
// means gone (a stale pid file from a crashed or reaped instance).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// sendSignal delivers sig to pid. It is a package var so tests can substitute a
// recorder and avoid actually signalling (and killing) the test runner.
var sendSignal = func(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// runSignalCommand implements `kapkan -s <name>`: resolve the running daemon
// from its pid file and deliver the mapped signal. It returns a human-readable
// error (nil on success); main turns that into the process exit code.
func runSignalCommand(name, pidPath string) error {
	sig, ok := signalActions[name]
	if !ok {
		return fmt.Errorf("unknown signal %q (want one of: %s)", name, signalNames)
	}
	pid, err := readPIDFile(pidPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("kapkan does not appear to be running: no pid file at %s", pidPath)
		}
		return err
	}
	if !processAlive(pid) {
		return fmt.Errorf("stale pid file %s: no process %d — kapkan not running?", pidPath, pid)
	}
	if err := sendSignal(pid, sig); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("not permitted to signal pid %d — run as root or the kapkan user", pid)
		}
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	return nil
}

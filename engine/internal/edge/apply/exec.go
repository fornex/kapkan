package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Default timeouts for the two terminator commands. A config test on a large
// zone set takes well under a second; the bounds exist so a hung binary cannot
// hold the applier's lock forever.
const (
	DefaultTestTimeout   = 30 * time.Second
	DefaultReloadTimeout = 30 * time.Second

	// maxToolOutput bounds how much of the terminator's stderr is carried in an
	// error (and so into a report field). `nginx -t` names the file and line
	// in its first [emerg] line; the rest is context.
	maxToolOutput = 4 << 10
)

// ExecTester runs `<Binary> -t [-c MainConf]`. The stderr of a failed test is
// the error message — that is where nginx names the offending file and line.
type ExecTester struct {
	// Binary is the terminator executable; "" means "nginx" on PATH. Angie
	// installs as "angie".
	Binary string
	// MainConf is passed as -c; "" uses the binary's compiled-in default.
	MainConf string
	// Timeout bounds the test; 0 means DefaultTestTimeout.
	Timeout time.Duration
}

// Test implements Tester.
func (t ExecTester) Test(ctx context.Context) error {
	args := []string{"-t"}
	if t.MainConf != "" {
		args = append(args, "-c", t.MainConf)
	}
	return runTool(ctx, binaryOr(t.Binary), args, t.Timeout, DefaultTestTimeout)
}

// ExecReloader runs `<Binary> -s reload [-c MainConf]`. With a non-default
// main config the -c is required: the binary reads it to find the pid file.
type ExecReloader struct {
	Binary   string
	MainConf string
	Timeout  time.Duration
}

// Reload implements Reloader.
func (r ExecReloader) Reload(ctx context.Context) error {
	args := []string{"-s", "reload"}
	if r.MainConf != "" {
		args = append(args, "-c", r.MainConf)
	}
	return runTool(ctx, binaryOr(r.Binary), args, r.Timeout, DefaultReloadTimeout)
}

// SignalReloader sends SIGHUP to the pid in PIDFile — what `nginx -s reload`
// does, without needing the binary or its config. For deployments where the
// terminator's pid file is the documented interface.
type SignalReloader struct {
	PIDFile string
}

// Reload implements Reloader.
func (r SignalReloader) Reload(_ context.Context) error {
	raw, err := os.ReadFile(r.PIDFile)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return fmt.Errorf("reload: %s does not hold a pid", r.PIDFile)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("reload: signal pid %d: %w", pid, err)
	}
	return nil
}

// Probe asks the binary for its kind and version (`nginx -v` prints
// "nginx version: nginx/1.26.2"; Angie prints "Angie version: Angie/1.6.2"),
// for the node's report. Kind is lower-case: "nginx" or "angie".
func Probe(ctx context.Context, binary string) (kind, version string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, binaryOr(binary), "-v")
	c.WaitDelay = time.Second
	out, err := c.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("%s -v: %w: %s", binaryOr(binary), err, tail(out))
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	before, after, ok := strings.Cut(line, "version:")
	if !ok {
		return "", "", fmt.Errorf("%s -v: unrecognised output %q", binaryOr(binary), line)
	}
	kind = strings.ToLower(strings.TrimSpace(before))
	if i := strings.LastIndex(after, "/"); i >= 0 {
		after = after[i+1:]
	}
	// Distro builds append their --build name: "nginx/1.24.0 (Ubuntu)".
	version, _, _ = strings.Cut(strings.TrimSpace(after), " ")
	if kind == "" || version == "" {
		return "", "", fmt.Errorf("%s -v: unrecognised output %q", binaryOr(binary), line)
	}
	return kind, version, nil
}

func binaryOr(b string) string {
	if b == "" {
		return "nginx"
	}
	return b
}

func runTool(ctx context.Context, binary string, args []string, timeout, def time.Duration) error {
	if timeout <= 0 {
		timeout = def
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(ctx, binary, args...)
	// A killed nginx may leave a child holding the output pipe (a shell wrapper
	// does, and so would a helper it spawned); without WaitDelay, Wait would
	// block on that pipe until the grandchild exits and the timeout would be
	// a fiction. One second after the kill the pipes are closed regardless.
	c.WaitDelay = time.Second
	out, err := c.CombinedOutput()
	if err != nil {
		cmd := binary + " " + strings.Join(args, " ")
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s: timed out after %s: %s", cmd, timeout, tail(out))
		}
		return fmt.Errorf("%s: %w: %s", cmd, err, tail(out))
	}
	return nil
}

// tail keeps the end of a tool's output, trimmed, bounded by maxToolOutput.
func tail(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > maxToolOutput {
		s = "…" + s[len(s)-maxToolOutput:]
	}
	return s
}

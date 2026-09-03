package apply

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeBinary writes a shell script standing in for nginx/angie.
func fakeBinary(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nginx")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecTesterPassesArgsAndReportsStderr(t *testing.T) {
	bin := fakeBinary(t, `echo "args: $*" >&2
echo 'nginx: [emerg] unknown directive "bogus" in /var/lib/kapkan/edge/conf/live/kapkan_zone_a.conf:7' >&2
echo 'nginx: configuration file /etc/nginx/nginx.conf test failed' >&2
exit 1`)
	err := ExecTester{Binary: bin, MainConf: "/etc/nginx/nginx.conf"}.Test(context.Background())
	if err == nil {
		t.Fatal("failing test reported success")
	}
	for _, want := range []string{"args: -t -c /etc/nginx/nginx.conf", "unknown directive", "kapkan_zone_a.conf:7", "exit status 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestExecTesterSucceedsQuietly(t *testing.T) {
	bin := fakeBinary(t, `case "$*" in "-t") exit 0;; *) echo "bad args: $*" >&2; exit 2;; esac`)
	if err := (ExecTester{Binary: bin}).Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestExecTesterTimesOut(t *testing.T) {
	bin := fakeBinary(t, `sleep 5`)
	start := time.Now()
	err := ExecTester{Binary: bin, Timeout: 100 * time.Millisecond}.Test(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestExecReloaderArgs(t *testing.T) {
	bin := fakeBinary(t, `case "$*" in "-s reload -c /etc/angie/angie.conf") exit 0;; *) echo "bad args: $*" >&2; exit 2;; esac`)
	if err := (ExecReloader{Binary: bin, MainConf: "/etc/angie/angie.conf"}).Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if err := (ExecReloader{Binary: bin}).Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "bad args: -s reload") {
		t.Fatalf("err = %v", err)
	}
}

func TestProbe(t *testing.T) {
	cases := []struct {
		out, kind, version string
	}{
		{"nginx version: nginx/1.22.1", "nginx", "1.22.1"},
		{"nginx version: nginx/1.26.2\nbuilt by gcc 12.2.0", "nginx", "1.26.2"},
		{"nginx version: nginx/1.24.0 (Ubuntu)", "nginx", "1.24.0"},
		{"Angie version: Angie/1.6.2", "angie", "1.6.2"},
	}
	for _, c := range cases {
		bin := fakeBinary(t, `printf '%s\n' "`+c.out+`" >&2`)
		kind, version, err := Probe(context.Background(), bin)
		if err != nil || kind != c.kind || version != c.version {
			t.Errorf("Probe(%q) = %q %q %v", c.out, kind, version, err)
		}
	}
	bin := fakeBinary(t, `echo "something else" >&2`)
	if _, _, err := Probe(context.Background(), bin); err == nil {
		t.Fatal("unrecognised output accepted")
	}
}

func TestSignalReloader(t *testing.T) {
	got := make(chan os.Signal, 1)
	signal.Notify(got, syscall.SIGHUP)
	defer signal.Stop(got)

	pidFile := filepath.Join(t.TempDir(), "nginx.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (SignalReloader{PIDFile: pidFile}).Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP not delivered")
	}

	if err := (SignalReloader{PIDFile: filepath.Join(t.TempDir(), "missing")}).Reload(context.Background()); err == nil {
		t.Fatal("missing pid file accepted")
	}
	bad := filepath.Join(t.TempDir(), "bad.pid")
	_ = os.WriteFile(bad, []byte("not-a-pid\n"), 0o644)
	if err := (SignalReloader{PIDFile: bad}).Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "does not hold a pid") {
		t.Fatalf("err = %v", err)
	}
}

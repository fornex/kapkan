package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/app"
	"github.com/kapkan-io/kapkan/internal/config"
)

// daemonYAML is a dry-run daemon on loopback with no BGP listener, neighbours
// or storage: enough for run() to come up and go down inside a test.
func daemonYAML(pps, sflowPort, apiPort int) string {
	return fmt.Sprintf(`dry_run: true
listen:
  sflow: "127.0.0.1:%d"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
thresholds:
  pps: %d
  mbps: 100
  flows_per_sec: 1000
ban:
  ttl_seconds: 300
  unban_hysteresis_seconds: 60
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:%d"
`, sflowPort, pps, apiPort)
}

// A reload that lands while the daemon is still starting — `systemctl reload`
// right after a start, `kapkan -s reload` as soon as the pid file exists — must
// neither kill the daemon nor be lost. Startup is held open at app.New, after
// the pid file is written, and the reload is sent there through the real
// `kapkan -s reload` path: a real SIGHUP to this test binary, which it kills
// while the signal is unhandled.
func TestReloadDuringStartupIsAppliedOnceUp(t *testing.T) {
	dir := t.TempDir()
	cfgPath, pidPath := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "kapkan.pid")
	sflowPort, apiPort := freePort(t, "udp"), freePort(t, "tcp")
	writeConfig := func(pps int) {
		t.Helper()
		if err := os.WriteFile(cfgPath, []byte(daemonYAML(pps, sflowPort, apiPort)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(1000)

	entered, release := make(chan *config.Store, 1), make(chan struct{})
	orig := newApp
	newApp = func(store *config.Store, log *slog.Logger) (*app.App, error) {
		entered <- store
		<-release
		return orig(store, log)
	}
	t.Cleanup(func() { newApp = orig })

	done := make(chan error, 1)
	go func() { done <- run(cfgPath, pidPath, slog.New(slog.DiscardHandler)) }()
	var store *config.Store
	select {
	case store = <-entered:
	case err := <-done:
		t.Fatalf("run returned before startup reached app.New: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("startup never reached app.New")
	}

	// Mid-startup, pid file written: the operator edits the file and reloads.
	writeConfig(2000)
	if err := runSignalCommand("reload", pidPath); err != nil {
		t.Fatalf("kapkan -s reload: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // ample for an unhandled SIGHUP to end this binary
	close(release)

	// Once the daemon is up, the reload that waited is applied.
	deadline := time.Now().Add(10 * time.Second)
	for store.Get().Thresholds.PPS != 2000 {
		if time.Now().After(deadline) {
			t.Fatalf("the reload sent during startup was lost: thresholds.pps = %d", store.Get().Thresholds.PPS)
		}
		select {
		case err := <-done:
			t.Fatalf("run returned before the reload was applied: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}

	// `kapkan -s stop` still shuts it down cleanly, and the pid file goes with it.
	if err := runSignalCommand("stop", pidPath); err != nil {
		t.Fatalf("kapkan -s stop: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon did not stop on SIGTERM")
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("pid file left behind after a clean stop: %v", err)
	}
}

// A reload and then a stop, both while the daemon is still starting: the stop
// wins, and the reload that waited in hup is never applied, least of all
// alongside the shutdown. Go's select picks at random between two ready cases,
// so a loop that let the reload race the stop would apply it about half the
// time; the scenario runs several times to make that visible.
func TestStopDuringStartupDropsAWaitingReload(t *testing.T) {
	for i := 0; i < 6; i++ {
		dir := t.TempDir()
		cfgPath, pidPath := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "kapkan.pid")
		sflowPort, apiPort := freePort(t, "udp"), freePort(t, "tcp")
		write := func(pps int) {
			t.Helper()
			if err := os.WriteFile(cfgPath, []byte(daemonYAML(pps, sflowPort, apiPort)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write(1000)

		entered, release := make(chan *config.Store, 1), make(chan struct{})
		orig := newApp
		newApp = func(store *config.Store, log *slog.Logger) (*app.App, error) {
			entered <- store
			<-release
			return orig(store, log)
		}

		done := make(chan error, 1)
		go func() { done <- run(cfgPath, pidPath, slog.New(slog.DiscardHandler)) }()
		var store *config.Store
		select {
		case store = <-entered:
		case err := <-done:
			newApp = orig
			t.Fatalf("run %d returned before startup reached app.New: %v", i, err)
		case <-time.After(10 * time.Second):
			newApp = orig
			t.Fatalf("run %d: startup never reached app.New", i)
		}

		write(2000)
		if err := runSignalCommand("reload", pidPath); err != nil {
			t.Fatalf("run %d: kapkan -s reload: %v", i, err)
		}
		if err := runSignalCommand("stop", pidPath); err != nil {
			t.Fatalf("run %d: kapkan -s stop: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond) // both signals delivered before startup resumes
		close(release)

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("run %d: the daemon did not stop", i)
		}
		newApp = orig
		time.Sleep(200 * time.Millisecond) // a reload racing the shutdown would have landed by now
		if got := store.Get().Thresholds.PPS; got != 1000 {
			t.Fatalf("run %d: the reload sent before the stop was applied (thresholds.pps = %d)", i, got)
		}
	}
}

// An API listener that cannot serve (its address taken) ends the daemon with
// an error, so main exits 1 and systemd's Restart=on-failure brings it back.
// It used to return nil: exit 0, a deliberate stop to systemd, and the daemon
// stayed down. The bind fails after Start has returned, on the API's own
// goroutine, which is why this is not a Start error.
func TestAPIListenerFailureEndsRunWithAnError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	yaml := daemonYAML(1000, freePort(t, "udp"), busy.Addr().(*net.TCPAddr).Port)
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- run(cfgPath, "", slog.New(slog.DiscardHandler)) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "api server") {
			t.Fatalf("run = %v, want the API server's error", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after its API listener failed")
	}
}

// freePort returns a loopback port that was free a moment ago.
func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

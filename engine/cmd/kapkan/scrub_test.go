package main

import (
	"bytes"
	"errors"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
)

// The scrub role takes its signals before its data plane loads, and an XDP
// attach can take seconds: a SIGHUP that lands mid-load must be ignored like
// any other. openDataplane stands in for the load, which needs an XDP-capable
// host, and raises a real SIGHUP from inside it, so a handler installed only
// after the load kills the whole test binary.
func TestScrubRoleIgnoresSIGHUPWhileTheDataPlaneLoads(t *testing.T) {
	sc, err := config.ParseScrub([]byte("controller:\n  url: \"https://kapkan.example.net:8443\"\n  token_env: KAPKAN_TEST_SCRUB_TOKEN\n  name: scrub-fra1\ndataplane:\n  interfaces: [eth0]\n"))
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	orig := openDataplane
	t.Cleanup(func() { openDataplane = orig })
	openDataplane = func(dataplane.Options) (*dataplane.Manager, error) {
		raise(t, syscall.SIGHUP)
		logs.waitFor(t, "SIGHUP ignored: the scrub role has no reload", 1)
		return nil, errors.New("stub: no XDP here")
	}
	err = runScrubAgent(sc, "tok", slog.New(slog.NewTextHandler(&logs, nil)))
	if err == nil || !strings.Contains(err.Error(), "stub: no XDP here") {
		t.Fatalf("runScrubAgent = %v, want the stub's error", err)
	}
}

func runScrubCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	f, err := parseFlags("kapkan", append([]string{"scrub"}, args...), flag.ContinueOnError)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	var out, errOut bytes.Buffer
	code := runSubcommand(f, &out, &errOut)
	return code, errOut.String()
}

func TestScrubCommandRejections(t *testing.T) {
	// A missing config file is a clean, named failure.
	code, msg := runScrubCLI(t, "-config", filepath.Join(t.TempDir(), "absent.yaml"))
	if code != 1 || !strings.Contains(msg, "read scrub config") {
		t.Fatalf("missing config: code=%d msg=%q", code, msg)
	}

	// An unexpected positional argument is a usage error.
	code, msg = runScrubCLI(t, "extra")
	if code != exitUsage || !strings.Contains(msg, "unexpected argument") {
		t.Fatalf("extra arg: code=%d msg=%q", code, msg)
	}

	// A valid file whose token env is unset must refuse to start: without a
	// credential the node's polls carry no identity and it would be counted
	// dead while enforcing.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "scrub.yaml")
	if err := os.WriteFile(cfg, []byte(`
controller:
  url: "https://kapkan.example.net:8443"
  token_env: KAPKAN_TEST_SCRUB_TOKEN_UNSET
  name: scrub-fra1
dataplane:
  interfaces: [eth0]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, msg = runScrubCLI(t, "-config", cfg)
	if code != 1 || !strings.Contains(msg, "KAPKAN_TEST_SCRUB_TOKEN_UNSET") {
		t.Fatalf("unset token env: code=%d msg=%q", code, msg)
	}
}

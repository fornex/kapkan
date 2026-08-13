package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

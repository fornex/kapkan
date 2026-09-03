package main

import (
	"bytes"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

func runEdgeCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	f, err := parseFlags("kapkan", append([]string{"edge"}, args...), flag.ContinueOnError)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	var out, errOut bytes.Buffer
	code := runSubcommand(f, &out, &errOut)
	return code, errOut.String()
}

const edgeTestYAML = `
controller:
  url: "https://kapkan.example.net:8443"
  token_env: KAPKAN_TEST_EDGE_TOKEN
  name: edge-1
acme:
  disabled: true
`

func writeEdgeYAML(t *testing.T, body string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "edge.yaml")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEdgeCommandRejections(t *testing.T) {
	// A missing config file is a clean, named failure.
	code, msg := runEdgeCLI(t, "-config", filepath.Join(t.TempDir(), "absent.yaml"))
	if code != 1 || !strings.Contains(msg, "read edge config") {
		t.Fatalf("missing config: code=%d msg=%q", code, msg)
	}
	// An unexpected positional argument is a usage error.
	code, msg = runEdgeCLI(t, "extra")
	if code != exitUsage || !strings.Contains(msg, "unexpected argument") {
		t.Fatalf("extra arg: code=%d msg=%q", code, msg)
	}
	// The global -config before the command is refused loudly: a node must
	// never read kapkan.yaml by accident.
	f, err := parseFlags("kapkan", []string{"-config", "/etc/kapkan/config.yaml", "edge"}, flag.ContinueOnError)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSubcommand(f, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "pass it AFTER the command") {
		t.Fatalf("global flag: code=%d msg=%q", code, errOut.String())
	}
	// A valid file whose token env is unset must refuse to start.
	t.Setenv("KAPKAN_TEST_EDGE_TOKEN", "")
	cfg := writeEdgeYAML(t, edgeTestYAML)
	code, msg = runEdgeCLI(t, "-config", cfg)
	if code != 1 || !strings.Contains(msg, "KAPKAN_TEST_EDGE_TOKEN") {
		t.Fatalf("unset token env: code=%d msg=%q", code, msg)
	}
}

func TestEdgeCheck(t *testing.T) {
	t.Setenv("KAPKAN_TEST_EDGE_TOKEN", "")
	cfg := writeEdgeYAML(t, edgeTestYAML)
	code, msg := runEdgeCLI(t, "-config", cfg, "-check")
	if code != exitOK || !strings.Contains(msg, "is valid (node edge-1") || !strings.Contains(msg, "dry_run true") {
		t.Fatalf("-check: code=%d msg=%q", code, msg)
	}
	// Absent secrets are warnings (the check may run outside the unit's
	// environment); a group that does not exist is a problem.
	if !strings.Contains(msg, "warning: the agent token variable KAPKAN_TEST_EDGE_TOKEN") {
		t.Fatalf("-check did not warn about the unset token: %q", msg)
	}
	cfg = writeEdgeYAML(t, edgeTestYAML+"socket_group: no-such-group-kapkan\n")
	code, msg = runEdgeCLI(t, "-config", cfg, "-check")
	if code != 1 || !strings.Contains(msg, "socket_group") {
		t.Fatalf("-check with an unknown group: code=%d msg=%q", code, msg)
	}
	// A malformed EAB key is a problem; an unset one a warning.
	eab := edgeTestYAML + "  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: k\n      hmac_key_env: KAPKAN_TEST_EAB\n"
	eab = strings.Replace(eab, "acme:\n  disabled: true\n  eab:", "acme:\n  disabled: true\n  eab:", 1)
	cfg = writeEdgeYAML(t, eab)
	t.Setenv("KAPKAN_TEST_EAB", "not base64url!")
	code, msg = runEdgeCLI(t, "-config", cfg, "-check")
	if code != 1 || !strings.Contains(msg, "base64url") {
		t.Fatalf("-check with a bad EAB key: code=%d msg=%q", code, msg)
	}
	t.Setenv("KAPKAN_TEST_EAB", "")
	code, msg = runEdgeCLI(t, "-config", cfg, "-check")
	if code != exitOK || !strings.Contains(msg, "warning: acme.eab") {
		t.Fatalf("-check with an unset EAB key: code=%d msg=%q", code, msg)
	}
}

func TestEdgeNodeOptionsMapping(t *testing.T) {
	ec, err := config.ParseEdgeNode([]byte(`
dry_run: false
controller:
  url: "https://kapkan.example.net:8443/"
  token_env: KAPKAN_TEST_EDGE_TOKEN
  name: edge-1
  report_interval_seconds: 3
socket_group: nginx
terminator:
  binary: angie
  reload: command
  command: [systemctl, reload, angie]
acme:
  contact: ["mailto:ops@example.net"]
  eab:
    - directory: https://acme.zerossl.com/v2/DV90
      kid: kid-1
      hmac_key_env: KAPKAN_TEST_EAB
status_listen: 127.0.0.1:9102
omit_catch_all: true
`))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KAPKAN_TEST_EAB", "c2VjcmV0")
	eab, err := ec.ACME.ResolveEAB()
	if err != nil {
		t.Fatal(err)
	}
	opt := edgeNodeOptions(ec, "tok", eab, slog.New(slog.DiscardHandler))
	if opt.Brain != "https://kapkan.example.net:8443" || opt.Token != "tok" || opt.Name != "edge-1" || opt.DryRun {
		t.Fatalf("identity: %+v", opt)
	}
	if opt.ReportInterval != 3*time.Second || opt.SocketGroup != "nginx" || !opt.OmitCatchAll || opt.StatusListen != "127.0.0.1:9102" {
		t.Fatalf("settings: %+v", opt)
	}
	if opt.Terminator.Binary != "angie" || opt.Terminator.Reload != "command" || len(opt.Terminator.Command) != 3 {
		t.Fatalf("terminator: %+v", opt.Terminator)
	}
	if opt.StateDir != config.DefaultEdgeStateDir || opt.SocketsDir != config.DefaultEdgeSocketsDir {
		t.Fatalf("directories: %s %s", opt.StateDir, opt.SocketsDir)
	}
	if b := opt.ACME.EAB["https://acme.zerossl.com/v2/DV90"]; b.KID != "kid-1" || b.HMACKey != "c2VjcmV0" || opt.ACME.Disabled || len(opt.ACME.Contact) != 1 {
		t.Fatalf("acme: %+v", opt.ACME)
	}
}

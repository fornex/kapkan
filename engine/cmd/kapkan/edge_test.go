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

// fakeTerminator writes an executable standing in for nginx: it answers `-V`
// with out on stderr, the way nginx does, so -check runs the real probe.
func fakeTerminator(t *testing.T, out string) string {
	t.Helper()
	dir := t.TempDir()
	payload := filepath.Join(dir, "version.txt")
	if err := os.WriteFile(payload, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "nginx")
	script := "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then cat " + payload + " >&2; exit 0; fi\necho \"bad args: $*\" >&2\nexit 2\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// -check runs the same probe the node runs at start and prints its findings.
// The advisory is a WARNING and never a problem — the exit code stays 0 on a
// build whose core falls in a published range, because a distribution may
// have backported the fix (E5.1); `quic.h3: off` states the readiness as
// node_off and stops repeating the advice.
func TestEdgeCheckProbesTheTerminator(t *testing.T) {
	const (
		withModule = "nginx version: nginx/1.26.3\n" +
			"built with OpenSSL 3.5.6 7 Apr 2026 (running with OpenSSL 3.5.7 9 Jun 2026)\n" +
			"TLS SNI support enabled\n" +
			"configure arguments: --with-http_ssl_module --with-http_v3_module\n"
		noModule    = "nginx version: nginx/1.22.1\nbuilt with OpenSSL 1.1.1n  15 Mar 2022\nconfigure arguments: --with-http_v2_module\n"
		versionOnly = "nginx version: nginx/1.26.2\n"
		unreadable  = "nginx: something else entirely\n"
	)
	cases := []struct {
		name, out, extraYAML string
		want, unwanted       []string
	}{
		{
			name: "module and an advisory: ready, warned, still valid",
			out:  withModule,
			want: []string{
				"note: terminator: nginx 1.26.3 (nginx core 1.26.3, OpenSSL 3.5.7, http_v3_module yes, 0-RTT capable no)",
				"HTTP/3 readiness: ready",
				"warning: nginx core 1.26.3 is in the range CVE-2026-40460 names",
				"is valid (node edge-1",
			},
		},
		{
			name:      "the same build with quic.h3 off: node_off and no advice to repeat",
			out:       withModule,
			extraYAML: "quic:\n  h3: off\n",
			want:      []string{"http_v3_module yes", "HTTP/3 readiness: node_off"},
			unwanted:  []string{"CVE-2026-40460"},
		},
		{
			name:     "a build without the module",
			out:      noModule,
			want:     []string{"nginx 1.22.1", "OpenSSL 1.1.1n", "http_v3_module no", "HTTP/3 readiness: no_module"},
			unwanted: []string{"CVE-"},
		},
		{
			name:     "-v-shaped output alone: the TLS library is unknown, not invented",
			out:      versionOnly,
			want:     []string{"nginx 1.26.2", "TLS library unknown", "HTTP/3 readiness: no_module"},
			unwanted: []string{"CVE-"},
		},
		{
			name:     "a binary the probe cannot read is a warning, and nothing is claimed",
			out:      unreadable,
			want:     []string{"warning: terminator probe failed", "unrecognised output", "is valid (node edge-1"},
			unwanted: []string{"note: terminator:", "HTTP/3 readiness"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("KAPKAN_TEST_EDGE_TOKEN", "")
			bin := fakeTerminator(t, c.out)
			cfg := writeEdgeYAML(t, edgeTestYAML+"terminator:\n  binary: "+bin+"\n"+c.extraYAML)
			code, msg := runEdgeCLI(t, "-config", cfg, "-check")
			if code != exitOK {
				t.Fatalf("an advisory or an unreadable binary must not fail the check: code=%d msg=%q", code, msg)
			}
			for _, want := range c.want {
				if !strings.Contains(msg, want) {
					t.Errorf("-check output lacks %q:\n%s", want, msg)
				}
			}
			for _, unwanted := range c.unwanted {
				if strings.Contains(msg, unwanted) {
					t.Errorf("-check output carries %q:\n%s", unwanted, msg)
				}
			}
		})
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
quic:
  h3: off
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
	// The node's HTTP/3 switch, both ways round: `off` is the only value that
	// stops this box rendering QUIC, and the default must never mean off.
	if !opt.QUIC.H3Off {
		t.Fatalf("quic.h3: off did not reach the node: %+v", opt.QUIC)
	}
	def, err := config.ParseEdgeNode([]byte(edgeTestYAML))
	if err != nil {
		t.Fatal(err)
	}
	if opt := edgeNodeOptions(def, "tok", nil, slog.New(slog.DiscardHandler)); opt.QUIC.H3Off {
		t.Fatalf("the default quic.h3 (%q) switched HTTP/3 off: %+v", def.QUIC.H3, opt.QUIC)
	}
}

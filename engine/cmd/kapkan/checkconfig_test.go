package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckConfigNamesUnboundAgentTokens pins the -check-config half of the
// E6.1 grace contract: a valid file with an unbound agent token is OK (exit 0),
// and a WARNING block after the OK line names exactly the unbound tokens —
// never a bound agent, never an operator; a file with every agent bound prints
// no WARNING at all.
func TestCheckConfigNamesUnboundAgentTokens(t *testing.T) {
	dir := t.TempDir()
	zones := filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zones, []byte("zones: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const base = `listen:
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
thresholds:
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
notify: {}
api:
  listen: "127.0.0.1:8080"
  tokens:
`
	edge := "edge:\n  zones_file: " + zones + "\n  nodes:\n    - name: e1\n"
	write := func(tokens string) string {
		p := filepath.Join(dir, "kapkan.yaml")
		if err := os.WriteFile(p, []byte(base+tokens+edge), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	var out bytes.Buffer
	p := write("    - {name: a0, token_env: K_A0, role: agent}\n" +
		"    - {name: a1, token_env: K_A1, role: agent, node: e1}\n" +
		"    - {name: o, token_env: K_O, role: operator}\n")
	if rc := checkConfigTo(&out, p); rc != 0 {
		t.Fatalf("exit code = %d, want 0 (a warning never fails the check): %s", rc, out.String())
	}
	s := out.String()
	ok, warn := strings.Index(s, "OK  "), strings.Index(s, "WARNING: 1 agent token(s)")
	if ok < 0 || warn < 0 || warn < ok {
		t.Fatalf("want an OK line followed by the WARNING block, got:\n%s", s)
	}
	if !strings.Contains(s, "\n    - a0\n") {
		t.Fatalf("the unbound token is not listed:\n%s", s)
	}
	for _, notListed := range []string{"\n    - a1\n", "\n    - o\n"} {
		if strings.Contains(s, notListed) {
			t.Fatalf("a bound agent or an operator is listed as unbound:\n%s", s)
		}
	}
	if !strings.Contains(s, "api.tokens[].node") {
		t.Fatalf("the WARNING does not say which key fixes it:\n%s", s)
	}

	out.Reset()
	p = write("    - {name: a1, token_env: K_A1, role: agent, node: e1}\n" +
		"    - {name: o, token_env: K_O, role: operator}\n")
	if rc := checkConfigTo(&out, p); rc != 0 || strings.Contains(out.String(), "WARNING") {
		t.Fatalf("every agent bound: rc = %d, output:\n%s", rc, out.String())
	}
}

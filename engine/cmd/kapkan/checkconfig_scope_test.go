package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const checkBase = `listen:
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

// checkPair writes a kapkan.yaml (checkBase + tokens + the two placement
// hostgroups + an edge block with nodes) over a three-zone zones file:
// us.example on edge-us, g.example global, as.example on edge-asia.
func checkPair(t *testing.T, tokens, nodes string) string {
	t.Helper()
	dir := t.TempDir()
	zones := filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zones, []byte("zones:\n  - name: us.example\n    hostgroup: edge-us\n    origins: [\"10.0.0.1:8080\"]\n"+
		"  - name: g.example\n    origins: [\"10.0.0.3:8080\"]\n  - name: as.example\n    hostgroup: edge-asia\n    origins: [\"10.0.0.4:8080\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "kapkan.yaml")
	yaml := checkBase + tokens +
		"hostgroups:\n  - name: edge-us\n    networks: [\"203.0.113.0/26\"]\n  - name: edge-asia\n    networks: [\"203.0.113.128/26\"]\n" +
		"edge:\n  zones_file: " + zones + "\n  nodes:" + nodes
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func checkOutput(t *testing.T, cfg string, wantRC int) string {
	t.Helper()
	var out bytes.Buffer
	if rc := checkConfigTo(&out, cfg); rc != wantRC {
		t.Fatalf("exit code = %d, want %d: %s", rc, wantRC, out.String())
	}
	return out.String()
}

func wantLines(t *testing.T, s string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
}

// TestCheckConfigPrintsThePlacementMatrix: -check-config shows the edge fleet
// as the brain will run it — each node's scope, the zones it covers and its
// token — and warns about a zone no node's scope covers, exit code unchanged.
// A node listing two groups shows both; a node whose scope covers two zones
// counts two.
func TestCheckConfigPrintsThePlacementMatrix(t *testing.T) {
	cfg := checkPair(t,
		"    - {name: a1, token_env: K_A1, role: agent, node: e1}\n"+
			"    - {name: a2, token_env: K_A2, role: agent, node: e2}\n"+
			"    - {name: a3, token_env: K_A3, role: agent, node: e3}\n",
		"\n    - name: e1\n      hostgroups: [edge-us]\n    - name: e2\n    - name: e3\n      hostgroups: [edge-us, edge-asia]\n")
	s := checkOutput(t, cfg, 0)
	wantLines(t, s,
		"edge:      3 node(s), 3 zone(s)",
		"scope=[edge-us]  zones=1  token=a1",
		"scope=[global]  zones=1  token=a2",
		"scope=[edge-us edge-asia]  zones=2  token=a3",
	)
	if strings.Contains(s, "no node's scope covers") || strings.Contains(s, "not bound to a node") {
		t.Fatalf("every zone is covered and every agent bound, yet:\n%s", s)
	}
}

// TestCheckConfigWarnsAboutOrphanZones: a zone placed on a group no node
// lists is named in a WARNING; with no nodes at all every zone is one, and
// the header still prints.
func TestCheckConfigWarnsAboutOrphanZones(t *testing.T) {
	cfg := checkPair(t,
		"    - {name: a1, token_env: K_A1, role: agent, node: e1}\n    - {name: a2, token_env: K_A2, role: agent, node: e2}\n",
		"\n    - name: e1\n      hostgroups: [edge-us]\n    - name: e2\n")
	s := checkOutput(t, cfg, 0)
	wantLines(t, s,
		"edge:      2 node(s), 3 zone(s)",
		"WARNING: 1 zone(s) that no node's scope covers",
		"as.example (hostgroup edge-asia)",
	)
	// An edge block with no nodes: the header and the WARNING for all three.
	cfg = checkPair(t, "    - {name: o, token_env: K_O, role: operator}\n", " []\n")
	s = checkOutput(t, cfg, 0)
	wantLines(t, s,
		"edge:      0 node(s), 3 zone(s)",
		"WARNING: 3 zone(s) that no node's scope covers",
		"us.example (hostgroup edge-us)", "g.example (hostgroup global)", "as.example (hostgroup edge-asia)",
	)
}

// TestCheckConfigTokenColumn: the token column reads the bound token's name,
// SHARED while an unbound agent token could act as the node, and "-" when no
// token can act as it.
func TestCheckConfigTokenColumn(t *testing.T) {
	// An unscoped fleet (scoping forbids unbound agents): a1 bound to e1, a0
	// unbound — e2 is served by the shared token.
	cfg := checkPair(t,
		"    - {name: a0, token_env: K_A0, role: agent}\n    - {name: a1, token_env: K_A1, role: agent, node: e1}\n",
		"\n    - name: e1\n    - name: e2\n")
	s := checkOutput(t, cfg, 0)
	wantLines(t, s,
		"scope=[global]  zones=1  token=a1",
		"scope=[global]  zones=1  token=SHARED",
		"WARNING: 1 agent token(s) are not bound to a node",
		"    - a0",
	)
	// Every agent bound, e2 without one: nothing can act as e2.
	cfg = checkPair(t,
		"    - {name: a1, token_env: K_A1, role: agent, node: e1}\n",
		"\n    - name: e1\n    - name: e2\n")
	s = checkOutput(t, cfg, 0)
	wantLines(t, s, "token=a1", "token=-")
	if strings.Contains(s, "SHARED") || strings.Contains(s, "not bound to a node") {
		t.Fatalf("no unbound token exists, yet:\n%s", s)
	}
}

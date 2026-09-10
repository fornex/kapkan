package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckConfigPrintsThePlacementMatrix: -check-config shows the edge fleet
// as the brain will run it — each node's scope, the zones it covers and its
// token — and warns about a zone no node's scope covers, exit code unchanged.
func TestCheckConfigPrintsThePlacementMatrix(t *testing.T) {
	dir := t.TempDir()
	zones := filepath.Join(dir, "zones.yaml")
	if err := os.WriteFile(zones, []byte("zones:\n  - name: us.example\n    hostgroup: edge-us\n    origins: [\"10.0.0.1:8080\"]\n"+
		"  - name: g.example\n    origins: [\"10.0.0.3:8080\"]\n  - name: as.example\n    hostgroup: edge-asia\n    origins: [\"10.0.0.4:8080\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "kapkan.yaml")
	yaml := `listen:
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
    - {name: a1, token_env: K_A1, role: agent, node: e1}
    - {name: a2, token_env: K_A2, role: agent, node: e2}
hostgroups:
  - name: edge-us
    networks: ["203.0.113.0/26"]
  - name: edge-asia
    networks: ["203.0.113.128/26"]
edge:
  zones_file: ` + zones + `
  nodes:
    - name: e1
      hostgroups: [edge-us]
    - name: e2
`
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if rc := checkConfigTo(&out, cfg); rc != 0 {
		t.Fatalf("exit code = %d: %s", rc, out.String())
	}
	s := out.String()
	for _, want := range []string{
		"edge:      2 node(s), 3 zone(s)",
		"scope=[edge-us]  zones=1  token=a1",
		"scope=[global]  zones=1  token=a2",
		"WARNING: 1 zone(s) that no node's scope covers",
		"as.example (hostgroup edge-asia)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "not bound to a node") {
		t.Fatalf("every agent is bound, yet:\n%s", s)
	}
}

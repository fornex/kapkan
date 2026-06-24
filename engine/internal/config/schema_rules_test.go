package config

import (
	"os"
	"strings"
	"testing"
)

// validBase is a complete, minimal config that Parse accepts. The rejection
// cases below each add or change exactly one thing to trip a specific
// cross-field rule, so a silent removal of that rule from config.go breaks the
// build even when the generated schema is unchanged (the schema cannot express
// these). It deliberately omits mitigation/escalation/hostgroups/storage so the
// additive cases introduce them cleanly.
const validBase = `
listen:
  sflow: ":6343"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
thresholds:
  pps: 1000
  mbps: 100
  flows_per_sec: 500
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 60
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
api:
  listen: "127.0.0.1:8080"
`

func TestParseAcceptsValidBase(t *testing.T) {
	if _, err := Parse([]byte(validBase)); err != nil {
		t.Fatalf("validBase should parse, got: %v", err)
	}
}

func TestParseRejectsCrossFieldViolations(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string // substring the error must contain — pins the rule, not just "some error"
	}{
		{
			name: "overlapping networks",
			yaml: `
listen: {sflow: ":6343"}
sampling: {default_rate: 1000}
networks: ["203.0.113.0/24", "203.0.113.128/25"]
thresholds: {pps: 1000, mbps: 100, flows_per_sec: 500}
ban: {ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50}
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors: [{address: "10.0.0.254", remote_asn: 65000}]
api: {listen: "127.0.0.1:8080"}
`,
			wantErr: "overlaps",
		},
		{
			name:    "de-escalating ladder",
			yaml:    validBase + "\nescalation:\n  - {after_seconds: 0, action: blackhole}\n  - {after_seconds: 30, action: flowspec}\n",
			wantErr: "de-escalates",
		},
		{
			name:    "flowspec on a total hostgroup",
			yaml:    validBase + "\nhostgroups:\n  - name: pool\n    calculation: total\n    mitigation: flowspec\n    networks: [\"203.0.113.0/26\"]\n",
			wantErr: "calculation: total",
		},
		{
			name:    "clickhouse batch_size exceeds queue_size",
			yaml:    validBase + "\nstorage:\n  clickhouse:\n    url: \"http://127.0.0.1:8123\"\n    batch_size: 2000\n    queue_size: 1000\n",
			wantErr: "batch_size",
		},
		{
			name:    "unknown mitigation value",
			yaml:    validBase + "\nmitigation: bogus\n",
			wantErr: "method must be",
		},
		{
			name:    "hostgroup prefix outside protected networks",
			yaml:    validBase + "\nhostgroups:\n  - name: stray\n    networks: [\"198.51.100.0/24\"]\n",
			wantErr: "not inside any configured networks",
		},
		{
			name: "ban rate guard without window",
			yaml: `
listen: {sflow: ":6343"}
sampling: {default_rate: 1000}
networks: ["203.0.113.0/24"]
thresholds: {pps: 1000, mbps: 100, flows_per_sec: 500}
ban: {ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50, max_bans_per_window: 10}
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors: [{address: "10.0.0.254", remote_asn: 65000}]
api: {listen: "127.0.0.1:8080"}
`,
			wantErr: "ban_window_seconds must be > 0",
		},
		{
			name:    "carpet block without any aggregate threshold",
			yaml:    validBase + "\ncarpet:\n  min_hosts: 5\n",
			wantErr: "carpet.thresholds",
		},
		{
			name:    "carpet with an invalid mitigation method",
			yaml:    validBase + "\ncarpet:\n  thresholds: {pps: 100000}\n  mitigation: bogus\n",
			wantErr: "carpet.mitigation",
		},
		{
			name: "duplicate boundary exporter",
			yaml: `
listen: {sflow: ":6343"}
sampling:
  default_rate: 1000
  boundary:
    - {exporter: "10.0.0.2", external_ifindexes: [1]}
    - {exporter: "10.0.0.2", external_ifindexes: [2]}
networks: ["203.0.113.0/24"]
thresholds: {pps: 1000, mbps: 100, flows_per_sec: 500}
ban: {ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50}
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors: [{address: "10.0.0.254", remote_asn: 65000}]
api: {listen: "127.0.0.1:8080"}
`,
			wantErr: "duplicate exporter",
		},
		{
			name: "boundary entry with no external interfaces",
			yaml: `
listen: {sflow: ":6343"}
sampling:
  default_rate: 1000
  boundary:
    - {exporter: "10.0.0.2", external_ifindexes: []}
networks: ["203.0.113.0/24"]
thresholds: {pps: 1000, mbps: 100, flows_per_sec: 500}
ban: {ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50}
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors: [{address: "10.0.0.254", remote_asn: 65000}]
api: {listen: "127.0.0.1:8080"}
`,
			wantErr: "external_ifindexes",
		},
		{
			name:    "unknown key is rejected (closed schema)",
			yaml:    validBase + "\nbogus_key: 1\n",
			wantErr: "not found",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

// TestParseAcceptsShippedDevConfig keeps the in-repo example honest: the file
// the docs point newcomers at must always be a valid config.
func TestParseAcceptsShippedDevConfig(t *testing.T) {
	raw, err := os.ReadFile("../../configs/dev.yaml")
	if err != nil {
		t.Fatalf("read dev.yaml: %v", err)
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("configs/dev.yaml should parse, got: %v", err)
	}
}

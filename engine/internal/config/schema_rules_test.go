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

// dataplaneBlock is the smallest data-plane stanza that validates, appended by
// the cases that need the feature present rather than under test themselves.
const dataplaneBlock = `
dataplane:
  interfaces: ["eth0"]
`

func TestParseAcceptsValidBase(t *testing.T) {
	if _, err := Parse([]byte(validBase)); err != nil {
		t.Fatalf("validBase should parse, got: %v", err)
	}
}

// TestParseAcceptsCarpetDataplane is the positive half of the two carpet
// dataplane rejections below: with the block present and enabled, the method
// parses AND resolves to the in-kernel mechanism. Without this, a validator
// that rejected the method outright would still pass the rejection cases.
func TestParseAcceptsCarpetDataplane(t *testing.T) {
	yaml := validBase + "\ndataplane:\n  enabled: true\n  interfaces: [\"eth0\"]\n" +
		"\ncarpet:\n  thresholds: {pps: 100000}\n  mitigation: dataplane\n"
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("carpet.mitigation: dataplane with an enabled data plane should parse, got: %v", err)
	}
	if got := cfg.Carpet.Method(); got != MitigateDataplane {
		t.Fatalf("carpet method = %q, want %q", got, MitigateDataplane)
	}
	if got := cfg.Carpet.Method().Action(); got != EscalateDataplane {
		t.Fatalf("carpet ladder action = %q, want %q — the operator asked for a surgical in-kernel "+
			"drop of one vector and would have got a null route for the whole prefix", got, EscalateDataplane)
	}
}

// TestParseAcceptsTLSClientHelloRule is the positive half of the three
// rejection cases below: the shape an operator actually writes to shed a TLS
// handshake flood — a per-source ceiling on ClientHellos to :443 — has to
// survive validation intact, or the rejections are just a wall.
func TestParseAcceptsTLSClientHelloRule(t *testing.T) {
	yaml := validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n" +
		"  ratelimit_profiles:\n    - {name: hs_per_src, pps: 20}\n" +
		"  static_rules:\n    - name: cap_tls_handshakes\n" +
		"      match: {proto: tcp, dst_port: 443, payload: tls_client_hello}\n" +
		"      action: ratelimit\n      profile: hs_per_src\n"
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("a tls_client_hello ratelimit rule should parse, got: %v", err)
	}
	m := cfg.Dataplane.StaticRules[0].Match
	if m.Payload != StaticPayloadTLSClientHello {
		t.Errorf("match.payload = %q, want %q", m.Payload, StaticPayloadTLSClientHello)
	}
	if m.DstPort != 443 || m.Proto != "tcp" {
		t.Errorf("match = %+v, want proto tcp on port 443", m)
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
			// A node restricted to other hostgroups is not a divert target for
			// this group: without this rule, unclaimed victims would divert to
			// an empty next-hop — an announce the peer rejects, silently
			// degrading them to the fallback instead of scrubbing them.
			name: "divert target restricted to a foreign hostgroup",
			yaml: validBase + `
mitigation: divert
scrubbing:
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
      hostgroups: [game]
hostgroups:
  - name: game
    networks: ["203.0.113.0/26"]
`,
			wantErr: "that serves this group",
		},
		{
			// An agent token is a scrub node's credential and its rules feed is
			// deployment-wide; a tenant on it would promise a scoping nothing
			// enforces (per-node scoping is the fleet milestone).
			name: "tenant-scoped agent token",
			yaml: strings.Replace(validBase, "api:\n  listen: \"127.0.0.1:8080\"\n",
				"api:\n  listen: \"127.0.0.1:8080\"\n  tokens:\n    - {name: n1, token_env: K_N1, role: agent, tenant: custA}\n", 1) +
				"\nhostgroups:\n  - {name: a-web, tenant: custA, networks: [\"203.0.113.0/26\"]}\n",
			wantErr: "cannot be tenant-scoped",
		},
		{
			// dataplane is the most surgical rung, so climbing from flowspec
			// back down to it is a de-escalation like any other.
			name:    "de-escalating from flowspec to dataplane",
			yaml:    validBase + dataplaneBlock + "\nescalation:\n  - {after_seconds: 0, action: flowspec}\n  - {after_seconds: 30, action: dataplane}\n",
			wantErr: "de-escalates",
		},
		{
			name:    "dataplane rung without a dataplane block",
			yaml:    validBase + "\nescalation:\n  - {after_seconds: 0, action: dataplane}\n",
			wantErr: "requires a dataplane block",
		},
		{
			name:    "dataplane rung with the block disabled",
			yaml:    validBase + "\ndataplane:\n  enabled: false\n  interfaces: [\"eth0\"]\n" + "\nescalation:\n  - {after_seconds: 0, action: dataplane}\n",
			wantErr: "requires dataplane.enabled",
		},
		{
			name:    "dataplane enabled without interfaces",
			yaml:    validBase + "\ndataplane:\n  interfaces: []\n",
			wantErr: "at least one interface",
		},
		{
			name:    "fingerprint plane on with the data plane disabled",
			yaml:    validBase + "\ndataplane:\n  enabled: false\n  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n",
			wantErr: "fingerprint.enabled requires dataplane.enabled",
		},
		{
			name:    "fingerprint blocklist entry that is not a JA4",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n    ja4_blocklist: [\"not-a-ja4\"]\n",
			wantErr: "is not a JA4 fingerprint",
		},
		{
			name:    "duplicate JA4 in the fingerprint blocklist",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  fingerprint:\n    enabled: true\n    ja4_blocklist: [\"t13d1516h2_8daaf6152771_e5627efa2ab1\", \"t13d1516h2_8daaf6152771_e5627efa2ab1\"]\n",
			wantErr: "duplicate entry",
		},
		{
			// The edge block (E3): the zones FILE is what the block is for, so a
			// block without it is a mistake, not an empty edge.
			name:    "edge block without a zones file",
			yaml:    validBase + "\nedge:\n  nodes:\n    - name: e1\n",
			wantErr: "edge.zones_file is required",
		},
		{
			name:    "edge zones file with a relative path",
			yaml:    validBase + "\nedge:\n  zones_file: zones.yaml\n",
			wantErr: "edge.zones_file must be an absolute path",
		},
		{
			name:    "duplicate edge node names",
			yaml:    validBase + "\nedge:\n  zones_file: /etc/kapkan/zones.yaml\n  nodes:\n    - name: e1\n    - name: e1\n",
			wantErr: "duplicate node name",
		},
		{
			name:    "static rule ratelimit without a profile",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - name: cap\n      match: {proto: icmp}\n      action: ratelimit\n",
			wantErr: "requires profile",
		},
		{
			name:    "static rule references an undeclared profile",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - name: cap\n      match: {proto: icmp}\n      action: ratelimit\n      profile: nope\n",
			wantErr: "is not declared",
		},
		{
			name:    "duplicate static rule names",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - {name: r, match: {proto: udp}, action: drop}\n    - {name: r, match: {proto: tcp}, action: drop}\n",
			wantErr: "duplicate rule name",
		},
		{
			// The bit is only ever set on TCP, so this rule would match the
			// same packets either way — it is refused so the config file
			// states the TCP-only nature at the place an operator reads it.
			name:    "payload match without an explicit proto",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - {name: hs, match: {dst_port: 443, payload: tls_client_hello}, action: drop}\n",
			wantErr: "requires proto: tcp",
		},
		{
			name:    "payload match on udp",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - {name: hs, match: {proto: udp, dst_port: 443, payload: tls_client_hello}, action: drop}\n",
			wantErr: "requires proto: tcp",
		},
		{
			name:    "unknown payload predicate",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - {name: hs, match: {proto: tcp, payload: http_get}, action: drop}\n",
			wantErr: "match.payload must be tls_client_hello or quic_initial",
		},
		{
			// The mirror of the tls-on-udp case: quic_initial is read from
			// the UDP payload, and the rule must say so where it is read.
			name:    "quic payload match without an explicit proto",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - {name: qi, match: {dst_port: 443, payload: quic_initial}, action: drop}\n",
			wantErr: "requires proto: udp",
		},
		{
			name:    "quic payload match on tcp",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  static_rules:\n    - {name: qi, match: {proto: tcp, dst_port: 443, payload: quic_initial}, action: drop}\n",
			wantErr: "requires proto: udp",
		},
		{
			name:    "ratelimit profile with neither pps nor mbps",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  ratelimit_profiles:\n    - {name: idle}\n",
			wantErr: "set pps, mbps or both",
		},
		{
			// max_active_bans is 50 in validBase, so the dynamic map must hold
			// 400 entries; sizing it below that guarantees mid-attack failures.
			name:    "dynamic rule map too small for max_active_bans",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  limits: {max_dynamic_rules: 8}\n",
			wantErr: "below ban.max_active_bans",
		},
		{
			name:    "unknown xdp_mode",
			yaml:    validBase + "\ndataplane:\n  interfaces: [\"eth0\"]\n  xdp_mode: turbo\n",
			wantErr: "xdp_mode must be",
		},
		{
			name:    "duplicate scrubbing node names",
			yaml:    validBase + "\nscrubbing:\n  nodes:\n    - {name: n, next_hop: \"192.0.2.9\"}\n    - {name: n, next_hop: \"192.0.2.10\"}\n",
			wantErr: "duplicate node name",
		},
		{
			name:    "node selection without any nodes",
			yaml:    validBase + "\nscrubbing:\n  node_selection: least_loaded\n",
			wantErr: "require at least one scrubbing.nodes entry",
		},
		{
			// A managed node satisfies the divert target, so this ladder is
			// valid even though the scalar next_hop is unset.
			name:    "divert with neither a next-hop nor a node",
			yaml:    validBase + "\nescalation:\n  - {after_seconds: 0, action: divert}\n",
			wantErr: "divert requires scrubbing.next_hop",
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
			// divert is a valid method everywhere ELSE. A carpet ban covers a
			// whole aggregation prefix, and diverting a /24 into a scrubbing
			// centre is a routing decision an operator makes deliberately, not
			// one a detector makes for them.
			name:    "carpet cannot select divert",
			yaml:    validBase + "\ncarpet:\n  thresholds: {pps: 100000}\n  mitigation: divert\n",
			wantErr: "carpet.mitigation must be empty or one of",
		},
		{
			// Accepting the method with no kernel to install into would mean
			// every carpet install fails and falls back to blackholing the whole
			// prefix — the widest outcome reached from the most surgical request.
			name:    "carpet dataplane without a dataplane block",
			yaml:    validBase + "\ncarpet:\n  thresholds: {pps: 100000}\n  mitigation: dataplane\n",
			wantErr: "carpet.mitigation \"dataplane\" requires a dataplane block",
		},
		{
			name: "carpet dataplane with the data plane switched off",
			yaml: validBase + "\ndataplane:\n  enabled: false\n  interfaces: [\"eth0\"]\n" +
				"\ncarpet:\n  thresholds: {pps: 100000}\n  mitigation: dataplane\n",
			wantErr: "carpet.mitigation \"dataplane\" requires dataplane.enabled: true",
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

package config

import (
	"strings"
	"testing"
)

// The placement axis (E6.3, D8/D9): edge.nodes[].hostgroups is a node's
// scope, zones[].hostgroup a zone's placement, and a node serves a zone when
// the placement is in the scope. Empty scope = the global group alone; empty
// placement = the global group.

func scopeYAML(tokens, nodes string) string {
	return strings.Replace(validYAML, "  listen: \"127.0.0.1:8080\"\n",
		"  listen: \"127.0.0.1:8080\"\n  tokens:\n"+tokens, 1) +
		"hostgroups:\n  - name: edge-us\n    networks: [\"203.0.113.0/26\"]\n  - name: edge-eu\n    tenant: eu\n    networks: [\"203.0.113.64/26\"]\n" +
		"edge:\n  zones_file: /etc/kapkan/zones.yaml\n  nodes:\n" + nodes
}

const boundTokens = "    - {name: a1, token_env: K_A1, role: agent, node: e1}\n" +
	"    - {name: a2, token_env: K_A2, role: agent, node: e2}\n" +
	"    - {name: a3, token_env: K_A3, role: agent, node: e3}\n" +
	"    - {name: o, token_env: K_O, role: operator}\n"

const scopedNodes = "    - name: e1\n      hostgroups: [edge-us]\n    - name: e2\n      hostgroups: [edge-eu, global]\n    - name: e3\n"

func TestEdgeScopePredicates(t *testing.T) {
	cfg, err := Parse([]byte(scopeYAML(boundTokens, scopedNodes)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	z, err := ParseZones([]byte("zones:\n  - name: us.example\n    hostgroup: edge-us\n    origins: [\"10.0.0.1:8080\"]\n" +
		"  - name: eu.example\n    hostgroup: edge-eu\n    origins: [\"10.0.0.2:8080\"]\n" +
		"  - name: g.example\n    origins: [\"10.0.0.3:8080\"]\n" +
		"  - name: lit.example\n    hostgroup: global\n    origins: [\"10.0.0.4:8080\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.BindZones(z); err != nil {
		t.Fatalf("BindZones: %v", err)
	}
	us, eu, g, lit := &z.Zones[0], &z.Zones[1], &z.Zones[2], &z.Zones[3]
	if EdgePlacement(us) != "edge-us" || EdgePlacement(g) != GlobalGroup || EdgePlacement(lit) != GlobalGroup {
		t.Fatalf("placements: %s %s %s", EdgePlacement(us), EdgePlacement(g), EdgePlacement(lit))
	}
	e3 := &cfg.Edge.Nodes[2]
	if got := e3.Scope(); len(got) != 1 || got[0] != GlobalGroup {
		t.Fatalf("empty scope = %v, want [global]", got)
	}
	cases := []struct {
		zone *Zone
		want []string
	}{
		{us, []string{"e1"}},        // the label alone keeps the zone off e2 and e3
		{eu, []string{"e2"}},        // e2 lists edge-eu
		{g, []string{"e2", "e3"}},   // e2 lists global explicitly, e3 by default
		{lit, []string{"e2", "e3"}}, // the literal is the same group
	}
	for _, tc := range cases {
		if got := cfg.EdgeNodesServing(tc.zone); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s served by %v, want %v", tc.zone.Name, got, tc.want)
		}
	}
	if cfg.EdgeNodeServes("e9", g) || !cfg.EdgeNodeServes("e3", g) || cfg.EdgeNodeServes("e1", g) {
		t.Fatal("EdgeNodeServes: an unknown node serves nothing; [edge-us] does not reach the global group")
	}
}

func TestEdgeScopeValidation(t *testing.T) {
	bad := []struct{ name, yaml, want string }{
		{"unknown group in a scope", scopeYAML(boundTokens, "    - name: e1\n      hostgroups: [edge-asia]\n    - name: e2\n    - name: e3\n"),
			`edge.nodes["e1"].hostgroups[0]: "edge-asia" is not a hostgroup`},
		{"a group listed twice", scopeYAML(boundTokens, "    - name: e1\n      hostgroups: [edge-us, edge-us]\n    - name: e2\n    - name: e3\n"),
			`edge.nodes["e1"].hostgroups: "edge-us" is listed twice`},
		{"a scope with an unbound agent token",
			scopeYAML("    - {name: a0, token_env: K_A0, role: agent}\n"+boundTokens, scopedNodes),
			`api.tokens["a0"] is an agent token bound to no node; bind every agent token`},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.yaml)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	// Without scopes an unbound agent stays legal (grace): nothing about
	// placement is claimed, so nothing is enforced against the shared token.
	if _, err := Parse([]byte(scopeYAML("    - {name: a0, token_env: K_A0, role: agent}\n"+boundTokens, "    - name: e1\n    - name: e2\n    - name: e3\n"))); err != nil {
		t.Fatalf("unscoped fleet with an unbound agent: %v", err)
	}
	// The literal global in a scope is fine.
	if _, err := Parse([]byte(scopeYAML(boundTokens, "    - name: e1\n      hostgroups: [global]\n    - name: e2\n    - name: e3\n"))); err != nil {
		t.Fatalf("literal global in a scope: %v", err)
	}
}

func TestBindZonesPlacement(t *testing.T) {
	cfg, err := Parse([]byte(scopeYAML(boundTokens, scopedNodes)))
	if err != nil {
		t.Fatal(err)
	}
	zones := func(body string) *Zones {
		z, err := ParseZones([]byte("zones:\n" + body))
		if err != nil {
			t.Fatalf("ParseZones: %v", err)
		}
		return z
	}
	cases := []struct{ name, body, want string }{
		{"typo in the hostgroup", "  - name: us.example\n    hostgroup: edge-uss\n    origins: [\"10.0.0.1:8080\"]\n",
			`zones["us.example"]: hostgroup "edge-uss" is not a hostgroup`},
		{"tenant disagrees with the group's", "  - name: eu.example\n    hostgroup: edge-eu\n    tenant: acme\n    origins: [\"10.0.0.2:8080\"]\n",
			`zones["eu.example"]: tenant "acme" differs from hostgroup "edge-eu"'s tenant "eu"`},
		{"tenant agrees", "  - name: eu.example\n    hostgroup: edge-eu\n    tenant: eu\n    origins: [\"10.0.0.2:8080\"]\n", ""},
		{"no inheritance: an unlabelled zone in a labelled group stays a house zone", "  - name: eu.example\n    hostgroup: edge-eu\n    origins: [\"10.0.0.2:8080\"]\n", ""},
		{"literal global", "  - name: g.example\n    hostgroup: global\n    origins: [\"10.0.0.3:8080\"]\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := zones(tc.body)
			err := cfg.BindZones(z)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("BindZones: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("BindZones err = %v, want %q", err, tc.want)
			case tc.want == "" && z.Zones[0].Tenant != "" && z.Zones[0].Tenant != "eu":
				t.Fatalf("tenant changed by binding: %q", z.Zones[0].Tenant)
			}
			if strings.Contains(tc.name, "no inheritance") && z.Zones[0].Tenant != "" {
				t.Fatalf("the zone inherited a tenant: %q", z.Zones[0].Tenant)
			}
		})
	}
	// The label's form is the zones file's business, like tenant's.
	if _, err := ParseZones([]byte("zones:\n  - name: a.example\n    hostgroup: \"bad group!\"\n    origins: [\"10.0.0.1:8080\"]\n")); err == nil || !strings.Contains(err.Error(), "a.example: hostgroup") {
		t.Fatalf("bad hostgroup form: err = %v", err)
	}
}

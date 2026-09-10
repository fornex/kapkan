package config

import (
	"strings"
	"testing"
)

// Token↔node binding (E6.1): api.tokens[].node is an agent-only key naming
// exactly one configured node, edge or scrub; every refusal below is a rule a
// silent removal from validateAPITokens would break.
func TestAPITokenNodeBinding(t *testing.T) {
	const nodes = `
scrubbing:
  next_hop: "192.0.2.9"
  nodes:
    - name: fra1
      next_hop: "192.0.2.10"
edge:
  zones_file: /etc/kapkan/zones.yaml
  nodes:
    - name: e1
    - name: e2
`
	tokens := func(list string) string {
		return strings.Replace(validBase, "api:\n  listen: \"127.0.0.1:8080\"\n",
			"api:\n  listen: \"127.0.0.1:8080\"\n  tokens:\n"+list, 1) + nodes
	}
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "agent bound to an edge node",
			yaml: tokens("    - {name: a1, token_env: K_A1, role: agent, node: e1}\n"),
		},
		{
			name: "agent bound to a scrub node",
			yaml: tokens("    - {name: s1, token_env: K_S1, role: agent, node: fra1}\n"),
		},
		{
			// Rotation without a gap: the new token overlaps the old one.
			name: "two tokens bound to one node",
			yaml: tokens("    - {name: a1, token_env: K_A1, role: agent, node: e1}\n    - {name: a1b, token_env: K_A1B, role: agent, node: e1}\n"),
		},
		{
			name:    "node on an operator token",
			yaml:    tokens("    - {name: o, token_env: K_O, role: operator, node: e1}\n"),
			wantErr: "may only be set on an agent token",
		},
		{
			name:    "node on a viewer token",
			yaml:    tokens("    - {name: v, token_env: K_V, role: viewer, node: e1}\n"),
			wantErr: "may only be set on an agent token",
		},
		{
			name:    "unknown node",
			yaml:    tokens("    - {name: a1, token_env: K_A1, role: agent, node: e9}\n"),
			wantErr: "neither an edge.nodes[] nor a scrubbing.nodes[] entry",
		},
		{
			// The two channels are different trust domains; a name in both lists
			// cannot be bound to "both".
			name: "node named in both lists",
			yaml: strings.Replace(tokens("    - {name: a1, token_env: K_A1, role: agent, node: fra1}\n"),
				"    - name: e2\n", "    - name: fra1\n", 1),
			wantErr: "both an edge.nodes[] and a scrubbing.nodes[] entry",
		},
		{
			// E6.1 does not relax the tenant rule for agents.
			name:    "bound agent token with a tenant",
			yaml:    tokens("    - {name: a1, token_env: K_A1, role: agent, node: e1, tenant: acme}\n") + "hostgroups:\n  - {name: acme-web, tenant: acme, networks: [\"203.0.113.0/26\"]}\n",
			wantErr: "cannot be tenant-scoped",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Parse([]byte(c.yaml))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				for _, tk := range cfg.API.TokenSpecs {
					if tk.Role == RoleAgent && tk.Node == "" {
						t.Errorf("token %s lost its node binding in TokenSpecs", tk.Name)
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted; want an error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

// UnboundAgentTokens names agents without a node only when there are nodes to
// bind them to: a brain with no fleet has nothing to warn about, and operator
// and viewer tokens are never "unbound".
func TestUnboundAgentTokens(t *testing.T) {
	withTokens := func(list, tail string) *Config {
		cfg, err := Parse([]byte(strings.Replace(validBase, "api:\n  listen: \"127.0.0.1:8080\"\n",
			"api:\n  listen: \"127.0.0.1:8080\"\n  tokens:\n"+list, 1) + tail))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	edge := "\nedge:\n  zones_file: /etc/kapkan/zones.yaml\n  nodes:\n    - name: e1\n"
	if got := withTokens("    - {name: a0, token_env: K_A0, role: agent}\n    - {name: o, token_env: K_O, role: operator}\n", "").UnboundAgentTokens(); got != nil {
		t.Errorf("no nodes configured, yet unbound = %v", got)
	}
	got := withTokens("    - {name: a0, token_env: K_A0, role: agent}\n    - {name: a1, token_env: K_A1, role: agent, node: e1}\n    - {name: o, token_env: K_O, role: operator}\n", edge).UnboundAgentTokens()
	if strings.Join(got, ",") != "a0" {
		t.Errorf("unbound = %v, want [a0]", got)
	}
	if got := withTokens("    - {name: a1, token_env: K_A1, role: agent, node: e1}\n", edge).UnboundAgentTokens(); got != nil {
		t.Errorf("every agent bound, yet unbound = %v", got)
	}
}

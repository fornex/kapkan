package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
)

// TestWarnUnboundAgentTokens pins the daemon-log half of the E6.1 grace
// contract: the unbound agent tokens are named — at startup through
// WarnUnboundAgentTokens, on every reload through ApplyReload — and a fleet
// with every agent bound logs nothing.
func TestWarnUnboundAgentTokens(t *testing.T) {
	base := strings.Replace(ladderBase, "dataplane:\n  interfaces: [\"eth0\"]\n", "", 1)
	withTokens := func(list string) *config.Config {
		cfg, err := config.Parse([]byte(strings.Replace(base, "api:\n  listen: \"127.0.0.1:8080\"\n",
			"api:\n  listen: \"127.0.0.1:8080\"\n  tokens:\n"+list, 1) +
			"edge:\n  zones_file: /etc/kapkan/zones.yaml\n  nodes:\n    - name: e1\n"))
		if err != nil {
			t.Fatalf("config.Parse: %v", err)
		}
		return cfg
	}
	mixed := withTokens("    - {name: a0, token_env: K_A0, role: agent}\n" +
		"    - {name: a1, token_env: K_A1, role: agent, node: e1}\n" +
		"    - {name: o, token_env: K_O, role: operator}\n")
	allBound := withTokens("    - {name: a1, token_env: K_A1, role: agent, node: e1}\n" +
		"    - {name: o, token_env: K_O, role: operator}\n")

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	check := func(what string) {
		t.Helper()
		s := buf.String()
		if !strings.Contains(s, "not bound to a node") || !strings.Contains(s, "a0") {
			t.Fatalf("%s: the unbound token is not named:\n%s", what, s)
		}
		if strings.Contains(s, "a1") || strings.Contains(s, `"o"`) {
			t.Fatalf("%s: a bound agent or an operator is named as unbound:\n%s", what, s)
		}
		if !strings.Contains(s, "api.tokens[].node") {
			t.Fatalf("%s: the line does not say which key fixes it:\n%s", what, s)
		}
	}
	WarnUnboundAgentTokens(log, mixed)
	check("startup")

	buf.Reset()
	(&App{log: log}).ApplyReload(mixed) // no data plane: the reload path still warns
	check("reload")

	buf.Reset()
	WarnUnboundAgentTokens(log, allBound)
	(&App{log: log}).ApplyReload(allBound)
	if buf.Len() != 0 {
		t.Fatalf("every agent bound, yet the log says:\n%s", buf.String())
	}
}

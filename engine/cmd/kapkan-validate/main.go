//go:build js && wasm

// Command kapkan-validate compiles the engine's real config Parse+validate
// chain to WebAssembly and exposes it to the browser as kapkanValidateConfig(),
// so the kapkan.io config builder can show engine-exact errors inline without
// sending the config anywhere. Filesystem checks (geoip database, exec hook)
// are deferred to the server here (see internal/config/statfile_js.go); the
// authoritative file check is `kapkan -check-config` on the host.
package main

import (
	"fmt"
	"strings"
	"syscall/js"

	"github.com/kapkan-io/kapkan/internal/config"
)

func main() {
	js.Global().Set("kapkanValidateConfig", js.FuncOf(validate))
	// Keep the Go runtime alive so the exported function stays callable.
	select {}
}

// validate parses and validates the YAML passed as args[0] and returns
// { ok: bool, error?: string, summary?: string }.
func validate(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return map[string]any{"ok": false, "error": "no config provided"}
	}
	cfg, err := config.Parse([]byte(args[0].String()))
	if err != nil {
		msg := err.Error()
		msg = strings.TrimPrefix(msg, "validate config: ")
		msg = strings.TrimPrefix(msg, "parse config: ")
		return map[string]any{"ok": false, "error": msg}
	}
	return map[string]any{"ok": true, "summary": summarize(cfg)}
}

func summarize(cfg *config.Config) string {
	var b strings.Builder
	mode := "dry-run — announcements simulated"
	if !cfg.DryRun {
		mode = "LIVE — announcements WILL be sent"
	}
	fmt.Fprintf(&b, "mode: %s\n", mode)
	fmt.Fprintf(&b, "networks: %s\n", strings.Join(cfg.Networks, ", "))
	fmt.Fprintf(&b, "groups: %d (including the implicit global group)\n", len(cfg.Groups))
	for _, g := range cfg.Groups {
		fmt.Fprintf(&b, "  • %-16s calc=%-8s ban=%-5t %s\n", g.Name, g.Calc, g.BanEnabled, ladder(g.Escalation))
	}
	return b.String()
}

func ladder(stages []config.EscalationStage) string {
	if len(stages) == 0 {
		return "mitigation=none"
	}
	parts := make([]string, len(stages))
	for i, s := range stages {
		parts[i] = fmt.Sprintf("%s@%ds", s.Action, s.AfterSeconds)
	}
	return "mitigation=" + strings.Join(parts, " → ")
}

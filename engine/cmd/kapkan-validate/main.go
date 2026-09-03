//go:build js && wasm

// Command kapkan-validate compiles the engine's real config Parse+validate
// chain to WebAssembly and exposes it to the browser as kapkanValidateConfig()
// — and the zones file's chain as kapkanValidateZones() — so the kapkan.io
// config builder and the zones editor can show engine-exact errors inline
// without sending anything anywhere. Filesystem checks (geoip database, exec
// hook, the zones file a kapkan.yaml points at) are deferred to the server here
// (see internal/config/statfile_js.go); the authoritative check is `kapkan
// -check-config` on the host, which follows edge.zones_file.
package main

import (
	"fmt"
	"strings"
	"syscall/js"

	"github.com/kapkan-io/kapkan/internal/config"
)

func main() {
	js.Global().Set("kapkanValidateConfig", js.FuncOf(validate))
	js.Global().Set("kapkanValidateZones", js.FuncOf(validateZones))
	// Keep the Go runtime alive so the exported functions stay callable.
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

// validateZones parses and validates a zones file (edge.zones_file) passed as
// args[0] with the same shape of answer.
func validateZones(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return map[string]any{"ok": false, "error": "no zones file provided"}
	}
	z, err := config.ParseZones([]byte(args[0].String()))
	if err != nil {
		msg := err.Error()
		msg = strings.TrimPrefix(msg, "validate zones: ")
		msg = strings.TrimPrefix(msg, "parse zones: ")
		return map[string]any{"ok": false, "error": msg}
	}
	return map[string]any{"ok": true, "summary": summarizeZones(z)}
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

func summarizeZones(z *config.Zones) string {
	var b strings.Builder
	fmt.Fprintf(&b, "zones: %d\n", len(z.Zones))
	for _, zone := range z.Zones {
		policy := zone.Policy.Mode
		if zone.Policy.Mode == config.ZonePolicyDecide {
			policy = fmt.Sprintf("decide/%s", zone.Policy.FailureMode)
			if zone.Policy.Rate.RPS > 0 || zone.Policy.Rate.Concurrency > 0 {
				policy += fmt.Sprintf(" rps=%d conc=%d", zone.Policy.Rate.RPS, zone.Policy.Rate.Concurrency)
			}
		}
		fmt.Fprintf(&b, "  • %-40s tls>=%s %-24s origins=%s\n", zone.Name, zone.TLS.MinVersion, policy, strings.Join(zone.Origins, ","))
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

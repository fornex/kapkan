package config

// Schema generation. GenerateSchema derives a deterministic JSON description of
// the configuration FILE shape directly from the Config struct's yaml tags, so
// the kapkan.io config wizard can render and pre-validate fields without
// re-implementing the schema, and a drift gate (schema_test.go) can fail the
// build whenever config.go changes the file shape but docs/config-schema.json
// was not regenerated.
//
// What reflection derives on its own: every yaml key path, its JSON type,
// pointer/slice optionality, and object closedness (additionalProperties:false,
// mirroring yaml.KnownFields(true) — an unknown key rejects the whole file).
//
// What reflection CANNOT see, supplied by the explicit tables below (they
// mirror the literals in validate()/resolve* and must be kept in step with
// them): the accepted value set of the enum-like string fields, the numeric
// bounds, and the regex patterns. Cross-field rules (CIDR overlap, prefix
// containment, monotonic escalation ladders, conditional requireds, …) cannot
// be expressed in a per-field schema at all; they are pinned by
// schema_rules_test.go and enforced for operators by `kapkan -check-config`.

import (
	"encoding/json"
	"reflect"
	"strings"
)

// enumValues maps a yaml path to the accepted non-empty string values. Keyed by
// the GLOBAL path; a leading "hostgroups." is stripped on lookup because a
// hostgroup mirrors the global blocks. Values reference the typed constants so
// a constant's string value cannot drift away from the schema unnoticed.
var enumValues = map[string][]string{
	"mitigation":             {string(MitigateBlackhole), string(MitigateFlowSpec), string(MitigateDivert)},
	"ban.fallback":           {"none", string(MitigateBlackhole)},
	"carpet.mitigation":      {string(MitigateFlowSpec), string(MitigateBlackhole)},
	"flowspec.action":        {string(FlowSpecDiscard), string(FlowSpecRateLimit)},
	"escalation.action":      {string(EscalateNone), string(EscalateFlowSpec), string(EscalateDivert), string(EscalateBlackhole)},
	"hostgroups.calculation": {string(CalcPerHost), string(CalcTotal)},
	"api.tokens.role":        {string(RoleViewer), string(RoleOperator)},
	"notify.exec.format":     {ExecFormatKapkan, ExecFormatFastNetMon},
	"update_check.channel":   {"stable", "prerelease"},
}

// numericBounds maps a yaml path to its inclusive {minimum,maximum} as enforced
// by validate(). Same global-path keying with a "hostgroups." strip on lookup.
// Cross-field upper bounds (e.g. batch_size <= queue_size) cannot live here.
var numericBounds = map[string]map[string]float64{
	"sampling.default_rate": {"minimum": 1},

	"thresholds.pps":           {"minimum": 1},
	"thresholds.mbps":          {"minimum": 1},
	"thresholds.flows_per_sec": {"minimum": 1},

	"ban.ttl_seconds":              {"minimum": 1},
	"ban.unban_hysteresis_seconds": {"minimum": 0},
	"ban.max_active_bans":          {"minimum": 1},
	"ban.max_banned_fraction":      {"minimum": 0, "maximum": 1},
	"ban.max_bans_per_window":      {"minimum": 0},
	"ban.ban_window_seconds":       {"minimum": 0},

	"baseline.factor":              {"minimum": 1.5, "maximum": 100},
	"baseline.half_life_seconds":   {"minimum": 10, "maximum": 604800},
	"baseline.warmup_seconds":      {"minimum": 0, "maximum": 86400},
	"baseline.floor.pps":           {"minimum": 1},
	"baseline.floor.mbps":          {"minimum": 1},
	"baseline.floor.flows_per_sec": {"minimum": 1},

	"samples.buffer_flows":     {"minimum": 256, "maximum": 1048576},
	"samples.flows_per_attack": {"minimum": 1, "maximum": 500},

	"storage.clickhouse.ttl_days":                 {"minimum": 1, "maximum": 365},
	"storage.clickhouse.batch_size":               {"minimum": 1},
	"storage.clickhouse.queue_size":               {"minimum": 1, "maximum": 10000000},
	"storage.clickhouse.flush_interval_seconds":   {"minimum": 1, "maximum": 3600},
	"storage.clickhouse.traffic_interval_seconds": {"minimum": 1, "maximum": 3600},

	"escalation.after_seconds": {"minimum": 0, "maximum": 86400},

	"bgp.local_asn":            {"minimum": 1},
	"bgp.neighbors.remote_asn": {"minimum": 1},
	// 0 means "use the default" (120 / 3600), so the floor is 0, not 1.
	"bgp.graceful_restart.restart_seconds":          {"minimum": 0, "maximum": 4095},
	"bgp.graceful_restart.long_lived_stale_seconds": {"minimum": 0, "maximum": 86400},

	// 0 means "use the default" (6h); a non-zero value is floored at 3600 by
	// validate() (a cross-field rule a single bound can't express).
	"update_check.interval_seconds": {"minimum": 0},

	"flowspec.rate_mbps":                {"minimum": 0},
	"flowspec.min_source_concentration": {"minimum": 0, "maximum": 1},

	"carpet.aggregation_prefix_v4":  {"minimum": 8, "maximum": 32},
	"carpet.aggregation_prefix_v6":  {"minimum": 16, "maximum": 128},
	"carpet.min_hosts":              {"minimum": 2},
	"carpet.max_active_prefix_bans": {"minimum": 1},
}

// stringPatterns maps a yaml path to a regex the value must match. Beyond these
// explicit entries, every field whose name ends in "_env" is an environment
// variable NAME and gets envNameRe. The regexes reference the same compiled
// expressions validate() uses, so they cannot drift. IP/CIDR/host:port/community
// fields are validated imperatively (net/netip), not by regex, and so carry no
// pattern here — `kapkan -check-config` is their backstop; the overlay marks
// their expected format for the wizard.
var stringPatterns = map[string]string{
	"tenant":                      groupNameRe.String(),
	"hostgroups.name":             groupNameRe.String(),
	"storage.clickhouse.database": dbNameRe.String(),
}

// GenerateSchema returns the canonical JSON Schema for the configuration file.
// Output is deterministic: encoding/json sorts object keys, and every array we
// emit (enums) is built in a fixed order, so two calls are byte-identical and
// the result can be committed and diffed.
func GenerateSchema() ([]byte, error) {
	root := schemaForStruct(reflect.TypeOf(Config{}), "")
	doc := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"title":                "Kapkan configuration",
		"description":          "Generated from engine/internal/config/config.go by `make -C engine schema`. DO NOT EDIT BY HAND. The file shape is closed: unknown keys are rejected.",
		"type":                 "object",
		"additionalProperties": false,
		"properties":           root["properties"],
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// schemaForStruct emits an object schema for every yaml-tagged exported field of
// t, recursing into nested structs and slice element types. prefix is the dotted
// path of t within the config (empty at the root).
func schemaForStruct(t reflect.Type, prefix string) map[string]any {
	props := map[string]any{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue // not part of the file shape (parsed-derivative or unexported)
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		props[name] = schemaForType(f.Type, path)
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties":           props,
	}
}

// schemaForType maps a Go type to its schema node. Pointers and slices are
// marked optional (x-optional) — a pointer field or a list may be omitted —
// which also makes a value↔pointer change in config.go visible to the gate.
func schemaForType(t reflect.Type, path string) map[string]any {
	optional := false
	if t.Kind() == reflect.Pointer {
		optional = true
		t = t.Elem()
	}

	var s map[string]any
	switch t.Kind() {
	case reflect.Bool:
		s = map[string]any{"type": "boolean"}
	case reflect.String:
		s = map[string]any{"type": "string"}
		if enum := lookupEnum(path); enum != nil {
			s["enum"] = enum
		}
		if pat, ok := lookupPattern(path); ok {
			s["pattern"] = pat
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		s = map[string]any{"type": "integer"}
		applyBounds(s, path)
	case reflect.Float32, reflect.Float64:
		s = map[string]any{"type": "number"}
		applyBounds(s, path)
	case reflect.Slice:
		optional = true
		s = map[string]any{"type": "array", "items": schemaForType(t.Elem(), path)}
	case reflect.Struct:
		s = schemaForStruct(t, path)
	default:
		// Maps appear only on yaml:"-" parsed-derivative fields, which are
		// skipped before we get here; anything else is opaque.
		s = map[string]any{}
	}

	if optional {
		s["x-optional"] = true
	}
	return s
}

func applyBounds(s map[string]any, path string) {
	if b := lookupBounds(path); b != nil {
		for k, v := range b {
			s[k] = v
		}
	}
}

// stripHostgroups returns the path with a single leading "hostgroups." removed,
// so per-group blocks reuse the global block's rules.
func stripHostgroups(path string) (string, bool) {
	if rest, ok := strings.CutPrefix(path, "hostgroups."); ok {
		return rest, true
	}
	return path, false
}

func lookupEnum(path string) []string {
	if v, ok := enumValues[path]; ok {
		return v
	}
	if rest, ok := stripHostgroups(path); ok {
		if v, ok := enumValues[rest]; ok {
			return v
		}
	}
	return nil
}

func lookupBounds(path string) map[string]float64 {
	if v, ok := numericBounds[path]; ok {
		return v
	}
	if rest, ok := stripHostgroups(path); ok {
		if v, ok := numericBounds[rest]; ok {
			return v
		}
	}
	return nil
}

func lookupPattern(path string) (string, bool) {
	if p, ok := stringPatterns[path]; ok {
		return p, true
	}
	if rest, ok := stripHostgroups(path); ok {
		if p, ok := stringPatterns[rest]; ok {
			return p, true
		}
	}
	// Every "*_env" field names an environment variable.
	if strings.HasSuffix(path, "_env") {
		return envNameRe.String(), true
	}
	return "", false
}

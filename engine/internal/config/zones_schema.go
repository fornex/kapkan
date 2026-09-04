package config

// The zones FILE's schema (edge track, E3.6): the same reflection over the
// Zones struct that GenerateSchema applies to Config, with the zone
// vocabulary's enums and bounds from the tables below, generated into
// docs/zones-schema.json by `kapkan -dump-zones-schema` and pinned by a drift
// gate (zones_schema_test.go) exactly like the configuration schema. Tenant
// tooling and the kapkan.io site read it to pre-validate a zones.yaml; the
// engine-exact check is `kapkan -check-config` (which follows edge.zones_file)
// or the WebAssembly kapkanValidateZones.

import (
	"encoding/json"
	"reflect"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// zoneEnumValues mirrors the literals validateZone accepts. Paths are rooted at
// the zones file ("zones." + the per-zone key), which never collide with a
// kapkan.yaml path, so lookupEnum consults both tables.
var zoneEnumValues = map[string][]string{
	"zones.tls.min_version":       {ZoneTLS12, ZoneTLS13},
	"zones.policy.mode":           {ZonePolicyDecide, ZonePolicyNone},
	"zones.policy.failure_mode":   {ZoneFailOpen, ZoneFailClosed},
	"zones.policy.challenge":      {ZoneChallengeOff, ZoneChallengeManual, ZoneChallengeAuto},
	"zones.acme.directory":        nil, // free-form URL; imperative check
	"zones.acme.fallback":         nil,
	"zones.extra_directives_file": nil,
}

// zoneNumericBounds: 0 means "no ceiling" for both rate fields, so only a
// negative is rejected — and the YAML type is unsigned anyway.
var zoneNumericBounds = map[string]map[string]float64{
	"zones.policy.rate.rps":         {"minimum": 0},
	"zones.policy.rate.concurrency": {"minimum": 0},
	// 0 means "the default" for both rung knobs; otherwise the validator's
	// range.
	"zones.policy.challenge_options.difficulty":         {"minimum": 0, "maximum": maxChallengeDifficulty},
	"zones.policy.challenge_options.cookie_ttl_seconds": {"minimum": 0, "maximum": edgedoc.MaxCookieTTLSeconds},
}

// GenerateZonesSchema returns the canonical JSON Schema for the zones file.
// Deterministic for the same reasons GenerateSchema is.
func GenerateZonesSchema() ([]byte, error) {
	root := schemaForStruct(reflect.TypeOf(Zones{}), "")
	doc := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"title":                "Kapkan edge zones",
		"description":          "Generated from engine/internal/config/zones.go by `make -C engine schema`. DO NOT EDIT BY HAND. The zones file the brain serves to edge nodes (edge.zones_file): one entry per zone with its origins, TLS floor, ACME directories and per-request policy. The file shape is closed: unknown keys are rejected. Names are lower-case hostnames (no wildcards, no IPs, at most 238 characters), origins are host:port with a bracketed IPv6 host; both are checked imperatively, not by pattern.",
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

func lookupZoneEnum(path string) []string {
	if v, ok := zoneEnumValues[path]; ok && len(v) > 0 {
		return v
	}
	return nil
}

func lookupZoneBounds(path string) map[string]float64 {
	if v, ok := zoneNumericBounds[path]; ok {
		return v
	}
	return nil
}

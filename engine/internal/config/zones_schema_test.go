package config

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const zonesSchemaPath = "../../../docs/zones-schema.json"

// The drift gate for the zones file's schema, the twin of
// TestSchemaMatchesGenerated: a change to zones.go's shape or vocabulary that
// is not regenerated fails the build.
func TestZonesSchemaMatchesGenerated(t *testing.T) {
	want, err := os.ReadFile(zonesSchemaPath)
	if err != nil {
		t.Fatalf("read %s: %v\nrun `make -C engine schema` to generate it", zonesSchemaPath, err)
	}
	got, err := GenerateZonesSchema()
	if err != nil {
		t.Fatalf("GenerateZonesSchema: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("%s is stale: zones.go changed the zones file's shape but the schema was not regenerated.\n"+
			"Run `make -C engine schema` and commit the updated %s.", zonesSchemaPath, zonesSchemaPath)
	}
}

func TestZonesSchemaDeterministic(t *testing.T) {
	a, err := GenerateZonesSchema()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateZonesSchema()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("GenerateZonesSchema is not deterministic")
	}
}

// Every zone enum and bound in the tables must land on a real path of the
// generated schema (a renamed key would otherwise leave a dangling rule), and
// every enum-like field of the zone vocabulary must carry its enum.
func TestZonesSchemaEnumsAndBoundsPresent(t *testing.T) {
	raw, err := GenerateZonesSchema()
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	node := func(path string) map[string]any {
		cur := schema
		for _, part := range strings.Split(path, ".") {
			props, _ := cur["properties"].(map[string]any)
			next, ok := props[part].(map[string]any)
			if !ok {
				t.Fatalf("path %q is not in the zones schema", path)
			}
			if items, ok := next["items"].(map[string]any); ok {
				next = items
			}
			cur = next
		}
		return cur
	}
	for path, values := range zoneEnumValues {
		n := node(path)
		if len(values) == 0 {
			if _, has := n["enum"]; has {
				t.Fatalf("%s carries an enum but the table says free-form", path)
			}
			continue
		}
		got, _ := n["enum"].([]any)
		if len(got) != len(values) {
			t.Fatalf("%s: enum %v, want %v", path, got, values)
		}
	}
	for path, bounds := range zoneNumericBounds {
		n := node(path)
		for k := range bounds {
			if _, has := n[k]; !has {
				t.Fatalf("%s lacks %s", path, k)
			}
		}
	}
	// The fields the validator treats as enums are exactly these four.
	for _, path := range []string{"zones.tls.min_version", "zones.policy.mode", "zones.policy.failure_mode", "zones.policy.challenge"} {
		if _, has := node(path)["enum"]; !has {
			t.Fatalf("%s has no enum in the zones schema", path)
		}
	}
	// The vocabulary in the schema is the vocabulary the validator accepts.
	for _, c := range []struct{ path, value string }{
		{"zones.tls.min_version", "1.1"}, {"zones.policy.mode", "observe"}, {"zones.policy.failure_mode", "fail"}, {"zones.policy.challenge", "js"},
	} {
		for _, v := range zoneEnumValues[c.path] {
			if v == c.value {
				t.Fatalf("%s: %q must not be in the enum", c.path, c.value)
			}
		}
	}
}

package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

const (
	schemaPath  = "../../../docs/config-schema.json"
	overlayPath = "../../../docs/config-schema-overlay.json"
)

// TestSchemaMatchesGenerated is the drift gate. It fails when config.go changes
// the file shape (a field added/removed/renamed/retyped, an enum/bound/pattern
// table edited) but docs/config-schema.json was not regenerated. This is the
// cross-contributor guarantee — it runs under `make test`, independent of any
// editor tooling. Mirrors the docs/callback-schema.json + channels_test.go
// precedent, but compares the whole canonical document since we own both sides.
func TestSchemaMatchesGenerated(t *testing.T) {
	want, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v\nrun `make -C engine schema` to generate it", schemaPath, err)
	}
	got, err := GenerateSchema()
	if err != nil {
		t.Fatalf("GenerateSchema: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("%s is stale: config.go changed the config shape but the schema was not regenerated.\n"+
			"Run `make -C engine schema` and commit the updated %s.", schemaPath, schemaPath)
	}
}

// TestSchemaDeterministic guards the gate itself: a non-deterministic generator
// (e.g. map iteration leaking into array order) would make the gate flap.
func TestSchemaDeterministic(t *testing.T) {
	a, err := GenerateSchema()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSchema()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("GenerateSchema is not deterministic across calls")
	}
}

// TestSchemaEnumsPresent pins that the enum-bearing fields still carry an enum.
// A new MitigationMethod/Role/… field reflected as a plain string (no enum)
// would silently degrade the wizard to free-text; this catches the regression
// at the known paths.
func TestSchemaEnumsPresent(t *testing.T) {
	doc := parseSchema(t)
	for _, segs := range [][]string{
		{"mitigation"},
		{"ban", "fallback"},
		{"flowspec", "action"},
		{"escalation", "action"},
		{"hostgroups", "calculation"},
		{"api", "tokens", "role"},
		{"notify", "exec", "format"},
	} {
		node := resolveField(t, doc, segs...)
		enum, ok := node["enum"].([]any)
		if !ok || len(enum) == 0 {
			t.Errorf("field %v: expected a non-empty enum, got %v", segs, node["enum"])
		}
	}
}

// TestOverlayKeysExist ensures every path the hand-maintained overlay annotates
// still resolves in the generated schema, so a renamed/removed field leaves a
// dangling overlay entry the build catches.
func TestOverlayKeysExist(t *testing.T) {
	raw, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read %s: %v", overlayPath, err)
	}
	var overlay struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(raw, &overlay); err != nil {
		t.Fatalf("parse %s: %v", overlayPath, err)
	}
	if len(overlay.Fields) == 0 {
		t.Fatalf("%s has no fields", overlayPath)
	}
	doc := parseSchema(t)
	for dotted := range overlay.Fields {
		resolveField(t, doc, splitPath(dotted)...)
	}
}

// --- helpers ---

func parseSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := GenerateSchema()
	if err != nil {
		t.Fatalf("GenerateSchema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal generated schema: %v", err)
	}
	return doc
}

func splitPath(dotted string) []string {
	out := []string{}
	for _, s := range bytes.Split([]byte(dotted), []byte(".")) {
		out = append(out, string(s))
	}
	return out
}

// resolveField walks an object schema along field-name segments, descending
// through nested "properties" and transparently through array "items", and
// returns the leaf field's schema node. Fails the test if any segment is
// missing — that is how a stale overlay key or moved enum field is reported.
func resolveField(t *testing.T, cur map[string]any, segs ...string) map[string]any {
	t.Helper()
	for _, seg := range segs {
		props, ok := cur["properties"].(map[string]any)
		if !ok {
			t.Fatalf("path %v: no properties while resolving %q", segs, seg)
		}
		next, ok := props[seg].(map[string]any)
		if !ok {
			t.Fatalf("path %v: field %q not found in schema", segs, seg)
		}
		if items, ok := next["items"].(map[string]any); ok {
			cur = items
		} else {
			cur = next
		}
	}
	return cur
}

package config

// The method -> ladder-action mapping, pinned.
//
// MitigationMethod.Action is the single hop between "what the operator wrote in
// the config" and "what mechanism will actually run". Every synthesized
// single-rung ladder — global, per hostgroup, and the carpet (prefix) path in
// internal/mitigate — resolves through it.
//
// It replaced a catch-all switch whose default was blackhole. That default is
// why widening carpet.mitigation to accept "dataplane" was not a one-line
// change: the validator would have accepted the method and the mapping would
// have quietly returned "blackhole the whole aggregation prefix". These tests
// make the mapping total and keep it that way.

import "testing"

// TestMitigationMethodActionIsTotal walks every method the type defines and
// asserts the mechanism it maps to. A method added to the type without a row
// here fails rather than defaulting to anything.
func TestMitigationMethodActionIsTotal(t *testing.T) {
	want := map[MitigationMethod]EscalationAction{
		MitigateBlackhole: EscalateBlackhole,
		MitigateFlowSpec:  EscalateFlowSpec,
		MitigateDivert:    EscalateDivert,
		MitigateDataplane: EscalateDataplane,
	}
	for _, m := range AllMitigationMethods() {
		exp, ok := want[m]
		if !ok {
			t.Fatalf("AllMitigationMethods() lists %q but this table has no row for it: add one "+
				"rather than letting the mapping decide on its own what %q means", m, m)
		}
		if got := m.Action(); got != exp {
			t.Errorf("method %q maps to action %q, want %q — the configured method and the "+
				"running mechanism would be different things", m, got, exp)
		}
		delete(want, m)
	}
	for m := range want {
		t.Errorf("method %q is in the expectation table but not in AllMitigationMethods(); one of "+
			"the two lists is stale", m)
	}
}

// TestUnknownMethodDoesNotBecomeABlackhole pins the failure mode of a lost
// method. The old catch-all answered "blackhole", which on the carpet path
// means a whole /24 or /48 null-routed because a branch forgot a case. An
// unrecognised method must degrade to alert-only instead: doing nothing and
// saying so is recoverable, taking address space offline is not.
func TestUnknownMethodDoesNotBecomeABlackhole(t *testing.T) {
	if got := MitigationMethod("something-we-have-not-built-yet").Action(); got != EscalateNone {
		t.Errorf("an unknown method maps to %q, want %q. A mapping that answers %q for anything it "+
			"does not recognise turns a typo — or a forgotten switch case — into the widest "+
			"action this product has.", got, EscalateNone, EscalateBlackhole)
	}
	// The empty method is NOT an unknown method: it means "nothing configured
	// anywhere", and its historical default is blackhole. That default is
	// reached only through the resolver, which has already validated the field.
	if got := methodAction(""); got != EscalateBlackhole {
		t.Errorf("methodAction(\"\") = %q, want %q (the documented default for an unset method)",
			got, EscalateBlackhole)
	}
}

// TestCarpetMethodsResolve pins that every method carpet.mitigation advertises
// actually resolves through Carpet.Method. A method that parses and then
// resolves to "" is alert-only: an operator who configured a mitigation would
// get none, and the only sign would be a missing ban.
func TestCarpetMethodsResolve(t *testing.T) {
	for _, m := range CarpetMethods() {
		c := Carpet{Mitigation: string(m)}
		if got := c.Method(); got != m {
			t.Errorf("carpet.mitigation %q resolves to %q, want %q", m, got, m)
		}
		if got := c.Method().Action(); got == EscalateNone {
			t.Errorf("carpet.mitigation %q resolves to an alert-only action; it was advertised as "+
				"a mitigation", m)
		}
	}
	if got := (Carpet{Mitigation: ""}).Method(); got != "" {
		t.Errorf("an empty carpet.mitigation resolved to %q, want alert-only", got)
	}
	if got := (Carpet{Mitigation: "divert"}).Method(); got != "" {
		t.Errorf("carpet.mitigation %q resolved to %q; divert is deliberately not a carpet method, "+
			"and a method the validator rejects must never resolve to a mechanism", "divert", got)
	}
}

// TestSchemaCarpetEnumMatchesTheValidator is the drift gate between the config builder
// and the engine: the schema enum and the accepted set are the same list.
func TestSchemaCarpetEnumMatchesTheValidator(t *testing.T) {
	got := enumValues["carpet.mitigation"]
	want := CarpetMethods()
	if len(got) != len(want) {
		t.Fatalf("schema enum %v has %d values, CarpetMethods() has %d", got, len(got), len(want))
	}
	for i, m := range want {
		if got[i] != string(m) {
			t.Errorf("schema enum[%d] = %q, want %q", i, got[i], m)
		}
	}
}

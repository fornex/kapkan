package api

// The frozen JSON contract for measured in-kernel drops.
//
// Two claims are pinned here, and the first is the one that costs money if it
// breaks:
//
//  1. A ban with no data-plane rules serializes EXACTLY as it did before this
//     feature existed. Byte-for-byte, against a golden file — not "the fields I
//     remembered to check". Every deployment that is not running the XDP data
//     plane (the overwhelming majority: flowspec and blackhole ladders) must see
//     no change at all in /api/v1/bans, and the only way to know that is to
//     compare all the bytes.
//
//  2. A ban WITH rules gains exactly one nested object under "dataplane", whose
//     key names are what docs/callback-schema.json, the console and
//     engine/deploy/dataplane-operations.md are written against.
//
// Constructing the Bans directly rather than driving a real mitigation is
// deliberate: this is a test about SERIALIZATION, and a ban built by hand pins
// the shape without depending on which rung a ladder happened to resolve to. The
// end-to-end proof that a real kernel produces these numbers lives in
// internal/app's Linux e2e, where there is a datapath to produce them.

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// blackholeBan is a fully-populated ban of the kind that must not change.
func blackholeBan() mitigate.Ban {
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	return mitigate.Ban{
		Target:    netip.MustParseAddr("203.0.113.66"),
		Prefix:    netip.MustParsePrefix("203.0.113.66/32"),
		Metric:    "pps",
		Rate:      200000,
		Threshold: 1000,
		NextHop:   "192.0.2.1",
		Community: "65000:666",
		LocalPref: 100,
		Route:     "203.0.113.66/32 next-hop 192.0.2.1 community 65000:666",
		State:     mitigate.BanActive,
		Manual:    false,
		StartedAt: at,
		ExpiresAt: at.Add(10 * time.Minute),
		Method:    config.MitigateBlackhole,
		Escalation: []config.EscalationStage{
			{AfterSeconds: 0, Action: config.EscalateBlackhole},
		},
		EscalationStep: 0,
	}
}

// TestBlackholeBanJSONIsByteIdentical is the compatibility gate.
//
// Update the golden ONLY when a change to the ban contract is intended and the
// consumers (docs, console, callback schema) are being updated with it. A diff
// here on a data-plane change means the nested object leaked into bans that have
// no rules — which would break every consumer that has not been told about it.
func TestBlackholeBanJSONIsByteIdentical(t *testing.T) {
	got, err := json.MarshalIndent(blackholeBan(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "blackhole_ban.golden.json")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with -update)", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("a ban with no data-plane rules no longer serializes identically.\n"+
			"--- golden (%s)\n%s\n--- got\n%s", path, want, got)
	}
	// Belt and braces, so the failure message above is not the only thing
	// pointing at the cause.
	var asMap map[string]any
	if err := json.Unmarshal(got, &asMap); err != nil {
		t.Fatal(err)
	}
	if _, ok := asMap["dataplane"]; ok {
		t.Error(`a blackhole ban carries a "dataplane" key; it must be omitted entirely`)
	}
}

// TestDataplaneBanJSONContract pins the added object's key names and nesting.
func TestDataplaneBanJSONContract(t *testing.T) {
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	b := blackholeBan()
	b.Method = config.MitigateDataplane
	b.Route = "dataplane: dst 203.0.113.66/32 udp src-port 123 -> discard"
	b.NextHop, b.Community, b.LocalPref = "", "", 0
	b.FlowSpec = []mitigate.FlowSpecRule{{
		Dst: netip.MustParsePrefix("203.0.113.66/32"), Proto: 17, SrcPort: 123, Action: "discard",
	}}
	b.Dataplane = &mitigate.BanDataplane{
		Packets: 41231, Bytes: 19873342,
		Rules:      []mitigate.BanDataplaneRule{{ID: 0, Packets: 41231, Bytes: 19873342}},
		PolicyID:   0,
		MeasuredAt: at.Add(90 * time.Second),
	}

	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	dp, ok := got["dataplane"].(map[string]any)
	if !ok {
		t.Fatalf(`"dataplane" is not a nested object: %v`, got["dataplane"])
	}
	// Exactly these keys, no more: an accidental extra field is an API addition
	// nobody documented.
	wantKeys := map[string]bool{"packets": true, "bytes": true, "rules": true,
		"policy_id": true, "measured_at": true}
	for k := range dp {
		if !wantKeys[k] {
			t.Errorf(`undocumented key "dataplane.%s"`, k)
		}
		delete(wantKeys, k)
	}
	for k := range wantKeys {
		t.Errorf(`missing key "dataplane.%s"`, k)
	}
	// "stale" is omitempty and absent on a fresh measurement — the common case,
	// so the common payload stays small — but present the moment it is true.
	if _, ok := dp["stale"]; ok {
		t.Error(`"stale" must be omitted when false`)
	}
	b.Dataplane.Stale = true
	raw2, _ := json.Marshal(b)
	var got2 map[string]any
	_ = json.Unmarshal(raw2, &got2)
	if st := got2["dataplane"].(map[string]any)["stale"]; st != true {
		t.Errorf(`"stale" = %v, want true`, st)
	}

	// The per-rule array joins to FlowSpec BY INDEX, which is the whole reason
	// the entries carry no match description of their own.
	rules := dp["rules"].([]any)
	if len(rules) != len(b.FlowSpec) {
		t.Fatalf("rules has %d entries, flowspec has %d; the console joins them by index",
			len(rules), len(b.FlowSpec))
	}
	r0 := rules[0].(map[string]any)
	for _, k := range []string{"id", "packets", "bytes"} {
		if _, ok := r0[k]; !ok {
			t.Errorf(`missing key "dataplane.rules[].%s"`, k)
		}
	}
	t.Logf("dataplane object: %s", mustJSON(t, dp))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

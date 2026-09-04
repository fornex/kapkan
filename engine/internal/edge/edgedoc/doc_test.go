package edgedoc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecodeRoundTripsEmpty(t *testing.T) {
	body, err := json.Marshal(Empty())
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(body)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Version != Version || len(d.Zones) != 0 || d.Zones == nil || d.ACMEChallenges == nil || d.IssuanceGrants == nil {
		t.Fatalf("decoded %+v", d)
	}
}

func TestDecodeRefusesOtherVersions(t *testing.T) {
	for _, body := range []string{`{"version":2,"zones":[]}`, `{"version":0}`, `{"zones":[]}`} {
		_, err := Decode([]byte(body))
		if err == nil || !strings.Contains(err.Error(), "version") {
			t.Errorf("%s: err = %v, want a version refusal", body, err)
		}
	}
}

func TestDecodeToleratesUnknownKeysAndNullArrays(t *testing.T) {
	body := `{"version":1,"zones":null,"acme_challenges":null,"issuance_grants":null,"future_key":{"x":1}}`
	d, err := Decode([]byte(body))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.Zones == nil || d.ACMEChallenges == nil || d.IssuanceGrants == nil {
		t.Fatalf("null arrays must decode to empty slices, got %+v", d)
	}
}

// TestDecodeWithoutClearanceKeysLeavesNil pins the E4.1 extension rule: a
// zone from an older brain simply has no clearance keys (nil slice, key
// absent on re-encode), and a zone with keys decodes them in order.
func TestDecodeWithoutClearanceKeysLeavesNil(t *testing.T) {
	old := `{"version":1,"zones":[{"name":"a.example","origins":["10.0.0.1:443"],"tls":{"min_version":"1.2"},` +
		`"policy":{"mode":"decide","failure_mode":"open","challenge":"off","rate":{}}}],"acme_challenges":[],"issuance_grants":[]}`
	d, err := Decode([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if d.Zones[0].ClearanceKeys != nil {
		t.Fatalf("clearance keys from an old document: %+v", d.Zones[0].ClearanceKeys)
	}
	body, _ := json.Marshal(d)
	if strings.Contains(string(body), "clearance_keys") {
		t.Fatalf("empty clearance keys were encoded: %s", body)
	}
	withKeys := `{"version":1,"zones":[{"name":"a.example","origins":["10.0.0.1:443"],"tls":{"min_version":"1.2"},` +
		`"policy":{"mode":"decide","failure_mode":"open","challenge":"manual","rate":{}},` +
		`"clearance_keys":[{"id":"c20260101","secret":"YQ","not_before":"2026-01-01T00:00:00Z","not_after":"2026-01-03T00:00:00Z"},` +
		`{"id":"c20260102","secret":"Yg","not_before":"2026-01-02T00:00:00Z","not_after":"2026-01-04T00:00:00Z"}]}],` +
		`"acme_challenges":[],"issuance_grants":[]}`
	d, err = Decode([]byte(withKeys))
	if err != nil {
		t.Fatal(err)
	}
	keys := d.Zones[0].ClearanceKeys
	if len(keys) != 2 || keys[0].ID != "c20260101" || keys[1].Secret != "Yg" || d.Zones[0].Policy.Challenge != ChallengeManual {
		t.Fatalf("decoded keys: %+v policy %+v", keys, d.Zones[0].Policy)
	}
}

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	if _, err := Decode([]byte(`{"version":1,`)); err == nil {
		t.Fatal("malformed body accepted")
	}
	if _, err := Decode([]byte(`{"version":1,"zones":"nope"}`)); err == nil {
		t.Fatal("wrongly typed zones accepted")
	}
}

// The wire shape is frozen: this test pins every key name at version 1,
// including the ACME challenge and issuance-grant shapes the issuance
// coordinator will populate, and the RFC 3339 time encoding.
func TestFrozenKeyNames(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d := Empty()
	d.Zones = append(d.Zones, Zone{
		Name:                "example.com",
		Origins:             []string{"10.0.0.1:443"},
		TLS:                 TLS{MinVersion: TLS12, H3: true},
		ACMEDirectory:       "https://ca.example/directory",
		ACMEFallback:        "https://fallback-ca.example/directory",
		Policy:              Policy{Mode: ModeDecide, FailureMode: FailOpen, Challenge: ChallengeOff, Rate: Rate{RPS: 5, Concurrency: 2}},
		ExtraDirectivesFile: "/etc/kapkan/extra/example.com.conf",
		ClearanceKeys:       []ClearanceKey{{ID: "c20260102", Secret: "c2VjcmV0", NotBefore: at, NotAfter: at.Add(48 * time.Hour)}},
	})
	d.ACMEChallenges = append(d.ACMEChallenges, Challenge{Zone: "example.com", Token: "tok", KeyAuthorization: "tok.thumb", ExpiresAt: at})
	d.IssuanceGrants = append(d.IssuanceGrants, Grant{Zone: "example.com", Node: "e1", ExpiresAt: at})
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"zones":[{"name":"example.com","origins":["10.0.0.1:443"],"tls":{"min_version":"1.2","h3":true},` +
		`"acme_directory":"https://ca.example/directory","acme_fallback":"https://fallback-ca.example/directory",` +
		`"policy":{"mode":"decide","failure_mode":"open","challenge":"off",` +
		`"rate":{"rps":5,"concurrency":2}},"extra_directives_file":"/etc/kapkan/extra/example.com.conf",` +
		`"clearance_keys":[{"id":"c20260102","secret":"c2VjcmV0","not_before":"2026-01-02T03:04:05Z","not_after":"2026-01-04T03:04:05Z"}]}],` +
		`"acme_challenges":[{"zone":"example.com","token":"tok","key_authorization":"tok.thumb","expires_at":"2026-01-02T03:04:05Z"}],` +
		`"issuance_grants":[{"zone":"example.com","node":"e1","expires_at":"2026-01-02T03:04:05Z"}]}`
	if string(body) != want {
		t.Fatalf("encoding changed — the v1 contract is frozen\n got %s\nwant %s", body, want)
	}
}

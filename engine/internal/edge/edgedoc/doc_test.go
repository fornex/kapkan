package edgedoc

import (
	"encoding/json"
	"strings"
	"testing"
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

func TestDecodeRejectsMalformedJSON(t *testing.T) {
	if _, err := Decode([]byte(`{"version":1,`)); err == nil {
		t.Fatal("malformed body accepted")
	}
	if _, err := Decode([]byte(`{"version":1,"zones":"nope"}`)); err == nil {
		t.Fatal("wrongly typed zones accepted")
	}
}

// The wire shape is frozen: this test pins the exact key names at version 1.
func TestFrozenKeyNames(t *testing.T) {
	d := Empty()
	d.Zones = append(d.Zones, Zone{
		Name:          "example.com",
		Origins:       []string{"10.0.0.1:443"},
		TLS:           TLS{MinVersion: TLS12, H3: false},
		ACMEDirectory: "https://ca.example/directory",
		Policy:        Policy{Mode: ModeDecide, FailureMode: FailOpen, Challenge: ChallengeOff, Rate: Rate{RPS: 5, Concurrency: 2}},
	})
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"zones":[{"name":"example.com","origins":["10.0.0.1:443"],"tls":{"min_version":"1.2"},` +
		`"acme_directory":"https://ca.example/directory","policy":{"mode":"decide","failure_mode":"open","challenge":"off",` +
		`"rate":{"rps":5,"concurrency":2}}}],"acme_challenges":[],"issuance_grants":[]}`
	if string(body) != want {
		t.Fatalf("encoding changed — the v1 contract is frozen\n got %s\nwant %s", body, want)
	}
}

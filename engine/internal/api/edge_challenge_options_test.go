package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// TestBuildEdgeDocChallengeOptions pins how the rung's options travel: the
// zones file's defaults (watch-only, nothing exempt) encode to NOTHING — a
// document written before E4 keeps its bytes and its ETag — and anything
// else is resolved and carried.
func TestBuildEdgeDocChallengeOptions(t *testing.T) {
	no := false
	yes := true
	z := &config.Zones{Zones: []config.Zone{
		{Name: "a.example", Origins: []string{"10.0.0.1:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeOff}},
		{Name: "b.example", Origins: []string{"10.0.0.2:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeManual,
				ChallengeOptions: config.ZoneChallengeOptions{DryRun: &yes}}},
		{Name: "c.example", Origins: []string{"10.0.0.3:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeManual,
				ChallengeOptions: config.ZoneChallengeOptions{DryRun: &no, ExemptPaths: []string{"/healthz", "/api/"}}}},
		{Name: "d.example", Origins: []string{"10.0.0.4:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeAuto,
				ChallengeOptions: config.ZoneChallengeOptions{ExemptPaths: []string{"/hook"}}}},
		// The zone-wide trigger travels only when set; the hold's default
		// (300, what validation fills in) encodes to nothing.
		{Name: "e.example", Origins: []string{"10.0.0.5:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeAuto,
				ChallengeOptions: config.ZoneChallengeOptions{Auto: config.ZoneAutoChallenge{ZoneRPS: 500, HoldSeconds: 60}}}},
		{Name: "f.example", Origins: []string{"10.0.0.6:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeAuto,
				ChallengeOptions: config.ZoneChallengeOptions{Auto: config.ZoneAutoChallenge{HoldSeconds: 300}}}},
		{Name: "g.example", Origins: []string{"10.0.0.7:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeAuto,
				ChallengeOptions: config.ZoneChallengeOptions{Auto: config.ZoneAutoChallenge{ZoneRPS: 20, HoldSeconds: 300}}}},
	}}
	doc := buildEdgeDoc(z)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if strings.Count(s, `"challenge_options"`) != 4 {
		t.Fatalf("challenge_options present %d times, want 4 (c, d, e, g):\n%s", strings.Count(s, `"challenge_options"`), s)
	}
	if !strings.Contains(s, `"challenge_options":{"dry_run":true,"auto":{"zone_rps":500,"hold_seconds":60}}`) {
		t.Fatalf("zone e auto trigger: %s", s)
	}
	if !strings.Contains(s, `"challenge_options":{"dry_run":true,"auto":{"zone_rps":20}}`) {
		t.Fatalf("zone g (default hold encodes to nothing): %s", s)
	}
	for _, zn := range doc.Zones {
		switch zn.Name {
		case "e.example":
			if zn.Policy.AutoZoneRPS() != 500 || zn.Policy.AutoHold() != time.Minute {
				t.Errorf("e: zone_rps=%d hold=%v", zn.Policy.AutoZoneRPS(), zn.Policy.AutoHold())
			}
		case "f.example":
			if zn.Policy.ChallengeOptions != nil || zn.Policy.AutoZoneRPS() != 0 || zn.Policy.AutoHold() != 5*time.Minute {
				t.Errorf("f: the default hold alone must encode to nothing: %+v", zn.Policy.ChallengeOptions)
			}
		case "g.example":
			if zn.Policy.AutoZoneRPS() != 20 || zn.Policy.AutoHold() != 5*time.Minute {
				t.Errorf("g: zone_rps=%d hold=%v", zn.Policy.AutoZoneRPS(), zn.Policy.AutoHold())
			}
		}
	}
	if !strings.Contains(s, `"name":"c.example"`) || !strings.Contains(s, `"challenge_options":{"dry_run":false,"exempt_paths":["/healthz","/api/"]}`) {
		t.Fatalf("zone c options: %s", s)
	}
	if !strings.Contains(s, `"challenge_options":{"dry_run":true,"exempt_paths":["/hook"]}`) {
		t.Fatalf("zone d options (default dry-run kept explicit once anything is set): %s", s)
	}
	for _, zn := range doc.Zones {
		switch zn.Name {
		case "a.example", "b.example":
			if zn.Policy.ChallengeOptions != nil || !zn.Policy.ChallengeDryRun() {
				t.Errorf("%s: defaults must encode to nothing and read as dry-run: %+v", zn.Name, zn.Policy.ChallengeOptions)
			}
		case "c.example":
			if zn.Policy.ChallengeDryRun() {
				t.Errorf("%s: dry_run false lost", zn.Name)
			}
		}
	}
	// The exempt list is copied, not aliased into the config.
	z.Zones[2].Policy.ChallengeOptions.ExemptPaths[0] = "/changed"
	if doc.Zones[2].Policy.ChallengeOptions.ExemptPaths[0] != "/healthz" {
		t.Error("exempt paths alias the zones file")
	}
}

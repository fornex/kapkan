package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
)

// TestBuildEdgeDocZoneDryRun pins how policy.dry_run travels (E4.7): set, it
// is in the document; unset, the policy encodes as it did before E4.7, so an
// older document's bytes and ETag do not move.
func TestBuildEdgeDocZoneDryRun(t *testing.T) {
	z := &config.Zones{Zones: []config.Zone{
		{Name: "live.example", Origins: []string{"10.0.0.1:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeOff}},
		{Name: "watched.example", Origins: []string{"10.0.0.2:80"}, TLS: config.ZoneTLS{MinVersion: config.ZoneTLS12},
			Policy: config.ZonePolicy{Mode: config.ZonePolicyDecide, FailureMode: config.ZoneFailOpen, Challenge: config.ZoneChallengeOff, DryRun: true}},
	}}
	doc := buildEdgeDoc(z)
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if strings.Count(s, `"dry_run":true`) != 1 {
		t.Fatalf("dry_run present %d times, want once (watched.example):\n%s", strings.Count(s, `"dry_run":true`), s)
	}
	if !strings.Contains(s, `"name":"watched.example"`) {
		t.Fatalf("watched zone missing: %s", s)
	}
	for _, zn := range doc.Zones {
		switch zn.Name {
		case "live.example":
			if zn.Policy.DryRun {
				t.Error("live.example must not be watch-only")
			}
		case "watched.example":
			if !zn.Policy.DryRun || !zn.Policy.ChallengeDryRun() {
				t.Error("watched.example must be watch-only, its rung included")
			}
		}
	}
}

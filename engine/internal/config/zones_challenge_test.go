package config

import (
	"strings"
	"testing"
)

// TestZonesChallengeVocabularyAndDefaults pins the rung's file shape (E4.2):
// off/manual/auto are the words; the options default to watch-only with no
// exemptions, and an explicit dry_run: false is kept; exempt paths are
// bounded.
func TestZonesChallengeVocabularyAndDefaults(t *testing.T) {
	z, err := ParseZones([]byte(`
zones:
  - name: a.example
    origins: ["10.0.0.1:8080"]
  - name: b.example
    origins: ["10.0.0.2:8080"]
    policy: {challenge: manual}
  - name: c.example
    origins: ["10.0.0.3:8080"]
    policy:
      challenge: auto
      challenge_options:
        dry_run: false
        exempt_paths: ["/healthz", "/api/"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := z.Zones[0].Policy.Challenge; got != ZoneChallengeOff {
		t.Fatalf("default challenge = %q", got)
	}
	for i, zn := range z.Zones[:2] {
		if zn.Policy.ChallengeOptions.DryRun == nil || !*zn.Policy.ChallengeOptions.DryRun || len(zn.Policy.ChallengeOptions.ExemptPaths) != 0 {
			t.Fatalf("zone %d: options not defaulted to watch-only: %+v", i, zn.Policy.ChallengeOptions)
		}
	}
	c := z.Zones[2].Policy
	if c.Challenge != ZoneChallengeAuto || c.ChallengeOptions.DryRun == nil || *c.ChallengeOptions.DryRun || len(c.ChallengeOptions.ExemptPaths) != 2 {
		t.Fatalf("zone c: %+v", c)
	}

	many := "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\"]\n    policy:\n      challenge_options:\n        exempt_paths: ["
	for i := 0; i <= maxExemptPaths; i++ {
		many += "\"/p" + strings.Repeat("x", i%7) + "\","
	}
	many = strings.TrimSuffix(many, ",") + "]\n"
	if _, err := ParseZones([]byte(many)); err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("too many exempt paths: %v", err)
	}
	long := "zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\"]\n    policy:\n      challenge_options:\n        exempt_paths: [\"/" + strings.Repeat("l", maxExemptPathLen) + "\"]\n"
	if _, err := ParseZones([]byte(long)); err == nil || !strings.Contains(err.Error(), "at most 256") {
		t.Fatalf("overlong exempt path: %v", err)
	}
}

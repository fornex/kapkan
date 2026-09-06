package edgedoc

import (
	"testing"
	"time"
)

// TestChallengeOverrideLive pins when the brain's lever counts: a manual or
// auto mode whose until is ahead — never a past one, never a mode this build
// does not know (an older node ignores what it cannot apply), never nil.
func TestChallengeOverrideLive(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	future, past := now.Add(time.Minute), now.Add(-time.Second)
	var none *ChallengeOverride
	for _, tc := range []struct {
		o    *ChallengeOverride
		want bool
	}{
		{&ChallengeOverride{Mode: ChallengeManual, Until: future}, true},
		{&ChallengeOverride{Mode: ChallengeAuto, Until: future}, true},
		{&ChallengeOverride{Mode: ChallengeManual, Until: past}, false},
		{&ChallengeOverride{Mode: ChallengeManual, Until: now}, false},
		{&ChallengeOverride{Mode: ChallengeOff, Until: future}, false},
		{&ChallengeOverride{Mode: "puzzle-v9", Until: future}, false},
		{none, false},
	} {
		if got := tc.o.Live(now); got != tc.want {
			t.Errorf("Live(%+v) = %v, want %v", tc.o, got, tc.want)
		}
	}
	z := Zone{Policy: Policy{Challenge: ChallengeOff}, ChallengeOverride: &ChallengeOverride{Mode: ChallengeAuto, Until: future}}
	if z.EffectiveChallenge(now) != ChallengeAuto || z.EffectiveChallenge(future) != ChallengeOff {
		t.Fatalf("EffectiveChallenge: %q then %q", z.EffectiveChallenge(now), z.EffectiveChallenge(future))
	}
}

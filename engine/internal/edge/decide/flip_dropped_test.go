package decide

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// TestSetZonesRetiresAnInertFlipWithItsLine pins that a live zone-wide flip
// dropped by a document whose effective mode is not auto — a manual lever
// arriving mid-incident — ends with the same closing line a lapse writes, so
// the node's log never leaves an "on … until T" open; and that the line says
// the flip did not lapse.
func TestSetZonesRetiresAnInertFlipWithItsLine(t *testing.T) {
	c := newClock()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeAuto, 0)
	s := New(Options{Now: c.now, Logger: log})
	s.SetZones(doc(z))
	if !s.SetZoneChallenge("shop.example", true, c.t.Add(time.Hour), "zone-rps") {
		t.Fatal("flip refused")
	}
	if strings.Count(buf.String(), "zone-wide challenge on") != 1 {
		t.Fatalf("the on line:\n%s", buf.String())
	}
	lever := z
	lever.ChallengeOverride = &edgedoc.ChallengeOverride{Mode: edgedoc.ChallengeManual, Until: c.t.Add(30 * time.Minute), Reason: "incident"}
	s.SetZones(doc(lever))
	if on, _, _ := s.ZoneChallenge("shop.example"); on {
		t.Fatal("the flip survived a manual lever")
	}
	out := buf.String()
	if strings.Count(out, "zone-wide challenge off") != 1 || !strings.Contains(out, "lapsed=false") || !strings.Contains(out, "reason=zone-rps") || !strings.Contains(out, "zone=shop.example") {
		t.Fatalf("the closing line:\n%s", out)
	}
	// The lever's own line follows; nothing is said twice.
	if strings.Count(out, "challenge override in effect") != 1 {
		t.Fatalf("the override line:\n%s", out)
	}
}

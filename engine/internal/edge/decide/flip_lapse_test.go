package decide

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

// TestZoneFlipLapseIsRetiredPerRequestAndLogged pins two things round two
// promised: a lapsed zone-wide flip is retired by the very next decision —
// inside a sweep interval, so not by the sweep — and the lapse is logged at
// Info as "zone-wide challenge off" with lapsed=true, once, after the mutex
// is released.
func TestZoneFlipLapseIsRetiredPerRequestAndLogged(t *testing.T) {
	c := newClock()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	z, _ := challengeZone(t, "shop.example", edgedoc.ChallengeAuto, 0)
	s := New(Options{Now: c.now, Logger: log})
	s.SetZones(doc(z))
	ip := src("198.51.100.90")

	if !s.SetZoneChallenge("shop.example", true, c.t.Add(5*time.Second), "zone-rps") {
		t.Fatal("flip refused")
	}
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); v.Allow || !v.Challenge {
		t.Fatalf("under the flip: %+v", v)
	}
	// Six seconds on: the flip lapsed one second ago, well inside the ten-
	// second sweep interval. The decision itself retires it.
	c.add(6 * time.Second)
	if v := s.DecideRequest(Request{Zone: "shop.example", Src: ip}); !v.Allow || v.Challenge {
		t.Fatalf("after the lapse: %+v", v)
	}
	if on, _, _ := s.ZoneChallenge("shop.example"); on {
		t.Fatal("the lapsed flip is still reported on")
	}
	out := buf.String()
	if strings.Count(out, "zone-wide challenge off") != 1 || !strings.Contains(out, "lapsed=true") || !strings.Contains(out, "zone=shop.example") || !strings.Contains(out, "reason=zone-rps") {
		t.Fatalf("lapse log:\n%s", out)
	}
	// Another decision logs nothing more: the episode was closed once.
	s.DecideRequest(Request{Zone: "shop.example", Src: ip})
	if strings.Count(buf.String(), "zone-wide challenge off") != 1 {
		t.Fatalf("the lapse was logged again:\n%s", buf.String())
	}

	// A node with NO traffic: the periodic Tick retires the lapsed flip —
	// gauge and log line — without a request to do it.
	buf.Reset()
	if !s.SetZoneChallenge("shop.example", true, c.t.Add(5*time.Second), "zone-rps") {
		t.Fatal("re-flip refused")
	}
	c.add(20 * time.Second) // past the flip's hold and past sweepEvery
	s.Tick()
	s.mu.Lock()
	on := s.zones["shop.example"].flipOn
	s.mu.Unlock()
	if on || strings.Count(buf.String(), "zone-wide challenge off") != 1 || !strings.Contains(buf.String(), "lapsed=true") {
		t.Fatalf("Tick did not retire the lapsed flip: on=%v log:\n%s", on, buf.String())
	}
}

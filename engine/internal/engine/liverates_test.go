package engine

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestLiveRates covers the accessor the API uses to replace an attack record's
// detection-time snapshot with a current measurement: one case per scope, plus
// the two "no longer tracked" answers a caller must distinguish from zero.
func TestLiveRates(t *testing.T) {
	t.Run("host reports the current windowed rate", func(t *testing.T) {
		clk := newMockClock()
		e := New(groupsStore(t, onsetYAML), WithClock(clk.Now), WithWindow(5))
		dst := netip.MustParseAddr("203.0.113.45")

		// Two complete seconds of the onset flood: the window holds 2 of its 5
		// seconds, so the live rate is two fifths of the true rate — the same
		// number windowedRates would give, read without a tick.
		for i := 0; i < 2; i++ {
			for j := 0; j < onsetRecordsPerSec; j++ {
				e.Process(nf9Flow(dst.String(), onsetPktsPerRecord, onsetSamplingRate))
			}
			clk.Advance(time.Second)
		}
		got, ok := e.LiveRates(ScopeHost, dst, "", DirIncoming)
		if !ok {
			t.Fatal("ok = false for a tracked host")
		}
		if want := float64(onsetTruePPS) * 2 / 5; got.PPS != want {
			t.Errorf("pps = %v, want %v", got.PPS, want)
		}
		// Nothing was recorded outgoing, so that direction is zero — not the
		// incoming number.
		if out, ok := e.LiveRates(ScopeHost, dst, "", DirOutgoing); !ok || out.PPS != 0 {
			t.Errorf("outgoing = %v (ok %v), want 0", out.PPS, ok)
		}
	})

	t.Run("untracked host reports not-ok so callers keep their snapshot", func(t *testing.T) {
		clk := newMockClock()
		e := New(groupsStore(t, onsetYAML), WithClock(clk.Now), WithWindow(5))
		if _, ok := e.LiveRates(ScopeHost, netip.MustParseAddr("203.0.113.99"), "", DirIncoming); ok {
			t.Error("ok = true for a host the engine never saw")
		}
	})

	t.Run("tracked host with an empty window reports zero, not not-ok", func(t *testing.T) {
		clk := newMockClock()
		e := New(groupsStore(t, onsetYAML), WithClock(clk.Now), WithWindow(5))
		dst := netip.MustParseAddr("203.0.113.45")
		e.Process(nf9Flow(dst.String(), onsetPktsPerRecord, onsetSamplingRate))
		// Walk past the whole window: the host is still tracked, its traffic has
		// aged out. For an attack in its hysteresis tail zero is the truth, and a
		// caller must be able to tell it from "gone".
		clk.Advance(10 * time.Second)
		got, ok := e.LiveRates(ScopeHost, dst, "", DirIncoming)
		if !ok {
			t.Fatal("ok = false for a host that is still tracked")
		}
		if got.PPS != 0 {
			t.Errorf("pps = %v, want 0", got.PPS)
		}
	})

	t.Run("total group reports the tick's summed rate", func(t *testing.T) {
		clk := newMockClock()
		e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(5))
		// "pool" is groupsYAML's calculation:total group. Two of its members
		// carrying 1000 corrected pps each must sum to 2000 for the group, over
		// a window holding 1 of 5 seconds => 400.
		for _, host := range []string{"203.0.113.33", "203.0.113.34"} {
			e.Process(udpFlow(host, 100, 1, 1000))
		}
		clk.Advance(time.Second)
		e.evalTick(clk.Now())

		got, ok := e.LiveRates(ScopeGroup, netip.Addr{}, "pool", DirIncoming)
		if !ok {
			t.Fatal("ok = false for a total group that was evaluated")
		}
		if want := 2 * 1000.0 / 5; got.PPS != want {
			t.Errorf("pps = %v, want %v", got.PPS, want)
		}
		if _, ok := e.LiveRates(ScopeGroup, netip.Addr{}, "web", DirIncoming); ok {
			t.Error("ok = true for a per-host group; only total groups are summed")
		}
	})

	t.Run("carpet prefix reports the tick's aggregate rate", func(t *testing.T) {
		clk := newMockClock()
		e := New(carpetStore(t), WithClock(clk.Now), WithWindow(5))
		// Six hosts in 203.0.113.0/24, each 100 000 corrected pps: over the
		// carpet threshold with enough fan-out once the window fills. Starting at
		// .2 skips baseYAML's whitelisted .1, which never reaches the carpet sum.
		for s := 0; s < 5; s++ {
			for i := 2; i <= 7; i++ {
				e.Process(udpFlow(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}).String(), 64000, 100, 1000))
			}
			clk.Advance(time.Second)
			e.evalTick(clk.Now())
		}
		// LiveRates keys a carpet by the aggregation prefix's network address,
		// which is what the attack record carries as its target.
		got, ok := e.LiveRates(ScopePrefix, netip.MustParseAddr("203.0.113.0"), "", DirIncoming)
		if !ok {
			t.Fatal("ok = false for a prefix in a carpet attack")
		}
		if want := 6 * 100000.0; got.PPS != want {
			t.Errorf("pps = %v, want %v", got.PPS, want)
		}
		if _, ok := e.LiveRates(ScopePrefix, netip.MustParseAddr("198.51.100.0"), "", DirIncoming); ok {
			t.Error("ok = true for a prefix with no carpet attack")
		}
	})

	// The group and carpet measurements are published by evalTick, which owns
	// that state on the Run goroutine; LiveRates is called from request
	// goroutines. Under -race this fails if the publication is not synchronized.
	t.Run("concurrent readers race a running evaluator", func(t *testing.T) {
		clk := newMockClock()
		e := New(groupsStore(t, groupsYAML), WithClock(clk.Now), WithWindow(5))
		dst := netip.MustParseAddr("203.0.113.33")

		var wg sync.WaitGroup
		stop := make(chan struct{})
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						e.LiveRates(ScopeGroup, netip.Addr{}, "pool", DirIncoming)
						e.LiveRates(ScopeHost, dst, "", DirIncoming)
						e.LiveRates(ScopePrefix, dst, "", DirIncoming)
					}
				}
			}()
		}
		for s := 0; s < 50; s++ {
			e.Process(udpFlow(dst.String(), 100, 1, 1000))
			clk.Advance(time.Second)
			e.evalTick(clk.Now())
		}
		close(stop)
		wg.Wait()
	})
}

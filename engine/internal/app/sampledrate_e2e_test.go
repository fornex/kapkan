package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"log/slog"
)

// nf9YAML is a dry-run config listening for NetFlow (v9) with pps far below
// the flood the test injects and the other two thresholds far above it, so pps
// is unambiguously the metric that trips.
//
// sampling.default_rate is 1 on purpose: it is the fallback for an exporter
// that reports no rate, so a broken options-template decode would collapse the
// corrected rate to the raw 520 pps instead of quietly substituting a
// plausible-looking 1000. The test's live-rate assertion therefore also proves
// the rate came off the wire.
func nf9YAML(netflowPort, apiPort int) string {
	return fmt.Sprintf(`dry_run: true
listen:
  netflow: ":%d"
sampling:
  default_rate: 1
networks:
  - "203.0.113.0/24"
thresholds:
  pps: 20000
  mbps: 100000
  flows_per_sec: 10000000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:%d"
`, netflowPort, apiPort)
}

type hostsResp struct {
	Hosts []struct {
		Target string `json:"target"`
		Rates  struct {
			PPS float64 `json:"pps"`
		} `json:"rates"`
	} `json:"hosts"`
}

type ratesAttacksResp struct {
	Active []struct {
		Target string  `json:"target"`
		Metric string  `json:"metric"`
		Rate   float64 `json:"rate"`
		Rates  struct {
			PPS float64 `json:"pps"`
		} `json:"rates"`
	} `json:"active"`
}

// TestEndToEndSampledRateFrozenAtDetection replays NetFlow v9 carrying its
// sampling rate in an options-data record and pins two facts about the numbers
// the daemon then reports for the target.
//
// 1. The sampling correction is right, and it scales with the reported rate:
// the same true 520 000 pps — advertised as 1-in-1000 over 130 records/s, or
// as 1-in-5000 over 26 records/s — reads back as 520 000 pps on
// /api/v1/hosts either way. The v9 options-template decode, the per-exporter
// sampling system and the per-second bucket accumulation are all correct.
//
// 2. /api/v1/attacks agrees with it. The attack record begins as the snapshot
// taken at the detection instant, when the sliding window held a single second
// of a five-second average — a fifth of the true rate, or a tenth when the
// exporter's ticks began mid-second — and handleAttacks replaces that with the
// engine's live measurement, so the two endpoints cannot disagree about the same
// host at the same moment. Before that fix this assertion was the opposite one:
// a fifth or a tenth, frozen for the life of the attack however long the flood
// ran.
func TestEndToEndSampledRateReported(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in -short mode")
	}
	// 520 000 true pps either way: records/s * 4 packets * the reported rate.
	for _, tc := range []struct {
		name         string
		samplingRate uint32
		recsPerTick  int // one tick every 500ms
	}{
		{"1-in-1000 over 130 records per second", 1000, 65},
		{"1-in-5000 over 26 records per second", 5000, 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const truePPS = 520000
			netflowPort := freeUDPPort(t)
			apiPort := freeTCPPort(t)

			cfg, err := config.Parse([]byte(nf9YAML(netflowPort, apiPort)))
			if err != nil {
				t.Fatalf("parse config: %v", err)
			}
			store := config.NewStore("", cfg)
			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			application, err := New(store, log)
			if err != nil {
				t.Fatalf("app.New: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := application.Start(ctx); err != nil {
				t.Fatalf("app.Start: %v", err)
			}
			defer application.Stop()

			// Give the UDP listener and API a moment to bind.
			time.Sleep(500 * time.Millisecond)

			victim := netip.MustParseAddr("203.0.113.45")
			recs := make([]flowgen.Record, tc.recsPerTick)
			for i := range recs {
				recs[i] = flowgen.Record{
					SrcAddr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i%250 + 1)}),
					DstAddr: victim,
					SrcPort: uint16(1024 + i),
					DstPort: 80,
					Proto:   flowgen.ProtoUDP,
					Bytes:   4 * 64, // 64-byte packets: keeps mbps well under its limit
					Packets: 4,
				}
			}

			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", netflowPort))
				if err != nil {
					t.Errorf("dial netflow udp: %v", err)
					return
				}
				defer func() { _ = conn.Close() }()
				start := time.Now()
				var seq uint32
				ticker := time.NewTicker(500 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-stop:
						return
					case now := <-ticker.C:
						_, _ = conn.Write(flowgen.BuildNetFlowV9(recs, flowgen.NetFlowV9Options{
							SourceID:     1,
							Sequence:     seq,
							Uptime:       uint32(now.Sub(start).Milliseconds()),
							UnixSecs:     uint32(now.Unix()),
							SamplingRate: tc.samplingRate,
						}))
						seq += uint32(len(recs))
					}
				}
			}()
			defer func() {
				close(stop)
				<-done
			}()

			hostPPS := func() float64 {
				var h hostsResp
				if !getJSON(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/hosts", apiPort), &h) {
					return -1
				}
				for _, x := range h.Hosts {
					if x.Target == victim.String() {
						return x.Rates.PPS
					}
				}
				return -1
			}
			attackPPS := func() (float64, float64, bool) {
				var a ratesAttacksResp
				if !getJSON(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/attacks", apiPort), &a) {
					return 0, 0, false
				}
				for _, x := range a.Active {
					if x.Target == victim.String() {
						return x.Rates.PPS, x.Rate, true
					}
				}
				return 0, 0, false
			}

			// The engine's live windowed rate is the sampling-corrected truth
			// once the five-second window has filled, whichever rate the
			// exporter advertised.
			if !waitFor(t, 25*time.Second, func() bool { return hostPPS() == truePPS }) {
				t.Fatalf("live /api/v1/hosts pps never reached %d (last %v)", truePPS, hostPPS())
			}

			// And the attack record reports the same number, not the fifth or
			// tenth it was stamped with at detection.
			ratesPPS, rate, ok := attackPPS()
			if !ok {
				t.Fatal("victim not in /api/v1/attacks while its live rate is at the flood level")
			}
			if ratesPPS != truePPS {
				t.Errorf("/api/v1/attacks pps = %v, want %d (the live rate /api/v1/hosts reports)",
					ratesPPS, truePPS)
			}
			// pps is the metric that tripped, so the headline rate must have been
			// re-derived from the same fresh measurement.
			if rate != ratesPPS {
				t.Errorf("/api/v1/attacks rate = %v, rates.pps = %v; want the same number", rate, ratesPPS)
			}

			// Three more seconds of the same flood keep both endpoints there —
			// the refresh tracks the attack rather than latching a new value.
			time.Sleep(3 * time.Second)
			if live := hostPPS(); live != truePPS {
				t.Fatalf("live pps drifted to %v; the flood stopped and the comparison is void", live)
			}
			after, _, ok := attackPPS()
			if !ok {
				t.Fatal("attack disappeared mid-flood")
			}
			if after != truePPS {
				t.Errorf("/api/v1/attacks pps = %v three seconds later, want %d", after, truePPS)
			}
		})
	}
}

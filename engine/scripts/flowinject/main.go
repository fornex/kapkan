// Command flowinject fabricates the traffic scene the operator-console
// screenshots are taken against, and nothing else. It is a development tool: it
// speaks the same NetFlow v9 wire format a router speaks, at kapkan's ordinary
// listener, so the engine has no idea it is being posed for a photograph.
//
// The scene is three hosts under attack on three different policy paths (a
// tight hostgroup, the same hostgroup on a different protocol, and the default
// /24 policy) plus a few quiet neighbours, so the Hosts view shows green rows
// next to the red ones instead of reading as a wall of fire.
//
// Sampling is what makes this cheap. Every packet reports a sampling rate in a
// NetFlow v9 options template, and kapkan multiplies the records it receives by
// that rate — so a few hundred fabricated records stand in for a multi-hundred-
// thousand-pps flood, and the numbers on screen are the numbers a real attack
// of that size would produce.
//
// Usage:
//
//	go run ./scripts/flowinject -target 127.0.0.1:2055
//	go run ./scripts/flowinject -target 127.0.0.1:2055 -duration 30s -v
//
// It runs until interrupted, because the console must keep seeing fresh flows
// or the attacks it is displaying stop being ongoing.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"
	"os/signal"
	"syscall"
	"time"

	"github.com/kapkan-io/kapkan/pkg/flowgen"
)

// maxRecordsPerDatagram keeps each datagram to roughly what a real exporter
// emits (~1.4 kB). Volume comes from sending more datagrams, which is also how
// a router behaves under load — not from one implausibly large packet.
const maxRecordsPerDatagram = 30

// actor is one host in the scene.
//
// Sizing is given as records per tick, and the obvious formula does predict it:
// effective pps = records × packets × samplingRate / interval, which is what
// /api/v1/hosts and /api/v1/attacks now report for every actor below.
//
// An earlier version of this comment recorded the formula as unreliable — the
// reported rate came out about 5× below it, and raising the reported sampling
// rate fivefold appeared to halve the reported pps. Neither was a sampling
// problem. /api/v1/attacks used to serve the measurement frozen at the instant
// of detection, which is the first sliding window to cross a threshold and so
// the one holding a single second of a five-second average: a fifth of the truth
// for the whole life of an attack, or a tenth when the first datagram landed
// mid-second, which is the apparent halving. It now serves the engine's live
// measurement, and the formula, /api/v1/hosts and the console all agree.
type actor struct {
	victim  string
	pattern flowgen.AttackPattern
	// recordsPerTick sets this actor's offered rate through the formula above.
	// The scene comment records what each one produces.
	recordsPerTick int
	// packetsPerRecord and bytesPerPacket separate a bandwidth attack from a
	// packet-rate one: an amplification vector is large packets, a SYN flood is
	// minimal ones.
	packetsPerRecord uint32
	bytesPerPacket   uint32
	// srcBase is where this actor's source addresses start. Distinct bases keep
	// the attackers of one victim from being mistaken for the attackers of
	// another in the per-attack source breakdown.
	srcBase string
	// everyNthTick throttles an actor without shrinking its records below one
	// per datagram. 1 (or 0) is every tick.
	everyNthTick int
}

// records builds one tick's worth for this actor. scale compensates for ticks
// the runtime dropped, so the offered rate is what was asked for even when the
// machine is busy.
func (a actor) records(scale float64) []flowgen.Record {
	n := int(float64(a.recordsPerTick) * scale)
	if n < 1 {
		n = 1
	}
	return flowgen.PatternParams{
		Pattern:          a.pattern,
		Victim:           netip.MustParseAddr(a.victim),
		Records:          n,
		PacketsPerRecord: a.packetsPerRecord,
		BytesPerRecord:   a.bytesPerPacket * a.packetsPerRecord,
		SrcBase:          netip.MustParseAddr(a.srcBase),
	}.Build()
}

// due reports whether this actor sends on the given tick.
func (a actor) due(tick uint64) bool {
	if a.everyNthTick <= 1 {
		return true
	}
	return tick%uint64(a.everyNthTick) == 0
}

// scene is deliberately hard-coded: it is matched to configs/dev.yaml, whose
// protected network is 203.0.113.0/24 with a tight `web` hostgroup on
// 203.0.113.0/26 (pps 20000, mbps 500, flows_per_sec 10000) and global
// thresholds at pps 80000 / udp_pps 60000. Change one and you must change the
// other.
//
// Measured at -sampling-rate 1000 -interval 500ms, ~20s in:
//
//	203.0.113.45  pps 2.6M vs 20k = 130×  (UDP flood, 29 Gbps)
//	203.0.113.10  pps 1.2M vs 20k =  60×  (SYN flood, 576 Mbps — packets, not bits)
//	203.0.113.77  pps 1.6M vs 80k =  20×  (DNS reflection, 19 Gbps)
//
// and exactly three active attacks: the quiet hosts stay under every threshold.
//
// These are five times the figures this comment carried when the scene was first
// calibrated, and the scene itself did not change: the old ones were read off the
// frozen /api/v1/attacks. Two consequences, neither of them a code change. The
// console screenshots were taken against the old figures
// and now understate what the console shows, so they want a recapture.
// And whether a 29 Gbps single-host flood is the scene the
// screenshots should show is now a calibration question worth asking, since the
// answer was previously hidden behind a fifth.
var scene = []actor{
	// A bandwidth-heavy UDP flood inside the tight hostgroup: the loudest row.
	{victim: "203.0.113.45", pattern: flowgen.UDPFlood, recordsPerTick: 325, packetsPerRecord: 4, bytesPerPacket: 1400, srcBase: "198.51.100.0"},
	// A SYN flood on the same hostgroup: high pps, negligible bandwidth, and a
	// different classification, so the Attacks view is not three of a kind.
	{victim: "203.0.113.10", pattern: flowgen.SYNFlood, recordsPerTick: 150, packetsPerRecord: 4, bytesPerPacket: 60, srcBase: "203.0.200.0"},
	// A DNS reflection against a host on the default /24 policy.
	{victim: "203.0.113.77", pattern: flowgen.DNSAmplification, recordsPerTick: 200, packetsPerRecord: 4, bytesPerPacket: 1500, srcBase: "192.0.2.0"},

	// Quiet neighbours, so the Hosts view has healthy rows to contrast against
	// instead of reading as a wall of fire. One record every eighth tick puts
	// them one to two orders of magnitude under every threshold that binds —
	// at two records per tick they intermittently tripped flows_per_sec and
	// showed up as attacks, which would have made the screenshot claim six
	// attacks where three were ordinary traffic.
	//
	// 203.0.113.1 is deliberately absent: it is the protected_whitelist entry,
	// and a whitelisted host appearing in a screenshot beside a ban invites
	// exactly the wrong conclusion.
	{victim: "203.0.113.20", pattern: flowgen.UDPFlood, recordsPerTick: 1, packetsPerRecord: 1, bytesPerPacket: 800, srcBase: "100.64.0.0", everyNthTick: 8},
	{victim: "203.0.113.30", pattern: flowgen.UDPFlood, recordsPerTick: 1, packetsPerRecord: 1, bytesPerPacket: 800, srcBase: "100.64.1.0", everyNthTick: 8},
	{victim: "203.0.113.40", pattern: flowgen.UDPFlood, recordsPerTick: 1, packetsPerRecord: 1, bytesPerPacket: 900, srcBase: "100.64.2.0", everyNthTick: 8},
}

func main() {
	target := flag.String("target", "127.0.0.1:2055", "host:port of kapkan's NetFlow listener")
	interval := flag.Duration("interval", 500*time.Millisecond, "how often to send one batch")
	samplingRate := flag.Uint("sampling-rate", 1000, "sampling rate to report in the options template")
	duration := flag.Duration("duration", 0, "stop after this long (0 = run until interrupted)")
	verbose := flag.Bool("v", false, "log every batch")
	flag.Parse()

	conn, err := net.Dial("udp", *target)
	if err != nil {
		log.Fatalf("dial %s: %v", *target, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	log.Printf("injecting into %s every %s, sampling rate %d, %d actors",
		*target, *interval, *samplingRate, len(scene))

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	start := time.Now()
	var seq uint32
	var n uint64
	last := start

	for {
		select {
		case <-ctx.Done():
			log.Printf("stopped after %s, %d datagrams", time.Since(start).Round(time.Second), seq)
			return
		case now := <-tick.C:
			n++
			// Scale by the time actually elapsed, not by the nominal interval.
			// time.Ticker DROPS ticks when the receiver is slow, so a busy
			// machine silently halves the offered rate — which showed up as a
			// scene measuring 13× threshold on one run and 26× on the next, from
			// identical inputs. Catching up on elapsed time makes the scene
			// reproducible regardless of scheduling.
			dt := now.Sub(last)
			last = now
			scale := dt.Seconds() / interval.Seconds()
			if scale < 1 {
				scale = 1
			} else if scale > 8 {
				scale = 8 // a suspended laptop should not emit one enormous burst
			}
			var sent int
			for _, a := range scene {
				if !a.due(n) {
					continue
				}
				// Never merge actors into one datagram: BuildNetFlowV9 picks its
				// template from the FIRST record, so a packet mixing IPv4 and
				// IPv6 records would encode the rest under the wrong template.
				sent += send(conn, a.records(scale), &seq, start, uint32(*samplingRate))
			}
			if *verbose {
				log.Printf("tick %d: %d datagrams, scale %.2f (seq now %d)", n, sent, scale, seq)
			}
		}
	}
}

// send chunks one actor's records into exporter-sized datagrams and writes them,
// returning how many went out.
func send(conn net.Conn, recs []flowgen.Record, seq *uint32, start time.Time, rate uint32) int {
	var sent int
	for i := 0; i < len(recs); i += maxRecordsPerDatagram {
		end := min(i+maxRecordsPerDatagram, len(recs))
		if sendOne(conn, recs[i:end], seq, start, rate) {
			sent++
		}
	}
	return sent
}

// sendOne encodes and sends a single NetFlow v9 datagram, advancing the
// sequence number. A write error is logged and skipped rather than fatal: the
// engine restarting underneath a long capture run should not kill the injector.
func sendOne(conn net.Conn, recs []flowgen.Record, seq *uint32, start time.Time, rate uint32) bool {
	if len(recs) == 0 {
		return false
	}
	pkt := flowgen.BuildNetFlowV9(recs, flowgen.NetFlowV9Options{
		SourceID:     256,
		Sequence:     *seq,
		Uptime:       uint32(time.Since(start).Milliseconds()),
		UnixSecs:     uint32(time.Now().Unix()),
		SamplingRate: rate,
	})
	if pkt == nil {
		return false
	}
	*seq++
	if _, err := conn.Write(pkt); err != nil {
		log.Printf("write: %v", err)
		return false
	}
	return true
}

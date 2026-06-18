package engine

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
)

// benchFlows pre-builds a pool of flows hitting distinct destinations in
// 203.0.113.0/24 with varied attributes (protocol, flags, fragments), so the
// hot path exercises real map lookups across shards and every counter class
// rather than one cached host.
func benchFlows(srcInside bool) []flow.Flow {
	const pool = 8192
	flows := make([]flow.Flow, pool)
	rng := rand.New(rand.NewSource(1))
	for i := range flows {
		dst := netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(254) + 1)})
		src := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		if srcInside {
			// Source inside the monitored prefix: with outgoing detection on
			// this makes every flow take both the dst and the src path.
			src = netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(254) + 1)})
		}
		f := flow.Flow{
			SrcAddr:      src,
			DstAddr:      dst,
			SrcPort:      uint16(1024 + i%4000),
			DstPort:      uint16(i % 65535),
			Bytes:        uint64(64 + i%1400),
			Packets:      1,
			SamplingRate: 1000,
			Wire:         flow.ProtoSFlow5,
		}
		switch i % 4 {
		case 0:
			f.IPProto = 17 // UDP
		case 1:
			f.IPProto = 6 // TCP
			f.TCPFlags = 0x18
		case 2:
			f.IPProto = 6 // TCP SYN
			f.TCPFlags = 0x02
		case 3:
			f.IPProto = 1 // ICMP
			f.Fragment = i%8 == 3
		}
		flows[i] = f
	}
	return flows
}

func runProcessBench(b *testing.B, yaml string, srcInside bool) {
	b.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		b.Fatal(err)
	}
	e := New(config.NewStore("", cfg), WithWindow(5))
	flows := benchFlows(srcInside)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			e.Process(flows[i&(len(flows)-1)])
			i++
		}
	})
	b.StopTimer()

	flowsPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(flowsPerSec, "flows/sec")
}

// BenchmarkProcess measures the hot-path per-flow cost with incoming-only
// detection and the default-enabled sample buffer. The target is >= 200k
// flows/sec on 8 cores; ns/op here translates directly (e.g. 100 ns/op
// single-thread => 10M flows/sec single-thread).
func BenchmarkProcess(b *testing.B) {
	runProcessBench(b, baseYAML, false)
}

// BenchmarkProcessNoSamples isolates the sample buffer's hot-path cost.
func BenchmarkProcessNoSamples(b *testing.B) {
	runProcessBench(b, baseYAML+"\nsamples:\n  enabled: false\n", false)
}

// BenchmarkProcessOutgoing measures the worst case for direction split:
// outgoing detection enabled and every flow's source also inside the
// monitored networks, so each flow is recorded twice.
func BenchmarkProcessOutgoing(b *testing.B) {
	yaml := baseYAML + "\nthresholds_outgoing:\n  pps: 50000\n"
	runProcessBench(b, yaml, true)
}

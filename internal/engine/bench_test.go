package engine

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
)

// BenchmarkProcess measures the hot-path per-flow cost across a realistic
// spread of destination hosts inside the monitored prefix. The target is
// >= 200k flows/sec on 8 cores; ns/op here translates directly (e.g.
// 100 ns/op single-thread => 10M flows/sec single-thread).
func BenchmarkProcess(b *testing.B) {
	cfg, err := config.Parse([]byte(baseYAML))
	if err != nil {
		b.Fatal(err)
	}
	e := New(config.NewStore("", cfg), WithWindow(5))

	// Pre-build a pool of flows hitting distinct destinations in
	// 203.0.113.0/24 plus varied attributes, so the hot path exercises
	// real map lookups across shards rather than one cached host.
	const pool = 8192
	flows := make([]flow.Flow, pool)
	rng := rand.New(rand.NewSource(1))
	for i := range flows {
		dst := netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(254) + 1)})
		flows[i] = flow.Flow{
			SrcAddr:      netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}),
			DstAddr:      dst,
			IPProto:      17,
			SrcPort:      uint16(1024 + i%4000),
			DstPort:      uint16(i % 65535),
			Bytes:        uint64(64 + i%1400),
			Packets:      1,
			SamplingRate: 1000,
			Wire:         flow.ProtoSFlow5,
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			e.Process(flows[i&(pool-1)])
			i++
		}
	})
	b.StopTimer()

	flowsPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(flowsPerSec, "flows/sec")
}

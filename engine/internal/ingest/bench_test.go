package ingest

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The ingest benchmarks time a listener's decode path end to end, short of
// the socket: goflow2's pipe decodes a datagram, the conversion producer
// (newDecodeProducer: goflow2's proto producer, convert and the two per-flow
// counters) turns each record into a flow.Flow, and Engine.Process folds it —
// the path internal/app wires, run inline in each decode worker. Left out are
// the socket reads that fill the listener's queue.
//
// Each runs twice: workers=1 is one decode worker, and workers=4 is a
// listener's decodeWorkers taking datagrams off the queue in turn. GOMAXPROCS
// (-cpu) is the cores they share with the garbage collector; -cpu 1 with one
// worker is the cost of a flow on one core, collection included.

const (
	// benchSamples is the flow samples per sFlow datagram. A switch fills its
	// default 1400-byte datagram with 6 to 9, depending on how much of each
	// packet it captures.
	benchSamples = 8
	// benchRecords is the records per NetFlow v9 datagram: thirty of the
	// router template make a 1436-byte datagram, which fills a 1500-byte MTU
	// as a router does.
	benchRecords = 30
	// benchPool is how many distinct datagrams the workers cycle through.
	benchPool = 256
)

var (
	benchExporter  = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), 5000)
	benchCollector = netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 2055)
)

// benchFlowRecords builds n records, numbered from first, with the attribute
// mix of the engine's BenchmarkProcess — UDP, TCP, TCP SYN and ICMP (every
// other one a fragment) to random hosts of the monitored 203.0.113.0/24 — so
// the fold does the same work in both and the two figures compare.
func benchFlowRecords(rng *rand.Rand, first, n int) []flowgen.Record {
	recs := make([]flowgen.Record, n)
	for j := range recs {
		i := first + j
		r := flowgen.Record{
			SrcAddr: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}),
			DstAddr: netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(254) + 1)}),
			SrcPort: uint16(1024 + i%4000),
			DstPort: uint16(i % 65535),
			Bytes:   uint32(64 + i%1400),
			Packets: 1,
		}
		switch i % 4 {
		case 0:
			r.Proto = flowgen.ProtoUDP
		case 1:
			r.Proto, r.TCPFlags = flowgen.ProtoTCP, flowgen.TCPPsh|flowgen.TCPAck
		case 2:
			r.Proto, r.TCPFlags = flowgen.ProtoTCP, flowgen.TCPSyn
		case 3:
			r.Proto = flowgen.ProtoICMP
			r.Fragment = i%8 == 3
		}
		recs[j] = r
	}
	return recs
}

// BenchmarkIngestSFlow is a switch's sFlow v5: 8 flow samples per datagram,
// each a raw packet header and an extended switch record, sampled 1 in 1000.
func BenchmarkIngestSFlow(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	pool := make([][]byte, benchPool)
	for d := range pool {
		pool[d] = flowgen.BuildSFlowV5(benchFlowRecords(rng, d*benchSamples, benchSamples), flowgen.SFlowOptions{
			AgentIP: benchExporter.Addr(), Sequence: uint32(d), SamplingRate: 1000, ExtendedSwitch: true,
		})
	}
	runIngestBench(b, true, nil, pool, benchSamples, flow.ProtoSFlow5)
}

// BenchmarkIngestNetFlowV9 is a router's NetFlow v9: 30 records per datagram
// in the classic eighteen-element template, plus the fragment offset the
// fragment records need, data only — the template and the 1-in-1000 sampling
// rate came in an earlier datagram, as they do between a router's template
// refreshes.
func BenchmarkIngestNetFlowV9(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	opts := flowgen.NetFlowV9Options{SourceID: 256, SamplingRate: 1000, RouterTemplate: true}
	template := flowgen.BuildNetFlowV9(benchFlowRecords(rng, 0, benchRecords), opts)
	opts.DataOnly = true
	pool := make([][]byte, benchPool)
	for d := range pool {
		opts.Sequence = uint32(d)
		pool[d] = flowgen.BuildNetFlowV9(benchFlowRecords(rng, d*benchRecords, benchRecords), opts)
	}
	runIngestBench(b, false, template, pool, benchRecords, flow.ProtoNetFlow9)
}

// runIngestBench decodes setup (when there is one) untimed, then times the
// workers taking pool's datagrams in turn, and fails unless every record of
// every timed datagram reached the engine.
func runIngestBench(b *testing.B, sflow bool, setup []byte, pool [][]byte, perDatagram int, wire flow.Proto) {
	for _, workers := range []int{1, decodeWorkers} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			store := testStore(b)
			e := engine.New(store, engine.WithWindow(5))
			prod := newDecodeProducer(store, e.Process)
			defer prod.Close()
			var pipe utils.FlowPipe
			if sflow {
				pipe = utils.NewSFlowPipe(&utils.PipeConfig{Producer: prod})
			} else {
				pipe = utils.NewNetFlowPipe(&utils.PipeConfig{Producer: prod})
			}
			defer pipe.Close()
			decode := debug.PanicDecoderWrapper(pipe.DecodeFlow) // as startReceiver wraps it
			if setup != nil {
				if err := decode(&utils.Message{Src: benchExporter, Dst: benchCollector, Payload: setup, Received: time.Now()}); err != nil {
					b.Fatalf("setup datagram: %v", err)
				}
			}

			// flows_total counts each flow as the producer hands it to the engine.
			flows := metrics.FlowsTotal.WithLabelValues(wire.String())
			before := testutil.ToFloat64(flows)
			var next atomic.Int64
			var wg sync.WaitGroup

			b.ReportAllocs()
			b.ResetTimer()
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					msg := &utils.Message{Src: benchExporter, Dst: benchCollector, Received: time.Now()}
					for {
						n := int(next.Add(1)) - 1
						if n >= b.N {
							return
						}
						msg.Payload = pool[n%len(pool)]
						if err := decode(msg); err != nil {
							b.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
			b.StopTimer()

			if got, want := testutil.ToFloat64(flows)-before, float64(b.N*perDatagram); got != want {
				b.Fatalf("kapkan_ingest_flows_total{proto=%q} rose by %v over %d datagrams, want %v", wire, got, b.N, want)
			}
			b.ReportMetric(float64(b.N*perDatagram)/b.Elapsed().Seconds(), "flows/sec")
		})
	}
}

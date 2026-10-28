package ingest

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestListenQueueBoundsTheReceiver pins listen.queue to the receiver it sizes.
// With every decode worker stuck in a blocked sink, a listener must hold
// exactly listen.queue datagrams and count each further one as dropped. The
// bound is what keeps a stalled listener's memory finite: goflow2 pins a
// 9000-byte buffer to every queued datagram, and the old fixed queue of a
// million let one listener grow to ~10 GB before the first drop was counted.
func TestListenQueueBoundsTheReceiver(t *testing.T) {
	const (
		queue   = 8
		workers = 4 // startReceiver's decode workers
		extra   = 5
	)
	port := freeUDPPort(t)
	yaml := strings.Replace(ingestYAML, "  sflow: \":6343\"\n  netflow: \":2055\"\n",
		fmt.Sprintf("  sflow: \"127.0.0.1:%d\"\n  queue: %d\n", port, queue), 1)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	release := make(chan struct{})
	var inSink atomic.Int64
	ing, err := New(config.NewStore("", cfg), func(flow.Flow) {
		inSink.Add(1)
		<-release
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("ingest.New: %v", err)
	}
	if err := ing.Start(); err != nil {
		t.Fatalf("ingest.Start: %v", err)
	}
	t.Cleanup(func() {
		// Release the workers first: Stop queues one sentinel per worker
		// and would block on a full queue. The pause sidesteps goflow2's
		// start->stop race; see startNetFlowIngester.
		close(release)
		time.Sleep(200 * time.Millisecond)
		ing.Stop()
	})

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// One flow per datagram, so a worker enters the sink once per datagram.
	datagram := flowgen.BuildSFlowV5([]flowgen.Record{{
		SrcAddr: netip.MustParseAddr("198.51.100.7"),
		DstAddr: netip.MustParseAddr("203.0.113.10"),
		SrcPort: 40000, DstPort: 53, Proto: flowgen.ProtoUDP,
		Bytes: 512, Packets: 1,
	}}, flowgen.SFlowOptions{AgentIP: netip.MustParseAddr("192.0.2.10"), SamplingRate: 1000})
	send := func(n int) {
		t.Helper()
		for range n {
			if _, err := conn.Write(datagram); err != nil {
				t.Fatalf("write udp: %v", err)
			}
		}
	}
	waitFor := func(cond func() bool) bool {
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if cond() {
				return true
			}
		}
		return cond()
	}

	// A datagram per worker, then wait until each is stuck in the sink: from
	// here on nothing leaves the queue.
	send(workers)
	if !waitFor(func() bool { return inSink.Load() == workers }) {
		t.Fatalf("%d of %d decode workers reached the sink", inSink.Load(), workers)
	}

	dropped := func() float64 { return testutil.ToFloat64(metrics.DroppedFlowsTotal) }
	before := dropped()
	send(queue + extra)
	waitFor(func() bool { return dropped()-before >= extra })
	time.Sleep(100 * time.Millisecond) // room for a wrongly sized queue to show
	if got := dropped() - before; got != extra {
		t.Fatalf("kapkan_ingest_dropped_flows_total rose by %v for %d datagrams behind %d blocked workers, want %d: the queue held %v, not listen.queue = %d",
			got, queue+extra, workers, extra, float64(queue+extra)-got, queue)
	}
}

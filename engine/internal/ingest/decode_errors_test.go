package ingest

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// freeUDPPort returns an available UDP port on the loopback interface so each
// test binds its own listener and never collides with the package's other
// tests (which use fixed ports) or with a parallel e2e run.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// errYAML builds a minimal config that listens for NetFlow on the given
// loopback port only. It mirrors ingestYAML but drops the sFlow listener and
// pins the NetFlow port so the test can target it.
func errYAML(netflowPort int) string {
	return fmt.Sprintf(`
listen:
  netflow: "127.0.0.1:%d"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
protected_whitelist: []
thresholds:
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
notify: {}
api:
  listen: "127.0.0.1:8080"
`, netflowPort)
}

// startNetFlowIngester builds and starts an Ingester listening for NetFlow on
// the given loopback port, with a discard logger and a no-op sink. It returns
// the running Ingester and registers cleanup that stops it.
func startNetFlowIngester(t *testing.T, port int) *Ingester {
	t.Helper()
	cfg, err := config.Parse([]byte(errYAML(port)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ing, err := New(store, func(flow.Flow) {}, log)
	if err != nil {
		t.Fatalf("ingest.New: %v", err)
	}
	if err := ing.Start(); err != nil {
		t.Fatalf("ingest.Start: %v", err)
	}
	// goflow2 v2.2.6 has a shutdown data race: UDPReceiver.Stop -> init()
	// reassigns the r.q quit channel while the per-socket "watcher" goroutine
	// (utils/udp.go:154, untracked by the receiver's WaitGroup) may still be
	// reading it. The window is only open until that watcher reaches its
	// blocked select, which it does microseconds after Start. The daemon runs
	// its receiver for its whole lifetime before Stop (the app e2e tests
	// exercise that path race-clean), so production never hits this; only a
	// near-instant start->stop does. Let the receiver settle before Stop so
	// this test does not trip the dependency's race. See found_real_bug.
	t.Cleanup(func() {
		time.Sleep(200 * time.Millisecond)
		ing.Stop()
	})
	return ing
}

// buildNetFlowV9OrphanData crafts a NetFlow v9 datagram whose only flowset is
// a DATA flowset referencing a template id the exporter never defined. goflow2
// has no template for that id, so it surfaces netflow.ErrorTemplateNotFound —
// exactly the "flow data before template (exporter warm-up)" branch in
// drainErrors. flowgen.BuildNetFlowV9 always prepends the matching template,
// so this orphan frame is hand-crafted on the wire.
func buildNetFlowV9OrphanData() []byte {
	const orphanTemplateID = 256 // never defined in this datagram

	// Data flowset: header (Id=templateID, Length) + an opaque record body.
	// The body just needs to be non-empty; the decoder fails at template
	// lookup before interpreting any field bytes.
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], 0xdead) // arbitrary record payload
	binary.BigEndian.PutUint16(data[2:4], 0xbeef)

	flowset := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(flowset[0:2], orphanTemplateID) // FlowSet Id = template id (>= 256)
	binary.BigEndian.PutUint16(flowset[2:4], uint16(len(flowset)))
	copy(flowset[4:], data)

	// NetFlow v9 packet header (20 bytes) + the one flowset.
	pkt := make([]byte, 20+len(flowset))
	binary.BigEndian.PutUint16(pkt[0:2], 9)   // Version
	binary.BigEndian.PutUint16(pkt[2:4], 1)   // Count = number of flowsets
	binary.BigEndian.PutUint32(pkt[4:8], 0)   // SystemUptime
	binary.BigEndian.PutUint32(pkt[8:12], 0)  // UnixSeconds
	binary.BigEndian.PutUint32(pkt[12:16], 0) // SequenceNumber
	binary.BigEndian.PutUint32(pkt[16:20], 0) // SourceId (observation domain)
	copy(pkt[20:], flowset)
	return pkt
}

// pumpUntil dials the loopback NetFlow port and writes payload on a tight
// ticker until cond() is true or the deadline passes. drainErrors records
// metrics on a separate goroutine and the receiver's error channel is
// unbuffered with a non-blocking send, so a single datagram can be missed if
// the drain goroutine is momentarily busy; repeatedly resending makes the
// positive-delta assertion deterministic without any fixed sleep.
func pumpUntil(t *testing.T, port int, payload []byte, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write udp: %v", err)
		}
		if cond() {
			return true
		}
		<-ticker.C
	}
	// One last check after the final write.
	return cond()
}

// TestDrainErrorsTemplateNotFound drives a real NetFlow v9 data flowset that
// references an undefined template through a started Ingester over UDP and
// asserts metrics.DecodeErrorsTotal{proto=netflow} increments — covering the
// netflow.ErrorTemplateNotFound branch of drainErrors.
func TestDrainErrorsTemplateNotFound(t *testing.T) {
	port := freeUDPPort(t)
	startNetFlowIngester(t, port)

	before := testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues("netflow"))
	payload := buildNetFlowV9OrphanData()

	ok := pumpUntil(t, port, payload, 10*time.Second, func() bool {
		return testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues("netflow")) > before
	})
	if !ok {
		after := testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues("netflow"))
		t.Fatalf("decode_errors_total{proto=netflow} did not increase (before=%v after=%v)", before, after)
	}
}

// TestDrainErrorsGarbage drives random non-NetFlow bytes through a started
// Ingester over UDP and asserts metrics.DecodeErrorsTotal{proto=netflow}
// increments — covering the default (generic decode error) branch of
// drainErrors.
func TestDrainErrorsGarbage(t *testing.T) {
	port := freeUDPPort(t)
	startNetFlowIngester(t, port)

	before := testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues("netflow"))
	// Not a valid NetFlow/IPFIX version, so the pipe rejects it outright.
	garbage := []byte{0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

	ok := pumpUntil(t, port, garbage, 10*time.Second, func() bool {
		return testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues("netflow")) > before
	})
	if !ok {
		after := testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues("netflow"))
		t.Fatalf("decode_errors_total{proto=netflow} did not increase (before=%v after=%v)", before, after)
	}
}

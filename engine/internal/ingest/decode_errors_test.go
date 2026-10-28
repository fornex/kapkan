package ingest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"
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
// the given loopback port, logging to log, with a no-op sink. It returns the
// running Ingester and registers cleanup that stops it.
func startNetFlowIngester(t *testing.T, port int, log *slog.Logger) *Ingester {
	t.Helper()
	cfg, err := config.Parse([]byte(errYAML(port)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	store := config.NewStore("", cfg)
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
// has no template for that id, so the decode fails with
// netflow.ErrorTemplateNotFound — what drainErrors logs as "flow data before
// template (exporter warm-up)". flowgen.BuildNetFlowV9 always prepends the
// matching template, so this orphan frame is hand-crafted on the wire.
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

// buildNetFlowV9Unconvertible crafts a NetFlow v9 datagram that decodes on the
// wire but whose one record the producer cannot convert: its template declares
// IN_BYTES nine bytes wide, and goflow2 converts no number wider than eight.
// The datagram reaches conversion, so it is the case DecodeErrorsTotal shares
// with PacketsTotal.
func buildNetFlowV9Unconvertible() []byte {
	const templateID, inBytes, width = 256, 1, 9

	// Template flowset (Id 0): one template with one field, IN_BYTES.
	tmpl := make([]byte, 12)
	binary.BigEndian.PutUint16(tmpl[0:2], 0) // FlowSet Id = template flowset
	binary.BigEndian.PutUint16(tmpl[2:4], uint16(len(tmpl)))
	binary.BigEndian.PutUint16(tmpl[4:6], templateID)
	binary.BigEndian.PutUint16(tmpl[6:8], 1) // Field Count
	binary.BigEndian.PutUint16(tmpl[8:10], inBytes)
	binary.BigEndian.PutUint16(tmpl[10:12], width)

	// Data flowset: one nine-byte record, padded to a 32-bit boundary.
	data := make([]byte, 4+width+3)
	binary.BigEndian.PutUint16(data[0:2], templateID)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	data[4+width-1] = 1 // the record's IN_BYTES: 1, in nine bytes

	// NetFlow v9 packet header (20 bytes) + the two flowsets.
	pkt := make([]byte, 20, 20+len(tmpl)+len(data))
	binary.BigEndian.PutUint16(pkt[0:2], 9) // Version
	binary.BigEndian.PutUint16(pkt[2:4], 2) // Count = one template + one data record
	return append(append(pkt, tmpl...), data...)
}

// garbage is neither sFlow nor NetFlow: an sFlow listener reads version
// 0xffff0001 and a NetFlow one 0xffff, and both refuse it outright.
var garbage = []byte{0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

// decodeErrorCount reads kapkan_ingest_decode_errors_total for a listener.
func decodeErrorCount(family string) float64 {
	return testutil.ToFloat64(metrics.DecodeErrorsTotal.WithLabelValues(family))
}

// sendUDP writes payload to the loopback port n times, one datagram each.
func sendUDP(t *testing.T, port int, payload []byte, n int) {
	t.Helper()
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer func() { _ = conn.Close() }()
	for range n {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write udp: %v", err)
		}
	}
}

// panicPipe is a FlowPipe whose decode panics, as a parser bug that a crafted
// datagram trips would.
type panicPipe struct{}

func (panicPipe) DecodeFlow(interface{}) error { panic("parser bug") }
func (panicPipe) Close()                       {}

// TestDecoderCountsEveryError pushes n datagrams of each kind through the
// decoder a listener's workers run, from as many goroutines as a receiver has
// workers, and asserts kapkan_ingest_decode_errors_total moved by exactly n
// for each malformed kind (one that decodes but whose record cannot be
// converted among them) and not at all for well-formed telemetry. The worker
// counts the failure itself, so nothing between the two can drop one, however
// fast the junk comes.
func TestDecoderCountsEveryError(t *testing.T) {
	const workers, n = 4, 400 // startReceiver's Workers; datagrams per kind
	store := testStore(t)
	exporter := netip.MustParseAddr("198.51.100.7")
	rec := flowgen.Record{
		SrcAddr: netip.MustParseAddr("192.0.2.10"),
		DstAddr: netip.MustParseAddr("203.0.113.5"),
		SrcPort: 123, DstPort: 40000, Proto: flowgen.ProtoUDP,
		Bytes: 1400, Packets: 1,
	}
	netflowPipe := func() utils.FlowPipe {
		return utils.NewNetFlowPipe(&utils.PipeConfig{Producer: newDecodeProducer(store, (&sink{}).add)})
	}
	sflowPipe := func() utils.FlowPipe {
		return utils.NewSFlowPipe(&utils.PipeConfig{Producer: newDecodeProducer(store, (&sink{}).add)})
	}
	tests := []struct {
		name    string
		family  string
		pipe    utils.FlowPipe
		payload []byte
		want    int // errors among the n datagrams
	}{
		{"netflow garbage", "netflow", netflowPipe(), garbage, n},
		{"netflow v9 data before its template", "netflow", netflowPipe(), buildNetFlowV9OrphanData(), n},
		{"netflow v9 record that cannot be converted", "netflow", netflowPipe(), buildNetFlowV9Unconvertible(), n},
		{"sflow garbage", "sflow", sflowPipe(), garbage, n},
		{"recovered panic", "netflow", panicPipe{}, garbage, n},
		{"netflow v9 well-formed", "netflow", netflowPipe(),
			flowgen.BuildNetFlowV9([]flowgen.Record{rec}, flowgen.NetFlowV9Options{SourceID: 256}), 0},
		{"sflow well-formed", "sflow", sflowPipe(),
			flowgen.BuildSFlowV5([]flowgen.Record{rec}, flowgen.SFlowOptions{AgentIP: exporter, SamplingRate: 1024}), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decode := decoder(tt.family, tt.pipe)
			before := decodeErrorCount(tt.family)
			var returned atomic.Int64
			var wg sync.WaitGroup
			for range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range n / workers {
						msg := &utils.Message{
							Src:      netip.AddrPortFrom(exporter, 5000),
							Dst:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 2055),
							Payload:  tt.payload,
							Received: time.Now(),
						}
						if decode(msg) != nil {
							returned.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			if got := decodeErrorCount(tt.family) - before; got != float64(tt.want) {
				t.Errorf("decode_errors_total{proto=%s} delta = %v, want %d", tt.family, got, tt.want)
			}
			// The error still goes back to goflow2, for drainErrors to log.
			if got := returned.Load(); got != int64(tt.want) {
				t.Errorf("decoder returned %d errors, want %d", got, tt.want)
			}
		})
	}
}

// stallHandler is a slog.Handler whose Warn and Error lines block until
// release is closed: a journal that has stopped keeping up.
type stallHandler struct{ release chan struct{} }

func (h stallHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h stallHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h stallHandler) WithGroup(string) slog.Handler            { return h }

func (h stallHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		<-h.release
	}
	return nil
}

// TestListenerCountsDecodeErrorsWhileLogStalls sends junk to a started
// Ingester whose log has stalled: drainErrors blocks on its first line, and
// goflow2 drops every error it reports after that. It asserts
// kapkan_ingest_decode_errors_total still moved by exactly the number of
// datagrams sent; counted off goflow2's error channel, it stopped at one.
func TestListenerCountsDecodeErrorsWhileLogStalls(t *testing.T) {
	port := freeUDPPort(t)
	release := make(chan struct{})
	startNetFlowIngester(t, port, slog.New(stallHandler{release}))
	t.Cleanup(func() { close(release) }) // runs before the Stop registered above

	const n = 10
	before := decodeErrorCount("netflow")
	sendUDP(t, port, garbage, n)
	sendUDP(t, port, buildNetFlowV9OrphanData(), n)

	for deadline := time.Now().Add(10 * time.Second); decodeErrorCount("netflow")-before < 2*n && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if got := decodeErrorCount("netflow") - before; got != 2*n {
		t.Fatalf("decode_errors_total{proto=netflow} delta = %v, want %d", got, 2*n)
	}
}

// TestDrainErrorsLogsABurstPerKind floods drainErrors with each kind of error
// goflow2 reports and asserts it logs decodeErrLogBurst lines of each kind and
// one line saying it muted the rest, ignores the socket closing at Stop, and
// counts nothing: decoder counts, drainErrors only logs.
func TestDrainErrorsLogsABurstPerKind(t *testing.T) {
	var buf bytes.Buffer
	ing := &Ingester{log: slog.New(slog.NewJSONHandler(&buf, nil)), stopC: make(chan struct{})}
	errs := make(chan error)
	done := make(chan struct{})
	go func() {
		ing.drainErrors("netflow", errs)
		close(done)
	}()

	msg := &utils.Message{Src: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), 5000)}
	kinds := []struct {
		err  error  // as goflow2's receiver reports it
		line string // what drainErrors logs for it
	}{
		{&utils.ReceiverError{Err: &utils.PipeMessageError{Message: msg, Err: fmt.Errorf("NetFlowV9: %w", netflow.ErrorTemplateNotFound)}},
			"flow data before template (exporter warm-up)"},
		{&utils.ReceiverError{Err: &debug.PanicErrorMessage{Msg: msg, Inner: "parser bug"}},
			"recovered panic decoding flow"},
		{&utils.ReceiverError{Err: &utils.PipeMessageError{Message: msg, Err: errors.New("not a NetFlow packet")}},
			"flow decode error"},
	}
	before := decodeErrorCount("netflow")
	for range 4 * decodeErrLogBurst {
		for _, k := range kinds {
			errs <- k.err
		}
		errs <- &utils.ReceiverError{Err: net.ErrClosed} // the socket closing at Stop
	}
	close(errs)
	<-done

	logged, muted := map[string]int{}, map[string]int{}
	for dec := json.NewDecoder(&buf); dec.More(); {
		var line struct{ Msg, Muted string }
		if err := dec.Decode(&line); err != nil {
			t.Fatalf("log line: %v", err)
		}
		if line.Muted != "" {
			muted[line.Muted]++
		} else {
			logged[line.Msg]++
		}
	}
	for _, k := range kinds {
		if logged[k.line] != decodeErrLogBurst || muted[k.line] != 1 {
			t.Errorf("%q: logged %d times and muted %d, want %d and 1", k.line, logged[k.line], muted[k.line], decodeErrLogBurst)
		}
	}
	if len(logged) != len(kinds) || len(muted) != len(kinds) {
		t.Errorf("logged %v, muted %v: want only the %d kinds (a closed socket is not an error)", logged, muted, len(kinds))
	}
	if got := decodeErrorCount("netflow") - before; got != 0 {
		t.Errorf("drainErrors moved decode_errors_total by %v, want 0: decoder counts, drainErrors only logs", got)
	}
}

// TestLogLimitWindow walks one logLimit through a window and into the next.
func TestLogLimitWindow(t *testing.T) {
	var lim logLimit
	t0 := time.Now()
	for i := range decodeErrLogBurst {
		if ok, muted := lim.allow(t0); !ok || muted {
			t.Fatalf("line %d of the window: ok=%v muted=%v, want it logged", i+1, ok, muted)
		}
	}
	if ok, muted := lim.allow(t0.Add(decodeErrLogWindow / 2)); ok || !muted {
		t.Fatalf("first line past the burst: ok=%v muted=%v, want it refused with the muted notice", ok, muted)
	}
	if ok, muted := lim.allow(t0.Add(decodeErrLogWindow - time.Nanosecond)); ok || muted {
		t.Fatalf("second line past the burst: ok=%v muted=%v, want it refused silently", ok, muted)
	}
	if ok, muted := lim.allow(t0.Add(decodeErrLogWindow)); !ok || muted {
		t.Fatalf("first line of the next window: ok=%v muted=%v, want it logged", ok, muted)
	}
}

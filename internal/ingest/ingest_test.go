package ingest

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"github.com/netsampler/goflow2/v2/utils"
)

const ingestYAML = `
listen:
  sflow: ":6343"
  netflow: ":2055"
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
`

type sink struct {
	mu    sync.Mutex
	flows []flow.Flow
}

func (s *sink) add(f flow.Flow) {
	s.mu.Lock()
	s.flows = append(s.flows, f)
	s.mu.Unlock()
}

func (s *sink) snapshot() []flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

func testStore(t *testing.T) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(ingestYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return config.NewStore("", cfg)
}

// feed pushes a synthetic datagram through the production conversion path.
func feed(t *testing.T, store *config.Store, s *sink, payload []byte, sflow bool, exporter netip.Addr) {
	t.Helper()
	prod := newDecodeProducer(store, s.add)
	defer prod.Close()
	var pipe utils.FlowPipe
	if sflow {
		pipe = utils.NewSFlowPipe(&utils.PipeConfig{Producer: prod})
	} else {
		pipe = utils.NewNetFlowPipe(&utils.PipeConfig{Producer: prod})
	}
	defer pipe.Close()
	msg := &utils.Message{
		Src:      netip.AddrPortFrom(exporter, 5000),
		Dst:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 2055),
		Payload:  payload,
		Received: time.Now(),
	}
	if err := pipe.DecodeFlow(msg); err != nil {
		t.Fatalf("DecodeFlow: %v", err)
	}
}

func TestConvertSFlow(t *testing.T) {
	store := testStore(t)
	s := &sink{}
	rec := flowgen.Record{
		SrcAddr: netip.MustParseAddr("192.0.2.10"),
		DstAddr: netip.MustParseAddr("203.0.113.5"),
		SrcPort: 123, DstPort: 40000, Proto: flowgen.ProtoUDP,
		Bytes: 1400, Packets: 1,
	}
	exporter := netip.MustParseAddr("198.51.100.7")
	payload := flowgen.BuildSFlowV5([]flowgen.Record{rec}, flowgen.SFlowOptions{AgentIP: exporter, SamplingRate: 1024})
	feed(t, store, s, payload, true, exporter)

	flows := s.snapshot()
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Wire != flow.ProtoSFlow5 {
		t.Errorf("wire = %v, want sflow5", f.Wire)
	}
	if f.DstAddr != rec.DstAddr || f.SrcAddr != rec.SrcAddr {
		t.Errorf("addrs = %v->%v, want %v->%v", f.SrcAddr, f.DstAddr, rec.SrcAddr, rec.DstAddr)
	}
	if f.SamplingRate != 1024 {
		t.Errorf("samplingRate = %d, want 1024", f.SamplingRate)
	}
	if f.Exporter != exporter {
		t.Errorf("exporter = %v, want %v", f.Exporter, exporter)
	}
}

func TestConvertNetFlowAppliesDefaultRate(t *testing.T) {
	store := testStore(t)
	s := &sink{}
	rec := flowgen.Record{
		SrcAddr: netip.MustParseAddr("192.0.2.20"),
		DstAddr: netip.MustParseAddr("203.0.113.6"),
		SrcPort: 12345, DstPort: 443, Proto: flowgen.ProtoTCP, TCPFlags: flowgen.TCPSyn,
		Bytes: 1500, Packets: 3,
	}
	exporter := netip.MustParseAddr("198.51.100.9")
	// No SamplingRate in the datagram -> the configured default (1000) must
	// be applied during conversion.
	payload := flowgen.BuildNetFlowV9([]flowgen.Record{rec}, flowgen.NetFlowV9Options{SourceID: 256})
	feed(t, store, s, payload, false, exporter)

	flows := s.snapshot()
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.Wire != flow.ProtoNetFlow9 {
		t.Errorf("wire = %v, want netflow9", f.Wire)
	}
	if f.SamplingRate != 1000 {
		t.Errorf("samplingRate = %d, want 1000 (config default fallback)", f.SamplingRate)
	}
	if f.TCPFlags != flowgen.TCPSyn {
		t.Errorf("tcpFlags = %#x, want %#x", f.TCPFlags, flowgen.TCPSyn)
	}
	if f.Bytes != 1500 || f.Packets != 3 {
		t.Errorf("bytes/packets = %d/%d, want 1500/3", f.Bytes, f.Packets)
	}
}

func TestConvertNetFlowReportedRateWins(t *testing.T) {
	store := testStore(t)
	s := &sink{}
	rec := flowgen.Record{
		SrcAddr: netip.MustParseAddr("192.0.2.20"),
		DstAddr: netip.MustParseAddr("203.0.113.6"),
		SrcPort: 80, DstPort: 5000, Proto: flowgen.ProtoUDP, Bytes: 100, Packets: 1,
	}
	payload := flowgen.BuildNetFlowV9([]flowgen.Record{rec}, flowgen.NetFlowV9Options{SourceID: 256, SamplingRate: 4096})
	feed(t, store, s, payload, false, netip.MustParseAddr("198.51.100.9"))

	flows := s.snapshot()
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	if flows[0].SamplingRate != 4096 {
		t.Errorf("samplingRate = %d, want 4096 (reported rate beats default)", flows[0].SamplingRate)
	}
}

func TestSplitListen(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{":6343", "", 6343, false},
		{"127.0.0.1:2055", "127.0.0.1", 2055, false},
		{"0.0.0.0:0", "", 0, true},
		{"nope", "", 0, true},
		{":99999", "", 0, true},
	}
	for _, tt := range tests {
		host, port, err := splitListen(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("splitListen(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && (host != tt.wantHost || port != tt.wantPort) {
			t.Errorf("splitListen(%q) = %q,%d, want %q,%d", tt.in, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

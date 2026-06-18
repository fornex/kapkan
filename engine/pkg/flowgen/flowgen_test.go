package flowgen

import (
	"net/netip"
	"testing"
	"time"

	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/utils"
)

// decoded is a flattened view of a goflow2 proto message for assertions.
type decoded struct {
	src, dst     netip.Addr
	sampler      netip.Addr
	srcPort      uint16
	dstPort      uint16
	proto        uint8
	tcpFlags     uint8
	bytes        uint64
	packets      uint64
	samplingRate uint64
}

// collector implements producer wrapping to capture decoded messages.
type collector struct {
	inner producer.ProducerInterface
	out   *[]decoded
}

func (c *collector) Produce(msg interface{}, args *producer.ProduceArgs) ([]producer.ProducerMessage, error) {
	set, err := c.inner.Produce(msg, args)
	for _, m := range set {
		pm, ok := m.(*protoproducer.ProtoProducerMessage)
		if !ok {
			continue
		}
		src, _ := netip.AddrFromSlice(pm.SrcAddr)
		dst, _ := netip.AddrFromSlice(pm.DstAddr)
		smp, _ := netip.AddrFromSlice(pm.SamplerAddress)
		*c.out = append(*c.out, decoded{
			src:          src.Unmap(),
			dst:          dst.Unmap(),
			sampler:      smp.Unmap(),
			srcPort:      uint16(pm.SrcPort),
			dstPort:      uint16(pm.DstPort),
			proto:        uint8(pm.Proto),
			tcpFlags:     uint8(pm.TcpFlags),
			bytes:        pm.Bytes,
			packets:      pm.Packets,
			samplingRate: pm.SamplingRate,
		})
	}
	return set, err
}

func (c *collector) Commit(set []producer.ProducerMessage) { c.inner.Commit(set) }
func (c *collector) Close()                                { c.inner.Close() }

func decode(t *testing.T, payload []byte, sflow bool, exporter netip.Addr) []decoded {
	t.Helper()
	var got []decoded
	cfg, err := (&protoproducer.ProducerConfig{}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := protoproducer.CreateProtoProducer(cfg, protoproducer.CreateSamplingSystem)
	if err != nil {
		t.Fatal(err)
	}
	prod := &collector{inner: inner, out: &got}
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
		t.Fatalf("DecodeFlow error = %v", err)
	}
	return got
}

func TestSFlowV5RoundTrip(t *testing.T) {
	rec := Record{
		SrcAddr: netip.MustParseAddr("192.0.2.10"),
		DstAddr: netip.MustParseAddr("203.0.113.5"),
		SrcPort: 123,
		DstPort: 40000,
		Proto:   ProtoUDP,
		Bytes:   1400,
		Packets: 1,
	}
	exporter := netip.MustParseAddr("198.51.100.7")
	payload := BuildSFlowV5([]Record{rec}, SFlowOptions{AgentIP: exporter, SamplingRate: 1024})
	got := decode(t, payload, true, exporter)
	if len(got) != 1 {
		t.Fatalf("decoded %d flows, want 1", len(got))
	}
	d := got[0]
	if d.src != rec.SrcAddr {
		t.Errorf("src = %v, want %v", d.src, rec.SrcAddr)
	}
	if d.dst != rec.DstAddr {
		t.Errorf("dst = %v, want %v", d.dst, rec.DstAddr)
	}
	if d.srcPort != 123 || d.dstPort != 40000 {
		t.Errorf("ports = %d/%d, want 123/40000", d.srcPort, d.dstPort)
	}
	if d.proto != ProtoUDP {
		t.Errorf("proto = %d, want %d", d.proto, ProtoUDP)
	}
	if d.samplingRate != 1024 {
		t.Errorf("samplingRate = %d, want 1024", d.samplingRate)
	}
	// sFlow producer sets Bytes from FrameLength — the record's on-wire
	// size, not the truncated captured header — and Packets = 1.
	if d.bytes != 1400 {
		t.Errorf("bytes = %d, want 1400 (FrameLength must carry Record.Bytes)", d.bytes)
	}
	if d.packets != 1 {
		t.Errorf("packets = %d, want 1", d.packets)
	}
	// sFlow SamplerAddress is the agent IP from the datagram.
	if d.sampler != exporter {
		t.Errorf("sampler = %v, want %v (agent IP)", d.sampler, exporter)
	}
}

func TestNetFlowV9RoundTrip(t *testing.T) {
	recs := []Record{
		{
			SrcAddr: netip.MustParseAddr("192.0.2.20"),
			DstAddr: netip.MustParseAddr("203.0.113.6"),
			SrcPort: 12345, DstPort: 443, Proto: ProtoTCP, TCPFlags: TCPSyn,
			Bytes: 1500, Packets: 3,
		},
		{
			SrcAddr: netip.MustParseAddr("192.0.2.21"),
			DstAddr: netip.MustParseAddr("203.0.113.6"),
			SrcPort: 12346, DstPort: 443, Proto: ProtoTCP, TCPFlags: TCPSyn,
			Bytes: 800, Packets: 2,
		},
	}
	exporter := netip.MustParseAddr("198.51.100.9")
	payload := BuildNetFlowV9(recs, NetFlowV9Options{SourceID: 256, Sequence: 1, SamplingRate: 2000})
	got := decode(t, payload, false, exporter)
	if len(got) != 2 {
		t.Fatalf("decoded %d flows, want 2", len(got))
	}
	d := got[0]
	if d.src != recs[0].SrcAddr || d.dst != recs[0].DstAddr {
		t.Errorf("addrs = %v->%v, want %v->%v", d.src, d.dst, recs[0].SrcAddr, recs[0].DstAddr)
	}
	if d.srcPort != 12345 || d.dstPort != 443 {
		t.Errorf("ports = %d/%d, want 12345/443", d.srcPort, d.dstPort)
	}
	if d.proto != ProtoTCP {
		t.Errorf("proto = %d, want TCP", d.proto)
	}
	if d.tcpFlags != TCPSyn {
		t.Errorf("tcpFlags = %#x, want %#x", d.tcpFlags, TCPSyn)
	}
	if d.bytes != 1500 || d.packets != 3 {
		t.Errorf("bytes/packets = %d/%d, want 1500/3", d.bytes, d.packets)
	}
	if d.samplingRate != 2000 {
		t.Errorf("samplingRate = %d, want 2000 (from options template)", d.samplingRate)
	}
	// NetFlow SamplerAddress is the UDP source (exporter).
	if d.sampler != exporter {
		t.Errorf("sampler = %v, want %v", d.sampler, exporter)
	}
}

func TestNetFlowV9IPv6(t *testing.T) {
	rec := Record{
		SrcAddr: netip.MustParseAddr("2001:db8::1"),
		DstAddr: netip.MustParseAddr("2001:db8::2"),
		SrcPort: 53, DstPort: 33000, Proto: ProtoUDP,
		Bytes: 1300, Packets: 1,
	}
	payload := BuildNetFlowV9([]Record{rec}, NetFlowV9Options{SourceID: 256, Sequence: 1})
	got := decode(t, payload, false, netip.MustParseAddr("198.51.100.9"))
	if len(got) != 1 {
		t.Fatalf("decoded %d flows, want 1", len(got))
	}
	if got[0].src != rec.SrcAddr || got[0].dst != rec.DstAddr {
		t.Errorf("addrs = %v->%v, want %v->%v", got[0].src, got[0].dst, rec.SrcAddr, rec.DstAddr)
	}
}

func TestNetFlowV9NoSamplingRate(t *testing.T) {
	// Without an options record, goflow2 reports samplingRate 0.
	rec := Record{
		SrcAddr: netip.MustParseAddr("192.0.2.30"),
		DstAddr: netip.MustParseAddr("203.0.113.7"),
		SrcPort: 1000, DstPort: 80, Proto: ProtoUDP, Bytes: 100, Packets: 1,
	}
	payload := BuildNetFlowV9([]Record{rec}, NetFlowV9Options{SourceID: 256})
	got := decode(t, payload, false, netip.MustParseAddr("198.51.100.9"))
	if len(got) != 1 {
		t.Fatalf("decoded %d flows, want 1", len(got))
	}
	if got[0].samplingRate != 0 {
		t.Errorf("samplingRate = %d, want 0 (no options record)", got[0].samplingRate)
	}
}

func TestPatternsDecode(t *testing.T) {
	victim := netip.MustParseAddr("203.0.113.50")
	tests := []struct {
		name         string
		pattern      AttackPattern
		wantProto    uint8
		wantFlags    uint8
		checkSrcPort func(uint16) bool
	}{
		{"udp flood", UDPFlood, ProtoUDP, 0, func(uint16) bool { return true }},
		{"syn flood", SYNFlood, ProtoTCP, TCPSyn, func(uint16) bool { return true }},
		{"ntp amp", NTPAmplification, ProtoUDP, 0, func(p uint16) bool { return p == 123 }},
		{"dns amp", DNSAmplification, ProtoUDP, 0, func(p uint16) bool { return p == 53 }},
		{"cldap amp", CLDAPAmplification, ProtoUDP, 0, func(p uint16) bool { return p == 389 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := PatternParams{Pattern: tt.pattern, Victim: victim, Records: 10}.Build()
			if len(recs) != 10 {
				t.Fatalf("built %d records, want 10", len(recs))
			}
			payload := BuildSFlowV5(recs, SFlowOptions{SamplingRate: 100})
			got := decode(t, payload, true, netip.MustParseAddr("198.51.100.1"))
			if len(got) != 10 {
				t.Fatalf("decoded %d flows, want 10", len(got))
			}
			for _, d := range got {
				if d.dst != victim {
					t.Errorf("dst = %v, want victim %v", d.dst, victim)
				}
				if d.proto != tt.wantProto {
					t.Errorf("proto = %d, want %d", d.proto, tt.wantProto)
				}
				if d.tcpFlags != tt.wantFlags {
					t.Errorf("tcpFlags = %#x, want %#x", d.tcpFlags, tt.wantFlags)
				}
				if !tt.checkSrcPort(d.srcPort) {
					t.Errorf("srcPort %d failed pattern check", d.srcPort)
				}
			}
		})
	}
}

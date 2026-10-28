package flowgen

import (
	"encoding/binary"
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
	fragOffset   uint32
	// What RouterTemplate and ExtendedSwitch add.
	inIf, outIf      uint32
	nextHop          netip.Addr
	srcAS, dstAS     uint32
	srcMask, dstMask uint32
	srcVLAN, dstVLAN uint32
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
		nh, _ := netip.AddrFromSlice(pm.NextHop)
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
			fragOffset:   pm.FragmentOffset,
			inIf:         pm.InIf,
			outIf:        pm.OutIf,
			nextHop:      nh.Unmap(),
			srcAS:        pm.SrcAs,
			dstAS:        pm.DstAs,
			srcMask:      pm.SrcNet,
			dstMask:      pm.DstNet,
			srcVLAN:      pm.SrcVlan,
			dstVLAN:      pm.DstVlan,
		})
	}
	return set, err
}

func (c *collector) Commit(set []producer.ProducerMessage) { c.inner.Commit(set) }
func (c *collector) Close()                                { c.inner.Close() }

func decode(t *testing.T, payload []byte, sflow bool, exporter netip.Addr) []decoded {
	t.Helper()
	return decodeAll(t, [][]byte{payload}, sflow, exporter)
}

// decodeAll feeds payloads through one pipe, in order, the way one exporter's
// datagrams reach a collector, so a template sent in one is there for the next.
func decodeAll(t *testing.T, payloads [][]byte, sflow bool, exporter netip.Addr) []decoded {
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
	for _, payload := range payloads {
		msg := &utils.Message{
			Src:      netip.AddrPortFrom(exporter, 5000),
			Dst:      netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 2055),
			Payload:  payload,
			Received: time.Now(),
		}
		if err := pipe.DecodeFlow(msg); err != nil {
			t.Fatalf("DecodeFlow error = %v", err)
		}
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

// TestNetFlowV9RouterTemplate decodes the router-shaped record in both
// address families: the ten extra elements must come back with their fixed
// values, and the eight kapkan reads must be unchanged by sharing a template
// with them — including the fragment element, which follows them.
func TestNetFlowV9RouterTemplate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst netip.Addr
		nextHop  netip.Addr
		mask     uint32
	}{
		{"ipv4", netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("203.0.113.6"), netip.MustParseAddr("192.0.2.1"), 24},
		{"ipv6", netip.MustParseAddr("2001:db8::20"), netip.MustParseAddr("2001:db8::6"), netip.MustParseAddr("2001:db8::1"), 48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs := []Record{
				{SrcAddr: tc.src, DstAddr: tc.dst, SrcPort: 12345, DstPort: 443, Proto: ProtoTCP, TCPFlags: TCPSyn, Bytes: 1500, Packets: 3},
				{SrcAddr: tc.src, DstAddr: tc.dst, Proto: ProtoICMP, Fragment: true, Bytes: 600, Packets: 1},
			}
			payload := BuildNetFlowV9(recs, NetFlowV9Options{SourceID: 256, Uptime: 60_000, SamplingRate: 2000, RouterTemplate: true})
			got := decode(t, payload, false, netip.MustParseAddr("198.51.100.9"))
			if len(got) != 2 {
				t.Fatalf("decoded %d flows, want 2", len(got))
			}
			d := got[0]
			if d.src != tc.src || d.dst != tc.dst {
				t.Errorf("addrs = %v->%v, want %v->%v", d.src, d.dst, tc.src, tc.dst)
			}
			if d.srcPort != 12345 || d.dstPort != 443 || d.proto != ProtoTCP || d.tcpFlags != TCPSyn {
				t.Errorf("ports/proto/flags = %d/%d/%d/%#x, want 12345/443/%d/%#x", d.srcPort, d.dstPort, d.proto, d.tcpFlags, ProtoTCP, TCPSyn)
			}
			if d.bytes != 1500 || d.packets != 3 || d.samplingRate != 2000 {
				t.Errorf("bytes/packets/rate = %d/%d/%d, want 1500/3/2000", d.bytes, d.packets, d.samplingRate)
			}
			if d.inIf != 5 || d.outIf != 8 {
				t.Errorf("interfaces = %d/%d, want 5/8", d.inIf, d.outIf)
			}
			if d.nextHop != tc.nextHop {
				t.Errorf("next hop = %v, want %v", d.nextHop, tc.nextHop)
			}
			if d.srcAS != 64500 || d.dstAS != 64501 {
				t.Errorf("AS = %d/%d, want 64500/64501", d.srcAS, d.dstAS)
			}
			if d.srcMask != tc.mask || d.dstMask != tc.mask {
				t.Errorf("masks = %d/%d, want %d/%d", d.srcMask, d.dstMask, tc.mask, tc.mask)
			}
			if d.fragOffset != 0 || got[1].fragOffset == 0 {
				t.Errorf("fragment offsets = %d/%d, want 0 then non-zero", d.fragOffset, got[1].fragOffset)
			}
		})
	}
}

// TestNetFlowV9DataOnly sends what an exporter sends between template
// refreshes: data only, decodable because the template — and the sampling
// rate — came in an earlier datagram from the same exporter.
func TestNetFlowV9DataOnly(t *testing.T) {
	victim := netip.MustParseAddr("203.0.113.8")
	recs := PatternParams{Pattern: FragmentFlood, Victim: victim, Records: 3}.Build()
	opts := NetFlowV9Options{SourceID: 256, SamplingRate: 2000, RouterTemplate: true}
	first := BuildNetFlowV9(recs[:1], opts)
	opts.DataOnly = true
	data := BuildNetFlowV9(recs[1:], opts)

	if flowsets := binary.BigEndian.Uint16(data[2:4]); flowsets != 1 {
		t.Fatalf("data-only datagram carries %d flowsets, want 1", flowsets)
	}
	got := decodeAll(t, [][]byte{first, data}, false, netip.MustParseAddr("198.51.100.9"))
	if len(got) != 3 {
		t.Fatalf("decoded %d flows, want 3", len(got))
	}
	for _, d := range got[1:] {
		if d.dst != victim || d.fragOffset == 0 || d.inIf != 5 {
			t.Errorf("data-only flow = dst %v, fragOffset %d, inIf %d; want %v, non-zero, 5", d.dst, d.fragOffset, d.inIf, victim)
		}
		if d.samplingRate != 2000 {
			t.Errorf("samplingRate = %d, want 2000 (learned from the first datagram)", d.samplingRate)
		}
	}
}

// TestSFlowV5ExtendedSwitch decodes samples that carry an extended switch
// record after the raw header: the VLANs come back, and the flow read from
// the header is unchanged by the second record.
func TestSFlowV5ExtendedSwitch(t *testing.T) {
	rec := Record{
		SrcAddr: netip.MustParseAddr("192.0.2.10"),
		DstAddr: netip.MustParseAddr("203.0.113.5"),
		SrcPort: 123, DstPort: 40000, Proto: ProtoUDP, Bytes: 1400, Packets: 1,
	}
	exporter := netip.MustParseAddr("198.51.100.7")
	got := decode(t, BuildSFlowV5([]Record{rec, rec}, SFlowOptions{AgentIP: exporter, SamplingRate: 1024, ExtendedSwitch: true}), true, exporter)
	if len(got) != 2 {
		t.Fatalf("decoded %d flows, want 2", len(got))
	}
	for _, d := range got {
		if d.src != rec.SrcAddr || d.dst != rec.DstAddr || d.dstPort != 40000 || d.bytes != 1400 || d.samplingRate != 1024 {
			t.Errorf("flow = %v->%v:%d, %d bytes, rate %d; want %v->%v:40000, 1400 bytes, rate 1024",
				d.src, d.dst, d.dstPort, d.bytes, d.samplingRate, rec.SrcAddr, rec.DstAddr)
		}
		if d.srcVLAN != 10 || d.dstVLAN != 20 {
			t.Errorf("VLANs = %d/%d, want 10/20", d.srcVLAN, d.dstVLAN)
		}
	}
	if plain := decode(t, BuildSFlowV5([]Record{rec}, SFlowOptions{AgentIP: exporter}), true, exporter); plain[0].srcVLAN != 0 {
		t.Errorf("srcVLAN = %d without ExtendedSwitch, want 0", plain[0].srcVLAN)
	}
}

// TestFragmentFloodDecodes proves Record.Fragment is not a generator-only
// fiction: both wire builders encode it where a real exporter would (a v9
// fragmentOffset element, an sFlow IPv4 fragment-offset field), so the
// decoder reports a non-zero offset — which is exactly what internal/ingest
// turns into flow.Flow.Fragment and what the engine's frag_pps counter is
// built from.
func TestFragmentFloodDecodes(t *testing.T) {
	victim := netip.MustParseAddr("203.0.113.50")
	agent := netip.MustParseAddr("198.51.100.1")
	recs := PatternParams{Pattern: FragmentFlood, Victim: victim, Records: 6}.Build()
	for _, r := range recs {
		if !r.Fragment {
			t.Fatal("FragmentFlood built a record with Fragment unset")
		}
	}

	for _, tc := range []struct {
		name    string
		payload []byte
		sflow   bool
	}{
		{"sflow", BuildSFlowV5(recs, SFlowOptions{SamplingRate: 100}), true},
		{"netflow9", BuildNetFlowV9(recs, NetFlowV9Options{SourceID: 1, SamplingRate: 100}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decode(t, tc.payload, tc.sflow, agent)
			if len(got) != len(recs) {
				t.Fatalf("decoded %d flows, want %d", len(got), len(recs))
			}
			for _, d := range got {
				if d.fragOffset == 0 {
					t.Errorf("fragmentOffset = 0, want non-zero (the record is a non-first fragment)")
				}
			}
		})
	}

	// And an unfragmented set must still decode with offset 0 — the element is
	// only added to the template when something in the set needs it.
	plain := PatternParams{Pattern: UDPFlood, Victim: victim, Records: 3}.Build()
	for _, d := range decode(t, BuildNetFlowV9(plain, NetFlowV9Options{SourceID: 1}), false, agent) {
		if d.fragOffset != 0 {
			t.Errorf("fragmentOffset = %d on an unfragmented record, want 0", d.fragOffset)
		}
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
		{"memcached amp", MemcachedAmplification, ProtoUDP, 0, func(p uint16) bool { return p == 11211 }},
		{"ssdp amp", SSDPAmplification, ProtoUDP, 0, func(p uint16) bool { return p == 1900 }},
		{"chargen amp", ChargenAmplification, ProtoUDP, 0, func(p uint16) bool { return p == 19 }},
		{"ack flood", ACKFlood, ProtoTCP, TCPAck, func(uint16) bool { return true }},
		{"icmp flood", ICMPFlood, ProtoICMP, 0, func(p uint16) bool { return p == 0 }},
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

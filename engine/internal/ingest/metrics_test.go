package ingest

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"github.com/netsampler/goflow2/v2/utils"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fiveFlows returns five IPv4 records, enough to tell a count per datagram
// from a count per flow.
func fiveFlows() []flowgen.Record {
	recs := make([]flowgen.Record, 5)
	for i := range recs {
		recs[i] = flowgen.Record{
			SrcAddr: netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}),
			DstAddr: netip.MustParseAddr("203.0.113.5"),
			SrcPort: 123, DstPort: uint16(40000 + i), Proto: flowgen.ProtoUDP,
			Bytes: 1400, Packets: 1,
		}
	}
	return recs
}

// buildSFlowCountersOnly crafts an sFlow v5 datagram whose only sample is a
// counter sample — what an agent sends every polling interval whether or not
// it sampled any traffic. It decodes and carries no flow records. flowgen
// builds flow samples only, so this one is hand-crafted on the wire.
func buildSFlowCountersOnly(agent netip.Addr) []byte {
	a := agent.As4()
	pkt := binary.BigEndian.AppendUint32(nil, 5) // version
	pkt = binary.BigEndian.AppendUint32(pkt, 1)  // agent address type: IPv4
	pkt = append(pkt, a[:]...)
	pkt = binary.BigEndian.AppendUint32(pkt, 0) // sub-agent id
	pkt = binary.BigEndian.AppendUint32(pkt, 1) // sequence number
	pkt = binary.BigEndian.AppendUint32(pkt, 0) // uptime
	pkt = binary.BigEndian.AppendUint32(pkt, 1) // samples
	// One counter sample (format 2) with no counter records in it.
	pkt = binary.BigEndian.AppendUint32(pkt, 2)  // sample format: counter
	pkt = binary.BigEndian.AppendUint32(pkt, 12) // sample length
	pkt = binary.BigEndian.AppendUint32(pkt, 1)  // sample sequence number
	pkt = binary.BigEndian.AppendUint32(pkt, 1)  // source: ifIndex 1
	pkt = binary.BigEndian.AppendUint32(pkt, 0)  // counter records
	return pkt
}

// buildNetFlowV9TemplateOnly crafts a NetFlow v9 datagram that carries a
// template and no data — what an exporter sends on a template refresh. It
// decodes and carries no flow records. flowgen always adds a data flowset, so
// this one is hand-crafted on the wire.
func buildNetFlowV9TemplateOnly() []byte {
	pkt := binary.BigEndian.AppendUint16(nil, 9)  // version
	pkt = binary.BigEndian.AppendUint16(pkt, 1)   // count: one flowset
	pkt = binary.BigEndian.AppendUint32(pkt, 0)   // system uptime
	pkt = binary.BigEndian.AppendUint32(pkt, 0)   // unix seconds
	pkt = binary.BigEndian.AppendUint32(pkt, 1)   // sequence number
	pkt = binary.BigEndian.AppendUint32(pkt, 256) // source id
	// Template flowset: template 256, two fields (IPv4 source and destination).
	pkt = binary.BigEndian.AppendUint16(pkt, 0)   // flowset id: template
	pkt = binary.BigEndian.AppendUint16(pkt, 16)  // flowset length
	pkt = binary.BigEndian.AppendUint16(pkt, 256) // template id
	pkt = binary.BigEndian.AppendUint16(pkt, 2)   // field count
	pkt = binary.BigEndian.AppendUint16(pkt, 8)   // IPV4_SRC_ADDR
	pkt = binary.BigEndian.AppendUint16(pkt, 4)
	pkt = binary.BigEndian.AppendUint16(pkt, 12) // IPV4_DST_ADDR
	pkt = binary.BigEndian.AppendUint16(pkt, 4)
	return pkt
}

// TestPacketsTotalCountsDatagrams pins the unit of kapkan_ingest_packets_total:
// one per decoded datagram however many flow records it carries — none
// included — on the exporter series its flows carry, while flows_total counts
// the records.
func TestPacketsTotalCountsDatagrams(t *testing.T) {
	store := testStore(t)
	udpSrc := netip.MustParseAddr("192.0.2.201")   // every datagram's UDP source
	agent := netip.MustParseAddr("198.51.100.201") // the agent an sFlow datagram names
	recs := fiveFlows()

	tests := []struct {
		name     string
		payload  []byte
		sflow    bool
		proto    string
		exporter netip.Addr // the series the datagram lands on
		flows    float64
	}{
		{"sflow five flow samples", flowgen.BuildSFlowV5(recs, flowgen.SFlowOptions{AgentIP: agent, SamplingRate: 1024}), true, "sflow5", agent, 5},
		{"sflow counters only", buildSFlowCountersOnly(agent), true, "sflow5", agent, 0},
		{"netflow9 five records", flowgen.BuildNetFlowV9(recs, flowgen.NetFlowV9Options{SourceID: 256}), false, "netflow9", udpSrc, 5},
		{"netflow9 template only", buildNetFlowV9TemplateOnly(), false, "netflow9", udpSrc, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs := []netip.Addr{udpSrc, agent}
			before := make([]float64, len(addrs))
			for i, a := range addrs {
				before[i] = testutil.ToFloat64(metrics.PacketsTotal.WithLabelValues(a.String(), tt.proto))
			}
			flowsBefore := testutil.ToFloat64(metrics.FlowsTotal.WithLabelValues(tt.proto))

			feed(t, store, &sink{}, tt.payload, tt.sflow, udpSrc)

			for i, a := range addrs {
				want := 0.0
				if a == tt.exporter {
					want = 1
				}
				got := testutil.ToFloat64(metrics.PacketsTotal.WithLabelValues(a.String(), tt.proto)) - before[i]
				if got != want {
					t.Errorf("packets_total{exporter=%q,proto=%q} delta = %v, want %v", a, tt.proto, got, want)
				}
			}
			if got := testutil.ToFloat64(metrics.FlowsTotal.WithLabelValues(tt.proto)) - flowsBefore; got != tt.flows {
				t.Errorf("flows_total{proto=%q} delta = %v, want %v", tt.proto, got, tt.flows)
			}
		})
	}
}

// TestDroppedFlowsTotalCountsDatagrams pins the unit of
// kapkan_ingest_dropped_flows_total: the receiver reports a drop once per
// datagram it could not queue, before anything decodes it, so a datagram
// carrying five flow records counts once.
func TestDroppedFlowsTotalCountsDatagrams(t *testing.T) {
	before := testutil.ToFloat64(metrics.DroppedFlowsTotal)
	dropCounter{}.Dropped(utils.Message{
		Src:     netip.AddrPortFrom(netip.MustParseAddr("192.0.2.201"), 5000),
		Payload: flowgen.BuildNetFlowV9(fiveFlows(), flowgen.NetFlowV9Options{SourceID: 256}),
	})
	if got := testutil.ToFloat64(metrics.DroppedFlowsTotal) - before; got != 1 {
		t.Errorf("dropped_flows_total delta = %v, want 1 (one per datagram)", got)
	}
}

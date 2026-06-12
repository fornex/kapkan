// Package flowgen builds synthetic NetFlow v9 and sFlow v5 datagrams on the
// wire, byte-for-byte, so tests and load benchmarks can exercise the real
// goflow2 decoders without a router. Builders encode attack patterns (UDP
// flood, SYN flood, NTP/DNS/CLDAP amplification) at configurable scale.
//
// All multi-byte integers are big-endian, matching goflow2's decoders and
// network byte order. See docs/research/wireformats.md for the exact field
// semantics each builder relies on.
package flowgen

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

// NetFlow v9 information-element type numbers honored by goflow2.
const (
	ieInBytes          = 1
	ieInPkts           = 2
	ieProtocol         = 4
	ieTCPFlags         = 6
	ieL4SrcPort        = 7
	ieIPv4Src          = 8
	ieL4DstPort        = 11
	ieIPv4Dst          = 12
	ieIPv6Src          = 27
	ieIPv6Dst          = 28
	ieSamplingInterval = 34 // honored only in an options-data record
)

// IP protocol numbers used by the generated records.
const (
	ProtoTCP = 6
	ProtoUDP = 17
)

// TCP flag bits.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
)

func beU16(b *bytes.Buffer, v uint16) {
	var t [2]byte
	binary.BigEndian.PutUint16(t[:], v)
	b.Write(t[:])
}

func beU32(b *bytes.Buffer, v uint32) {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	b.Write(t[:])
}

// Record is one synthetic flow to encode. Bytes/Packets are the raw
// (pre-sampling) counters; the exporter's sampling rate is carried out of
// band in the datagram so the decoder reports it.
type Record struct {
	SrcAddr  netip.Addr
	DstAddr  netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	TCPFlags uint8
	Bytes    uint32
	Packets  uint32
}

// NetFlowV9Options configures a NetFlow v9 datagram.
type NetFlowV9Options struct {
	// AgentIP is the exporter (router) address; also used as the UDP source
	// when replayed, but encoded only implicitly via the transport.
	SourceID uint32 // observation domain
	Sequence uint32
	Uptime   uint32 // ms
	UnixSecs uint32
	// SamplingRate, when > 0, is advertised via an options template + options
	// data record (the only way goflow2 reports a v9 sampling rate). It is
	// keyed to SourceID, so send it at least once before/with data records.
	SamplingRate uint32
}

// BuildNetFlowV9 encodes one NetFlow v9 datagram carrying recs as a single
// IPv4 or IPv6 data flowset (records must be homogeneous in address family).
// When opts.SamplingRate > 0 an options template + options data flowset are
// prepended so the decoder reports that rate.
func BuildNetFlowV9(recs []Record, opts NetFlowV9Options) []byte {
	if len(recs) == 0 {
		return nil
	}
	isV6 := recs[0].DstAddr.Is6() && !recs[0].DstAddr.Is4In6()

	const dataTemplateID = 256
	const optTemplateID = 258

	var flowsets [][]byte
	flowsets = append(flowsets, buildDataTemplate(dataTemplateID, isV6))
	if opts.SamplingRate > 0 {
		flowsets = append(flowsets, buildOptionsTemplate(optTemplateID))
		flowsets = append(flowsets, buildOptionsData(optTemplateID, opts.SamplingRate))
	}
	flowsets = append(flowsets, buildDataFlowSet(dataTemplateID, recs, isV6))

	pkt := &bytes.Buffer{}
	beU16(pkt, 9)                     // Version
	beU16(pkt, uint16(len(flowsets))) // Count = number of flowsets
	beU32(pkt, opts.Uptime)           // SystemUptime (ms)
	beU32(pkt, opts.UnixSecs)         // UnixSeconds
	beU32(pkt, opts.Sequence)         // SequenceNumber
	beU32(pkt, opts.SourceID)         // SourceId (observation domain)
	for _, fs := range flowsets {
		pkt.Write(fs)
	}
	return pkt.Bytes()
}

// dataTemplateFields returns the field specifiers for the data template,
// choosing IPv4 or IPv6 address elements.
func dataTemplateFields(isV6 bool) [][2]uint16 {
	srcIE, dstIE, addrLen := uint16(ieIPv4Src), uint16(ieIPv4Dst), uint16(4)
	if isV6 {
		srcIE, dstIE, addrLen = ieIPv6Src, ieIPv6Dst, 16
	}
	return [][2]uint16{
		{srcIE, addrLen},
		{dstIE, addrLen},
		{ieL4SrcPort, 2},
		{ieL4DstPort, 2},
		{ieProtocol, 1},
		{ieTCPFlags, 1},
		{ieInBytes, 4},
		{ieInPkts, 4},
	}
}

func buildDataTemplate(templateID uint16, isV6 bool) []byte {
	fields := dataTemplateFields(isV6)
	body := &bytes.Buffer{}
	beU16(body, templateID)
	beU16(body, uint16(len(fields)))
	for _, f := range fields {
		beU16(body, f[0])
		beU16(body, f[1])
	}
	return wrapFlowSet(0, body.Bytes())
}

func buildDataFlowSet(templateID uint16, recs []Record, isV6 bool) []byte {
	body := &bytes.Buffer{}
	for _, r := range recs {
		if isV6 {
			s := r.SrcAddr.As16()
			d := r.DstAddr.As16()
			body.Write(s[:])
			body.Write(d[:])
		} else {
			s := r.SrcAddr.As4()
			d := r.DstAddr.As4()
			body.Write(s[:])
			body.Write(d[:])
		}
		beU16(body, r.SrcPort)
		beU16(body, r.DstPort)
		body.WriteByte(r.Proto)
		body.WriteByte(r.TCPFlags)
		beU32(body, r.Bytes)
		beU32(body, r.Packets)
	}
	return wrapFlowSet(templateID, body.Bytes())
}

// buildOptionsTemplate builds a v9 options template (FlowSet Id=1) with one
// System scope field and one SAMPLING_INTERVAL option field.
func buildOptionsTemplate(templateID uint16) []byte {
	body := &bytes.Buffer{}
	beU16(body, templateID)
	beU16(body, 4) // ScopeLength bytes (1 scope field * 4)
	beU16(body, 4) // OptionLength bytes (1 option field * 4)
	// Scope field: type 1 (System), length 4.
	beU16(body, 1)
	beU16(body, 4)
	// Option field: SAMPLING_INTERVAL (34), length 4.
	beU16(body, ieSamplingInterval)
	beU16(body, 4)
	return wrapFlowSet(1, body.Bytes())
}

// buildOptionsData builds the options data record carrying the sampling rate.
// Record layout = scope value (4 bytes) + option value (4 bytes).
func buildOptionsData(templateID uint16, rate uint32) []byte {
	body := &bytes.Buffer{}
	beU32(body, 0)    // scope (System) value
	beU32(body, rate) // SAMPLING_INTERVAL value
	return wrapFlowSet(templateID, body.Bytes())
}

// wrapFlowSet prepends the 4-byte flowset header (Id, Length) and pads the
// flowset to a 4-byte boundary; Length includes the header and padding.
func wrapFlowSet(id uint16, body []byte) []byte {
	total := 4 + len(body)
	pad := (4 - total%4) % 4
	out := &bytes.Buffer{}
	beU16(out, id)
	beU16(out, uint16(total+pad))
	out.Write(body)
	out.Write(make([]byte, pad))
	return out.Bytes()
}

// SFlowOptions configures an sFlow v5 datagram.
type SFlowOptions struct {
	AgentIP      netip.Addr
	SubAgentID   uint32
	Sequence     uint32
	Uptime       uint32
	SamplingRate uint32 // per-sample rate, reported directly by the decoder
}

// BuildSFlowV5 encodes one sFlow v5 datagram with one flow sample per record,
// each wrapping a synthetic Ethernet+IP+L4 raw packet header built from the
// Record. The sampling rate is taken from opts and applied to every sample.
func BuildSFlowV5(recs []Record, opts SFlowOptions) []byte {
	if len(recs) == 0 {
		return nil
	}
	rate := opts.SamplingRate
	if rate == 0 {
		rate = 1
	}

	samples := &bytes.Buffer{}
	for i, r := range recs {
		samples.Write(buildFlowSample(uint32(i+1), rate, r))
	}

	pkt := &bytes.Buffer{}
	beU32(pkt, 5) // Version
	agent := opts.AgentIP
	if !agent.IsValid() {
		agent = netip.MustParseAddr("198.51.100.1")
	}
	if agent.Is4() {
		beU32(pkt, 1) // IP version 1 = IPv4
		a := agent.As4()
		pkt.Write(a[:])
	} else {
		beU32(pkt, 2) // IP version 2 = IPv6
		a := agent.As16()
		pkt.Write(a[:])
	}
	beU32(pkt, opts.SubAgentID)
	beU32(pkt, opts.Sequence)
	beU32(pkt, opts.Uptime)
	beU32(pkt, uint32(len(recs))) // SamplesCount
	pkt.Write(samples.Bytes())
	return pkt.Bytes()
}

func buildFlowSample(seq, rate uint32, r Record) []byte {
	header := buildRawHeader(r)

	// Raw packet header record (data_format = 1).
	recBody := &bytes.Buffer{}
	beU32(recBody, 1)                   // Protocol = 1 (Ethernet) — required for parsing
	beU32(recBody, uint32(len(header))) // FrameLength -> Bytes
	beU32(recBody, 0)                   // Stripped
	beU32(recBody, uint32(len(header))) // OriginalLength
	recBody.Write(header)
	if pad := (4 - len(header)%4) % 4; pad > 0 {
		recBody.Write(make([]byte, pad)) // XDR 4-byte alignment (mandatory)
	}
	record := &bytes.Buffer{}
	beU32(record, 1) // record DataFormat = 1 (raw packet header)
	beU32(record, uint32(recBody.Len()))
	record.Write(recBody.Bytes())

	// Flow sample body (format = 1).
	body := &bytes.Buffer{}
	beU32(body, seq)       // SampleSequenceNumber
	beU32(body, (0<<24)|5) // sourceId: type 0, value 5
	beU32(body, rate)      // SamplingRate -> reported directly
	beU32(body, rate*100)  // SamplePool
	beU32(body, 0)         // Drops
	beU32(body, 5)         // Input ifIndex
	beU32(body, 8)         // Output ifIndex
	beU32(body, 1)         // FlowRecordsCount
	body.Write(record.Bytes())

	sample := &bytes.Buffer{}
	beU32(sample, 1) // Format = 1 (flow sample)
	beU32(sample, uint32(body.Len()))
	sample.Write(body.Bytes())
	return sample.Bytes()
}

// buildRawHeader assembles an Ethernet + IPv4/IPv6 + TCP/UDP header from the
// Record so goflow2's packet parser extracts addresses, ports and flags.
func buildRawHeader(r Record) []byte {
	h := &bytes.Buffer{}
	// Ethernet (14 bytes).
	h.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // dst mac
	h.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}) // src mac
	isV6 := r.DstAddr.Is6() && !r.DstAddr.Is4In6()
	l4 := buildL4(r)
	if isV6 {
		h.Write([]byte{0x86, 0xdd}) // ethertype IPv6
		// IPv6 header (40 bytes).
		h.WriteByte(0x60) // version + traffic class hi
		h.Write([]byte{0x00, 0x00, 0x00})
		beU16(h, uint16(len(l4))) // payload length
		h.WriteByte(r.Proto)      // next header (offset 6)
		h.WriteByte(64)           // hop limit
		s := r.SrcAddr.As16()
		d := r.DstAddr.As16()
		h.Write(s[:])
		h.Write(d[:])
	} else {
		h.Write([]byte{0x08, 0x00}) // ethertype IPv4
		// IPv4 header (20 bytes).
		h.WriteByte(0x45) // version + IHL
		h.WriteByte(0x00) // DSCP/ECN
		beU16(h, uint16(20+len(l4)))
		beU16(h, 0)     // id
		beU16(h, 0)     // flags + frag
		h.WriteByte(64) // TTL (offset 8)
		h.WriteByte(r.Proto)
		beU16(h, 0) // checksum (parser ignores)
		s := r.SrcAddr.As4()
		d := r.DstAddr.As4()
		h.Write(s[:])
		h.Write(d[:])
	}
	h.Write(l4)
	return h.Bytes()
}

func buildL4(r Record) []byte {
	l4 := &bytes.Buffer{}
	switch r.Proto {
	case ProtoTCP:
		beU16(l4, r.SrcPort)
		beU16(l4, r.DstPort)
		beU32(l4, 0)       // seq
		beU32(l4, 0)       // ack
		l4.WriteByte(0x50) // data offset (5 words)
		l4.WriteByte(r.TCPFlags)
		beU16(l4, 0) // window
		beU16(l4, 0) // checksum
		beU16(l4, 0) // urgent
	default: // treat anything else as UDP framing for header extraction
		beU16(l4, r.SrcPort)
		beU16(l4, r.DstPort)
		beU16(l4, 8) // length
		beU16(l4, 0) // checksum
	}
	return l4.Bytes()
}

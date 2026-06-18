package flowgen

import "net/netip"

// AttackPattern enumerates the synthetic attack shapes the generator can
// produce. Each sets characteristic ports and packet sizes so tests can
// assert on classification-relevant fields.
type AttackPattern int

// Supported attack patterns.
const (
	// UDPFlood is a generic high-pps UDP flood to a victim port.
	UDPFlood AttackPattern = iota
	// SYNFlood is a TCP SYN flood (SYN flag set, tiny packets).
	SYNFlood
	// NTPAmplification reflects off UDP/123 with large responses.
	NTPAmplification
	// DNSAmplification reflects off UDP/53 with large responses.
	DNSAmplification
	// CLDAPAmplification reflects off UDP/389 with large responses.
	CLDAPAmplification
)

// PatternParams shapes a generated attack toward a single victim.
type PatternParams struct {
	Pattern AttackPattern
	Victim  netip.Addr // destination (the protected host under attack)
	// Records is the number of flow records to generate.
	Records int
	// BytesPerRecord and PacketsPerRecord set the raw counters per record.
	// When zero, pattern-appropriate defaults are used.
	BytesPerRecord   uint32
	PacketsPerRecord uint32
	// SrcBase is the first source address; successive records increment it
	// to simulate many reflectors/bots. Defaults to 198.51.100.0.
	SrcBase netip.Addr
}

// reflectorPort returns the characteristic UDP source port for reflection
// attacks (the service being abused), 0 otherwise.
func (p AttackPattern) reflectorPort() uint16 {
	switch p {
	case NTPAmplification:
		return 123
	case DNSAmplification:
		return 53
	case CLDAPAmplification:
		return 389
	default:
		return 0
	}
}

// Build produces the flow records for the configured attack pattern.
func (pp PatternParams) Build() []Record {
	src := pp.SrcBase
	if !src.IsValid() {
		src = netip.MustParseAddr("198.51.100.0")
	}
	bytesPer := pp.BytesPerRecord
	pktsPer := pp.PacketsPerRecord
	if pktsPer == 0 {
		pktsPer = 1
	}

	proto := uint8(ProtoUDP)
	var flags uint8
	var srcPort, dstPort uint16
	switch pp.Pattern {
	case SYNFlood:
		proto = ProtoTCP
		flags = TCPSyn
		dstPort = 80
		if bytesPer == 0 {
			bytesPer = 60
		}
	case NTPAmplification, DNSAmplification, CLDAPAmplification:
		srcPort = pp.Pattern.reflectorPort()
		dstPort = 40000
		if bytesPer == 0 {
			bytesPer = 1400 // large reflected responses
		}
	default: // UDPFlood
		dstPort = 53413
		if bytesPer == 0 {
			bytesPer = 512
		}
	}

	recs := make([]Record, pp.Records)
	for i := range recs {
		sp := srcPort
		if sp == 0 {
			sp = uint16(1024 + (i % 60000)) // ephemeral source for floods
		}
		recs[i] = Record{
			SrcAddr:  nextAddr(src, i),
			DstAddr:  pp.Victim,
			SrcPort:  sp,
			DstPort:  dstPort,
			Proto:    proto,
			TCPFlags: flags,
			Bytes:    bytesPer,
			Packets:  pktsPer,
		}
	}
	return recs
}

// nextAddr returns base offset by n (wrapping within its address family),
// used to spread synthetic traffic across many source addresses.
func nextAddr(base netip.Addr, n int) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(n)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := base.As16()
	// Increment the low 32 bits — enough spread for tests.
	lo := uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	lo += uint32(n)
	b[12], b[13], b[14], b[15] = byte(lo>>24), byte(lo>>16), byte(lo>>8), byte(lo)
	return netip.AddrFrom16(b)
}

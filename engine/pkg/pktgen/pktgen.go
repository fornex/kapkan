// Package pktgen builds raw Ethernet/IP/L4 frames on the wire, byte-for-byte,
// and reads/writes them as classic libpcap capture files. Unlike pkg/flowgen,
// which fabricates NetFlow/sFlow *telemetry*, pktgen fabricates the *packets*
// themselves so the XDP/eBPF data plane can be exercised through
// BPF_PROG_TEST_RUN and gated by a committed pcap block-rate suite.
//
// Correctness of the checksums is the whole point: a wrong IPv4 header or
// TCP/UDP checksum silently invalidates every future block-rate number, so the
// checksum logic is cross-checked against hand-computed vectors in the tests.
//
// All multi-byte integers are big-endian (network byte order). Only the fields
// a Frame actually sets are guaranteed to survive a Build/WritePcap/ReadPcap
// round trip; see Frame for the exact set.
package pktgen

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IP protocol numbers understood by Frame.Build.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// TCP flag bits (matching the layout in pkg/flowgen for cross-package
// consistency).
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
	TCPUrg = 0x20
	TCPEce = 0x40
	TCPCwr = 0x80
)

// EtherType values emitted/parsed at L2.
const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	// tpid8021Q tags a single VLAN; tpid8021ad tags the outer of a stack.
	// Build emits 0x8100 for every tag; Parse accepts either.
	tpid8021Q  = 0x8100
	tpid8021ad = 0x88a8
)

// Frame describes a single L2 frame to synthesise. Zero values are sensible
// defaults: an all-zero MAC is emitted verbatim and TTL 0 is rewritten to 64.
//
// SrcIP and DstIP must share an address family. IPv4 fragmentation is driven by
// IPID, DontFragment, MoreFragments and FragOffset; IPv6 fragmentation (a
// fragment extension header) is not supported and Build rejects it.
//
// The following fields survive a Build -> WritePcap -> ReadPcap round trip
// unchanged: SrcMAC, DstMAC, VLANs, SrcIP, DstIP, Proto, SrcPort, DstPort,
// TCPFlags, ICMPType, ICMPCode, IPID, DontFragment, MoreFragments, FragOffset,
// TTL (once defaulted) and Payload.
type Frame struct {
	SrcMAC, DstMAC [6]byte
	// VLANs is an optional 802.1Q tag stack, outermost first. Each entry is a
	// full 16-bit TCI (PCP/DEI/VID). Build emits TPID 0x8100 per tag.
	VLANs []uint16

	SrcIP, DstIP netip.Addr

	Proto    uint8  // ProtoTCP, ProtoUDP, ProtoICMP or ProtoICMPv6
	SrcPort  uint16 // TCP/UDP only
	DstPort  uint16 // TCP/UDP only
	TCPFlags uint8  // TCP only

	ICMPType uint8 // ICMP/ICMPv6 only
	ICMPCode uint8 // ICMP/ICMPv6 only

	TTL uint8 // IPv4 TTL / IPv6 hop limit; 0 is rewritten to 64

	// IPv4 fragmentation.
	IPID          uint16
	DontFragment  bool
	MoreFragments bool
	FragOffset    uint16 // in units of 8 bytes; when >0 no L4 header is emitted

	// Payload is the L4 payload for a first/whole packet, or the raw IP payload
	// continuation when FragOffset > 0.
	Payload []byte
}

// Build serialises the frame into a complete L2 frame with a correct IPv4
// header checksum and correct TCP/UDP/ICMPv6 checksums (including the IPv6
// pseudo-header, where the L4 checksum is mandatory). It returns an error for
// an address-family mismatch, an invalid address, an unsupported protocol or a
// request for IPv6 fragmentation.
func (f Frame) Build() ([]byte, error) {
	if !f.SrcIP.IsValid() || !f.DstIP.IsValid() {
		return nil, fmt.Errorf("pktgen: SrcIP/DstIP must both be valid")
	}
	src, dst := f.SrcIP.Unmap(), f.DstIP.Unmap()
	if src.Is4() != dst.Is4() {
		return nil, fmt.Errorf("pktgen: SrcIP (%v) and DstIP (%v) address families differ", src, dst)
	}
	isV6 := src.Is6()
	if isV6 && (f.FragOffset != 0 || f.MoreFragments) {
		return nil, fmt.Errorf("pktgen: IPv6 fragmentation is not supported")
	}

	ttl := f.TTL
	if ttl == 0 {
		ttl = 64
	}

	// L4 bytes: absent for a non-first fragment (offset > 0), which carries a
	// raw payload continuation instead of an L4 header.
	var l4 []byte
	if f.FragOffset == 0 {
		var err error
		l4, err = f.buildL4(src, dst, isV6)
		if err != nil {
			return nil, err
		}
	} else {
		l4 = f.Payload
	}

	out := make([]byte, 0, 14+4*len(f.VLANs)+40+len(l4))

	// Ethernet header.
	out = append(out, f.DstMAC[:]...)
	out = append(out, f.SrcMAC[:]...)
	for _, tci := range f.VLANs {
		out = appendU16(out, tpid8021Q)
		out = appendU16(out, tci)
	}
	if isV6 {
		out = appendU16(out, etherTypeIPv6)
		out = f.appendIPv6(out, src, dst, ttl, l4)
	} else {
		out = appendU16(out, etherTypeIPv4)
		out = f.appendIPv4(out, src, dst, ttl, l4)
	}
	out = append(out, l4...)
	return out, nil
}

// appendIPv4 appends a 20-byte IPv4 header (no options) with a correct header
// checksum. totalLen covers the header plus l4.
func (f Frame) appendIPv4(out []byte, src, dst netip.Addr, ttl uint8, l4 []byte) []byte {
	start := len(out)
	out = append(out, 0x45, 0x00) // version 4, IHL 5, DSCP/ECN 0
	out = appendU16(out, uint16(20+len(l4)))
	out = appendU16(out, f.IPID)
	frag := f.FragOffset & 0x1fff
	if f.DontFragment {
		frag |= 0x4000
	}
	if f.MoreFragments {
		frag |= 0x2000
	}
	out = appendU16(out, frag)
	out = append(out, ttl, f.Proto)
	out = appendU16(out, 0) // checksum placeholder
	s4, d4 := src.As4(), dst.As4()
	out = append(out, s4[:]...)
	out = append(out, d4[:]...)
	binary.BigEndian.PutUint16(out[start+10:], checksum(out[start:]))
	return out
}

// appendIPv6 appends a 40-byte IPv6 header. payloadLen is len(l4).
func (f Frame) appendIPv6(out []byte, src, dst netip.Addr, ttl uint8, l4 []byte) []byte {
	out = append(out, 0x60, 0x00, 0x00, 0x00) // version 6, TC 0, flow label 0
	out = appendU16(out, uint16(len(l4)))
	out = append(out, f.Proto, ttl)
	s16, d16 := src.As16(), dst.As16()
	out = append(out, s16[:]...)
	out = append(out, d16[:]...)
	return out
}

// buildL4 builds the transport header plus payload with a correct checksum.
func (f Frame) buildL4(src, dst netip.Addr, isV6 bool) ([]byte, error) {
	switch f.Proto {
	case ProtoTCP:
		l4 := make([]byte, 20+len(f.Payload))
		binary.BigEndian.PutUint16(l4[0:], f.SrcPort)
		binary.BigEndian.PutUint16(l4[2:], f.DstPort)
		// seq/ack left zero.
		l4[12] = 0x50 // data offset 5 words, reserved 0
		l4[13] = f.TCPFlags
		binary.BigEndian.PutUint16(l4[14:], 0xffff) // window
		// checksum at [16:18] left zero for computation.
		copy(l4[20:], f.Payload)
		cs := l4Checksum(src, dst, ProtoTCP, l4)
		binary.BigEndian.PutUint16(l4[16:], cs)
		return l4, nil

	case ProtoUDP:
		l4 := make([]byte, 8+len(f.Payload))
		binary.BigEndian.PutUint16(l4[0:], f.SrcPort)
		binary.BigEndian.PutUint16(l4[2:], f.DstPort)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		// checksum at [6:8] left zero for computation.
		copy(l4[8:], f.Payload)
		cs := l4Checksum(src, dst, ProtoUDP, l4)
		if cs == 0 {
			cs = 0xffff // 0 is transmitted as all-ones (RFC 768)
		}
		binary.BigEndian.PutUint16(l4[6:], cs)
		return l4, nil

	case ProtoICMP, ProtoICMPv6:
		l4 := make([]byte, 4+len(f.Payload))
		l4[0] = f.ICMPType
		l4[1] = f.ICMPCode
		// checksum at [2:4] left zero for computation.
		copy(l4[4:], f.Payload)
		var cs uint16
		if f.Proto == ProtoICMPv6 {
			// ICMPv6 checksum covers the IPv6 pseudo-header (mandatory).
			cs = l4Checksum(src, dst, ProtoICMPv6, l4)
		} else {
			cs = checksum(l4)
		}
		binary.BigEndian.PutUint16(l4[2:], cs)
		return l4, nil

	default:
		return nil, fmt.Errorf("pktgen: unsupported protocol %d", f.Proto)
	}
}

// checksum computes the 16-bit one's-complement sum used by IPv4/ICMP/TCP/UDP.
// An odd-length input is padded with a trailing zero byte.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// l4Checksum computes a transport checksum over the IPv4/IPv6 pseudo-header
// followed by the L4 bytes (whose own checksum field must already be zero).
func l4Checksum(src, dst netip.Addr, proto uint8, l4 []byte) uint16 {
	var pseudo []byte
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		pseudo = make([]byte, 12)
		copy(pseudo[0:], s[:])
		copy(pseudo[4:], d[:])
		pseudo[9] = proto
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(l4)))
	} else {
		s, d := src.As16(), dst.As16()
		pseudo = make([]byte, 40)
		copy(pseudo[0:], s[:])
		copy(pseudo[16:], d[:])
		binary.BigEndian.PutUint32(pseudo[32:], uint32(len(l4)))
		pseudo[39] = proto
	}
	return checksum(append(pseudo, l4...))
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// Parse decodes a raw L2 frame (as produced by Build) back into a Frame,
// recovering every field Build serialises. It is the reader ReadPcap uses per
// record. It returns an error on a truncated or unrecognised frame.
func Parse(b []byte) (Frame, error) {
	var f Frame
	if len(b) < 14 {
		return f, fmt.Errorf("pktgen: frame too short (%d bytes)", len(b))
	}
	copy(f.DstMAC[:], b[0:6])
	copy(f.SrcMAC[:], b[6:12])
	off := 12
	et := binary.BigEndian.Uint16(b[off:])
	for et == tpid8021Q || et == tpid8021ad {
		if len(b) < off+4 {
			return f, fmt.Errorf("pktgen: truncated VLAN tag")
		}
		f.VLANs = append(f.VLANs, binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		et = binary.BigEndian.Uint16(b[off:])
	}
	off += 2

	switch et {
	case etherTypeIPv4:
		return parseIPv4(f, b[off:])
	case etherTypeIPv6:
		return parseIPv6(f, b[off:])
	default:
		return f, fmt.Errorf("pktgen: unsupported ethertype %#04x", et)
	}
}

func parseIPv4(f Frame, b []byte) (Frame, error) {
	if len(b) < 20 {
		return f, fmt.Errorf("pktgen: truncated IPv4 header")
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return f, fmt.Errorf("pktgen: bad IPv4 IHL %d", ihl)
	}
	f.TTL = b[8]
	f.Proto = b[9]
	f.IPID = binary.BigEndian.Uint16(b[4:])
	frag := binary.BigEndian.Uint16(b[6:])
	f.DontFragment = frag&0x4000 != 0
	f.MoreFragments = frag&0x2000 != 0
	f.FragOffset = frag & 0x1fff
	f.SrcIP = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	f.DstIP = netip.AddrFrom4([4]byte{b[16], b[17], b[18], b[19]})
	total := int(binary.BigEndian.Uint16(b[2:]))
	if total < ihl || total > len(b) {
		total = len(b)
	}
	payload := b[ihl:total]
	if f.FragOffset > 0 {
		f.Payload = clone(payload)
		return f, nil
	}
	return parseL4(f, payload, false)
}

func parseIPv6(f Frame, b []byte) (Frame, error) {
	if len(b) < 40 {
		return f, fmt.Errorf("pktgen: truncated IPv6 header")
	}
	f.Proto = b[6]
	f.TTL = b[7]
	var s, d [16]byte
	copy(s[:], b[8:24])
	copy(d[:], b[24:40])
	f.SrcIP = netip.AddrFrom16(s)
	f.DstIP = netip.AddrFrom16(d)
	plen := int(binary.BigEndian.Uint16(b[4:]))
	end := 40 + plen
	if plen == 0 || end > len(b) {
		end = len(b)
	}
	return parseL4(f, b[40:end], true)
}

func parseL4(f Frame, b []byte, isV6 bool) (Frame, error) {
	switch f.Proto {
	case ProtoTCP:
		if len(b) < 20 {
			return f, fmt.Errorf("pktgen: truncated TCP header")
		}
		f.SrcPort = binary.BigEndian.Uint16(b[0:])
		f.DstPort = binary.BigEndian.Uint16(b[2:])
		f.TCPFlags = b[13]
		dataOff := int(b[12]>>4) * 4
		if dataOff < 20 || dataOff > len(b) {
			dataOff = 20
		}
		f.Payload = clone(b[dataOff:])
	case ProtoUDP:
		if len(b) < 8 {
			return f, fmt.Errorf("pktgen: truncated UDP header")
		}
		f.SrcPort = binary.BigEndian.Uint16(b[0:])
		f.DstPort = binary.BigEndian.Uint16(b[2:])
		f.Payload = clone(b[8:])
	case ProtoICMP, ProtoICMPv6:
		if len(b) < 4 {
			return f, fmt.Errorf("pktgen: truncated ICMP header")
		}
		f.ICMPType = b[0]
		f.ICMPCode = b[1]
		f.Payload = clone(b[4:])
	default:
		return f, fmt.Errorf("pktgen: unsupported protocol %d", f.Proto)
	}
	return f, nil
}

// clone returns a copy so parsed frames never alias the input buffer; it
// returns nil for an empty slice so round-trips compare equal to an unset
// Payload.
func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

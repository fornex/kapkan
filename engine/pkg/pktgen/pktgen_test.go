package pktgen

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// mustBuild builds f or fails the test.
func mustBuild(t *testing.T, f Frame) []byte {
	t.Helper()
	b, err := f.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return b
}

// TestIPv4HeaderChecksumVector cross-checks the IPv4 header checksum against a
// well-known hand vector: the header
//
//	45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01 c0 a8 00 c7
//
// (192.168.0.1 -> 192.168.0.199, proto 17, DF, total length 115) has header
// checksum 0xB861. This is the canonical example from the Wikipedia "IPv4
// header checksum" worked calculation; the one's-complement sum of the ten
// 16-bit words (checksum field zeroed) is 0x479E, whose complement is 0xB861.
func TestIPv4HeaderChecksumVector(t *testing.T) {
	// total length 115 = 20 (IP) + 95 (UDP); UDP payload = 95 - 8 = 87 bytes.
	f := Frame{
		SrcIP:        netip.MustParseAddr("192.168.0.1"),
		DstIP:        netip.MustParseAddr("192.168.0.199"),
		Proto:        ProtoUDP,
		TTL:          64,
		DontFragment: true,
		SrcPort:      1, DstPort: 2,
		Payload: make([]byte, 87),
	}
	pkt := mustBuild(t, f)
	// IPv4 header starts after the 14-byte Ethernet header; checksum at +10.
	if got := binary.BigEndian.Uint16(pkt[14+2:]); got != 0x0073 {
		t.Fatalf("total length = %#04x, want 0x0073 (vector precondition)", got)
	}
	if got := binary.BigEndian.Uint16(pkt[14+10:]); got != 0xb861 {
		t.Errorf("IPv4 header checksum = %#04x, want 0xb861", got)
	}
	// Self-check: the sum over the header *including* the checksum is zero.
	if got := checksum(pkt[14:34]); got != 0 {
		t.Errorf("checksum over complete header = %#04x, want 0", got)
	}
}

// TestUDPChecksumVector cross-checks the transport checksum against a hand
// vector computed for a UDP datagram 10.0.0.1:8080 -> 10.0.0.2:53 carrying the
// 2-byte payload {0x48,0x69}. The one's-complement sum of the IPv4
// pseudo-header (0A000001 0A000002 0011 000A) and the UDP header+payload
// (1F90 0035 000A 0000 4869) is 0x7C56, whose complement is 0x83A9.
func TestUDPChecksumVector(t *testing.T) {
	f := Frame{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		Proto:   ProtoUDP,
		TTL:     64,
		SrcPort: 8080, DstPort: 53,
		Payload: []byte{0x48, 0x69},
	}
	pkt := mustBuild(t, f)
	// UDP header starts at 14 (Ethernet) + 20 (IPv4); checksum at +6.
	if got := binary.BigEndian.Uint16(pkt[34+6:]); got != 0x83a9 {
		t.Errorf("UDP checksum = %#04x, want 0x83a9", got)
	}
}

// TestL4ChecksumSelfConsistent verifies that recomputing a transport checksum
// over the segment (checksum field left in place) yields 0 — the standard
// receiver-side validity test — for every protocol and both address families.
func TestL4ChecksumSelfConsistent(t *testing.T) {
	cases := []struct {
		name        string
		f           Frame
		l4Off       int
		pseudoProto uint8 // 0 => plain checksum (ICMPv4), else pseudo-header
	}{
		{"v4 tcp", Frame{SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"), Proto: ProtoTCP, TCPFlags: TCPSyn, SrcPort: 1234, DstPort: 80, Payload: []byte("abc")}, 34, ProtoTCP},
		{"v4 udp", Frame{SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"), Proto: ProtoUDP, SrcPort: 5, DstPort: 6, Payload: []byte("hello!")}, 34, ProtoUDP},
		{"v4 icmp", Frame{SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"), Proto: ProtoICMP, ICMPType: 8, Payload: []byte("ping")}, 34, 0},
		{"v6 udp", Frame{SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"), Proto: ProtoUDP, SrcPort: 7, DstPort: 8, Payload: []byte("world!!")}, 54, ProtoUDP},
		{"v6 icmp6", Frame{SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"), Proto: ProtoICMPv6, ICMPType: 128, Payload: []byte("pong")}, 54, ProtoICMPv6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := mustBuild(t, tc.f)
			l4 := pkt[tc.l4Off:]
			var got uint16
			if tc.pseudoProto == 0 {
				got = checksum(l4)
			} else {
				got = l4Checksum(tc.f.SrcIP, tc.f.DstIP, tc.pseudoProto, l4)
			}
			if got != 0 {
				t.Errorf("recomputed checksum = %#04x, want 0", got)
			}
		})
	}
}

// equalFrame reports whether two frames match on every round-trippable field.
func equalFrame(a, b Frame) bool {
	if a.SrcMAC != b.SrcMAC || a.DstMAC != b.DstMAC {
		return false
	}
	if len(a.VLANs) != len(b.VLANs) {
		return false
	}
	for i := range a.VLANs {
		if a.VLANs[i] != b.VLANs[i] {
			return false
		}
	}
	if a.SrcIP != b.SrcIP || a.DstIP != b.DstIP {
		return false
	}
	if a.Proto != b.Proto || a.SrcPort != b.SrcPort || a.DstPort != b.DstPort {
		return false
	}
	if a.TCPFlags != b.TCPFlags || a.ICMPType != b.ICMPType || a.ICMPCode != b.ICMPCode {
		return false
	}
	if a.TTL != b.TTL || a.IPID != b.IPID {
		return false
	}
	if a.DontFragment != b.DontFragment || a.MoreFragments != b.MoreFragments || a.FragOffset != b.FragOffset {
		return false
	}
	if !bytes.Equal(a.IPv4Options, b.IPv4Options) {
		return false
	}
	return bytes.Equal(a.Payload, b.Payload)
}

// TestBuildParseRoundTrip checks that Build then Parse recovers the frame for
// v4/v6, TCP/UDP/ICMP, VLAN-tagged and fragmented frames.
func TestBuildParseRoundTrip(t *testing.T) {
	frames := map[string]Frame{
		"v4 tcp": {
			DstMAC: [6]byte{1, 2, 3, 4, 5, 6}, SrcMAC: [6]byte{7, 8, 9, 10, 11, 12},
			SrcIP: netip.MustParseAddr("198.51.100.7"), DstIP: netip.MustParseAddr("203.0.113.9"),
			Proto: ProtoTCP, TCPFlags: TCPSyn | TCPAck, SrcPort: 44321, DstPort: 443, TTL: 64,
			Payload: []byte("GET / HTTP/1.0\r\n"),
		},
		"v4 tcp single vlan": {
			VLANs: []uint16{0x0064}, // VID 100
			SrcIP: netip.MustParseAddr("198.51.100.1"), DstIP: netip.MustParseAddr("203.0.113.1"),
			Proto: ProtoTCP, TCPFlags: TCPAck, SrcPort: 1000, DstPort: 80, TTL: 32,
		},
		"v4 udp qinq": {
			VLANs: []uint16{0x2064, 0x000a}, // stacked tags
			SrcIP: netip.MustParseAddr("192.0.2.5"), DstIP: netip.MustParseAddr("203.0.113.2"),
			Proto: ProtoUDP, SrcPort: 53, DstPort: 33333, TTL: 64, Payload: bytes.Repeat([]byte{0xAB}, 40),
		},
		"v6 udp": {
			SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"),
			Proto: ProtoUDP, SrcPort: 123, DstPort: 40000, TTL: 64, Payload: bytes.Repeat([]byte{0xCD}, 100),
		},
		"v4 icmp": {
			SrcIP: netip.MustParseAddr("198.51.100.9"), DstIP: netip.MustParseAddr("203.0.113.3"),
			Proto: ProtoICMP, ICMPType: 8, ICMPCode: 0, TTL: 64, Payload: bytes.Repeat([]byte{0x11}, 56),
		},
		"v6 icmp6": {
			SrcIP: netip.MustParseAddr("2001:db8::9"), DstIP: netip.MustParseAddr("2001:db8::a"),
			Proto: ProtoICMPv6, ICMPType: 128, ICMPCode: 0, TTL: 64, Payload: bytes.Repeat([]byte{0x22}, 8),
		},
		"v4 first fragment": {
			SrcIP: netip.MustParseAddr("198.51.100.2"), DstIP: netip.MustParseAddr("203.0.113.4"),
			Proto: ProtoUDP, SrcPort: 6000, DstPort: 53413, TTL: 64,
			IPID: 0x4321, MoreFragments: true, Payload: bytes.Repeat([]byte{0x33}, 1480),
		},
		"v4 continuation fragment": {
			SrcIP: netip.MustParseAddr("198.51.100.2"), DstIP: netip.MustParseAddr("203.0.113.4"),
			Proto: ProtoUDP, TTL: 64, IPID: 0x4321, FragOffset: 185, Payload: bytes.Repeat([]byte{0x44}, 800),
		},
		"v4 tcp with options": {
			SrcIP: netip.MustParseAddr("198.51.100.3"), DstIP: netip.MustParseAddr("203.0.113.5"),
			Proto: ProtoTCP, TCPFlags: TCPSyn, SrcPort: 1234, DstPort: 80, TTL: 64,
			// NOP, NOP, NOP, End of Option List: the shortest legal 4-byte
			// option block, so IHL becomes 6 and L4 starts at 38, not 34.
			IPv4Options: []byte{0x01, 0x01, 0x01, 0x00},
			Payload:     []byte("x"),
		},
		"v4 udp with maximum options": {
			SrcIP: netip.MustParseAddr("198.51.100.4"), DstIP: netip.MustParseAddr("203.0.113.6"),
			Proto: ProtoUDP, SrcPort: 53, DstPort: 33333, TTL: 64,
			IPv4Options: bytes.Repeat([]byte{0x01}, 40), // IHL 15, the ceiling
		},
	}
	for name, f := range frames {
		t.Run(name, func(t *testing.T) {
			pkt := mustBuild(t, f)
			got, err := Parse(pkt)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !equalFrame(f, got) {
				t.Errorf("round trip mismatch\n have %+v\n want %+v", got, f)
			}
		})
	}
}

// TestIPv4OptionsHeader checks the three things an option block has to get
// right: IHL counts the longer header, the header checksum covers the options,
// and the transport checksum (whose pseudo-header does NOT include them) stays
// valid. A frame that fails any of these would silently mis-drive a parser
// under test instead of exercising its option-skipping path.
func TestIPv4OptionsHeader(t *testing.T) {
	for _, n := range []int{4, 12, 40} {
		t.Run(itoa(n), func(t *testing.T) {
			f := Frame{
				SrcIP: netip.MustParseAddr("198.51.100.7"), DstIP: netip.MustParseAddr("203.0.113.9"),
				Proto: ProtoTCP, TCPFlags: TCPSyn, SrcPort: 1024, DstPort: 80, TTL: 64,
				IPv4Options: bytes.Repeat([]byte{0x01}, n),
			}
			pkt := mustBuild(t, f)
			ip := pkt[14:]
			if got, want := int(ip[0]&0x0f), (20+n)/4; got != want {
				t.Errorf("IHL = %d, want %d", got, want)
			}
			if got, want := int(binary.BigEndian.Uint16(ip[2:])), 20+n+20; got != want {
				t.Errorf("total length = %d, want %d", got, want)
			}
			if got := checksum(ip[:20+n]); got != 0 {
				t.Errorf("header checksum over the header+options = %#04x, want 0", got)
			}
			if got := l4Checksum(f.SrcIP, f.DstIP, ProtoTCP, pkt[14+20+n:]); got != 0 {
				t.Errorf("TCP checksum = %#04x, want 0 (options are not in the pseudo-header)", got)
			}
		})
	}
}

// TestIPv6ExtensionHeaders pins the three things an extension chain can get
// wrong and that nothing else in this package would catch: the next-header
// chaining, the hdr_ext_len encoding (8-octet units, not counting the first
// 8), and the fact that the chain counts toward the IPv6 payload length but
// NOT toward the L4 checksum's pseudo-header — which measures the upper-layer
// payload only, so an implementation that folded the chain in would produce a
// checksum every receiver rejects.
func TestIPv6ExtensionHeaders(t *testing.T) {
	src := netip.MustParseAddr("2001:db8:beef::7")
	dst := netip.MustParseAddr("2001:db8::99")
	f := Frame{
		SrcIP: src, DstIP: dst, TTL: 64,
		Proto: ProtoUDP, SrcPort: 53, DstPort: 40000,
		ExtHdrs: []ExtHdr{
			{Type: ExtHopByHop, Data: bytes.Repeat([]byte{0x01}, 6)}, // 8 bytes total
			{Type: ExtDstOpts, Data: bytes.Repeat([]byte{0x01}, 14)}, // 16 bytes total
			{Type: ExtRouting, Data: bytes.Repeat([]byte{0x00}, 22)}, // 24 bytes total
		},
		Payload: make([]byte, 100),
	}
	pkt := mustBuild(t, f)
	ip := pkt[14:]

	if got := ip[6]; got != ExtHopByHop {
		t.Errorf("IPv6 next-header = %d, want %d (the first extension header)", got, ExtHopByHop)
	}
	const chainLen = 8 + 16 + 24
	if got, want := int(binary.BigEndian.Uint16(ip[4:])), chainLen+8+100; got != want {
		t.Errorf("IPv6 payload length = %d, want %d (chain + UDP header + payload)", got, want)
	}
	// Walk the chain by hand: types in order, then UDP.
	off := 40
	for i, want := range []uint8{ExtDstOpts, ExtRouting, ProtoUDP} {
		n := (int(ip[off+1]) + 1) * 8
		if got := ip[off]; got != want {
			t.Fatalf("extension header %d chains to %d, want %d", i, got, want)
		}
		off += n
	}
	if off != 40+chainLen {
		t.Fatalf("chain ended at offset %d, want %d", off, 40+chainLen)
	}
	if got := l4Checksum(src, dst, ProtoUDP, ip[off:]); got != 0 {
		t.Errorf("UDP checksum over the pseudo-header = %#04x, want 0 — the extension "+
			"chain must not be part of the upper-layer length", got)
	}

	// And the whole thing survives a round trip.
	got, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.ExtHdrs) != len(f.ExtHdrs) {
		t.Fatalf("parsed %d extension headers, want %d", len(got.ExtHdrs), len(f.ExtHdrs))
	}
	for i := range f.ExtHdrs {
		if got.ExtHdrs[i].Type != f.ExtHdrs[i].Type ||
			!bytes.Equal(got.ExtHdrs[i].Data, f.ExtHdrs[i].Data) {
			t.Errorf("extension header %d = %+v, want %+v", i, got.ExtHdrs[i], f.ExtHdrs[i])
		}
	}
	if got.Proto != ProtoUDP || got.SrcPort != 53 || got.DstPort != 40000 {
		t.Errorf("L4 after the chain = proto %d %d->%d, want udp 53->40000",
			got.Proto, got.SrcPort, got.DstPort)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestPcapRoundTrip verifies a generated set survives WritePcap/ReadPcap
// losslessly and that WritePcap is byte-stable for identical input.
func TestPcapRoundTrip(t *testing.T) {
	frames := Generate(MixedVector, GenConfig{
		Victim:  netip.MustParseAddr("203.0.113.50"),
		Sources: []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.11")},
		Count:   12,
	})

	var buf1, buf2 bytes.Buffer
	if err := WritePcap(&buf1, frames); err != nil {
		t.Fatalf("WritePcap() error = %v", err)
	}
	if err := WritePcap(&buf2, frames); err != nil {
		t.Fatalf("WritePcap() (second) error = %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("WritePcap is not byte-stable across identical input")
	}
	if buf1.Len() <= globalHdrLen {
		t.Fatalf("pcap unexpectedly small: %d bytes", buf1.Len())
	}

	got, err := ReadPcap(bytes.NewReader(buf1.Bytes()))
	if err != nil {
		t.Fatalf("ReadPcap() error = %v", err)
	}
	if len(got) != len(frames) {
		t.Fatalf("read %d frames, want %d", len(got), len(frames))
	}
	for i := range frames {
		if !equalFrame(frames[i], got[i]) {
			t.Errorf("frame %d round-trip mismatch\n have %+v\n want %+v", i, got[i], frames[i])
		}
	}
}

// TestGeneratePatterns builds every pattern for both address families and
// confirms each frame is well-formed, parses cleanly and carries the
// vector-defining protocol/ports.
func TestGeneratePatterns(t *testing.T) {
	all := []Pattern{
		UDPFlood, SYNFlood, ACKFlood, DNSAmplification, NTPMonlist, CLDAPAmplification,
		MemcachedAmplification, SSDPAmplification, ChargenAmplification, ICMPFlood,
		FragmentFlood, MixedVector,
	}
	victims := map[string]netip.Addr{
		"v4": netip.MustParseAddr("203.0.113.50"),
		"v6": netip.MustParseAddr("2001:db8:1::50"),
	}
	for fam, victim := range victims {
		for _, p := range all {
			t.Run(fam+"/"+patternName(p), func(t *testing.T) {
				frames := Generate(p, GenConfig{Victim: victim, Count: 8})
				if len(frames) != 8 {
					t.Fatalf("generated %d frames, want 8", len(frames))
				}
				for i, f := range frames {
					pkt, err := f.Build()
					if err != nil {
						t.Fatalf("frame %d Build() error = %v", i, err)
					}
					back, err := Parse(pkt)
					if err != nil {
						t.Fatalf("frame %d Parse() error = %v", i, err)
					}
					if back.DstIP != victim {
						t.Errorf("frame %d dst = %v, want victim %v", i, back.DstIP, victim)
					}
					// Reflection patterns must carry the abused service source port.
					if port := p.reflectorPort(); port != 0 && back.SrcPort != port {
						t.Errorf("frame %d src port = %d, want reflector %d", i, back.SrcPort, port)
					}
				}
			})
		}
	}
}

// TestReflectionSourcePorts pins the characteristic reflector ports.
func TestReflectionSourcePorts(t *testing.T) {
	want := map[Pattern]uint16{
		DNSAmplification: 53, NTPMonlist: 123, CLDAPAmplification: 389,
		MemcachedAmplification: 11211, SSDPAmplification: 1900, ChargenAmplification: 19,
	}
	for p, port := range want {
		if got := p.reflectorPort(); got != port {
			t.Errorf("%s reflector port = %d, want %d", patternName(p), got, port)
		}
	}
}

// TestGenerateSizeControl checks that GenConfig.Size sets the on-wire length.
func TestGenerateSizeControl(t *testing.T) {
	frames := Generate(UDPFlood, GenConfig{
		Victim: netip.MustParseAddr("203.0.113.50"), Count: 3, Size: 200,
	})
	for i, f := range frames {
		pkt := mustBuild(t, f)
		if len(pkt) != 200 {
			t.Errorf("frame %d on-wire size = %d, want 200", i, len(pkt))
		}
	}
}

// TestBuildErrors checks the rejected cases.
func TestBuildErrors(t *testing.T) {
	cases := map[string]Frame{
		"family mismatch": {SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("2001:db8::1"), Proto: ProtoUDP},
		"invalid addr":    {Proto: ProtoUDP},
		"bad proto":       {SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"), Proto: 99},
		"v6 fragment":     {SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"), Proto: ProtoUDP, MoreFragments: true},
		"unaligned options": {
			SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"),
			Proto: ProtoUDP, IPv4Options: []byte{0x01, 0x01, 0x00},
		},
		"oversized options": {
			SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"),
			Proto: ProtoUDP, IPv4Options: bytes.Repeat([]byte{0x01}, 44),
		},
		"options on v6": {
			SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"),
			Proto: ProtoUDP, IPv4Options: []byte{0x01, 0x01, 0x01, 0x00},
		},
		"ext headers on v4": {
			SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("192.0.2.2"),
			Proto: ProtoUDP, ExtHdrs: []ExtHdr{{Type: ExtDstOpts, Data: make([]byte, 6)}},
		},
		"ext header misaligned": {
			SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"),
			Proto: ProtoUDP, ExtHdrs: []ExtHdr{{Type: ExtDstOpts, Data: make([]byte, 8)}},
		},
		"ext header too short": {
			SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"),
			Proto: ProtoUDP, ExtHdrs: []ExtHdr{{Type: ExtDstOpts, Data: nil}},
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.Build(); err == nil {
				t.Errorf("Build() error = nil, want an error")
			}
		})
	}
}

func patternName(p Pattern) string {
	switch p {
	case UDPFlood:
		return "UDPFlood"
	case SYNFlood:
		return "SYNFlood"
	case ACKFlood:
		return "ACKFlood"
	case DNSAmplification:
		return "DNSAmplification"
	case NTPMonlist:
		return "NTPMonlist"
	case CLDAPAmplification:
		return "CLDAPAmplification"
	case MemcachedAmplification:
		return "MemcachedAmplification"
	case SSDPAmplification:
		return "SSDPAmplification"
	case ChargenAmplification:
		return "ChargenAmplification"
	case ICMPFlood:
		return "ICMPFlood"
	case FragmentFlood:
		return "FragmentFlood"
	case MixedVector:
		return "MixedVector"
	default:
		return "unknown"
	}
}

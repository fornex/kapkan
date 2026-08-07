package pktgen

import "net/netip"

// Pattern enumerates the synthetic attack shapes the generator produces. Each
// sets characteristic ports, protocol and packet sizing so the block-rate
// suite can gate mitigation of a specific vector.
type Pattern int

// Supported attack patterns.
const (
	// UDPFlood is a generic high-pps UDP flood to a victim service port.
	UDPFlood Pattern = iota
	// SYNFlood is a TCP SYN flood (SYN set, no payload).
	SYNFlood
	// ACKFlood is a TCP ACK flood (ACK set, no payload).
	ACKFlood
	// DNSAmplification reflects off UDP source port 53 with large payloads.
	DNSAmplification
	// NTPMonlist reflects off UDP source port 123 (the monlist request).
	NTPMonlist
	// CLDAPAmplification reflects off UDP source port 389.
	CLDAPAmplification
	// MemcachedAmplification reflects off UDP source port 11211.
	MemcachedAmplification
	// SSDPAmplification reflects off UDP source port 1900.
	SSDPAmplification
	// ChargenAmplification reflects off UDP source port 19.
	ChargenAmplification
	// ICMPFlood is an ICMP/ICMPv6 echo-request flood.
	ICMPFlood
	// FragmentFlood is an IPv4 fragment flood: alternating first fragments
	// (MoreFragments set) and non-first fragments (FragOffset > 0).
	FragmentFlood
	// MixedVector interleaves several vectors at once (SYN, UDP, ICMP, DNS).
	MixedVector
)

// GenConfig parameterises a generated attack toward a single victim.
type GenConfig struct {
	// Victim is the destination (the protected host under attack). Its address
	// family selects IPv4 vs IPv6 for every generated frame; Sources are mapped
	// to that family.
	Victim netip.Addr
	// Sources is the set of attacker/reflector addresses, cycled across the
	// generated frames. When empty a default /24 base is used and incremented.
	Sources []netip.Addr
	// Count is the number of frames to generate (defaults to 1).
	Count int
	// Size is the target on-wire L2 frame length in bytes; the payload is sized
	// to hit it. When 0 a pattern-appropriate default is used.
	Size int
	// VictimMAC and RouterMAC are the L2 addresses (destination and source);
	// zero values fall back to fixed lab defaults.
	VictimMAC, RouterMAC [6]byte
}

// reflectorPort returns the characteristic UDP source port a reflection
// pattern abuses, or 0 if the pattern is not a reflection attack.
func (p Pattern) reflectorPort() uint16 {
	switch p {
	case DNSAmplification:
		return 53
	case NTPMonlist:
		return 123
	case CLDAPAmplification:
		return 389
	case MemcachedAmplification:
		return 11211
	case SSDPAmplification:
		return 1900
	case ChargenAmplification:
		return 19
	default:
		return 0
	}
}

var (
	defaultVictimMAC = [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	defaultRouterMAC = [6]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
)

// Generate builds the frames for pattern p under cfg. Every returned frame is
// well-formed and parses back cleanly with Parse. MixedVector rotates through
// SYN flood, UDP flood, ICMP flood and DNS amplification, one vector per frame.
func Generate(p Pattern, cfg GenConfig) []Frame {
	count := cfg.Count
	if count <= 0 {
		count = 1
	}
	victim := cfg.Victim.Unmap()
	if !victim.IsValid() {
		victim = netip.MustParseAddr("203.0.113.1")
	}
	dstMAC := cfg.VictimMAC
	if dstMAC == ([6]byte{}) {
		dstMAC = defaultVictimMAC
	}
	srcMAC := cfg.RouterMAC
	if srcMAC == ([6]byte{}) {
		srcMAC = defaultRouterMAC
	}

	frames := make([]Frame, count)
	for i := 0; i < count; i++ {
		sub := p
		if p == MixedVector {
			sub = mixedRotation[i%len(mixedRotation)]
		}
		f := frameFor(sub, victim, sourceAddr(cfg.Sources, victim, i), cfg.Size, i)
		f.DstMAC = dstMAC
		f.SrcMAC = srcMAC
		frames[i] = f
	}
	return frames
}

var mixedRotation = []Pattern{SYNFlood, UDPFlood, ICMPFlood, DNSAmplification}

// frameFor fills the L3/L4 fields for a single frame of pattern p.
func frameFor(p Pattern, victim, src netip.Addr, size, i int) Frame {
	isV6 := victim.Is6()
	f := Frame{SrcIP: src, DstIP: victim, TTL: 64}

	if port := p.reflectorPort(); port != 0 {
		f.Proto = ProtoUDP
		f.SrcPort = port
		f.DstPort = 40000
		f.Payload = payloadForSize(size, defaultSize(p), overheadUDP(isV6, 0))
		return f
	}

	switch p {
	case SYNFlood:
		f.Proto = ProtoTCP
		f.TCPFlags = TCPSyn
		f.SrcPort = ephemeralPort(i)
		f.DstPort = 80
		// SYN/ACK floods carry no L4 payload by default (the 60-byte wire
		// minimum is NIC padding); an explicit Size overrides.
		f.Payload = payloadForSize(size, overheadTCP(isV6, 0), overheadTCP(isV6, 0))
	case ACKFlood:
		f.Proto = ProtoTCP
		f.TCPFlags = TCPAck
		f.SrcPort = ephemeralPort(i)
		f.DstPort = 80
		f.Payload = payloadForSize(size, overheadTCP(isV6, 0), overheadTCP(isV6, 0))
	case ICMPFlood:
		if isV6 {
			f.Proto = ProtoICMPv6
			f.ICMPType = 128 // ICMPv6 echo request
		} else {
			f.Proto = ProtoICMP
			f.ICMPType = 8 // ICMPv4 echo request
		}
		f.Payload = payloadForSize(size, defaultSize(ICMPFlood), overheadICMP(isV6, 0))
	case FragmentFlood:
		// Fragment floods are an IPv4 shape; on an IPv6 victim fall back to a
		// plain UDP flood so the generator never emits an invalid frame.
		if isV6 {
			f.Proto = ProtoUDP
			f.SrcPort = ephemeralPort(i)
			f.DstPort = 53413
			f.Payload = payloadForSize(size, defaultSize(UDPFlood), overheadUDP(true, 0))
			return f
		}
		f.Proto = ProtoUDP
		f.IPID = uint16(0x4000 + i)
		if i%2 == 0 {
			// First fragment: UDP header present, more fragments to follow.
			f.MoreFragments = true
			f.SrcPort = ephemeralPort(i)
			f.DstPort = 53413
			f.Payload = payloadForSize(size, defaultSize(FragmentFlood), overheadUDP(false, 0))
		} else {
			// Non-first fragment: raw continuation, no L4 header.
			f.FragOffset = 185 // 1480 bytes / 8
			f.Payload = payloadForSize(size, defaultSize(FragmentFlood), 14+20)
		}
	default: // UDPFlood
		f.Proto = ProtoUDP
		f.SrcPort = ephemeralPort(i)
		f.DstPort = 53413
		f.Payload = payloadForSize(size, defaultSize(UDPFlood), overheadUDP(isV6, 0))
	}
	return f
}

// sourceAddr picks the i-th source address, cycling cfg.Sources or, when empty,
// incrementing a default base in the victim's address family.
func sourceAddr(sources []netip.Addr, victim netip.Addr, i int) netip.Addr {
	if len(sources) > 0 {
		s := sources[i%len(sources)].Unmap()
		// Keep the family consistent with the victim.
		if s.Is4() == victim.Is4() {
			return s
		}
	}
	base := netip.MustParseAddr("198.51.100.0")
	if victim.Is6() {
		base = netip.MustParseAddr("2001:db8:beef::")
	}
	return nextAddr(base, i)
}

// nextAddr returns base offset by n within its address family.
func nextAddr(base netip.Addr, n int) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += uint32(n)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b := base.As16()
	lo := uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	lo += uint32(n)
	b[12], b[13], b[14], b[15] = byte(lo>>24), byte(lo>>16), byte(lo>>8), byte(lo)
	return netip.AddrFrom16(b)
}

// ephemeralPort spreads flood source ports across the ephemeral range.
func ephemeralPort(i int) uint16 { return uint16(1024 + (i % 60000)) }

// defaultSize is the target on-wire frame size for a pattern when the caller
// leaves GenConfig.Size at zero.
func defaultSize(p Pattern) int {
	switch p {
	case ICMPFlood:
		return 98 // classic ping
	case DNSAmplification, NTPMonlist, CLDAPAmplification,
		MemcachedAmplification, SSDPAmplification, ChargenAmplification:
		return 1400 // large reflected response
	case FragmentFlood:
		return 1400
	default: // UDPFlood
		return 512
	}
}

// overhead* return the L2+L3+L4 byte count (no VLAN tags) so payloadForSize can
// hit a target on-wire size.
func overheadUDP(isV6 bool, vlans int) int  { return ethIPOverhead(isV6, vlans) + 8 }
func overheadTCP(isV6 bool, vlans int) int  { return ethIPOverhead(isV6, vlans) + 20 }
func overheadICMP(isV6 bool, vlans int) int { return ethIPOverhead(isV6, vlans) + 4 }

func ethIPOverhead(isV6 bool, vlans int) int {
	ip := 20
	if isV6 {
		ip = 40
	}
	return 14 + 4*vlans + ip
}

// payloadForSize returns a payload sized so the total frame reaches target
// bytes given the header overhead; it falls back to def when target is unset,
// and never returns a negative length.
func payloadForSize(target, def, overhead int) []byte {
	if target <= 0 {
		target = def
	}
	n := target - overhead
	if n <= 0 {
		return nil
	}
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildFPRecord serialises an FPEvent by the same offsets DecodeFPEvent reads,
// so the round-trip actually exercises the layout rather than a shared struct.
func buildFPRecord(src, dst [16]byte, sport, dport uint16, isV6, proto, axis byte, pktLen, snapLen uint32, payloadOff uint16, data []byte) []byte {
	raw := make([]byte, FPEventSize)
	copy(raw[0:16], src[:])
	copy(raw[16:32], dst[:])
	binary.LittleEndian.PutUint16(raw[32:34], sport)
	binary.LittleEndian.PutUint16(raw[34:36], dport)
	raw[36] = isV6
	raw[37] = proto
	raw[38] = axis
	binary.LittleEndian.PutUint32(raw[40:44], pktLen)
	binary.LittleEndian.PutUint32(raw[44:48], snapLen)
	binary.LittleEndian.PutUint16(raw[48:50], payloadOff)
	copy(raw[52:], data)
	return raw
}

func TestDecodeFPEvent(t *testing.T) {
	var src, dst [16]byte
	copy(src[:4], []byte{198, 51, 100, 7})
	copy(dst[:4], []byte{203, 0, 113, 9})
	data := []byte{0x16, 0x03, 0x01, 0xAA, 0xBB, 0x01} // a TLS record head + a byte

	raw := buildFPRecord(src, dst, 51000, 443, 0, 6, MatchTLSClientHello, 260, uint32(len(data)), 0, data)
	ev, ok := DecodeFPEvent(raw)
	if !ok {
		t.Fatal("DecodeFPEvent ok = false on a full record")
	}
	if ev.Sport != 51000 || ev.Dport != 443 {
		t.Errorf("ports = %d->%d, want 51000->443", ev.Sport, ev.Dport)
	}
	if ev.Proto != 6 || ev.IsV6 != 0 || ev.Axis != MatchTLSClientHello {
		t.Errorf("proto/is_v6/axis = %d/%d/%d", ev.Proto, ev.IsV6, ev.Axis)
	}
	if ev.PktLen != 260 || ev.SnapLen != uint32(len(data)) || ev.PayloadOff != 0 {
		t.Errorf("pkt_len/snap_len/payload_off = %d/%d/%d", ev.PktLen, ev.SnapLen, ev.PayloadOff)
	}
	if ev.SourceAddr() != netip.MustParseAddr("198.51.100.7") {
		t.Errorf("source = %s, want 198.51.100.7", ev.SourceAddr())
	}
	if ev.VictimAddr() != netip.MustParseAddr("203.0.113.9") {
		t.Errorf("victim = %s, want 203.0.113.9", ev.VictimAddr())
	}
	if p := ev.Payload(); string(p) != string(data) {
		t.Errorf("payload = % x, want % x", p, data)
	}
}

func TestDecodeFPEventShort(t *testing.T) {
	if _, ok := DecodeFPEvent(make([]byte, FPEventSize-1)); ok {
		t.Error("DecodeFPEvent ok = true on a short record")
	}
	if _, ok := DecodeFPEvent(nil); ok {
		t.Error("DecodeFPEvent ok = true on nil")
	}
}

func TestFPEventPayloadFailOpen(t *testing.T) {
	var z [16]byte
	// payload_off past snap_len → no payload (fail open), not a slice panic.
	raw := buildFPRecord(z, z, 0, 0, 0, 6, MatchTLSClientHello, 100, 40, 100, nil)
	ev, _ := DecodeFPEvent(raw)
	if p := ev.Payload(); p != nil {
		t.Errorf("payload = % x, want nil when payload_off >= snap_len", p)
	}
	// snap_len larger than the buffer is clamped to the captured data, no panic.
	raw2 := buildFPRecord(z, z, 0, 0, 0, 6, MatchTLSClientHello, 100, FPSnapLen+999, 0, []byte{1, 2, 3})
	ev2, _ := DecodeFPEvent(raw2)
	if got := len(ev2.Payload()); got != FPSnapLen {
		t.Errorf("clamped payload len = %d, want %d", got, FPSnapLen)
	}
}

func TestFPEventIPv6Addr(t *testing.T) {
	var src, dst [16]byte
	copy(src[:], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(dst[:], netip.MustParseAddr("2001:db8::2").AsSlice())
	raw := buildFPRecord(src, dst, 1, 2, 1 /*is_v6*/, 6, MatchTLSClientHello, 0, 0, 0, nil)
	ev, _ := DecodeFPEvent(raw)
	if ev.SourceAddr() != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("v6 source = %s", ev.SourceAddr())
	}
	if ev.VictimAddr() != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("v6 victim = %s", ev.VictimAddr())
	}
}

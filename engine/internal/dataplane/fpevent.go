package dataplane

// Decoding one fingerprint-plane ring record. This lives with the type (F6 /
// bindings.go) rather than in the reader so the wire layout of struct
// kapkan_fp_event has exactly one authority. It is untagged — pure byte decode,
// no bpf(2) — so the reader's classification logic stays testable on any host.

import (
	"encoding/binary"
	"net/netip"
)

// FPEventSize is the wire size of struct kapkan_fp_event: a 52-byte header
// (two 16-byte addresses, ports, flags, two lengths, padding) plus the snapshot.
// Spelled as one expression so DecodeFPEvent's offsets are checked against it and
// a layout change trips the drift gate.
const FPEventSize = 52 + FPSnapLen

// DecodeFPEvent decodes one ring-buffer record into an FPEvent. ok is false when
// the record is shorter than a whole event — a malformed/partial sample the
// reader drops. The datapath and the reader share a little-endian host (amd64/
// arm64), which is also the byte order of the host-order port fields.
func DecodeFPEvent(raw []byte) (ev FPEvent, ok bool) {
	if len(raw) < FPEventSize {
		return FPEvent{}, false
	}
	copy(ev.Src[:], raw[0:16])
	copy(ev.Dst[:], raw[16:32])
	ev.Sport = binary.LittleEndian.Uint16(raw[32:34])
	ev.Dport = binary.LittleEndian.Uint16(raw[34:36])
	ev.IsV6 = raw[36]
	ev.Proto = raw[37]
	ev.Axis = raw[38]
	ev.PktLen = binary.LittleEndian.Uint32(raw[40:44])
	ev.SnapLen = binary.LittleEndian.Uint32(raw[44:48])
	ev.PayloadOff = binary.LittleEndian.Uint16(raw[48:50])
	copy(ev.Data[:], raw[52:FPEventSize])
	return ev, true
}

// Payload returns the captured L4 payload — Data[PayloadOff:SnapLen], the bytes
// the userspace classifier parses. It returns nil (fail open) when the offsets
// are inconsistent or the payload was entirely truncated away, so a caller can
// treat "no payload" and "unclassifiable" alike.
func (e *FPEvent) Payload() []byte {
	end := int(e.SnapLen)
	if end > len(e.Data) {
		end = len(e.Data)
	}
	off := int(e.PayloadOff)
	if off < 0 || off >= end {
		return nil
	}
	return e.Data[off:end]
}

// SourceAddr and VictimAddr render the packet's source and destination as
// netip.Addr from the event's network-order bytes. An IPv4 event left-aligns the
// address in the first four bytes; an IPv6 event uses all sixteen.
func (e *FPEvent) SourceAddr() netip.Addr { return fpAddr(e.Src, e.IsV6) }
func (e *FPEvent) VictimAddr() netip.Addr { return fpAddr(e.Dst, e.IsV6) }

func fpAddr(b [16]byte, isV6 uint8) netip.Addr {
	if isV6 != 0 {
		return netip.AddrFrom16(b)
	}
	var v4 [4]byte
	copy(v4[:], b[:4])
	return netip.AddrFrom4(v4)
}

//go:build linux

package dataplane

// Kernel-side tests for the fingerprint plane (E2). They load the committed
// object, enable the copy path in kapkan_cfg, drive TLS ClientHello and QUIC
// Initial frames through BPF_PROG_TEST_RUN, and read the resulting copies off
// the kapkan_fp_events ring. The charter claims these prove:
//
//   - a recognised ClientHello/Initial is copied to userspace with the right
//     metadata and payload prefix, and NOTHING else is;
//   - the copy never changes the verdict (every packet here still PASSes);
//   - the in-kernel sampler caps copy volume under flood — the property that
//     stops the plane from becoming its own DoS.
//
// See smoke_linux_test.go for the load harness and the run recipe.

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// fpEventBytes is the on-wire size of struct kapkan_fp_event: a 52-byte header
// (two 16-byte addresses, ports, flags, two lengths, padding) plus the snapshot.
// Spelled out rather than derived so decodeFP's offsets are checked against one
// number, and a layout change trips it.
const fpEventBytes = 52 + FPSnapLen

// setFPCfg writes kapkan_cfg[0] with the fingerprint plane configured. It goes
// through the production PutConfig so the strides, schema version and the
// sampler reciprocal are exactly what the manager would write.
func setFPCfg(t *testing.T, objs *kapkanXDPObjects, enabled bool, samplePPS, burst uint64) {
	t.Helper()
	if err := PutConfig(objs.MapSet(), ConfigSpec{
		FPEnabled:   enabled,
		FPSamplePPS: samplePPS,
		FPBurst:     burst,
	}); err != nil {
		t.Fatalf("write kapkan_cfg[0]: %v", err)
	}
}

// openFP opens a reader on the copy ring. Created before the program runs so a
// record submitted during Run is guaranteed visible.
func openFP(t *testing.T, objs *kapkanXDPObjects) *ringbuf.Reader {
	t.Helper()
	rd, err := ringbuf.NewReader(objs.KapkanFpEvents)
	if err != nil {
		t.Fatalf("open kapkan_fp_events reader: %v", err)
	}
	t.Cleanup(func() { _ = rd.Close() })
	return rd
}

// drainFP reads every copy currently on the ring. A short deadline turns the
// "no more records" case into a return rather than a block, so the caller gets
// exactly what the run produced.
func drainFP(t *testing.T, rd *ringbuf.Reader) []FPEvent {
	t.Helper()
	var out []FPEvent
	for {
		rd.SetDeadline(time.Now().Add(300 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return out
		}
		if err != nil {
			t.Fatalf("ringbuf read: %v", err)
		}
		out = append(out, decodeFP(t, rec.RawSample))
	}
}

// decodeFP unpacks one raw ring record into an FPEvent by explicit offset. It
// deliberately does not use binary.Read on the generated struct: the offsets
// are the contract with the C layout, and writing them out means a silent
// reordering on either side fails a specific assertion here instead of decoding
// into the wrong fields. The test arch is little-endian (amd64/arm64), which is
// also the datapath's byte order for the host-order port fields.
func decodeFP(t *testing.T, raw []byte) FPEvent {
	t.Helper()
	if len(raw) != fpEventBytes {
		t.Fatalf("fp event is %d bytes, want %d (struct kapkan_fp_event layout drift)", len(raw), fpEventBytes)
	}
	var ev FPEvent
	copy(ev.Src[:], raw[0:16])
	copy(ev.Dst[:], raw[16:32])
	ev.Sport = binary.LittleEndian.Uint16(raw[32:34])
	ev.Dport = binary.LittleEndian.Uint16(raw[34:36])
	ev.IsV6 = raw[36]
	ev.Proto = raw[37]
	ev.Axis = raw[38]
	ev.PktLen = binary.LittleEndian.Uint32(raw[40:44])
	ev.SnapLen = binary.LittleEndian.Uint32(raw[44:48])
	copy(ev.Data[:], raw[52:fpEventBytes])
	return ev
}

// TestFingerprintCopiesClientHello is the core E2.1 promise: a recognised TLS
// ClientHello is copied to the ring with correct metadata and payload, and the
// packet still passes.
func TestFingerprintCopiesClientHello(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, true, 1_000_000, 1000) // generous: nothing throttles here
	rd := openFP(t, objs)

	// A ClientHello on a TCP segment carrying options, so the copy offset is
	// proven to come from doff and not an assumed 20-byte header.
	hdr, payload := tcpWithOptions(51000, 443, 0x18, 3), clientHello()
	pkt := tlsFrameFrom(attackerIP, hdr, payload)
	if got := run(t, objs, pkt); got != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS — the copy must not change the verdict", verdictName(got))
	}

	events := drainFP(t, rd)
	if len(events) != 1 {
		t.Fatalf("got %d copies, want exactly 1", len(events))
	}
	ev := events[0]

	if ev.Axis != MatchTLSClientHello {
		t.Errorf("axis = %#x, want MatchTLSClientHello (%#x)", ev.Axis, MatchTLSClientHello)
	}
	if ev.Proto != 6 || ev.IsV6 != 0 {
		t.Errorf("proto/is_v6 = %d/%d, want 6/0", ev.Proto, ev.IsV6)
	}
	if ev.Sport != 51000 || ev.Dport != 443 {
		t.Errorf("ports = %d->%d, want 51000->443 (host order)", ev.Sport, ev.Dport)
	}
	if got := [4]byte(ev.Src[:4]); got != attackerIP || [4]byte(ev.Dst[:4]) != victimIP {
		t.Errorf("addrs = %v->%v, want %v->%v", got, ev.Dst[:4], attackerIP, victimIP)
	}
	if int(ev.PktLen) != len(pkt) {
		t.Errorf("pkt_len = %d, want %d (full frame)", ev.PktLen, len(pkt))
	}
	// The whole payload fits under the snapshot ceiling, captured to 64-byte
	// granularity: floor(len/64)*64.
	wantSnap := (len(payload) / 64) * 64
	if int(ev.SnapLen) != wantSnap {
		t.Errorf("snap_len = %d, want %d (64-byte-granular prefix of a %d-byte payload)",
			ev.SnapLen, wantSnap, len(payload))
	}
	// data[] must start at the TLS record, i.e. the six bytes the peek read.
	if ev.Data[0] != 0x16 || ev.Data[1] != 0x03 || ev.Data[5] != 0x01 {
		t.Errorf("data[0..5] = % x, want a ClientHello record head (16 03 .. 01)", ev.Data[0:6])
	}
}

// TestFingerprintCopiesQUICInitial is the UDP twin: a QUIC v1 Initial is copied
// with axis=QUIC and the long header at data[0].
func TestFingerprintCopiesQUICInitial(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, true, 1_000_000, 1000)
	rd := openFP(t, objs)

	payload := quicInitial()
	pkt := quicFrameFrom(attackerIP, 51000, 443, payload)
	if got := run(t, objs, pkt); got != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS", verdictName(got))
	}

	events := drainFP(t, rd)
	if len(events) != 1 {
		t.Fatalf("got %d copies, want exactly 1", len(events))
	}
	ev := events[0]

	if ev.Axis != MatchQUICInitial {
		t.Errorf("axis = %#x, want MatchQUICInitial (%#x)", ev.Axis, MatchQUICInitial)
	}
	if ev.Proto != 17 {
		t.Errorf("proto = %d, want 17 (UDP)", ev.Proto)
	}
	if ev.Dport != 443 {
		t.Errorf("dport = %d, want 443", ev.Dport)
	}
	// The 1200-byte Initial fits under the 1536-byte ceiling, captured to
	// 64-byte granularity (1200 -> 1152). The ceiling itself is exercised
	// separately by TestFingerprintTruncatesAtSnapCeiling.
	wantSnap := (len(payload) / 64) * 64
	if int(ev.SnapLen) != wantSnap {
		t.Errorf("snap_len = %d, want %d", ev.SnapLen, wantSnap)
	}
	if ev.Data[0] != 0xC3 {
		t.Errorf("data[0] = %#x, want the QUIC long header 0xC3", ev.Data[0])
	}
}

// TestFingerprintCopiesClientHelloIPv6 exercises the IPv6 path end to end: the
// v6 fp_off derivation (payload after a 40-byte IPv6 header), the is_v6 flag,
// and the full 16-byte address copy — none of which the IPv4 tests touch.
func TestFingerprintCopiesClientHelloIPv6(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, true, 1_000_000, 1000)
	rd := openFP(t, objs)

	// ipv6() carries the documentation prefix 2001:db8::1 -> 2001:db8::2.
	wantSrc := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	wantDst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	hdr, payload := tcp(51000, 443, 0x18), clientHello()
	pkt := cat(eth(etherTypeIPv6), ipv6(6, len(hdr)+len(payload)), hdr, payload)
	if got := run(t, objs, pkt); got != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS", verdictName(got))
	}

	events := drainFP(t, rd)
	if len(events) != 1 {
		t.Fatalf("got %d copies, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Axis != MatchTLSClientHello {
		t.Errorf("axis = %#x, want MatchTLSClientHello (%#x)", ev.Axis, MatchTLSClientHello)
	}
	if ev.IsV6 != 1 || ev.Proto != 6 {
		t.Errorf("is_v6/proto = %d/%d, want 1/6", ev.IsV6, ev.Proto)
	}
	if ev.Src != wantSrc || ev.Dst != wantDst {
		t.Errorf("addrs = %x -> %x, want %x -> %x", ev.Src, ev.Dst, wantSrc, wantDst)
	}
	if ev.Data[0] != 0x16 || ev.Data[1] != 0x03 || ev.Data[5] != 0x01 {
		t.Errorf("data[0..5] = % x, want a ClientHello record head", ev.Data[0:6])
	}
}

// TestFingerprintCopyCoexistsWithDrop locks the safety-critical half of the
// charter claim: the copy runs BEFORE the decision engine, so a ClientHello that
// a rule drops is still both DROPPED and copied. The copy neither rescues the
// packet nor is suppressed by the drop.
func TestFingerprintCopyCoexistsWithDrop(t *testing.T) {
	objs := loadObjects(t)
	// A static rule that drops everything to the victim, plus the fp plane on.
	installStatics(t, objs, 0, mkRule(ruleOpts{id: 1, action: ActionDrop, dst: &victimIP}))
	if err := PutConfig(objs.MapSet(), ConfigSpec{
		StaticCount: 1,
		FPEnabled:   true,
		FPSamplePPS: 1_000_000,
		FPBurst:     1000,
	}); err != nil {
		t.Fatalf("write kapkan_cfg[0]: %v", err)
	}
	rd := openFP(t, objs)

	pkt := tlsFrameFrom(attackerIP, tcp(51000, 443, 0x18), clientHello())
	if got := run(t, objs, pkt); got != xdpDrop {
		t.Fatalf("verdict = %s, want XDP_DROP (the static rule must still drop it)", verdictName(got))
	}
	if p, _ := readStat(t, objs, StatDropStatic); p != 1 {
		t.Errorf("drop_static = %d, want 1", p)
	}
	if events := drainFP(t, rd); len(events) != 1 {
		t.Errorf("got %d copies, want 1 — a dropped handshake must still be copied", len(events))
	}
}

// TestFingerprintTruncatesAtSnapCeiling drives a payload larger than the
// snapshot ceiling and proves the capture caps at FPSnapLen exactly — exercising
// the copy loop's upper bound and the last 64-byte block ([1472:1536]).
func TestFingerprintTruncatesAtSnapCeiling(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, true, 1_000_000, 1000)
	rd := openFP(t, objs)

	// 6-byte record head + 1600 body = 1606 bytes of payload, comfortably past
	// the 1536-byte ceiling.
	payload := tlsRecordHead(0x16, 0x03, 0x01, 1600)
	if len(payload) <= FPSnapLen {
		t.Fatalf("test payload %d bytes does not exceed the %d ceiling", len(payload), FPSnapLen)
	}
	pkt := tlsFrameFrom(attackerIP, tcp(51000, 443, 0x18), payload)
	if got := run(t, objs, pkt); got != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS", verdictName(got))
	}

	events := drainFP(t, rd)
	if len(events) != 1 {
		t.Fatalf("got %d copies, want exactly 1", len(events))
	}
	ev := events[0]
	if int(ev.SnapLen) != FPSnapLen {
		t.Errorf("snap_len = %d, want %d (capped at the ceiling)", ev.SnapLen, FPSnapLen)
	}
	if ev.Data[0] != 0x16 || ev.Data[5] != 0x01 {
		t.Errorf("data head = % x, want a ClientHello record head", ev.Data[0:6])
	}
}

// TestFingerprintIgnoresNonHandshake proves the copy fires ONLY for a
// recognised handshake: ordinary TCP and non-QUIC UDP produce no copy at all,
// so the ring never carries traffic the plane has no business fingerprinting.
func TestFingerprintIgnoresNonHandshake(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, true, 1_000_000, 1000)
	rd := openFP(t, objs)

	// A plain ACK segment (no TLS record) and a UDP datagram that is not a
	// QUIC Initial.
	run(t, objs, tlsFrameFrom(attackerIP, tcp(51000, 443, 0x10),
		tlsRecordHead(0x17, 0x03, 0x01, 200)))
	run(t, objs, quicFrameFrom(attackerIP, 51000, 443, quicHead(0xC3, 0, 200)))

	if events := drainFP(t, rd); len(events) != 0 {
		t.Fatalf("got %d copies for non-handshake traffic, want 0", len(events))
	}
	if p, _ := readStat(t, objs, StatFPEmitted); p != 0 {
		t.Errorf("fp_emitted = %d, want 0", p)
	}
}

// TestFingerprintDisabledCopiesNothing proves cfg.fp_enabled gates the whole
// path: with it off, a ClientHello produces no copy and touches none of the fp
// counters — the plane is inert until an operator turns it on.
func TestFingerprintDisabledCopiesNothing(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, false, 1_000_000, 1000) // disabled
	rd := openFP(t, objs)

	if got := run(t, objs, tlsFrameFrom(attackerIP, tcp(51000, 443, 0x18), clientHello())); got != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS", verdictName(got))
	}

	if events := drainFP(t, rd); len(events) != 0 {
		t.Fatalf("got %d copies with the plane disabled, want 0", len(events))
	}
	for _, s := range []Stat{StatFPEmitted, StatFPThrottled, StatFPRingFull} {
		if p, _ := readStat(t, objs, s); p != 0 {
			t.Errorf("%s = %d with the plane disabled, want 0", s, p)
		}
	}
}

// TestFingerprintSamplerCapsUnderFlood is the DoS-safety proof. With a bucket of
// one copy and a 1/s refill, a flood of identical ClientHellos yields only a
// bounded handful of copies — at most one per CPU the burst can start on — while
// every packet is accounted as either emitted or throttled and every one still
// passes. Copy volume is capped by the sampler, not by packet rate.
func TestFingerprintSamplerCapsUnderFlood(t *testing.T) {
	objs := loadObjects(t)
	setFPCfg(t, objs, true, 1, 1) // burst 1, refill 1/s: throttles almost at once
	// No ring reader here: the proof is in the counters, and the ring holds a
	// bounded handful of copies that never fill it.

	const flood = 200
	pkt := tlsFrameFrom(attackerIP, tcp(51000, 443, 0x18), clientHello())
	for i := 0; i < flood; i++ {
		if got := run(t, objs, pkt); got != xdpPass {
			t.Fatalf("verdict on packet %d = %s, want XDP_PASS — the sampler must never drop a packet",
				i, verdictName(got))
		}
	}

	emitted, _ := readStat(t, objs, StatFPEmitted)
	throttled, _ := readStat(t, objs, StatFPThrottled)

	// Every ClientHello is either copied or throttled — nothing the fp path
	// touched went unaccounted.
	if emitted+throttled != flood {
		t.Errorf("fp_emitted(%d) + fp_throttled(%d) = %d, want %d", emitted, throttled, emitted+throttled, flood)
	}
	if throttled == 0 {
		t.Errorf("fp_throttled = 0 under a %d-packet flood: the sampler is not capping", flood)
	}
	// The cap is a hard ceiling independent of packet rate: with burst 1, no CPU
	// emits more than its single token within the sub-second the test runs, so
	// the total cannot exceed the CPU count however many packets arrive.
	var per []kapkanXDPKapkanCounter
	if err := objs.KapkanStats.Lookup(uint32(StatFPEmitted), &per); err != nil {
		t.Fatalf("read per-CPU fp_emitted: %v", err)
	}
	if nCPU := uint64(len(per)); emitted > nCPU {
		t.Errorf("fp_emitted = %d exceeds the %d-CPU burst ceiling: copy volume is not capped", emitted, nCPU)
	}
	if emitted == 0 {
		t.Errorf("fp_emitted = 0: the initial burst should have copied at least once")
	}
}

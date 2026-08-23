package fpplane

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/fingerprint"
)

// These tests drive the classify/enforce path directly (handle → classifyTLS)
// with hand-built ring records and a fake blocker, so no kernel is needed. The
// end-to-end path (kernel emits a copy → reader blocks the source) is the E2.5
// lab rig; here we lock the wiring: which events block, which don't, and that a
// block carries the right source/victim/ttl/reason.

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// blockCall records one Blocker invocation.
type blockCall struct {
	victim, source netip.Addr
	ttl            time.Duration
	reason         string
}

// fakeBlocker captures calls and can be made to fail.
type fakeBlocker struct {
	calls []blockCall
	err   error
}

func (f *fakeBlocker) block(victim, source netip.Addr, ttl time.Duration, reason string) error {
	f.calls = append(f.calls, blockCall{victim, source, ttl, reason})
	return f.err
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// clientHelloRecord builds a minimal, parseable TLS ClientHello carrying the
// given SNI. Its exact JA4 does not matter to these tests — they compute it with
// the real parser and drive the blocklist from that — only that it parses.
func clientHelloRecord(sni string) []byte {
	name := append([]byte{0x00}, be16(uint16(len(sni)))...) // name_type host + len
	name = append(name, sni...)
	sniList := append(be16(uint16(len(name))), name...) // server_name_list
	ext := append(be16(0x0000), be16(uint16(len(sniList)))...)
	ext = append(ext, sniList...)

	body := []byte{0x03, 0x03}               // client_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length 0
	body = append(body, be16(4)...)          // cipher_suites length
	body = append(body, 0x13, 0x01, 0x13, 0x02)
	body = append(body, 0x01, 0x00) // compression_methods: null
	body = append(body, be16(uint16(len(ext)))...)
	body = append(body, ext...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, be16(uint16(len(hs)))...)
	return append(rec, hs...)
}

// fpRecord serialises one FPEvent ring record (payload at offset 0), the inverse
// of dataplane.DecodeFPEvent, so a test can feed Reader.handle without a kernel.
func fpRecord(src, dst netip.Addr, sport, dport uint16, axis byte, payload []byte) []byte {
	raw := make([]byte, dataplane.FPEventSize)
	s4, d4 := src.As4(), dst.As4()
	copy(raw[0:4], s4[:])
	copy(raw[16:20], d4[:])
	binary.LittleEndian.PutUint16(raw[32:34], sport)
	binary.LittleEndian.PutUint16(raw[34:36], dport)
	raw[36] = 0 // is_v6
	raw[37] = 6 // proto TCP
	raw[38] = axis
	binary.LittleEndian.PutUint32(raw[40:44], uint32(len(payload)+54)) // pkt_len (approx)
	binary.LittleEndian.PutUint32(raw[44:48], uint32(len(payload)))    // snap_len
	binary.LittleEndian.PutUint16(raw[48:50], 0)                       // payload_off
	copy(raw[52:], payload)
	return raw
}

var (
	testSrc = netip.MustParseAddr("198.51.100.7")
	testDst = netip.MustParseAddr("203.0.113.9")
)

func newTestReader(fb *fakeBlocker, pol Policy) *Reader {
	return &Reader{
		block:  fb.block,
		policy: func() Policy { return pol },
		log:    discardLog(),
	}
}

func TestReaderBlocksOnJA4Match(t *testing.T) {
	ch := clientHelloRecord("evil.example.com")
	res, err := fingerprint.TLSClientHello(ch)
	if err != nil {
		t.Fatalf("build JA4: %v", err)
	}

	fb := &fakeBlocker{}
	r := newTestReader(fb, Policy{
		Blocklist: map[string]struct{}{res.JA4: {}},
		TTL:       5 * time.Minute,
	})
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch))

	if len(fb.calls) != 1 {
		t.Fatalf("blocker calls = %d, want 1", len(fb.calls))
	}
	c := fb.calls[0]
	if c.source != testSrc || c.victim != testDst {
		t.Errorf("blocked %s->%s, want source %s victim %s", c.source, c.victim, testSrc, testDst)
	}
	if c.ttl != 5*time.Minute {
		t.Errorf("ttl = %s, want 5m", c.ttl)
	}
	if want := "ja4:" + res.JA4; c.reason != want {
		t.Errorf("reason = %q, want %q", c.reason, want)
	}
}

func TestReaderIgnoresUnlistedJA4(t *testing.T) {
	ch := clientHelloRecord("good.example.com")
	fb := &fakeBlocker{}
	r := newTestReader(fb, Policy{
		Blocklist: map[string]struct{}{"t13d1516h2_deadbeefdead_beefdeadbeef": {}},
		TTL:       time.Minute,
	})
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch))
	if len(fb.calls) != 0 {
		t.Errorf("blocked a JA4 not on the list: %d calls", len(fb.calls))
	}
}

func TestReaderSkipsQUICAndMalformed(t *testing.T) {
	ch := clientHelloRecord("q.example.com")
	res, _ := fingerprint.TLSClientHello(ch)
	fb := &fakeBlocker{}
	r := newTestReader(fb, Policy{Blocklist: map[string]struct{}{res.JA4: {}}, TTL: time.Minute})

	// A QUIC-axis record must not be classified as TLS (QUIC decrypt is a later
	// sub-PR), even though its bytes would parse as a ClientHello.
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchQUICInitial, ch))
	// A too-short ring record is dropped, not decoded.
	r.handle([]byte{1, 2, 3})
	// A recognised-but-truncated ClientHello payload fails open.
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch[:8]))

	if len(fb.calls) != 0 {
		t.Errorf("blocked on a QUIC/malformed/truncated event: %d calls", len(fb.calls))
	}
}

func TestReaderBlockErrorIsNonFatal(t *testing.T) {
	ch := clientHelloRecord("evil.example.com")
	res, _ := fingerprint.TLSClientHello(ch)
	fb := &fakeBlocker{err: errBlockRefused}
	r := newTestReader(fb, Policy{Blocklist: map[string]struct{}{res.JA4: {}}, TTL: time.Minute})
	// Must not panic; the refusal is counted and swallowed.
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch))
	if len(fb.calls) != 1 {
		t.Fatalf("blocker calls = %d, want 1 (attempted)", len(fb.calls))
	}
}

var errBlockRefused = errTest("source is allowlisted")

type errTest string

func (e errTest) Error() string { return string(e) }

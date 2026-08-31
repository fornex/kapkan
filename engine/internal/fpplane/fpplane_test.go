package fpplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/fingerprint"
)

// buildQUICInitial seals a bare TLS handshake message into a valid QUIC v1 client
// Initial datagram (RFC 9001 §5), keyed from a fixed Destination Connection ID.
// It mirrors what a real client sends so the reader's QUIC path can be exercised
// without a kernel; the packet is self-checking, since the RFC-anchored
// fingerprint.QUICInitial must accept it.
func buildQUICInitial(t *testing.T, handshake []byte) []byte {
	t.Helper()
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	salt := []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	expand := func(secret []byte, label string, n int) []byte {
		full := "tls13 " + label
		info := []byte{byte(n >> 8), byte(n), byte(len(full))}
		info = append(info, full...)
		info = append(info, 0)
		out, err := hkdf.Expand(sha256.New, secret, string(info), n)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	initialSecret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		t.Fatal(err)
	}
	clientSecret := expand(initialSecret, "client in", 32)
	key := expand(clientSecret, "quic key", 16)
	iv := expand(clientSecret, "quic iv", 12)
	hp := expand(clientSecret, "quic hp", 16)

	payload := []byte{0x06, 0x00, byte(len(handshake)>>8&0x3f) | 0x40, byte(len(handshake))}
	payload = append(payload, handshake...)
	for len(payload) < 1162 {
		payload = append(payload, 0x00)
	}
	const pnLen = 4
	length := uint64(pnLen + len(payload) + 16)

	hdr := []byte{0xc0 | (pnLen - 1), 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // empty SCID
	hdr = append(hdr, 0x00) // token length 0
	hdr = append(hdr, byte(0x40|length>>8), byte(length))
	pnOffset := len(hdr)
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x02) // packet number 2

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	nonce[len(nonce)-1] ^= 0x02 // packet number 2
	pkt := aead.Seal(hdr, nonce, payload, hdr)

	hpBlock, _ := aes.NewCipher(hp)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

// These tests drive the classify/enforce path directly (handle → classify)
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

// fakeBlocker captures calls and can be made to fail or report dry-run.
type fakeBlocker struct {
	calls  []blockCall
	err    error
	dryRun bool
}

func (f *fakeBlocker) block(victim, source netip.Addr, ttl time.Duration, reason string) (bool, error) {
	f.calls = append(f.calls, blockCall{victim, source, ttl, reason})
	return f.dryRun, f.err
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
		now:    time.Now,
		recent: make(map[string]time.Time),
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

func TestReaderFailsOpenOnBadPayloads(t *testing.T) {
	ch := clientHelloRecord("q.example.com")
	res, _ := fingerprint.TLSClientHello(ch)
	fb := &fakeBlocker{}
	r := newTestReader(fb, Policy{Blocklist: map[string]struct{}{res.JA4: {}}, TTL: time.Minute})

	// A QUIC-axis record whose bytes are not a valid QUIC Initial (here a TLS
	// record) fails open: it is decrypted as QUIC, not misparsed as TLS.
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchQUICInitial, ch))
	// A too-short ring record is dropped, not decoded.
	r.handle([]byte{1, 2, 3})
	// A recognised-but-truncated ClientHello payload fails open.
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch[:8]))

	if len(fb.calls) != 0 {
		t.Errorf("blocked on a QUIC/malformed/truncated event: %d calls", len(fb.calls))
	}
}

// TestReaderBlocksOnQUICJA4 locks the QUIC routing end to end: a real QUIC v1
// Initial on the QUIC axis is decrypted, its JA4 matched against the blocklist,
// and the source blocked — the same enforcement as TLS, reached via a different
// parser. The packet is a genuine encrypted Initial (buildQUICInitial), so a
// mis-wired axis would fail to block and trip this test.
func TestReaderBlocksOnQUICJA4(t *testing.T) {
	host := "quic.evil.example"
	record := clientHelloRecord(host)
	res, err := fingerprint.QUICInitial(buildQUICInitial(t, record[5:]))
	if err != nil {
		t.Fatalf("build QUIC JA4: %v", err)
	}
	if res.JA4[0] != 'q' {
		t.Fatalf("expected a QUIC fingerprint, got %q", res.JA4)
	}

	fb := &fakeBlocker{}
	r := newTestReader(fb, Policy{Blocklist: map[string]struct{}{res.JA4: {}}, TTL: time.Minute})
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchQUICInitial, buildQUICInitial(t, record[5:])))

	if len(fb.calls) != 1 {
		t.Fatalf("blocker calls = %d, want 1 (QUIC JA4 not blocked)", len(fb.calls))
	}
	if c := fb.calls[0]; c.source != testSrc || c.reason != "ja4:"+res.JA4 {
		t.Errorf("blocked %s reason %q, want %s ja4:%s", c.source, c.reason, testSrc, res.JA4)
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

func TestReaderDryRunStillCallsBlockSource(t *testing.T) {
	ch := clientHelloRecord("evil.example.com")
	res, _ := fingerprint.TLSClientHello(ch)
	fb := &fakeBlocker{dryRun: true}
	r := newTestReader(fb, Policy{Blocklist: map[string]struct{}{res.JA4: {}}, TTL: time.Minute})
	// In dry-run the reader still calls the Blocker (which records the block and
	// installs nothing) and must not panic or error; it just reports would-block.
	// The audit record for a reader block is written by the app's Blocker adapter
	// (source="auto"), above this seam — see internal/app auditingBlocker.
	r.handle(fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch))
	if len(fb.calls) != 1 {
		t.Fatalf("blocker calls = %d, want 1 (dry-run still calls BlockSource)", len(fb.calls))
	}
}

// TestReaderDedupsRepeatedSource proves an already-actioned source is not
// re-blocked on every sampled copy, and is refreshed once its cooldown lapses.
func TestReaderDedupsRepeatedSource(t *testing.T) {
	ch := clientHelloRecord("evil.example.com")
	res, _ := fingerprint.TLSClientHello(ch)
	fb := &fakeBlocker{}
	clock := time.Unix(1000, 0)
	r := newTestReader(fb, Policy{Blocklist: map[string]struct{}{res.JA4: {}}, TTL: 10 * time.Second})
	r.now = func() time.Time { return clock } // cooldown = TTL/2 = 5s

	rec := fpRecord(testSrc, testDst, 51000, 443, dataplane.MatchTLSClientHello, ch)
	r.handle(rec)
	r.handle(rec) // within the 5s cooldown → suppressed
	if len(fb.calls) != 1 {
		t.Fatalf("blocker calls = %d, want 1 (repeat within cooldown deduped)", len(fb.calls))
	}
	clock = clock.Add(6 * time.Second) // past the cooldown
	r.handle(rec)
	if len(fb.calls) != 2 {
		t.Fatalf("blocker calls = %d, want 2 (refreshed after cooldown)", len(fb.calls))
	}
}

var errBlockRefused = errTest("source is allowlisted")

type errTest string

func (e errTest) Error() string { return string(e) }

package fingerprint

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// rfc9001DCID is the Destination Connection ID from RFC 9001 Appendix A.
const rfc9001DCID = "8394c8f03e515708"

// TestQUICClientInitialKeys anchors the HKDF derivation to RFC 9001 A.1: the
// client key/iv/hp derived from the Destination Connection ID must match the
// published vectors exactly. This proves the labels, the "tls13 " prefix, and the
// Extract/Expand steps are correct — independently of the packet round-trip below,
// which shares only the same (now-anchored) key schedule.
func TestQUICClientInitialKeys(t *testing.T) {
	key, iv, hp, err := quicClientInitialKeys(mustHex(t, rfc9001DCID))
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	for _, tc := range []struct {
		name, want string
		got        []byte
	}{
		{"key", "1f369613dd76d5467730efcbe3b1a22d", key},
		{"iv", "fa044b2f42a3fd3b46fb255c", iv},
		{"hp", "9f50449e04a0e810283a1e9933adedd2", hp},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s = %s, want %s (RFC 9001 A.1)", tc.name, got, tc.want)
		}
	}
}

// quicVarint encodes a QUIC variable-length integer in its minimal form.
func quicVarint(v uint64) []byte {
	switch {
	case v <= 63:
		return []byte{byte(v)}
	case v <= 16383:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v <= 1073741823:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		b[0] |= 0xc0
		return b
	}
}

// buildClientInitial seals a TLS handshake message into a valid QUIC v1 client
// Initial packet, keyed from dcid exactly as a real client would: a CRYPTO frame
// at offset 0, PADDING to the ~1200-byte floor, AES-128-GCM, then header
// protection. It is the inverse of quicClientHelloBytes, so a decrypt round-trip
// exercises the whole path; the key schedule it uses is the one anchored to RFC
// 9001 A.1 by TestQUICClientInitialKeys.
func buildClientInitial(t *testing.T, dcid, handshake []byte) []byte {
	t.Helper()
	key, iv, hp, err := quicClientInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x06} // CRYPTO frame
	payload = append(payload, quicVarint(0)...)
	payload = append(payload, quicVarint(uint64(len(handshake)))...)
	payload = append(payload, handshake...)
	for len(payload) < 1162 { // PADDING (0x00) toward the client Initial floor
		payload = append(payload, 0x00)
	}

	const pnLen = 4
	const pn = uint32(2)
	length := uint64(pnLen + len(payload) + 16) // packet number + payload + GCM tag

	hdr := []byte{0xc0 | (pnLen - 1)} // long header, fixed bit, Initial, pnlen-1
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // empty SCID
	hdr = append(hdr, quicVarint(0)...)
	hdr = append(hdr, quicVarint(length)...)
	pnOffset := len(hdr)
	var pnb [4]byte
	binary.BigEndian.PutUint32(pnb[:], pn)
	hdr = append(hdr, pnb[:]...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	var pn8 [8]byte
	binary.BigEndian.PutUint64(pn8[:], uint64(pn))
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= pn8[i]
	}
	pkt := aead.Seal(hdr, nonce, payload, hdr)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt
}

// quicHandshake builds a ClientHello and strips the TLS record header, leaving
// the bare handshake message that QUIC CRYPTO frames carry.
func quicHandshake(ciphers []uint16, exts ...[]byte) []byte {
	return clientHelloBytes(ciphers, exts...)[5:]
}

// TestQUICInitialRoundTrip seals a known ClientHello into a client Initial and
// checks the decrypt recovers it: SNI, ALPN, and — as an independent cross-check
// — a JA4 equal to the TLS parse of the same ClientHello with the transport digit
// flipped t->q (the only field JA4 derives from transport).
func TestQUICInitialRoundTrip(t *testing.T) {
	dcid := mustHex(t, rfc9001DCID)
	record := clientHelloBytes(
		[]uint16{0x1301, 0x1302, 0x1303},
		sniExt("example.com"),
		alpnExt("h3"),
		supportedVersionsExt(0x0304),
		sigAlgsExt(0x0403, 0x0804),
	)
	pkt := buildClientInitial(t, dcid, record[5:])

	res, err := QUICInitial(pkt)
	if err != nil {
		t.Fatalf("QUICInitial: %v", err)
	}
	if res.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", res.SNI)
	}
	if len(res.ALPN) != 1 || res.ALPN[0] != "h3" {
		t.Errorf("ALPN = %v, want [h3]", res.ALPN)
	}
	tls, err := TLSClientHello(record)
	if err != nil {
		t.Fatalf("TLSClientHello: %v", err)
	}
	want := "q" + tls.JA4[1:]
	if res.JA4 != want {
		t.Errorf("JA4 = %q, want %q (TLS JA4 with transport q)", res.JA4, want)
	}
}

// TestQUICInitialSpanningCryptoFrames proves the CRYPTO reassembly joins a
// ClientHello split across two out-of-order CRYPTO frames within one packet.
func TestQUICInitialSpanningCryptoFrames(t *testing.T) {
	dcid := mustHex(t, rfc9001DCID)
	hs := quicHandshake([]uint16{0x1301, 0x1302}, sniExt("split.example"))
	cut := len(hs) / 2

	// Two CRYPTO frames, second one first, to exercise ordering + joining.
	var payload []byte
	frame := func(off int, data []byte) {
		payload = append(payload, 0x06)
		payload = append(payload, quicVarint(uint64(off))...)
		payload = append(payload, quicVarint(uint64(len(data)))...)
		payload = append(payload, data...)
	}
	frame(cut, hs[cut:])
	frame(0, hs[:cut])

	pkt := sealRawInitial(t, dcid, payload)
	res, err := QUICInitial(pkt)
	if err != nil {
		t.Fatalf("QUICInitial: %v", err)
	}
	if res.SNI != "split.example" {
		t.Errorf("SNI = %q, want split.example", res.SNI)
	}
}

// TestQUICInitialAEADTamper proves a modified packet fails to authenticate rather
// than yielding a bogus fingerprint.
func TestQUICInitialAEADTamper(t *testing.T) {
	dcid := mustHex(t, rfc9001DCID)
	pkt := buildClientInitial(t, dcid, quicHandshake([]uint16{0x1301}, sniExt("a.example")))
	pkt[len(pkt)-1] ^= 0xff // corrupt the GCM tag
	if _, err := QUICInitial(pkt); !errors.Is(err, ErrQUICDecrypt) {
		t.Errorf("err = %v, want ErrQUICDecrypt", err)
	}
}

// TestQUICInitialRejects covers the fail-open cases the ring reader relies on.
func TestQUICInitialRejects(t *testing.T) {
	dcid := mustHex(t, rfc9001DCID)
	full := buildClientInitial(t, dcid, quicHandshake([]uint16{0x1301}, sniExt("a.example")))

	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrNotQUICInitial},
		{"short header", []byte{0x40, 0x00, 0x00, 0x00, 0x01}, ErrNotQUICInitial},
		{"snapshot cut mid-payload", full[:len(full)-400], ErrTruncated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := QUICInitial(tc.in); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestQUICUnsupportedVersion rejects a long-header packet whose version is not v1
// (QUIC v2's 0x6b3343cf), since v2 uses different salts and labels.
func TestQUICUnsupportedVersion(t *testing.T) {
	dcid := mustHex(t, rfc9001DCID)
	pkt := buildClientInitial(t, dcid, quicHandshake([]uint16{0x1301}, sniExt("a.example")))
	pkt[1], pkt[2], pkt[3], pkt[4] = 0x6b, 0x33, 0x43, 0xcf
	if _, err := QUICInitial(pkt); !errors.Is(err, ErrQUICUnsupportedVersion) {
		t.Errorf("err = %v, want ErrQUICUnsupportedVersion", err)
	}
}

// sealRawInitial seals an already-built frame payload into a client Initial,
// for tests that need to control the exact frame layout.
func sealRawInitial(t *testing.T, dcid, payload []byte) []byte {
	t.Helper()
	for len(payload) < 1162 {
		payload = append(payload, 0x00)
	}
	key, iv, hp, err := quicClientInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	const pnLen = 4
	const pn = uint32(2)
	length := uint64(pnLen + len(payload) + 16)

	hdr := []byte{0xc0 | (pnLen - 1)}
	hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00)
	hdr = append(hdr, quicVarint(0)...)
	hdr = append(hdr, quicVarint(length)...)
	pnOffset := len(hdr)
	var pnb [4]byte
	binary.BigEndian.PutUint32(pnb[:], pn)
	hdr = append(hdr, pnb[:]...)

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	var pn8 [8]byte
	binary.BigEndian.PutUint64(pn8[:], uint64(pn))
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= pn8[i]
	}
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

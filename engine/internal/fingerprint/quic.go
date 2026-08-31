package fingerprint

// QUIC Initial decryption, for JA4 over the QUIC/h3 handshake (E2). A QUIC v1
// Initial packet protects the client's ClientHello with keys DERIVED FROM THE
// DESTINATION CONNECTION ID — public inputs, no secret exchange — so an off-path
// observer that copied the datagram can decrypt it (RFC 9001 §5.2). The client's
// first flight carries the ClientHello in CRYPTO frames inside one Initial; this
// removes header protection, AEAD-decrypts the payload, reassembles the CRYPTO
// stream, and hands the TLS handshake to the same ClientHello parser the TLS path
// uses (with transport 'q').
//
// Scope and failure model match the rest of the package: ONE captured datagram,
// no cross-datagram reassembly. A ClientHello that spans datagrams, a version
// other than QUIC v1, a truncated snapshot, or a failed AEAD is simply
// "not fingerprintable" — an error the ring reader fails open on, never a crash.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// ErrNotQUICInitial marks a datagram that is not a QUIC v1 long-header Initial
// (a short header, a non-Initial long-header type, or too short to tell). The
// fixed-offset kernel peek can copy a UDP packet that only looked like one.
var ErrNotQUICInitial = errors.New("fingerprint: not a QUIC v1 Initial")

// ErrQUICUnsupportedVersion marks a long-header packet whose version is not QUIC
// v1 (0x00000001) — v2 and the draft versions use different salts/labels and are
// not decrypted here.
var ErrQUICUnsupportedVersion = errors.New("fingerprint: unsupported QUIC version")

// ErrQUICDecrypt marks a packet whose Initial payload would not authenticate
// (AEAD open failed) — a corrupt, truncated, or non-conforming packet.
var ErrQUICDecrypt = errors.New("fingerprint: QUIC Initial AEAD open failed")

// quicV1 is the only QUIC version this decrypts. quicV1InitialSalt is the v1
// Initial salt from RFC 9001 §5.2.
const quicV1 = 0x00000001

var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// QUICInitial computes JA4 (SNI, ALPN) from a QUIC v1 Initial datagram — the UDP
// payload exactly as the datapath captured it (data[payload_off:snap_len]).
func QUICInitial(datagram []byte) (Result, error) {
	hs, err := quicClientHelloBytes(datagram)
	if err != nil {
		return Result{}, err
	}
	ch, err := parseClientHelloHandshake(hs, 'q')
	if err != nil {
		return Result{}, err
	}
	return Result{JA4: ja4(ch), SNI: ch.sni, ALPN: ch.alpn}, nil
}

// quicClientHelloBytes decrypts one QUIC v1 Initial and returns the reassembled
// TLS handshake bytes (starting at the ClientHello msg_type) from its CRYPTO
// stream. It reads only the FIRST packet in the datagram; a coalesced 0-RTT or
// Handshake packet after it is ignored.
func quicClientHelloBytes(pkt []byte) ([]byte, error) {
	c := cursor{b: pkt}

	first, ok := c.u8()
	if !ok {
		return nil, ErrNotQUICInitial
	}
	// Long header form (0x80) and fixed bit (0x40) must be set.
	if first&0xc0 != 0xc0 {
		return nil, ErrNotQUICInitial
	}
	ver, ok := c.u32()
	if !ok {
		return nil, ErrNotQUICInitial
	}
	if ver != quicV1 {
		return nil, ErrQUICUnsupportedVersion
	}
	// With v1 fixed, the long-header type lives in bits 4-5; Initial is 0b00.
	if (first>>4)&0x03 != 0x00 {
		return nil, ErrNotQUICInitial
	}

	dcid, ok := c.vec8() // Destination Connection ID (len prefix + id)
	if !ok || len(dcid) > 20 {
		return nil, ErrNotQUICInitial
	}
	if _, ok := c.vec8(); !ok { // Source Connection ID — skip
		return nil, ErrNotQUICInitial
	}
	tokenLen, ok := c.varint() // Token Length + Token
	if !ok || !c.skip(int(tokenLen)) {
		return nil, ErrTruncated
	}
	length, ok := c.varint() // Length: packet number + protected payload
	if !ok {
		return nil, ErrTruncated
	}
	pnOffset := c.pos
	// The whole protected region must be present to authenticate; a snapshot that
	// cut it is not fingerprintable.
	if length < 20 || pnOffset+int(length) > len(pkt) {
		return nil, ErrTruncated
	}
	// Header protection samples 16 bytes starting 4 bytes into the packet-number
	// field, regardless of its actual length (RFC 9001 §5.4.2).
	sampleOff := pnOffset + 4
	if sampleOff+16 > len(pkt) {
		return nil, ErrTruncated
	}

	key, iv, hp, err := quicClientInitialKeys(dcid)
	if err != nil {
		return nil, err
	}

	// Remove header protection into a private, mutable copy of the packet through
	// the end of its declared length (never touching the caller's buffer).
	buf := make([]byte, pnOffset+int(length))
	copy(buf, pkt[:pnOffset+int(length)])

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[sampleOff:sampleOff+16])

	buf[0] ^= mask[0] & 0x0f // long header: the low 4 bits are protected
	pnLen := int(buf[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		buf[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(buf[pnOffset+i])
	}

	// AEAD nonce = IV XOR the packet number, right-aligned in 12 bytes. For a
	// client's first Initial the truncated packet number is the full value
	// (largest-acked is 0), so no packet-number reconstruction is needed.
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	var pnb [8]byte
	binary.BigEndian.PutUint64(pnb[:], pn)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= pnb[i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := buf[:pnOffset+pnLen]
	ciphertext := buf[pnOffset+pnLen : pnOffset+int(length)]
	plaintext, err := aead.Open(ciphertext[:0], nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrQUICDecrypt
	}
	return reassembleCryptoStream(plaintext)
}

// quicClientInitialKeys derives the client's Initial write key/iv and header-
// protection key from the Destination Connection ID (RFC 9001 §5.1-5.2).
func quicClientInitialKeys(dcid []byte) (key, iv, hp []byte, err error) {
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return nil, nil, nil, err
	}
	clientSecret, err := expandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(clientSecret, "quic key", 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(clientSecret, "quic iv", 12); err != nil {
		return nil, nil, nil, err
	}
	if hp, err = expandLabel(clientSecret, "quic hp", 16); err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

// expandLabel is TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with the "tls13 "
// prefix and an empty context, as QUIC uses it (RFC 9001 §5.1).
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// cryptoChunk is one CRYPTO frame's data at its stream offset.
type cryptoChunk struct {
	off  uint64
	data []byte
}

// reassembleCryptoStream walks the decrypted Initial payload's frames, collects
// the CRYPTO frames, and returns the contiguous handshake bytes from offset 0.
// PADDING/PING are ignored, ACK is skipped; any other frame ends the walk (the
// ClientHello of a first flight precedes anything exotic), and whatever CRYPTO
// was contiguous from 0 is returned for the parser to accept or reject.
func reassembleCryptoStream(payload []byte) ([]byte, error) {
	c := cursor{b: payload}
	var chunks []cryptoChunk
walk:
	for c.remaining() > 0 {
		ftype, ok := c.varint()
		if !ok {
			break
		}
		switch ftype {
		case 0x00, 0x01: // PADDING, PING — no payload
			continue
		case 0x02, 0x03: // ACK (0x03 carries ECN counts)
			if !skipACKFrame(&c, ftype == 0x03) {
				break walk
			}
		case 0x06: // CRYPTO: Offset, Length, Crypto Data
			off, ok := c.varint()
			if !ok {
				break walk
			}
			ln, ok := c.varint()
			if !ok {
				break walk
			}
			data, ok := c.take(int(ln))
			if !ok {
				break walk
			}
			chunks = append(chunks, cryptoChunk{off: off, data: data})
		default:
			break walk
		}
	}
	return contiguousFromZero(chunks)
}

// skipACKFrame advances past an ACK frame's fields (RFC 9000 §19.3).
func skipACKFrame(c *cursor, ecn bool) bool {
	if _, ok := c.varint(); !ok { // Largest Acknowledged
		return false
	}
	if _, ok := c.varint(); !ok { // ACK Delay
		return false
	}
	rangeCount, ok := c.varint() // ACK Range Count
	if !ok {
		return false
	}
	if _, ok := c.varint(); !ok { // First ACK Range
		return false
	}
	for i := uint64(0); i < rangeCount; i++ {
		if _, ok := c.varint(); !ok { // Gap
			return false
		}
		if _, ok := c.varint(); !ok { // ACK Range Length
			return false
		}
	}
	if ecn {
		for i := 0; i < 3; i++ { // ECT0, ECT1, ECN-CE counts
			if _, ok := c.varint(); !ok {
				return false
			}
		}
	}
	return true
}

// contiguousFromZero orders the CRYPTO chunks and returns the unbroken run from
// stream offset 0, joining adjacent/overlapping chunks and stopping at the first
// gap. The parser downstream treats a short result as a truncated ClientHello.
func contiguousFromZero(chunks []cryptoChunk) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, ErrTruncated
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].off < chunks[j].off })
	var out []byte
	var next uint64
	for _, ch := range chunks {
		if ch.off > next {
			break // a gap before this chunk — stop at what we have
		}
		end := ch.off + uint64(len(ch.data))
		if end <= next {
			continue // wholly covered already
		}
		out = append(out, ch.data[next-ch.off:]...)
		next = end
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

// u32 reads a big-endian uint32.
func (c *cursor) u32() (uint32, bool) {
	if c.remaining() < 4 {
		return 0, false
	}
	v := uint32(c.b[c.pos])<<24 | uint32(c.b[c.pos+1])<<16 |
		uint32(c.b[c.pos+2])<<8 | uint32(c.b[c.pos+3])
	c.pos += 4
	return v, true
}

// varint reads a QUIC variable-length integer (RFC 9000 §16): the two high bits
// of the first byte select a 1/2/4/8-byte encoding; the rest is the value.
func (c *cursor) varint() (uint64, bool) {
	first, ok := c.u8()
	if !ok {
		return 0, false
	}
	n := 1 << (first >> 6)
	v := uint64(first & 0x3f)
	for i := 1; i < n; i++ {
		b, ok := c.u8()
		if !ok {
			return 0, false
		}
		v = v<<8 | uint64(b)
	}
	return v, true
}

// Package fingerprint computes JA4 client fingerprints — and extracts SNI and
// ALPN — from the TLS ClientHello and QUIC Initial handshakes the data plane's
// fingerprint ring copies to userspace (E2, see engine/docs/edge-spec.md §6).
//
// It is pure Go and stdlib-only, and knows nothing about BPF: the kernel COPIES
// the handshake bytes, this package CLASSIFIES them. That split is the whole
// point of the fingerprint plane, so this package is deliberately usable — and
// tested — on any host, with no kernel involved.
//
// # What JA4 is
//
// JA4 (FoxIO, BSD-3 spec) is a TLS-client fingerprint of the form A_B_C:
//
//	t13d1516h2_8daaf6152771_e5627efa2ab1
//	│└ version │ └ sha256(sorted ciphers)[:12]
//	│  SNI d/i │           └ sha256(sorted exts "_" sigalgs)[:12]
//	└ transport (t=TLS/TCP, q=QUIC)
//
// See ja4.go for the exact construction. This file is the wire parser that feeds
// it; ja4.go turns parsed fields into the string.
//
// # Failure model
//
// Parsing NEVER reassembles across TLS records or TCP segments — the datapath
// captured a single, possibly truncated, frame prefix, and a handshake split
// across segments is simply not fingerprintable here. Every malformed or short
// input is an error, and the caller (the ring reader) fails open: an
// unfingerprinted handshake is not classified, never misclassified.
package fingerprint

import "errors"

// Result is one classified handshake.
type Result struct {
	// JA4 is the client fingerprint, e.g. "t13d1516h2_8daaf6152771_e5627efa2ab1".
	JA4 string
	// SNI is the server_name (host_name) the client asked for, or "" if the
	// ClientHello carried no SNI extension.
	SNI string
	// ALPN is the list of application protocols the client offered, in order
	// (e.g. ["h2", "http/1.1"]); nil if no ALPN extension.
	ALPN []string
}

// ErrTruncated marks an input too short to parse in full — the common case for a
// handshake the datapath's bounded snapshot cut off. Callers treat it as
// "not fingerprintable", not as an attack signal.
var ErrTruncated = errors.New("fingerprint: handshake truncated")

// ErrNotClientHello marks a well-formed-enough TLS record that is not a
// handshake ClientHello (a mismatch the fixed-offset kernel peek can let
// through, e.g. a record whose type or handshake byte does not line up).
var ErrNotClientHello = errors.New("fingerprint: not a TLS ClientHello")

// clientHello holds the raw ClientHello fields JA4 is built from. Everything is
// kept in wire order where JA4 cares about order (extensions as seen; signature
// algorithms as listed) and sorted only inside ja4.go, so the parser stays a
// faithful transcription of the bytes.
type clientHello struct {
	transport  byte     // 't' for TLS-over-TCP, 'q' for QUIC
	legacyVer  uint16   // ClientHello.client_version (the record fallback)
	ciphers    []uint16 // cipher_suites, in wire order (GREASE included; ja4 filters)
	extensions []uint16 // extension types, in wire order
	sigAlgs    []uint16 // signature_algorithms (ext 0x000d) values, in wire order
	hasSNI     bool
	sni        string
	alpn       []string

	// supported_versions extension (0x002b): JA4's version digits come from the
	// highest non-GREASE value here when present, else from legacyVer.
	hasSupportedVersions bool
	supportedVersions    []uint16
}

// TLS record / handshake constants.
const (
	tlsRecordHandshake = 0x16
	tlsHandshakeCH     = 0x01

	extSNI          = 0x0000
	extALPN         = 0x0010
	extSupportedVer = 0x002b
	extSigAlgs      = 0x000d

	sniHostName = 0x00
)

// TLSClientHello parses a TLS ClientHello from the start of its TLS record — the
// TCP payload exactly as the datapath captured it (data[payload_off:snap_len]) —
// and returns its JA4 fingerprint, SNI and ALPN.
func TLSClientHello(record []byte) (Result, error) {
	ch, err := parseTLSClientHello(record)
	if err != nil {
		return Result{}, err
	}
	return Result{JA4: ja4(ch), SNI: ch.sni, ALPN: ch.alpn}, nil
}

// parseTLSClientHello strips the TLS record header and hands the handshake body
// to parseClientHelloHandshake. The handshake must live inside the record, so it
// clamps to the record length (a lying outer length can never walk past it) while
// tolerating a body the snapshot truncated (recLen may exceed what we captured).
func parseTLSClientHello(record []byte) (clientHello, error) {
	r := cursor{b: record}

	// TLS record header: type(1) legacy_version(2) length(2).
	recType, ok := r.u8()
	if !ok {
		return clientHello{transport: 't'}, ErrTruncated
	}
	if recType != tlsRecordHandshake {
		return clientHello{transport: 't'}, ErrNotClientHello
	}
	if !r.skip(2) { // record legacy_version — not used
		return clientHello{transport: 't'}, ErrTruncated
	}
	recLen, ok := r.u16()
	if !ok {
		return clientHello{transport: 't'}, ErrTruncated
	}
	body := r.rest()
	if int(recLen) < len(body) {
		body = body[:recLen]
	}
	return parseClientHelloHandshake(body, 't')
}

// parseClientHelloHandshake walks a TLS handshake message that must be a
// ClientHello, starting at the msg_type byte (0x01): the layer QUIC CRYPTO frames
// carry directly, and the layer inside a TLS record. The ClientHello bytes are
// identical either way, so transport ('t' for TLS/TCP, 'q' for QUIC) is simply
// stamped into the result. It reads only what JA4/SNI/ALPN need, skipping the
// rest by length.
func parseClientHelloHandshake(hs []byte, transport byte) (clientHello, error) {
	ch := clientHello{transport: transport, legacyVer: 0x0301}
	h := cursor{b: hs}

	// Handshake header: msg_type(1) length(3).
	msgType, ok := h.u8()
	if !ok {
		return ch, ErrTruncated
	}
	if msgType != tlsHandshakeCH {
		return ch, ErrNotClientHello
	}
	hsLen, ok := h.u24()
	if !ok {
		return ch, ErrTruncated
	}
	// Clamp to the handshake length so trailing bytes (record padding, a second
	// CRYPTO-carried message) cannot leak into the ClientHello parse, but tolerate
	// a body the snapshot truncated (hsLen may exceed what we captured).
	body := h.rest()
	if int(hsLen) < len(body) {
		body = body[:hsLen]
	}
	b := cursor{b: body}

	// ClientHello body: client_version(2) random(32) session_id opaque<0..32>.
	lv, ok := b.u16()
	if !ok {
		return ch, ErrTruncated
	}
	ch.legacyVer = lv
	if !b.skip(32) { // random
		return ch, ErrTruncated
	}
	if !b.skipVec8() { // session_id
		return ch, ErrTruncated
	}

	// cipher_suites <2..2^16-2>.
	csuites, ok := b.vec16()
	if !ok {
		return ch, ErrTruncated
	}
	ch.ciphers = u16s(csuites)

	// compression_methods <1..2^8-1>.
	if !b.skipVec8() {
		return ch, ErrTruncated
	}

	// extensions <0..2^16-1>. The field is OPTIONAL: a ClientHello may end right
	// after compression_methods (legal for TLS 1.2 and earlier) and simply have
	// no extensions. But a length field that IS present and cannot be satisfied —
	// the snapshot cut the extensions region (routine for a modern hello whose
	// post-quantum key shares run past the capture ceiling), or an attacker
	// inflated the length to erase SNI/ALPN/extensions from the fingerprint —
	// must be ErrTruncated, NOT a silent zero-extension JA4 that misclassifies.
	// Distinguish the two by what remains: nothing left = no field (legal);
	// anything left must parse as a valid extensions vector.
	if b.remaining() == 0 {
		return ch, nil
	}
	extAll, ok := b.vec16()
	if !ok {
		return ch, ErrTruncated
	}
	if err := ch.parseExtensions(extAll); err != nil {
		return ch, err
	}
	return ch, nil
}

// parseExtensions records each extension type in order and decodes the few whose
// contents JA4/SNI/ALPN need. A truncated or lying inner extension length is
// ErrTruncated — the whole parse fails open to "unclassified" rather than
// computing a JA4 over a partial extension list, which would be unstable and
// would drop fields (matching how the outer extensions length is handled).
func (ch *clientHello) parseExtensions(ext []byte) error {
	r := cursor{b: ext}
	for r.remaining() > 0 {
		etype, ok := r.u16()
		if !ok {
			return ErrTruncated
		}
		edata, ok := r.vec16()
		if !ok {
			return ErrTruncated
		}
		ch.extensions = append(ch.extensions, etype)
		switch etype {
		case extSNI:
			ch.hasSNI = true
			ch.sni = parseSNI(edata)
		case extALPN:
			ch.alpn = parseALPN(edata)
		case extSupportedVer:
			ch.hasSupportedVersions = true
			ch.supportedVersions = parseSupportedVersions(edata)
		case extSigAlgs:
			ch.sigAlgs = parseSigAlgs(edata)
		}
	}
	return nil
}

// parseSNI returns the first host_name in a server_name_list, or "".
func parseSNI(b []byte) string {
	r := cursor{b: b}
	list, ok := r.vec16() // server_name_list
	if !ok {
		return ""
	}
	lr := cursor{b: list}
	for lr.remaining() > 0 {
		nameType, ok := lr.u8()
		if !ok {
			return ""
		}
		name, ok := lr.vec16()
		if !ok {
			return ""
		}
		if nameType == sniHostName {
			return string(name)
		}
	}
	return ""
}

// parseALPN returns the offered protocol names, in order.
func parseALPN(b []byte) []string {
	r := cursor{b: b}
	list, ok := r.vec16() // ProtocolNameList
	if !ok {
		return nil
	}
	lr := cursor{b: list}
	var out []string
	for lr.remaining() > 0 {
		proto, ok := lr.vec8()
		if !ok {
			break
		}
		out = append(out, string(proto))
	}
	return out
}

// parseSupportedVersions returns the versions the client lists, in order.
func parseSupportedVersions(b []byte) []uint16 {
	r := cursor{b: b}
	list, ok := r.vec8() // the extension body is itself a u8-length vector
	if !ok {
		return nil
	}
	return u16s(list)
}

// parseSigAlgs returns the signature_algorithms values, in order.
func parseSigAlgs(b []byte) []uint16 {
	r := cursor{b: b}
	list, ok := r.vec16()
	if !ok {
		return nil
	}
	return u16s(list)
}

// u16s reinterprets a byte slice as big-endian u16s, dropping a trailing odd
// byte (a truncated final value). Used for cipher/version/sigalg lists.
func u16s(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

// cursor is a bounds-checked big-endian reader over a byte slice. Every read
// returns ok=false rather than panicking on a short buffer, so a truncated
// snapshot degrades to ErrTruncated instead of a crash.
type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }
func (c *cursor) rest() []byte   { return c.b[c.pos:] }

func (c *cursor) u8() (byte, bool) {
	if c.remaining() < 1 {
		return 0, false
	}
	v := c.b[c.pos]
	c.pos++
	return v, true
}

func (c *cursor) u16() (uint16, bool) {
	if c.remaining() < 2 {
		return 0, false
	}
	v := uint16(c.b[c.pos])<<8 | uint16(c.b[c.pos+1])
	c.pos += 2
	return v, true
}

func (c *cursor) u24() (uint32, bool) {
	if c.remaining() < 3 {
		return 0, false
	}
	v := uint32(c.b[c.pos])<<16 | uint32(c.b[c.pos+1])<<8 | uint32(c.b[c.pos+2])
	c.pos += 3
	return v, true
}

func (c *cursor) skip(n int) bool {
	if n < 0 || c.remaining() < n {
		return false
	}
	c.pos += n
	return true
}

// vec8 reads a u8-length-prefixed byte vector and returns its contents.
func (c *cursor) vec8() ([]byte, bool) {
	n, ok := c.u8()
	if !ok {
		return nil, false
	}
	return c.take(int(n))
}

// vec16 reads a u16-length-prefixed byte vector and returns its contents.
func (c *cursor) vec16() ([]byte, bool) {
	n, ok := c.u16()
	if !ok {
		return nil, false
	}
	return c.take(int(n))
}

func (c *cursor) skipVec8() bool { _, ok := c.vec8(); return ok }

func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || c.remaining() < n {
		return nil, false
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v, true
}

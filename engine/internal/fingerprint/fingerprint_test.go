package fingerprint

import (
	"errors"
	"testing"
)

/* -------------------------------------------------------- wire builders */

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// vec16/vec8 prepend a u16/u8 length to a body — the two TLS vector forms.
func vec16(b []byte) []byte { return append(be16(uint16(len(b))), b...) }
func vec8(b []byte) []byte  { return append([]byte{byte(len(b))}, b...) }

// u16list flattens values into big-endian bytes.
func u16list(vals ...uint16) []byte {
	out := make([]byte, 0, len(vals)*2)
	for _, v := range vals {
		out = append(out, be16(v)...)
	}
	return out
}

// ext builds one extension: type(2) + u16-length-prefixed body.
func ext(etype uint16, body []byte) []byte { return append(be16(etype), vec16(body)...) }

// sniExt builds a server_name extension carrying one host_name.
func sniExt(host string) []byte {
	entry := append([]byte{sniHostName}, vec16([]byte(host))...) // name_type + name
	return ext(extSNI, vec16(entry))                             // server_name_list
}

// alpnExt builds an ALPN extension from the given protocols, in order.
func alpnExt(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, vec8([]byte(p))...)
	}
	return ext(extALPN, vec16(list))
}

// supportedVersionsExt builds a supported_versions extension (a u8-length list).
func supportedVersionsExt(vals ...uint16) []byte {
	return ext(extSupportedVer, vec8(u16list(vals...)))
}

// sigAlgsExt builds a signature_algorithms extension (a u16-length list).
func sigAlgsExt(vals ...uint16) []byte {
	return ext(extSigAlgs, vec16(u16list(vals...)))
}

// clientHelloBytes assembles a full TLS record carrying a ClientHello from the
// given cipher list and already-serialised extension blocks (in order).
func clientHelloBytes(ciphers []uint16, exts ...[]byte) []byte {
	var body []byte
	body = append(body, be16(0x0303)...)               // client_version (legacy)
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, vec8(nil)...)                  // session_id (empty)
	body = append(body, vec16(u16list(ciphers...))...) // cipher_suites
	body = append(body, vec8([]byte{0x00})...)         // compression_methods: null
	var allExt []byte
	for _, e := range exts {
		allExt = append(allExt, e...)
	}
	body = append(body, vec16(allExt)...) // extensions

	hs := append([]byte{tlsHandshakeCH, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{tlsRecordHandshake, 0x03, 0x01}, be16(uint16(len(hs)))...)
	return append(rec, hs...)
}

/* --------------------------------------------------------------- golden */

// goldenCiphers/goldenExtOrder/goldenSigAlgs are the exact inputs from the FoxIO
// JA4 spec's worked example, which must produce goldenJA4.
var (
	goldenCiphers = []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
		0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	// The 16 extension types in the example's wire order; SNI (0000) and ALPN
	// (0010) are among them and are filled with real bodies below.
	goldenExtOrder = []uint16{
		0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
		0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
	}
	goldenSigAlgs = []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	goldenJA4     = "t13d1516h2_8daaf6152771_e5627efa2ab1"
)

// goldenRecord assembles a ClientHello whose ciphers/extensions/sigalgs/ALPN/
// SNI/version match the spec example exactly.
func goldenRecord(t *testing.T) []byte {
	t.Helper()
	exts := make([][]byte, 0, len(goldenExtOrder))
	for _, e := range goldenExtOrder {
		switch e {
		case extSNI:
			exts = append(exts, sniExt("example.com"))
		case extALPN:
			exts = append(exts, alpnExt("h2", "http/1.1"))
		case extSupportedVer:
			exts = append(exts, supportedVersionsExt(0x0304)) // TLS 1.3
		case extSigAlgs:
			exts = append(exts, sigAlgsExt(goldenSigAlgs...))
		default:
			exts = append(exts, ext(e, nil)) // type only; body irrelevant to JA4
		}
	}
	return clientHelloBytes(goldenCiphers, exts...)
}

// TestJA4GoldenVector is the anchor: the FoxIO reference example must reproduce
// byte-for-byte, which validates the whole pipeline (parse + A/B/C + the real
// sha256 truncations) against the standard, not against our own arithmetic.
func TestJA4GoldenVector(t *testing.T) {
	res, err := TLSClientHello(goldenRecord(t))
	if err != nil {
		t.Fatalf("TLSClientHello: %v", err)
	}
	if res.JA4 != goldenJA4 {
		t.Errorf("JA4 = %q, want %q", res.JA4, goldenJA4)
	}
	if res.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", res.SNI)
	}
	if len(res.ALPN) != 2 || res.ALPN[0] != "h2" || res.ALPN[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", res.ALPN)
	}
}

// TestJA4GREASEIgnored proves GREASE ciphers and extensions change neither the
// counts nor the B/C hashes: injecting them must yield the identical JA4.
func TestJA4GREASEIgnored(t *testing.T) {
	base := goldenRecord(t)
	baseRes, err := TLSClientHello(base)
	if err != nil {
		t.Fatalf("base: %v", err)
	}

	// Rebuild with a GREASE cipher first and a GREASE extension first.
	ciphers := append([]uint16{0x0a0a}, goldenCiphers...)
	exts := [][]byte{ext(0x1a1a, nil)}
	for _, e := range goldenExtOrder {
		switch e {
		case extSNI:
			exts = append(exts, sniExt("example.com"))
		case extALPN:
			exts = append(exts, alpnExt("h2", "http/1.1"))
		case extSupportedVer:
			exts = append(exts, supportedVersionsExt(0x2a2a, 0x0304)) // GREASE + TLS 1.3
		case extSigAlgs:
			exts = append(exts, sigAlgsExt(goldenSigAlgs...))
		default:
			exts = append(exts, ext(e, nil))
		}
	}
	greased := clientHelloBytes(ciphers, exts...)
	res, err := TLSClientHello(greased)
	if err != nil {
		t.Fatalf("greased: %v", err)
	}
	if res.JA4 != baseRes.JA4 {
		t.Errorf("GREASE changed the fingerprint: %q != %q", res.JA4, baseRes.JA4)
	}
	if res.JA4 != goldenJA4 {
		t.Errorf("JA4 = %q, want %q", res.JA4, goldenJA4)
	}
}

// TestJA4NoSNINoALPN checks the "i" SNI flag, the "00" ALPN, and that the
// version falls back to the legacy field when supported_versions is absent.
func TestJA4NoSNINoALPN(t *testing.T) {
	// Only two extensions, neither SNI nor ALPN nor supported_versions.
	rec := clientHelloBytes([]uint16{0x1301, 0x1302}, ext(0x0017, nil), sigAlgsExt(0x0403))
	res, err := TLSClientHello(rec)
	if err != nil {
		t.Fatalf("TLSClientHello: %v", err)
	}
	// transport t, version 12 (legacy 0x0303), SNI i, 2 ciphers, 2 exts, alpn 00.
	if got, want := res.JA4[:10], "t12i0202"+"00"; got != want {
		t.Errorf("JA4 a-section = %q, want %q", got, want)
	}
	if res.SNI != "" {
		t.Errorf("SNI = %q, want empty", res.SNI)
	}
	if res.ALPN != nil {
		t.Errorf("ALPN = %v, want nil", res.ALPN)
	}
}

// TestParseErrors covers the fail-open inputs the ring reader will hand us.
func TestParseErrors(t *testing.T) {
	if _, err := TLSClientHello(nil); !errors.Is(err, ErrTruncated) {
		t.Errorf("empty input: err = %v, want ErrTruncated", err)
	}
	if _, err := TLSClientHello([]byte{0x17, 0x03, 0x03, 0x00, 0x05}); !errors.Is(err, ErrNotClientHello) {
		t.Errorf("application-data record: err = %v, want ErrNotClientHello", err)
	}
	// A handshake record whose message type is not client_hello (e.g. a
	// ServerHello 0x02) is rejected.
	sh := []byte{tlsRecordHandshake, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}
	if _, err := TLSClientHello(sh); !errors.Is(err, ErrNotClientHello) {
		t.Errorf("server_hello: err = %v, want ErrNotClientHello", err)
	}
	// A ClientHello cut off mid-cipher-list is truncated, not a panic.
	full := goldenRecord(t)
	if _, err := TLSClientHello(full[:40]); !errors.Is(err, ErrTruncated) {
		t.Errorf("cut ClientHello: err = %v, want ErrTruncated", err)
	}
}

// TestIsGREASE pins the RFC 8701 predicate against the full GREASE set and a few
// near-misses.
func TestIsGREASE(t *testing.T) {
	for i := 0; i < 16; i++ {
		v := uint16(i)<<12 | 0x0a00 | uint16(i)<<4 | 0x0a // 0x0a0a, 0x1a1a, … 0xfafa
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0000, 0x0a0b, 0x0b0b, 0xabab, 0x0aaa} {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}

// TestVersionFromSupportedVersions confirms the highest non-GREASE
// supported_versions value wins over the legacy field.
func TestVersionFromSupportedVersions(t *testing.T) {
	// legacy 0x0303 (would be "12"), but supported_versions offers 1.3.
	rec := clientHelloBytes([]uint16{0x1301}, supportedVersionsExt(0x2a2a, 0x0303, 0x0304))
	res, err := TLSClientHello(rec)
	if err != nil {
		t.Fatalf("TLSClientHello: %v", err)
	}
	if res.JA4[1:3] != "13" {
		t.Errorf("version = %q, want 13 (from supported_versions)", res.JA4[1:3])
	}
}

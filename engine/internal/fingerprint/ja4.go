package fingerprint

// JA4 construction, faithful to the FoxIO spec (technical_details/JA4.md, BSD-3).
// The reference worked example is pinned as a golden test: a TLS 1.3 ClientHello
// with 15 ciphers, 16 extensions and first ALPN "h2" must produce
//
//	t13d1516h2_8daaf6152771_e5627efa2ab1
//
// JA4 = A_B_C:
//
//	A = transport + version + SNI-flag + cipher-count + ext-count + alpn2
//	B = sha256(sorted non-GREASE ciphers, comma-joined)[:12]
//	C = sha256(sorted non-GREASE exts (minus SNI/ALPN) "_" sigalgs-in-order)[:12]
//
// GREASE (RFC 8701) values are ignored EVERYWHERE — counts, hashes, versions.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// ja4 renders the full A_B_C fingerprint for a parsed ClientHello.
func ja4(ch clientHello) string {
	return ja4a(ch) + "_" + ja4b(ch) + "_" + ja4c(ch)
}

// ja4a builds the 10-char "a" section: transport, TLS version, SNI presence,
// cipher count, extension count, first-ALPN characters.
func ja4a(ch clientHello) string {
	sni := byte('i')
	if ch.hasSNI {
		sni = 'd'
	}
	nc := countNonGREASE(ch.ciphers)
	ne := countNonGREASE(ch.extensions) // extension count INCLUDES SNI and ALPN
	return fmt.Sprintf("%c%s%c%s%s%s",
		ch.transport, ja4Version(ch), sni, count2(nc), count2(ne), ja4ALPN(ch.alpn))
}

// ja4b hashes the sorted non-GREASE cipher list.
func ja4b(ch clientHello) string {
	return hash12(sortedHex(ch.ciphers))
}

// ja4c hashes the sorted non-GREASE extension list (minus SNI and ALPN, which
// JA4 excludes because their presence is already encoded in the "a" section)
// joined by "_" to the signature algorithms in their original order.
func ja4c(ch clientHello) string {
	exts := make([]uint16, 0, len(ch.extensions))
	for _, e := range ch.extensions {
		if isGREASE(e) || e == extSNI || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return zeroHash
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	s := joinHex(exts)
	if sigs := filterGREASE(ch.sigAlgs); len(sigs) > 0 {
		s += "_" + joinHex(sigs) // signature algorithms stay in wire order
	}
	return hash12(s)
}

// zeroHash is JA4's sentinel for an empty cipher or extension list.
const zeroHash = "000000000000"

// ja4Version maps the negotiated version to two characters. It prefers the
// highest non-GREASE value in supported_versions (0x002b); absent that, the
// ClientHello's legacy version.
//
// "Highest" is by RECENCY, not by numeric value: DTLS codepoints are inverted
// (DTLS 1.3 = 0xfefc < DTLS 1.0 = 0xfeff), so a numeric max would pick the
// oldest DTLS version. versionRank orders them correctly.
func ja4Version(ch clientHello) string {
	v := ch.legacyVer
	if ch.hasSupportedVersions {
		bestRank := 0 // known versions rank >= 1; an all-unknown list keeps legacy
		for _, sv := range ch.supportedVersions {
			if isGREASE(sv) {
				continue
			}
			if r := versionRank(sv); r > bestRank {
				bestRank, v = r, sv
			}
		}
	}
	return versionString(v)
}

// versionRank orders TLS/SSL/DTLS versions by recency (newer = higher). Unknown
// codepoints rank 0 so they never displace a known version but still fall back
// to the legacy field. Kept in lockstep with versionString.
func versionRank(v uint16) int {
	switch v {
	case 0x0304: // TLS 1.3
		return 9
	case 0x0303: // TLS 1.2
		return 8
	case 0x0302: // TLS 1.1
		return 7
	case 0x0301: // TLS 1.0
		return 6
	case 0x0300: // SSL 3.0
		return 5
	case 0x0002: // SSL 2.0
		return 4
	case 0xfefc: // DTLS 1.3
		return 3
	case 0xfefd: // DTLS 1.2
		return 2
	case 0xfeff: // DTLS 1.0
		return 1
	default:
		return 0
	}
}

// versionString is JA4's two-character rendering of a version codepoint.
func versionString(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4ALPN returns the two ALPN characters: the first and last character of the
// first offered protocol when both are ASCII-alphanumeric, otherwise a hex
// rendering of the first and last bytes, and "00" when there is no ALPN.
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || len(alpn[0]) == 0 {
		return "00"
	}
	p := alpn[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	// Non-alphanumeric: JA4 uses the first hex nibble of the first byte and the
	// last hex nibble of the last byte.
	h := fmt.Sprintf("%02x%02x", first, last)
	return string([]byte{h[0], h[3]})
}

// sortedHex returns the non-GREASE values as sorted 4-char lowercase hex joined
// by commas, JA4's canonical cipher/extension list form; zeroHash's companion
// empty case is handled by hash12.
func sortedHex(vals []uint16) string {
	f := filterGREASE(vals)
	if len(f) == 0 {
		return ""
	}
	sort.Slice(f, func(i, j int) bool { return f[i] < f[j] })
	return joinHex(f)
}

// joinHex renders values as comma-separated 4-char lowercase hex, in the given
// order.
func joinHex(vals []uint16) string {
	out := make([]byte, 0, len(vals)*5)
	var tmp [2]byte
	for i, v := range vals {
		if i > 0 {
			out = append(out, ',')
		}
		tmp[0], tmp[1] = byte(v>>8), byte(v)
		out = append(out, []byte(hex.EncodeToString(tmp[:]))...)
	}
	return string(out)
}

// hash12 is sha256 truncated to the first 12 lowercase-hex chars, JA4's B/C form,
// with zeroHash for an empty input.
func hash12(s string) string {
	if s == "" {
		return zeroHash
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// filterGREASE drops RFC 8701 GREASE values, preserving order.
func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func countNonGREASE(vals []uint16) int { return len(filterGREASE(vals)) }

// count2 is a 2-digit zero-padded count capped at 99, per JA4.
func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// isGREASE reports whether v is an RFC 8701 GREASE value: both bytes equal and
// their low nibble is 0xa (0x0a0a, 0x1a1a, … 0xfafa).
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

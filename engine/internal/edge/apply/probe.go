package apply

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Terminator is what Probe learned from `<binary> -V`: the facts the node
// needs before it renders anything for this box (edge-spec §8, E5.1). Nothing
// here is a secret; the whole value goes into the node's report.
type Terminator struct {
	// Kind is "nginx" or "angie"; Version the binary's own version ("1.26.3",
	// "1.12.1").
	Kind    string
	Version string
	// Core is the nginx core the build derives from: Version itself for nginx,
	// the "nginx version:" line Angie prints second ("1.31.2"). Feature and
	// advisory ranges are stated against the core.
	Core string
	// HTTP3Module reports --with-http_v3_module among the configure arguments.
	// Without it `listen … quic` fails `nginx -t` with `invalid parameter
	// "quic"`, so the renderer must know before it emits a byte of QUIC.
	HTTP3Module bool
	// TLSLibrary is the TLS library and version the binary RUNS with ("OpenSSL
	// 3.5.7", "BoringSSL", "LibreSSL 3.9.2", "OpenSSL 3.0.13+quic"), from the
	// "built with … (running with …)" line; the running-with half wins when
	// present because that is the code that executes.
	TLSLibrary string
	// EarlyDataCapable says the build COULD do 0-RTT over QUIC if asked:
	// BoringSSL, LibreSSL or QuicTLS, or OpenSSL ≥ 3.5.1 with a core ≥ 1.29.1
	// (nginx's ngx_http_v3_module documentation). Recorded for the inventory
	// only — E5 renders no ssl_early_data (0-RTT is off by policy).
	EarlyDataCapable bool
}

// Probe asks the binary what it is and what it was built with (`nginx -V`
// prints the version, the TLS library and the configure arguments on stderr;
// Angie prints its own version first and the nginx core second). Kind is
// lower-case: "nginx" or "angie".
func Probe(ctx context.Context, binary string) (Terminator, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, binaryOr(binary), "-V")
	c.WaitDelay = time.Second
	out, err := c.CombinedOutput()
	if err != nil {
		return Terminator{}, fmt.Errorf("%s -V: %w: %s", binaryOr(binary), err, tail(out))
	}
	t, err := ParseVersionOutput(string(out))
	if err != nil {
		return Terminator{}, fmt.Errorf("%s -V: %w", binaryOr(binary), err)
	}
	return t, nil
}

// ParseVersionOutput reads the output of `nginx -V` / `angie -V`. Exported so
// the real-terminator harness reads a container's binary through the same
// code the node runs. The first line must be the version line; everything
// after it is optional (`-v` output parses too, with the build facts absent).
func ParseVersionOutput(out string) (Terminator, error) {
	var t Terminator
	lines := strings.Split(strings.TrimSpace(out), "\n")
	kind, version, ok := parseVersionLine(lines[0])
	if !ok {
		return t, fmt.Errorf("unrecognised output %q", lines[0])
	}
	t.Kind, t.Version, t.Core = kind, version, version
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "nginx version:"):
			// Angie's second line names the nginx core it derives from.
			if _, core, ok := parseVersionLine(line); ok && t.Kind != "nginx" {
				t.Core = core
			}
		case strings.HasPrefix(line, "built with "):
			t.TLSLibrary = tlsLibrary(strings.TrimPrefix(line, "built with "))
		case strings.HasPrefix(line, "configure arguments:"):
			for _, arg := range strings.Fields(strings.TrimPrefix(line, "configure arguments:")) {
				if arg == "--with-http_v3_module" {
					t.HTTP3Module = true
				}
			}
		}
	}
	t.EarlyDataCapable = earlyDataCapable(t.TLSLibrary, t.Core)
	return t, nil
}

// parseVersionLine reads "nginx version: nginx/1.26.2" or "Angie version:
// Angie/1.6.2" (distro builds append their name: "nginx/1.24.0 (Ubuntu)").
func parseVersionLine(line string) (kind, version string, ok bool) {
	before, after, ok := strings.Cut(strings.TrimSpace(line), "version:")
	if !ok {
		return "", "", false
	}
	kind = strings.ToLower(strings.TrimSpace(before))
	if i := strings.LastIndex(after, "/"); i >= 0 {
		after = after[i+1:]
	}
	version, _, _ = strings.Cut(strings.TrimSpace(after), " ")
	if kind == "" || version == "" {
		return "", "", false
	}
	return kind, version, true
}

// tlsLibrary reduces "OpenSSL 3.5.6 7 Apr 2026 (running with OpenSSL 3.5.7 9
// Jun 2026)" to "OpenSSL 3.5.7", "OpenSSL 1.1.1 (compatible; BoringSSL)" to
// "BoringSSL", "LibreSSL 3.9.2" to itself, "OpenSSL 3.0.13+quic 30 Jan 2024"
// to "OpenSSL 3.0.13+quic".
func tlsLibrary(s string) string {
	if strings.Contains(s, "BoringSSL") {
		return "BoringSSL"
	}
	if _, running, ok := strings.Cut(s, "(running with "); ok {
		s, _, _ = strings.Cut(running, ")")
	}
	f := strings.Fields(s)
	switch len(f) {
	case 0:
		return ""
	case 1:
		return f[0]
	}
	return f[0] + " " + f[1]
}

// earlyDataCapable applies the nginx documentation's rule for 0-RTT over
// QUIC: "0-RTT support requires the OpenSSL library version 3.5.1 or higher.
// Alternatively, BoringSSL, LibreSSL, or QuicTLS libraries can be used";
// "before version 1.29.1, 0-RTT support could not be enabled with OpenSSL
// regardless of the ssl_early_data directive value".
func earlyDataCapable(lib, core string) bool {
	name, ver, _ := strings.Cut(lib, " ")
	switch name {
	case "BoringSSL", "LibreSSL":
		return true
	case "OpenSSL":
		if strings.Contains(ver, "+quic") {
			return true
		}
		v, ok := parseVersion(ver)
		c, okc := parseVersion(core)
		return ok && okc && compareVersions(v, [3]int{3, 5, 1}) >= 0 && compareVersions(c, [3]int{1, 29, 1}) >= 0
	}
	return false
}

// Advisory names the published QUIC advisory whose affected range holds this
// build's nginx core — advice, never a verdict: distributions backport fixes
// without moving the version (Debian 13's nginx 1.26.3-3+deb13u7 carries the
// CVE-2026-40460 fix and reports 1.26.3), so the node says what it sees and
// the operator checks the package changelog, or turns HTTP/3 off on the node.
// Empty for a build without the HTTP/3 module (the code is not compiled in)
// and for cores outside the ranges.
func (t Terminator) Advisory() string {
	if !t.HTTP3Module {
		return ""
	}
	v, ok := parseVersion(t.Core)
	if !ok {
		return ""
	}
	within := func(lo, hi [3]int) bool { return compareVersions(v, lo) >= 0 && compareVersions(v, hi) <= 0 }
	switch {
	case within([3]int{1, 25, 0}, [3]int{1, 30, 0}):
		return fmt.Sprintf("nginx core %s is in the range CVE-2026-40460 names (1.25.0–1.30.0: after a QUIC connection migrates, new streams carry an unverified client address — the accounting key kapkan decides on); verify your build carries the fix (distributions backport it, e.g. Debian 13 nginx 1.26.3-3+deb13u7) or set quic.h3: off on this node", t.Core)
	case within([3]int{1, 31, 0}, [3]int{1, 31, 1}):
		return fmt.Sprintf("nginx core %s is in the range CVE-2026-42530 names (1.31.0–1.31.1: a use-after-free in the HTTP/3 QPACK decoder, fixed in 1.31.2); verify your build carries the fix or set quic.h3: off on this node", t.Core)
	}
	return ""
}

// parseVersion reads "1.26.3" (a trailing letter or suffix, "1.1.1k",
// "3.0.13+quic", is ignored); ok is false for anything else.
func parseVersion(s string) (v [3]int, ok bool) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		digits := strings.TrimRightFunc(p, func(r rune) bool { return r < '0' || r > '9' })
		if digits == "" {
			return v, false
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func compareVersions(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

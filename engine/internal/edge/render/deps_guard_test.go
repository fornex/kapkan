package render_test

// The E5 dependency guard.
//
// Decision D10 of the E5 (QUIC/HTTP3) plan: Kapkan orchestrates a terminator,
// it never terminates QUIC itself (edge-spec §"Shape: orchestrate over
// own-proxy"), so the product must not acquire a QUIC implementation as a
// dependency — not for a test client, not for a fixture, not "just for the
// rig". A QUIC stack in engine/go.mod would be linked into the kapkan binary's
// module graph, would have to be tracked for CVEs, and would quietly undo the
// reason the shape was chosen.
//
// The h3 test clients therefore live outside the engine module:
// engine/hack/h3probe is its OWN Go module (`go build ./...` and `go test ./...`
// in engine/ do not descend into it) and engine/hack/h3client is a Dockerfile.
// See engine/hack/README.md.
//
// The guard lives beside the real-terminator harness because that is the test
// most likely to want a QUIC client of its own once E5 lands h3 in the render:
// whoever reaches for one meets this file first.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// engineModulePath is the engine module, as declared in engine/go.mod.
const engineModulePath = "github.com/kapkan-io/kapkan"

// quicMarker matches every QUIC implementation by the one thing they share in
// their module paths. quic-go is the concrete one D10 is about.
const quicMarker = "quic-go"

func TestGuardTheProductHasNoQUICDependency(t *testing.T) {
	t.Parallel()

	path := engineGoMod(t)
	for _, req := range requirements(t, path) {
		if strings.Contains(req, quicMarker) {
			t.Errorf("%s requires %q.\n"+
				"E5 decision D10: the product carries no QUIC dependency — Kapkan orchestrates a\n"+
				"terminator, it never terminates QUIC itself. A QUIC client for a test or a rig\n"+
				"belongs in engine/hack/h3probe, which is its own Go module; see engine/hack/README.md.",
				path, req)
		}
	}
}

// TestGuardTheProbeModuleHoldsTheQUICDependency is the other half of the pair.
// Without it the guard above would pass just as happily on a tree where the
// probe was deleted, or where quic-go was never wired up at all: a rule that
// nothing anywhere depends on QUIC proves nothing about where the dependency
// was put. This asserts it is present, in the nested module, where D10 says.
func TestGuardTheProbeModuleHoldsTheQUICDependency(t *testing.T) {
	t.Parallel()

	path := filepath.Join(filepath.Dir(engineGoMod(t)), "hack", "h3probe", "go.mod")
	var found string
	for _, req := range requirements(t, path) {
		if strings.Contains(req, quicMarker) {
			found = req
			break
		}
	}
	if found == "" {
		t.Fatalf("%s requires no QUIC implementation.\n"+
			"h3probe is the QUIC test client; if it no longer needs one, the guard above has\n"+
			"nothing left to guard and both tests should go.", path)
	}
}

// engineGoMod walks up from the test's own directory to the engine module's
// go.mod. It refuses any other module's: the guard has to be reading the file
// that describes the shipped binary, and a nested module's go.mod (h3probe's,
// for one) would pass the check while proving nothing.
func engineGoMod(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting the working directory: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(candidate); err == nil {
			if got := modulePath(t, candidate); got != engineModulePath {
				t.Fatalf("walked up from %s to %s, which declares module %q, want %q",
					must(os.Getwd()), candidate, got, engineModulePath)
			}
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", must(os.Getwd()))
		}
		dir = parent
	}
}

// modulePath returns the path a go.mod declares.
func modulePath(t *testing.T, path string) string {
	t.Helper()

	for _, line := range lines(t, path) {
		if rest, ok := strings.CutPrefix(line, "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	t.Fatalf("%s declares no module path", path)
	return ""
}

// requirements returns the module path of every requirement in a go.mod, from
// both forms (`require path version` and a `require ( … )` block), plus the
// right-hand side of every replace. A comment naming a module — this file's own
// prose, quoted in a go.mod, for instance — is not a requirement and is not
// returned.
func requirements(t *testing.T, path string) []string {
	t.Helper()

	var reqs []string
	inBlock := false
	for _, line := range lines(t, path) {
		switch {
		case inBlock:
			if line == ")" {
				inBlock = false
				continue
			}
			if p := firstField(line); p != "" {
				reqs = append(reqs, p)
			}
		case line == "require (" || line == "replace (":
			inBlock = true
		case strings.HasPrefix(line, "require ") || strings.HasPrefix(line, "replace "):
			_, rest, _ := strings.Cut(line, " ")
			if p := firstField(rest); p != "" {
				reqs = append(reqs, p)
			}
		}
		// A replace's target is the module actually built, so both sides of an
		// arrow count; firstField above takes the left, this takes the right.
		if _, target, ok := strings.Cut(line, "=> "); ok {
			if p := firstField(target); p != "" {
				reqs = append(reqs, p)
			}
		}
	}
	if len(reqs) == 0 {
		t.Fatalf("%s parsed to no requirements at all; the guard is reading it wrong", path)
	}
	return reqs
}

// lines returns path's lines, trimmed, with comments and blanks dropped.
func lines(t *testing.T, path string) []string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out []string
	for line := range strings.Lines(string(b)) {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// firstField is the module path at the head of a go.mod line.
func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func must(s string, err error) string {
	if err != nil {
		return "the working directory"
	}
	return s
}

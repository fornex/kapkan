package dataplane

// Drift gate for the committed BPF artifacts.
//
// kapkanxdp_bpfel.o and kapkanxdp_bpfel.go are generated from bpf/kapkan_xdp.c
// and committed, because clang is a contributor/CI dependency and never an
// operator one (`make build` works on a box with nothing but Go). That makes
// the committed object — not the C — the thing that actually runs in an
// operator's kernel. If the two ever disagree, every other test in this package
// is testing a binary that no longer corresponds to the source it is reviewed
// against, and a change reviewed on the C side silently never ships.
//
// So: recompile the C and byte-compare, exactly as TestSchemaMatchesGenerated
// does for docs/config-schema.json.
//
// This test SELF-SKIPS when the toolchain is absent, which is the normal case
// on a contributor's machine and inside the alpine container `make
// dataplane-test` uses. A skipping gate gates nothing, so CI sets
// KAPKAN_BPF_DRIFT=require, which turns every skip in this file into a
// failure. See the `bpf` job in .github/workflows/ci.yml.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// pinnedClangMajor is the LLVM major version the committed artifacts were
// generated with. It is pinned rather than "whatever clang you have" because
// this gate compares BYTES: a different LLVM major reorders instructions and
// renumbers BTF for reasons that have nothing to do with kapkan_xdp.c, and the
// resulting failure would read as source drift when it is a toolchain
// difference. CI installs exactly this major; see the bpf job.
//
// Verified portable across hosts at this major: Homebrew clang 21.1.8 on
// darwin/x86_64 and Ubuntu 24.04's apt.llvm.org clang 21.1.8 on linux/aarch64
// produce a byte-identical object. bpf2go is what makes that true — it passes
// -fno-ident, -fdebug-prefix-map and -fdebug-compilation-dir precisely so the
// output does not depend on the compiler build or the checkout path.
const pinnedClangMajor = 21

// objectClangVersion is the full version of the compiler that produced the
// committed artifacts. Unlike the major it is advisory: a patch-release bump is
// allowed to run the comparison, and this value only exists so that a byte
// mismatch can say "you have 21.1.9, the object was built with 21.1.8" instead
// of leaving the reader to guess whether the C really changed.
const objectClangVersion = "21.1.8"

// generatedFiles are the artifacts `make dataplane-sync` writes. Both are
// compared: the .o is what the kernel runs, and the .go carries the BTF-derived
// struct declarations the map encoders are built on, so a silent layout change
// has to show up in one or the other.
var generatedFiles = []string{"kapkanxdp_bpfel.o", "kapkanxdp_bpfel.go"}

// bpf2goArgs is the generate invocation minus -output-dir. It must stay
// identical to the //go:generate line in gen.go; TestGenerateDirectiveMatches
// enforces that rather than trusting a comment.
var bpf2goArgs = []string{
	"run", "github.com/cilium/ebpf/cmd/bpf2go",
	"-target", "bpfel",
	"-output-stem", "kapkanxdp",
	"-type", "kapkan_rule",
	"-type", "kapkan_policy_block",
	"-type", "kapkan_profile",
	"-type", "kapkan_bucket",
	"-type", "kapkan_config",
	"-type", "kapkan_counter",
	"-type", "kapkan_lpm_key_v4",
	"-type", "kapkan_lpm_key_v6",
	"-type", "kapkan_rl_key_v4",
	"-type", "kapkan_rl_key_v6",
	"-type", "kapkan_fp_event",
	"kapkanXDP", "../../bpf/kapkan_xdp.c",
	"--", "-I../../bpf/include", "-O2", "-g", "-Wall", "-Werror", "-mcpu=v2",
}

// skipUnlessRequired skips, or fails if CI asked for the gate to be enforced.
func skipUnlessRequired(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv("KAPKAN_BPF_DRIFT") == "require" {
		t.Fatalf("KAPKAN_BPF_DRIFT=require but the drift gate cannot run: %s", msg)
	}
	t.Skipf("%s; set BPF_CLANG/BPF_STRIP or run `make dataplane-sync` to check by hand", msg)
}

// clangCandidates lists where a bpf-capable clang of the pinned major lives, in
// order of preference. Apple's /usr/bin/clang is deliberately never a candidate
// under any name — it has no bpf target at all — but it is also never reached,
// because every candidate has its version checked before use.
func clangCandidates() [][2]string {
	if cc := os.Getenv("BPF_CLANG"); cc != "" {
		return [][2]string{{cc, os.Getenv("BPF_STRIP")}}
	}
	if cc := os.Getenv("BPF2GO_CC"); cc != "" {
		return [][2]string{{cc, os.Getenv("BPF2GO_STRIP")}}
	}
	v := strconv.Itoa(pinnedClangMajor)
	return [][2]string{
		// Debian/Ubuntu apt.llvm.org layout — what CI installs.
		{"clang-" + v, "llvm-strip-" + v},
		// Homebrew, Intel and Apple Silicon prefixes.
		{"/usr/local/opt/llvm@" + v + "/bin/clang", "/usr/local/opt/llvm@" + v + "/bin/llvm-strip"},
		{"/opt/homebrew/opt/llvm@" + v + "/bin/clang", "/opt/homebrew/opt/llvm@" + v + "/bin/llvm-strip"},
		// Last resort: an unsuffixed clang, accepted only if its version matches.
		{"clang", "llvm-strip"},
	}
}

var clangVersionRE = regexp.MustCompile(`clang version (\d+)\.(\d+)\.(\d+)`)

// clangVersion returns the full version string reported by cc.
func clangVersion(cc string) (full string, major int, err error) {
	out, err := exec.Command(cc, "--version").Output()
	if err != nil {
		return "", 0, err
	}
	m := clangVersionRE.FindSubmatch(out)
	if m == nil {
		return "", 0, fmt.Errorf("no version in %q", firstLine(out))
	}
	major, err = strconv.Atoi(string(m[1]))
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%s.%s.%s", m[1], m[2], m[3]), major, nil
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// findToolchain resolves a clang/llvm-strip pair of the pinned major, or skips.
func findToolchain(t *testing.T) (cc, strip, version string) {
	t.Helper()

	var tried []string
	for _, pair := range clangCandidates() {
		path, err := exec.LookPath(pair[0])
		if err != nil {
			tried = append(tried, pair[0]+" (not found)")
			continue
		}
		full, major, err := clangVersion(path)
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (%v)", path, err))
			continue
		}
		if major != pinnedClangMajor {
			tried = append(tried, fmt.Sprintf("%s (clang %s, want major %d)", path, full, pinnedClangMajor))
			continue
		}
		stripPath, err := exec.LookPath(pair[1])
		if err != nil {
			tried = append(tried, fmt.Sprintf("%s (found, but %s is missing)", path, pair[1]))
			continue
		}
		return path, stripPath, full
	}

	skipUnlessRequired(t, "no clang %d found (tried: %s)", pinnedClangMajor, strings.Join(tried, ", "))
	return "", "", ""
}

// TestGeneratedArtifactsMatchSource is the gate. It re-runs bpf2go — the real
// generator, not a hand-copied clang line, so it cannot drift from `make
// dataplane-sync` — into a temp dir and byte-compares both outputs.
//
// bpf2go's -output-dir moves only the destination; the process working
// directory stays this package, which is what keeps the result byte-identical
// to the committed one (the compilation dir and the debug prefix map are
// derived from cwd).
func TestGeneratedArtifactsMatchSource(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		// The cross-compiled binary run by `make dataplane-test` lands in a
		// container with a kernel but no toolchain. Nothing to do there.
		skipUnlessRequired(t, "no go toolchain on PATH (%v)", err)
	}
	cc, strip, version := findToolchain(t)
	t.Logf("regenerating with %s (clang %s) + %s on %s/%s",
		cc, version, strip, runtime.GOOS, runtime.GOARCH)

	out := t.TempDir()
	// Insert -output-dir directly after the bpf2go package path: before it and
	// `go run` would eat the flag, after the positional ident and bpf2go's own
	// flag parsing has already stopped.
	args := make([]string, 0, len(bpf2goArgs)+2)
	args = append(args, bpf2goArgs[:2]...)
	args = append(args, "-output-dir", out)
	args = append(args, bpf2goArgs[2:]...)

	cmd := exec.Command("go", args...)
	cmd.Dir = "." // must be the package dir; see the doc comment above.
	cmd.Env = append(os.Environ(),
		"GOPACKAGE=dataplane", // go generate sets this; bpf2go refuses without it
		"BPF2GO_CC="+cc,
		"BPF2GO_STRIP="+strip,
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bpf2go failed (this is a broken build, not drift): %v\n%s", err, combined)
	}

	for _, name := range generatedFiles {
		want, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read committed %s: %v", name, err)
		}
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("read regenerated %s: %v", name, err)
		}
		if bytes.Equal(want, got) {
			t.Logf("%s matches (%d bytes, sha256 %s)", name, len(want), sum(want))
			continue
		}
		t.Errorf(`%s is stale: the committed artifact does not match a rebuild of bpf/.

  committed:   %6d bytes  sha256 %s
  regenerated: %6d bytes  sha256 %s

The committed object is what an operator's kernel actually runs, so the C
source having moved on is a shipping bug, not a cosmetic one. Fix with:

    cd engine && make dataplane-sync && git add internal/dataplane/kapkanxdp_bpfel.*

If bpf/ genuinely did not change, suspect the compiler: this rebuild used
clang %s and the committed artifacts were built with clang %s. A patch-release
difference is enough to move bytes; regenerate and commit in that case too, and
update objectClangVersion.`,
			name, len(want), sum(want), len(got), sum(got), version, objectClangVersion)
	}
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// TestGenerateDirectiveMatches keeps bpf2goArgs honest. The gate is only a gate
// if it compiles the C the way `go generate` does; if someone adds a -type to
// gen.go and not here, this test would happily "verify" an object built from a
// different invocation than the committed one and pass on a mismatch it caused
// itself. Needs no toolchain, so it runs everywhere.
func TestGenerateDirectiveMatches(t *testing.T) {
	b, err := os.ReadFile("gen.go")
	if err != nil {
		t.Fatalf("read gen.go: %v", err)
	}
	const marker = "//go:generate go run github.com/cilium/ebpf/cmd/bpf2go "
	i := strings.Index(string(b), marker)
	if i < 0 {
		t.Fatalf("no bpf2go //go:generate directive in gen.go")
	}
	got := string(b)[i+len("//go:generate "):]
	if j := strings.IndexByte(got, '\n'); j >= 0 {
		got = got[:j]
	}
	got = strings.TrimSpace(got)

	want := "go " + strings.Join(bpf2goArgs, " ")
	if got != want {
		t.Errorf("gen.go's //go:generate and objects_test.go's bpf2goArgs disagree.\n"+
			"gen.go:     %s\nbpf2goArgs: %s\n"+
			"Keep them identical or the drift gate checks the wrong build.", got, want)
	}
}

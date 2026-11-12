package steer_test

// The gates: the E7 invariants that live in this package's shape rather than
// in its behaviour (package doc, THE CONTRACT). A well-meant change can break
// any of them without a behavioural test noticing — a fifth trigger "for
// completeness", an import that makes a helper shorter, a unit line that
// unblocks a library — so each is pinned here, and each failure says which
// invariant broke and why it exists.
//
//   - I2, the closed trigger set: Triggers has exactly Refused, NotTLS,
//     Unbound and Drained, all plain bool, in that order. A new field is a
//     new way out of service, and that is a design round, not a field: the
//     failure message is the review rule.
//   - I4, the leaf: steer's transitive imports are the standard library and
//     internal/edge/apply, on every GOOS `make lint` builds.
//   - I1, no route builder: no internal/edge package imports gobgp or
//     internal/mitigate directly, and kapkan-edge.service grants no
//     AF_NETLINK.
//
// The import gates ask the go tool, as internal/app's storage gate does: the
// toolchain's own reading of the build — build tags, GOOS, the standard
// library's vendored packages — is the one that ships, and a hand-rolled
// import scanner would drift from it.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

const (
	// gateModule is the engine module, as engine/go.mod declares it. The gates
	// name packages by import path, so `go list` resolves them from any
	// directory inside the module — this package's, where `go test` runs.
	gateModule = "github.com/kapkan-io/kapkan"
	gateSteer  = gateModule + "/internal/edge/steer"
	gateApply  = gateModule + "/internal/edge/apply"
)

// gateGOOS are the GOOS values `make lint` type-checks: a build-tagged file
// is invisible to the other one, and an import hidden in a _linux.go file is
// still an import.
var gateGOOS = []string{"linux", "darwin"}

// gateTriggerFields is the closed trigger set, in declaration order. Editing
// this list is editing E7; gateReviewRule says when that is allowed.
var gateTriggerFields = []string{"Refused", "NotTLS", "Unbound", "Drained"}

// gateReviewRule is the E7 review rule (the design's §1, in the words of the
// package doc), printed when the pin fails: the person changing Triggers is
// the one who must read it.
const gateReviewRule = `Triggers changed. The E7 review rule: an input may withdraw an address only
if its "no" means this box certainly will not complete TCP+TLS on that
address. Anything Kapkan computes, the brain sends or a client can provoke
may delay a join, never cause a withdrawal; unknown means hold. A new way out
of service is a design round (edge-spec §8, E7), not a field — if this change
is that round's outcome, update this test with it.`

// TestGateTriggersAreTheClosedSet pins Triggers field by field (I2). The
// automaton's only way out of service reads Triggers, so its fields are the
// whole list of what can withdraw an address; the pin is what makes that
// list a reviewed decision rather than a struct anyone may grow. A field that
// is not a plain bool fails too: a named type could carry methods, and a
// nested struct could carry triggers of its own.
func TestGateTriggersAreTheClosedSet(t *testing.T) {
	typ := reflect.TypeOf(steer.Triggers{})
	var got []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		desc := f.Name
		if f.Type != reflect.TypeOf(false) {
			desc += " (" + f.Type.String() + ", not bool)"
		}
		if f.Anonymous {
			desc += " (embedded)"
		}
		got = append(got, desc)
	}
	if !slices.Equal(got, gateTriggerFields) {
		t.Fatalf("steer.Triggers has the fields\n\t%s\nwant exactly\n\t%s\nall plain bool, in this order.\n\n%s",
			strings.Join(got, ", "), strings.Join(gateTriggerFields, ", "), gateReviewRule)
	}
}

// TestGateSteerIsALeaf is I4: every package steer depends on, transitively,
// is the standard library or internal/edge/apply. The leaf is what keeps the
// verdict out of the brain's reach (I5) — no document type, no API route and
// no lever can arrive through an import — and what keeps a route builder out
// of the process that testifies (I1). The standard library's vendored
// golang.org/x packages are reported as standard by the go tool, and are.
func TestGateSteerIsALeaf(t *testing.T) {
	gateNeedGo(t)
	for _, goos := range gateGOOS {
		std := map[string]bool{}
		imports := map[string][]string{}
		for _, line := range gateList(t, goos, "-deps", "-f", "{{.ImportPath}} {{.Standard}}{{range .Imports}} {{.}}{{end}}", gateSteer) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				t.Fatalf("GOOS=%s: unexpected go list line %q", goos, line)
			}
			std[fields[0]] = fields[1] == "true"
			imports[fields[0]] = fields[2:]
		}
		if _, ok := std[gateSteer]; !ok {
			t.Fatalf("GOOS=%s: go list -deps %s did not list the package itself; the gate is reading the wrong output", goos, gateSteer)
		}
		var outside []string
		for pkg, isStd := range std {
			if !isStd && pkg != gateSteer && pkg != gateApply {
				outside = append(outside, pkg)
			}
		}
		slices.Sort(outside)
		for _, pkg := range outside {
			t.Errorf("GOOS=%s: steer depends on %s, through\n\t%s\n"+
				"I4: steer is a leaf — its transitive imports are the standard library and internal/edge/apply.\n"+
				"The brain must have no path to the verdict (I5) and the edge process no route builder (I1); the\n"+
				"node hands steer data (the live zones, the rendered :443 zones), never a package to import.",
				goos, pkg, strings.Join(gateChain(imports, gateSteer, pkg), "\n\t→ "))
		}
	}
}

// gateRouteBuilders are the import paths I1 bars from internal/edge: the BGP
// implementation, under any major version, and the brain's mitigation tree,
// which drives it.
var gateRouteBuilders = []string{"github.com/osrg/gobgp", gateModule + "/internal/mitigate"}

// TestGateEdgeImportsNoRouteBuilder is the import half of I1: no package
// under internal/edge imports gobgp or internal/mitigate directly. Kapkan
// never speaks BGP on an edge node and never names a prefix — the node
// testifies, the operator's speaker announces (edge-spec §8, E7) — and the
// first step towards breaking that would be exactly such an import.
//
// The gate is on direct imports of the shipped code, as internal/app's
// storage gate is: internal/edge/node imports internal/api for the types it
// shares with the brain, internal/api reaches internal/mitigate, so gobgp is
// in the node's transitive graph — known, and harmless while nothing on the
// edge side calls it; the one binary links every role. What must not happen
// is edge code naming a route builder itself.
func TestGateEdgeImportsNoRouteBuilder(t *testing.T) {
	gateNeedGo(t)
	for _, goos := range gateGOOS {
		listed := false
		for _, line := range gateList(t, goos, "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", gateModule+"/internal/edge/...") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			listed = listed || fields[0] == gateSteer
			for _, imp := range fields[1:] {
				if gateBuildsRoutes(imp) {
					t.Errorf("GOOS=%s: %s imports %s.\n"+
						"I1: Kapkan builds no route — no internal/edge package imports gobgp or internal/mitigate\n"+
						"directly. Kapkan never speaks BGP on an edge node and never names a prefix: the node\n"+
						"testifies to its own fitness, the operator's speaker announces (edge-spec §8, E7).",
						goos, fields[0], imp)
				}
			}
		}
		if !listed {
			t.Fatalf("GOOS=%s: go list %s/internal/edge/... did not list %s; the gate is reading the wrong output", goos, gateModule, gateSteer)
		}
	}
}

// gateBuildsRoutes reports whether an import path is one of
// gateRouteBuilders or a package below one.
func gateBuildsRoutes(imp string) bool {
	for _, p := range gateRouteBuilders {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return true
		}
	}
	return false
}

// gateUnit is the edge role's systemd unit, from this package's directory.
var gateUnit = filepath.Join("..", "..", "..", "deploy", "kapkan-edge.service")

// TestGateEdgeUnitGrantsNoNetlink is the unit half of I1: kapkan-edge.service
// restricts its address families to an allow list without AF_NETLINK. Netlink
// is how a process writes routes and addresses; the edge role reads the
// kernel's addresses and listeners from /proc instead (D5), so the unit can
// keep it closed — and a later wish to open it is a design question, which
// this failure raises. Every RestrictAddressFamilies= line counts: an empty
// one resets the restriction, and a ~ deny list grants whatever it does not
// name, so either grants AF_NETLINK as surely as naming it.
func TestGateEdgeUnitGrantsNoNetlink(t *testing.T) {
	b, err := os.ReadFile(gateUnit)
	if err != nil {
		t.Fatalf("reading the edge unit: %v", err)
	}
	const why = "I1: Kapkan builds no route — kapkan-edge.service grants no AF_NETLINK; the edge role reads\n" +
		"/proc, never netlink (D5)."
	assignments := 0
	for _, line := range gateUnitLines(string(b)) {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "RestrictAddressFamilies" {
			continue
		}
		assignments++
		value = strings.TrimSpace(value)
		switch {
		case value == "":
			t.Errorf("%s: an empty RestrictAddressFamilies= resets the restriction, granting every family.\n%s", gateUnit, why)
		case strings.HasPrefix(value, "~"):
			t.Errorf("%s: RestrictAddressFamilies=%s is a deny list, granting every family it does not name.\n%s", gateUnit, value, why)
		case slices.Contains(strings.Fields(value), "AF_NETLINK"):
			t.Errorf("%s: RestrictAddressFamilies=%s grants AF_NETLINK.\n%s", gateUnit, value, why)
		}
	}
	if assignments == 0 {
		t.Errorf("%s has no RestrictAddressFamilies=, so it grants every family.\n%s", gateUnit, why)
	}
}

// gateUnitLines returns a unit file's logical lines as systemd reads them:
// comment lines (# or ;) are dropped, even inside a continued line, and a
// trailing backslash continues a line with a space.
func gateUnitLines(text string) []string {
	var out []string
	cur := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if cont, ok := strings.CutSuffix(line, `\`); ok {
			cur += cont + " "
			continue
		}
		out = append(out, cur+line)
		cur = ""
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// gateNeedGo skips a gate that asks the go tool when none is on PATH — a test
// binary cross-compiled into a container has none — except under CI, where a
// runner without one is broken and a skip would pass for a green gate.
func gateNeedGo(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI is set but no go tool is on PATH (%v): the import gates cannot run", err)
		}
		t.Skipf("no go tool on PATH (%v): the import gates need `go list`", err)
	}
}

// gateList runs `go list` for goos and returns its lines. CGO_ENABLED=0 is
// how the release binary is built. -mod=readonly, on the command line so it
// overrides whatever GOFLAGS the caller exported (-mod=mod would let go list
// add hashes to go.sum), keeps the gate from ever writing go.mod or go.sum.
func gateList(t *testing.T, goos string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-mod=readonly"}, args...)...)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = ee.Stderr
		}
		t.Fatalf("go list %s (GOOS=%s): %v\n%s", strings.Join(args, " "), goos, err, stderr)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// gateChain is an import path from from to to in a `go list -deps` graph —
// which of steer's imports pulled a package in, for the failure message.
func gateChain(imports map[string][]string, from, to string) []string {
	prev := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if pkg == to {
			var chain []string
			for ; pkg != ""; pkg = prev[pkg] {
				chain = append(chain, pkg)
			}
			slices.Reverse(chain)
			return chain
		}
		for _, imp := range imports[pkg] {
			if _, seen := prev[imp]; !seen {
				prev[imp] = pkg
				queue = append(queue, imp)
			}
		}
	}
	return []string{from, "…", to}
}

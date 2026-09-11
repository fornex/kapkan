package app

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestNodeSidePackagesNeverImportStorage is the import-direction gate of the
// edge history (E6.5): the node-side code (internal/edge/...) and the
// mitigator (internal/mitigate/...) run on boxes that must never learn about
// ClickHouse — the brain stores, the nodes report. No package in either tree
// may IMPORT internal/storage: a row type or a writer reaching a node is a
// design regression, not a build error, so this pins it.
//
// The gate is on direct imports. internal/edge/node imports internal/api for
// the report and document types it shares with the brain, and internal/api
// imports internal/storage (it is the brain's writer), so the TRANSITIVE
// dependency exists and is known; the single binary links every package
// anyway. What must not happen is node-side code naming storage itself.
func TestNodeSidePackagesNeverImportStorage(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	// The test runs in the package directory; the relative patterns need the
	// module root as cwd.
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	// Both GOOS the Makefile lints for: a build-tagged file is invisible to
	// the other one.
	for _, goos := range []string{"linux", "darwin"} {
		for _, tree := range []string{"./internal/edge/...", "./internal/mitigate/..."} {
			cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, tree)
			cmd.Dir = strings.TrimSpace(string(root))
			cmd.Env = append(os.Environ(), "GOOS="+goos)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list %s (GOOS=%s): %v", tree, goos, err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				for _, imp := range fields[1:] {
					if strings.HasSuffix(imp, "/internal/storage") || strings.Contains(imp, "/internal/storage/") {
						t.Fatalf("%s imports %s (GOOS=%s) — node-side code must never know about the brain's storage", fields[0], imp, goos)
					}
				}
			}
		}
	}
}

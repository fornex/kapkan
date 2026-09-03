package apply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The E3 acceptance rig (and the first draft of the install guide) created
// `live` by hand as a directory so nginx's wildcard include would compile
// before the first render; a rename cannot replace a directory with a symlink,
// so every install failed with "file exists" and the node never served
// anything. An empty directory is now removed; a populated one is refused
// with a message that names it.
func TestApplyReplacesAnEmptyLiveDirectory(t *testing.T) {
	a, _, _ := newApplier(t)
	if err := os.MkdirAll(filepath.Join(a.Root, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := mustApply(t, a, "a")
	if res.Generation != 1 || !res.Reloaded {
		t.Fatalf("Result = %+v", res)
	}
	if got := liveTarget(t, a.Root); got != "gen-000001" {
		t.Fatalf("live -> %q", got)
	}
}

func TestApplyRefusesAPopulatedLiveDirectory(t *testing.T) {
	a, ft, fr := newApplier(t)
	if err := os.MkdirAll(filepath.Join(a.Root, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.Root, "live", "theirs.conf"), []byte("# operator's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := a.Apply(context.Background(), files("a"))
	if err == nil || !strings.Contains(err.Error(), "is a directory with 1 entries") {
		t.Fatalf("err = %v", err)
	}
	if ft.calls != 0 || fr.calls != 0 {
		t.Fatalf("tested (%d) or reloaded (%d) with a foreign live directory in place", ft.calls, fr.calls)
	}
	if _, err := os.Stat(filepath.Join(a.Root, "live", "theirs.conf")); err != nil {
		t.Fatalf("the operator's file was touched: %v", err)
	}
}

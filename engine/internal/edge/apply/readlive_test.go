package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type liveRead struct {
	gen    uint64
	tested bool
	err    error
}

// The steering join gate reads `live` every second (internal/edge/steer), so
// ReadLive must answer while Apply holds the mutex through `nginx -t` — and
// what it must answer there is the untested candidate.
func TestReadLiveAnswersDuringTheTestWithoutTheLock(t *testing.T) {
	a, ft, _ := newApplier(t)
	mustApply(t, a, "a")

	var during liveRead
	ft.onTest = func() {
		got := make(chan liveRead, 1)
		go func() {
			gen, tested, err := ReadLive(a.Root)
			got <- liveRead{gen, tested, err}
		}()
		select {
		case during = <-got:
		case <-time.After(5 * time.Second):
			t.Error("ReadLive blocked while Apply held the mutex through the test")
		}
	}
	mustApply(t, a, "b")
	if during.err != nil || during.gen != 2 || during.tested {
		t.Fatalf("during the test: ReadLive = %+v, want generation 2, untested", during)
	}
	if gen, tested, err := ReadLive(a.Root); err != nil || gen != 2 || !tested {
		t.Fatalf("after the test: ReadLive = (%d, %v, %v), want (2, true, nil)", gen, tested, err)
	}
}

func TestReadLiveAfterAFailedTestNamesTheRestoredGeneration(t *testing.T) {
	a, ft, _ := newApplier(t)
	mustApply(t, a, "a")
	ft.fail = errors.New("nginx: [emerg] unexpected end of file")
	if _, err := a.Apply(context.Background(), files("b")); !errors.Is(err, ErrTestFailed) {
		t.Fatalf("Apply = %v, want ErrTestFailed", err)
	}
	if gen, tested, err := ReadLive(a.Root); err != nil || gen != 1 || !tested {
		t.Fatalf("ReadLive = (%d, %v, %v), want the restored (1, true, nil)", gen, tested, err)
	}
}

func TestReadLiveWithoutAGenerationOfOurs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conf")
	if gen, tested, err := ReadLive(root); !errors.Is(err, os.ErrNotExist) || gen != 0 || tested {
		t.Fatalf("fresh node: ReadLive = (%d, %v, %v), want (0, false, ErrNotExist)", gen, tested, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "theirs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "theirs", testedMarker), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("theirs", filepath.Join(root, liveLink)); err != nil {
		t.Fatal(err)
	}
	if gen, tested, err := ReadLive(root); err != nil || gen != 0 || tested {
		t.Fatalf("foreign link: ReadLive = (%d, %v, %v), want (0, false, nil)", gen, tested, err)
	}
}

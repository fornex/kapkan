package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTester records what `live` pointed at while it ran — the property the
// gate depends on — and fails on demand.
type fakeTester struct {
	root    string
	fail    error
	calls   int
	sawLive []string
}

func (f *fakeTester) Test(context.Context) error {
	f.calls++
	target, _ := os.Readlink(filepath.Join(f.root, liveLink))
	f.sawLive = append(f.sawLive, target)
	return f.fail
}

type fakeReloader struct {
	fail  error
	calls int
}

func (f *fakeReloader) Reload(context.Context) error {
	f.calls++
	return f.fail
}

func newApplier(t *testing.T) (*Applier, *fakeTester, *fakeReloader) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "conf")
	ft := &fakeTester{root: root}
	fr := &fakeReloader{}
	return &Applier{Root: root, Tester: ft, Reloader: fr, MinInterval: time.Millisecond}, ft, fr
}

func files(tag string) map[string][]byte {
	return map[string][]byte{
		"kapkan_00_common.conf":        []byte("# common " + tag + "\n"),
		"kapkan_zone_example.com.conf": []byte("# zone " + tag + "\n"),
	}
}

func liveTarget(t *testing.T, root string) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(root, liveLink))
	if err != nil {
		return ""
	}
	return target
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestApplyInstallsFirstGeneration(t *testing.T) {
	a, ft, fr := newApplier(t)
	res, err := a.Apply(context.Background(), files("a"))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := Result{Generation: 1, Hash: Hash(files("a")), Changed: true, TestOK: true, Reloaded: true}
	if res != want {
		t.Fatalf("Result = %+v, want %+v", res, want)
	}
	if got := liveTarget(t, a.Root); got != "gen-000001" {
		t.Fatalf("live -> %q", got)
	}
	if ft.calls != 1 || ft.sawLive[0] != "gen-000001" {
		t.Fatalf("tester calls=%d sawLive=%v; the test must run with the candidate live", ft.calls, ft.sawLive)
	}
	if fr.calls != 1 {
		t.Fatalf("reloader calls = %d", fr.calls)
	}
	for name, content := range files("a") {
		got, err := os.ReadFile(filepath.Join(a.Root, "live", name))
		if err != nil || string(got) != string(content) {
			t.Fatalf("live/%s = %q, %v", name, got, err)
		}
	}
	if !exists(filepath.Join(a.Root, "gen-000001", manifestFile)) {
		t.Fatal("no manifest written")
	}
	if !exists(filepath.Join(a.Root, "gen-000001.tmp")) == false {
		t.Fatal("temporary directory left behind")
	}
}

func TestApplyUnchangedIsANoop(t *testing.T) {
	a, ft, fr := newApplier(t)
	if _, err := a.Apply(context.Background(), files("a")); err != nil {
		t.Fatal(err)
	}
	res, err := a.Apply(context.Background(), files("a"))
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if res.Changed || res.Generation != 1 || !res.TestOK || res.Reloaded {
		t.Fatalf("Result = %+v; want unchanged generation 1", res)
	}
	if ft.calls != 1 || fr.calls != 1 {
		t.Fatalf("unchanged render caused test=%d reload=%d", ft.calls, fr.calls)
	}
	if exists(filepath.Join(a.Root, "gen-000002")) {
		t.Fatal("a generation was written for an unchanged render")
	}
}

func TestApplyFailedTestKeepsPreviousGenerationLive(t *testing.T) {
	a, ft, fr := newApplier(t)
	if _, err := a.Apply(context.Background(), files("a")); err != nil {
		t.Fatal(err)
	}
	ft.fail = errors.New(`nginx: [emerg] unknown directive "bogus" in /conf/live/kapkan_zone_example.com.conf:1`)
	res, err := a.Apply(context.Background(), files("b"))
	if !errors.Is(err, ErrTestFailed) {
		t.Fatalf("err = %v, want ErrTestFailed", err)
	}
	if !strings.Contains(err.Error(), "unknown directive") || !strings.Contains(res.TestError, "unknown directive") {
		t.Fatalf("tester message lost: err=%v TestError=%q", err, res.TestError)
	}
	if res.Generation != 1 || !res.Changed || res.TestOK || res.Reloaded {
		t.Fatalf("Result = %+v; want generation 1 still live, test failed, no reload", res)
	}
	if got := liveTarget(t, a.Root); got != "gen-000001" {
		t.Fatalf("live -> %q after a failed test", got)
	}
	if ft.sawLive[1] != "gen-000002" {
		t.Fatalf("the candidate was not live during its test: %v", ft.sawLive)
	}
	if exists(filepath.Join(a.Root, "gen-000002")) {
		t.Fatal("failed candidate still present as a passed generation")
	}
	got, err := os.ReadFile(filepath.Join(a.Root, "failed-000002", "kapkan_zone_example.com.conf"))
	if err != nil || string(got) != "# zone b\n" {
		t.Fatalf("failed candidate not kept for inspection: %q, %v", got, err)
	}
	if fr.calls != 1 {
		t.Fatalf("reload ran after a failed test (calls=%d)", fr.calls)
	}
	// Numbers are never reused: the next passing candidate is generation 3.
	ft.fail = nil
	res, err = a.Apply(context.Background(), files("c"))
	if err != nil || res.Generation != 3 {
		t.Fatalf("after recovery: %+v, %v", res, err)
	}
	if got := liveTarget(t, a.Root); got != "gen-000003" {
		t.Fatalf("live -> %q", got)
	}
}

func TestApplyFirstFailureLeavesNothingLive(t *testing.T) {
	a, ft, _ := newApplier(t)
	ft.fail = errors.New("boom")
	res, err := a.Apply(context.Background(), files("a"))
	if !errors.Is(err, ErrTestFailed) {
		t.Fatalf("err = %v", err)
	}
	if res.Generation != 0 || liveTarget(t, a.Root) != "" {
		t.Fatalf("Result = %+v live=%q; nothing must be live", res, liveTarget(t, a.Root))
	}
	if !exists(filepath.Join(a.Root, "failed-000001")) {
		t.Fatal("failed candidate not kept")
	}
	if _, _, ok := a.Live(); ok {
		t.Fatal("Live() reports a generation")
	}
}

func TestApplyReloadFailureKeepsTestedGenerationLive(t *testing.T) {
	a, _, fr := newApplier(t)
	fr.fail = errors.New("nginx -s reload: exit status 1: open() \"/run/nginx.pid\" failed")
	res, err := a.Apply(context.Background(), files("a"))
	if err == nil || errors.Is(err, ErrTestFailed) || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("err = %v", err)
	}
	if res.Generation != 1 || !res.TestOK || res.Reloaded {
		t.Fatalf("Result = %+v; want generation 1 live and tested, not reloaded", res)
	}
	if got := liveTarget(t, a.Root); got != "gen-000001" {
		t.Fatalf("live -> %q; a tested generation stays live when only the reload failed", got)
	}
}

func TestApplyPrunesOldGenerations(t *testing.T) {
	a, ft, _ := newApplier(t)
	a.Keep = 2
	for _, tag := range []string{"a", "b", "c", "d", "e"} {
		if _, err := a.Apply(context.Background(), files(tag)); err != nil {
			t.Fatal(err)
		}
	}
	for n, want := range map[string]bool{"gen-000001": false, "gen-000002": false, "gen-000003": true, "gen-000004": true, "gen-000005": true} {
		if got := exists(filepath.Join(a.Root, n)); got != want {
			t.Errorf("%s exists=%v, want %v", n, got, want)
		}
	}
	if got := liveTarget(t, a.Root); got != "gen-000005" {
		t.Fatalf("live -> %q", got)
	}
	// Failed candidates: only the newest is kept.
	ft.fail = errors.New("boom")
	for _, tag := range []string{"f", "g"} {
		if _, err := a.Apply(context.Background(), files(tag)); !errors.Is(err, ErrTestFailed) {
			t.Fatal(err)
		}
	}
	if exists(filepath.Join(a.Root, "failed-000006")) || !exists(filepath.Join(a.Root, "failed-000007")) {
		t.Fatal("failed generations not pruned to the newest")
	}
	if got := liveTarget(t, a.Root); got != "gen-000005" {
		t.Fatalf("live -> %q after failures", got)
	}
}

func TestApplyPacesAttempts(t *testing.T) {
	a, _, _ := newApplier(t)
	a.MinInterval = 300 * time.Millisecond
	if _, err := a.Apply(context.Background(), files("a")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := a.Apply(context.Background(), files("b")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Fatalf("second apply after %v; want the pacing interval", el)
	}
	// An unchanged render is answered at once — pacing is for attempts.
	start = time.Now()
	if _, err := a.Apply(context.Background(), files("b")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Fatalf("unchanged apply took %v", el)
	}
	// Cancellation while waiting installs nothing.
	a.MinInterval = 5 * time.Second
	if _, err := a.Apply(context.Background(), files("c")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := a.Apply(ctx, files("d"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if exists(filepath.Join(a.Root, "gen-000004")) {
		t.Fatal("a generation was written for a cancelled apply")
	}
}

func TestApplyRejectsBadInputs(t *testing.T) {
	good, _, _ := newApplier(t)
	cases := []struct {
		name    string
		mutate  func(a *Applier)
		files   map[string][]byte
		wantErr string
	}{
		{"relative root", func(a *Applier) { a.Root = "conf" }, files("a"), "absolute"},
		{"no tester", func(a *Applier) { a.Tester = nil }, files("a"), "no tester"},
		{"no reloader", func(a *Applier) { a.Reloader = nil }, files("a"), "no reloader"},
		{"no files", nil, map[string][]byte{}, "nothing to install"},
		{"path in name", nil, map[string][]byte{"../x.conf": nil}, "plain name"},
		{"dot name", nil, map[string][]byte{".kapkan-manifest": nil}, "must not start with a dot"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &Applier{Root: good.Root, Tester: good.Tester, Reloader: good.Reloader, MinInterval: time.Millisecond}
			if c.mutate != nil {
				c.mutate(a)
			}
			_, err := a.Apply(context.Background(), c.files)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestLiveSurvivesRestart(t *testing.T) {
	a, _, _ := newApplier(t)
	if _, err := a.Apply(context.Background(), files("a")); err != nil {
		t.Fatal(err)
	}
	// A fresh process over the same directory knows what is live without
	// re-rendering, and treats the same render as unchanged.
	b := &Applier{Root: a.Root, Tester: &fakeTester{root: a.Root}, Reloader: &fakeReloader{}, MinInterval: time.Millisecond}
	gen, hash, ok := b.Live()
	if !ok || gen != 1 || hash != Hash(files("a")) {
		t.Fatalf("Live() = %d %q %v", gen, hash, ok)
	}
	res, err := b.Apply(context.Background(), files("a"))
	if err != nil || res.Changed {
		t.Fatalf("Result = %+v, %v; want unchanged", res, err)
	}
	res, err = b.Apply(context.Background(), files("b"))
	if err != nil || res.Generation != 2 {
		t.Fatalf("Result = %+v, %v; want generation 2", res, err)
	}
}

func TestHashIsOrderIndependentAndShapeSensitive(t *testing.T) {
	a := map[string][]byte{"x": []byte("1"), "y": []byte("2")}
	b := map[string][]byte{"y": []byte("2"), "x": []byte("1")}
	if Hash(a) != Hash(b) {
		t.Fatal("hash depends on map order")
	}
	c := map[string][]byte{"x": []byte("12"), "y": []byte("")}
	if Hash(a) == Hash(c) {
		t.Fatal("hash must separate names from contents")
	}
}

func TestParseGen(t *testing.T) {
	for name, want := range map[string]uint64{"gen-000001": 1, "gen-42": 42, "gen-": 0, "gen-0": 0, "gen-1.tmp": 0, "gen-abc": 0, "failed-3": 0} {
		got, ok := parseGen(name, genPrefix)
		if (want == 0) == ok || got != want {
			t.Errorf("parseGen(%q) = %d,%v want %d", name, got, ok, want)
		}
	}
}

package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeTester records what `live` pointed at while it ran — the property the
// gate depends on — fails on demand, and can run a hook (to cancel a context).
type fakeTester struct {
	root    string
	fail    error
	calls   int
	sawLive []string
	onTest  func()
}

func (f *fakeTester) Test(ctx context.Context) error {
	f.calls++
	target, _ := os.Readlink(filepath.Join(f.root, liveLink))
	f.sawLive = append(f.sawLive, target)
	if f.onTest != nil {
		f.onTest()
	}
	if f.fail != nil {
		return f.fail
	}
	return ctx.Err()
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

func mustApply(t *testing.T, a *Applier, tag string) Result {
	t.Helper()
	res, err := a.Apply(context.Background(), files(tag))
	if err != nil {
		t.Fatalf("Apply(%s): %v", tag, err)
	}
	return res
}

func TestApplyInstallsFirstGeneration(t *testing.T) {
	a, ft, fr := newApplier(t)
	res := mustApply(t, a, "a")
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
	gen := filepath.Join(a.Root, "gen-000001")
	for _, marker := range []string{manifestFile, testedMarker, reloadedMarker} {
		if !exists(filepath.Join(gen, marker)) {
			t.Errorf("%s not written", marker)
		}
	}
	if exists(gen + ".tmp") {
		t.Fatal("temporary directory left behind")
	}
	if !exists(filepath.Join(a.Root, lockFile)) {
		t.Fatal("no lock file: applies are not serialised across processes")
	}
}

func TestApplyUnchangedIsANoop(t *testing.T) {
	a, ft, fr := newApplier(t)
	mustApply(t, a, "a")
	res := mustApply(t, a, "a")
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
	mustApply(t, a, "a")
	emerg := errors.New(`nginx -t: exit status 1: nginx: [emerg] unknown directive "bogus" in /conf/live/kapkan_zone_example.com.conf:1`)
	ft.fail = emerg
	res, err := a.Apply(context.Background(), files("b"))
	if !errors.Is(err, ErrTestFailed) || !errors.Is(err, emerg) {
		t.Fatalf("err = %v, want ErrTestFailed wrapping the tester's error", err)
	}
	if !strings.Contains(res.TestError, "unknown directive") || res.FailedZone != "example.com" {
		t.Fatalf("TestError=%q FailedZone=%q", res.TestError, res.FailedZone)
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
	res = mustApply(t, a, "c")
	if res.Generation != 3 || liveTarget(t, a.Root) != "gen-000003" {
		t.Fatalf("after recovery: %+v, live -> %q", res, liveTarget(t, a.Root))
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

// A previous `live` that is not a tested generation of ours — an operator's
// own link, or a generation whose manifest was lost — is put back exactly as
// it was when the candidate fails; it is never deleted.
func TestApplyRestoresWhateverLiveWasOnFailure(t *testing.T) {
	t.Run("foreign link", func(t *testing.T) {
		a, ft, _ := newApplier(t)
		if err := os.MkdirAll(filepath.Join(a.Root, "manual"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("manual", filepath.Join(a.Root, liveLink)); err != nil {
			t.Fatal(err)
		}
		ft.fail = errors.New("boom")
		res, err := a.Apply(context.Background(), files("a"))
		if !errors.Is(err, ErrTestFailed) {
			t.Fatalf("err = %v", err)
		}
		if got := liveTarget(t, a.Root); got != "manual" {
			t.Fatalf("live -> %q; the operator's link must be restored", got)
		}
		if res.Generation != 0 {
			t.Fatalf("Generation = %d for a foreign live link", res.Generation)
		}
		ft.fail = nil
		if res := mustApply(t, a, "a"); res.Generation != 2 || liveTarget(t, a.Root) != "gen-000002" {
			t.Fatalf("after the foreign link: %+v live -> %q", res, liveTarget(t, a.Root))
		}
	})
	t.Run("manifest lost", func(t *testing.T) {
		a, ft, _ := newApplier(t)
		mustApply(t, a, "a")
		if err := os.Remove(filepath.Join(a.Root, "gen-000001", manifestFile)); err != nil {
			t.Fatal(err)
		}
		ft.fail = errors.New("boom")
		res, err := a.Apply(context.Background(), files("b"))
		if !errors.Is(err, ErrTestFailed) {
			t.Fatalf("err = %v", err)
		}
		if got := liveTarget(t, a.Root); got != "gen-000001" || res.Generation != 1 {
			t.Fatalf("live -> %q, Generation %d; the tested generation must stay live", got, res.Generation)
		}
	})
}

// A generation `live` points at without the tested marker is what a crash
// between the swap and the test leaves behind. It is never trusted: an
// identical re-send is tested (as a new generation), not short-circuited.
func TestApplyDoesNotTrustAnUntestedLiveGeneration(t *testing.T) {
	a, ft, fr := newApplier(t)
	mustApply(t, a, "a")
	if err := os.Remove(filepath.Join(a.Root, "gen-000001", testedMarker)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := a.Live(); ok {
		t.Fatal("Live() trusts an untested generation")
	}
	res := mustApply(t, a, "a")
	if !res.Changed || res.Generation != 2 || ft.calls != 2 || fr.calls != 2 {
		t.Fatalf("Result = %+v tester=%d reloader=%d; want a fresh, tested generation 2", res, ft.calls, fr.calls)
	}
	if got := liveTarget(t, a.Root); got != "gen-000002" || !exists(filepath.Join(a.Root, "gen-000002", testedMarker)) {
		t.Fatalf("live -> %q (tested marker present: %v)", got, exists(filepath.Join(a.Root, "gen-000002", testedMarker)))
	}
}

func TestRecover(t *testing.T) {
	t.Run("nothing to do", func(t *testing.T) {
		a, ft, _ := newApplier(t)
		res, err := a.Recover(context.Background())
		if err != nil || res.Changed || ft.calls != 0 {
			t.Fatalf("empty root: %+v, %v, tester=%d", res, err, ft.calls)
		}
		mustApply(t, a, "a")
		res, err = a.Recover(context.Background())
		if err != nil || res.Changed || !res.TestOK || res.Generation != 1 || ft.calls != 1 {
			t.Fatalf("tested live: %+v, %v, tester=%d", res, err, ft.calls)
		}
	})
	t.Run("untested live passes", func(t *testing.T) {
		a, ft, _ := newApplier(t)
		mustApply(t, a, "a")
		_ = os.Remove(filepath.Join(a.Root, "gen-000001", testedMarker))
		_ = os.Remove(filepath.Join(a.Root, "gen-000001", reloadedMarker))
		_ = os.MkdirAll(filepath.Join(a.Root, "gen-000002.tmp"), 0o755) // a half-written candidate
		res, err := a.Recover(context.Background())
		if err != nil || !res.Changed || !res.TestOK || res.Generation != 1 || ft.calls != 2 {
			t.Fatalf("Recover: %+v, %v, tester=%d", res, err, ft.calls)
		}
		if !exists(filepath.Join(a.Root, "gen-000001", testedMarker)) || exists(filepath.Join(a.Root, "gen-000002.tmp")) {
			t.Fatal("marker not written or temporary directory not removed")
		}
		// It passed but was never reloaded: the next unchanged apply reloads it.
		fr := a.Reloader.(*fakeReloader)
		res = mustApply(t, a, "a")
		if res.Changed || !res.Reloaded || fr.calls != 2 {
			t.Fatalf("after Recover: %+v reloader=%d; want the pending reload", res, fr.calls)
		}
	})
	t.Run("untested live fails, older tested exists", func(t *testing.T) {
		a, ft, _ := newApplier(t)
		mustApply(t, a, "a")
		mustApply(t, a, "b")
		_ = os.Remove(filepath.Join(a.Root, "gen-000002", testedMarker))
		ft.fail = errors.New("nginx: [emerg] bad in /x/kapkan_zone_example.com.conf:3")
		res, err := a.Recover(context.Background())
		if !errors.Is(err, ErrTestFailed) || res.Generation != 1 || res.FailedZone != "example.com" {
			t.Fatalf("Recover: %+v, %v", res, err)
		}
		if got := liveTarget(t, a.Root); got != "gen-000001" {
			t.Fatalf("live -> %q; want the newest tested generation", got)
		}
		if exists(filepath.Join(a.Root, "gen-000002")) || !exists(filepath.Join(a.Root, "failed-000002")) {
			t.Fatal("untested candidate not moved aside as failed-000002")
		}
	})
	t.Run("untested live fails, nothing tested", func(t *testing.T) {
		a, ft, _ := newApplier(t)
		mustApply(t, a, "a")
		_ = os.Remove(filepath.Join(a.Root, "gen-000001", testedMarker))
		ft.fail = errors.New("boom")
		res, err := a.Recover(context.Background())
		if !errors.Is(err, ErrTestFailed) || res.Generation != 0 || liveTarget(t, a.Root) != "" {
			t.Fatalf("Recover: %+v, %v, live -> %q", res, err, liveTarget(t, a.Root))
		}
	})
}

func TestApplyReloadFailureIsRetriedOnTheNextApply(t *testing.T) {
	a, ft, fr := newApplier(t)
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
	if exists(filepath.Join(a.Root, "gen-000001", reloadedMarker)) {
		t.Fatal("reloaded marker written for a failed reload")
	}
	// The same document again: no new generation, but the reload is retried.
	fr.fail = nil
	res = mustApply(t, a, "a")
	if res.Changed || res.Generation != 1 || !res.Reloaded || fr.calls != 2 || ft.calls != 1 {
		t.Fatalf("retry: %+v reloader=%d tester=%d", res, fr.calls, ft.calls)
	}
	// And once it succeeded, it is not repeated.
	res = mustApply(t, a, "a")
	if res.Reloaded || fr.calls != 2 {
		t.Fatalf("after a successful retry: %+v reloader=%d", res, fr.calls)
	}
}

// A test that ended because the caller gave up is not a verdict on the
// candidate: nothing is kept as failed, and the error is the context's.
func TestApplyCancelledTestIsNotAVerdict(t *testing.T) {
	a, ft, fr := newApplier(t)
	mustApply(t, a, "a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft.onTest = cancel
	res, err := a.Apply(ctx, files("b"))
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTestFailed) {
		t.Fatalf("err = %v, want context.Canceled and not ErrTestFailed", err)
	}
	if res.Generation != 1 || liveTarget(t, a.Root) != "gen-000001" {
		t.Fatalf("Result = %+v live -> %q", res, liveTarget(t, a.Root))
	}
	if exists(filepath.Join(a.Root, "failed-000002")) || exists(filepath.Join(a.Root, "gen-000002")) {
		t.Fatal("a cancelled candidate was kept")
	}
	if fr.calls != 1 {
		t.Fatalf("reloader calls = %d", fr.calls)
	}
	// A context that is already done installs nothing at all.
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if _, err := a.Apply(done, files("c")); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if ft.calls != 2 {
		t.Fatalf("tester ran for a done context (calls=%d)", ft.calls)
	}
}

func TestApplyPrunesOldGenerations(t *testing.T) {
	a, ft, _ := newApplier(t)
	a.Keep = 2
	for _, tag := range []string{"a", "b", "c", "d", "e"} {
		mustApply(t, a, tag)
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
	a, ft, fr := newApplier(t)
	a.MinInterval = 300 * time.Millisecond
	mustApply(t, a, "a")
	start := time.Now()
	mustApply(t, a, "b")
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Fatalf("second apply after %v; want the pacing interval", el)
	}
	// An unchanged render is answered at once — pacing is for attempts.
	tests, reloads := ft.calls, fr.calls
	mustApply(t, a, "b")
	if ft.calls != tests || fr.calls != reloads {
		t.Fatal("unchanged apply tested or reloaded")
	}
	// Cancellation while waiting installs nothing.
	a.MinInterval = time.Hour
	a.lastAttempt = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := a.Apply(ctx, files("c"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if exists(filepath.Join(a.Root, "gen-000003")) || ft.calls != tests {
		t.Fatal("a generation was written or tested for a cancelled apply")
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
	mustApply(t, a, "a")
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

// The lock file serialises two Applier values over one Root, as two processes
// would be: an Apply waits while another holder has the lock.
func TestApplyWaitsForTheRootLock(t *testing.T) {
	a, _, _ := newApplier(t)
	mustApply(t, a, "a")
	f, err := os.OpenFile(filepath.Join(a.Root, lockFile), os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	b := &Applier{Root: a.Root, Tester: &fakeTester{root: a.Root}, Reloader: &fakeReloader{}, MinInterval: time.Millisecond}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = b.Apply(context.Background(), files("b"))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Apply proceeded while another holder had the lock")
	case <-time.After(200 * time.Millisecond):
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not proceed after the lock was released")
	}
	wg.Wait()
	if got := liveTarget(t, a.Root); got != "gen-000002" {
		t.Fatalf("live -> %q", got)
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

func TestFailedZone(t *testing.T) {
	cases := map[string]string{
		`nginx: [emerg] unknown directive "bogus" in /var/lib/kapkan/edge/conf/live/kapkan_zone_shop.example.com.conf:12`: "shop.example.com",
		`nginx: [emerg] host not found in upstream "x" in /w/live/kapkan_zone_a-b.example.net.conf:3`:                     "a-b.example.net",
		`nginx: [emerg] invalid number of arguments in /w/live/kapkan_00_common.conf:9`:                                   "",
		`context deadline exceeded`: "",
	}
	for msg, want := range cases {
		if got := failedZone(msg); got != want {
			t.Errorf("failedZone(%q) = %q, want %q", msg, got, want)
		}
	}
}

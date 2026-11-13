package steer

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/apply"
)

// TestVIPTargetKey: every spelling of one address is one target — an
// IPv4-mapped address is the IPv4 address it maps, a zone is dropped — whose
// key is the canonical text, a key the Store takes: SetDrain under it writes
// one file per address, whatever the spelling, and no zone's text leads a
// path out of the steering directory.
func TestVIPTargetKey(t *testing.T) {
	tests := []struct{ vip, key string }{
		{"192.0.2.10", "192.0.2.10"},
		{"::ffff:192.0.2.10", "192.0.2.10"},
		{"::ffff:192.0.2.10%eth0", "192.0.2.10"},
		{"2001:db8::10", "2001:db8::10"},
		{"2001:0db8:0:0:0:0:0:0010", "2001:db8::10"},
		{"2001:db8::10%eth0", "2001:db8::10"},
		{"2001:db8::10%../../state.json", "2001:db8::10"},
		{"2001:db8::10%/../../../escaped", "2001:db8::10"},
	}
	stateDir := t.TempDir()
	s := NewStore(stateDir)
	for _, tc := range tests {
		target := VIPTarget(netip.MustParseAddr(tc.vip))
		if target.Key != tc.key || !slices.Equal(target.Addrs, []netip.Addr{netip.MustParseAddr(tc.key)}) {
			t.Errorf("VIPTarget(%s) = %+v, want key %s and that address alone", tc.vip, target, tc.key)
		}
		if err := s.SetDrain(target.Key, Drain{Reason: "maintenance"}); err != nil {
			t.Errorf("SetDrain(VIPTarget(%s).Key) = %v: a target's key must name its drain file", tc.vip, err)
		}
	}
	if entries, err := os.ReadDir(stateDir); err != nil || len(entries) != 1 || entries[0].Name() != DirName {
		t.Fatalf("state_dir holds %v (%v), want %s alone: a key led a path out of the directory", entries, err, DirName)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var drains []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "drain.") {
			drains = append(drains, e.Name())
		}
	}
	if want := []string{"drain.192.0.2.10", "drain.2001:db8::10"}; !slices.Equal(drains, want) {
		t.Fatalf("eight spellings of two addresses left the drain files %v, want %v", drains, want)
	}
}

// TestGatesHolding: every gate is closed at its zero value, the first gate
// closed is the one named, and a join is let through only with all three
// open.
func TestGatesHolding(t *testing.T) {
	tests := []struct {
		g    Gates
		want Reason
	}{
		{Gates{}, ReasonGenerationNotLive},
		{Gates{Zones: 1, DrainKnown: true}, ReasonGenerationNotLive},
		{Gates{GenerationLive: true}, ReasonNoZones},
		{Gates{GenerationLive: true, DrainKnown: true}, ReasonNoZones},
		{Gates{GenerationLive: true, Zones: -1, DrainKnown: true}, ReasonNoZones},
		{Gates{GenerationLive: true, Zones: 1}, ReasonDrainUnknown},
		{Gates{GenerationLive: true, Zones: 1, DrainKnown: true}, ""},
		{Gates{GenerationLive: true, Zones: 40, DrainKnown: true}, ""},
	}
	for _, tc := range tests {
		if got := tc.g.Holding(); got != tc.want {
			t.Errorf("%+v.Holding() = %q, want %q", tc.g, got, tc.want)
		}
	}
}

// typesTester is the Applier's `nginx -t`: it records what the generation
// gate reads while the test runs — the window the gate exists for — and fails
// the calls fail numbers, from 1.
type typesTester struct {
	root string
	fail map[int]bool
	seen []bool
}

func (g *typesTester) Test(context.Context) error {
	g.seen = append(g.seen, ReadGenerationLive(g.root))
	if g.fail[len(g.seen)] {
		return errors.New("nginx: [emerg] unexpected end of file")
	}
	return nil
}

type typesReloader struct{}

func (typesReloader) Reload(context.Context) error { return nil }

// TestReadGenerationLive drives a real Applier: the gate is closed before
// anything is installed and inside every apply's `nginx -t`; open once a
// generation of ours has passed its test, and still open after a later
// candidate fails and the previous one is restored; closed after a failed
// first install, and on a `live` that is not ours.
func TestReadGenerationLive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conf")
	if ReadGenerationLive(root) {
		t.Fatal("a fresh root: the gate is open before anything was installed")
	}
	tester := &typesTester{root: root, fail: map[int]bool{3: true}}
	a := &apply.Applier{Root: root, Tester: tester, Reloader: typesReloader{}, MinInterval: time.Nanosecond}
	for i, body := range []string{"a", "b", "c"} {
		_, err := a.Apply(context.Background(), map[string][]byte{"kapkan_00_common.conf": []byte("# " + body + "\n")})
		if failing := tester.fail[i+1]; failing && !errors.Is(err, apply.ErrTestFailed) || !failing && err != nil {
			t.Fatalf("apply %d = %v, want it to fail its test: %v", i+1, err, failing)
		}
		if !ReadGenerationLive(root) {
			t.Errorf("after apply %d: the gate is closed on a generation that passed its test", i+1)
		}
	}
	if !slices.Equal(tester.seen, []bool{false, false, false}) {
		t.Errorf("inside the three applies' `nginx -t`, the gate read %v; want it closed in each", tester.seen)
	}

	first := filepath.Join(t.TempDir(), "conf")
	b := &apply.Applier{Root: first, Tester: &typesTester{root: first, fail: map[int]bool{1: true}}, Reloader: typesReloader{}, MinInterval: time.Nanosecond}
	if _, err := b.Apply(context.Background(), map[string][]byte{"kapkan_00_common.conf": []byte("# a\n")}); !errors.Is(err, apply.ErrTestFailed) {
		t.Fatalf("a failing first apply = %v, want ErrTestFailed", err)
	}
	if ReadGenerationLive(first) {
		t.Error("after a failed first install: the gate is open with nothing of ours live")
	}

	foreign := filepath.Join(t.TempDir(), "conf")
	if err := os.MkdirAll(filepath.Join(foreign, "theirs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "theirs", ".kapkan-tested"), []byte("ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("theirs", filepath.Join(foreign, "live")); err != nil {
		t.Fatal(err)
	}
	if ReadGenerationLive(foreign) {
		t.Error("a `live` link that is not a generation of ours, a tested marker beside it: the gate is open")
	}
}

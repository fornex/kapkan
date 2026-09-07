package node

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/apply"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

func withModule(ctx context.Context, binary string) (apply.Terminator, error) {
	return apply.Terminator{Kind: "nginx", Version: "1.30.4", Core: "1.30.4", HTTP3Module: true, TLSLibrary: "OpenSSL 3.5.7", EarlyDataCapable: true}, nil
}

func h3Doc(rps uint64) *edgedoc.Doc {
	d := testDoc(rps)
	d.Zones[0].TLS.H3 = true
	return d
}

func readLive(t *testing.T, state, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(state, "conf", "live", name))
	if err != nil {
		t.Fatalf("live %s: %v", name, err)
	}
	return string(raw)
}

// A ready node renders QUIC for a zone that asks, names the host key it minted
// (32 random bytes, 0600, once — the same after a restart), and reports the
// zone under serving. The switch is the slow path: a rate change on the h3
// zone does not touch the generation; turning h3 off does.
func TestReadyNodeRendersQUICAndKeepsItsHostKey(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(h3Doc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	// No certificate, no TLS server, no QUIC: the zone needs one on disk.
	selfSignedSet(t, state, "example.com")
	tester, reloader := &fakeTester{}, &fakeReloader{}
	opt := baseOptions(srv, state, sockets, tester, reloader)
	opt.ACME = ACME{Directory: "http://127.0.0.1:1/never"} // never contacted: the certificate is fresh
	opt.Prober = withModule
	// /proc/net/udp is not there off Linux, so stub the sampler to prove the
	// report carries `listening` when the node serves QUIC (the parser itself
	// is tested from fixtures in TestUDPListeningFromProc).
	defer stubUDPListening(true)()
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })

	common := readLive(t, state, "kapkan_00_common.conf")
	keyPath := filepath.Join(state, "tls", "quic_host.key")
	for _, want := range []string{"quic_retry on;", "quic_host_key " + keyPath + ";", "listen 443 quic reuseport default_server;", `'"proto":"$server_protocol",'`} {
		if !strings.Contains(common, want) {
			t.Errorf("common file lacks %q", want)
		}
	}
	zone := readLive(t, state, "kapkan_zone_example.com.conf")
	for _, want := range []string{"listen 443 quic;", `add_header Alt-Svc 'h3=":443"; ma=86400';`} {
		if !strings.Contains(zone, want) {
			t.Errorf("zone file lacks %q", want)
		}
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != quicHostKeyLen || st.Mode().Perm() != 0o600 {
		t.Errorf("host key: %d bytes, mode %v", st.Size(), st.Mode())
	}
	key1, _ := os.ReadFile(keyPath)
	if dst, _ := os.Stat(filepath.Dir(keyPath)); dst.Mode().Perm() != 0o700 {
		t.Errorf("tls dir mode %v, want 0700", dst.Mode())
	}

	waitFor(t, "a report", func() bool {
		rep, ok := brain.lastReport()
		return ok && rep.Terminator != nil && rep.Terminator.H3 != nil && len(rep.Terminator.H3.Serving) > 0
	})
	rep, _ := brain.lastReport()
	if strings.Join(rep.Terminator.H3.Serving, ",") != "example.com" || len(rep.Terminator.H3.Unsupported) != 0 || rep.Terminator.H3.State != "ready" {
		t.Errorf("report h3 = %+v", *rep.Terminator.H3)
	}
	if rep.Terminator.H3.Listening == nil || !*rep.Terminator.H3.Listening {
		t.Errorf("report h3.listening = %v, want true (the sampler is stubbed on)", rep.Terminator.H3.Listening)
	}
	if !n.Status().Converged {
		t.Error("not converged")
	}
	gen1Installs := tester.calls.Load()

	// Fast path: a rate change on the h3 zone moves the ETag it renders (so we
	// know the document was processed) but installs no new generation.
	brain.set(h3Doc(20), `"v2"`)
	waitFor(t, "v2 rendered", func() bool { return n.Status().ZonesETag == `"v2"` })
	if g := n.Status().Generation; g != 1 {
		t.Fatalf("a rate change on an h3 zone reinstalled: generation %d", g)
	}
	if c := tester.calls.Load(); c != gen1Installs {
		t.Fatalf("a rate change ran nginx -t again: %d installs, want %d", c, gen1Installs)
	}
	// Slow path: h3 off is a new tested generation, and the QUIC lines go.
	brain.set(testDoc(20), `"v3"`)
	waitFor(t, "v3 installed", func() bool { return n.Status().Generation == 2 && n.Status().ZonesETag == `"v3"` })
	if c := readLive(t, state, "kapkan_00_common.conf"); strings.Contains(c, "quic") {
		t.Error("h3 off, yet the shared file still carries QUIC")
	}
	waitFor(t, "a report without serving", func() bool {
		rep, ok := brain.lastReport()
		return ok && rep.ZonesETag == `"v3"` && rep.Terminator != nil && rep.Terminator.H3 != nil && len(rep.Terminator.H3.Serving) == 0
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	// A restart keeps the key: the tokens nginx derived from it stay valid.
	n2, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop2 := run(t, n2)
	waitFor(t, "restart from disk", func() bool { return n2.Status().Generation != 0 })
	key2, _ := os.ReadFile(keyPath)
	if !bytes.Equal(key1, key2) || len(key2) != quicHostKeyLen {
		t.Error("the host key changed across a restart")
	}
	if err := stop2(); err != nil {
		t.Fatal(err)
	}
}

// A node without the module (or switched off) renders the zone over TCP,
// converges, and names the zone under unsupported — never a refused document.
func TestNodeWithoutModuleDegradesH3Zones(t *testing.T) {
	for _, c := range []struct {
		name  string
		probe func(context.Context, string) (apply.Terminator, error)
		off   bool
		state string
	}{
		{"no module", nil, false, "no_module"},
		{"module, quic.h3 off", withModule, true, "node_off"},
	} {
		t.Run(c.name, func(t *testing.T) {
			brain := &fakeBrain{}
			brain.set(h3Doc(10), `"v1"`)
			srv := httptest.NewServer(brain)
			defer srv.Close()
			state, sockets := shortDirs(t)
			if err := os.MkdirAll(state, 0o755); err != nil {
				t.Fatal(err)
			}
			selfSignedSet(t, state, "example.com")
			opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
			opt.ACME = ACME{Directory: "http://127.0.0.1:1/never"}
			// Count the degraded-set warning: exactly one, even across a
			// second document that keeps the same degraded set.
			warns := &countingHandler{substr: "served over TCP"}
			opt.Logger = slog.New(warns)
			if c.probe != nil {
				opt.Prober = c.probe
			}
			opt.QUIC.H3Off = c.off
			n, err := New(opt)
			if err != nil {
				t.Fatal(err)
			}
			stop := run(t, n)
			defer func() {
				if err := stop(); err != nil {
					t.Error(err)
				}
			}()
			// Converged and the h3 readiness are published in a later critical
			// section than the one that bumps Generation, so wait on the whole
			// condition, not just the generation.
			waitFor(t, "the degraded zone converged", func() bool {
				st := n.Status()
				return st.Generation == 1 && st.Converged && st.H3 != nil && strings.Join(st.H3.Unsupported, ",") == "example.com"
			})
			for _, f := range []string{"kapkan_00_common.conf", "kapkan_zone_example.com.conf"} {
				if body := readLive(t, state, f); strings.Contains(body, "quic") || strings.Contains(body, "Alt-Svc") {
					t.Errorf("%s carries QUIC on a node that cannot render it", f)
				}
			}
			if !strings.Contains(readLive(t, state, "kapkan_zone_example.com.conf"), "HTTP/3 ASKED FOR, NOT RENDERED") {
				t.Error("the zone file does not say why HTTP/3 is missing")
			}
			if st := n.Status(); st.H3.State != c.state || len(st.H3.Serving) != 0 {
				t.Errorf("status = %+v h3 %+v", st, st.H3)
			}
			waitFor(t, "a report", func() bool {
				rep, ok := brain.lastReport()
				return ok && rep.Terminator != nil && rep.Terminator.H3 != nil && len(rep.Terminator.H3.Unsupported) > 0
			})
			rep, _ := brain.lastReport()
			if strings.Join(rep.Terminator.H3.Unsupported, ",") != "example.com" || rep.Terminator.H3.Listening != nil {
				t.Errorf("report h3 = %+v", *rep.Terminator.H3)
			}
			// A second document that keeps the degraded set (a new generation,
			// via a rate change) must not warn again.
			brain.set(h3Doc(20), `"v2"`)
			waitFor(t, "v2 rendered", func() bool { return n.Status().ZonesETag == `"v2"` })
			if got := warns.count(); got != 1 {
				t.Errorf("degraded-set warnings = %d, want exactly 1", got)
			}
		})
	}
}

// stubUDPListening replaces the /proc sampler for a test and returns a restore.
func stubUDPListening(up bool) func() {
	prev := udpListeningFn
	udpListeningFn = func(int) *bool { return &up }
	return func() { udpListeningFn = prev }
}

// countingHandler is a slog.Handler that counts WARN records whose message
// contains substr.
type countingHandler struct {
	substr string
	mu     sync.Mutex
	n      int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn && strings.Contains(r.Message, h.substr) {
		h.mu.Lock()
		h.n++
		h.mu.Unlock()
	}
	return nil
}
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }
func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

// The node's own quic.retry:false and omit_anchor reach the renderer: the
// shared file says quic_retry off, and under omit_catch_all with omit_anchor
// there is no anchor and no reuseport, while the zone still lists 443 quic.
func TestNodeQUICRetryAndOmitAnchor(t *testing.T) {
	brain := &fakeBrain{}
	brain.set(h3Doc(10), `"v1"`)
	srv := httptest.NewServer(brain)
	defer srv.Close()
	state, sockets := shortDirs(t)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	selfSignedSet(t, state, "example.com")
	opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
	opt.ACME = ACME{Directory: "http://127.0.0.1:1/never"}
	opt.Prober = withModule
	no := false
	opt.QUIC.Retry = &no
	opt.OmitCatchAll = true
	opt.QUIC.OmitAnchor = true
	n, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	stop := run(t, n)
	defer func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	}()
	waitFor(t, "first install", func() bool { return n.Status().Generation == 1 })
	common := readLive(t, state, "kapkan_00_common.conf")
	if !strings.Contains(common, "quic_retry off;") || strings.Contains(common, "quic_retry on;") {
		t.Error("quic.retry:false did not render quic_retry off")
	}
	if strings.Contains(common, "reuseport") || strings.Contains(common, "The QUIC anchor") || strings.Contains(common, "default_server") {
		t.Errorf("omit_catch_all + omit_anchor still rendered an anchor/catch-all:\n%s", common)
	}
	if !strings.Contains(common, "quic_host_key") {
		t.Error("the http-level quic_host_key is still needed under omit_anchor")
	}
	if z := readLive(t, state, "kapkan_zone_example.com.conf"); !strings.Contains(z, "listen 443 quic;") {
		t.Error("the zone still lists its own QUIC listener under omit_anchor")
	}
}

// udpTableListens / udpListeningIn over fixtures: the local port is column 2,
// "<hex addr>:<hex port>"; a header-only or empty file is false; no readable
// file is nil.
func TestUDPListeningFromProc(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
	v4on443 := write("udp", header+"  1: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000 0\n")
	v4other := write("udp_other", header+"  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0000 0\n")
	v6on443 := write("udp6", header+"  1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 2 0000 0\n")
	headerOnly := write("udp_hdr", header)
	empty := write("udp_empty", "")
	missing := filepath.Join(dir, "nope")

	tf := func(v *bool) string {
		if v == nil {
			return "nil"
		}
		return strconv.FormatBool(*v)
	}
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{"v4 has 443", []string{v4on443}, "true"},
		{"v6 has 443", []string{v6on443}, "true"},
		{"v4 only, other port", []string{v4other}, "false"},
		{"443 in v6 only", []string{v4other, v6on443}, "true"},
		{"header only", []string{headerOnly}, "false"},
		{"empty file", []string{empty}, "false"},
		{"one missing one present", []string{missing, v4on443}, "true"},
		{"both missing", []string{missing, missing}, "nil"},
	}
	for _, c := range cases {
		if got := tf(udpListeningIn(c.paths, 443)); got != c.want {
			t.Errorf("%s: udpListeningIn = %s, want %s", c.name, got, c.want)
		}
	}
}

// The host key is minted once; an existing key is kept and an empty one is
// refused loudly rather than silently regenerated.
func TestEnsureQUICHostKey(t *testing.T) {
	state, _ := shortDirs(t)
	n := &Node{files: nodeFiles{quicHostKey: filepath.Join(state, "tls", "quic_host.key")}, log: slog.New(slog.DiscardHandler)}
	if err := n.ensureQUICHostKey(); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(n.files.quicHostKey)
	if err := n.ensureQUICHostKey(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(n.files.quicHostKey)
	if !bytes.Equal(a, b) || len(a) != quicHostKeyLen {
		t.Fatal("the key was rewritten")
	}
	if err := os.Chmod(n.files.quicHostKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := n.ensureQUICHostKey(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(n.files.quicHostKey); st.Mode().Perm() != 0o600 {
		t.Errorf("mode not tightened back: %v", st.Mode())
	}
	if err := os.WriteFile(n.files.quicHostKey, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := n.ensureQUICHostKey(); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty key file was accepted: %v", err)
	}
}

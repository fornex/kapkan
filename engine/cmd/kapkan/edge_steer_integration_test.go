package main

// The CLI against a real node (E7.2). Everywhere else the CLI's
// tests script the daemon's answers in the node's own wire types, and the
// node's tests read its answers themselves: this is where `kapkan edge
// -steer`, `-s drain|undrain -wait` and -check read a running kapkan edge,
// so the two sides of the wire cannot drift apart unnoticed. The node is
// built from edge.yaml exactly as `kapkan edge` builds it (edgeNodeOptions);
// only the terminator, the kernel and :443 are fakes, and the CLI's seams
// share the node's kernel and probe.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/apply"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/node"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// itBrain is the brain for one node, cut down from node_test.go's fakeBrain:
// the agent token checked, the zone document served with its ETag (a 304
// for the ETag the node already holds), and reports accepted.
type itBrain struct {
	token, node string
	doc         []byte
	etag        string
	reports     atomic.Int64
}

func (b *itBrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+b.token {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/edge/zones":
		if r.URL.Query().Get("node") != b.node {
			http.Error(w, "unknown edge node", http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", b.etag)
		if r.Header.Get("If-None-Match") == b.etag {
			time.Sleep(50 * time.Millisecond) // a long poll, cut short
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(b.doc)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/report"):
		b.reports.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// itTerminator passes every `nginx -t` and reload: there is no nginx here.
type itTerminator struct{}

func (itTerminator) Test(context.Context) error   { return nil }
func (itTerminator) Reload(context.Context) error { return nil }

// itListen443 is the node's :443: a TLS listener on 127.0.0.1 that
// handshakes every connection with a self-signed leaf and closes it, so the
// probe's ClientHello gets a ServerHello (0x16), which reads ok.
func itListen443(t *testing.T) uint16 {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// itConsumer stands in for the speaker's healthcheck on this box: it reads
// GET /steer as consumer `it`, live (no dry), every 200 ms until stopped.
// It reports what it was served last.
type itConsumer struct {
	stop func()
	mu   sync.Mutex
	last string
}

func startConsumer(t *testing.T, addr string) *itConsumer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	c := &itConsumer{}
	var wg sync.WaitGroup
	c.stop = func() { cancel(); wg.Wait() }
	t.Cleanup(c.stop)
	client := &http.Client{Timeout: time.Second}
	wg.Go(func() {
		for ctx.Err() == nil {
			got := "no answer"
			if resp, err := client.Get("http://" + addr + "/steer?consumer=it"); err == nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				_ = resp.Body.Close()
				got = fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			c.mu.Lock()
			c.last = got
			c.mu.Unlock()
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	})
	return c
}

func (c *itConsumer) served() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func TestEdgeSteerAgainstARealNode(t *testing.T) {
	const token = "it-agent-token"
	doc := edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{
		Name: "example.com", Origins: []string{"10.0.0.1:8080"}, TLS: edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy: edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff, Rate: edgedoc.Rate{RPS: 10}},
	})
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	brain := &itBrain{token: token, node: "edge-1", doc: raw, etag: `"v1"`}
	srv := httptest.NewServer(brain)
	defer srv.Close()

	// Unix socket paths are short (104 bytes on darwin); t.TempDir is long.
	base, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	state, sockets := filepath.Join(base, "s"), filepath.Join(base, "r")
	// The status port is picked first and written into edge.yaml, so the node
	// and the CLI read one address, as they do on a box.
	pick, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := pick.Addr().String()
	_ = pick.Close()
	// The node itself is the target (no VIPs; 127.0.0.1 alone under
	// disable_ipv6): edge.yaml refuses a loopback VIP, and a VIP this host
	// does not hold probes blind.
	cfg := writeEdgeYAML(t, fmt.Sprintf(`controller:
  url: %s
  token_env: KAPKAN_TEST_EDGE_TOKEN
  name: edge-1
state_dir: %s
sockets_dir: %s
status_listen: %q
disable_ipv6: true
terminator:
  binary: %s
acme:
  disabled: true
steering:
  enabled: true
  interval_seconds: 1
  recover_after: 3
  vips: []
`, srv.URL, state, sockets, listen, fakeTerminator(t, "nginx version: nginx/1.26.3\n")))
	ec, err := config.LoadEdgeNode(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// One kernel and one :443 for the node and the CLI: no listener table
	// (so a refusal would be Refused), 127.0.0.1 on an interface.
	proc := steer.Proc{
		FS: fstest.MapFS{"net/tcp": {}, "net/tcp6": {}},
		Ifaddrs4: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}, nil
		},
	}
	prober := steer.Prober{Port: itListen443(t)}
	sp, spr, wt, wp := edgeSteerProc, edgeSteerProber, edgeWaitTimeout, edgeWaitPoll
	t.Cleanup(func() { edgeSteerProc, edgeSteerProber, edgeWaitTimeout, edgeWaitPoll = sp, spr, wt, wp })
	edgeSteerProc = func() steer.Proc { return proc }
	edgeSteerProber = func() steer.Prober { return prober }
	edgeWaitTimeout, edgeWaitPoll = 20*time.Second, 50*time.Millisecond

	// state.json as a node that ran here before leaves it: no new-node drain.
	if err := steer.NewStore(state).Save(steer.StateFile{Born: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var logs syncBuffer
	opt := edgeNodeOptions(ec, token, nil, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	opt.Tester, opt.Reloader = itTerminator{}, itTerminator{}
	opt.Prober = func(context.Context, string) (apply.Terminator, error) {
		return apply.Terminator{Kind: "nginx", Version: "1.99.0", Core: "1.99.0", TLSLibrary: "OpenSSL 3.5.7"}, nil
	}
	opt.Steering.Proc, opt.Steering.Prober = proc, prober
	n, err := node.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("Run did not stop")
			}
		})
	}
	t.Cleanup(stop)
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf(format+"\nthe node's log:\n%s", append(args, logs.String())...)
	}
	steerCLI := func() (int, string, string) {
		t.Helper()
		return runEdgeCLIOut(t, "-config", cfg, "-steer")
	}

	// -steer answers 0 once the node announces, and the answer is the
	// daemon's: a /steer that refused this box's CLI (403) would read as no
	// answer and quietly fall back to source=local.
	var code int
	var out, errOut string
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if code, out, errOut = steerCLI(); code == exitOK && out == "node announce ok source=daemon\n" {
			break
		}
		if time.Now().After(deadline) {
			fail("-steer never answered the daemon's announce: code=%d stdout=%q stderr=%q", code, out, errOut)
		}
	}

	// -check reads the same daemon through /healthz, beside its own
	// evaluation, and exits 0: nothing here is a problem.
	code, errOut = runEdgeCLI(t, "-config", cfg, "-check")
	if code != exitOK || !strings.Contains(errOut, "kapkan edge: note: steering node: would announce now (unmanaged); kapkan edge says announce (ok) since ") {
		fail("-check against the running node: code=%d stderr=%q", code, errOut)
	}

	// The speaker's healthcheck reads /steer from here on.
	consumer := startConsumer(t, listen)

	// -s drain -wait returns 0 once the consumer has read the drain, and
	// -steer then answers the daemon's drain.
	code, errOut = runEdgeCLI(t, "-config", cfg, "-s", "drain", "-reason", "integration", "-wait")
	if code != exitOK || !strings.Contains(errOut, `kapkan edge: drained node (reason "integration")`) || !strings.Contains(errOut, "kapkan edge: node: drain read by it at ") {
		fail("-s drain -wait: code=%d stderr=%q; the consumer was served %s", code, errOut, consumer.served())
	}
	if code, out, errOut = steerCLI(); code != exitSteerDrain || out != "node drain drained source=daemon\n" {
		fail("-steer after the drain: code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	// -s undrain -wait returns 0 once the consumer has read the announce
	// again (unknown, as the node rejoins, is not enough), and -steer agrees.
	code, errOut = runEdgeCLI(t, "-config", cfg, "-s", "undrain", "-wait")
	if code != exitOK || !strings.Contains(errOut, "kapkan edge: undrained node") || !strings.Contains(errOut, "kapkan edge: node: announce read by it at ") {
		fail("-s undrain -wait: code=%d stderr=%q; the consumer was served %s", code, errOut, consumer.served())
	}
	if code, out, errOut = steerCLI(); code != exitOK || out != "node announce ok source=daemon\n" {
		fail("-steer after the undrain: code=%d stdout=%q stderr=%q", code, out, errOut)
	}

	// The node stops: -steer evaluates locally — the same kernel, :443 still
	// answering, the live generation and its zone on disk — and says so.
	consumer.stop()
	stop()
	code, out, errOut = steerCLI()
	if code != exitOK || out != "node announce unmanaged source=local\n" || !strings.Contains(errOut, "kapkan edge -steer: kapkan edge did not answer (") {
		fail("-steer with the node stopped: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

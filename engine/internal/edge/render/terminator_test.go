package render_test

// TestRealTerminator runs the rendered configuration through the terminator it
// targets, inside a container. Three arms:
//
//   - test/<fixture>: `nginx -t` accepts every fixture's render. This is what
//     the reload gate runs on a node; a directive that the templates get wrong
//     for one nginx version fails here, on that version.
//   - serve/…/no-decider: the terminator SERVES the render with no decision
//     service listening (the socket is absent): a decide/open zone passes
//     requests to the origin, a decide/closed zone answers 503, a mode/none
//     zone passes, :80 redirects (or answers 503 without a certificate). This
//     is the fail-open idiom (package doc) proven on a real binary — the one
//     thing about this milestone that could not be settled by reading docs.
//   - serve/…/decider (Linux only): with a decision service on the socket, a
//     403 denies, a 200 allows and its X-Kapkan-Mark reaches the origin, the
//     subrequest carries the zone/client/URI headers, and the ACME location is
//     answered by the challenge socket. Unix sockets only cross a bind mount
//     when host and container share a kernel, so Docker Desktop skips this arm.
//
// KAPKAN_EDGE_TERMINATOR_IMAGE names the image (nginx:1.22 is the floor;
// nginx:stable; docker.angie.software/angie:latest). Unset, the test skips;
// KAPKAN_EDGE_TERMINATOR=require turns that skip into a failure, so the CI
// job cannot go green by losing Docker. KAPKAN_EDGE_TERMINATOR_OUT keeps the
// work directory (rendered configs, terminator logs) for upload.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/render"
)

const (
	envImage = "KAPKAN_EDGE_TERMINATOR_IMAGE"
	envMode  = "KAPKAN_EDGE_TERMINATOR"
	envOut   = "KAPKAN_EDGE_TERMINATOR_OUT"

	// containerWork is the mount point of the work directory inside the
	// container; every path the rendered configuration names is under it.
	containerWork = "/w"
	originPort    = 8080

	// termBinary picks the terminator's executable inside either image.
	termBinary = `PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH; exec "$(command -v angie || command -v nginx)"`
)

func TestRealTerminator(t *testing.T) {
	image := os.Getenv(envImage)
	required := os.Getenv(envMode) == "require"
	if image == "" {
		if required {
			t.Fatalf("%s=require but %s is empty", envMode, envImage)
		}
		t.Skipf("set %s (e.g. nginx:stable) to run the rendered configuration through a real terminator", envImage)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		if required {
			t.Fatalf("docker is required: %v", err)
		}
		t.Skipf("docker not found: %v", err)
	}
	h := newHarness(t, image)

	for _, name := range fixtureNames(t) {
		t.Run("test/"+name, func(t *testing.T) {
			h.prepare(t, name, nil)
			h.configTest(t, name)
		})
	}

	t.Run("serve/decide-open/no-decider", func(t *testing.T) {
		s := h.serve(t, "decide-open")
		res := s.get(t, true, "example.com", "/")
		res.expect(t, 200, "origin-ok mark=")
		res80 := s.get(t, false, "example.com", "/anything?q=1")
		res80.expect(t, 301, "")
		if loc := res80.header.Get("Location"); loc != "https://example.com/anything?q=1" {
			t.Errorf("Location = %q", loc)
		}
	})
	t.Run("serve/decide-closed/no-decider", func(t *testing.T) {
		s := h.serve(t, "decide-closed")
		s.get(t, true, "closed.example.net", "/").expect(t, 503, "")
	})
	t.Run("serve/mode-none", func(t *testing.T) {
		s := h.serve(t, "mode-none")
		res := s.get(t, true, "static.example.org", "/")
		res.expect(t, 200, "origin-ok")
		if got := res.header.Get("X-Kapkan-Extra"); got != "yes" {
			t.Errorf("extra_directives_file not in effect: X-Kapkan-Extra = %q", got)
		}
	})
	t.Run("serve/no-cert", func(t *testing.T) {
		s := h.serve(t, "no-cert")
		s.get(t, false, "new.example.com", "/").expect(t, 503, "")
	})

	if runtime.GOOS != "linux" {
		t.Log("skipping the decision-service arms: a unix socket does not cross a Docker Desktop bind mount")
		return
	}
	t.Run("serve/decide-open/decider", func(t *testing.T) {
		s := h.serve(t, "decide-open")
		d := h.startDecider(t)

		d.set(403, "")
		s.get(t, true, "example.com", "/probe?x=1").expect(t, 403, "")
		seen := d.last()
		if seen == nil {
			t.Fatal("the decision service was not consulted")
		}
		if seen.Method != "GET" || seen.URL.Path != "/decide" {
			t.Errorf("subrequest was %s %s, want GET /decide", seen.Method, seen.URL.Path)
		}
		for k, want := range map[string]string{"X-Kapkan-Zone": "example.com", "X-Kapkan-Uri": "/probe?x=1", "X-Kapkan-Method": "GET"} {
			if got := seen.Header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		// The requested host travels as the subrequest's own Host header.
		if seen.Host != "example.com" {
			t.Errorf("subrequest Host = %q, want example.com", seen.Host)
		}
		if seen.Header.Get("X-Kapkan-Client") == "" {
			t.Error("X-Kapkan-Client is empty")
		}
		if seen.ContentLength != 0 {
			t.Errorf("subrequest carried a body (Content-Length %d)", seen.ContentLength)
		}

		d.set(200, "suspicious")
		s.get(t, true, "example.com", "/").expect(t, 200, "origin-ok mark=suspicious")

		// A decider that answers something outside the contract is a failed
		// decision, and this zone fails open.
		d.set(500, "")
		s.get(t, true, "example.com", "/").expect(t, 200, "origin-ok mark=")
	})
	t.Run("serve/decide-closed/decider", func(t *testing.T) {
		s := h.serve(t, "decide-closed")
		d := h.startDecider(t)
		d.set(200, "")
		s.get(t, true, "closed.example.net", "/").expect(t, 200, "origin-ok")
		d.set(403, "")
		s.get(t, true, "closed.example.net", "/").expect(t, 403, "")
	})
	t.Run("serve/acme-challenge", func(t *testing.T) {
		s := h.serve(t, "no-cert")
		h.startChallenge(t)
		res := s.get(t, false, "new.example.com", "/.well-known/acme-challenge/tok123")
		res.expect(t, 200, "key-auth-for-tok123 zone=new.example.com")
	})
}

// harness owns the work directory the containers mount.
type harness struct {
	image string
	work  string
}

func newHarness(t *testing.T, image string) *harness {
	t.Helper()
	work := os.Getenv(envOut)
	if work == "" {
		dir, err := os.MkdirTemp("", "kapkan-edge-terminator-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		work = dir
	} else {
		abs, err := filepath.Abs(work)
		if err != nil {
			t.Fatal(err)
		}
		work = abs
		if err := os.MkdirAll(work, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The terminator's workers run as an unprivileged user inside the
	// container and must traverse into run/ to reach the sockets.
	if err := os.Chmod(work, 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{image: image, work: work}
	for _, sub := range []string{"run", "empty", "certs", "extra"} {
		if err := os.MkdirAll(filepath.Join(work, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range fixtureNames(t) {
		in := loadFixture(t, name)
		for zone := range in.Certs {
			h.selfSignedCert(t, zone)
		}
		for _, z := range in.Doc.Zones {
			if z.ExtraDirectivesFile != "" {
				writeFile(t, filepath.Join(work, "extra", z.Name+".conf"), "add_header X-Kapkan-Extra yes always;\n")
			}
		}
	}
	t.Logf("work directory: %s (image %s)", work, image)
	return h
}

// prepare renders a fixture with every path remapped under the mount point and
// writes it, plus a throwaway main configuration, to <work>/<fixture>/.
func (h *harness) prepare(t *testing.T, name string, mutate func(*render.Inputs)) {
	t.Helper()
	in := loadFixture(t, name)
	in.Node = render.Node{
		DecideSocket:    containerWork + "/run/decide.sock",
		ChallengeSocket: containerWork + "/run/challenge.sock",
		LogSocket:       containerWork + "/run/log.sock",
		EmptyRoot:       containerWork + "/empty",
		// Containers commonly have no IPv6 stack; binding [::] would fail at
		// start (not at -t) and hide what this test is after.
		DisableIPv6: true,
	}
	for zone := range in.Certs {
		in.Certs[zone] = render.Cert{
			Fullchain: containerWork + "/certs/" + zone + "/fullchain.pem",
			Key:       containerWork + "/certs/" + zone + "/privkey.pem",
		}
	}
	for i := range in.Doc.Zones {
		if in.Doc.Zones[i].ExtraDirectivesFile != "" {
			in.Doc.Zones[i].ExtraDirectivesFile = containerWork + "/extra/" + in.Doc.Zones[i].Name + ".conf"
		}
	}
	if mutate != nil {
		mutate(&in)
	}
	files, err := render.Render(in)
	if err != nil {
		t.Fatalf("Render(%s): %v", name, err)
	}
	dir := filepath.Join(h.work, name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		writeFile(t, filepath.Join(dir, "conf", n), string(b))
	}
	writeFile(t, filepath.Join(dir, "main.conf"), fmt.Sprintf(`# Throwaway main configuration for the real-terminator test. A deployment's
# nginx.conf differs in every other line; the one that matters is the include.
pid /tmp/kapkan-terminator.pid;
error_log /dev/stderr notice;
worker_processes 1;
events { worker_connections 256; }
http {
    access_log off;
    include %s/%s/conf/*.conf;
    # The stand-in origin echoes the mark the decision service set, so the
    # test can see that the header reached the origin.
    server {
        listen 127.0.0.1:%d;
        location / { return 200 "origin-ok mark=$http_x_kapkan_mark"; }
    }
}
`, containerWork, name, originPort))
}

// configTest is arm A: `nginx -t` on the prepared fixture.
func (h *harness) configTest(t *testing.T, name string) {
	t.Helper()
	script := termBinary + " -t -c " + containerWork + "/" + name + "/main.conf"
	out, err := exec.Command("docker", "run", "--rm", "-v", h.work+":"+containerWork, h.image, "sh", "-c", script).CombinedOutput()
	writeFile(t, filepath.Join(h.work, name, "test.log"), string(out))
	if err != nil {
		t.Fatalf("%s rejected the %s render: %v\n%s\n--- rendered files ---\n%s", h.image, name, err, out, h.dumpConf(t, name))
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

func (h *harness) dumpConf(t *testing.T, name string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.work, name, "conf"))
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(h.work, name, "conf", e.Name()))
		fmt.Fprintf(&b, "==> %s\n%s\n", e.Name(), raw)
	}
	return b.String()
}

// served is a running terminator with the fixture's render, ports published
// on the loopback.
type served struct {
	h       *harness
	id      string
	port443 string
	port80  string
}

// serve is arms B/C: start the terminator on the fixture, origins pointed at
// the stand-in origin.
func (h *harness) serve(t *testing.T, name string) *served {
	t.Helper()
	h.prepare(t, name, func(in *render.Inputs) {
		for i := range in.Doc.Zones {
			in.Doc.Zones[i].Origins = []string{fmt.Sprintf("127.0.0.1:%d", originPort)}
		}
	})
	// No decider or challenge socket unless a subtest starts one.
	for _, sock := range []string{"decide.sock", "challenge.sock"} {
		_ = os.Remove(filepath.Join(h.work, "run", sock))
	}
	script := termBinary + " -c " + containerWork + "/" + name + "/main.conf -g 'daemon off;'"
	out, err := exec.Command("docker", "run", "-d",
		"-v", h.work+":"+containerWork,
		"-p", "127.0.0.1:0:443", "-p", "127.0.0.1:0:80",
		h.image, "sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	s := &served{h: h, id: strings.TrimSpace(string(out))}
	t.Cleanup(func() {
		logs, _ := exec.Command("docker", "logs", s.id).CombinedOutput()
		writeFile(t, filepath.Join(h.work, name, "serve.log"), string(logs))
		if t.Failed() {
			t.Logf("terminator log (%s):\n%s", name, logs)
		}
		_ = exec.Command("docker", "rm", "-f", s.id).Run()
	})
	s.port443 = s.publishedPort(t, "443/tcp")
	s.port80 = s.publishedPort(t, "80/tcp")
	s.waitReady(t)
	return s
}

func (s *served) publishedPort(t *testing.T, port string) string {
	t.Helper()
	out, err := exec.Command("docker", "port", s.id, port).CombinedOutput()
	if err != nil {
		t.Fatalf("docker port %s: %v\n%s", port, err, out)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if line == "" {
		t.Fatalf("no published address for %s", port)
	}
	return line
}

func (s *served) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", s.port443, time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		// A container that died is reported now, not as a 20 s timeout.
		if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.id).Output(); err == nil && strings.TrimSpace(string(out)) == "false" {
			logs, _ := exec.Command("docker", "logs", s.id).CombinedOutput()
			t.Fatalf("terminator exited during start:\n%s", logs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("terminator not accepting on %s after 20s", s.port443)
}

type response struct {
	status int
	body   string
	header http.Header
}

func (r response) expect(t *testing.T, status int, bodyContains string) {
	t.Helper()
	if r.status != status {
		t.Errorf("status %d, want %d (body %q)", r.status, status, r.body)
	}
	if bodyContains != "" && !strings.Contains(r.body, bodyContains) {
		t.Errorf("body %q does not contain %q", r.body, bodyContains)
	}
}

// get requests path from the zone: over TLS with SNI on the published 443, or
// plain on the published 80. The URL names the zone so Host is right; dialing
// is redirected to the loopback port.
func (s *served) get(t *testing.T, https bool, zone, path string) response {
	t.Helper()
	addr, scheme := s.port80, "http"
	if https {
		addr, scheme = s.port443, "https"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
		},
		// Self-signed test certificate: verification is not what this arm tests.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: zone},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(scheme + "://" + zone + path)
	if err != nil {
		t.Fatalf("GET %s://%s%s: %v", scheme, zone, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return response{status: resp.StatusCode, body: string(body), header: resp.Header}
}

// decider is a stand-in decision service on the work directory's socket.
type decider struct {
	mu     sync.Mutex
	status int
	mark   string
	seen   *http.Request
}

func (d *decider) set(status int, mark string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status, d.mark = status, mark
}

func (d *decider) last() *http.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen
}

func (d *decider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = r.Clone(r.Context())
	if d.mark != "" {
		w.Header().Set("X-Kapkan-Mark", d.mark)
	}
	w.WriteHeader(d.status)
}

func (h *harness) startDecider(t *testing.T) *decider {
	t.Helper()
	d := &decider{status: 403}
	h.serveUnix(t, "decide.sock", d)
	return d
}

func (h *harness) startChallenge(t *testing.T) {
	t.Helper()
	h.serveUnix(t, "challenge.sock", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		_, _ = fmt.Fprintf(w, "key-auth-for-%s zone=%s", token, r.Header.Get("X-Kapkan-Zone"))
	}))
}

// serveUnix listens on <work>/run/<name> — the path the container sees as
// /w/run/<name> — world-connectable so the terminator's worker user may use it.
func (h *harness) serveUnix(t *testing.T, name string, handler http.Handler) {
	t.Helper()
	path := filepath.Join(h.work, "run", name)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = os.Remove(path)
	})
}

// selfSignedCert writes a throwaway ECDSA certificate for zone under
// <work>/certs/<zone>/. Test material only: the key is world-readable so the
// container's terminator can load it regardless of uid.
func (h *harness) selfSignedCert(t *testing.T, zone string) {
	t.Helper()
	dir := filepath.Join(h.work, "certs", zone)
	if _, err := os.Stat(filepath.Join(dir, "fullchain.pem")); err == nil {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: zone},
		DNSNames:     []string{zone},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "fullchain.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, filepath.Join(dir, "privkey.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

package render_test

// TestRealTerminator runs the rendered configuration through the terminator it
// targets, inside a container. Three arms:
//
//   - test/<fixture>: `nginx -t` accepts every fixture's render. This is what
//     the reload gate runs on a node; a directive that the templates get wrong
//     for one nginx version fails here, on that version.
//   - serve/…: the terminator SERVES the render. With no decision service
//     listening (the socket is absent): a decide/open zone passes requests to
//     the origin — with its keepalive intact — a decide/closed zone answers
//     503, a mode/none zone passes, :80 redirects (or answers 503 without a
//     certificate), a Host or SNI matching no zone is refused by the
//     catch-all, a WebSocket handshake and a request body reach the origin,
//     client-forged kapkan headers do not, and the per-zone TLS floor is
//     checked against what this terminator version can honour. This is the
//     fail-open idiom (package doc) proven on a real binary — the one thing
//     about this milestone that could not be settled by reading docs.
//   - serve/…/decider (Linux only): with a decision service on the socket, a
//     403 denies, a 200 allows and its X-Kapkan-Mark reaches the origin, an
//     off-contract 500 fails open WITHOUT its mark, the subrequest carries the
//     zone/client/URI/method headers and never a body, and the ACME location
//     is answered by the challenge socket for GET and refused for POST. Unix
//     sockets only cross a bind mount when host and container share a kernel,
//     so Docker Desktop skips this arm.
//
// KAPKAN_EDGE_TERMINATOR_IMAGE names the image (nginx:1.22 is the floor;
// nginx:stable; docker.angie.software/angie:latest). Unset, the test skips;
// KAPKAN_EDGE_TERMINATOR=require turns that skip into a failure, so the CI
// job cannot go green by losing Docker. KAPKAN_EDGE_TERMINATOR_OUT keeps the
// work directory (rendered configs, terminator logs, one subdirectory per
// arm) for upload. Containers carry the label kapkan-edge-terminator-test;
// after an aborted run: docker rm -f $(docker ps -aq --filter label=…).

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
	"strconv"
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
	containerWork  = "/w"
	originPort     = 8080
	containerLabel = "kapkan-edge-terminator-test"

	// termBinary picks the terminator's executable inside either image.
	termBinary = `PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH; exec "$(command -v angie || command -v nginx)"`

	// originBody is what the stand-in origin answers: every header the edge
	// owns or relays, echoed, so the test sees exactly what arrived.
	originBody = `origin-ok mark=$http_x_kapkan_mark;zone=$http_x_kapkan_zone;conn=$http_connection;upg=$http_upgrade;len=$content_length;`
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
	kind, version := h.probe(t)
	perServerTLS := honoursPerServerProtocols(kind, version)
	t.Logf("terminator %s %s; honours per-server ssl_protocols: %v", kind, version, perServerTLS)

	for _, name := range fixtureNames(t) {
		t.Run("test/"+name, func(t *testing.T) {
			h.configTest(t, name)
		})
	}

	t.Run("serve/decide-open/no-decider", func(t *testing.T) {
		s := h.serve(t, "decide-open", "no-decider")
		res := s.get(t, "example.com", "/")
		res.expect(t, 200, "origin-ok mark=;zone=example.com;")
		if c := res.header.Get("Connection"); c != "keep-alive" {
			t.Errorf("fail-open response carries Connection %q; the undecided path must not cost the keepalive", c)
		}
		// Client-forged kapkan headers never reach the origin.
		res = s.request(t, "GET", true, "example.com", "/", "", http.Header{"X-Kapkan-Mark": {"spoof"}, "X-Kapkan-Zone": {"other.example"}})
		res.expect(t, 200, "origin-ok mark=;zone=example.com;")
		// A WebSocket handshake arrives at the origin as one.
		res = s.request(t, "GET", true, "example.com", "/ws", "", http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}})
		res.expect(t, 200, ";conn=upgrade;upg=websocket;")
		// A request body is carried to the origin.
		res = s.request(t, "POST", true, "example.com", "/submit", strings.Repeat("x", 300), nil)
		res.expect(t, 200, ";len=300;")
		// :80 redirects…
		res80 := s.request(t, "GET", false, "example.com", "/anything?q=1", "", nil)
		res80.expect(t, 301, "")
		if loc := res80.header.Get("Location"); loc != "https://example.com/anything?q=1" {
			t.Errorf("Location = %q", loc)
		}
		// …and a Host or SNI that matches no zone is refused, not served here.
		if _, err := s.try("GET", false, "unknown.example", "/", "", nil, 0); err == nil {
			t.Error("a Host matching no zone was served on :80; want the catch-all's 444")
		}
		if _, err := s.try("GET", true, "unknown.example", "/", "", nil, 0); err == nil {
			t.Error("an SNI matching no zone completed a TLS handshake; want ssl_reject_handshake")
		}
	})
	t.Run("serve/decide-closed/no-decider", func(t *testing.T) {
		s := h.serve(t, "decide-closed", "no-decider")
		s.get(t, "closed.example.net", "/").expect(t, 503, "")
	})
	t.Run("serve/mode-none", func(t *testing.T) {
		s := h.serve(t, "mode-none", "serve")
		res := s.request(t, "GET", true, "static.example.org", "/", "", http.Header{"X-Kapkan-Mark": {"spoof"}})
		res.expect(t, 200, "origin-ok mark=;zone=static.example.org;")
		if got := res.header.Get("X-Kapkan-Extra"); got != "yes" {
			t.Errorf("extra_directives_file not in effect: X-Kapkan-Extra = %q", got)
		}
	})
	t.Run("serve/no-cert", func(t *testing.T) {
		s := h.serve(t, "no-cert", "serve")
		s.request(t, "GET", false, "new.example.com", "/", "", nil).expect(t, 503, "")
	})
	t.Run("serve/multi/tls-floor", func(t *testing.T) {
		s := h.serve(t, "multi", "tls-floor")
		// b allows TLS 1.2: it must never be refused, whatever the default
		// server's protocols are on this terminator.
		res, err := s.try("GET", true, "b.example.com", "/", "", nil, tls.VersionTLS12)
		if err != nil {
			t.Fatalf("TLS 1.2 to a tls.min_version 1.2 zone was refused: %v", err)
		}
		res.expect(t, 200, "zone=b.example.com;")
		if res.tlsVersion != tls.VersionTLS12 {
			t.Errorf("negotiated 0x%04x, want TLS 1.2", res.tlsVersion)
		}
		// a is TLS 1.3-only. Whether that holds per zone is the terminator's
		// to decide (package doc): from nginx 1.29.2 and on Angie it does; the
		// older line applies the node-wide floor, 1.2 here.
		_, err = s.try("GET", true, "a.example.com", "/", "", nil, tls.VersionTLS12)
		switch {
		case perServerTLS && err == nil:
			t.Errorf("%s %s honours per-server ssl_protocols, yet TLS 1.2 to the TLS 1.3-only zone succeeded", kind, version)
		case !perServerTLS && err != nil:
			t.Errorf("%s %s applies the node-wide floor (1.2 here), yet TLS 1.2 to the TLS 1.3-only zone was refused: %v", kind, version, err)
		case !perServerTLS:
			t.Logf("documented limitation: %s %s accepted TLS 1.2 for the TLS 1.3-only zone (node-wide floor)", kind, version)
		}
		res = s.get(t, "a.example.com", "/")
		res.expect(t, 200, "zone=a.example.com;")
		if res.tlsVersion != tls.VersionTLS13 {
			t.Errorf("negotiated 0x%04x with a.example.com, want TLS 1.3", res.tlsVersion)
		}
	})

	if runtime.GOOS != "linux" {
		t.Log("skipping the decision-service arms: a unix socket does not cross a Docker Desktop bind mount")
		return
	}
	t.Run("serve/decide-open/decider", func(t *testing.T) {
		s := h.serve(t, "decide-open", "decider")
		d := h.startDecider(t)

		d.set(403, "")
		s.get(t, "example.com", "/probe?x=1").expect(t, 403, "")
		seen := d.last()
		if seen == nil {
			t.Fatal("the decision service was not consulted")
		}
		if seen.req.Method != "GET" || seen.req.URL.Path != "/decide" {
			t.Errorf("subrequest was %s %s, want GET /decide", seen.req.Method, seen.req.URL.Path)
		}
		for k, want := range map[string]string{"X-Kapkan-Zone": "example.com", "X-Kapkan-Uri": "/probe?x=1", "X-Kapkan-Method": "GET"} {
			if got := seen.req.Header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if seen.req.Host != "example.com" {
			t.Errorf("subrequest Host = %q, want example.com", seen.req.Host)
		}
		if seen.req.Header.Get("X-Kapkan-Client") == "" {
			t.Error("X-Kapkan-Client is empty")
		}

		// Headers only: a POST with a body reaches the origin whole, and the
		// decider sees the verb but none of the body.
		d.set(200, "")
		res := s.request(t, "POST", true, "example.com", "/submit", strings.Repeat("y", 300), nil)
		res.expect(t, 200, "origin-ok mark=;zone=example.com;")
		res.expect(t, 200, ";len=300;")
		seen = d.last()
		if seen.req.Header.Get("X-Kapkan-Method") != "POST" {
			t.Errorf("X-Kapkan-Method = %q for a POST", seen.req.Header.Get("X-Kapkan-Method"))
		}
		if seen.req.ContentLength != 0 || seen.body != 0 {
			t.Errorf("the decider saw a body: Content-Length %d, %d bytes read", seen.req.ContentLength, seen.body)
		}

		d.set(200, "suspicious")
		s.get(t, "example.com", "/").expect(t, 200, "origin-ok mark=suspicious;")

		// Off-contract answer: undecided, its mark dropped, keepalive intact.
		d.set(500, "leak")
		res = s.get(t, "example.com", "/")
		res.expect(t, 200, "origin-ok mark=;zone=example.com;")
		if c := res.header.Get("Connection"); c != "keep-alive" {
			t.Errorf("fail-open after an off-contract answer carries Connection %q", c)
		}

		// With every socket it needs present, the terminator logs nothing at
		// crit level. The log socket is absent by design in this milestone: nginx
		// reports that connect failure at alert, Angie at crit, so those lines are
		// not counted (E3.3 brings the listener and drops this exception).
		if crit := critLines(s.logs(t)); len(crit) > 0 {
			t.Errorf("terminator logged at crit level:\n%s", strings.Join(crit, "\n"))
		}
	})
	t.Run("serve/decide-closed/decider", func(t *testing.T) {
		s := h.serve(t, "decide-closed", "decider")
		d := h.startDecider(t)
		d.set(200, "")
		s.get(t, "closed.example.net", "/").expect(t, 200, "origin-ok")
		d.set(403, "")
		s.get(t, "closed.example.net", "/").expect(t, 403, "")
	})
	t.Run("serve/acme-challenge", func(t *testing.T) {
		s := h.serve(t, "no-cert", "acme-challenge")
		h.startChallenge(t)
		res := s.request(t, "GET", false, "new.example.com", "/.well-known/acme-challenge/tok123", "", nil)
		res.expect(t, 200, "key-auth-for-tok123 zone=new.example.com body=0")
		s.request(t, "POST", false, "new.example.com", "/.well-known/acme-challenge/tok123", "payload", nil).expect(t, 403, "")
	})
}

// honoursPerServerProtocols says whether this terminator applies ssl_protocols
// per virtual server (nginx 1.29.2 fixed it; Angie always has).
func honoursPerServerProtocols(kind, version string) bool {
	if kind == "angie" {
		return true
	}
	parts := strings.Split(version, ".")
	nums := make([]int, 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		nums[i], _ = strconv.Atoi(parts[i])
	}
	switch {
	case nums[0] != 1:
		return nums[0] > 1
	case nums[1] != 29:
		return nums[1] > 29
	default:
		return nums[2] >= 2
	}
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
	// Pull once, so no arm pays for it and no `docker run` output carries it;
	// an image already present is used as is (a registry hiccup must not fail
	// a run that needs nothing from the registry).
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		if out, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
			t.Fatalf("docker pull %s: %v\n%s", image, err, out)
		}
	}
	t.Logf("work directory: %s (image %s)", work, image)
	return h
}

// probe asks the image's terminator for its kind and version.
func (h *harness) probe(t *testing.T) (kind, version string) {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", h.image, "sh", "-c", termBinary+" -v").CombinedOutput()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	before, after, ok := strings.Cut(line, "version:")
	if !ok {
		t.Fatalf("probe: unrecognised output %q", line)
	}
	kind = strings.ToLower(strings.TrimSpace(before))
	if i := strings.LastIndex(after, "/"); i >= 0 {
		after = after[i+1:]
	}
	version, _, _ = strings.Cut(strings.TrimSpace(after), " ")
	return kind, version
}

// prepare renders a fixture with every path remapped under the mount point and
// writes it, plus a throwaway main configuration, to <work>/<fixture>/<arm>/.
// Each arm has its own directory so no arm's logs overwrite another's.
func (h *harness) prepare(t *testing.T, name, arm string, mutate func(*render.Inputs)) string {
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
	dir := filepath.Join(h.work, name, arm)
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
    include %s/%s/%s/conf/*.conf;
    # The stand-in origin echoes what arrived, so the test can see which
    # headers the edge owned, relayed or dropped.
    server {
        listen 127.0.0.1:%d;
        location / { return 200 "%s"; }
    }
}
`, containerWork, name, arm, originPort, originBody))
	return dir
}

// configTest is arm A: `nginx -t` on the prepared fixture.
func (h *harness) configTest(t *testing.T, name string) {
	t.Helper()
	dir := h.prepare(t, name, "test", nil)
	script := termBinary + " -t -c " + containerWork + "/" + name + "/test/main.conf"
	out, err := exec.Command("docker", "run", "--rm", "-v", h.work+":"+containerWork, h.image, "sh", "-c", script).CombinedOutput()
	writeFile(t, filepath.Join(dir, "test.log"), string(out))
	if err != nil {
		t.Fatalf("%s rejected the %s render: %v\n%s\n--- rendered files ---\n%s", h.image, name, err, out, dumpConf(t, dir))
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

func dumpConf(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "conf"))
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, "conf", e.Name()))
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
func (h *harness) serve(t *testing.T, name, arm string) *served {
	t.Helper()
	dir := h.prepare(t, name, arm, func(in *render.Inputs) {
		for i := range in.Doc.Zones {
			in.Doc.Zones[i].Origins = []string{fmt.Sprintf("127.0.0.1:%d", originPort)}
		}
	})
	// No decider or challenge socket unless a subtest starts one.
	for _, sock := range []string{"decide.sock", "challenge.sock"} {
		_ = os.Remove(filepath.Join(h.work, "run", sock))
	}
	script := termBinary + " -c " + containerWork + "/" + name + "/" + arm + "/main.conf -g 'daemon off;'"
	out, err := exec.Command("docker", "run", "-d", "--label", containerLabel,
		"-v", h.work+":"+containerWork,
		"-p", "127.0.0.1:0:443", "-p", "127.0.0.1:0:80",
		h.image, "sh", "-c", script).Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("docker run: %v\n%s", err, stderr)
	}
	s := &served{h: h, id: strings.TrimSpace(string(out))}
	t.Cleanup(func() {
		logs := s.logs(t)
		writeFile(t, filepath.Join(dir, "serve.log"), logs)
		if t.Failed() {
			t.Logf("terminator log (%s/%s):\n%s", name, arm, logs)
		}
		_ = exec.Command("docker", "rm", "-f", s.id).Run()
	})
	s.port443 = s.publishedPort(t, "443/tcp")
	s.port80 = s.publishedPort(t, "80/tcp")
	s.waitReady(t)
	return s
}

func (s *served) logs(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("docker", "logs", s.id).CombinedOutput()
	return string(out)
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

// waitReady probes the published :80 — rendered for every zone, certificate
// or not — until the terminator accepts, or reports a container that died.
func (s *served) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", s.port80, time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.id).Output(); err == nil && strings.TrimSpace(string(out)) == "false" {
			t.Fatalf("terminator exited during start:\n%s", s.logs(t))
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("terminator not accepting on %s after 20s", s.port80)
}

type response struct {
	status     int
	body       string
	header     http.Header
	tlsVersion uint16
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

func (s *served) get(t *testing.T, zone, path string) response {
	t.Helper()
	return s.request(t, "GET", true, zone, path, "", nil)
}

// request performs one request and fails the test if it could not complete.
func (s *served) request(t *testing.T, method string, https bool, zone, path, body string, hdr http.Header) response {
	t.Helper()
	res, err := s.try(method, https, zone, path, body, hdr, 0)
	if err != nil {
		t.Fatalf("%s %s%s: %v", method, zone, path, err)
	}
	return res
}

// try performs one request to the zone: over TLS with SNI on the published
// 443 (optionally capped at maxTLS), or plain on the published 80. The URL
// names the zone so Host is right; dialing is redirected to the loopback port.
// Keep-alives are left on so the response's Connection header is meaningful.
func (s *served) try(method string, https bool, zone, path, body string, hdr http.Header, maxTLS uint16) (response, error) {
	addr, scheme := s.port80, "http"
	if https {
		addr, scheme = s.port443, "https"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
		},
		// Self-signed test certificate: verification is not what this arm tests.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: zone, MaxVersion: maxTLS},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, scheme+"://"+zone+path, rd)
	if err != nil {
		return response{}, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	res := response{status: resp.StatusCode, body: string(b), header: resp.Header}
	if resp.TLS != nil {
		res.tlsVersion = resp.TLS.Version
	}
	return res, nil
}

// decider is a stand-in decision service on the work directory's socket.
type decider struct {
	mu     sync.Mutex
	status int
	mark   string
	seen   *seenRequest
}

type seenRequest struct {
	req  *http.Request
	body int64
}

func (d *decider) set(status int, mark string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status, d.mark = status, mark
}

func (d *decider) last() *seenRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen
}

func (d *decider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n, _ := io.Copy(io.Discard, r.Body)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = &seenRequest{req: r.Clone(r.Context()), body: n}
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
		n, _ := io.Copy(io.Discard, r.Body)
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		_, _ = fmt.Fprintf(w, "key-auth-for-%s zone=%s body=%d", token, r.Header.Get("X-Kapkan-Zone"), n)
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

// critLines returns the terminator's [crit] log lines, minus the syslog
// connect failures a deliberately absent log socket produces.
func critLines(logs string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "[crit]") && !strings.Contains(line, "while logging to syslog") {
			out = append(out, line)
		}
	}
	return out
}

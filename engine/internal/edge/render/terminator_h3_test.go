package render_test

// The HTTP/3 arms of TestRealTerminator (edge-spec §8, milestone E5.4): a
// rendered terminator is driven over QUIC by the two clients hack/ provides —
// stock Debian curl in the h3client image (the ordinary client) and h3probe
// (the instrumented one, for the Retry that curl cannot see). Both run in
// containers on the same Docker bridge as the terminator, addressed by its
// bridge IP with --add-host for each zone name, so UDP/443 is never published
// and the arms behave the same on Docker Desktop and on a Linux runner.
//
// Neither client is part of the product (E5 decision D10): the image is built
// from hack/h3client and h3probe is cross-compiled from its own module, once
// per run, on first use — and a client that cannot speak h3 fails the run
// rather than skipping it (the image's own `curl -V | grep HTTP3` gate, and a
// probe build failure, are both fatal).
//
// On an image with the HTTP/3 module (nginx:stable, Angie):
//
//   - serve/h3/request: `curl --http3-only` reaches a decide zone and a
//     mode:none zone over h3 (HTTP/3, status 200, the origin echoes the zone).
//   - serve/h3/alt-svc-upgrade: a first request over TCP negotiates h2 and
//     carries Alt-Svc; a second request with curl's alt-svc cache is h3.
//   - serve/h3/quiet-h3: the advertise:false zone is still reachable by a
//     client that asks for h3 explicitly (the canary's point).
//   - serve/h3/non-h3-zone: QUIC to a zone that did not ask is refused (the
//     UDP default server rejects the handshake); TCP still serves it.
//   - serve/h3/catch-all-rejects, serve/h3/anchor-rejects: an unknown SNI over
//     QUIC is refused both with the catch-all and, under omit_catch_all, with
//     the QUIC anchor.
//   - serve/h3/retry: h3probe sees a Retry with the default quic_retry and
//     none with quic.retry:false — the http-level placement takes effect.
//   - serve/h3/decider (Linux only, needs the unix sockets): over h3 a 403
//     denies, a rate denial is 429 + Retry-After, a 200's mark reaches the
//     origin, a 401 lands on the clearance page, the subrequest carries the
//     kapkan headers, and the access log says proto=HTTP/3.0.
//
// On an image without the module (nginx:1.22):
//
//   - serve/h3/degrades: the zone that asked is served over TCP, `--http3-only`
//     fails, and the rendered zone file says why.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

const (
	// h3clientTag is the sidecar image the run builds from hack/h3client.
	h3clientTag = "kapkan-h3client:e5-test"
	// h3clientDir and h3probeDir are relative to this package's directory,
	// where `go test` runs.
	h3clientDir = "../../../hack/h3client"
	h3probeDir  = "../../../hack/h3probe"
)

// h3tools is built once per run: the curl image and the linux h3probe binary
// (under <work>/h3probe, so every client container can mount it).
var h3tools struct {
	once  sync.Once
	err   error
	probe string
}

// h3Clients builds the two clients on first use and fails the test if either
// cannot be had — an h3 arm must never pass over a client that lacks h3.
func (h *harness) h3Clients(t *testing.T) {
	t.Helper()
	h3tools.once.Do(func() {
		out, err := exec.Command("docker", "build", "-q", "-t", h3clientTag, h3clientDir).CombinedOutput()
		if err != nil {
			h3tools.err = fmt.Errorf("docker build %s: %v\n%s", h3clientDir, err, out)
			return
		}
		arch, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
		if err != nil {
			h3tools.err = fmt.Errorf("docker version: %v", err)
			return
		}
		bin := filepath.Join(h.work, "h3probe")
		build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
		build.Dir = h3probeDir
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)))
		if out, err := build.CombinedOutput(); err != nil {
			h3tools.err = fmt.Errorf("go build h3probe (linux/%s): %v\n%s", strings.TrimSpace(string(arch)), err, out)
			return
		}
		h3tools.probe = bin
	})
	if h3tools.err != nil {
		t.Fatalf("HTTP/3 clients: %v", h3tools.err)
	}
}

// bridgeIP is the terminator container's address on the Docker bridge, where
// the client containers reach it directly — UDP included. Read from the
// per-network endpoint: the legacy top-level NetworkSettings.IPAddress is gone
// from Docker 29's inspect output.
func (s *served) bridgeIP(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", s.id).Output()
	if err != nil {
		t.Fatalf("docker inspect %s: %v", s.id, err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		t.Fatalf("terminator %s has no bridge address", s.id)
	}
	return ip
}

// clientArgs is the `docker run` prefix for a client container: on the
// terminator's bridge, every fixture zone name resolving to the terminator,
// the work directory mounted for certificates, the probe and curl's caches.
func (s *served) clientArgs(t *testing.T, fixture string) []string {
	t.Helper()
	ip := s.bridgeIP(t)
	args := []string{"run", "--rm", "-v", s.h.work + ":" + containerWork}
	fx := loadFixture(t, fixture)
	for _, z := range fx.Doc.Zones {
		args = append(args, "--add-host", z.Name+":"+ip)
	}
	return args
}

// curlResult is one sidecar request: curl's exit status, the body it printed,
// and the trailer -w wrote (status and HTTP version).
type curlResult struct {
	exit    int
	body    string
	code    string
	version string
	raw     string
}

// h3curl runs stock curl in the sidecar against the zone. extra are curl
// flags placed before the URL (`--http3-only`, `--alt-svc file`, `-i`…). The
// certificate is the test's own self-signed one, so -k, as the Go client's
// InsecureSkipVerify does.
func (s *served) h3curl(t *testing.T, fixture, zone, path string, extra ...string) curlResult {
	t.Helper()
	s.h.h3Clients(t)
	args := append(s.clientArgs(t, fixture), h3clientTag, "-s", "-k", "-m", "10", "-w", "\n::%{http_code}::%{http_version}::")
	args = append(args, extra...)
	args = append(args, "https://"+zone+path)
	out, err := exec.Command("docker", args...).CombinedOutput()
	res := curlResult{raw: string(out)}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.exit = ee.ExitCode()
		} else {
			t.Fatalf("docker run curl: %v\n%s", err, out)
		}
	}
	// The trailer is the last "::code::version::" curl wrote; on a failed
	// request it says 000 and the body is whatever curl printed before.
	if i := strings.LastIndex(res.raw, "\n::"); i >= 0 {
		res.body = res.raw[:i]
		parts := strings.Split(strings.TrimSpace(res.raw[i+1:]), "::")
		if len(parts) >= 3 {
			res.code, res.version = parts[1], parts[2]
		}
	} else {
		res.body = res.raw
	}
	t.Logf("curl %s https://%s%s -> exit %d, %s HTTP/%s", strings.Join(extra, " "), zone, path, res.exit, res.code, res.version)
	return res
}

// probeResult mirrors hack/h3probe's JSON object (its field names are the
// tool's contract; see its usage text).
type probeResult struct {
	Status    int    `json:"status"`
	ALPN      string `json:"alpn"`
	Proto     string `json:"proto"`
	AltSvc    string `json:"alt_svc"`
	RetrySeen bool   `json:"retry_seen"`
	Resumed   bool   `json:"resumed"`
	Error     string `json:"error"`
}

// h3probe runs the instrumented client against the zone: one QUIC connection,
// SNI as given (the zone, or a name no zone has), and the handshake facts.
func (s *served) h3probe(t *testing.T, fixture, zone, sni, path string) probeResult {
	t.Helper()
	s.h.h3Clients(t)
	args := append(s.clientArgs(t, fixture), "--entrypoint", containerWork+"/h3probe", h3clientTag,
		"get", "-url", "https://"+zone+path, "-sni", sni, "-insecure", "-timeout", "8s")
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("h3probe: %v\n%s", err, stderr)
	}
	var res probeResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("h3probe printed no JSON object: %v\n%s", err, out)
	}
	t.Logf("h3probe %s (sni %s)%s -> %+v", zone, sni, path, res)
	return res
}

// h3Arms is the HTTP/3 half of TestRealTerminator, split by what the image can do.
func (h *harness) h3Arms(t *testing.T) {
	if !h.term.HTTP3Module {
		// D2, honest degrade: the render for a zone that asked is TCP-only,
		// says so, and an h3 client cannot reach it — while TCP is served.
		t.Run("serve/h3/degrades", func(t *testing.T) {
			s := h.serve(t, "h3", "degrades")
			s.get(t, "example.com", "/").expect(t, 200, "origin-ok")
			if res := s.h3curl(t, "h3", "example.com", "/", "--http3-only"); res.exit == 0 || res.code == "200" {
				t.Errorf("a build without the module served HTTP/3: exit %d, %s HTTP/%s\n%s", res.exit, res.code, res.version, res.raw)
			}
			zoneFile, err := os.ReadFile(filepath.Join(h.work, "h3", "degrades", "conf", "kapkan_zone_example.com.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(zoneFile), "HTTP/3 ASKED FOR, NOT RENDERED") || strings.Contains(string(zoneFile), "quic") {
				t.Errorf("degraded zone file does not say why, or still carries QUIC:\n%s", zoneFile)
			}
		})
		return
	}

	t.Run("serve/h3/request", func(t *testing.T) {
		s := h.serve(t, "h3", "request")
		res := s.h3curl(t, "h3", "example.com", "/h3?x=1", "--http3-only")
		if res.exit != 0 || res.code != "200" || res.version != "3" || !strings.Contains(res.body, "origin-ok") || !strings.Contains(res.body, "zone=example.com;") {
			t.Errorf("decide zone over HTTP/3: exit %d, %s HTTP/%s\n%s", res.exit, res.code, res.version, res.raw)
		}
		res = s.h3curl(t, "h3", "static.example.org", "/static", "--http3-only")
		if res.exit != 0 || res.code != "200" || res.version != "3" || !strings.Contains(res.body, "origin-ok") {
			t.Errorf("mode:none zone over HTTP/3: exit %d, %s HTTP/%s\n%s", res.exit, res.code, res.version, res.raw)
		}
	})

	// The browser path: TCP first, Alt-Svc learnt, the next connection h3.
	// curl's --alt-svc cache is the browser's memory here; both calls share it.
	t.Run("serve/h3/alt-svc-upgrade", func(t *testing.T) {
		s := h.serve(t, "h3", "alt-svc-upgrade")
		cache := containerWork + "/h3/alt-svc-upgrade/altsvc.cache"
		_ = os.Remove(filepath.Join(h.work, "h3", "alt-svc-upgrade", "altsvc.cache"))
		first := s.h3curl(t, "h3", "example.com", "/first", "-i", "--alt-svc", cache)
		if first.exit != 0 || first.code != "200" || first.version != "2" || !strings.Contains(strings.ToLower(first.body), "alt-svc: h3=\":443\"; ma=86400") {
			t.Errorf("first request should be h2 with Alt-Svc: exit %d, %s HTTP/%s\n%s", first.exit, first.code, first.version, first.raw)
		}
		second := s.h3curl(t, "h3", "example.com", "/second", "--alt-svc", cache)
		if second.exit != 0 || second.code != "200" || second.version != "3" || !strings.Contains(second.body, "zone=example.com;") {
			t.Errorf("second request should have upgraded to h3 via Alt-Svc: exit %d, %s HTTP/%s\n%s", second.exit, second.code, second.version, second.raw)
		}
	})

	// The canary (D8): advertise:false renders the QUIC listener without the
	// announcement — browsers stay on TCP (serve/h3/quiet pins the absent
	// header), a client that asks for h3 explicitly is served.
	t.Run("serve/h3/quiet-h3", func(t *testing.T) {
		s := h.serve(t, "h3-quiet", "quiet-h3")
		res := s.h3curl(t, "h3-quiet", "example.com", "/canary", "--http3-only")
		if res.exit != 0 || res.code != "200" || res.version != "3" {
			t.Errorf("quiet zone not reachable over HTTP/3: exit %d, %s HTTP/%s\n%s", res.exit, res.code, res.version, res.raw)
		}
	})

	// A zone that did not ask has no QUIC server: the UDP default server
	// (the catch-all) answers its SNI with a rejected handshake.
	t.Run("serve/h3/non-h3-zone", func(t *testing.T) {
		s := h.serve(t, "h3", "non-h3-zone")
		s.get(t, "plain.example.net", "/").expect(t, 200, "origin-ok")
		if res := s.h3curl(t, "h3", "plain.example.net", "/", "--http3-only"); res.exit == 0 || res.code == "200" {
			t.Errorf("a zone without tls.h3 answered over HTTP/3: exit %d, %s HTTP/%s\n%s", res.exit, res.code, res.version, res.raw)
		}
	})

	// Unknown SNI over QUIC is refused by whichever server owns the UDP
	// default: the catch-all, or under omit_catch_all the QUIC anchor.
	for _, c := range []struct{ arm, fixture string }{{"catch-all-rejects", "h3"}, {"anchor-rejects", "h3-omit-catchall"}} {
		t.Run("serve/h3/"+c.arm, func(t *testing.T) {
			s := h.serve(t, c.fixture, c.arm)
			res := s.h3probe(t, c.fixture, "example.com", "unknown.invalid", "/")
			if res.Status != 0 || res.Error == "" {
				t.Errorf("unknown SNI over QUIC was served (%s): %+v", c.fixture, res)
			}
			// The known zone on the same address still works: the rejection is
			// the default server's, not the socket's.
			if ok := s.h3probe(t, c.fixture, "example.com", "example.com", "/known"); ok.Status != 200 || ok.ALPN != "h3" || ok.Proto != "HTTP/3.0" {
				t.Errorf("known zone over QUIC (%s): %+v", c.fixture, ok)
			}
		})
	}

	// Retry is node-wide at the http level (D3): on by default, off with
	// quic.retry:false — both observed on the wire by the instrumented client.
	t.Run("serve/h3/retry", func(t *testing.T) {
		s := h.serve(t, "h3", "retry-on")
		on := s.h3probe(t, "h3", "example.com", "example.com", "/retry")
		if on.Status != 200 || on.ALPN != "h3" || on.Proto != "HTTP/3.0" || !on.RetrySeen {
			t.Errorf("default quic_retry on: want a Retry before a 200 over h3, got %+v", on)
		}
		if !strings.Contains(on.AltSvc, `h3=":443"`) {
			t.Errorf("Alt-Svc on the h3 response itself: %q", on.AltSvc)
		}
		// h3-noipv6 is the fixture with quic_retry:false. Its zone is
		// failure_mode:closed and this arm runs no decider, so the request itself
		// is answered 503 (as serve/decide-closed/no-decider pins) — over h3,
		// after a handshake with no Retry, which is the fact under test.
		off := h.serve(t, "h3-noipv6", "retry-off")
		res := off.h3probe(t, "h3-noipv6", "example.com", "example.com", "/retry")
		if res.Status != 503 || res.ALPN != "h3" || res.Proto != "HTTP/3.0" || res.RetrySeen {
			t.Errorf("quic.retry:false: want the zone's own 503 over h3 with no Retry, got %+v", res)
		}
	})

	if runtime.GOOS != "linux" {
		t.Logf("serve/h3/decider needs the decision sockets across the bind mount (Linux only); skipped on %s", runtime.GOOS)
		return
	}
	// The same decisions over h3 as over TCP, made by the same local decider,
	// and logged with the protocol the rollups count.
	t.Run("serve/h3/decider", func(t *testing.T) {
		s := h.serve(t, "h3", "decider")
		d := h.startDecider(t)
		logs := h.startLogSink(t)
		h.startClearancePage(t)

		d.set(403, "")
		if res := s.h3curl(t, "h3", "example.com", "/probe?x=1", "--http3-only"); res.code != "403" || res.version != "3" {
			t.Errorf("403 over h3: %s HTTP/%s\n%s", res.code, res.version, res.raw)
		}
		seen := d.last()
		if seen == nil {
			t.Fatal("the decision service was not consulted over h3")
		}
		rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/probe?x=1" })
		if rec.Proto != "HTTP/3.0" || rec.Zone != "example.com" || rec.Port != 443 || rec.Status != 403 || rec.Decision != "403" || !rec.Decided() {
			t.Errorf("access-log record over h3: %+v (proto must be HTTP/3.0 — what kapkan_edge_requests_total{protocol=h3} counts)", rec)
		}
		for k, want := range map[string]string{"X-Kapkan-Zone": "example.com", "X-Kapkan-Uri": "/probe?x=1", "X-Kapkan-Method": "GET"} {
			if got := seen.req.Header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if seen.req.Header.Get("X-Kapkan-Client") == "" {
			t.Error("X-Kapkan-Client is empty on an h3 request")
		}

		d.setReason(403, "rate")
		if res := s.h3curl(t, "h3", "example.com", "/limited", "-i", "--http3-only"); res.code != "429" || !strings.Contains(strings.ToLower(res.body), "retry-after: 1") {
			t.Errorf("rate denial over h3: %s HTTP/%s\n%s", res.code, res.version, res.raw)
		}
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/limited" }); rec.Status != 429 || rec.Reason != "rate" || rec.Proto != "HTTP/3.0" {
			t.Errorf("rate denial's record over h3: %+v", rec)
		}

		d.set(200, "suspicious")
		if res := s.h3curl(t, "h3", "example.com", "/marked", "--http3-only"); res.code != "200" || !strings.Contains(res.body, "origin-ok mark=suspicious;zone=example.com;") {
			t.Errorf("allowed request over h3: %s\n%s", res.code, res.raw)
		}

		d.setReason(401, "challenge:manual")
		if res := s.h3curl(t, "h3", "example.com", "/cart?x=1", "--http3-only"); res.code != "403" || !strings.Contains(res.body, "clearance-page zone=example.com uri=/cart?x=1 reason=challenge:manual") {
			t.Errorf("401 over h3 should land on the clearance page: %s\n%s", res.code, res.raw)
		}
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/cart?x=1" }); rec.Status != 403 || rec.Decision != "401" || !rec.Challenged() || rec.Proto != "HTTP/3.0" {
			t.Errorf("challenge's record over h3: %+v", rec)
		}

		if crit := critLines(s.logs(t)); len(crit) > 0 {
			t.Errorf("terminator logged at crit level:\n%s", strings.Join(crit, "\n"))
		}
	})
}

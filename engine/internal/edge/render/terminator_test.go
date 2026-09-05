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
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/render"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
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
	originBody = `origin-ok mark=$http_x_kapkan_mark;zone=$http_x_kapkan_zone;conn=$http_connection;upg=$http_upgrade;len=$content_length;uri=$request_uri;`
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
		logs := h.startLogSink(t)

		d.set(403, "")
		s.get(t, "example.com", "/probe?x=1").expect(t, 403, "")
		seen := d.last()
		if seen == nil {
			t.Fatal("the decision service was not consulted")
		}
		// The access log names the request, the port and the decision — what
		// the rollup will aggregate and what closes the decider's in-flight
		// slot — and its src is the very address the decider was asked about.
		rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/probe?x=1" })
		if rec.Zone != "example.com" || rec.Port != 443 || rec.Status != 403 || rec.Decision != "403" || rec.Method != "GET" || !rec.Decided() || rec.Host != "example.com" {
			t.Errorf("access-log record: %+v", rec)
		}
		if client, err := netipParse(seen.req.Header.Get("X-Kapkan-Client")); err != nil || client != rec.Src {
			t.Errorf("log src %v differs from the decider's client %q", rec.Src, seen.req.Header.Get("X-Kapkan-Client"))
		}

		// A denial's reason decides its status: rate → 429 + Retry-After,
		// table → 403; both are logged with the reason.
		d.setReason(403, "rate")
		res429 := s.get(t, "example.com", "/limited")
		res429.expect(t, 429, "")
		if ra := res429.header.Get("Retry-After"); ra != "1" {
			t.Errorf("Retry-After = %q on a rate denial", ra)
		}
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/limited" }); rec.Status != 429 || rec.Decision != "403" || rec.Reason != "rate" {
			t.Errorf("rate denial's record: %+v", rec)
		}
		d.setReason(403, "table:flood")
		s.get(t, "example.com", "/banned").expect(t, 403, "")
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/banned" }); rec.Status != 403 || rec.Reason != "table:flood" {
			t.Errorf("table denial's record: %+v", rec)
		}

		// Nothing the client sends can push the subrequest off the contract:
		// 22 KiB of junk headers and a cookie — above the 16 KiB the decider
		// once capped at, below nginx's own 32 KiB (large_client_header_buffers)
		// so nginx admits the request — never reach the decider, and the
		// request is still decided (a 429, not an undecided 200).
		junk := http.Header{"Cookie": {"session=" + strings.Repeat("c", 2000)}}
		for i := 0; i < 20; i++ {
			junk.Set(fmt.Sprintf("X-Junk-%d", i), strings.Repeat("j", 1000))
		}
		d.setReason(403, "rate")
		s.request(t, "GET", true, "example.com", "/junk", "", junk).expect(t, 429, "")
		seenJunk := d.last()
		if seenJunk.req.URL.Path != "/decide" || seenJunk.req.Header.Get("X-Junk-0") != "" || seenJunk.req.Header.Get("Cookie") != "" || seenJunk.req.Header.Get("X-Kapkan-Uri") != "/junk" {
			t.Errorf("client headers reached the decider: %v", seenJunk.req.Header)
		}
		// A control byte in a header value: nginx accepts it, the decider must
		// never see it, and the decision still happens.
		if line := s.rawRequest(t, "example.com", "GET /ctl HTTP/1.1\r\nHost: example.com\r\nX-Bad: a\x01b\r\nConnection: close\r\n\r\n"); !strings.Contains(line, " 429 ") {
			t.Errorf("control byte in a client header: status line %q, want a decided 429", line)
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
		s.get(t, "example.com", "/marked").expect(t, 200, "origin-ok mark=suspicious;")
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/marked" }); rec.Decision != "200" || rec.Status != 200 {
			t.Errorf("allowed request's record: %+v", rec)
		}

		// Off-contract answer: undecided, its mark dropped, keepalive intact —
		// and the log says the decision was not made (a 5xx, not 200/403).
		d.set(500, "leak")
		res = s.get(t, "example.com", "/undecided")
		res.expect(t, 200, "origin-ok mark=;zone=example.com;")
		if c := res.header.Get("Connection"); c != "keep-alive" {
			t.Errorf("fail-open after an off-contract answer carries Connection %q", c)
		}
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/undecided" }); rec.Decision != "500" || rec.Decided() || rec.Status != 200 {
			t.Errorf("undecided request's record: %+v", rec)
		}

		// With every socket it needs present — the log socket included, since
		// this arm runs the real listener — the terminator logs nothing at crit
		// level. Syslog connect failures are still excluded (critLines): the
		// listener starts after the container, so the first lines may predate it.
		if crit := critLines(s.logs(t)); len(crit) > 0 {
			t.Errorf("terminator logged at crit level:\n%s", strings.Join(crit, "\n"))
		}

		// The auth_request tax, measured through the terminator (edge-spec §5,
		// §8): keep-alive GETs with a 200-answering decider versus a zone that
		// does not decide. Logged, not gated — the runner's noise is not ours.
		d.set(200, "")
		p50, p99 := s.timeGets(t, "example.com", 200)
		none := h.serve(t, "mode-none", "overhead")
		n50, n99 := none.timeGets(t, "static.example.org", 200)
		t.Logf("auth_request overhead through %s: decide p50 %v / p99 %v, none p50 %v / p99 %v, added p50 %v", image, p50, p99, n50, n99, p50-n50)
	})
	t.Run("serve/decide-open/challenge", func(t *testing.T) {
		s := h.serve(t, "decide-open", "challenge")
		d := h.startDecider(t)
		logs := h.startLogSink(t)
		page := h.startClearancePage(t)

		// A 401 from the decider lands on the clearance page: the client gets
		// the page's status and body, never the 401; the log carries the
		// decision and the reason.
		d.setReason(401, "challenge:manual")
		res := s.get(t, "example.com", "/cart?x=1")
		res.expect(t, 403, "clearance-page zone=example.com uri=/cart?x=1 reason=challenge:manual path=/cart?x=1")
		if cc := res.header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q on the challenge page", cc)
		}
		if rec := logs.wait(t, func(r rollup.Record) bool { return r.URI == "/cart?x=1" }); rec.Status != 403 || rec.Decision != "401" || rec.Reason != "challenge:manual" || !rec.Decided() || !rec.Challenged() {
			t.Errorf("challenge's record: %+v", rec)
		}
		// Only the clearance cookie's VALUE reaches the decider, in its own
		// header; the Cookie header itself and everything else stay behind.
		d.set(200, "cleared")
		hdr := http.Header{"Cookie": {"junk=1; kapkan_clr=v1.c1.pow.1.abc; other=" + strings.Repeat("o", 500)}}
		s.request(t, "GET", true, "example.com", "/with-cookie", "", hdr).expect(t, 200, "origin-ok mark=cleared;")
		seen := d.last()
		if seen.req.Header.Get("X-Kapkan-Clearance") != "v1.c1.pow.1.abc" || seen.req.Header.Get("Cookie") != "" {
			t.Errorf("clearance forwarding: %v", seen.req.Header)
		}
		// Without the cookie the header is absent (an empty proxy_set_header
		// value removes it), never something else.
		d.set(200, "")
		s.get(t, "example.com", "/no-cookie").expect(t, 200, "")
		if got := d.last().req.Header.Get("X-Kapkan-Clearance"); got != "" {
			t.Errorf("X-Kapkan-Clearance without a cookie = %q", got)
		}
		// A cookie that is not shaped like a token — a control byte, a space,
		// a quote — is forwarded as NOTHING: Go's server would refuse a header
		// carrying it as malformed, and that failed decision would pass the
		// request under failure_mode: open. The request must still be DECIDED.
		d.set(200, "")
		if line := s.rawRequest(t, "example.com", "GET /ctl-cookie HTTP/1.1\r\nHost: example.com\r\nCookie: kapkan_clr=a\x01b\r\nConnection: close\r\n\r\n"); !strings.Contains(line, " 200 ") {
			t.Errorf("control byte in the cookie: status line %q", line)
		}
		if seen := d.last(); seen == nil || seen.req.Header.Get("X-Kapkan-Uri") != "/ctl-cookie" || seen.req.Header.Get("X-Kapkan-Clearance") != "" {
			t.Errorf("control-byte cookie: decider saw %v", seen)
		}
		hdr = http.Header{"Cookie": {`kapkan_clr="quoted value"`}}
		s.request(t, "GET", true, "example.com", "/odd-cookie", "", hdr).expect(t, 200, "")
		if got := d.last().req.Header.Get("X-Kapkan-Clearance"); got != "" {
			t.Errorf("an unshaped cookie was forwarded: %q", got)
		}
		// Exemptions are matched on nginx's NORMALISED path beside the raw
		// target: the decider sees /admin for a dot-segment request.
		s.get(t, "example.com", "/healthz/../admin?x=1").expect(t, 200, "")
		if seen := d.last(); seen.req.Header.Get("X-Kapkan-Path") != "/admin" || seen.req.Header.Get("X-Kapkan-Uri") != "/healthz/../admin?x=1" {
			t.Errorf("path normalisation: %v", seen.req.Header)
		}
		// A percent-encoded control byte decodes into $uri; it must NOT reach
		// the decider as a header byte (Go would refuse the subrequest — a
		// failed decision, which fail-open would pass). The request is still
		// DECIDED, with the path header simply absent.
		d.set(403, "")
		s.get(t, "example.com", "/x/%01?y=1").expect(t, 403, "")
		if seen := d.last(); seen == nil || seen.req.Header.Get("X-Kapkan-Uri") != "/x/%01?y=1" || seen.req.Header.Get("X-Kapkan-Path") != "" {
			t.Errorf("control byte in the decoded path: decider saw %v", seen)
		}
		s.get(t, "example.com", "/x/%7f").expect(t, 403, "")
		if seen := d.last(); seen == nil || seen.req.Header.Get("X-Kapkan-Path") != "" {
			t.Errorf("DEL in the decoded path: decider saw %v", seen)
		}
		// Non-ASCII decodes to bytes Go accepts and IS forwarded (an /api/
		// exemption must cover /api/items/café); a double-encoded dot stays
		// encoded in nginx's decoded form, so the decider sees the '%' and
		// can refuse the exemption; ordinary paths are forwarded as they are.
		s.get(t, "example.com", "/caf%C3%A9").expect(t, 403, "")
		if seen := d.last(); seen.req.Header.Get("X-Kapkan-Path") != "/café" {
			t.Errorf("non-ASCII path: %q", seen.req.Header.Get("X-Kapkan-Path"))
		}
		s.get(t, "example.com", "/api/%252e%252e/admin").expect(t, 403, "")
		if seen := d.last(); seen.req.Header.Get("X-Kapkan-Path") != "/api/%2e%2e/admin" || seen.req.Header.Get("X-Kapkan-Uri") != "/api/%252e%252e/admin" {
			t.Errorf("double-encoded path: %v", seen.req.Header)
		}
		// A single %25 decodes to a bare '%' — a literal, forwarded as such.
		s.get(t, "example.com", "/api/coupons/50%25-off").expect(t, 403, "")
		if seen := d.last(); seen.req.Header.Get("X-Kapkan-Path") != "/api/coupons/50%-off" {
			t.Errorf("literal percent: %q", seen.req.Header.Get("X-Kapkan-Path"))
		}
		s.get(t, "example.com", "/plain/path.txt?q=1").expect(t, 403, "")
		if seen := d.last(); seen.req.Header.Get("X-Kapkan-Path") != "/plain/path.txt" {
			t.Errorf("plain path not forwarded: %q", seen.req.Header.Get("X-Kapkan-Path"))
		}
		d.set(200, "")

		// The page's public endpoints are reachable from outside without a
		// decision, GET/HEAD/POST with a small body, kapkan's headers only;
		// the decision endpoints are not.
		d.set(403, "")
		s.get(t, "example.com", "/_kapkan/clearance/answer").expect(t, 200, "clearance-public path=/_kapkan/clearance/answer zone=example.com")
		body := `{"nonce":"n","solution":"s"}`
		res = s.request(t, "POST", true, "example.com", "/_kapkan/clearance/answer", body, http.Header{"Cookie": {"kapkan_clr=old"}, "Content-Type": {"application/json"}})
		res.expect(t, 200, "body="+body)
		res.expect(t, 200, "ctype=application/json")
		res.expect(t, 200, "clr=old")
		if last := page.last(); last == nil || last.Header.Get("Cookie") != "" || last.Header.Get("X-Kapkan-Client") == "" {
			t.Errorf("public endpoint's headers: %v", last)
		}
		s.request(t, "PUT", true, "example.com", "/_kapkan/clearance/answer", "x", nil).expect(t, 403, "")
		if r, err := s.try("POST", true, "example.com", "/_kapkan/clearance/answer", strings.Repeat("b", 5000), nil, 0); err == nil && r.status != 413 {
			t.Errorf("5 KB answer body: status %d, want 413", r.status)
		}
		s.get(t, "example.com", "/_kapkan/decide").expect(t, 404, "")
		s.get(t, "example.com", "/_kapkan/undecided").expect(t, 404, "")
		if last := page.last(); last != nil && last.Header.Get("X-Kapkan-Uri") == "/_kapkan/decide" {
			t.Error("the decision endpoint reached the page")
		}

		// The page answering 5xx (the node's placeholder before E4.3, or a
		// broken page) and the page server gone: failure_mode open passes the
		// challenged request to the origin, undecided-style, with no mark —
		// and with the CLIENT's URI, not the page's.
		d.setReason(401, "challenge:manual")
		page.fail(true)
		s.get(t, "example.com", "/page-503?y=2").expect(t, 200, "origin-ok mark=;zone=example.com;")
		s.get(t, "example.com", "/page-503?y=2").expect(t, 200, "uri=/page-503?y=2;")
		page.stop()
		res = s.get(t, "example.com", "/page-down")
		res.expect(t, 200, "origin-ok mark=;zone=example.com;")
		res.expect(t, 200, "uri=/page-down;")
	})
	t.Run("serve/decide-closed/challenge", func(t *testing.T) {
		s := h.serve(t, "decide-closed", "challenge")
		d := h.startDecider(t)
		page := h.startClearancePage(t)
		// The page up: served. Answering 5xx, or gone: failure_mode closed
		// answers the challenged request with 503, as it would a failed
		// decision.
		d.setReason(401, "challenge:manual")
		s.get(t, "closed.example.net", "/").expect(t, 403, "clearance-page zone=closed.example.net")
		page.fail(true)
		s.get(t, "closed.example.net", "/").expect(t, 503, "")
		page.stop()
		s.get(t, "closed.example.net", "/").expect(t, 503, "")
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
		ClearanceSocket: containerWork + "/run/clearance.sock",
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
	for _, sock := range []string{"decide.sock", "challenge.sock", "clearance.sock"} {
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
	fx := loadFixture(t, name)
	tlsZone := ""
	for zone := range fx.Certs {
		tlsZone = zone
		break
	}
	zone80 := ""
	if len(fx.Doc.Zones) > 0 {
		zone80 = fx.Doc.Zones[0].Name
	}
	s.waitReady(t, zone80, tlsZone)
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
// or not — until the terminator ANSWERS a request for zone80 (any status: a
// 301 to https or a no-certificate 503 both mean a worker is serving), and,
// when the fixture has a TLS zone, completes a TLS handshake with it: a
// worker that accepts on :80 may still be a moment away from serving TLS
// (Angie reset the first handshake once on CI), and the first assertion must
// not be that moment. A bare TCP connect is not proof of anything here: the
// port is published through Docker's userland proxy, which accepts before
// the container listens and resets the first real request (nginx:stable did
// exactly that to the no-cert arm once on CI).
func (s *served) waitReady(t *testing.T, zone80, tlsZone string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	accepted := false
	for time.Now().Before(deadline) {
		if !accepted {
			if zone80 != "" {
				if _, err := s.try("GET", false, zone80, "/", "", nil, 0); err == nil {
					accepted = true
				}
			} else if c, err := net.DialTimeout("tcp", s.port80, time.Second); err == nil {
				_ = c.Close()
				accepted = true
			}
		}
		if accepted {
			if tlsZone == "" {
				return
			}
			d := &net.Dialer{Timeout: time.Second}
			c, err := tls.DialWithDialer(d, "tcp", s.port443, &tls.Config{InsecureSkipVerify: true, ServerName: tlsZone})
			if err == nil {
				_ = c.Close()
				return
			}
		}
		if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.id).Output(); err == nil && strings.TrimSpace(string(out)) == "false" {
			t.Fatalf("terminator exited during start:\n%s", s.logs(t))
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("terminator not ready on %s / %s after 20s", s.port80, s.port443)
}

// rawRequest writes a request line and headers verbatim over TLS to the zone
// and returns the status line — for headers Go's client refuses to send.
func (s *served) rawRequest(t *testing.T, zone, raw string) string {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", s.port443, &tls.Config{InsecureSkipVerify: true, ServerName: zone})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read: %v", err)
	}
	line, _, _ := strings.Cut(string(buf[:n]), "\r\n")
	return line
}

// timeGets measures n keep-alive GETs to the zone on one connection and
// returns the p50 and p99 round trips.
func (s *served) timeGets(t *testing.T, zone string, n int) (p50, p99 time.Duration) {
	t.Helper()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", s.port443)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: zone},
		MaxIdleConnsPerHost: 1,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n+5; i++ {
		start := time.Now()
		resp, err := client.Get("https://" + zone + "/bench")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if i >= 5 { // the first few warm the connection and the caches
			samples = append(samples, time.Since(start))
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], samples[len(samples)*99/100]
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
	reason string
	seen   *seenRequest
}

type seenRequest struct {
	req  *http.Request
	body int64
}

func (d *decider) set(status int, mark string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status, d.mark, d.reason = status, mark, ""
}

// setReason answers status with an X-Kapkan-Reason, as the real service does
// on a denial.
func (d *decider) setReason(status int, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status, d.mark, d.reason = status, "", reason
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
	if d.reason != "" {
		w.Header().Set("X-Kapkan-Reason", d.reason)
	}
	w.WriteHeader(d.status)
}

func (h *harness) startDecider(t *testing.T) *decider {
	t.Helper()
	d := &decider{status: 403}
	h.serveUnix(t, "decide.sock", d)
	return d
}

// clearancePage is a stand-in clearance page server on the fourth socket. It
// echoes what it was given so the test can see the contract: the challenge
// endpoint answers 403 no-store (the page's real status, D5), the public
// endpoints echo path, body, content type and the forwarded clearance value.
type clearancePage struct {
	mu      sync.Mutex
	seen    *http.Request
	failing bool
	stop    func()
}

func (p *clearancePage) last() *http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

// fail makes the page answer 503 to everything, as the node's placeholder
// does before E4.3 (and a broken page would).
func (p *clearancePage) fail(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failing = on
}

func (p *clearancePage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	p.mu.Lock()
	p.seen = r.Clone(r.Context())
	failing := p.failing
	p.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	if failing {
		http.Error(w, "page down", http.StatusServiceUnavailable)
		return
	}
	// The challenge entry point is known by X-Kapkan-Reason, which only the
	// named location sets; the URI is the client's own.
	if r.Header.Get("X-Kapkan-Reason") != "" {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "clearance-page zone=%s uri=%s reason=%s path=%s", r.Header.Get("X-Kapkan-Zone"), r.Header.Get("X-Kapkan-URI"), r.Header.Get("X-Kapkan-Reason"), r.URL.RequestURI())
		return
	}
	_, _ = fmt.Fprintf(w, "clearance-public path=%s zone=%s body=%s ctype=%s clr=%s", r.URL.Path, r.Header.Get("X-Kapkan-Zone"), body, r.Header.Get("Content-Type"), r.Header.Get("X-Kapkan-Clearance"))
}

func (h *harness) startClearancePage(t *testing.T) *clearancePage {
	t.Helper()
	p := &clearancePage{}
	p.stop = h.serveUnix(t, "clearance.sock", p)
	return p
}

func (h *harness) startChallenge(t *testing.T) {
	t.Helper()
	h.serveUnix(t, "challenge.sock", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		_, _ = fmt.Fprintf(w, "key-auth-for-%s zone=%s body=%d", token, r.Header.Get("X-Kapkan-Zone"), n)
	}))
}

// logSink receives the terminator's access log on the work directory's log
// socket, through the same listener a node runs (internal/edge/rollup).
type logSink struct {
	mu   sync.Mutex
	recs []rollup.Record
}

func (h *harness) startLogSink(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{}
	l := &rollup.Listener{Path: filepath.Join(h.work, "run", "log.sock"), Mode: 0o666, Handle: func(r rollup.Record) {
		sink.mu.Lock()
		sink.recs = append(sink.recs, r)
		sink.mu.Unlock()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = l.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return sink
}

// wait returns the first received record matching match, failing after 5 s.
func (s *logSink) wait(t *testing.T, match func(rollup.Record) bool) rollup.Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, r := range s.recs {
			if match(r) {
				s.mu.Unlock()
				return r
			}
		}
		s.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("no matching access-log record received; have %d: %+v", len(s.recs), s.recs)
	return rollup.Record{}
}

// serveUnix listens on <work>/run/<name> — the path the container sees as
// /w/run/<name> — world-connectable so the terminator's worker user may use it
// (a deployment uses 0660 and the worker's group; the container's uid is not
// in any group of ours).
func (h *harness) serveUnix(t *testing.T, name string, handler http.Handler) (stop func()) {
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
	stop = func() {
		_ = srv.Close()
		_ = os.Remove(path)
	}
	t.Cleanup(stop)
	return stop
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

func netipParse(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	return a.Unmap(), err
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

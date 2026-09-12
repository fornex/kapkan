package render_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/render"
)

var update = flag.Bool("update", false, "rewrite testdata/golden from the current renderer")

// fixtureNames lists testdata/fixtures/*.json without the extension. The same
// fixtures feed the golden test here and the real-terminator test.
func fixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no fixtures under testdata/fixtures")
	}
	return names
}

// loadFixture decodes one fixture strictly: an unknown key in a fixture is a
// typo that would silently test nothing.
func loadFixture(t *testing.T, name string) render.Inputs {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "fixtures", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var in render.Inputs
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return in
}

// TestGolden compares every fixture's render with testdata/golden/<fixture>/.
// `go test ./internal/edge/render -update` rewrites the golden files; review
// the diff like any other change to what a node installs.
func TestGolden(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			files, err := render.Render(loadFixture(t, name))
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			dir := filepath.Join("testdata", "golden", name)
			if *update {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for n, b := range files {
					if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("no golden files for %s (run: go test ./internal/edge/render -update): %v", name, err)
			}
			want := make(map[string][]byte, len(entries))
			for _, e := range entries {
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				want[e.Name()] = b
			}
			gotNames := files.Names()
			wantNames := make([]string, 0, len(want))
			for n := range want {
				wantNames = append(wantNames, n)
			}
			sort.Strings(wantNames)
			if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
				t.Fatalf("file set differs\n got %v\nwant %v", gotNames, wantNames)
			}
			for _, n := range wantNames {
				if !bytes.Equal(want[n], files[n]) {
					t.Errorf("%s differs from golden:\n%s", n, firstDiff(want[n], files[n]))
				}
			}
		})
	}
}

func firstDiff(want, got []byte) string {
	w := strings.Split(string(want), "\n")
	g := strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + strconv.Itoa(i+1) + ":\n want: " + wl + "\n  got: " + gl
		}
	}
	return "(identical lines; trailing bytes differ)"
}

func TestRenderIsDeterministic(t *testing.T) {
	in := loadFixture(t, "multi")
	a, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	// Reverse the zones: the brain sorts, but the output must not rely on it.
	zs := in.Doc.Zones
	for i, j := 0, len(zs)-1; i < j; i, j = i+1, j-1 {
		zs[i], zs[j] = zs[j], zs[i]
	}
	b, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() != b.Hash() {
		t.Fatalf("zone order changed the output: %s vs %s", a.Hash(), b.Hash())
	}
	if len(a) != len(in.Doc.Zones)+1 {
		t.Fatalf("%d files for %d zones", len(a), len(in.Doc.Zones))
	}
	if a.Names()[0] != render.CommonFile {
		t.Fatalf("common file must sort first, got %v", a.Names())
	}
}

// A zone's policy.rate is a fast-path field (edge-spec §2.2): changing it must
// not change a single rendered byte, or every rate change would be a reload.
func TestRateDoesNotReachTheTerminator(t *testing.T) {
	in := loadFixture(t, "decide-open")
	before, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Doc.Zones[0].Policy.Rate = edgedoc.Rate{RPS: 5, Concurrency: 2}
	after, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash() != after.Hash() {
		t.Fatal("policy.rate changed the rendered configuration")
	}
	for _, f := range after {
		if strings.Contains(string(f), "limit_req") || strings.Contains(string(f), "limit_conn") {
			t.Fatal("rate limiting rendered into nginx")
		}
	}
}

// TestPolicyShapes pins which directives each policy produces — the decisions
// the package doc explains — independently of the exact golden bytes.
func TestPolicyShapes(t *testing.T) {
	cases := []struct {
		fixture, file string
		want, wantNot []string
	}{
		{
			fixture: "decide-open", file: render.ZoneFile("example.com"),
			want: []string{
				"listen 443 ssl http2;", "listen [::]:443 ssl http2;",
				"auth_request /_kapkan/decide;",
				"auth_request_set $kapkan_mark $kapkan_decided_mark;",
				"auth_request_set $kapkan_decision $upstream_status;",
				"auth_request_set $kapkan_reason $upstream_http_x_kapkan_reason;",
				"error_page 403 = @kapkan_denied;",
				"location @kapkan_denied {", "return 429;", "add_header Retry-After 1 always;",
				"proxy_pass_request_headers off;",
				"proxy_intercept_errors on;",
				"error_page 500 502 503 504 =200 /_kapkan/undecided;",
				"location = /_kapkan/undecided {",
				"error_page 500 502 503 504 = @kapkan_pass;",
				"try_files /dev/null @kapkan_pass;",
				"proxy_set_header X-Kapkan-Mark $kapkan_mark;",
				"proxy_set_header X-Kapkan-Zone example.com;",
				"proxy_set_header Connection $kapkan_connection;",
				"proxy_set_header Upgrade $http_upgrade;",
				"limit_except GET HEAD { deny all; }",
				"proxy_pass_request_body off;",
				"ssl_protocols TLSv1.2 TLSv1.3;", "ssl_ciphers ECDHE-",
				"return 301 https://$host$request_uri;",
				"location ^~ /.well-known/acme-challenge/",
			},
			wantNot: []string{"@kapkan_unavailable", "limit_req", "limit_conn", "include /", "default_server", "X-Kapkan-User-Agent"},
		},
		{
			fixture: "decide-open", file: render.CommonFile,
			want: []string{
				"listen 80 default_server;", "listen [::]:80 default_server;",
				"listen 443 ssl default_server;", "ssl_reject_handshake on;",
				"ssl_protocols TLSv1.2 TLSv1.3;", "return 444;",
				"map $http_upgrade $kapkan_connection {", "map $upstream_status $kapkan_decided_mark {",
				"map $upstream_status $kapkan_decision {", "map $upstream_status $kapkan_reason {", "map $upstream_status $kapkan_mark {",
				`'"port":$server_port,'`, `'"proto":"$server_protocol",'`, `'"decision":"$kapkan_decision",'`, `'"reason":"$kapkan_reason",'`, `'"mark":"$kapkan_mark"'`,
				"upstream kapkan_decide {", "keepalive 64;", "upstream kapkan_challenge {",
			},
			// No zone asks for HTTP/3: not one QUIC byte, so a node without h3
			// zones renders the shared file it rendered before E5.
			wantNot: []string{"server_names_hash_bucket_size", "limit_req_zone", "limit_conn_zone", "quic", "$http3"},
		},
		{
			// HTTP/3 on a node that may render it: the zone gets the QUIC
			// listeners and announces them; nothing QUIC-wide lives here.
			fixture: "h3", file: render.ZoneFile("example.com"),
			want: []string{
				"listen 443 ssl http2;", "listen [::]:443 ssl http2;",
				"listen 443 quic;", "listen [::]:443 quic;",
				`add_header Alt-Svc 'h3=":443"; ma=86400';`,
				"auth_request /_kapkan/decide;",
			},
			wantNot: []string{"reuseport", "quic_retry", "quic_host_key", "ssl_early_data", "NOT RENDERED", "default_server"},
		},
		{
			// A mode: none zone speaks h3 too — it is a TLS-level fact, not a
			// policy — with its own Alt-Svc max-age.
			fixture: "h3", file: render.ZoneFile("static.example.org"),
			want:    []string{"listen 443 quic;", `add_header Alt-Svc 'h3=":443"; ma=300';`},
			wantNot: []string{"auth_request", "ma=86400", "NOT RENDERED"},
		},
		{
			// The zone beside them that did not ask stays as it was.
			fixture: "h3", file: render.ZoneFile("plain.example.net"),
			want:    []string{"listen 443 ssl http2;"},
			wantNot: []string{"quic", "Alt-Svc", "NOT RENDERED"},
		},
		{
			// The shared file: quic_* at the http level (before SNI, nginx
			// reads the default server), the catch-all's one reuseport QUIC
			// listener per family, the proto field; nothing 0-RTT.
			fixture: "h3", file: render.CommonFile,
			want: []string{
				"quic_retry on;", "quic_host_key /var/lib/kapkan-edge/tls/quic_host.key;",
				"listen 443 quic reuseport default_server;", "listen [::]:443 quic reuseport default_server;",
				"ssl_reject_handshake on;", `'"proto":"$server_protocol",'`,
			},
			// No anchor beside a catch-all (its comment is the anchor's signature).
			wantNot: []string{"ssl_early_data", "quic_gso", "quic_bpf", "http3", "The QUIC anchor"},
		},
		{
			// The same document on a node without the module: TCP only, the
			// comment says why, and the shared file carries no QUIC at all.
			fixture: "h3-unsupported", file: render.ZoneFile("example.com"),
			want:    []string{"HTTP/3 ASKED FOR, NOT RENDERED", "listen 443 ssl http2;"},
			wantNot: []string{"quic", "Alt-Svc"},
		},
		{
			fixture: "h3-unsupported", file: render.CommonFile,
			want:    []string{`'"proto":"$server_protocol",'`, "listen 443 ssl default_server;"},
			wantNot: []string{"quic"},
		},
		{
			// omit_catch_all: the operator's default server handles TCP; the
			// address still needs its one reuseport QUIC listener — the anchor.
			fixture: "h3-omit-catchall", file: render.CommonFile,
			// The anchor is the UDP default server: its protocol set governs
			// every QUIC handshake, so it must say TLSv1.3 whatever the
			// operator's http level says.
			want:    []string{"quic_retry on;", "quic_host_key", "listen 443 quic reuseport;", "listen [::]:443 quic reuseport;", "server_name _;", "ssl_reject_handshake on;", "ssl_protocols TLSv1.3;", "The QUIC anchor"},
			wantNot: []string{"default_server", "return 444", "TLSv1.2"},
		},
		{
			// …unless the operator's own server carries it.
			fixture: "h3-omit-anchor", file: render.CommonFile,
			want:    []string{"quic_retry on;", "quic_host_key"},
			wantNot: []string{"reuseport", "listen 443 quic", "server_name _;"},
		},
		{
			// IPv6 off drops the [::] QUIC listeners too; Retry can be turned
			// off node-wide; the host key path is the node's to name.
			fixture: "h3-noipv6", file: render.CommonFile,
			want:    []string{"quic_retry off;", "quic_host_key /srv/kapkan-edge/tls/host.key;", "listen 443 quic reuseport default_server;"},
			wantNot: []string{"[::]", "quic_retry on"},
		},
		{
			fixture: "h3-noipv6", file: render.ZoneFile("example.com"),
			want:    []string{"listen 443 quic;", "error_page 500 502 503 504 = @kapkan_unavailable;"},
			wantNot: []string{"[::]"},
		},
		{
			// No certificate, no TLS server, no QUIC — and no QUIC-wide lines
			// either, since nothing listens.
			fixture: "h3-no-cert", file: render.ZoneFile("new.example.com"),
			want:    []string{"NO CERTIFICATE YET", "listen 80;"},
			wantNot: []string{"quic", "NOT RENDERED", "Alt-Svc"},
		},
		{
			fixture: "h3-no-cert", file: render.CommonFile,
			wantNot: []string{"quic"},
		},
		{
			// The canary: the listener is there, nobody is told.
			fixture: "h3-quiet", file: render.ZoneFile("example.com"),
			want:    []string{"listen 443 quic;", "listen [::]:443 quic;"},
			wantNot: []string{"Alt-Svc"},
		},
		{
			fixture: "decide-closed", file: render.ZoneFile("closed.example.net"),
			want: []string{
				"error_page 500 502 503 504 = @kapkan_unavailable;",
				"location @kapkan_unavailable {", "return 503;",
				"ssl_protocols TLSv1.3;",
				// The clearance page failing follows failure_mode too.
				"location @kapkan_clearance {", "error_page 401 = @kapkan_clearance;",
			},
			wantNot: []string{"/_kapkan/undecided", "= @kapkan_pass;", "ssl_ciphers", "TLSv1.2", "limit_req", "limit_conn"},
		},
		{
			// A single TLS 1.3-only zone: the node-wide floor is 1.3 too.
			fixture: "decide-closed", file: render.CommonFile,
			want:    []string{"ssl_protocols TLSv1.3;"},
			wantNot: []string{"TLSv1.2", "limit_"},
		},
		{
			fixture: "mode-none", file: render.ZoneFile("static.example.org"),
			want: []string{
				"try_files /dev/null @kapkan_pass;",
				"include /etc/kapkan/extra/static.example.org.conf;",
				"server [2001:db8::10]:8080;",
				`proxy_set_header X-Kapkan-Mark "";`,
				"proxy_set_header X-Kapkan-Zone static.example.org;",
			},
			wantNot: []string{"auth_request", "error_page 500", "$kapkan_mark", "$kapkan_decision", "@kapkan_denied", "acme-staging"},
		},
		{
			fixture: "no-cert", file: render.ZoneFile("new.example.com"),
			want:    []string{"NO CERTIFICATE YET", "listen 80;", "return 503;", "location ^~ /.well-known/acme-challenge/", "limit_except GET HEAD { deny all; }"},
			wantNot: []string{"listen 443", "ssl_certificate", "auth_request", "return 301"},
		},
		{
			// Mixed floors (a: 1.3, b: 1.2, c: 1.2 without a certificate): the
			// catch-all carries the lowest; IPv6 off drops every [::] listener.
			fixture: "multi", file: render.CommonFile,
			want:    []string{"server unix:/run/kapkan-test/decide.sock;", "server unix:/run/kapkan-test/challenge.sock;", "ssl_protocols TLSv1.2 TLSv1.3;", "listen 443 ssl default_server;"},
			wantNot: []string{"/run/kapkan/edge-decide.sock", "[::]", "server_names_hash_bucket_size"},
		},
		{
			fixture: "multi", file: render.ZoneFile("a.example.com"),
			want:    []string{"ssl_protocols TLSv1.3;"},
			wantNot: []string{"[::]", "TLSv1.2"},
		},
		{
			fixture: "multi", file: render.ZoneFile("b.example.com"),
			want:    []string{"listen 80;", "listen 443 ssl http2;", "root /srv/kapkan-empty;", "syslog:server=unix:/run/kapkan-test/log.sock,"},
			wantNot: []string{"[::]", "limit_req"},
		},
		{
			fixture: "empty", file: render.CommonFile,
			want:    []string{"log_format kapkan_edge", "upstream kapkan_decide", "upstream kapkan_challenge", "listen 80 default_server;", "ssl_protocols TLSv1.2 TLSv1.3;"},
			wantNot: []string{"limit_req_zone", "limit_conn_zone", "server_names_hash_bucket_size"},
		},
		{
			// The catch-all default server declares the zones' shared session
			// cache: OpenSSL looks sessions up through the context of the server
			// a connection started on, so without it no session resumed anywhere
			// (the E6.9 rig's finding). Tickets and early data stay off there too.
			fixture: "h3", file: render.CommonFile,
			want:    []string{"listen 443 ssl default_server;", "ssl_session_cache shared:kapkan_ssl:10m;", "ssl_session_timeout 1d;", "ssl_session_tickets off;"},
			wantNot: []string{"ssl_session_tickets on"},
		},
		{
			// Under omit_catch_all the bare QUIC anchor is the server a QUIC
			// connection starts on, so it carries the cache in the catch-all's
			// place (the operator's own TCP default server must declare the
			// same three lines too — the install guide says so).
			fixture: "h3-omit-catchall", file: render.CommonFile,
			want:    []string{"listen 443 quic reuseport;", "ssl_session_cache shared:kapkan_ssl:10m;"},
			wantNot: []string{"listen 443 ssl default_server;"},
		},
		{
			// A 75-byte name does not fit the stock 64-byte bucket.
			fixture: "long-name", file: render.CommonFile,
			want: []string{"server_names_hash_bucket_size 128;"},
		},
	}
	for _, c := range cases {
		t.Run(c.fixture+"/"+c.file, func(t *testing.T) {
			files, err := render.Render(loadFixture(t, c.fixture))
			if err != nil {
				t.Fatal(err)
			}
			body, ok := files[c.file]
			if !ok {
				t.Fatalf("no file %s; have %v", c.file, files.Names())
			}
			s := string(body)
			for _, w := range c.want {
				if !strings.Contains(s, w) {
					t.Errorf("missing %q", w)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(s, w) {
					t.Errorf("unexpected %q", w)
				}
			}
			if t.Failed() {
				t.Logf("rendered %s:\n%s", c.file, s)
			}
		})
	}
}

func TestEmptyDocumentRendersOnlyTheCommonFile(t *testing.T) {
	files, err := render.Render(loadFixture(t, "empty"))
	if err != nil {
		t.Fatal(err)
	}
	if got := files.Names(); len(got) != 1 || got[0] != render.CommonFile {
		t.Fatalf("files = %v", got)
	}
}

func TestOmitCatchAll(t *testing.T) {
	in := baseInputs()
	in.Node.OmitCatchAll = true
	files, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	common := string(files[render.CommonFile])
	for _, w := range []string{"default_server", "ssl_reject_handshake", "return 444"} {
		if strings.Contains(common, w) {
			t.Errorf("catch-all rendered despite OmitCatchAll: %q", w)
		}
	}
}

func TestHashBucketGrowsWithTheLongestName(t *testing.T) {
	in := baseInputs()
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 8) // 200
	in.Doc.Zones[0].Name = name
	in.Certs = nil
	files, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(files[render.CommonFile]), "server_names_hash_bucket_size 256;") {
		t.Fatalf("no 256-byte bucket for a %d-byte name:\n%s", len(name), files[render.CommonFile])
	}
	if _, ok := files[render.ZoneFile(name)]; !ok {
		t.Fatalf("zone file missing; have %v", files.Names())
	}
}

func baseInputs() render.Inputs {
	doc := edgedoc.Empty()
	doc.Zones = append(doc.Zones, edgedoc.Zone{
		Name:    "example.com",
		Origins: []string{"10.0.0.1:8080"},
		TLS:     edgedoc.TLS{MinVersion: edgedoc.TLS12},
		Policy:  edgedoc.Policy{Mode: edgedoc.ModeDecide, FailureMode: edgedoc.FailOpen, Challenge: edgedoc.ChallengeOff},
	})
	return render.Inputs{
		Doc: &doc,
		Certs: map[string]render.Cert{
			"example.com": {Fullchain: "/var/lib/kapkan/edge/certs/example.com/fullchain.pem", Key: "/var/lib/kapkan/edge/certs/example.com/privkey.pem"},
		},
	}
}

// TestRenderRejects is the config-injection table: every value the renderer
// interpolates is checked, because the document crossed a network.
func TestRenderRejects(t *testing.T) {
	tooLong := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 47) // 239
	cases := []struct {
		name    string
		mutate  func(in *render.Inputs)
		wantErr string
	}{
		{"nil document", func(in *render.Inputs) { in.Doc = nil }, "nil edge document"},
		{"other version", func(in *render.Inputs) { in.Doc.Version = 2 }, "version 2"},
		{"uppercase zone", func(in *render.Inputs) { in.Doc.Zones[0].Name = "Example.com" }, "not a lower-case hostname"},
		{"empty label", func(in *render.Inputs) { in.Doc.Zones[0].Name = "a..b" }, "not a lower-case hostname"},
		{"leading dash", func(in *render.Inputs) { in.Doc.Zones[0].Name = "-a.example" }, "not a lower-case hostname"},
		{"zone with slash", func(in *render.Inputs) { in.Doc.Zones[0].Name = "a/b" }, "not a lower-case hostname"},
		{"zone name over 238", func(in *render.Inputs) { in.Doc.Zones[0].Name = tooLong }, "longer than the 238"},
		{"no origins", func(in *render.Inputs) { in.Doc.Zones[0].Origins = nil }, "no origins"},
		{"origin ends a directive", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1:8080;"} }, "not a canonical host:port"},
		{"origin leading-zero port", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1:0080"} }, "not a canonical host:port"},
		{"origin without port", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1"} }, "not a canonical host:port"},
		{"origin with scheme", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"http://10.0.0.1:80"} }, "not a canonical host:port"},
		{"origin with space", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1:80 backup"} }, "not a canonical host:port"},
		{"tls 1.1", func(in *render.Inputs) { in.Doc.Zones[0].TLS.MinVersion = "1.1" }, "tls.min_version"},
		{"alt-svc max-age too small, on the rendered path", func(in *render.Inputs) {
			in.Node.H3Supported = true
			in.Doc.Zones[0].TLS.H3 = true
			in.Doc.Zones[0].TLS.H3Options = &edgedoc.H3Options{AltSvcMaxAgeSeconds: 59}
		}, "alt_svc_max_age_seconds 59"},
		{"alt-svc max-age too large, even where h3 is not rendered", func(in *render.Inputs) {
			in.Node.H3Supported = false
			in.Doc.Zones[0].TLS.H3 = true
			in.Doc.Zones[0].TLS.H3Options = &edgedoc.H3Options{AltSvcMaxAgeSeconds: 604801}
		}, "alt_svc_max_age_seconds 604801"},
		{"quic host key with space", func(in *render.Inputs) { in.Node.QUICHostKey = "/var/lib/kapkan edge/host.key" }, "node.quic_host_key"},
		{"quic host key relative", func(in *render.Inputs) { in.Node.QUICHostKey = "tls/host.key" }, "node.quic_host_key"},
		{"unknown mode", func(in *render.Inputs) { in.Doc.Zones[0].Policy.Mode = "maybe" }, "policy.mode"},
		{"empty mode", func(in *render.Inputs) { in.Doc.Zones[0].Policy.Mode = "" }, "policy.mode"},
		{"unknown failure mode", func(in *render.Inputs) { in.Doc.Zones[0].Policy.FailureMode = "half" }, "policy.failure_mode"},
		{"challenge", func(in *render.Inputs) { in.Doc.Zones[0].Policy.Challenge = "js" }, "policy.challenge"},
		{"cert key only", func(in *render.Inputs) { in.Certs["example.com"] = render.Cert{Key: "/k.pem"} }, "both fullchain and key"},
		{"cert relative", func(in *render.Inputs) {
			in.Certs["example.com"] = render.Cert{Fullchain: "certs/f.pem", Key: "/k.pem"}
		}, "not an absolute path"},
		{"cert with space", func(in *render.Inputs) { in.Certs["example.com"] = render.Cert{Fullchain: "/a b.pem", Key: "/k.pem"} }, "misread"},
		{"cert with glob", func(in *render.Inputs) {
			in.Certs["example.com"] = render.Cert{Fullchain: "/certs/*.pem", Key: "/k.pem"}
		}, "misread"},
		{"extra relative", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "extra.conf" }, "extra_directives_file"},
		{"extra ends a directive", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "/etc/x.conf;" }, "misread"},
		{"extra opens a block", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "/etc/x.conf{" }, "misread"},
		{"extra is a glob", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "/etc/kapkan/[prod]-extra.conf" }, "misread"},
		{"extra with star", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "/etc/kapkan/*.conf" }, "misread"},
		{"node socket relative", func(in *render.Inputs) { in.Node.DecideSocket = "run/x.sock" }, "node.decide_socket"},
		{"node socket with newline", func(in *render.Inputs) { in.Node.LogSocket = "/run/x.sock\ninclude /etc/passwd" }, "node.log_socket"},
		{"empty root is the filesystem root", func(in *render.Inputs) { in.Node.EmptyRoot = "/" }, "node.empty_root"},
		{"duplicate zone", func(in *render.Inputs) { in.Doc.Zones = append(in.Doc.Zones, in.Doc.Zones[0]) }, "appears twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := baseInputs()
			c.mutate(&in)
			_, err := render.Render(in)
			if err == nil {
				t.Fatalf("accepted; want error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %q, want it to contain %q", err, c.wantErr)
			}
		})
	}
	// And the base itself renders, so the table is testing the mutations.
	if _, err := render.Render(baseInputs()); err != nil {
		t.Fatalf("base inputs rejected: %v", err)
	}
}

func TestNamesAndZoneFile(t *testing.T) {
	if got := render.ZoneFile("example.com"); got != "kapkan_zone_example.com.conf" {
		t.Fatalf("ZoneFile = %q", got)
	}
	files := render.Files{"kapkan_zone_b.conf": nil, render.CommonFile: nil, "kapkan_zone_a.conf": nil}
	if got := strings.Join(files.Names(), ","); got != "kapkan_00_common.conf,kapkan_zone_a.conf,kapkan_zone_b.conf" {
		t.Fatalf("Names = %s", got)
	}
	a := render.Files{"x": []byte("1"), "y": []byte("2")}
	b := render.Files{"y": []byte("2"), "x": []byte("1")}
	if a.Hash() != b.Hash() {
		t.Fatal("hash depends on map order")
	}
	c := render.Files{"x": []byte("12"), "y": []byte("")}
	if a.Hash() == c.Hash() {
		t.Fatal("hash must separate names from contents")
	}
}

// A zone that asks for HTTP/3 on a node that cannot render it is served over
// TCP: byte for byte the tls.h3: false render, plus the comment block that
// says why — a zone is never held hostage to one node's package, and the node
// reports the zones it degraded.
func TestH3DegradesToTheTCPRender(t *testing.T) {
	in := loadFixture(t, "h3-unsupported")
	degraded, info, err := render.RenderDetailed(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(info.Degraded, ",") != "example.com,static.example.org" || len(info.H3Zones) != 0 {
		t.Fatalf("info = %+v", info)
	}
	for i := range in.Doc.Zones {
		in.Doc.Zones[i].TLS.H3 = false
		in.Doc.Zones[i].TLS.H3Options = nil
	}
	plain, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(degraded.Names(), ",") != strings.Join(plain.Names(), ",") {
		t.Fatalf("file sets differ: %v vs %v", degraded.Names(), plain.Names())
	}
	for _, name := range degraded.Names() {
		body, stripped := stripDegradedComment(t, string(degraded[name]))
		wantStripped := name == render.ZoneFile("example.com") || name == render.ZoneFile("static.example.org")
		if stripped != wantStripped {
			t.Errorf("%s: degraded comment present=%v, want %v", name, stripped, wantStripped)
		}
		if body != string(plain[name]) {
			t.Errorf("%s differs from the tls.h3: false render beyond the comment:\n%s", name, firstDiff(plain[name], []byte(body)))
		}
	}
}

// stripDegradedComment removes the HTTP/3 ASKED FOR, NOT RENDERED block (a "#"
// line, the headline and its continuation lines) and reports whether it was
// there.
func stripDegradedComment(t *testing.T, body string) (string, bool) {
	t.Helper()
	lines := strings.Split(body, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "# HTTP/3 ASKED FOR, NOT RENDERED") {
			continue
		}
		if i < 1 || lines[i-1] != "#" {
			t.Fatalf("degraded comment block has an unexpected shape around line %d:\n%s", i+1, body)
		}
		end := i + 1
		for end < len(lines) && strings.HasPrefix(lines[end], "# ") {
			end++
		}
		if end == i+1 {
			t.Fatalf("degraded comment block has no continuation lines:\n%s", body)
		}
		return strings.Join(append(lines[:i-1:i-1], lines[end:]...), "\n"), true
	}
	return body, false
}

// Toggling tls.h3 on a node that renders QUIC changes the bytes — that is the
// slow path, edge-spec §2.2 ("h3 toggle → reload yes") — while the fast-path
// fields still change nothing on an h3 zone.
func TestH3ToggleIsANewGeneration(t *testing.T) {
	in := loadFixture(t, "h3")
	on, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Doc.Zones[0].TLS.H3 = false // example.com
	off, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if on.Hash() == off.Hash() {
		t.Fatal("turning tls.h3 off rendered the same bytes")
	}
	if !strings.Contains(string(off[render.CommonFile]), "quic_retry on;") {
		t.Fatal("static.example.org still speaks h3, so the shared file must keep its QUIC lines")
	}
	in = loadFixture(t, "h3")
	in.Doc.Zones[0].Policy.Rate = edgedoc.Rate{RPS: 5, Concurrency: 2}
	in.Doc.Zones[0].Policy.Challenge = edgedoc.ChallengeAuto
	in.Doc.Zones[0].Policy.DryRun = true
	fast, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if fast.Hash() != on.Hash() {
		t.Fatal("a fast-path change altered an h3 zone's render")
	}
}

// Exactly one reuseport per address family in a render, and only when some
// zone listens over QUIC: nginx refuses a second reuseport on one address:port
// (the operator's own is the reason omit_quic_anchor exists), and a node
// without h3 zones must not carry a QUIC socket at all.
func TestReuseportOncePerAddress(t *testing.T) {
	want := map[string][2]int{
		"h3": {1, 1}, "h3-omit-catchall": {1, 1}, "h3-omit-anchor": {0, 0}, "h3-noipv6": {1, 0},
		"h3-quiet": {1, 1}, "h3-unsupported": {0, 0}, "h3-no-cert": {0, 0}, "decide-open": {0, 0}, "multi": {0, 0},
	}
	for _, name := range fixtureNames(t) {
		files, err := render.Render(loadFixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		var v4, v6, quic int
		for _, body := range files {
			for _, l := range strings.Split(string(body), "\n") {
				l = strings.TrimSpace(l)
				if !strings.HasPrefix(l, "listen ") {
					continue
				}
				if strings.Contains(l, " quic") {
					quic++
				}
				if strings.Contains(l, "reuseport") {
					if strings.Contains(l, "[::]") {
						v6++
					} else {
						v4++
					}
				}
			}
		}
		if v4 > 1 || v6 > 1 {
			t.Errorf("%s: %d IPv4 and %d IPv6 reuseport listeners", name, v4, v6)
		}
		if w, ok := want[name]; ok && (v4 != w[0] || v6 != w[1]) {
			t.Errorf("%s: reuseport v4=%d v6=%d, want %d/%d", name, v4, v6, w[0], w[1])
		}
		if quic > 0 && v4+v6 == 0 && name != "h3-omit-anchor" {
			t.Errorf("%s: QUIC listeners without a reuseport one", name)
		}
	}
}

func TestRenderDetailedInfo(t *testing.T) {
	cases := map[string]struct{ h3, degraded string }{
		"h3":             {"example.com,static.example.org", ""},
		"h3-unsupported": {"", "example.com,static.example.org"},
		"h3-no-cert":     {"", ""},
		"h3-quiet":       {"example.com", ""},
		"decide-open":    {"", ""},
	}
	for name, want := range cases {
		_, info, err := render.RenderDetailed(loadFixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(info.H3Zones, ","); got != want.h3 {
			t.Errorf("%s: H3Zones %q, want %q", name, got, want.h3)
		}
		if got := strings.Join(info.Degraded, ","); got != want.degraded {
			t.Errorf("%s: Degraded %q, want %q", name, got, want.degraded)
		}
	}
}

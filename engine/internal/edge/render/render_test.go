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
				"auth_request_set $kapkan_mark $upstream_http_x_kapkan_mark;",
				"error_page 500 502 503 504 = @kapkan_pass;",
				"try_files /dev/null @kapkan_pass;",
				"proxy_set_header X-Kapkan-Mark $kapkan_mark;",
				"ssl_protocols TLSv1.2 TLSv1.3;", "ssl_ciphers ECDHE-",
				"return 301 https://$host$request_uri;",
				"location ^~ /.well-known/acme-challenge/",
			},
			wantNot: []string{"@kapkan_unavailable", "limit_req ", "limit_conn ", "include /"},
		},
		{
			fixture: "decide-closed", file: render.ZoneFile("closed.example.net"),
			want: []string{
				"error_page 500 502 503 504 = @kapkan_unavailable;",
				"location @kapkan_unavailable {", "return 503;",
				"limit_req zone=kapkan_rps_", "burst=200 nodelay;",
				"limit_conn kapkan_conn_", " 50;",
				"ssl_protocols TLSv1.3;",
			},
			wantNot: []string{"= @kapkan_pass;", "ssl_ciphers", "TLSv1.2"},
		},
		{
			fixture: "decide-closed", file: render.CommonFile,
			want: []string{"limit_req_zone $binary_remote_addr zone=kapkan_rps_", "rate=200r/s;", "limit_conn_zone $binary_remote_addr zone=kapkan_conn_"},
		},
		{
			fixture: "mode-none", file: render.ZoneFile("static.example.org"),
			want:    []string{"try_files /dev/null @kapkan_pass;", "include /etc/kapkan/extra/static.example.org.conf;", "server [2001:db8::10]:8080;"},
			wantNot: []string{"auth_request", "error_page 500", "X-Kapkan-Mark", "acme-staging"},
		},
		{
			fixture: "no-cert", file: render.ZoneFile("new.example.com"),
			want:    []string{"NO CERTIFICATE YET", "listen 80;", "return 503;", "location ^~ /.well-known/acme-challenge/"},
			wantNot: []string{"listen 443", "ssl_certificate", "auth_request", "return 301"},
		},
		{
			fixture: "multi", file: render.CommonFile,
			want:    []string{"server unix:/run/kapkan-test/decide.sock;", "server unix:/run/kapkan-test/challenge.sock;"},
			wantNot: []string{"/run/kapkan/edge-decide.sock"},
		},
		{
			fixture: "multi", file: render.ZoneFile("b.example.com"),
			want:    []string{"listen 80;", "listen 443 ssl http2;", "root /srv/kapkan-empty;", "syslog:server=unix:/run/kapkan-test/log.sock,"},
			wantNot: []string{"[::]"},
		},
		{
			fixture: "empty", file: render.CommonFile,
			want:    []string{"log_format kapkan_edge", "upstream kapkan_decide", "upstream kapkan_challenge"},
			wantNot: []string{"limit_req_zone", "limit_conn_zone"},
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
		{"no origins", func(in *render.Inputs) { in.Doc.Zones[0].Origins = nil }, "no origins"},
		{"origin ends a directive", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1:8080;"} }, "not a canonical host:port"},
		{"origin leading-zero port", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1:0080"} }, "not a canonical host:port"},
		{"origin without port", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1"} }, "not a canonical host:port"},
		{"origin with scheme", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"http://10.0.0.1:80"} }, "not a canonical host:port"},
		{"origin with space", func(in *render.Inputs) { in.Doc.Zones[0].Origins = []string{"10.0.0.1:80 backup"} }, "not a canonical host:port"},
		{"tls 1.1", func(in *render.Inputs) { in.Doc.Zones[0].TLS.MinVersion = "1.1" }, "tls.min_version"},
		{"h3", func(in *render.Inputs) { in.Doc.Zones[0].TLS.H3 = true }, "tls.h3"},
		{"unknown mode", func(in *render.Inputs) { in.Doc.Zones[0].Policy.Mode = "maybe" }, "policy.mode"},
		{"empty mode", func(in *render.Inputs) { in.Doc.Zones[0].Policy.Mode = "" }, "policy.mode"},
		{"unknown failure mode", func(in *render.Inputs) { in.Doc.Zones[0].Policy.FailureMode = "half" }, "policy.failure_mode"},
		{"challenge", func(in *render.Inputs) { in.Doc.Zones[0].Policy.Challenge = "js" }, "policy.challenge"},
		{"cert key only", func(in *render.Inputs) { in.Certs["example.com"] = render.Cert{Key: "/k.pem"} }, "both fullchain and key"},
		{"cert relative", func(in *render.Inputs) {
			in.Certs["example.com"] = render.Cert{Fullchain: "certs/f.pem", Key: "/k.pem"}
		}, "not an absolute path"},
		{"cert with space", func(in *render.Inputs) { in.Certs["example.com"] = render.Cert{Fullchain: "/a b.pem", Key: "/k.pem"} }, "misread"},
		{"extra relative", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "extra.conf" }, "extra_directives_file"},
		{"extra ends a directive", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "/etc/x.conf;" }, "misread"},
		{"extra opens a block", func(in *render.Inputs) { in.Doc.Zones[0].ExtraDirectivesFile = "/etc/x.conf{" }, "misread"},
		{"node socket relative", func(in *render.Inputs) { in.Node.DecideSocket = "run/x.sock" }, "node.decide_socket"},
		{"node socket with newline", func(in *render.Inputs) { in.Node.LogSocket = "/run/x.sock\ninclude /etc/passwd" }, "node.log_socket"},
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

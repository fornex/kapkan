package apply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures under testdata/probe are `-V` outputs captured from the CI
// matrix images (nginx:1.22, nginx:stable, docker.angie.software/angie:latest)
// and from Debian 13's stock nginx package on 2026-09-07.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "probe", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestParseVersionOutput(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want Terminator
		// advisory is a substring the Advisory must carry, "" for none.
		advisory string
	}{
		{
			name: "nginx:1.22 image — no module, OpenSSL 1.1.1",
			out:  readFixture(t, "nginx-1.22.1.txt"),
			want: Terminator{Kind: "nginx", Version: "1.22.1", Core: "1.22.1", TLSLibrary: "OpenSSL 1.1.1n"},
		},
		{
			name:     "nginx:stable image — module, OpenSSL 3.5.7, 0-RTT capable, outside the advisory ranges",
			out:      readFixture(t, "nginx-1.30.4.txt"),
			want:     Terminator{Kind: "nginx", Version: "1.30.4", Core: "1.30.4", HTTP3Module: true, TLSLibrary: "OpenSSL 3.5.7", EarlyDataCapable: true},
			advisory: "",
		},
		{
			name:     "Debian 13 stock nginx — module, core below 1.29.1 so no 0-RTT, advisory (the backport is invisible to -V)",
			out:      readFixture(t, "debian13-nginx-1.26.3.txt"),
			want:     Terminator{Kind: "nginx", Version: "1.26.3", Core: "1.26.3", HTTP3Module: true, TLSLibrary: "OpenSSL 3.5.7"},
			advisory: "CVE-2026-40460",
		},
		{
			name: "Angie 1.12.1 — core is the second line, module, capable, core 1.31.2 is past the second range",
			out:  readFixture(t, "angie-1.12.1.txt"),
			want: Terminator{Kind: "angie", Version: "1.12.1", Core: "1.31.2", HTTP3Module: true, TLSLibrary: "OpenSSL 3.5.7", EarlyDataCapable: true},
		},
		{
			name:     "OpenSSL 3.0 compat build — module but no 0-RTT, advisory",
			out:      "nginx version: nginx/1.28.3\nbuilt by gcc 12.2.0 (Debian 12.2.0-14)\nbuilt with OpenSSL 3.0.15 3 Sep 2024\nTLS SNI support enabled\nconfigure arguments: --prefix=/etc/nginx --with-http_v3_module --with-http_v2_module",
			want:     Terminator{Kind: "nginx", Version: "1.28.3", Core: "1.28.3", HTTP3Module: true, TLSLibrary: "OpenSSL 3.0.15"},
			advisory: "CVE-2026-40460",
		},
		{
			name: "distro suffix and running-with — the running library wins",
			out:  "nginx version: nginx/1.24.0 (Ubuntu)\nbuilt with OpenSSL 3.0.2 15 Mar 2022 (running with OpenSSL 3.0.13 30 Jan 2024)\nconfigure arguments: --with-http_v2_module --with-http_v3_modulex",
			want: Terminator{Kind: "nginx", Version: "1.24.0", Core: "1.24.0", TLSLibrary: "OpenSSL 3.0.13"},
		},
		{
			name:     "QuicTLS — capable regardless of core",
			out:      "nginx version: nginx/1.27.0\nbuilt with OpenSSL 3.0.13+quic 30 Jan 2024\nconfigure arguments: --with-http_v3_module",
			want:     Terminator{Kind: "nginx", Version: "1.27.0", Core: "1.27.0", HTTP3Module: true, TLSLibrary: "OpenSSL 3.0.13+quic", EarlyDataCapable: true},
			advisory: "CVE-2026-40460",
		},
		{
			name:     "BoringSSL — capable; core 1.29.1 is inside the first range",
			out:      "nginx version: nginx/1.29.1\nbuilt with OpenSSL 1.1.1 (compatible; BoringSSL)\nconfigure arguments: --with-http_v3_module",
			want:     Terminator{Kind: "nginx", Version: "1.29.1", Core: "1.29.1", HTTP3Module: true, TLSLibrary: "BoringSSL", EarlyDataCapable: true},
			advisory: "CVE-2026-40460",
		},
		{
			name: "LibreSSL — capable, no advisory past 1.31.1",
			out:  "nginx version: nginx/1.31.2\nbuilt with LibreSSL 3.9.2\nconfigure arguments: --with-http_v3_module",
			want: Terminator{Kind: "nginx", Version: "1.31.2", Core: "1.31.2", HTTP3Module: true, TLSLibrary: "LibreSSL 3.9.2", EarlyDataCapable: true},
		},
		{
			name: "-v output alone still parses (build facts absent)",
			out:  "nginx version: nginx/1.26.2\n",
			want: Terminator{Kind: "nginx", Version: "1.26.2", Core: "1.26.2"},
		},
		{
			name: "Angie without a core line keeps its own version as the core",
			out:  "Angie version: Angie/1.6.2",
			want: Terminator{Kind: "angie", Version: "1.6.2", Core: "1.6.2"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseVersionOutput(c.out)
			if err != nil {
				t.Fatalf("ParseVersionOutput: %v", err)
			}
			if got != c.want {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
			adv := got.Advisory()
			if c.advisory == "" && adv != "" {
				t.Errorf("unexpected advisory %q", adv)
			}
			if c.advisory != "" && !strings.Contains(adv, c.advisory) {
				t.Errorf("advisory %q lacks %q", adv, c.advisory)
			}
			if adv != "" && !strings.Contains(adv, got.Core) {
				t.Errorf("advisory %q does not name the core %s", adv, got.Core)
			}
		})
	}
	if _, err := ParseVersionOutput("something else\nconfigure arguments: --with-http_v3_module"); err == nil {
		t.Fatal("unrecognised output accepted")
	}
}

// The advisory ranges, edge to edge: CVE-2026-40460 is 1.25.0–1.30.0 (fixed
// 1.30.1 and 1.31.0), CVE-2026-42530 is 1.31.0–1.31.1 (fixed 1.31.2). A build
// without the module carries no advisory — the code is not compiled in.
func TestAdvisoryBoundaries(t *testing.T) {
	cases := map[string]string{
		"1.24.9": "", "1.25.0": "CVE-2026-40460", "1.26.3": "CVE-2026-40460", "1.30.0": "CVE-2026-40460",
		"1.30.1": "", "1.30.4": "", "1.31.0": "CVE-2026-42530", "1.31.1": "CVE-2026-42530", "1.31.2": "", "1.31.5": "",
		"2.0.0": "", "garbage": "",
	}
	for core, want := range cases {
		adv := Terminator{Kind: "nginx", Version: core, Core: core, HTTP3Module: true}.Advisory()
		if (want == "" && adv != "") || (want != "" && !strings.Contains(adv, want)) {
			t.Errorf("core %s: advisory %q, want %q", core, adv, want)
		}
	}
	if adv := (Terminator{Kind: "nginx", Version: "1.26.3", Core: "1.26.3"}).Advisory(); adv != "" {
		t.Errorf("a build without the module carries an advisory: %q", adv)
	}
	// Angie is judged by its nginx core, not its own version.
	if adv := (Terminator{Kind: "angie", Version: "1.10.0", Core: "1.29.3", HTTP3Module: true}).Advisory(); !strings.Contains(adv, "CVE-2026-40460") {
		t.Errorf("angie on core 1.29.3: %q", adv)
	}
}

func TestEarlyDataRule(t *testing.T) {
	cases := []struct {
		lib, core string
		want      bool
	}{
		{"OpenSSL 3.5.1", "1.29.1", true},
		{"OpenSSL 3.5.0", "1.29.1", false},
		{"OpenSSL 3.5.7", "1.29.0", false},
		{"OpenSSL 3.5.7", "1.31.2", true},
		{"OpenSSL 3.0.13+quic", "1.22.1", true},
		{"BoringSSL", "1.22.1", true},
		{"LibreSSL 3.9.2", "1.22.1", true},
		{"", "1.31.2", false},
		{"wolfSSL 5.7.0", "1.31.2", false},
	}
	for _, c := range cases {
		if got := earlyDataCapable(c.lib, c.core); got != c.want {
			t.Errorf("earlyDataCapable(%q, %q) = %v, want %v", c.lib, c.core, got, c.want)
		}
	}
}

func TestProbeRunsDashV(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("testdata", "probe", "debian13-nginx-1.26.3.txt"))
	if err != nil {
		t.Fatal(err)
	}
	bin := fakeBinary(t, `case "$*" in "-V") cat "`+fixture+`" >&2;; *) echo "bad args: $*" >&2; exit 2;; esac`)
	got, err := Probe(context.Background(), bin)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	want, _ := ParseVersionOutput(readFixture(t, "debian13-nginx-1.26.3.txt"))
	if got != want {
		t.Errorf("Probe = %+v, want %+v", got, want)
	}
	if _, err := Probe(context.Background(), fakeBinary(t, `echo "something else" >&2`)); err == nil || !strings.Contains(err.Error(), "unrecognised") {
		t.Fatalf("unrecognised output: err = %v", err)
	}
	if _, err := Probe(context.Background(), fakeBinary(t, `exit 3`)); err == nil || !strings.Contains(err.Error(), "-V") {
		t.Fatalf("failing binary: err = %v", err)
	}
}

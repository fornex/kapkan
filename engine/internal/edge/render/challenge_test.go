package render_test

import (
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/render"
)

// TestRenderIsIndependentOfTheChallengeMode pins edge-spec §2.2 for the rung:
// the clearance machinery is rendered for every decide-mode zone, so the
// bytes a node installs are the same whether policy.challenge is off, manual
// or auto, and whatever challenge_options say — turning the rung on is a
// decision-service change, never a reload.
func TestRenderIsIndependentOfTheChallengeMode(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			base := loadFixture(t, name)
			if len(base.Doc.Zones) == 0 {
				t.Skip("no zones")
			}
			want, err := render.Render(base)
			if err != nil {
				t.Fatal(err)
			}
			variants := []func(z *edgedoc.Zone){
				func(z *edgedoc.Zone) { z.Policy.Challenge = edgedoc.ChallengeManual },
				func(z *edgedoc.Zone) { z.Policy.Challenge = edgedoc.ChallengeAuto },
				func(z *edgedoc.Zone) {
					z.Policy.Challenge = edgedoc.ChallengeManual
					z.Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false, ExemptPaths: []string{"/healthz"}}
				},
				func(z *edgedoc.Zone) {
					z.ClearanceKeys = []edgedoc.ClearanceKey{{ID: "c1", Secret: "c2VjcmV0"}}
				},
			}
			for i, mutate := range variants {
				in := loadFixture(t, name)
				for j := range in.Doc.Zones {
					mutate(&in.Doc.Zones[j])
				}
				got, err := render.Render(in)
				if err != nil {
					t.Fatalf("variant %d: %v", i, err)
				}
				if got.Hash() != want.Hash() {
					t.Fatalf("variant %d renders different bytes: the rung leaked into the slow path", i)
				}
			}
		})
	}
}

// TestChallengeMachineryShape pins the directives the rung needs in a
// decide-mode zone, and their absence from a mode: none zone.
func TestChallengeMachineryShape(t *testing.T) {
	files, err := render.Render(loadFixture(t, "decide-open"))
	if err != nil {
		t.Fatal(err)
	}
	zone := string(files[render.ZoneFile("example.com")])
	for _, want := range []string{
		"proxy_set_header X-Kapkan-Clearance $kapkan_clr_safe;",
		"set $kapkan_path $uri;",
		"proxy_set_header X-Kapkan-Path $kapkan_path;",
		"error_page 401 = @kapkan_clearance;",
		"location @kapkan_clearance {",
		"recursive_error_pages on;",
		"proxy_set_header X-Kapkan-Reason $kapkan_reason;",
		"proxy_set_header Accept-Language $http_accept_language;",
		"location ^~ /_kapkan/clearance/ {",
		"limit_except GET HEAD POST { deny all; }",
		"client_max_body_size 4k;",
		"proxy_pass http://kapkan_clearance;",
	} {
		if !strings.Contains(zone, want) {
			t.Errorf("decide-open zone lacks %q", want)
		}
	}
	// Nothing rewrites the URI on the way to the page: a rewrite in the named
	// location would follow a fallen-back request into @kapkan_pass and reach
	// the origin as the page's path. The raw cookie never travels either.
	for _, no := range []string{"rewrite ^", "$cookie_kapkan_clr;"} {
		if strings.Contains(zone, no) {
			t.Errorf("decide-open zone contains %q", no)
		}
	}
	// The named location reaches the page through a 401 only: the public
	// prefix never asks a decision (no auth_request inside it).
	start := strings.Index(zone, "location ^~ /_kapkan/clearance/ {")
	if start < 0 {
		t.Fatal("no public clearance prefix")
	}
	pub := zone[start:]
	if end := strings.Index(pub, "\n    }\n"); end >= 0 {
		pub = pub[:end]
	}
	if strings.Contains(pub, "auth_request") {
		t.Error("the public clearance prefix asks a decision")
	}
	common := string(files[render.CommonFile])
	for _, want := range []string{
		"upstream kapkan_clearance {", "server unix:/run/kapkan-edge/edge-clearance.sock;",
		"map $cookie_kapkan_clr $kapkan_clr_safe {", `"~^[A-Za-z0-9._-]{1,512}$" $cookie_kapkan_clr;`,
	} {
		if !strings.Contains(common, want) {
			t.Errorf("common file lacks %q", want)
		}
	}
	none, err := render.Render(loadFixture(t, "mode-none"))
	if err != nil {
		t.Fatal(err)
	}
	if z := string(none[render.ZoneFile("static.example.org")]); strings.Contains(z, "kapkan_clearance") {
		t.Error("a mode: none zone renders clearance machinery")
	}
}

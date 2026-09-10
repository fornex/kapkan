package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestZoneTenantLabel (E6.2): the zone's tenant is optional, must be a
// log/JSON-safe label like a hostgroup's, and an unlabelled zone stays
// unlabelled — nothing is inherited.
func TestZoneTenantLabel(t *testing.T) {
	z, err := ParseZones([]byte("zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\"]\n    tenant: acme\n  - name: b.example\n    origins: [\"10.0.0.2:8080\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if z.Zones[0].Tenant != "acme" || z.Zones[1].Tenant != "" {
		t.Fatalf("tenants = %q, %q; want acme and empty", z.Zones[0].Tenant, z.Zones[1].Tenant)
	}
	for _, bad := range []string{`"bad tenant!"`, `"a/b"`, `"` + strings.Repeat("x", 65) + `"`} {
		_, err := ParseZones([]byte("zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\"]\n    tenant: " + bad + "\n"))
		if err == nil || !strings.Contains(err.Error(), "a.example: tenant") {
			t.Errorf("tenant %s: err = %v, want a tenant charset error naming the zone", bad, err)
		}
	}
}

// TestBindZonesTenantRule (E6.2): a token's tenant must be in use by a
// hostgroup or a zone. With an edge block the decision is Load's (BindZones,
// over both files); without one it stays Parse's, byte for byte as before.
func TestBindZonesTenantRule(t *testing.T) {
	tokens := func(tenant string) string {
		return strings.Replace(validYAML, "  listen: \"127.0.0.1:8080\"\n",
			"  listen: \"127.0.0.1:8080\"\n  tokens:\n    - {name: x, token_env: K_X, role: viewer, tenant: "+tenant+"}\n", 1)
	}
	const hg = "hostgroups:\n  - name: a\n    tenant: \"custA\"\n    networks: [\"203.0.113.0/26\"]\n"
	const edge = "edge:\n  zones_file: /etc/kapkan/zones.yaml\n  nodes:\n    - name: e1\n"
	zones := func(tenant string) *Zones {
		label := ""
		if tenant != "" {
			label = "    tenant: " + tenant + "\n"
		}
		z, err := ParseZones([]byte("zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\"]\n" + label))
		if err != nil {
			t.Fatal(err)
		}
		return z
	}

	cases := []struct {
		name, yaml string
		z          *Zones
		wantErr    string
	}{
		{"hostgroup-only tenant", tokens("custA") + hg + edge, zones(""), ""},
		{"zone-only tenant (an edge-only customer)", tokens("shop") + edge, zones("shop"), ""},
		{"typo names the token and the tenant", tokens("shpo") + edge, zones("shop"), `api.tokens["x"]: tenant "shpo" is not used by any hostgroup or zone`},
		{"a zone label nobody holds a token for is legal", tokens("custA") + hg + edge, zones("orphan"), ""},
		{"no zones yet", tokens("custA") + hg + edge, nil, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("Parse with an edge block must defer the tenant rule to Load: %v", err)
			}
			err = cfg.BindZones(tt.z)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("BindZones: %v", err)
			case tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr):
				t.Fatalf("BindZones err = %v, want %q", err, tt.wantErr)
			case tt.wantErr == "" && cfg.ZonesCfg != tt.z:
				t.Fatalf("BindZones did not attach the zones file")
			case tt.wantErr != "" && cfg.ZonesCfg != nil:
				t.Fatalf("BindZones attached the zones file although it refused")
			}
		})
	}

	// Without an edge block there is no second file: Parse decides, with the
	// message it always had.
	if _, err := Parse([]byte(tokens("ghost") + hg)); err == nil || !strings.Contains(err.Error(), `tenant "ghost" is not used by any hostgroup`) {
		t.Fatalf("Parse without an edge block: err = %v, want the hostgroup-only refusal", err)
	}

	t.Run("Load runs the rule over both files", func(t *testing.T) {
		dir := t.TempDir()
		zp := filepath.Join(dir, "zones.yaml")
		if err := os.WriteFile(zp, []byte("zones:\n  - name: a.example\n    origins: [\"10.0.0.1:8080\"]\n    tenant: shop\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		edgeAt := "edge:\n  zones_file: " + zp + "\n  nodes:\n    - name: e1\n"
		cp := filepath.Join(dir, "kapkan.yaml")
		if err := os.WriteFile(cp, []byte(tokens("shop")+edgeAt), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(cp)
		if err != nil {
			t.Fatalf("Load with a zone-only tenant: %v", err)
		}
		if cfg.ZonesCfg == nil || len(cfg.ZonesCfg.Zones) != 1 || cfg.ZonesCfg.Zones[0].Tenant != "shop" {
			t.Fatalf("zones not attached with their label: %+v", cfg.ZonesCfg)
		}
		if err := os.WriteFile(cp, []byte(tokens("shpo")+edgeAt), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(cp); err == nil || !strings.Contains(err.Error(), `api.tokens["x"]: tenant "shpo" is not used by any hostgroup or zone`) {
			t.Fatalf("Load with a typo'd tenant: err = %v, want a refusal naming token and tenant", err)
		}
	})
}

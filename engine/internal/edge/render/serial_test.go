package render_test

import (
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/render"
)

// A renewed certificate lands at the same paths (through the store's
// `current` link), so the serial is what makes a renewal a new generation:
// two renders that differ only in the serial must differ, and the serial
// must be visible in the zone file for the operator.
func TestCertificateSerialMakesARenewalANewGeneration(t *testing.T) {
	in := loadFixture(t, "multi")
	zone := in.Doc.Zones[0].Name
	if in.Certs == nil {
		in.Certs = map[string]render.Cert{}
	}
	cert := render.Cert{Fullchain: "/var/lib/kapkan/edge/certs/" + zone + "/current/fullchain.pem", Key: "/var/lib/kapkan/edge/certs/" + zone + "/current/privkey.pem"}
	in.Certs[zone] = cert
	base, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cert.Serial = "0a1b2c3d4e5f"
	in.Certs[zone] = cert
	first, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash() == base.Hash() {
		t.Fatal("a serial changed nothing; a renewal would never reach nginx")
	}
	zoneFile := first[render.ZoneFile(zone)]
	if !strings.Contains(string(zoneFile), "# certificate serial 0a1b2c3d4e5f") {
		t.Fatalf("serial comment missing from the zone file:\n%s", zoneFile)
	}
	cert.Serial = "0a1b2c3d4e60"
	in.Certs[zone] = cert
	second, err := render.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if second.Hash() == first.Hash() {
		t.Fatal("two serials rendered the same generation")
	}
	// Only lower-case hex passes: the serial ends up inside the configuration.
	for _, bad := range []string{"0A1B", "abc;", "1 2", strings.Repeat("f", 65)} {
		cert.Serial = bad
		in.Certs[zone] = cert
		if _, err := render.Render(in); err == nil {
			t.Fatalf("serial %q accepted", bad)
		}
	}
}

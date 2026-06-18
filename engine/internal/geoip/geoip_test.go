package geoip

import (
	"net/netip"
	"testing"
)

const (
	asnDB     = "testdata/asn.mmdb"
	countryDB = "testdata/country.mmdb"
)

// TestLookupASNAndCountry resolves every fixture prefix across both databases.
func TestLookupASNAndCountry(t *testing.T) {
	db, err := Open(asnDB, countryDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cases := []struct {
		addr    string
		asn     uint32
		org     string
		country string
	}{
		{"198.51.100.7", 64500, "Evil Corp", "RU"},
		{"203.0.113.20", 64501, "Victim Net LLC", "US"},
		{"2001:db8:ffff::1", 64502, "IPv6 Botnet AS", "CN"},
	}
	for _, c := range cases {
		info, ok := db.Lookup(netip.MustParseAddr(c.addr))
		if !ok {
			t.Errorf("%s: ok = false, want true", c.addr)
			continue
		}
		if info.ASN != c.asn || info.Org != c.org || info.Country != c.country {
			t.Errorf("%s: info = %+v, want {ASN:%d Org:%q Country:%q}", c.addr, info, c.asn, c.org, c.country)
		}
	}
}

// TestRegisteredCountryFallback: a record carrying only registered_country
// (no country object) still resolves a country code.
func TestRegisteredCountryFallback(t *testing.T) {
	db, err := Open(asnDB, countryDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	info, ok := db.Lookup(netip.MustParseAddr("198.18.0.1"))
	if !ok || info.Country != "JP" {
		t.Errorf("info = %+v, ok = %v, want country JP from registered_country fallback", info, ok)
	}
}

// TestLookupUnknown: an address in neither database is not placed.
func TestLookupUnknown(t *testing.T) {
	db, err := Open(asnDB, countryDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	info, ok := db.Lookup(netip.MustParseAddr("192.0.2.1"))
	if ok {
		t.Errorf("ok = true for an unmapped address; info = %+v", info)
	}
	if info != (Info{}) {
		t.Errorf("info = %+v, want zero", info)
	}
}

// TestASNOnly: with only the ASN database, country stays empty but the AS is
// still resolved (ok is true).
func TestASNOnly(t *testing.T) {
	db, err := Open(asnDB, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	info, ok := db.Lookup(netip.MustParseAddr("198.51.100.7"))
	if !ok || info.ASN != 64500 || info.Org != "Evil Corp" {
		t.Errorf("info = %+v, ok = %v, want AS64500 Evil Corp", info, ok)
	}
	if info.Country != "" {
		t.Errorf("country = %q, want empty (no country database)", info.Country)
	}
	if !db.HasASN() {
		t.Error("HasASN() = false with an ASN database loaded")
	}
}

// TestHasASN reflects whether an ASN database is loaded, across configurations.
func TestHasASN(t *testing.T) {
	var nilDB *DB
	if nilDB.HasASN() {
		t.Error("nil DB HasASN() = true, want false")
	}
	country, err := Open("", countryDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = country.Close() })
	if country.HasASN() {
		t.Error("country-only DB HasASN() = true, want false")
	}
}

// TestCountryOnly: with only the country database, the AS stays zero.
func TestCountryOnly(t *testing.T) {
	db, err := Open("", countryDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	info, ok := db.Lookup(netip.MustParseAddr("203.0.113.20"))
	if !ok || info.Country != "US" {
		t.Errorf("info = %+v, ok = %v, want country US", info, ok)
	}
	if info.ASN != 0 || info.Org != "" {
		t.Errorf("ASN = %d, Org = %q, want zero (no ASN database)", info.ASN, info.Org)
	}
}

// TestOpenErrors: no path and a missing file both fail (and never return a
// half-open DB).
func TestOpenErrors(t *testing.T) {
	if _, err := Open("", ""); err == nil {
		t.Error("Open(\"\", \"\") = nil error, want failure")
	}
	if _, err := Open("testdata/does-not-exist.mmdb", ""); err == nil {
		t.Error("Open(missing) = nil error, want failure")
	}
	// A valid ASN path with a missing country path closes the ASN reader and
	// returns the error rather than a partially-open DB.
	if db, err := Open(asnDB, "testdata/does-not-exist.mmdb"); err == nil {
		_ = db.Close()
		t.Error("Open(valid, missing) = nil error, want failure")
	}
}

// TestNilAndInvalid: a nil DB and an invalid address are safe no-ops.
func TestNilAndInvalid(t *testing.T) {
	var nilDB *DB
	if _, ok := nilDB.Lookup(netip.MustParseAddr("198.51.100.7")); ok {
		t.Error("nil DB Lookup ok = true, want false")
	}
	if err := nilDB.Close(); err != nil {
		t.Errorf("nil DB Close = %v, want nil", err)
	}

	db, err := Open(asnDB, countryDB)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, ok := db.Lookup(netip.Addr{}); ok {
		t.Error("Lookup(invalid addr) ok = true, want false")
	}
}

// Package geoip provides optional GeoIP/ASN attribution of flow source
// addresses against MaxMind GeoLite2 (or GeoIP2) databases. It is a thin,
// read-only wrapper over the maxminddb reader: open the ASN and/or country
// database once at startup, then resolve addresses concurrently on the
// sample-collection path.
//
// Both databases are optional and independent. With only the ASN database an
// address resolves to an AS number/organization but no country; with only the
// country database it resolves to a country code but no AS. When neither is
// configured the feature is off and the engine attaches no geo data.
package geoip

import (
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Info is the GeoIP/ASN attribution of a single address. Zero values mean
// "unknown": ASN 0 when the address is in no known autonomous system (or the
// ASN database is absent), and an empty Country when it maps to no country.
type Info struct {
	// ASN is the autonomous system number, 0 when unknown.
	ASN uint32
	// Org is the autonomous system organization name, "" when unknown.
	Org string
	// Country is the ISO 3166-1 alpha-2 country code (e.g. "US"), "" when
	// unknown.
	Country string
}

// Resolver attributes an address to an autonomous system and country. The nil
// Resolver is never called by the engine; a real Resolver returns ok=false for
// any address it cannot place (private ranges, gaps in the database, etc.).
// HasASN reports whether AS attribution is available at all, so consumers can
// avoid surfacing a degenerate "every source is unknown" breakdown when only a
// country database is loaded.
type Resolver interface {
	Lookup(netip.Addr) (Info, bool)
	HasASN() bool
}

// asnRecord mirrors the GeoLite2-ASN record shape.
type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// countryRecord mirrors the relevant slice of the GeoLite2-Country/City record.
// registered_country is consulted as a fallback: some records (satellite,
// anonymizing and certain registered-but-not-geolocated ranges) carry no
// `country` object but do carry the registering country's ISO code.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// DB resolves addresses against the opened MaxMind databases over mmap.
// Lookups are safe for concurrent use (the underlying reader is thread-safe).
type DB struct {
	asn     *maxminddb.Reader
	country *maxminddb.Reader
}

// Open opens whichever of the ASN and country databases have a non-empty path.
// At least one path must be set. On any open failure every already-opened
// reader is closed so a partial DB is never returned.
func Open(asnPath, countryPath string) (*DB, error) {
	if asnPath == "" && countryPath == "" {
		return nil, fmt.Errorf("geoip: at least one of asn/country database paths must be set")
	}
	db := &DB{}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			return nil, fmt.Errorf("geoip: open asn database %q: %w", asnPath, err)
		}
		db.asn = r
	}
	if countryPath != "" {
		r, err := maxminddb.Open(countryPath)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("geoip: open country database %q: %w", countryPath, err)
		}
		db.country = r
	}
	return db, nil
}

// Lookup attributes addr to an AS and country. ok is true when at least one
// database placed the address; a decode error on either database is treated as
// "not found" for that field rather than surfaced, so a single malformed
// record never disrupts sample collection.
func (d *DB) Lookup(addr netip.Addr) (Info, bool) {
	if d == nil || !addr.IsValid() {
		return Info{}, false
	}
	var info Info
	if d.asn != nil {
		if res := d.asn.Lookup(addr); res.Found() {
			var rec asnRecord
			if err := res.Decode(&rec); err == nil {
				info.ASN = rec.Number
				info.Org = rec.Org
			}
		}
	}
	if d.country != nil {
		if res := d.country.Lookup(addr); res.Found() {
			var rec countryRecord
			if err := res.Decode(&rec); err == nil {
				info.Country = rec.Country.ISOCode
				if info.Country == "" {
					info.Country = rec.RegisteredCountry.ISOCode
				}
			}
		}
	}
	ok := info.ASN != 0 || info.Country != ""
	return info, ok
}

// HasASN reports whether an ASN database is loaded. False (including for a nil
// DB) means Lookup can never populate Info.ASN, so callers should not present a
// per-ASN breakdown.
func (d *DB) HasASN() bool { return d != nil && d.asn != nil }

// Close releases the mmap-ed database files. It is safe to call on a nil DB or
// with either reader absent.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	var first error
	if d.asn != nil {
		if err := d.asn.Close(); err != nil && first == nil {
			first = err
		}
		d.asn = nil
	}
	if d.country != nil {
		if err := d.country.Close(); err != nil && first == nil {
			first = err
		}
		d.country = nil
	}
	return first
}

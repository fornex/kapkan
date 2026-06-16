# geoip test fixtures

`asn.mmdb` and `country.mmdb` are tiny, self-contained MaxMind DB files used
only by the package tests. They are **not** real GeoLite2 data — they hold a
handful of documentation/test prefixes (RFC 5737 / RFC 3849) with synthetic
ASN and country values, so they carry no license obligations.

Mappings:

| prefix              | ASN   | org             | country |
|---------------------|-------|-----------------|---------|
| `198.51.100.0/24`   | 64500 | Evil Corp       | RU      |
| `203.0.113.0/24`    | 64501 | Victim Net LLC  | US      |
| `2001:db8:ffff::/48`| 64502 | IPv6 Botnet AS  | CN      |

`country.mmdb` additionally maps `198.18.0.0/24` with **only** a
`registered_country` of `JP` (no `country` object) to exercise the
registered-country fallback in `Lookup`.

They were generated once with `github.com/maxmind/mmdbwriter` (a build-time-only
tool, intentionally kept out of this module's `go.mod`):

```go
asn, _ := mmdbwriter.New(mmdbwriter.Options{
    DatabaseType: "GeoLite2-ASN", RecordSize: 24, IncludeReservedNetworks: true,
})
_, net, _ := net.ParseCIDR("198.51.100.0/24")
asn.Insert(net, mmdbtype.Map{
    "autonomous_system_number":       mmdbtype.Uint32(64500),
    "autonomous_system_organization": mmdbtype.String("Evil Corp"),
})
// ...repeat for the other rows, write to asn.mmdb

country, _ := mmdbwriter.New(mmdbwriter.Options{
    DatabaseType: "GeoLite2-Country", RecordSize: 24, IncludeReservedNetworks: true,
})
country.Insert(net, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("RU")}})
// ...repeat, write to country.mmdb
```

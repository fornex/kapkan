package clearance

import (
	"strings"
	"testing"
	"time"
)

// TestReturnPathShapes pins what the answer endpoint may be sent to: an
// absolute path on this host — never a scheme-relative URL, never a backslash
// (a browser reads "/\host" as "//host"), never a control byte, never more
// than the bound — and that a long but legal path is usable.
func TestReturnPathShapes(t *testing.T) {
	for _, bad := range []string{"", "cart", "//evil.example/", `/\evil.example/`, `/a\b`, "/a\x00b", "/a\x7fb", "/" + strings.Repeat("x", maxReturnPath)} {
		if ValidReturnPath(bad) {
			t.Errorf("%q accepted as a return path", bad)
		}
	}
	for _, good := range []string{"/", "/cart?x=1&y=/é", "/a/b/c#frag", "/" + strings.Repeat("x", maxReturnPath-1)} {
		if !ValidReturnPath(good) {
			t.Errorf("%q refused as a return path", good)
		}
	}
}

// TestTicketCarriesTheLongestReturnPath pins that every ticket NewTicket
// mints is redeemable: a return path at the bound still fits the presented
// ticket's own bound.
func TestTicketCarriesTheLongestReturnPath(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	secret, err := DeriveZoneKey([]byte(strings.Repeat("m", 32)), "shop.example")
	if err != nil {
		t.Fatal(err)
	}
	k := Key{ID: "clearance-2026-09-06", Secret: secret, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(47 * time.Hour)}
	long := "/search?" + strings.Repeat("q=very-long-filter-value&", 100)
	long = long[:maxReturnPath-1]
	ticket, err := NewTicket(k, "shop.example", "203.0.113.4", long, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ticket) > maxTicket {
		t.Fatalf("a minted ticket is %d bytes, over the %d it must fit", len(ticket), maxTicket)
	}
	ret, ok := CheckTicket([]Key{k}, "shop.example", "203.0.113.4", ticket, now.Add(5*time.Second))
	if !ok || ret != long {
		t.Fatalf("the long ticket did not redeem: ok=%v len=%d", ok, len(ret))
	}
}

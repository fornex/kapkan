package clearance

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

func key(t *testing.T, id string, master string, zone string, from, to time.Time) Key {
	t.Helper()
	m := bytes.Repeat([]byte(master), 32)[:32]
	s, err := DeriveZoneKey(m, zone)
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: id, Secret: s, NotBefore: from, NotAfter: to}
}

func TestDeriveZoneKeyIsDeterministicAndPerZone(t *testing.T) {
	m := bytes.Repeat([]byte("m"), 32)
	a1, _ := DeriveZoneKey(m, "a.example")
	a2, _ := DeriveZoneKey(m, "a.example")
	b, _ := DeriveZoneKey(m, "b.example")
	if !bytes.Equal(a1, a2) || bytes.Equal(a1, b) || len(a1) != SecretLen {
		t.Fatalf("derive: a1=%x a2=%x b=%x", a1[:4], a2[:4], b[:4])
	}
	m2 := bytes.Repeat([]byte("n"), 32)
	a3, _ := DeriveZoneKey(m2, "a.example")
	if bytes.Equal(a1, a3) {
		t.Fatal("two masters derived the same zone key")
	}
	if _, err := DeriveZoneKey(m[:16], "a.example"); err == nil {
		t.Fatal("a short master was accepted")
	}
	if _, err := DeriveZoneKey(m, ""); err == nil {
		t.Fatal("an empty zone was accepted")
	}
}

func TestTokenRoundTripAndBinding(t *testing.T) {
	k := key(t, "e1", "m", "shop.test", t0.Add(-time.Hour), t0.Add(23*time.Hour))
	tok, err := Issue(k, "shop.test", "203.0.113.4", KindPoW, t0.Add(30*time.Minute), t0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "v1.e1.pow.") || len(tok) > 200 {
		t.Fatalf("token shape: %q", tok)
	}
	if kind, ok := Verify([]Key{k}, "shop.test", "203.0.113.4", tok, t0.Add(time.Minute)); !ok || kind != KindPoW {
		t.Fatalf("verify: %q %v", kind, ok)
	}
	// Bound to the zone and the source key.
	if _, ok := Verify([]Key{k}, "other.test", "203.0.113.4", tok, t0); ok {
		t.Fatal("token verified on another zone")
	}
	if _, ok := Verify([]Key{k}, "shop.test", "203.0.113.5", tok, t0); ok {
		t.Fatal("token verified for another source")
	}
	// Expiry is enforced at the second.
	if _, ok := Verify([]Key{k}, "shop.test", "203.0.113.4", tok, t0.Add(30*time.Minute)); ok {
		t.Fatal("expired token verified")
	}
	// Tampering with any field fails.
	for _, bad := range []string{
		strings.Replace(tok, ".pow.", ".nojs.", 1),
		strings.Replace(tok, "v1.", "v2.", 1),
		tok[:len(tok)-1] + "A",
		tok + "x",
		strings.Replace(tok, ".e1.", ".e2.", 1),
		"", "v1", "v1.e1.pow.1.x.y", strings.Repeat("a", 600),
	} {
		if _, ok := Verify([]Key{k}, "shop.test", "203.0.113.4", bad, t0); ok {
			t.Fatalf("tampered token verified: %q", bad)
		}
	}
	// A different zone's key (same master) does not verify it either.
	other := key(t, "e1", "m", "other.test", t0.Add(-time.Hour), t0.Add(23*time.Hour))
	if _, ok := Verify([]Key{other}, "shop.test", "203.0.113.4", tok, t0); ok {
		t.Fatal("another zone's key verified the token")
	}
}

func TestKeyWindowsAndRotation(t *testing.T) {
	prev := key(t, "e0", "p", "shop.test", t0.Add(-25*time.Hour), t0.Add(-time.Hour))
	cur := key(t, "e1", "c", "shop.test", t0.Add(-time.Hour), t0.Add(23*time.Hour))
	next := key(t, "e2", "n", "shop.test", t0.Add(23*time.Hour), t0.Add(47*time.Hour))
	// Issuing needs a live key.
	if _, err := Issue(prev, "shop.test", "s", KindPoW, t0.Add(time.Hour), t0); err == nil {
		t.Fatal("issued under a key past its window")
	}
	if _, err := Issue(next, "shop.test", "s", KindPoW, t0.Add(time.Hour), t0); err == nil {
		t.Fatal("issued under a key before its window")
	}
	// A token issued under the previous epoch verifies while that key is
	// still live (the overlap), and not after — even though the TOKEN itself
	// has not expired: the key's window, not the token's, is what bounds a
	// leaked key's usefulness.
	tokPrev, err := Issue(prev, "shop.test", "s", KindNoJS, t0.Add(time.Hour), t0.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if kind, ok := Verify([]Key{prev, cur}, "shop.test", "s", tokPrev, t0.Add(-100*time.Minute)); !ok || kind != KindNoJS {
		t.Fatal("previous-epoch token refused inside the overlap")
	}
	if _, ok := Verify([]Key{prev, cur}, "shop.test", "s", tokPrev, t0); ok {
		t.Fatal("an unexpired token verified after its key's window ended")
	}
	// A key not yet live refuses too: a token minted tomorrow under the next
	// epoch (live then) is worthless today.
	tokNext, err := Issue(next, "shop.test", "s", KindPoW, t0.Add(25*time.Hour), t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Verify([]Key{cur, next}, "shop.test", "s", tokNext, t0); ok {
		t.Fatal("a token under a not-yet-live key verified")
	}
	if _, ok := Verify([]Key{cur, next}, "shop.test", "s", tokNext, t0.Add(24*time.Hour)); !ok {
		t.Fatal("the same token refused once its key is live")
	}
	// Puzzles honour the window the same way: one issued under prev a minute
	// before it died is refused a minute after, although its bucket is still
	// within the checker's reach.
	p, err := NewPuzzle(prev, "shop.test", "s", "/", MinDifficulty, t0.Add(-61*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	sol := Solve(p)
	if !Check([]Key{prev, cur}, "shop.test", "s", "/", MinDifficulty, p.Nonce, sol, t0.Add(-60*time.Minute-time.Second)) {
		t.Fatal("a solution under a live key was refused")
	}
	if Check([]Key{prev, cur}, "shop.test", "s", "/", MinDifficulty, p.Nonce, sol, t0.Add(-59*time.Minute)) {
		t.Fatal("a solution under a dead key was accepted")
	}
	// A key with a malformed secret or ID never verifies or issues.
	bad := Key{ID: "e.1", Secret: cur.Secret, NotBefore: cur.NotBefore, NotAfter: cur.NotAfter}
	if _, err := Issue(bad, "shop.test", "s", KindPoW, t0.Add(time.Hour), t0); err == nil {
		t.Fatal("a key id with a dot was accepted")
	}
	short := Key{ID: "e3", Secret: cur.Secret[:16], NotBefore: cur.NotBefore, NotAfter: cur.NotAfter}
	if _, err := Issue(short, "shop.test", "s", KindPoW, t0.Add(time.Hour), t0); err == nil {
		t.Fatal("a short secret was accepted")
	}
}

func TestPuzzleIsStatelessAndBound(t *testing.T) {
	k := key(t, "e1", "m", "shop.test", t0.Add(-time.Hour), t0.Add(23*time.Hour))
	p, err := NewPuzzle(k, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Nonce, "e1.") || p.Return != "/cart?x=1" || p.Difficulty != MinDifficulty {
		t.Fatalf("puzzle: %+v", p)
	}
	sol := Solve(p)
	keys := []Key{k}
	if !Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0.Add(10*time.Second)) {
		t.Fatal("a correct solution was refused")
	}
	// Still accepted in the next bucket (the client took its time) and in the
	// previous one (the checking node's clock is behind the issuing node's),
	// not two buckets away.
	if !Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0.Add(3*time.Minute)) {
		t.Fatal("solution refused in the following bucket")
	}
	if !Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0.Add(-90*time.Second)) {
		t.Fatal("solution refused by a checker one bucket behind the issuer")
	}
	if Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0.Add(4*time.Minute)) {
		t.Fatal("stale nonce accepted")
	}
	if Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0.Add(-4*time.Minute)) {
		t.Fatal("a nonce from two buckets ahead was accepted")
	}
	// Bound to zone, source, return path and the server's difficulty.
	if Check(keys, "other.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0) {
		t.Fatal("solution accepted for another zone")
	}
	if Check(keys, "shop.test", "203.0.113.5", "/cart?x=1", MinDifficulty, p.Nonce, sol, t0) {
		t.Fatal("solution accepted for another source")
	}
	if Check(keys, "shop.test", "203.0.113.4", "/evil", MinDifficulty, p.Nonce, sol, t0) {
		t.Fatal("solution accepted for another return path")
	}
	if Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty+8, p.Nonce, sol, t0) {
		// The server may have raised the difficulty since; a 12-bit solution
		// must not pass a 20-bit policy.
		t.Fatal("a weak solution passed a harder policy")
	}
	if Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, p.Nonce, sol+"x", t0) {
		t.Fatal("a wrong solution was accepted")
	}
	if Check(keys, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, "e1.forged", sol, t0) {
		t.Fatal("a forged nonce was accepted")
	}
	// The nonce is stable within a bucket (no state needed) and changes across.
	p2, _ := NewPuzzle(k, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, t0.Add(100*time.Second))
	p3, _ := NewPuzzle(k, "shop.test", "203.0.113.4", "/cart?x=1", MinDifficulty, t0.Add(2*time.Minute))
	if p2.Nonce != p.Nonce || p3.Nonce == p.Nonce {
		t.Fatalf("nonce stability: %q %q %q", p.Nonce, p2.Nonce, p3.Nonce)
	}
}

func TestPuzzleRefusesBadInputs(t *testing.T) {
	k := key(t, "e1", "m", "shop.test", t0.Add(-time.Hour), t0.Add(23*time.Hour))
	for _, ret := range []string{"", "cart", "//evil.example/", "https://evil.example/", "/a\nb", "/" + strings.Repeat("x", 3000)} {
		if _, err := NewPuzzle(k, "shop.test", "s", ret, DefaultDifficulty, t0); err == nil {
			t.Fatalf("return path %q accepted", ret)
		}
	}
	for _, d := range []int{0, MinDifficulty - 1, MaxDifficulty + 1, 64} {
		if _, err := NewPuzzle(k, "shop.test", "s", "/", d, t0); err == nil {
			t.Fatalf("difficulty %d accepted", d)
		}
	}
	dead := Key{ID: "e0", Secret: k.Secret, NotBefore: t0.Add(-48 * time.Hour), NotAfter: t0.Add(-24 * time.Hour)}
	if _, err := NewPuzzle(dead, "shop.test", "s", "/", DefaultDifficulty, t0); err == nil {
		t.Fatal("a puzzle was issued under a dead key")
	}
	if Check([]Key{k}, "shop.test", "s", "/", DefaultDifficulty, strings.Repeat("n", 200), "1", t0) {
		t.Fatal("an oversized nonce was accepted")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	var sum [32]byte
	if leadingZeroBits(sum) != 256 {
		t.Fatal("all-zero sum")
	}
	sum[0] = 0x0f
	if leadingZeroBits(sum) != 4 {
		t.Fatalf("0x0f: %d", leadingZeroBits(sum))
	}
	sum[0] = 0
	sum[1] = 0x80
	if leadingZeroBits(sum) != 8 {
		t.Fatalf("00 80: %d", leadingZeroBits(sum))
	}
}

func BenchmarkVerify(b *testing.B) {
	k := Key{ID: "e1", Secret: bytes.Repeat([]byte("k"), 32), NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour)}
	tok, _ := Issue(k, "shop.test", "203.0.113.4", KindPoW, t0.Add(30*time.Minute), t0)
	keys := []Key{k, {ID: "e0", Secret: bytes.Repeat([]byte("j"), 32), NotBefore: t0.Add(-25 * time.Hour), NotAfter: t0.Add(time.Hour)}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := Verify(keys, "shop.test", "203.0.113.4", tok, t0); !ok {
			b.Fatal("verify failed")
		}
	}
}

// Package clearance is the edge's proof-of-work rung (edge-spec §1 layer 5,
// §5; milestone E4): the primitives a node needs to CHALLENGE a client and to
// recognise one that passed — a puzzle it can hand out without remembering
// anything about the client, and a signed token (the clearance cookie) it can
// verify on any node of the fleet.
//
// It is a LEAF package, standard library only, imported by the decision
// service, the page server and the brain's keyring. Nothing here knows about
// HTTP, nginx or the zone document; those wire the primitives.
//
// The words: the edge's own ACME machinery already owns "challenge" on a node
// (acme.ChallengeTable, edge-challenge.sock), so the code word for this rung
// is CLEARANCE; the zones file keeps the spec's `policy.challenge`.
//
// Keys. Every zone has a small set of live keys — the current epoch's and the
// previous one's, so a token issued just before a rotation still verifies —
// each a 32-byte secret with a validity window. The brain derives a zone's key
// from a fleet master with HKDF (DeriveZoneKey), so two nodes agree without
// storing anything per zone and the zone document stays deterministic; a node
// that got no keys from its brain mints an ephemeral one of its own.
//
// Tokens. A clearance token binds a zone, a source key (edgedoc.SourceKey: the
// IPv4 address or the IPv6 /64 the decider accounts by), a kind (how it was
// earned) and an expiry under an HMAC-SHA256 of one key. Nothing else: it is
// not a session, carries no client identity, and is useless on another zone
// (a different key) or from another source.
//
// Puzzles. A puzzle is hashcash: find a solution such that SHA-256(nonce ||
// solution) starts with Difficulty zero bits. The nonce is itself an HMAC of
// (zone, source key, return path, minute bucket) under the zone's key, so the
// server keeps NO per-client state: a solution is checked by recomputing the
// nonce for the current and the previous minute. The return path is signed
// into the nonce, so the answer endpoint can only send a client where the
// terminator said it came from (no open redirect).
package clearance

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

// Kinds of clearance: how the token was earned. They ride in the token (and
// in the origin's X-Kapkan-Mark as "cleared" / "cleared:nojs"), so an origin
// can tell a solved puzzle from the timed no-JS ticket.
const (
	KindPoW  = "pow"
	KindNoJS = "nojs"
)

// Puzzle bounds. Difficulty is the number of leading zero bits the SHA-256 of
// nonce||solution must have: 2^d hashes on average; 18 is a fraction of a
// second on a laptop, a few seconds on a low-end phone.
const (
	MinDifficulty     = 12
	MaxDifficulty     = 24
	DefaultDifficulty = 18
	// SecretLen is the size of a key secret.
	SecretLen = 32
	// maxToken bounds what Verify will look at: a cookie header is untrusted
	// input on the request path.
	maxToken = 512
	// nonceBucket is the puzzle nonce's time granularity; a solution is
	// accepted for the bucket it was issued in and the one after.
	nonceBucket = time.Minute
	// maxReturnPath bounds the path signed into a puzzle.
	maxReturnPath = 2048
)

// Key is one clearance key of a zone: an opaque ID (the brain's epoch), the
// secret, and the window in which tokens under it are honoured.
type Key struct {
	ID        string
	Secret    []byte
	NotBefore time.Time
	NotAfter  time.Time
}

// live reports whether the key may verify (or issue) at now.
func (k Key) live(now time.Time) bool {
	return len(k.Secret) == SecretLen && k.ID != "" && !now.Before(k.NotBefore) && now.Before(k.NotAfter)
}

// NewSecret draws a fresh key secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DeriveZoneKey derives a zone's secret from a fleet master with HKDF-SHA256:
// the same (master, zone) always yields the same secret, so the brain stores
// one master per epoch and the document stays deterministic.
func DeriveZoneKey(master []byte, zone string) ([]byte, error) {
	if len(master) < SecretLen {
		return nil, fmt.Errorf("clearance: master key is %d bytes, need at least %d", len(master), SecretLen)
	}
	if zone == "" {
		return nil, errors.New("clearance: empty zone")
	}
	return hkdf.Key(sha256.New, master, nil, "kapkan-clearance:"+zone, SecretLen)
}

// Issue mints a token for (zone, source key, kind) under key, expiring at exp.
// The caller picks the live current key; Issue refuses a key outside its
// window so a rotation cannot mint under yesterday's secret.
func Issue(key Key, zone, sourceKey, kind string, exp time.Time, now time.Time) (string, error) {
	if !key.live(now) {
		return "", errors.New("clearance: key is not live")
	}
	if zone == "" || sourceKey == "" {
		return "", errors.New("clearance: zone and source key are required")
	}
	if kind != KindPoW && kind != KindNoJS {
		return "", fmt.Errorf("clearance: unknown kind %q", kind)
	}
	if strings.ContainsAny(key.ID, ".| ") {
		return "", errors.New("clearance: key id must not contain '.', '|' or spaces")
	}
	if !exp.After(now) {
		return "", errors.New("clearance: expiry is not in the future")
	}
	expUnix := strconv.FormatInt(exp.Unix(), 10)
	mac := tokenMAC(key.Secret, zone, sourceKey, kind, expUnix)
	return "v1." + key.ID + "." + kind + "." + expUnix + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// Verify checks a token presented by sourceKey for zone against the zone's
// live keys. It returns the kind the token was earned with. Every failure is
// the same "false": a bad token is not worth a reason on the request path.
func Verify(keys []Key, zone, sourceKey, token string, now time.Time) (kind string, ok bool) {
	if len(token) == 0 || len(token) > maxToken {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[0] != "v1" {
		return "", false
	}
	keyID, kind, expStr, macB64 := parts[1], parts[2], parts[3], parts[4]
	if kind != KindPoW && kind != KindNoJS {
		return "", false
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || expUnix <= 0 {
		return "", false
	}
	if now.Unix() >= expUnix {
		return "", false
	}
	mac, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil || len(mac) != sha256.Size {
		return "", false
	}
	for _, k := range keys {
		if k.ID != keyID || !k.live(now) {
			continue
		}
		want := tokenMAC(k.Secret, zone, sourceKey, kind, expStr)
		if subtle.ConstantTimeCompare(mac, want) == 1 {
			return kind, true
		}
	}
	return "", false
}

func tokenMAC(secret []byte, zone, sourceKey, kind, expUnix string) []byte {
	h := hmac.New(sha256.New, secret)
	// Length-prefixed fields: no separator ambiguity between zone, source
	// key and kind whatever characters they carry.
	for _, f := range []string{"token", zone, sourceKey, kind, expUnix} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

// Puzzle is what a challenged client is asked to solve. Everything a client
// sees is public; the nonce is what binds the puzzle to (zone, source, return
// path, minute) without the server remembering it.
type Puzzle struct {
	Nonce      string `json:"nonce"`
	Difficulty int    `json:"difficulty"`
	// Return is the path the client is sent back to once cleared; it came
	// from the terminator (X-Kapkan-URI), never from the client, and is
	// signed into the nonce.
	Return string `json:"return"`
}

// NewPuzzle issues the puzzle for (zone, source key, return path) at now.
func NewPuzzle(key Key, zone, sourceKey, returnPath string, difficulty int, now time.Time) (Puzzle, error) {
	if !key.live(now) {
		return Puzzle{}, errors.New("clearance: key is not live")
	}
	if difficulty < MinDifficulty || difficulty > MaxDifficulty {
		return Puzzle{}, fmt.Errorf("clearance: difficulty %d outside %d..%d", difficulty, MinDifficulty, MaxDifficulty)
	}
	if err := checkReturnPath(returnPath); err != nil {
		return Puzzle{}, err
	}
	bucket := now.Unix() / int64(nonceBucket/time.Second)
	return Puzzle{Nonce: nonceFor(key, zone, sourceKey, returnPath, bucket), Difficulty: difficulty, Return: returnPath}, nil
}

// Check verifies a client's solution to the puzzle it was handed: the nonce
// must be one this key would have issued for (zone, source key, return path)
// in the current or the previous minute bucket, and SHA-256(nonce||solution)
// must carry the difficulty. Difficulty comes from the server's own policy,
// never from the client.
func Check(keys []Key, zone, sourceKey, returnPath string, difficulty int, nonce, solution string, now time.Time) bool {
	if len(nonce) == 0 || len(nonce) > 128 || len(solution) == 0 || len(solution) > 64 {
		return false
	}
	if difficulty < MinDifficulty || difficulty > MaxDifficulty || checkReturnPath(returnPath) != nil {
		return false
	}
	bucket := now.Unix() / int64(nonceBucket/time.Second)
	matched := false
	for _, k := range keys {
		if !k.live(now) {
			continue
		}
		for _, b := range []int64{bucket, bucket - 1} {
			want := nonceFor(k, zone, sourceKey, returnPath, b)
			if subtle.ConstantTimeCompare([]byte(want), []byte(nonce)) == 1 {
				matched = true
			}
		}
	}
	if !matched {
		return false
	}
	return leadingZeroBits(sha256.Sum256([]byte(nonce+solution))) >= difficulty
}

// Solve finds a solution for the puzzle — for tests and for the acceptance
// rig's "browser"; a real client runs the same loop in a Worker.
func Solve(p Puzzle) string {
	for i := uint64(0); ; i++ {
		s := strconv.FormatUint(i, 36)
		if leadingZeroBits(sha256.Sum256([]byte(p.Nonce+s))) >= p.Difficulty {
			return s
		}
	}
}

func nonceFor(key Key, zone, sourceKey, returnPath string, bucket int64) string {
	h := hmac.New(sha256.New, key.Secret)
	for _, f := range []string{"puzzle", key.ID, zone, sourceKey, returnPath, strconv.FormatInt(bucket, 10)} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	// 16 bytes of the MAC is plenty for an unguessable nonce and keeps the
	// puzzle small; the key ID travels in front so Check can find the key
	// without trying every one.
	return key.ID + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
}

// checkReturnPath admits only an absolute path on this host: no scheme, no
// authority, no control bytes — the answer endpoint redirects here.
func checkReturnPath(p string) error {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || len(p) > maxReturnPath {
		return errors.New("clearance: return path must be an absolute path on this host")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return errors.New("clearance: return path carries a control byte")
		}
	}
	return nil
}

func leadingZeroBits(sum [sha256.Size]byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

package acme

// fakeCA is a hermetic ACME server for the tests: enough of RFC 8555 for
// golang.org/x/crypto/acme to register, order, be validated and receive a
// certificate — with a REAL HTTP-01 validation step that fetches the token
// from an answerer the test provides, exactly as a CA would from a node.
// Signatures are not verified (the test owns both ends); the account JWK is
// parsed to compute the thumbprint the key authorization must carry.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"
)

type fakeOrder struct {
	id        string
	zone      string
	authz     string
	token     string
	status    string
	certPEM   []byte
	thumb     string
	authzOK   bool
	validated bool
	// processing: the challenge was accepted and the CA "is validating" —
	// the next authorization poll completes it (asyncValidate).
	processing bool
	// finalizing: finalize answered "processing" once; the next order poll
	// turns it valid (finalizeProcessing).
	finalizing bool
	// signFailed: the order went invalid after finalize (invalidAfterFinalize).
	signFailed bool
}

type fakeCA struct {
	t      *testing.T
	srv    *httptest.Server
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	now    func() time.Time
	// lifetime of issued certificates.
	lifetime time.Duration
	// answerer is where validation fetches tokens (the ChallengeTable's
	// handler served by httptest); zone selects the Host header.
	answerer string

	mu       sync.Mutex
	orders   map[string]*fakeOrder
	accounts map[string]string // account URL -> thumbprint
	seq      int
	// failNewOrder makes newOrder answer with this ACME problem (e.g. 429).
	failNewOrder int
	newOrders    int
	validations  []string // "zone/token" of every validation fetch
	// requireEAB makes newAccount demand an External Account Binding whose
	// kid is eabKID (urn:ietf:params:acme:error:externalAccountRequired).
	requireEAB bool
	eabKID     string
	eabSeen    []string // kids of the bindings received
	// asyncValidate: Accept answers "processing" and the validation happens
	// on the next authorization poll, as a real VA does.
	asyncValidate bool
	// finalizeProcessing: finalize answers "processing" once (with the order's
	// Location, RFC 8555 §7.4) before the certificate is ready.
	finalizeProcessing bool
	// misissue signs the certificate for a fresh key instead of the CSR's.
	misissue bool
	// lateFinalize omits the order's finalize URL while it is pending.
	lateFinalize bool
	// finalizeNoLocation answers finalize without the order's Location header
	// (Pebble), so a "processing" answer leaves the client nothing to poll.
	finalizeNoLocation bool
	// failFinalize answers finalize with this ACME problem status (badCSR).
	failFinalize int
	// invalidAfterFinalize: a "processing" order turns invalid with a problem
	// on the next poll instead of valid — the CA could not sign it.
	invalidAfterFinalize bool
	certFetches          int
	// nonces issued and not yet used; badNonce for a reuse.
	nonces map[string]bool
}

func newFakeCA(t *testing.T, now func() time.Time, answerer string) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake Kapkan Test CA"},
		NotBefore: now().Add(-time.Hour), NotAfter: now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	f := &fakeCA{t: t, caKey: key, caCert: caCert, now: now, lifetime: 90 * 24 * time.Hour, answerer: answerer,
		orders: make(map[string]*fakeOrder), accounts: make(map[string]string), nonces: make(map[string]bool)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCA) directory() string { return f.srv.URL + "/dir" }

func (f *fakeCA) nextID() string {
	f.seq++
	return strconv.Itoa(f.seq)
}

// jws is the body of every ACME POST.
type jws struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
}

type protectedHeader struct {
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	KID   string          `json:"kid"`
	JWK   json.RawMessage `json:"jwk"`
}

func b64url(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

// readJWS parses a POST body; ok is false (and a badNonce problem written)
// when the nonce was never issued or was used before.
func (f *fakeCA) readJWS(w http.ResponseWriter, r *http.Request) (protectedHeader, []byte, bool) {
	body, _ := io.ReadAll(r.Body)
	var j jws
	_ = json.Unmarshal(body, &j)
	var ph protectedHeader
	_ = json.Unmarshal(b64url(j.Protected), &ph)
	if !f.nonces[ph.Nonce] {
		f.problem(w, 400, "urn:ietf:params:acme:error:badNonce", "nonce "+ph.Nonce+" is not fresh")
		return ph, nil, false
	}
	delete(f.nonces, ph.Nonce)
	return ph, b64url(j.Payload), true
}

func (f *fakeCA) nonce(w http.ResponseWriter) {
	n := "nonce-" + f.nextID()
	f.nonces[n] = true
	w.Header().Set("Replay-Nonce", n)
}

func (f *fakeCA) writeJSON(w http.ResponseWriter, status int, v any) {
	f.nonce(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeCA) problem(w http.ResponseWriter, status int, typ, detail string) {
	f.nonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": typ, "detail": detail, "status": status})
}

func (f *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base := f.srv.URL
	switch {
	case r.URL.Path == "/dir":
		meta := map[string]any{"termsOfService": base + "/tos"}
		if f.requireEAB {
			meta["externalAccountRequired"] = true
		}
		f.writeJSON(w, 200, map[string]any{
			"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order",
			"revokeCert": base + "/revoke", "keyChange": base + "/keychange",
			"meta": meta,
		})
	case r.URL.Path == "/nonce":
		f.nonce(w)
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/acct":
		ph, payload, ok := f.readJWS(w, r)
		if !ok {
			return
		}
		thumb, err := thumbprintFromJWK(ph.JWK)
		if err != nil {
			f.problem(w, 400, "urn:ietf:params:acme:error:malformed", err.Error())
			return
		}
		if f.requireEAB {
			var acct struct {
				EAB *jws `json:"externalAccountBinding"`
			}
			_ = json.Unmarshal(payload, &acct)
			if acct.EAB == nil {
				f.problem(w, 400, "urn:ietf:params:acme:error:externalAccountRequired", "this CA requires an external account binding")
				return
			}
			var eabHdr struct {
				KID string `json:"kid"`
			}
			_ = json.Unmarshal(b64url(acct.EAB.Protected), &eabHdr)
			f.eabSeen = append(f.eabSeen, eabHdr.KID)
			if eabHdr.KID != f.eabKID {
				f.problem(w, 403, "urn:ietf:params:acme:error:unauthorized", "unknown eab kid "+eabHdr.KID)
				return
			}
		}
		for url, th := range f.accounts {
			if th == thumb {
				// Existing account: RFC 8555 answers 200 with the same Location.
				w.Header().Set("Location", url)
				f.writeJSON(w, 200, map[string]any{"status": "valid"})
				return
			}
		}
		url := base + "/acct/" + f.nextID()
		f.accounts[url] = thumb
		w.Header().Set("Location", url)
		f.writeJSON(w, 201, map[string]any{"status": "valid"})
	case r.URL.Path == "/order":
		ph, payload, ok := f.readJWS(w, r)
		if !ok {
			return
		}
		f.newOrders++
		if f.failNewOrder != 0 {
			f.problem(w, f.failNewOrder, "urn:ietf:params:acme:error:rateLimited", "too many certificates already issued")
			return
		}
		var req struct {
			Identifiers []struct{ Type, Value string } `json:"identifiers"`
		}
		_ = json.Unmarshal(payload, &req)
		if len(req.Identifiers) != 1 || req.Identifiers[0].Type != "dns" {
			f.problem(w, 400, "urn:ietf:params:acme:error:malformed", "one dns identifier expected")
			return
		}
		o := &fakeOrder{id: f.nextID(), zone: req.Identifiers[0].Value, status: "pending", thumb: f.accounts[ph.KID]}
		o.authz = f.nextID()
		o.token = "tok-" + strings.Repeat("x", 20) + o.id
		f.orders[o.id] = o
		w.Header().Set("Location", base+"/order/"+o.id)
		f.writeJSON(w, 201, f.orderJSON(o))
	case strings.HasPrefix(r.URL.Path, "/order/") && strings.HasSuffix(r.URL.Path, "/finalize"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/order/"), "/finalize")
		o := f.orders[id]
		if o == nil || o.status != "ready" {
			f.problem(w, 403, "urn:ietf:params:acme:error:orderNotReady", "order is not ready")
			return
		}
		_, payload, ok := f.readJWS(w, r)
		if !ok {
			return
		}
		if f.failFinalize != 0 {
			f.problem(w, f.failFinalize, "urn:ietf:params:acme:error:badCSR", "the CSR was refused by the fake")
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(payload, &req)
		csr, err := x509.ParseCertificateRequest(b64url(req.CSR))
		if err != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != o.zone {
			f.problem(w, 400, "urn:ietf:params:acme:error:badCSR", "csr does not match the order")
			return
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
		tmpl := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: o.zone}, DNSNames: []string{o.zone},
			NotBefore: f.now().Add(-time.Minute), NotAfter: f.now().Add(f.lifetime),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		pub := csr.PublicKey
		if f.misissue {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			pub = &other.PublicKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, pub, f.caKey)
		if err != nil {
			f.problem(w, 500, "urn:ietf:params:acme:error:serverInternal", err.Error())
			return
		}
		o.certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})...)
		// RFC 8555 §7.4: the finalize response carries the order's URL, which
		// the client polls when the answer is "processing" — unless the CA
		// forgets it (Pebble does).
		if !f.finalizeNoLocation {
			w.Header().Set("Location", base+"/order/"+o.id)
		}
		if f.finalizeProcessing && !o.finalizing {
			o.finalizing = true
			o.status = "processing"
			w.Header().Set("Retry-After", "1")
			f.writeJSON(w, 200, f.orderJSON(o))
			return
		}
		o.status = "valid"
		f.writeJSON(w, 200, f.orderJSON(o))
	case strings.HasPrefix(r.URL.Path, "/order/"):
		id := strings.TrimPrefix(r.URL.Path, "/order/")
		o := f.orders[id]
		if o == nil {
			f.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no such order")
			return
		}
		if o.status == "processing" {
			// The poll after a processing finalize finds the certificate — or
			// the CA's refusal.
			if f.invalidAfterFinalize {
				o.status = "invalid"
				o.signFailed = true
			} else {
				o.status = "valid"
			}
		}
		f.writeJSON(w, 200, f.orderJSON(o))
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		o := f.orderByAuthz(strings.TrimPrefix(r.URL.Path, "/authz/"))
		if o == nil {
			f.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no such authorization")
			return
		}
		if o.processing {
			// The VA finished between the Accept and this poll.
			o.processing = false
			f.validate(o)
		}
		f.writeJSON(w, 200, f.authzJSON(o))
	case strings.HasPrefix(r.URL.Path, "/chal/"):
		o := f.orderByAuthz(strings.TrimPrefix(r.URL.Path, "/chal/"))
		if o == nil {
			f.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no such challenge")
			return
		}
		if _, _, ok := f.readJWS(w, r); !ok {
			return
		}
		if f.asyncValidate {
			// Accept: the VA will fetch the token "shortly" — on the next
			// authorization poll here — and tells the client to come back.
			o.processing = true
			w.Header().Set("Retry-After", "1")
			f.writeJSON(w, 200, f.challengeJSON(o))
			return
		}
		// Accept: validate NOW, the way a CA's VA would — by fetching the
		// token from the zone (our answerer, Host set to the zone).
		f.validate(o)
		f.writeJSON(w, 200, f.challengeJSON(o))
	case strings.HasPrefix(r.URL.Path, "/cert/"):
		o := f.orders[strings.TrimPrefix(r.URL.Path, "/cert/")]
		f.certFetches++
		if o == nil || o.status != "valid" {
			f.problem(w, 404, "urn:ietf:params:acme:error:malformed", "no certificate")
			return
		}
		f.nonce(w)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = w.Write(o.certPEM)
	default:
		f.problem(w, 404, "urn:ietf:params:acme:error:malformed", "unknown endpoint "+r.URL.Path)
	}
}

func (f *fakeCA) orderByAuthz(id string) *fakeOrder {
	for _, o := range f.orders {
		if o.authz == id {
			return o
		}
	}
	return nil
}

func (f *fakeCA) orderJSON(o *fakeOrder) map[string]any {
	m := map[string]any{
		"status": o.status, "expires": f.now().Add(time.Hour).Format(time.RFC3339),
		"identifiers":    []map[string]string{{"type": "dns", "value": o.zone}},
		"authorizations": []string{f.srv.URL + "/authz/" + o.authz},
	}
	// RFC 8555 puts the finalize URL on every order; a CA that fills it only
	// once the order is ready must still work. Model both.
	if !f.lateFinalize || o.status == "ready" || o.status == "processing" || o.status == "valid" {
		m["finalize"] = f.srv.URL + "/order/" + o.id + "/finalize"
	}
	if o.status == "valid" {
		m["certificate"] = f.srv.URL + "/cert/" + o.id
	}
	if o.signFailed {
		m["error"] = map[string]any{"type": "urn:ietf:params:acme:error:serverInternal", "detail": "the CA could not sign the order", "status": 500}
	}
	return m
}

func (f *fakeCA) authzJSON(o *fakeOrder) map[string]any {
	status := "pending"
	switch {
	case o.authzOK:
		status = "valid"
	case o.processing:
		status = "pending"
	case o.validated:
		status = "invalid"
	}
	return map[string]any{
		"status": status, "expires": f.now().Add(time.Hour).Format(time.RFC3339),
		"identifier": map[string]string{"type": "dns", "value": o.zone},
		"challenges": []map[string]any{f.challengeJSON(o)},
	}
}

func (f *fakeCA) challengeJSON(o *fakeOrder) map[string]any {
	status := "pending"
	switch {
	case o.authzOK:
		status = "valid"
	case o.processing:
		status = "processing"
	case o.validated:
		status = "invalid"
	}
	m := map[string]any{"type": "http-01", "url": f.srv.URL + "/chal/" + o.authz, "token": o.token, "status": status}
	if o.validated && !o.authzOK {
		m["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "key authorization did not match"}
	}
	return m
}

// validate performs the HTTP-01 fetch against the answerer.
func (f *fakeCA) validate(o *fakeOrder) {
	o.validated = true
	f.validations = append(f.validations, o.zone+"/"+o.token)
	req, _ := http.NewRequest("GET", f.answerer+"/.well-known/acme-challenge/"+o.token, nil)
	req.Host = o.zone
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	want := o.token + "." + o.thumb
	if resp.StatusCode == 200 && strings.TrimSpace(string(body)) == want {
		o.authzOK = true
		o.status = "ready"
	}
}

// thumbprintFromJWK computes the RFC 7638 thumbprint of an EC P-256 JWK, as
// the key authorization is token || '.' || thumbprint.
func thumbprintFromJWK(raw json.RawMessage) (string, error) {
	var jwk struct {
		Kty, Crv, X, Y string
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return "", err
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return "", fmt.Errorf("unsupported jwk %s/%s", jwk.Kty, jwk.Crv)
	}
	x, y := b64url(jwk.X), b64url(jwk.Y)
	if len(x) != 32 || len(y) != 32 {
		return "", fmt.Errorf("jwk coordinates are %d/%d bytes, want 32", len(x), len(y))
	}
	point := append(append([]byte{0x04}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return "", err
	}
	return xacme.JWKThumbprint(pub)
}

// client trusts the fake CA's certificate (the directory is plain http from
// httptest, but the manager's client is shared with tests that check TLS).
func (f *fakeCA) client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

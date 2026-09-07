package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// The tests are hermetic: every one of them runs a real quic-go HTTP/3 server
// on a random loopback UDP port with a throwaway certificate, and drives the
// CLI in-process through run(), so the JSON asserted on is the JSON an arm
// would parse.

const altSvcHeader = `h3=":443"; ma=86400`

// testServer is one in-process HTTP/3 server.
type testServer struct {
	addr   string // host:port, always on 127.0.0.1
	caFile string // PEM file holding the server's self-signed certificate
}

// startServer runs an HTTP/3 server on a random loopback port. With
// verifySource set, its QUIC transport validates every source address, which is
// what makes it answer the first Initial with a Retry.
//
// Handler: "/" answers 200 with an Alt-Svc header, "/second" answers 204 with
// none, so a resume leg's response can be told from the first one's.
func startServer(t *testing.T, verifySource bool) testServer {
	t.Helper()

	cert, certPEM := selfSignedCert(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing the CA file: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listening on loopback UDP: %v", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	if verifySource {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", altSvcHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/second", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ln, err := tr.ListenEarly(
		&tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{http3.NextProtoH3},
			MinVersion:   tls.VersionTLS13,
		},
		&quic.Config{Versions: []quic.Version{quic.Version1}},
	)
	if err != nil {
		t.Fatalf("listening for QUIC: %v", err)
	}
	srv := &http3.Server{Handler: mux}
	go func() { _ = srv.ServeListener(ln) }()

	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		_ = tr.Close()
		_ = udpConn.Close()
	})
	return testServer{addr: udpConn.LocalAddr().String(), caFile: caFile}
}

func (s testServer) url(path string) string { return "https://" + s.addr + path }

// selfSignedCert issues a certificate valid for localhost and 127.0.0.1, so a
// probe can verify it either by SNI or by the IP in the URL.
func selfSignedCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "h3probe test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, certPEM
}

// probeRun drives the CLI exactly as a shell arm would and returns the exit
// code with the decoded result.
func probeRun(t *testing.T, args ...string) (int, result, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	var res result
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout.String())
		}
	}
	return code, res, stderr.String()
}

func TestRetrySeenWhenTheServerValidatesTheSourceAddress(t *testing.T) {
	t.Parallel()

	srv := startServer(t, true)
	code, res, stderr := probeRun(t, "get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if res.Error != "" {
		t.Fatalf("error = %q, want empty", res.Error)
	}
	if !res.RetrySeen {
		t.Error("retry_seen = false, want true: the server validates every source address")
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
	if res.ALPN != "h3" {
		t.Errorf("alpn = %q, want \"h3\"", res.ALPN)
	}
	if res.Proto != "HTTP/3.0" {
		t.Errorf("proto = %q, want \"HTTP/3.0\"", res.Proto)
	}
	if res.Resumed {
		t.Error("resumed = true without -resume")
	}
	if res.ResumeStatus != nil {
		t.Errorf("resume_status = %d, want it absent without -resume", *res.ResumeStatus)
	}
}

func TestNoRetryWhenTheServerDoesNotValidate(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	code, res, stderr := probeRun(t, "get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if res.Error != "" {
		t.Fatalf("error = %q, want empty", res.Error)
	}
	if res.RetrySeen {
		t.Error("retry_seen = true, want false: the server validates no address")
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
}

func TestAltSvcIsEchoedWhenPresent(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	_, res, _ := probeRun(t, "get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile)
	if res.AltSvc != altSvcHeader {
		t.Errorf("alt_svc = %q, want %q", res.AltSvc, altSvcHeader)
	}

	// The /second handler sets no Alt-Svc, and the field is then absent.
	_, res, _ = probeRun(t, "get", "-url", srv.url("/second"), "-sni", "localhost", "-ca", srv.caFile)
	if res.AltSvc != "" {
		t.Errorf("alt_svc = %q, want it empty on a response without the header", res.AltSvc)
	}
}

func TestResumeReportsTheSecondConnectionsResumption(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	code, res, stderr := probeRun(t,
		"get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile, "-resume")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if res.Error != "" {
		t.Fatalf("error = %q, want empty", res.Error)
	}
	if !res.Resumed {
		t.Error("resumed = false, want true: the second connection offered the first one's ticket")
	}
	if res.ResumeStatus == nil {
		t.Fatal("resume_status is absent, want it present under -resume")
	}
	if *res.ResumeStatus != http.StatusOK {
		t.Errorf("resume_status = %d, want 200", *res.ResumeStatus)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
}

func TestWithoutResumeThereIsNoSecondConnection(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	_, res, _ := probeRun(t, "get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile)

	if res.Resumed {
		t.Error("resumed = true, want false: only one connection is made without -resume")
	}
	if res.ResumeStatus != nil {
		t.Errorf("resume_status = %d, want it absent without -resume", *res.ResumeStatus)
	}
}

// The second connection has to go where -resume-url points, which is how the
// E5 rig will prove that a ticket issued by edge-1 resumes on edge-2. Here both
// URLs reach the same server, and the distinct status of /second is what shows
// the second request followed the flag.
func TestResumeURLTargetsTheSecondConnection(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	code, res, stderr := probeRun(t,
		"get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile,
		"-resume-url", srv.url("/second"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if res.Error != "" {
		t.Fatalf("error = %q, want empty", res.Error)
	}
	if !res.Resumed {
		t.Error("resumed = false, want true")
	}
	if res.ResumeStatus == nil || *res.ResumeStatus != http.StatusNoContent {
		t.Errorf("resume_status = %v, want 204 from /second", res.ResumeStatus)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200 from the first URL", res.Status)
	}
}

// -insecure is the flag a rig reaches for before ACME has issued anything.
func TestInsecureSkipsVerification(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	_, res, _ := probeRun(t, "get", "-url", srv.url("/"), "-sni", "not-in-the-certificate", "-insecure")
	if res.Error != "" {
		t.Fatalf("error = %q, want empty under -insecure", res.Error)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", res.Status)
	}
}

func TestVerificationFailureIsAResultNotAnExitCode(t *testing.T) {
	t.Parallel()

	srv := startServer(t, false)
	code, res, _ := probeRun(t, "get", "-url", srv.url("/"), "-sni", "not-in-the-certificate", "-ca", srv.caFile)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: a refused request is still a result", code)
	}
	if res.Error == "" {
		t.Error("error is empty, want the verification failure")
	}
	if res.Status != 0 {
		t.Errorf("status = %d, want 0 on a failed request", res.Status)
	}
}

func TestUnreachableServerIsAResultNotAnExitCode(t *testing.T) {
	t.Parallel()

	// A port that was bound and released: nothing answers there.
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := c.LocalAddr().String()
	if err := c.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}

	code, res, _ := probeRun(t, "get", "-url", "https://"+addr+"/", "-insecure", "-timeout", "1s")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: a failed request is still a result", code)
	}
	if res.Error == "" {
		t.Error("error is empty, want the dial failure")
	}
	if res.Status != 0 {
		t.Errorf("status = %d, want 0", res.Status)
	}
	if res.ALPN != "" || res.Proto != "" {
		t.Errorf("alpn = %q, proto = %q, want both empty", res.ALPN, res.Proto)
	}
}

// The JSON is the interface: shell arms select fields by name, so the shape of
// a successful object is asserted key by key.
func TestJSONShape(t *testing.T) {
	t.Parallel()

	srv := startServer(t, true)

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"get", "-url", srv.url("/"), "-sni", "localhost", "-ca", srv.caFile, "-resume",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want it empty on a successful run", stderr.String())
	}

	var obj map[string]any
	dec := json.NewDecoder(&stdout)
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("decoding stdout: %v", err)
	}
	if dec.More() {
		t.Error("stdout carries more than one JSON object")
	}

	want := map[string]string{
		"status":        "float64",
		"alpn":          "string",
		"proto":         "string",
		"alt_svc":       "string",
		"retry_seen":    "bool",
		"resumed":       "bool",
		"resume_status": "float64",
		"error":         "string",
	}
	for key, kind := range want {
		v, ok := obj[key]
		if !ok {
			t.Errorf("field %q is missing", key)
			continue
		}
		if got := typeName(v); got != kind {
			t.Errorf("field %q is %s, want %s", key, got, kind)
		}
	}
	for key := range obj {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected field %q", key)
		}
	}
}

func typeName(v any) string {
	switch v.(type) {
	case float64:
		return "float64"
	case string:
		return "string"
	case bool:
		return "bool"
	default:
		return "unknown"
	}
}

func TestUsageErrorsExitTwoAndPrintNothingOnStdout(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"unknown subcommand", []string{"post", "-url", "https://example.test/"}},
		{"no url", []string{"get"}},
		{"not https", []string{"get", "-url", "http://example.test/"}},
		{"no host", []string{"get", "-url", "https:///path"}},
		{"bad resume url", []string{"get", "-url", "https://example.test/", "-resume-url", "http://example.test/"}},
		{"non-positive timeout", []string{"get", "-url", "https://example.test/", "-timeout", "0s"}},
		{"unknown flag", []string{"get", "-url", "https://example.test/", "-nope"}},
		{"stray argument", []string{"get", "-url", "https://example.test/", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want it empty on a usage error", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Error("stderr is empty, want an explanation")
			}
		})
	}
}

func TestMissingCAFileIsAUsageErrorFreeResult(t *testing.T) {
	t.Parallel()

	code, res, _ := probeRun(t, "get", "-url", "https://example.test/", "-ca", filepath.Join(t.TempDir(), "absent.pem"))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if res.Error == "" {
		t.Error("error is empty, want the unreadable -ca file reported in the result")
	}
}

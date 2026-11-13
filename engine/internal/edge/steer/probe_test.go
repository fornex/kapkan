package steer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	probeV4 = netip.MustParseAddr("127.0.0.1")
	probeV6 = netip.IPv6Loopback()
)

// probeAlert is the catch-all's answer to the probe (ssl_reject_handshake): one
// TLS record, an alert, fatal, unrecognized_name.
var probeAlert = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70}

const (
	// probeAnswerWait is the first-byte timeout of a probe whose listener
	// answers. It is generous so that a slow CI host under -race cannot turn
	// an answer into a timeout; an answer ends the wait at once.
	probeAnswerWait = 5 * time.Second
	// probeSilenceWait is the first-byte timeout of a probe meant to time out.
	probeSilenceWait = 150 * time.Millisecond
)

// probeFamilies runs a test on 127.0.0.1 and on ::1.
func probeFamilies(t *testing.T, run func(t *testing.T, addr netip.Addr)) {
	for _, addr := range []netip.Addr{probeV4, probeV6} {
		t.Run(probeNetwork(addr), func(t *testing.T) { run(t, addr) })
	}
}

func probeNetwork(addr netip.Addr) string {
	if addr.Is4() {
		return "tcp4"
	}
	return "tcp6"
}

// probeListen listens on addr:0; an IPv6 address the host cannot listen on
// skips the test.
func probeListen(t *testing.T, addr netip.Addr) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP(probeNetwork(addr), net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
	if err != nil {
		if addr.Is6() {
			t.Skipf("no IPv6 loopback on this host: %v", err)
		}
		t.Fatal(err)
	}
	return ln
}

func probePort(ln net.Listener) uint16 { return uint16(ln.Addr().(*net.TCPAddr).Port) }

// probeServe runs serve on every connection accepted on addr:0 until the test
// ends, and returns the port. The connection is closed when serve returns.
func probeServe(t *testing.T, addr netip.Addr, serve func(c *net.TCPConn)) uint16 {
	t.Helper()
	return probeServeOn(t, probeListen(t, addr), serve)
}

func probeServeOn(t *testing.T, ln *net.TCPListener, serve func(c *net.TCPConn)) uint16 {
	t.Helper()
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				// A safety net: no server outlives a broken test by long.
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				serve(c)
			})
		}
	})
	return probePort(ln)
}

// probeClosed is a port on addr that nothing listens on: bound, then closed.
func probeClosed(t *testing.T, addr netip.Addr) uint16 {
	t.Helper()
	ln := probeListen(t, addr)
	port := probePort(ln)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// probeReadRecord reads one TLS record: the 5-byte header, then its body.
func probeReadRecord(r io.Reader) ([]byte, error) {
	rec := make([]byte, 5)
	if _, err := io.ReadFull(r, rec); err != nil {
		return nil, err
	}
	body := make([]byte, int(rec[3])<<8|int(rec[4]))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(rec, body...), nil
}

// probeCert is a self-signed certificate for names, valid until notAfter.
func probeCert(t *testing.T, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notAfter.Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The design's table, against real loopback listeners: what a listener
// answers decides the class, and only a TLS record type is ok.
func TestProbeClassesAgainstRealListeners(t *testing.T) {
	cert := probeCert(t, time.Now().Add(time.Hour), "zone.example")
	for _, tc := range []struct {
		name  string
		serve func(c *net.TCPConn)
		wait  time.Duration
		class Class
		first byte  // for ok and not_tls
		errIs error // for soft, when the error is certain
	}{
		{name: "the catch-all's alert", serve: func(c *net.TCPConn) {
			if _, err := probeReadRecord(c); err == nil {
				_, _ = c.Write(probeAlert)
			}
		}, wait: probeAnswerWait, class: ClassOK, first: recordAlert},
		{name: "a TLS server's ServerHello", serve: func(c *net.TCPConn) {
			_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
		}, wait: probeAnswerWait, class: ClassOK, first: recordHandshake},
		{name: "plain HTTP on :443", serve: func(c *net.TCPConn) {
			if _, err := probeReadRecord(c); err == nil {
				_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
			}
		}, wait: probeAnswerWait, class: ClassNotTLS, first: 'H'},
		{name: "a protocol that speaks first", serve: func(c *net.TCPConn) {
			_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n")
			_, _ = io.Copy(io.Discard, c)
		}, wait: probeAnswerWait, class: ClassNotTLS, first: 'S'},
		{name: "accept and silence", serve: func(c *net.TCPConn) {
			_, _ = io.Copy(io.Discard, c)
		}, wait: probeSilenceWait, class: ClassSoft, errIs: os.ErrDeadlineExceeded},
		{name: "accept, read the hello, close", serve: func(c *net.TCPConn) {
			_, _ = probeReadRecord(c)
		}, wait: probeAnswerWait, class: ClassSoft},
		{name: "accept and close at once", serve: func(c *net.TCPConn) {},
			wait: probeAnswerWait, class: ClassSoft},
		{name: "a reset before any byte", serve: func(c *net.TCPConn) {
			_, _ = probeReadRecord(c)
			_ = c.SetLinger(0)
		}, wait: probeAnswerWait, class: ClassSoft},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probeFamilies(t, func(t *testing.T, addr netip.Addr) {
				port := probeServe(t, addr, tc.serve)
				r := Prober{Port: port, FirstByteTimeout: tc.wait}.Probe(context.Background(), addr)
				if r.Class != tc.class {
					t.Fatalf("class = %v (%+v), want %v", r.Class, r, tc.class)
				}
				if tc.class == ClassSoft {
					if r.HasFirst || r.Err == nil {
						t.Fatalf("soft result %+v: want no byte and the error behind it", r)
					}
					if tc.errIs != nil && !errors.Is(r.Err, tc.errIs) {
						t.Fatalf("soft for %v, want %v", r.Err, tc.errIs)
					}
					return
				}
				if !r.HasFirst || r.First != tc.first || r.Err != nil {
					t.Fatalf("result %+v: want first byte %#x and no error", r, tc.first)
				}
			})
		})
	}
}

func TestProbeClosedPortIsRefused(t *testing.T) {
	probeFamilies(t, func(t *testing.T, addr netip.Addr) {
		r := Prober{Port: probeClosed(t, addr)}.Probe(context.Background(), addr)
		if r.Class != ClassRefused || !errors.Is(r.Err, syscall.ECONNREFUSED) || r.HasFirst {
			t.Fatalf("closed port: %+v, want refused, with ECONNREFUSED", r)
		}
	})
}

// The probe cannot look when this process is out of descriptors: that is
// blind, and never a refusal — not on a closed port, and not when the failure
// carries ECONNREFUSED itself.
func TestProbeControlFailureIsBlindNeverRefused(t *testing.T) {
	probeFamilies(t, func(t *testing.T, addr netip.Addr) {
		ports := map[string]uint16{
			"closed port": probeClosed(t, addr),
			"listener":    probeServe(t, addr, func(c *net.TCPConn) { _, _ = c.Write(probeAlert) }),
		}
		for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ECONNREFUSED} {
			for what, port := range ports {
				p := Prober{Port: port, Control: func(context.Context, string, string, syscall.RawConn) error { return errno }}
				r := p.Probe(context.Background(), addr)
				if r.Class != ClassBlind || !errors.Is(r.Err, errno) {
					t.Errorf("%s, Control fails with %v: %+v, want blind", what, errno, r)
				}
			}
		}
	})
}

// A failed connect is classed by the system call that failed and its errno,
// as the net package reports them.
func TestProbeDialClass(t *testing.T) {
	dial := func(call string, errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp4", Err: os.NewSyscallError(call, errno)}
	}
	for _, tc := range []struct {
		name    string
		err     error
		control bool
		want    Class
	}{
		{"connect refused", dial("connect", syscall.ECONNREFUSED), false, ClassRefused},
		{"connect out of descriptors", dial("connect", syscall.EMFILE), false, ClassBlind},
		{"connect, the system out of files", dial("connect", syscall.ENFILE), false, ClassBlind},
		{"connect out of buffers", dial("connect", syscall.ENOBUFS), false, ClassBlind},
		{"connect out of ports", dial("connect", syscall.EADDRINUSE), false, ClassBlind},
		{"connect without a source", dial("connect", syscall.EADDRNOTAVAIL), false, ClassBlind},
		{"socket out of descriptors", dial("socket", syscall.EMFILE), false, ClassBlind},
		{"bind: the address is gone", dial("bind", syscall.EADDRNOTAVAIL), false, ClassBlind},
		{"setsockopt", dial("setsockopt", syscall.EINVAL), false, ClassBlind},
		{"getsockopt after connect", dial("getsockopt", syscall.EBADF), false, ClassBlind},
		{"a refusal from socket()", dial("socket", syscall.ECONNREFUSED), false, ClassBlind},
		{"a refusal from bind()", dial("bind", syscall.ECONNREFUSED), false, ClassBlind},
		{"Control's refusal", dial("connect", syscall.ECONNREFUSED), true, ClassBlind},
		{"Control's failure", errors.New("injected"), true, ClassBlind},
		{"a refusal not from connect()", syscall.ECONNREFUSED, false, ClassSoft},
		{"connect timed out", dial("connect", syscall.ETIMEDOUT), false, ClassSoft},
		{"connect reset", dial("connect", syscall.ECONNRESET), false, ClassSoft},
		{"host unreachable", dial("connect", syscall.EHOSTUNREACH), false, ClassSoft},
		{"network unreachable", dial("connect", syscall.ENETUNREACH), false, ClassSoft},
		{"a local firewall's drop", dial("connect", syscall.EPERM), false, ClassSoft},
		{"the dial deadline", &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, false, ClassSoft},
		{"ctx ended", &net.OpError{Op: "dial", Err: context.Canceled}, false, ClassSoft},
	} {
		if got := probeDialClass(tc.err, tc.control); got != tc.want {
			t.Errorf("%s: %v (Control failed: %v) is %v, want %v", tc.name, tc.err, tc.control, got, tc.want)
		}
	}
}

// A VIP the kernel dropped between the /proc read and the probe: bind() refuses
// the source, so the probe is blind — never refused, and never answered by
// whichever box the network routes the VIP to now.
func TestProbeAnAddressTheKernelDoesNotHoldIsBlind(t *testing.T) {
	gone := netip.MustParseAddr("192.0.2.1") // TEST-NET-1: nobody's address
	r := Prober{Port: probeClosed(t, probeV4)}.Probe(context.Background(), gone)
	if r.Class == ClassBlind && errors.Is(r.Err, syscall.EADDRNOTAVAIL) {
		return
	}
	if probeNonlocalBind() && r.Class == ClassSoft {
		return // ip_nonlocal_bind=1 let the bind through; the SYN left, unanswered
	}
	t.Fatalf("probe from an address this host does not hold: %+v, want blind (EADDRNOTAVAIL)", r)
}

func probeNonlocalBind() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_nonlocal_bind")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// The IPv6 sibling. On Linux the source is bound with IP_FREEBIND, so the
// bind of an address nobody holds goes through; the SYN finds no route, or
// leaves carrying that address as its source, and nothing answers it here:
// soft. Elsewhere the bind refuses it: blind. Never ok, never refused.
func TestProbeAnIPv6AddressTheKernelDoesNotHoldIsNeverAnswered(t *testing.T) {
	port := probeClosed(t, probeV6)              // skips a host without IPv6
	gone := netip.MustParseAddr("2001:db8:9::9") // the documentation prefix: nobody's
	r := Prober{Port: port, ConnectTimeout: 200 * time.Millisecond}.Probe(context.Background(), gone)
	want := ClassBlind
	if runtime.GOOS == "linux" {
		want = ClassSoft
	}
	if r.Class != want || r.HasFirst {
		t.Fatalf("probe from an IPv6 address this host does not hold: %+v, want %v", r, want)
	}
}

// The source is bound to the probed address. On Linux all of 127.0.0.0/8 is
// local, and the kernel would pick 127.0.0.1 as the source for 127.0.0.2, so a
// listener that sees 127.0.0.2 shows the bind. Hosts without 127.0.0.2 skip.
func TestProbeSourceIsTheProbedAddress(t *testing.T) {
	addr := netip.MustParseAddr("127.0.0.2")
	ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)))
	if err != nil {
		t.Skipf("127.0.0.2 is not local on this host: %v", err)
	}
	from := make(chan netip.Addr, 1)
	port := probeServeOn(t, ln, func(c *net.TCPConn) {
		from <- c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
		if _, err := probeReadRecord(c); err == nil {
			_, _ = c.Write(probeAlert)
		}
	})
	if r := (Prober{Port: port, FirstByteTimeout: probeAnswerWait}).Probe(context.Background(), addr); r.Class != ClassOK {
		t.Fatalf("probe: %+v, want ok", r)
	}
	if src := <-from; src != addr {
		t.Fatalf("the listener saw the probe from %v, want %v", src, addr)
	}
}

// The probe writes one TLS handshake record — a ClientHello naming ProbeSNI —
// and nothing else: no HTTP, ever.
func TestProbeWritesOnlyAClientHelloNamingTheProbeSNI(t *testing.T) {
	sent := make(chan []byte, 1)
	port := probeServe(t, probeV4, func(c *net.TCPConn) {
		b, _ := io.ReadAll(c) // all the probe writes, until it closes
		sent <- b
	})
	r := Prober{Port: port, FirstByteTimeout: probeSilenceWait}.Probe(context.Background(), probeV4)
	if r.Class != ClassSoft {
		t.Fatalf("silent listener: %+v, want soft", r)
	}
	var b []byte
	select {
	case b = <-sent:
	case <-time.After(10 * time.Second):
		t.Fatal("the listener never saw the probe close")
	}
	if len(b) < 6 || b[0] != recordHandshake || int(b[3])<<8|int(b[4]) != len(b)-5 {
		t.Fatalf("the probe wrote %d bytes (% x…), want exactly one handshake record", len(b), b[:min(len(b), 8)])
	}
	if b[5] != 1 { // HandshakeType client_hello
		t.Fatalf("the probe's record holds handshake message %d, want a ClientHello", b[5])
	}
	if !bytes.Contains(b, []byte(ProbeSNI)) {
		t.Fatalf("the ClientHello does not carry the server name %q", ProbeSNI)
	}
}

// A real TLS server sees ProbeSNI, answers with its ServerHello — ok — and
// never completes the handshake: the probe leaves no session in any cache.
func TestProbeNeverCompletesAHandshake(t *testing.T) {
	cert := probeCert(t, time.Now().Add(time.Hour), "zone.example")
	sni := make(chan string, 1)
	done := make(chan error, 1)
	cfg := &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sni <- h.ServerName
		return &cert, nil
	}}
	port := probeServe(t, probeV4, func(c *net.TCPConn) { done <- tls.Server(c, cfg).Handshake() })
	r := Prober{Port: port, FirstByteTimeout: probeAnswerWait}.Probe(context.Background(), probeV4)
	if r.Class != ClassOK || r.First != recordHandshake {
		t.Fatalf("TLS server: %+v, want ok on a handshake record", r)
	}
	if got := <-sni; got != ProbeSNI {
		t.Fatalf("the server saw the name %q, want %q", got, ProbeSNI)
	}
	if err := <-done; err == nil {
		t.Fatal("the server completed a handshake with the probe")
	}
}

func TestProbeContextBoundsTheAttempt(t *testing.T) {
	port := probeServe(t, probeV4, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := Prober{Port: port, FirstByteTimeout: time.Minute}.Probe(ctx, probeV4)
	if r.Class != ClassSoft || !errors.Is(r.Err, context.DeadlineExceeded) {
		t.Fatalf("ctx ended: %+v, want soft with the context's error", r)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the probe outlived its context by %v", took)
	}
}

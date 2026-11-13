package steer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// probeTLS serves TLS on addr:0 with the certificate cert returns for each
// ClientHello's name (an error refuses the handshake with an alert), and
// reports each name it is asked for.
func probeTLS(t *testing.T, addr netip.Addr, cert func(sni string) (*tls.Certificate, error)) (uint16, <-chan string) {
	t.Helper()
	asked := make(chan string, 16)
	cfg := &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		select {
		case asked <- h.ServerName:
		default:
		}
		return cert(h.ServerName)
	}}
	port := probeServe(t, addr, func(c *net.TCPConn) {
		tc := tls.Server(c, cfg)
		if tc.Handshake() == nil {
			_, _ = io.Copy(io.Discard, tc) // until the client's close_notify
		}
	})
	return port, asked
}

// probeTLSWith serves one certificate whatever the name asked.
func probeTLSWith(t *testing.T, cert tls.Certificate) (uint16, <-chan string) {
	t.Helper()
	return probeTLS(t, probeV4, func(string) (*tls.Certificate, error) { return &cert, nil })
}

func TestHandshakePassesWhenTheLeafNamesTheZone(t *testing.T) {
	probeFamilies(t, func(t *testing.T, addr netip.Addr) {
		cert := probeCert(t, time.Now().Add(time.Hour), "a.example")
		port, asked := probeTLS(t, addr, func(string) (*tls.Certificate, error) { return &cert, nil })
		if err := (Prober{Port: port}).Handshake(context.Background(), addr, "a.example"); err != nil {
			t.Fatalf("Handshake = %v, want nil", err)
		}
		if got := <-asked; got != "a.example" {
			t.Fatalf("the terminator was asked for %q, want the zone", got)
		}
	})
}

// The name is all the exit test checks: an expired, self-signed or wildcard
// certificate that names the zone passes — the chain and the dates are the
// CA's and the renewal's business, never a reason to keep a node out.
func TestHandshakeChecksTheNameOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		zone string
	}{
		{"expired", probeCert(t, time.Now().Add(-24*time.Hour), "a.example"), "a.example"},
		{"wildcard", probeCert(t, time.Now().Add(time.Hour), "*.example.com"), "a.example.com"},
		{"one of several names", probeCert(t, time.Now().Add(time.Hour), "b.example", "a.example"), "a.example"},
	} {
		port, _ := probeTLSWith(t, tc.cert)
		if err := (Prober{Port: port}).Handshake(context.Background(), probeV4, tc.zone); err != nil {
			t.Errorf("%s certificate: Handshake(%s) = %v, want nil", tc.name, tc.zone, err)
		}
	}
}

func TestHandshakeOtherNameIsErrNotNamed(t *testing.T) {
	port, _ := probeTLSWith(t, probeCert(t, time.Now().Add(time.Hour), "b.example"))
	err := Prober{Port: port}.Handshake(context.Background(), probeV4, "a.example")
	var hostname x509.HostnameError
	if !errors.Is(err, ErrNotNamed) || !errors.As(err, &hostname) {
		t.Fatalf("Handshake = %v, want ErrNotNamed wrapping the x509 hostname error", err)
	}
}

// A handshake that does not complete says nothing about the certificate:
// it is an error, and not ErrNotNamed.
func TestHandshakeFailureIsNotErrNotNamed(t *testing.T) {
	refusing, _ := probeTLS(t, probeV4, func(string) (*tls.Certificate, error) {
		return nil, errors.New("no certificate for this name")
	})
	catchAll := probeServe(t, probeV4, func(c *net.TCPConn) {
		if _, err := probeReadRecord(c); err == nil {
			_, _ = c.Write(probeAlert)
		}
	})
	for what, port := range map[string]uint16{
		"a terminator without the zone's certificate": refusing,
		"the catch-all's alert":                       catchAll,
		"a closed port":                               probeClosed(t, probeV4),
	} {
		err := Prober{Port: port}.Handshake(context.Background(), probeV4, "a.example")
		if err == nil || errors.Is(err, ErrNotNamed) {
			t.Errorf("%s: Handshake = %v, want an error that is not ErrNotNamed", what, err)
		}
	}
	if err := (Prober{Port: probeClosed(t, probeV4)}).Handshake(context.Background(), probeV4, "a.example"); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("closed port: Handshake = %v, want the connect's ECONNREFUSED", err)
	}
}

func TestHandshakeTimesOut(t *testing.T) {
	port := probeServe(t, probeV4, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })
	start := time.Now()
	err := Prober{Port: port, HandshakeTimeout: 200 * time.Millisecond}.Handshake(context.Background(), probeV4, "a.example")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent terminator: Handshake = %v, want the timeout", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the handshake outlived its timeout by %v", took)
	}
}

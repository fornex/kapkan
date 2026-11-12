package steer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"
)

const (
	// ProbeSNI is the name the probe's ClientHello carries. .invalid is
	// reserved (RFC 2606): no zone can ever be called that, so the attempt
	// always ends at the catch-all, which refuses it with an alert before any
	// session or HTTP exists.
	ProbeSNI = "kapkan-steer.invalid"
	// DefaultPort is what every target is probed on: the port every zone is
	// served from.
	DefaultPort = 443
	// DefaultConnectTimeout bounds the TCP connect. A SYN dropped by a full
	// accept queue times out here — soft, never refused.
	DefaultConnectTimeout = 300 * time.Millisecond
	// DefaultFirstByteTimeout bounds the wait for the answer's first byte
	// once the ClientHello is written.
	DefaultFirstByteTimeout = 600 * time.Millisecond
	// DefaultHandshakeTimeout bounds one whole join handshake.
	DefaultHandshakeTimeout = 2 * time.Second
	// DefaultJoinRetry spaces the join handshakes of a zone that has not
	// passed yet.
	DefaultJoinRetry = 10 * time.Second

	// The TLS record types a TLS server answers a ClientHello with.
	recordAlert     = 0x15
	recordHandshake = 0x16
)

// ErrNotNamed is the join handshake's failure when the leaf certificate the
// terminator served does not name the zone asked for.
var ErrNotNamed = errors.New("steer: the leaf certificate does not name the zone")

// errProbeAnswered is what the probe's connection hands crypto/tls in place
// of the answer's bytes: it ends the handshake at the server's first record.
var errProbeAnswered = errors.New("steer: the probe stops at the answer's first byte")

// Prober makes the steering probe and the join handshake. The zero value is
// the production probe; the fields exist for tests.
type Prober struct {
	// Port is the probed port; 0 means DefaultPort. Tests point it at their
	// own listeners.
	Port uint16
	// ConnectTimeout, FirstByteTimeout and HandshakeTimeout: 0 means the
	// defaults (300 ms, 600 ms, 2 s).
	ConnectTimeout, FirstByteTimeout, HandshakeTimeout time.Duration
	// Control, when set, runs on every socket the Prober opens, before its
	// bind and connect (net.Dialer.ControlContext): the seam through which a
	// test injects EMFILE and its kin. Nil on a node.
	Control func(ctx context.Context, network, address string, c syscall.RawConn) error
}

// Result is one probe attempt.
type Result struct {
	Class Class
	// First is the answer's first byte; HasFirst says one arrived (ClassOK
	// and ClassNotTLS always have one).
	First    byte
	HasFirst bool
	// Err is what made the class: the connect error behind ClassRefused and
	// ClassBlind, the timeout, EOF or reset behind ClassSoft; nil for ClassOK
	// and ClassNotTLS.
	Err error
}

// Probe makes one attempt at addr: a TCP connect from addr (the source is
// bound to it, port 0) to addr:Port within ConnectTimeout, a TLS ClientHello
// naming ProbeSNI, and one read for the answer's first byte within
// FirstByteTimeout. Then it closes: it never completes a handshake, so it
// never makes a session in the terminator's cache, and it never sends a byte
// of HTTP.
//
// Classes, in the order they are decided:
//
//   - the socket, the bind or Control failed, or the connect returned EMFILE,
//     ENFILE, ENOBUFS, EADDRINUSE or EADDRNOTAVAIL: ClassBlind — decided
//     first, so it is never ClassRefused, whatever the error wraps;
//   - the connect itself returned ECONNREFUSED: ClassRefused (whether that is
//     a trigger is Observation.Triggers' business, after the listener table);
//   - any other failure before a byte arrived — a connect or first-byte
//     timeout, EOF, a reset, an unreachable, ctx ending: ClassSoft;
//   - a first byte 0x15 or 0x16: ClassOK; any other first byte: ClassNotTLS.
//
// ctx bounds the whole attempt on top of the two timeouts.
//
// The ClientHello is crypto/tls's own, written through a connection whose
// first read that returns data keeps the first byte and fails: the handshake
// dies on the server's first record and goes no further. A catch-all answers
// with a 7-byte alert and closes; that one read (crypto/tls offers it at
// least 512 bytes) normally takes the alert whole, so the probe's close is a
// FIN after the server's, with nothing for the terminator to log above info.
func (p Prober) Probe(ctx context.Context, addr netip.Addr) Result {
	conn, controlFailed, err := p.dial(ctx, addr.Unmap())
	if err != nil {
		return Result{Class: probeDialClass(err, controlFailed), Err: err}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(probeDuration(p.FirstByteTimeout, DefaultFirstByteTimeout)))

	answer := &probeFirstByte{Conn: conn}
	err = tls.Client(answer, probeHello()).HandshakeContext(ctx)
	if !answer.has {
		return Result{Class: ClassSoft, Err: err}
	}
	r := Result{Class: ClassNotTLS, First: answer.first, HasFirst: true}
	if answer.first == recordAlert || answer.first == recordHandshake {
		r.Class = ClassOK
	}
	return r
}

// probeHello is the probe's TLS configuration. It names ProbeSNI and offers
// X25519 and P-256 only, so the ClientHello is a few hundred bytes instead of
// one that carries a post-quantum key share; P-256 keeps it valid where
// fips140=only removes X25519. No certificate is ever verified: the handshake
// never gets that far.
func probeHello() *tls.Config {
	return &tls.Config{
		ServerName:       ProbeSNI,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// probeFirstByte is the probe's connection as crypto/tls sees it: writes go
// through — the ClientHello — and the first read that returns data keeps its
// first byte and fails, so no byte of the answer ever reaches the handshake.
type probeFirstByte struct {
	net.Conn
	first byte
	has   bool
}

func (c *probeFirstByte) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n == 0 {
		return 0, err
	}
	if !c.has {
		c.first, c.has = b[0], true
	}
	return 0, errProbeAnswered
}

// dial connects from addr to addr:Port within ConnectTimeout, running Control
// on the socket; controlFailed reports that the error is Control's own.
func (p Prober) dial(ctx context.Context, addr netip.Addr) (conn net.Conn, controlFailed bool, err error) {
	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	d := net.Dialer{
		// The source is the target address itself, so the SYN goes from a
		// local address to a local address and never leaves lo. Should the
		// kernel have dropped the address since /proc listed it, bind()
		// refuses (EADDRNOTAVAIL: blind); and under ip_nonlocal_bind=1 a SYN
		// that does leave carries the VIP as its source, which another node
		// holding the VIP drops as a martian — so no other node can answer
		// for this one.
		LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)),
		Timeout:   probeDuration(p.ConnectTimeout, DefaultConnectTimeout),
		// The connection lives under a second; keepalive is a wasted syscall.
		KeepAlive: -1,
	}
	if p.Control != nil {
		d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			err := p.Control(ctx, network, address, c)
			controlFailed = err != nil
			return err
		}
	}
	conn, err = d.DialContext(ctx, network, netip.AddrPortFrom(addr, p.port()).String())
	return conn, controlFailed, err
}

// probeDialClass classes a failed connect. A refusal is the connect system
// call itself returning ECONNREFUSED, and nothing else. A failure of this
// process or its own stack — Control, socket(), setsockopt(), bind(), or a
// connect that ran out of descriptors, buffers or ports — is ClassBlind
// whatever the error wraps, so neither an injected nor a real EMFILE can ever
// read as a refusal. The rest — a timeout, ctx ending, an unreachable, a reset,
// a local firewall's EPERM — is ClassSoft.
func probeDialClass(err error, controlFailed bool) Class {
	if controlFailed {
		return ClassBlind
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.EADDRINUSE, syscall.EADDRNOTAVAIL:
			return ClassBlind
		}
	}
	var sc *os.SyscallError
	if !errors.As(err, &sc) {
		return ClassSoft
	}
	switch {
	case sc.Syscall != "connect":
		return ClassBlind
	case errors.Is(sc.Err, syscall.ECONNREFUSED):
		return ClassRefused
	}
	return ClassSoft
}

func (p Prober) port() uint16 {
	if p.Port == 0 {
		return DefaultPort
	}
	return p.Port
}

// probeDuration is d, or def when d is not positive.
func probeDuration(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Handshake makes one TLS handshake with sni to addr:Port, from addr, within
// HandshakeTimeout, and checks one thing: that the leaf certificate names sni
// (x509.Certificate.VerifyHostname) — no chain, no dates, no revocation.
// It is the new-node drain's exit test (D7) and nothing else: it completes a
// handshake, and a completed handshake is an entry in the shared kapkan_ssl
// session cache, which is why the steady-state Probe never does (D4). It
// returns nil when the leaf names sni, ErrNotNamed (errors.Is) when it does
// not, and the connect or handshake error otherwise.
func (p Prober) Handshake(ctx context.Context, addr netip.Addr, sni string) error {
	ctx, cancel := context.WithTimeout(ctx, probeDuration(p.HandshakeTimeout, DefaultHandshakeTimeout))
	defer cancel()
	conn, _, err := p.dial(ctx, addr.Unmap())
	if err != nil {
		return err
	}
	// The chain and the dates are skipped on purpose: they are the CA's and
	// the renewal's business, and a terminator that serves an expired or
	// self-signed certificate for the zone still serves the zone. What the
	// exit test needs to know is that the zone's own server answered.
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = tc.Close() }()
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("%w: no certificate was shown", ErrNotNamed)
	}
	if err := certs[0].VerifyHostname(sni); err != nil {
		return fmt.Errorf("%w: %w", ErrNotNamed, err)
	}
	return nil
}

// Kernel is what Observe asks the kernel: whether it holds an address, and —
// only after a refused probe — whether a LISTEN socket on the probed port
// covers it. *Tick (proc.go) is the real one, reading each /proc table at
// most once per tick; tests fake it.
type Kernel interface {
	Local(addr netip.Addr) Tri
	Listening(addr netip.Addr) Tri
}

// Observe makes one tick's observation of t, in the order the trigger rules
// need: the kernel is asked whether it holds the address, an address it does
// not hold (TriNo) or cannot say about (TriUnknown) is not probed, a held one
// is probed once, and only a ClassRefused asks k.Listening. A VIP target's
// observation is its address's: Local, Probe, Listening, and ProbeErr from
// the Result.
//
// The node target (NodeTarget) is never Unbound: a loopback address the
// kernel does not hold is skipped, not reported, and its addresses are probed
// concurrently. Its observation is one of its addresses' — an ok one if any
// answered TLS; else the first, when every probed address is hard (its
// Triggers would fire); else the first that is neither — and with no address
// left it is Observation{} (unknown: hold).
func (p Prober) Observe(ctx context.Context, k Kernel, t Target) Observation {
	if t.Key == NodeKey {
		return p.observeNode(ctx, k, t.Addrs)
	}
	if len(t.Addrs) == 0 {
		return Observation{}
	}
	return p.observeAddr(ctx, k, t.Addrs[0])
}

// observeAddr is one address's observation: the kernel first, the probe only
// on an address it holds, the listener table only after a refusal — the
// table lists every socket on the box, and is read on no other tick.
func (p Prober) observeAddr(ctx context.Context, k Kernel, addr netip.Addr) Observation {
	o := Observation{Local: k.Local(addr)}
	if o.Local != TriYes {
		return o
	}
	r := p.Probe(ctx, addr)
	o.Probe = r.Class
	if r.Err != nil {
		o.ProbeErr = r.Err.Error()
	}
	if r.Class == ClassRefused {
		o.Listening = k.Listening(addr)
	}
	return o
}

func (p Prober) observeNode(ctx context.Context, k Kernel, addrs []netip.Addr) Observation {
	obs := make([]Observation, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Go(func() { obs[i] = p.observeAddr(ctx, k, addr) })
	}
	wg.Wait()
	return probeMerge(obs)
}

// probeMerge is the node target's observation from its addresses'. One the
// kernel does not hold is dropped: the node's loopback addresses are not the
// operator's to lose, and a box without ::1 still serves on 127.0.0.1. Of
// the rest, the best wins — the node serves while any of them does: an ok
// one; else, when every one is hard, the first; else the first that is
// neither, which holds. Nothing left is Observation{}, which holds too.
func probeMerge(obs []Observation) Observation {
	var probed []Observation
	for _, o := range obs {
		if o.Local == TriYes {
			probed = append(probed, o)
		}
	}
	if len(probed) == 0 {
		return Observation{}
	}
	for _, o := range probed {
		if o.Probe == ClassOK {
			return o
		}
	}
	for _, o := range probed {
		if !o.Triggers(false).Hard() {
			return o
		}
	}
	return probed[0]
}

// FirstEntry is where the new-node drain's exit test stands (D7): the drain
// may lift once the live document names at least one zone, and every one of
// them has a :443 server in the live render and has passed its one join
// handshake.
type FirstEntry struct {
	// Zones is the number of zones in the live document; Ready how many of
	// them meet both conditions — "N of M zones with a certificate" in E7.2's
	// `-s undrain` refusal.
	Zones, Ready int
	// Missing names the zones not yet ready, sorted, for the log and the
	// report.
	Missing []string
}

// Done reports whether the new-node drain may lift.
func (f FirstEntry) Done() bool { return f.Zones > 0 && f.Ready == f.Zones }

// Joiner runs the new-node drain's join handshakes and remembers their
// outcome, so each zone is handshaken until it passes and never again: the
// steady state completes no handshake at all (D4). The account is in memory
// only — a restart under the new-node drain handshakes each zone once more,
// which costs a few cache entries. Not safe for concurrent use: the sampler
// calls it.
type Joiner struct {
	// Handshake makes one join handshake for a zone: on a node, a Prober's
	// Handshake bound to the target address the caller picks (the first local
	// VIP, or 127.0.0.1). Nil passes no zone.
	Handshake func(ctx context.Context, sni string) error
	// Retry spaces the attempts at one zone that has not passed; 0 means
	// DefaultJoinRetry.
	Retry time.Duration

	passed map[string]bool
	tried  map[string]time.Time
}

// Check handshakes — one at a time, each zone at most once per Retry — the
// zones of zones that are in tlsZones and have not passed, until ctx ends,
// and reports the exit test: zones are the live document's, tlsZones those
// with a :443 server in the live render (E7.2's render.Info.TLSZones). A zone
// outside tlsZones has no certificate rendered and is not handshaken; a zone
// in tlsZones but not in zones does not count. Passed zones stay passed for
// the Joiner's life. A name listed twice in zones counts once.
func (j *Joiner) Check(ctx context.Context, zones, tlsZones []string, now time.Time) FirstEntry {
	if j.passed == nil {
		j.passed = make(map[string]bool)
		j.tried = make(map[string]time.Time)
	}
	rendered := make(map[string]bool, len(tlsZones))
	for _, z := range tlsZones {
		rendered[z] = true
	}
	zones = slices.Compact(slices.Sorted(slices.Values(zones)))
	f := FirstEntry{Zones: len(zones)}
	for _, z := range zones {
		if rendered[z] && !j.passed[z] && j.due(z, now) && ctx.Err() == nil && j.Handshake != nil {
			j.tried[z] = now
			j.passed[z] = j.Handshake(ctx, z) == nil
		}
		if rendered[z] && j.passed[z] {
			f.Ready++
		} else {
			f.Missing = append(f.Missing, z)
		}
	}
	return f
}

// due reports whether zone may be handshaken at now: never tried, tried at
// least Retry ago, or "tried" in what is now the future — a clock that
// stepped back must not park a zone until it catches up.
func (j *Joiner) due(zone string, now time.Time) bool {
	last, ok := j.tried[zone]
	return !ok || now.Sub(last) >= probeDuration(j.Retry, DefaultJoinRetry) || now.Before(last)
}

package mitigate

// A configured BGP neighbor is the one party that writes bytes straight into
// the brain's gobgp FSM. These tests stand in for that neighbor with a peer
// written by hand rather than a second gobgp, for two reasons: the peer can send
// what no BGP implementation would, and the bytes on the wire are fixed here
// rather than by the library under test.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// BGP message types (RFC 4271 §4.1).
const (
	bgpMsgOpen         = 1
	bgpMsgUpdate       = 2
	bgpMsgNotification = 3
	bgpMsgKeepalive    = 4
)

func bgpMsgName(typ byte) string {
	switch typ {
	case bgpMsgOpen:
		return "OPEN"
	case bgpMsgUpdate:
		return "UPDATE"
	case bgpMsgNotification:
		return "NOTIFICATION"
	case bgpMsgKeepalive:
		return "KEEPALIVE"
	}
	return "type " + strconv.Itoa(int(typ))
}

// brainHelperEnv carries the test peer's port to the re-executed test binary
// (see TestBGPBrainHelperProcess). Its presence is what turns that function
// from a skip into the brain.
const brainHelperEnv = "KAPKAN_TEST_BGP_BRAIN_PEER_PORT"

// TestBGPSurvivesUnknownMessageType is the regression test for a crash in
// gobgp v3.37.0. A neighbor sends a well-formed BGP header whose type no RFC
// defines; gobgp's parseBody returns a nil message, handlingError dereferences
// it, and the panic, raised in a gobgp goroutine with no recover, ends the
// whole brain process. Any configured neighbor could do that with 19 bytes,
// through a firmware bug or a compromised router, and the DDoS mitigation then
// died exactly when it might be needed.
//
// RFC 4271 §6.1 wants a NOTIFICATION instead: Message Header Error, Bad Message
// Type. The test asserts that, then that the process is still up, then that
// the speaker dials back in. It covers each state in which the brain reads a
// neighbor's message, because the fault sat in the read path they share.
//
// The brain runs in a SUBPROCESS: this test binary re-executed as
// TestBGPBrainHelperProcess. A panic then kills the child, and this test fails
// with the child's panic in its output, instead of the panic killing the test
// binary and every test in it.
func TestBGPSurvivesUnknownMessageType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in -short mode")
	}
	for _, tc := range []struct {
		state string
		reach func(p *testPeer, brain *brainProcess)
	}{
		{"OpenSent", reachOpenSent},
		{"OpenConfirm", reachOpenConfirm},
		{"Established", reachEstablished},
	} {
		t.Run(tc.state, func(t *testing.T) {
			t.Parallel()
			// A well-formed header: all-ones marker, a length that matches
			// what follows (nothing), and a type that does not exist.
			assertBrainSurvives(t, tc.reach, bgpMessage(200, nil),
				bgpNotification{1, 3, "Message Header Error / Bad Message Type"})
		})
	}
}

// TestBGPSurvivesMalformedNextHop replays the UPDATE published with gobgp
// issue #3305 (GO-2026-4736, CVE-2026-30405): a NEXT_HOP two octets long
// where RFC 4271 §5.1.3 fixes four, then one octet of a truncated attribute.
// gobgp handles the attribute error by treating the UPDATE as a withdraw, as
// RFC 7606 §7.3 asks and as it does by default. gobgp v4 before 4.4.0 then
// validated the UPDATE with the malformed attribute still in it and panicked;
// v3 validates only the withdraw it rewrote the UPDATE into, so v3.37.0
// survives this message too. The brain must stay up and keep the session: the
// UPDATE is withdrawn, the session is not reset.
func TestBGPSurvivesMalformedNextHop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in -short mode")
	}
	ln := listenPeer(t)
	brain := startBrainProcess(t, ln.Addr().(*net.TCPAddr).Port)
	p := acceptPeer(t, ln, brain)
	reachEstablished(p, brain)

	p.send(bgpMessage(bgpMsgUpdate, []byte{
		0x00, 0x00, // withdrawn routes length
		0x00, 0x0d, // total path attribute length: 13
		0x40, 0x01, 0x01, 0x02, // ORIGIN: INCOMPLETE
		0x40, 0x02, 0x00, // AS_PATH: empty
		0x40, 0x03, 0x02, 0x01, 0x02, // NEXT_HOP, length 2
		0x01,                   // the first octet of an attribute that never arrives
		0x18, 0xc0, 0xa8, 0x01, // NLRI: 192.168.1.0/24
	}))
	brain.waitLog(t, "treated as withdraw")

	// The session holds: neither a NOTIFICATION nor a close follows.
	for deadline := time.Now().Add(2 * time.Second); ; {
		typ, body, err := p.read(deadline)
		if errors.Is(err, errReadTimeout) {
			break
		}
		if err != nil {
			p.lost("watching the session after the malformed UPDATE", err)
		}
		if typ != bgpMsgKeepalive {
			t.Fatalf("after the malformed UPDATE the speaker sent its %s: % x", bgpMsgName(typ), body)
		}
	}
	brain.requireAlive(t, "after the malformed UPDATE")
	out := brain.out.String()
	if after := out[strings.Index(out, "treated as withdraw"):]; strings.Contains(after, "bgp peer state") {
		t.Errorf("the session changed state after the malformed UPDATE; RFC 7606 treat-as-withdraw keeps it\n%s",
			brain.tail())
	}
}

// bgpNotification is the NOTIFICATION a test expects the speaker to send.
type bgpNotification struct {
	code, subcode byte
	name          string
}

// assertBrainSurvives starts a brain in a child process, drives its session
// with the test peer up to a state (reach), sends msg, and asserts the outcome
// RFC 4271 asks for: the expected NOTIFICATION, then a session reset that
// leaves the process up and the neighbor configured, so the speaker dials back
// in.
func assertBrainSurvives(t *testing.T, reach func(*testPeer, *brainProcess), msg []byte, want bgpNotification) {
	t.Helper()
	ln := listenPeer(t)
	brain := startBrainProcess(t, ln.Addr().(*net.TCPAddr).Port)

	p := acceptPeer(t, ln, brain)
	reach(p, brain)
	p.send(msg)

	body := p.expect(bgpMsgNotification)
	if len(body) < 2 || body[0] != want.code || body[1] != want.subcode {
		t.Errorf("NOTIFICATION = % x, want code %d subcode %d (%s)", body, want.code, want.subcode, want.name)
	}
	brain.requireAlive(t, "after the test peer's message")

	p = acceptPeer(t, ln, brain)
	p.expect(bgpMsgOpen)
	brain.requireAlive(t, "after the speaker dialed back in")
}

// reachOpenSent, reachOpenConfirm and reachEstablished drive the handshake up
// to the state each is named after: the states in which the brain reads what
// a neighbor sends.
func reachOpenSent(p *testPeer, _ *brainProcess) {
	p.expect(bgpMsgOpen)
}

func reachOpenConfirm(p *testPeer, brain *brainProcess) {
	reachOpenSent(p, brain)
	p.send(testPeerOpen())
	p.expect(bgpMsgKeepalive)
}

func reachEstablished(p *testPeer, brain *brainProcess) {
	reachOpenConfirm(p, brain)
	p.send(bgpMessage(bgpMsgKeepalive, nil))
	brain.waitLog(p.t, "state=ESTABLISHED")
}

// TestBGPBrainHelperProcess is not a test. assertBrainSurvives re-executes the
// test binary with brainHelperEnv set, and this function then runs the brain's
// BGP speaker, peered with that test's hand-written neighbor, until stdin
// closes. It has to be another process: when gobgp panics, the panic must end
// this child, not the test that is watching for it.
func TestBGPBrainHelperProcess(t *testing.T) {
	port := os.Getenv(brainHelperEnv)
	if port == "" {
		t.Skip("helper process for the TestBGPSurvives tests; runs only when one of them starts it")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatalf("%s=%q: %v", brainHelperEnv, port, err)
	}
	m, err := New(storeFrom(t, bgpYAML(uint32(p))), slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("mitigator Start: %v", err)
	}
	defer m.Stop()
	// The parent closes stdin when it is done, and so does its death.
	_, _ = io.Copy(io.Discard, os.Stdin)
}

/* --------------------------------------------- where the speaker runs */

// speakerHost is where the speaker under test runs: a child process
// (brainProcess) or this one (inProcess). A test peer whose session breaks
// asks it whether the speaker died.
type speakerHost interface {
	requireAlive(t *testing.T, when string)
	diedWithin(d time.Duration) bool
	tail() string
}

// inProcess hosts a speaker in the test binary itself, where it cannot die
// without taking the test along.
type inProcess struct{}

func (inProcess) requireAlive(*testing.T, string) {}
func (inProcess) diedWithin(time.Duration) bool   { return false }
func (inProcess) tail() string                    { return "" }

// brainProcess is a brain's BGP speaker running in a child process.
type brainProcess struct {
	cmd    *exec.Cmd
	out    *syncBuffer // the child's stdout and stderr: its logs, or its panic
	exited chan struct{}
	err    error // cmd.Wait's result, set before exited is closed
	// reported is set once requireAlive has failed the test over the child's
	// exit, so the cleanup does not quote the same panic a second time.
	reported bool
}

func startBrainProcess(t *testing.T, peerPort int) *brainProcess {
	t.Helper()
	b := &brainProcess{out: &syncBuffer{}, exited: make(chan struct{})}
	b.cmd = exec.Command(os.Args[0], "-test.run=^TestBGPBrainHelperProcess$", "-test.v")
	b.cmd.Env = append(os.Environ(), brainHelperEnv+"="+strconv.Itoa(peerPort))
	b.cmd.Stdout, b.cmd.Stderr = b.out, b.out
	stdin, err := b.cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := b.cmd.Start(); err != nil {
		t.Fatalf("start the brain process: %v", err)
	}
	go func() { b.err = b.cmd.Wait(); close(b.exited) }()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-b.exited:
			if b.err != nil && !b.reported {
				t.Errorf("the brain process did not exit cleanly: %v\n%s", b.err, b.tail())
			}
		case <-time.After(15 * time.Second):
			_ = b.cmd.Process.Kill()
			<-b.exited
			t.Errorf("the brain process did not stop within 15s of stdin closing\n%s", b.tail())
		}
	})
	return b
}

// requireAlive fails the test if the child has exited, quoting its output,
// which for a crash is gobgp's panic.
func (b *brainProcess) requireAlive(t *testing.T, when string) {
	t.Helper()
	select {
	case <-b.exited:
		b.reported = true
		t.Fatalf("the brain process died %s: %v\n%s", when, b.err, b.tail())
	default:
	}
}

// diedWithin reports whether the child exits within d. A peer that loses its
// connection asks this first: a crash closes the socket a moment before the
// process is reaped.
func (b *brainProcess) diedWithin(d time.Duration) bool {
	select {
	case <-b.exited:
		return true
	case <-time.After(d):
		return false
	}
}

// waitLog waits for the child to log a line containing substr.
func (b *brainProcess) waitLog(t *testing.T, substr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(b.out.String(), substr) {
		b.requireAlive(t, "waiting for "+strconv.Quote(substr)+" in its log")
		if time.Now().After(deadline) {
			t.Fatalf("the brain never logged %q\n%s", substr, b.tail())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// tail is the child's output from its panic on, or its last lines when there
// is none, capped so a goroutine dump stays readable.
func (b *brainProcess) tail() string {
	out := b.out.String()
	if i := strings.Index(out, "panic:"); i >= 0 {
		out = out[i:]
	} else if lines := strings.Split(out, "\n"); len(lines) > 40 {
		out = strings.Join(lines[len(lines)-40:], "\n")
	}
	const limit = 6 << 10
	if len(out) > limit {
		out = out[:limit] + "\n…"
	}
	return "--- brain process output ---\n" + out
}

// syncBuffer is a bytes.Buffer the exec package can write while a test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

/* -------------------------------------------------------------- the peer */

// testPeer is the router's side of one TCP session with the brain.
type testPeer struct {
	t    *testing.T
	host speakerHost
	conn net.Conn
}

// listenPeer opens the test peer's listening socket on an ephemeral loopback
// port; the speaker under test is configured to dial it.
func listenPeer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// acceptPeer waits for the speaker to dial the test peer listening on ln.
func acceptPeer(t *testing.T, ln net.Listener, host speakerHost) *testPeer {
	t.Helper()
	tl := ln.(*net.TCPListener)
	deadline := time.Now().Add(30 * time.Second)
	for {
		host.requireAlive(t, "waiting for the speaker to dial the test peer")
		if time.Now().After(deadline) {
			t.Fatalf("the speaker never dialed the test peer\n%s", host.tail())
		}
		_ = tl.SetDeadline(time.Now().Add(250 * time.Millisecond))
		conn, err := tl.Accept()
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return &testPeer{t: t, host: host, conn: conn}
	}
}

func (p *testPeer) send(msg []byte) {
	p.t.Helper()
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.conn.Write(msg); err != nil {
		p.lost("writing to it", err)
	}
}

// expect reads until a message of type want arrives and returns its body.
// KEEPALIVEs and UPDATEs the speaker sends on its own (End-of-RIB) are
// skipped; anything else is a failure.
func (p *testPeer) expect(want byte) []byte {
	p.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		typ, body, err := p.read(deadline)
		if err != nil {
			p.lost("waiting for its "+bgpMsgName(want), err)
		}
		switch typ {
		case want:
			return body
		case bgpMsgKeepalive, bgpMsgUpdate:
			continue
		default:
			p.t.Fatalf("waiting for the speaker's %s, got its %s: % x", bgpMsgName(want), bgpMsgName(typ), body)
		}
	}
}

// next returns the speaker's next message other than a KEEPALIVE, whose
// timing belongs to the hold timer rather than to anything a test did.
func (p *testPeer) next(within time.Duration) (byte, []byte) {
	p.t.Helper()
	deadline := time.Now().Add(within)
	for {
		typ, body, err := p.read(deadline)
		if err != nil {
			p.lost("waiting for its next message", err)
		}
		if typ != bgpMsgKeepalive {
			return typ, body
		}
	}
}

// read reads one message, checking liveness between short read slices so a
// dead child is reported as soon as it dies, not after the deadline.
func (p *testPeer) read(deadline time.Time) (byte, []byte, error) {
	var hdr [19]byte
	if err := p.readFull(hdr[:], deadline); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(hdr[:16], bytes.Repeat([]byte{0xff}, 16)) {
		p.t.Fatalf("the speaker sent a header without the all-ones marker: % x", hdr)
	}
	n := int(binary.BigEndian.Uint16(hdr[16:18]))
	if n < len(hdr) || n > 4096 {
		p.t.Fatalf("the speaker sent a message of length %d", n)
	}
	body := make([]byte, n-len(hdr))
	if err := p.readFull(body, deadline); err != nil {
		return 0, nil, err
	}
	return hdr[18], body, nil
}

// errReadTimeout is what read returns when its deadline passes first.
var errReadTimeout = errors.New("timed out")

func (p *testPeer) readFull(buf []byte, deadline time.Time) error {
	for got := 0; got < len(buf); {
		p.host.requireAlive(p.t, "while the test peer was reading from it")
		if time.Now().After(deadline) {
			return errReadTimeout
		}
		_ = p.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, err := p.conn.Read(buf[got:])
		got += n
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		if err != nil && got < len(buf) {
			return err
		}
	}
	return nil
}

// lost reports a session that broke under the test peer: the brain's death
// when that is what broke it, a plain failure otherwise.
func (p *testPeer) lost(doing string, err error) {
	p.t.Helper()
	if p.host.diedWithin(3 * time.Second) {
		p.host.requireAlive(p.t, "and dropped the session while the test peer was "+doing)
	}
	p.t.Fatalf("session lost while %s: %v\n%s", doing, err, p.host.tail())
}

// bgpMessage frames body as a BGP message of type typ (RFC 4271 §4.1).
func bgpMessage(typ byte, body []byte) []byte {
	m := append(bytes.Repeat([]byte{0xff}, 16), 0, 0, typ)
	binary.BigEndian.PutUint16(m[16:18], uint16(19+len(body)))
	return append(m, body...)
}

// bgpOpen builds an OPEN from AS asn with hold time 90 s and BGP identifier
// 2.2.2.2, carrying caps (already encoded) in one Capabilities parameter.
func bgpOpen(asn uint16, caps []byte) []byte {
	params := append([]byte{2, byte(len(caps))}, caps...)
	body := []byte{4, byte(asn >> 8), byte(asn), 0, 90, 2, 2, 2, 2, byte(len(params))}
	return bgpMessage(bgpMsgOpen, append(body, params...))
}

// testPeerOpen is the test peer's OPEN, matching the neighbor bgpYAML
// configures (AS 65000), with the Multiprotocol (IPv4 unicast) and 4-octet AS
// capabilities.
func testPeerOpen() []byte {
	return bgpOpen(65000, []byte{
		1, 4, 0, 1, 0, 1, // Multiprotocol: AFI 1, reserved, SAFI 1
		65, 4, 0, 0, 0xfd, 0xe8, // 4-octet AS: 65000
	})
}

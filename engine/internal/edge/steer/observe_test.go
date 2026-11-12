package steer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/fstest"
	"time"
)

// probeKernel is a Kernel whose answers the test sets; it counts the listener
// lookups. Its maps are only read, so concurrent observations may share it.
type probeKernel struct {
	local     map[netip.Addr]Tri
	listening map[netip.Addr]Tri
	asked     atomic.Int32
}

func (k *probeKernel) Local(addr netip.Addr) Tri { return k.local[addr] }

func (k *probeKernel) Listening(addr netip.Addr) Tri {
	k.asked.Add(1)
	return k.listening[addr]
}

// probeCounting is a Prober on port whose Control counts the sockets it opens.
func probeCounting(port uint16, dials *atomic.Int32) Prober {
	return Prober{Port: port, FirstByteTimeout: probeAnswerWait, Control: func(context.Context, string, string, syscall.RawConn) error {
		dials.Add(1)
		return nil
	}}
}

func probeAnswering(t *testing.T, addr netip.Addr) uint16 {
	t.Helper()
	return probeServe(t, addr, func(c *net.TCPConn) {
		if _, err := probeReadRecord(c); err == nil {
			_, _ = c.Write(probeAlert)
		}
	})
}

// An address the kernel does not hold is Unbound and never probed; one it
// cannot say about is not probed either, and triggers nothing.
func TestObserveProbesOnlyWhatTheKernelHolds(t *testing.T) {
	port := probeAnswering(t, probeV4)
	for _, tc := range []struct {
		local Tri
		dials int32
		want  Triggers
	}{
		{TriNo, 0, Triggers{Unbound: true}},
		{TriUnknown, 0, Triggers{}},
		{TriYes, 1, Triggers{}},
	} {
		var dials atomic.Int32
		k := &probeKernel{local: map[netip.Addr]Tri{probeV4: tc.local}}
		o := probeCounting(port, &dials).Observe(context.Background(), k, VIPTarget(probeV4))
		if dials.Load() != tc.dials || o.Local != tc.local || o.Triggers(false) != tc.want {
			t.Errorf("Local %v: %+v after %d dials, want %d dials and triggers %+v", tc.local, o, dials.Load(), tc.dials, tc.want)
		}
		if tc.local != TriYes && o != (Observation{Local: tc.local}) {
			t.Errorf("Local %v: %+v, want nothing but the kernel's answer", tc.local, o)
		}
	}
}

// The listener table is read only after a refusal: it lists every socket on
// the box, and only a refusal needs it.
func TestObserveAsksForListenersOnlyAfterARefusal(t *testing.T) {
	silent := probeServe(t, probeV4, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })
	for _, tc := range []struct {
		name      string
		port      uint16
		listening Tri
		asked     int32
		class     Class
		want      Triggers
	}{
		{"ok", probeAnswering(t, probeV4), TriNo, 0, ClassOK, Triggers{}},
		{"soft", silent, TriNo, 0, ClassSoft, Triggers{}},
		{"refused, nothing listening", probeClosed(t, probeV4), TriNo, 1, ClassRefused, Triggers{Refused: true}},
		{"refused, a listener behind it", probeClosed(t, probeV4), TriYes, 1, ClassRefused, Triggers{}},
		{"refused, the table unread", probeClosed(t, probeV4), TriUnknown, 1, ClassRefused, Triggers{}},
	} {
		k := &probeKernel{
			local:     map[netip.Addr]Tri{probeV4: TriYes},
			listening: map[netip.Addr]Tri{probeV4: tc.listening},
		}
		p := Prober{Port: tc.port, FirstByteTimeout: probeSilenceWait}
		if tc.class != ClassSoft {
			p.FirstByteTimeout = probeAnswerWait
		}
		o := p.Observe(context.Background(), k, VIPTarget(probeV4))
		if o.Probe != tc.class || k.asked.Load() != tc.asked || o.Triggers(false) != tc.want {
			t.Errorf("%s: %+v, %d listener lookups; want class %v, %d lookups, triggers %+v", tc.name, o, k.asked.Load(), tc.class, tc.asked, tc.want)
		}
		if tc.asked == 0 && o.Listening != TriUnknown {
			t.Errorf("%s: Listening = %v without a lookup, want unknown", tc.name, o.Listening)
		}
		if (tc.class == ClassOK) != (o.ProbeErr == "") {
			t.Errorf("%s: ProbeErr %q", tc.name, o.ProbeErr)
		}
	}
}

// The refusal rule end to end — a real closed port, observed through a Tick
// over a /proc fixture. A refusal is Refused only when the listener table
// shows nothing on the port that covers the address. A listener there means
// something else refused the connection — a firewall's REJECT, which a unit
// test cannot install and the table stands in for — and an unreadable table
// means unknown: neither withdraws.
func TestObserveRefusalNeedsAnEmptyListenerTable(t *testing.T) {
	port := probeClosed(t, probeV4)
	other := netip.AddrPortFrom(probeV4, port+1).String()
	for _, tc := range []struct {
		name    string
		tcp     []byte // nil: net/tcp is missing
		tcp6    []byte
		refused bool
		listen  Tri
	}{
		{"nothing listens", procTCP(false), procTCP(true), true, TriNo},
		{"nothing listens on the port", procTCP(false, procSock{other, procListen}), procTCP(true), true, TriNo},
		{"a listener on 10.0.0.5 only", procTCP(false, procSock{netip.AddrPortFrom(procAddr("10.0.0.5"), port).String(), procListen}), procTCP(true), true, TriNo},
		{"only a connection on the port", procTCP(false, procSock{netip.AddrPortFrom(probeV4, port).String(), 0x01}), procTCP(true), true, TriNo},
		{"a listener on the address", procTCP(false, procSock{netip.AddrPortFrom(probeV4, port).String(), procListen}), procTCP(true), false, TriYes},
		{"a listener on 0.0.0.0", procTCP(false, procSock{netip.AddrPortFrom(netip.IPv4Unspecified(), port).String(), procListen}), procTCP(true), false, TriYes},
		{"a listener on [::]", procTCP(false), procTCP(true, procSock{netip.AddrPortFrom(netip.IPv6Unspecified(), port).String(), procListen}), false, TriYes},
		{"net/tcp unreadable", nil, procTCP(true), false, TriUnknown},
	} {
		fsys := procFixture(t)
		if tc.tcp != nil {
			fsys["net/tcp"] = &fstest.MapFile{Data: tc.tcp}
		}
		fsys["net/tcp6"] = &fstest.MapFile{Data: tc.tcp6}
		tick := Proc{FS: fsys}.Tick(port)
		o := Prober{Port: port}.Observe(context.Background(), tick, VIPTarget(probeV4))
		if o.Local != TriYes || o.Probe != ClassRefused || o.Listening != tc.listen {
			t.Errorf("%s: %+v, want a held address, refused, listening %v", tc.name, o, tc.listen)
			continue
		}
		if got := o.Triggers(false); got != (Triggers{Refused: tc.refused}) {
			t.Errorf("%s: triggers %+v, want Refused %v", tc.name, got, tc.refused)
		}
	}
}

// Without a /proc — a darwin host — nothing is held, so nothing is probed and
// nothing triggers, whatever listens.
func TestObserveWithoutProcHolds(t *testing.T) {
	port := probeClosed(t, probeV4)
	tick := Proc{FS: fstest.MapFS{}}.Tick(port)
	var dials atomic.Int32
	for _, target := range []Target{VIPTarget(probeV4), NodeTarget(true)} {
		o := probeCounting(port, &dials).Observe(context.Background(), tick, target)
		if o.Triggers(false) != (Triggers{}) || o.Probe != ClassNone {
			t.Errorf("%s without /proc: %+v, want no probe and no trigger", target.Key, o)
		}
	}
	if dials.Load() != 0 {
		t.Errorf("%d probes without /proc, want none", dials.Load())
	}
}

// The node target is the best of its loopback addresses, and never Unbound.
func TestObserveNodeTarget(t *testing.T) {
	ok := probeAnswering(t, probeV4)
	for _, tc := range []struct {
		name  string
		local map[netip.Addr]Tri
		want  Observation
	}{
		{"::1 not held: skipped, not Unbound",
			map[netip.Addr]Tri{probeV4: TriYes, probeV6: TriNo},
			Observation{Local: TriYes, Probe: ClassOK}},
		{"neither held",
			map[netip.Addr]Tri{probeV4: TriNo, probeV6: TriNo},
			Observation{}},
		{"nothing known",
			map[netip.Addr]Tri{},
			Observation{}},
	} {
		k := &probeKernel{local: tc.local}
		o := Prober{Port: ok, FirstByteTimeout: probeAnswerWait}.Observe(context.Background(), k, NodeTarget(true))
		if o != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, o, tc.want)
		}
		if o.Triggers(false).Unbound {
			t.Errorf("%s: the node target is Unbound", tc.name)
		}
	}
}

// The node target's addresses are probed at once, not one after the other:
// each probe's Control waits until both have started.
func TestObserveNodeTargetProbesConcurrently(t *testing.T) {
	port := probeAnswering(t, probeV4)
	_ = probeListen(t, probeV6).Close() // skips a host without ::1
	var started sync.WaitGroup
	started.Add(2)
	both := make(chan struct{})
	go func() { started.Wait(); close(both) }()
	p := Prober{Port: port, FirstByteTimeout: probeAnswerWait, Control: func(context.Context, string, string, syscall.RawConn) error {
		started.Done()
		select {
		case <-both:
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("the other address was never probed alongside")
		}
	}}
	k := &probeKernel{local: map[netip.Addr]Tri{probeV4: TriYes, probeV6: TriYes}}
	o := p.Observe(context.Background(), k, NodeTarget(true))
	if o.Probe != ClassOK {
		t.Fatalf("node target: %+v, want 127.0.0.1's ok", o)
	}
}

// The merge, on its own: an ok wins; hard only when every probed address is
// hard; otherwise the first that is neither; an address the kernel does not
// hold is dropped.
func TestObserveMerge(t *testing.T) {
	var (
		ok      = Observation{Local: TriYes, Probe: ClassOK}
		hard    = Observation{Local: TriYes, Probe: ClassRefused, Listening: TriNo, ProbeErr: "first"}
		hard2   = Observation{Local: TriYes, Probe: ClassNotTLS, ProbeErr: "second"}
		held    = Observation{Local: TriYes, Probe: ClassRefused, Listening: TriYes}
		soft    = Observation{Local: TriYes, Probe: ClassSoft}
		blind   = Observation{Local: TriYes, Probe: ClassBlind}
		notHeld = Observation{Local: TriNo}
		unknown = Observation{Local: TriUnknown}
	)
	for _, tc := range []struct {
		name string
		in   []Observation
		want Observation
	}{
		{"ok and hard", []Observation{hard, ok}, ok},
		{"hard and ok", []Observation{ok, hard}, ok},
		{"both hard", []Observation{hard, hard2}, hard},
		{"hard and soft", []Observation{hard, soft}, soft},
		{"hard and blind", []Observation{hard, blind}, blind},
		{"a refusal with a listener, then hard", []Observation{held, hard}, held},
		{"hard and not held", []Observation{hard, notHeld}, hard},
		{"not held and unknown", []Observation{notHeld, unknown}, Observation{}},
		{"none", nil, Observation{}},
	} {
		if got := probeMerge(tc.in); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

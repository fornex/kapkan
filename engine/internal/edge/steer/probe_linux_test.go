//go:build linux

package steer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// An IPv6 probe socket is freebind, so that a VIP in an AnyIP range can be the
// source; an IPv4 one is not, so that its bind still refuses an address the
// kernel dropped. Control runs after the Prober's own option and reads it
// back. No privilege is needed.
func TestProbeSetsFreebindOnIPv6SocketsOnly(t *testing.T) {
	probeFamilies(t, func(t *testing.T, addr netip.Addr) {
		port := probeServe(t, addr, func(c *net.TCPConn) {
			if _, err := probeReadRecord(c); err == nil {
				_, _ = c.Write(probeAlert)
			}
		})
		freebind := -1
		p := Prober{Port: port, FirstByteTimeout: probeAnswerWait, Control: func(_ context.Context, _, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				freebind, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND)
			}); err != nil {
				return err
			}
			return serr
		}}
		if r := p.Probe(context.Background(), addr); r.Class != ClassOK {
			t.Fatalf("probe: %+v, want ok", r)
		}
		want := 0
		if addr.Is6() {
			want = 1
		}
		if freebind != want {
			t.Fatalf("IP_FREEBIND on the %s socket = %d, want %d", probeNetwork(addr), freebind, want)
		}
	})
}

// probeNetnsVar names the variable that lets the AnyIP test change lo's
// addresses and routes. Set it only in a throwaway network namespace — a
// container with NET_ADMIN — never on a host whose routes matter.
const probeNetnsVar = "KAPKAN_STEER_NETNS"

// probeNetns runs each `ip` command, and its undo at the end of the test. It
// skips the test unless probeNetnsVar is 1.
func probeNetns(t *testing.T, cmds ...[2]string) {
	t.Helper()
	if os.Getenv(probeNetnsVar) != "1" {
		t.Skipf("set %s=1 in a throwaway network namespace with NET_ADMIN: this test adds addresses and routes to lo", probeNetnsVar)
	}
	for _, c := range cmds {
		if out, err := exec.Command("ip", strings.Fields(c[0])...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", c[0], err, out)
		}
		t.Cleanup(func() { _ = exec.Command("ip", strings.Fields(c[1])...).Run() })
	}
}

// An AnyIP range — a local route, on no interface — on Linux: /proc reads
// it held, and the probe can look at it from itself. An IPv6 VIP there is
// probed ok, refused when nothing listens, and passes the join handshake; the
// IPv4 range, whose bind needs no option, is the control. An interface's
// address is in the interface list, an AnyIP address is not.
func TestProbeAnyIPRangesFromThemselves(t *testing.T) {
	probeNetns(t,
		[2]string{"-6 route add local 2001:db8:77::/64 dev lo", "-6 route del local 2001:db8:77::/64 dev lo"},
		[2]string{"route add local 198.51.100.0/24 dev lo", "route del local 198.51.100.0/24 dev lo"},
		[2]string{"addr add 192.0.2.77/32 dev lo", "addr del 192.0.2.77/32 dev lo"},
	)
	vip6, vip4, iface := procAddr("2001:db8:77::10"), procAddr("198.51.100.10"), procAddr("192.0.2.77")

	listed, err := procIfaddrs4()
	if err != nil || !slices.Contains(listed, iface) || slices.Contains(listed, vip4) {
		t.Fatalf("procIfaddrs4 = %v (%v), want 192.0.2.77 and not the AnyIP 198.51.100.10", listed, err)
	}
	tick := HostProc().Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{
		"2001:db8:77::10": TriYes, "198.51.100.10": TriYes, "192.0.2.77": TriYes,
		"2001:db8:78::1": TriNo, "198.51.101.10": TriNo,
	})

	ln, err := net.Listen("tcp", "[::]:0") // dual-stack, as `listen [::]:443` renders
	if err != nil {
		t.Fatal(err)
	}
	cert := probeCert(t, time.Now().Add(time.Hour), "a.example")
	port := probeServeOn(t, ln.(*net.TCPListener), func(c *net.TCPConn) {
		_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	})
	for _, vip := range []netip.Addr{vip6, vip4} {
		if r := (Prober{Port: port, FirstByteTimeout: probeAnswerWait}).Probe(context.Background(), vip); r.Class != ClassOK {
			t.Errorf("probe of %v: %+v, want ok", vip, r)
		}
	}
	if err := (Prober{Port: port}).Handshake(context.Background(), vip6, "a.example"); err != nil {
		t.Errorf("Handshake from %v = %v, want nil", vip6, err)
	}

	closed := probeClosed(t, probeV6)
	o := Prober{Port: closed}.Observe(context.Background(), HostProc().Tick(context.Background(), closed), VIPTarget(vip6))
	if o.Local != TriYes || o.Probe != ClassRefused || o.Listening != TriNo || !o.Triggers(false).Refused {
		t.Errorf("%v with nothing listening: %+v, want held, refused, no listener: Refused", vip6, o)
	}
	if r := (Prober{Port: closed}).Probe(context.Background(), vip6); !errors.Is(r.Err, syscall.ECONNREFUSED) {
		t.Errorf("probe of %v on a closed port: %+v, want ECONNREFUSED", vip6, r)
	}
}

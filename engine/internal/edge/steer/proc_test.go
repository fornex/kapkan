package steer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

// procFixture is a /proc tree of testdata/proc's files plus "self", which marks
// it as a live process table. Tests add, replace and delete entries.
func procFixture(t *testing.T) fstest.MapFS {
	t.Helper()
	fsys := fstest.MapFS{"self": &fstest.MapFile{Mode: fs.ModeDir | 0o555}}
	root := os.DirFS("testdata/proc")
	err := fs.WalkDir(root, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(root, name)
		fsys[name] = &fstest.MapFile{Data: data}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

// procSock is one socket of a generated net/tcp or net/tcp6.
type procSock struct {
	local string // its local address and port, as netip.AddrPort text
	st    byte   // its state: procListen, 0x01 established, 0x06 time-wait
}

// procTCP writes net/tcp (v6 false) or net/tcp6 as this host's kernel writes
// it: each 32-bit word of the network-order address, read in the host's byte
// order, printed %08X — so the tests hold on either endianness.
func procTCP(v6 bool, socks ...procSock) []byte {
	var b strings.Builder
	if v6 {
		b.WriteString("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	} else {
		b.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	}
	for i, s := range socks {
		local := netip.MustParseAddrPort(s.local)
		raw := local.Addr().AsSlice()
		var words strings.Builder
		for w := 0; w < len(raw); w += 4 {
			fmt.Fprintf(&words, "%08X", binary.NativeEndian.Uint32(raw[w:]))
		}
		fmt.Fprintf(&b, "%4d: %s:%04X %s:0000 %02X 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
			i, words.String(), local.Port(), strings.Repeat("0", 2*len(raw)), s.st, 40000+i)
	}
	return []byte(b.String())
}

// procCountFS counts the opens of each file. A name in fail fails to open with
// that error; a name in failRead opens, hands over all its lines, and then
// fails where its end would be — a read cut short, whose lines must not count.
type procCountFS struct {
	fs.FS
	fail, failRead map[string]error

	mu    sync.Mutex
	opens map[string]int
}

func (c *procCountFS) Open(name string) (fs.File, error) {
	c.mu.Lock()
	if c.opens == nil {
		c.opens = make(map[string]int)
	}
	c.opens[name]++
	c.mu.Unlock()
	if err := c.fail[name]; err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	f, err := c.FS.Open(name)
	if err != nil || c.failRead[name] == nil {
		return f, err
	}
	return procFailingFile{File: f, err: c.failRead[name]}, nil
}

func (c *procCountFS) opened(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opens[name]
}

type procFailingFile struct {
	fs.File
	err error
}

func (f procFailingFile) Read(b []byte) (int, error) {
	n, err := f.File.Read(b)
	if err == io.EOF {
		return n, f.err
	}
	return n, err
}

func procAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// procExpect checks Has for every address of want.
func procExpect(t *testing.T, l Locals, want map[string]Tri) {
	t.Helper()
	for addr, tri := range want {
		if got := l.Has(procAddr(addr)); got != tri {
			t.Errorf("Has(%s) = %v, want %v", addr, got, tri)
		}
	}
}

func TestProcLocalsReadsTheKernelsTables(t *testing.T) {
	l, err := Proc{FS: procFixture(t)}.Locals()
	if err != nil {
		t.Fatalf("Locals: %v", err)
	}
	for _, tc := range []struct {
		addr string
		want Tri
		why  string
	}{
		{"127.0.0.1", TriYes, "lo's own /32"},
		{"127.1.2.3", TriYes, "127.0.0.0/8 is LOCAL as a whole"},
		{"10.0.0.5", TriYes, "eth0's address"},
		{"10.0.0.1", TriNo, "a link route is not a local one"},
		{"10.0.0.255", TriNo, "a BROADCAST entry is not LOCAL"},
		{"192.0.2.10", TriYes, "the VIP on lo"},
		{"192.0.2.11", TriNo, "the VIP's neighbour"},
		{"198.51.100.77", TriYes, "an AnyIP /24 covers its whole range"},
		{"203.0.113.7", TriYes, "a LOCAL route in table 100 counts"},
		{"203.0.113.8", TriNo, "a unicast route in table 100 does not"},
		{"8.8.8.8", TriNo, "the default route is not local"},
		{"::ffff:192.0.2.10", TriYes, "an IPv4-mapped address is the IPv4 address"},
		{"::1", TriYes, "lo"},
		{"2001:db8::10", TriYes, "the IPv6 VIP on lo"},
		{"2001:db8::11", TriNo, "neither listed nor routed locally"},
		{"2001:db8:1::5", TriYes, "eth0's address"},
		{"2001:db8:1::6", TriNo, "tentative counts as absent, and it has no local route yet"},
		{"2001:db8:1::7", TriNo, "dadfailed counts as absent, and it has no local route"},
		{"2001:db8:1::8", TriYes, "deprecated still receives"},
		{"2001:db8:1::9", TriYes, "optimistic: listed tentative, but given its local route already"},
		{"2001:db8:2::a", TriYes, "listed tentative, but inside an AnyIP range"},
		{"2001:db8:2::ffff", TriYes, "an AnyIP /64 covers its whole range"},
		{"2001:db8:1::", TriNo, "the subnet-router anycast route is not RTF_LOCAL"},
		{"2001:db8:3::1", TriNo, "unknown to both files"},
		{"fe80::20c:29ff:fe8a:3c5d", TriYes, "a link-local address"},
	} {
		if got := l.Has(procAddr(tc.addr)); got != tc.want {
			t.Errorf("Has(%s) = %v, want %v: %s", tc.addr, got, tc.want, tc.why)
		}
	}
	if got := l.Has(netip.Addr{}); got != TriUnknown {
		t.Errorf("Has(the zero Addr) = %v, want unknown", got)
	}
}

// A kernel booted with ipv6.disable=1 has neither IPv6 file, and holds no IPv6
// address: that is an answer, not an error. One disabled by sysctl has both,
// empty.
func TestProcLocalsWithoutIPv6(t *testing.T) {
	booted := procFixture(t)
	delete(booted, "net/if_inet6")
	delete(booted, "net/ipv6_route")
	sysctl := procFixture(t)
	sysctl["net/if_inet6"] = &fstest.MapFile{}
	sysctl["net/ipv6_route"] = &fstest.MapFile{}
	for name, fsys := range map[string]fstest.MapFS{"ipv6.disable=1": booted, "disable_ipv6=1": sysctl} {
		l, err := Proc{FS: fsys}.Locals()
		if err != nil {
			t.Errorf("%s: Locals: %v", name, err)
			continue
		}
		for _, addr := range []string{"::1", "2001:db8::10", "2001:db8:2::ffff"} {
			if got := l.Has(procAddr(addr)); got != TriNo {
				t.Errorf("%s: Has(%s) = %v, want no", name, addr, got)
			}
		}
		if got := l.Has(procAddr("192.0.2.10")); got != TriYes {
			t.Errorf("%s: Has(192.0.2.10) = %v, want yes", name, got)
		}
	}
}

// What a file that could not be read would have told stays unknown — never a
// no, so never Unbound — and the other files still answer.
func TestProcLocalsUnreadableFilesLeaveUnknown(t *testing.T) {
	for _, tc := range []struct {
		name           string
		fail, failRead map[string]error
		want           map[string]Tri
	}{
		{
			name: "no fib_trie",
			fail: map[string]error{"net/fib_trie": fs.ErrNotExist},
			want: map[string]Tri{"127.0.0.1": TriUnknown, "8.8.8.8": TriUnknown, "::1": TriYes, "2001:db8:3::1": TriNo},
		},
		{
			name:     "fib_trie fails mid-read",
			failRead: map[string]error{"net/fib_trie": errors.New("read failed")},
			want:     map[string]Tri{"192.0.2.10": TriUnknown, "192.0.2.11": TriUnknown},
		},
		{
			name: "ipv6_route unreadable",
			fail: map[string]error{"net/ipv6_route": fs.ErrPermission},
			want: map[string]Tri{
				"::1":              TriYes,     // if_inet6 lists it usable
				"2001:db8:2::ffff": TriUnknown, // only an AnyIP route could say yes
				"2001:db8:1::6":    TriUnknown, // tentative: only a route could say yes
				"2001:db8:3::1":    TriUnknown,
				"192.0.2.10":       TriYes,
			},
		},
		{
			name:     "if_inet6 fails mid-read",
			failRead: map[string]error{"net/if_inet6": errors.New("read failed")},
			want: map[string]Tri{
				"2001:db8::10":     TriYes, // its own /128 local route
				"2001:db8:2::ffff": TriYes, // the AnyIP route
				"2001:db8:3::1":    TriUnknown,
			},
		},
		{
			name: "only fib_trie, IPv6 files unreadable rather than absent",
			fail: map[string]error{"net/if_inet6": fs.ErrPermission, "net/ipv6_route": fs.ErrNotExist},
			want: map[string]Tri{"::1": TriUnknown, "192.0.2.10": TriYes},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Proc{FS: &procCountFS{FS: procFixture(t), fail: tc.fail, failRead: tc.failRead}}.Locals()
			if err == nil {
				t.Fatal("Locals returned no error for an unreadable file")
			}
			procExpect(t, l, tc.want)
		})
	}
}

// Where there is no /proc at all — a darwin host — nothing is known: every
// answer is unknown, never a no, and the error says why.
func TestProcWithoutProcKnowsNothing(t *testing.T) {
	for name, p := range map[string]Proc{"an empty tree": {FS: fstest.MapFS{}}, "this host, if not Linux": HostProc()} {
		if name != "an empty tree" && runtime.GOOS == "linux" {
			continue
		}
		l, err := p.Locals()
		if err == nil {
			t.Errorf("%s: Locals returned no error", name)
		}
		ls, lerr := p.Listeners(DefaultPort)
		if lerr == nil {
			t.Errorf("%s: Listeners returned no error", name)
		}
		for _, addr := range []netip.Addr{probeV4, probeV6, procAddr("192.0.2.10")} {
			if got := l.Has(addr); got != TriUnknown {
				t.Errorf("%s: Has(%v) = %v, want unknown", name, addr, got)
			}
			if got := ls.Covers(addr); got != TriUnknown {
				t.Errorf("%s: Covers(%v) = %v, want unknown", name, addr, got)
			}
		}
		if got := p.Process(os.Getpid()); got != (Process{}) {
			t.Errorf("%s: Process(self) = %+v, want unknown", name, got)
		}
	}
}

// Lines the readers do not understand are passed over, and never take a good
// line's meaning away from it.
func TestProcLocalsSkipsMalformedLines(t *testing.T) {
	trie := strings.Join([]string{
		"Main:",
		"garbage at the start of a table",
		"  +-- 0.0.0.0/0 3 0 5",
		"     |-- not-an-address",
		"        /32 host LOCAL",
		"     |-- 192.0.2.20",
		"        /99 host LOCAL",
		"        /x host LOCAL",
		"        /",
		"        /32",
		"        /32 host",
		"     |-- 2001:db8::1",
		"        /128 host LOCAL",
		"  +-- 192.0.2.0/24 2 0 1",
		"        /24 host LOCAL",
		"     |-- 192.0.2.30",
		"        some indented garbage",
		"        /32 host LOCAL",
		"",
	}, "\n")
	inet6 := strings.Join([]string{
		"zz",
		"0000 01 80 10 80 lo",
		"00000000000000000000000000000001 01 80 10 zz lo",
		"2001db800000000000000000000000zz 01 80 00 80 lo",
		"20010db8000000000000000000000020 01 80 00 80 lo",
		"",
	}, "\n")
	route := strings.Join([]string{
		"short line",
		"20010db8000300000000000000000000 zz 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001 lo",
		"20010db8000400000000000000000000 ff 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001 lo",
		"20010db8000500000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 zz lo",
		"",
	}, "\n")
	fsys := fstest.MapFS{
		"net/fib_trie":   {Data: []byte(trie)},
		"net/if_inet6":   {Data: []byte(inet6)},
		"net/ipv6_route": {Data: []byte(route)},
	}
	l, err := Proc{FS: fsys}.Locals()
	if err != nil {
		t.Fatalf("Locals: %v", err)
	}
	procExpect(t, l, map[string]Tri{
		"192.0.2.20":    TriNo,  // only impossible route lines under it
		"192.0.2.30":    TriYes, // garbage between a leaf and its route orphans nothing
		"192.0.2.1":     TriNo,  // a route under an inner node belongs to no leaf
		"::1":           TriNo,  // its flags did not parse
		"2001:db8::1":   TriNo,  // an IPv6 key in fib_trie is not an IPv6 fact
		"2001:db8::20":  TriYes,
		"2001:db8:3::1": TriNo,
		"2001:db8:4::1": TriNo, // prefix length 255
		"2001:db8:5::1": TriNo,
	})
}

func TestProcListenersCoverTheirAddresses(t *testing.T) {
	fsys := procFixture(t)
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false,
		procSock{"127.0.0.1:8080", procListen},
		procSock{"192.0.2.10:443", procListen},
		procSock{"10.0.0.5:443", 0x01},
		procSock{"10.0.0.6:443", 0x06},
	)}
	fsys["net/tcp6"] = &fstest.MapFile{Data: procTCP(true,
		procSock{"[::ffff:198.51.100.9]:443", procListen},
		procSock{"[2001:db8::10]:443", procListen},
		procSock{"[2001:db8::11]:8443", procListen},
	)}
	specific := map[string]Tri{
		"192.0.2.10":        TriYes, // bound to it
		"::ffff:192.0.2.10": TriYes,
		"192.0.2.11":        TriNo,
		"10.0.0.5":          TriNo,  // an established connection on :443 is no listener
		"10.0.0.6":          TriNo,  // nor is one in time-wait
		"127.0.0.1":         TriNo,  // listening, on another port
		"198.51.100.9":      TriYes, // an IPv6 socket bound to the IPv4-mapped address
		"2001:db8::10":      TriYes,
		"2001:db8::11":      TriNo,
	}
	for _, port := range []uint16{443, 0} {
		l, err := Proc{FS: fsys}.Listeners(port)
		if err != nil {
			t.Fatalf("Listeners(%d): %v", port, err)
		}
		for addr, want := range specific {
			if got := l.Covers(procAddr(addr)); got != want {
				t.Errorf("Listeners(%d).Covers(%s) = %v, want %v", port, addr, got, want)
			}
		}
		if got := l.Covers(netip.Addr{}); got != TriUnknown {
			t.Errorf("Covers(the zero Addr) = %v, want unknown", got)
		}
	}

	// The wildcards: 0.0.0.0 covers every IPv4 address and no IPv6 one; ::
	// covers every address — whether it is V6ONLY cannot be read here.
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false, procSock{"0.0.0.0:443", procListen})}
	fsys["net/tcp6"] = &fstest.MapFile{Data: procTCP(true)}
	l, err := Proc{FS: fsys}.Listeners(443)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]Tri{"10.0.0.5": TriYes, "203.0.113.1": TriYes, "2001:db8::99": TriNo} {
		if got := l.Covers(procAddr(addr)); got != want {
			t.Errorf("with 0.0.0.0:443, Covers(%s) = %v, want %v", addr, got, want)
		}
	}
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false)}
	fsys["net/tcp6"] = &fstest.MapFile{Data: procTCP(true, procSock{"[::]:443", procListen})}
	if l, err = (Proc{FS: fsys}).Listeners(443); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"10.0.0.5", "2001:db8::99"} {
		if got := l.Covers(procAddr(addr)); got != TriYes {
			t.Errorf("with [::]:443, Covers(%s) = %v, want yes", addr, got)
		}
	}
}

// The kernel's own text, as a little-endian host prints it.
func TestProcListenersDecodeTheKernelsText(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the literals below are what a little-endian kernel prints")
	}
	fsys := fstest.MapFS{
		"net/tcp": {Data: []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23461 1 0000000000000000 100 0 0 10 0\n")},
		"net/tcp6": {Data: []byte("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23462 1 0000000000000000 100 0 0 10 0\n")},
	}
	l, err := Proc{FS: fsys}.Listeners(443)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]Tri{"127.0.0.1": TriYes, "127.0.0.2": TriNo, "::1": TriYes, "::2": TriNo} {
		if got := l.Covers(procAddr(addr)); got != want {
			t.Errorf("Covers(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestProcListenersUnreadable(t *testing.T) {
	fsys := procFixture(t)
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false)}
	fsys["net/tcp6"] = &fstest.MapFile{Data: procTCP(true)}
	for _, tc := range []struct {
		name           string
		fail, failRead map[string]error
		want           Tri
		wantErr        bool
	}{
		{name: "both read", want: TriNo},
		{name: "no tcp6: a kernel without IPv6", fail: map[string]error{"net/tcp6": fs.ErrNotExist}, want: TriNo},
		{name: "no tcp", fail: map[string]error{"net/tcp": fs.ErrNotExist}, want: TriUnknown, wantErr: true},
		{name: "tcp6 unreadable", fail: map[string]error{"net/tcp6": fs.ErrPermission}, want: TriUnknown, wantErr: true},
		{name: "tcp fails mid-read", failRead: map[string]error{"net/tcp": errors.New("read failed")}, want: TriUnknown, wantErr: true},
	} {
		l, err := Proc{FS: &procCountFS{FS: fsys, fail: tc.fail, failRead: tc.failRead}}.Listeners(443)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: Listeners error = %v, want an error: %v", tc.name, err, tc.wantErr)
		}
		if got := l.Covers(probeV4); got != tc.want {
			t.Errorf("%s: Covers(127.0.0.1) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestProcProcessReadsTheStateLetter(t *testing.T) {
	fsys := procFixture(t)
	for pid, stat := range map[int]string{
		100: "100 (nginx) S 1 100 100 0 -1 4194560 2135 0 0 0 3 2 0 0 20 0 1 0 1840 13680640 1543 18446744073709551615\n",
		101: "101 (nginx) R 1 100 100 0 -1\n",
		102: "102 (nginx) T 1 100 100 0 -1\n",
		103: "103 (nginx) t 1 100 100 0 -1\n",
		104: "104 (nginx) Z 1 100 100 0 -1\n",
		105: "105 (nginx) X 1 100 100 0 -1\n",
		106: "106 (a) (b) D 1 100 100 0 -1\n",
		107: "107 (x) Z (y) S 1 100 100 0 -1\n",
		108: "108 nginx S 1 100 100 0 -1\n",
		109: "109 (nginx)\n",
		110: "",
		111: "111 (nginx) 7 1 100\n",
		112: "112 (nginx) SS 1 100\n",
	} {
		fsys[fmt.Sprintf("%d/stat", pid)] = &fstest.MapFile{Data: []byte(stat)}
	}
	for _, tc := range []struct {
		pid  int
		want Process
		why  string
	}{
		{100, Process{State: PIDAlive}, "sleeping"},
		{101, Process{State: PIDAlive}, "running"},
		{102, Process{State: PIDAlive, Frozen: true}, "stopped (SIGSTOP)"},
		{103, Process{State: PIDAlive, Frozen: true}, "stopped by a tracer"},
		{104, Process{State: PIDAlive, Frozen: true}, "a zombie"},
		{105, Process{State: PIDGone}, "dead"},
		{106, Process{State: PIDAlive}, "a command name holding ') ('"},
		{107, Process{State: PIDAlive}, "a command name holding ') Z (' is no zombie"},
		{108, Process{}, "no parentheses"},
		{109, Process{}, "no state"},
		{110, Process{}, "an empty file"},
		{111, Process{}, "not a state letter"},
		{112, Process{}, "two letters"},
		{999, Process{State: PIDGone}, "no such process"},
		{0, Process{}, "no pid"},
		{-1, Process{}, "a negative pid"},
	} {
		if got := (Proc{FS: fsys}).Process(tc.pid); got != tc.want {
			t.Errorf("Process(%d) = %+v, want %+v: %s", tc.pid, got, tc.want, tc.why)
		}
	}

	// A missing stat is "gone" only in a tree that is a process table.
	delete(fsys, "self")
	if got := (Proc{FS: fsys}).Process(999); got != (Process{}) {
		t.Errorf("Process(999) without self = %+v, want unknown", got)
	}
	unreadable := &procCountFS{FS: procFixture(t), fail: map[string]error{"100/stat": fs.ErrPermission}}
	if got := (Proc{FS: unreadable}).Process(100); got != (Process{}) {
		t.Errorf("Process(100) unreadable = %+v, want unknown", got)
	}
}

// The tick reads each table at most once, the TCP tables only when asked, and
// shares that one reading between every caller.
func TestTickReadsEachTableAtMostOnce(t *testing.T) {
	fsys := procFixture(t)
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false, procSock{"192.0.2.10:443", procListen})}
	fsys["net/tcp6"] = &fstest.MapFile{Data: procTCP(true)}
	c := &procCountFS{FS: fsys}
	tick := Proc{FS: c}.Tick(DefaultPort)
	for range 3 {
		if got := tick.Local(procAddr("192.0.2.10")); got != TriYes {
			t.Fatalf("Local(192.0.2.10) = %v, want yes", got)
		}
	}
	for name, want := range map[string]int{"net/fib_trie": 1, "net/if_inet6": 1, "net/ipv6_route": 1, "net/tcp": 0, "net/tcp6": 0} {
		if got := c.opened(name); got != want {
			t.Errorf("after Local: %s opened %d times, want %d", name, got, want)
		}
	}
	for range 3 {
		if got := tick.Listening(procAddr("192.0.2.10")); got != TriYes {
			t.Fatalf("Listening(192.0.2.10) = %v, want yes", got)
		}
	}
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		if got := c.opened(name); got != 1 {
			t.Errorf("after Listening: %s opened %d times, want once", name, got)
		}
	}
	if err := tick.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

func TestTickIsSafeForConcurrentUse(t *testing.T) {
	fsys := procFixture(t)
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false, procSock{"0.0.0.0:443", procListen})}
	c := &procCountFS{FS: fsys, fail: map[string]error{"net/tcp6": fs.ErrPermission}}
	tick := Proc{FS: c}.Tick(DefaultPort)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_ = tick.Err()
			if got := tick.Local(procAddr("192.0.2.10")); got != TriYes {
				t.Errorf("Local = %v, want yes", got)
			}
			if got := tick.Listening(procAddr("192.0.2.10")); got != TriUnknown {
				t.Errorf("Listening with tcp6 unreadable = %v, want unknown", got)
			}
			_ = tick.Err()
		})
	}
	wg.Wait()
	for _, name := range []string{"net/fib_trie", "net/tcp", "net/tcp6"} {
		if got := c.opened(name); got != 1 {
			t.Errorf("%s opened %d times, want once", name, got)
		}
	}
}

// Err joins the failures of the reads this tick made, and only of those.
func TestTickErrJoinsTheReadsMade(t *testing.T) {
	c := &procCountFS{FS: procFixture(t), fail: map[string]error{"net/tcp": fs.ErrNotExist}}
	tick := Proc{FS: c}.Tick(DefaultPort)
	tick.Local(probeV4)
	if err := tick.Err(); err != nil {
		t.Fatalf("after Local, Err = %v, want nil: the TCP tables were not read", err)
	}
	if got := tick.Listening(probeV4); got != TriUnknown {
		t.Fatalf("Listening without net/tcp = %v, want unknown", got)
	}
	if err := tick.Err(); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "net/tcp") {
		t.Fatalf("after Listening, Err = %v, want the net/tcp failure", err)
	}

	broken := &procCountFS{FS: procFixture(t), fail: map[string]error{"net/fib_trie": fs.ErrPermission}}
	tick = Proc{FS: broken}.Tick(DefaultPort)
	if got := tick.Local(probeV4); got != TriUnknown {
		t.Fatalf("Local without fib_trie = %v, want unknown", got)
	}
	if err := tick.Err(); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Err = %v, want the fib_trie failure", err)
	}
}

// On Linux, the real /proc: this box holds 127.0.0.1, a listener the test
// opens is listed until it closes, and this process is alive.
func TestProcReadsThisLinuxHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is Linux's; TestProcWithoutProcKnowsNothing covers this host")
	}
	p := HostProc()
	l, err := p.Locals()
	if err != nil {
		t.Fatalf("Locals: %v", err)
	}
	if got := l.Has(probeV4); got != TriYes {
		t.Fatalf("Has(127.0.0.1) = %v, want yes", got)
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probePort(ln)
	ls, err := p.Listeners(port)
	if err != nil {
		t.Fatalf("Listeners: %v", err)
	}
	if got := ls.Covers(probeV4); got != TriYes {
		t.Fatalf("with a listener on 127.0.0.1:%d, Covers(127.0.0.1) = %v, want yes", port, got)
	}
	_ = ln.Close()
	if ls, err = p.Listeners(port); err != nil || ls.Covers(probeV4) != TriNo {
		t.Fatalf("after closing it, Covers(127.0.0.1) = %v (%v), want no", ls.Covers(probeV4), err)
	}
	if got := p.Process(os.Getpid()); got != (Process{State: PIDAlive}) {
		t.Fatalf("Process(self) = %+v, want alive", got)
	}
	if got := p.Process(1 << 30); got != (Process{State: PIDGone}) {
		t.Fatalf("Process(1<<30) = %+v, want gone", got)
	}
}

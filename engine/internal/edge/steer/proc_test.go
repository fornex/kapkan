package steer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
)

// procFixture is a /proc tree of testdata/proc's files plus "self" and "1",
// which mark it as a live process table that shows this reader every process.
// Tests add, replace and delete entries. Its net/fib_trie is a real kernel's,
// with an ip rule in place (so the tables are not merged): eth0 is
// 10.0.0.5/24, lo holds the VIP 192.0.2.10/32 and the AnyIP range
// 198.51.100.0/24, and table 100 has 203.0.113.7 LOCAL.
func procFixture(t *testing.T) fstest.MapFS {
	t.Helper()
	fsys := fstest.MapFS{
		"self": &fstest.MapFile{Mode: fs.ModeDir | 0o555},
		"1":    &fstest.MapFile{Mode: fs.ModeDir | 0o555},
	}
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
// A name in seq is served from its successive readings: the n-th open gets
// seq[name][n], or the last one once they run out — a table the kernel
// changed while it was read.
type procCountFS struct {
	fs.FS
	fail, failRead map[string]error
	seq            map[string][]string

	mu    sync.Mutex
	opens map[string]int
}

func (c *procCountFS) Open(name string) (fs.File, error) {
	c.mu.Lock()
	if c.opens == nil {
		c.opens = make(map[string]int)
	}
	n := c.opens[name]
	c.opens[name]++
	c.mu.Unlock()
	if err := c.fail[name]; err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	var f fs.File
	var err error
	if readings, ok := c.seq[name]; ok {
		f, err = fstest.MapFS{name: {Data: []byte(readings[min(n, len(readings)-1)])}}.Open(name)
	} else {
		f, err = c.FS.Open(name)
	}
	if err != nil || c.failRead[name] == nil {
		return f, err
	}
	return procFailingFile{File: f, err: c.failRead[name]}, nil
}

// Stat looks without opening, as os.DirFS does: a stat is not a reading.
func (c *procCountFS) Stat(name string) (fs.FileInfo, error) {
	if err := c.fail[name]; err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	if readings, ok := c.seq[name]; ok {
		return fstest.MapFS{name: {Data: []byte(readings[0])}}.Stat(name)
	}
	return fs.Stat(c.FS, name)
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

// procTickExpect checks Local for every address of want.
func procTickExpect(t *testing.T, tick *Tick, want map[string]Tri) {
	t.Helper()
	for addr, tri := range want {
		if got := tick.Local(procAddr(addr)); got != tri {
			t.Errorf("Local(%s) = %v, want %v", addr, got, tri)
		}
	}
}

// procInterfaces is a Proc.Ifaddrs4 that lists addrs, or fails with err, and
// counts its calls.
type procInterfaces struct {
	addrs []string
	err   error
	calls atomic.Int32
}

func (p *procInterfaces) list() ([]netip.Addr, error) {
	p.calls.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	var addrs []netip.Addr
	for _, a := range p.addrs {
		addrs = append(addrs, procAddr(a))
	}
	return addrs, nil
}

// procFixtureTrie is the fixture's net/fib_trie.
func procFixtureTrie(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/proc/net/fib_trie")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// procRecords splits a fib_trie dump into the records the kernel serves it
// in — a node's line with its route lines, a section's header with its root's
// — and returns the index of the first record of the Local: section.
func procRecords(t *testing.T, trie string) ([]string, int) {
	t.Helper()
	var recs []string
	local, header := -1, false
	for _, line := range strings.SplitAfter(trie, "\n") {
		node := strings.HasPrefix(strings.TrimLeft(line, " "), "+--") || strings.HasPrefix(strings.TrimLeft(line, " "), "|--")
		switch {
		case line == "":
		case strings.HasSuffix(line, ":\n"):
			if line == "Local:\n" {
				local = len(recs)
			}
			recs, header = append(recs, line), true
		case node && header:
			recs[len(recs)-1] += line
			header = false
		case node || len(recs) == 0:
			recs = append(recs, line)
		default:
			recs[len(recs)-1] += line
		}
	}
	if local < 0 {
		t.Fatal("the dump has no Local: section")
	}
	return recs, local
}

// procWithout is trie with the records in [i, j) skipped.
func procWithout(recs []string, i, j int) string {
	return strings.Join(slices.Concat(recs[:i], recs[j:]), "")
}

func TestProcLocalsReadsTheKernelsTables(t *testing.T) {
	l, err := Proc{FS: procFixture(t)}.Locals(context.Background())
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
		{"fe80::20c:29ff:fe8a:3c5d%eth0", TriYes, "a zone is dropped"},
	} {
		if got := l.Has(procAddr(tc.addr)); got != tc.want {
			t.Errorf("Has(%s) = %v, want %v: %s", tc.addr, got, tc.want, tc.why)
		}
	}
	if got := l.Has(netip.Addr{}); got != TriUnknown {
		t.Errorf("Has(the zero Addr) = %v, want unknown", got)
	}
	if got := (Locals{}).Has(procAddr("127.0.0.1")); got != TriUnknown {
		t.Errorf("the zero Locals: Has(127.0.0.1) = %v, want unknown", got)
	}
}

// Without an ip rule the kernel keeps one trie for tables main and local,
// and fib_trie prints it twice, as Main: and as Local:. A real kernel's dump.
func TestProcLocalsReadsAMergedTrie(t *testing.T) {
	trie, err := os.ReadFile("testdata/fib_trie.merged")
	if err != nil {
		t.Fatal(err)
	}
	fsys := procFixture(t)
	fsys["net/fib_trie"] = &fstest.MapFile{Data: trie}
	l, err := Proc{FS: fsys}.Locals(context.Background())
	if err != nil {
		t.Fatalf("Locals: %v", err)
	}
	procExpect(t, l, map[string]Tri{
		"127.0.0.1":     TriYes,
		"10.0.0.5":      TriYes,
		"192.0.2.10":    TriYes,
		"198.51.100.77": TriYes,
		"10.0.0.1":      TriNo,
		"192.0.2.11":    TriNo,
		"8.8.8.8":       TriNo,
	})
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
		l, err := Proc{FS: fsys}.Locals(context.Background())
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
			l, err := Proc{FS: &procCountFS{FS: procFixture(t), fail: tc.fail, failRead: tc.failRead}}.Locals(context.Background())
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
		l, err := p.Locals(context.Background())
		if err == nil {
			t.Errorf("%s: Locals returned no error", name)
		}
		ls, lerr := p.Listeners(context.Background(), DefaultPort)
		if lerr == nil {
			t.Errorf("%s: Listeners returned no error", name)
		}
		tick := p.Tick(context.Background(), DefaultPort)
		for _, addr := range []netip.Addr{probeV4, probeV6, procAddr("192.0.2.10")} {
			if got := l.Has(addr); got != TriUnknown {
				t.Errorf("%s: Has(%v) = %v, want unknown", name, addr, got)
			}
			if got := tick.Local(addr); got != TriUnknown {
				t.Errorf("%s: Tick.Local(%v) = %v, want unknown", name, addr, got)
			}
			if got := ls.Covers(addr); got != TriUnknown {
				t.Errorf("%s: Covers(%v) = %v, want unknown", name, addr, got)
			}
		}
		if tick.Err() == nil {
			t.Errorf("%s: Tick.Err = nil, want why nothing is known", name)
		}
		if got := p.Process(os.Getpid()); got != (Process{}) {
			t.Errorf("%s: Process(self) = %+v, want unknown", name, got)
		}
	}
}

// Lines the readers do not understand are passed over, and never take a good
// line's meaning away from it. The garbage of fib_trie is in Main:, which is
// not checked whole (procFibTrie); Local: is whole, so the reading's "no"s
// are answers.
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
		"     |-- 192.0.2.40",
		"        /32 host LOCAL",
		"  +-- 192.0.2.0/24 2 0 1",
		"        /24 host LOCAL",
		"     |-- 192.0.2.30",
		"        some indented garbage",
		"        /32 host LOCAL",
		"Local:",
		"  +-- 127.0.0.0/8 2 0 2",
		"     +-- 127.0.0.0/31 1 0 0",
		"        |-- 127.0.0.0",
		"           /8 host LOCAL",
		"        |-- 127.0.0.1",
		"           /32 host LOCAL",
		"     |-- 127.255.255.255",
		"        /32 link BROADCAST",
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
	l, err := Proc{FS: fsys}.Locals(context.Background())
	if err != nil {
		t.Fatalf("Locals: %v", err)
	}
	procExpect(t, l, map[string]Tri{
		"192.0.2.20":    TriNo,  // only impossible route lines under it
		"192.0.2.30":    TriYes, // garbage between a leaf and its route orphans nothing
		"192.0.2.1":     TriNo,  // a route under an inner node belongs to no leaf
		"192.0.2.40":    TriYes, // the leaf the inner node ends: its /24 must not reach 192.0.2.1
		"127.0.0.1":     TriYes,
		"::1":           TriNo, // its flags did not parse
		"2001:db8::1":   TriNo, // an IPv6 key in fib_trie is not an IPv6 fact
		"2001:db8::20":  TriYes,
		"2001:db8:3::1": TriNo,
		"2001:db8:4::1": TriNo, // prefix length 255
		"2001:db8:5::1": TriNo,
	})
}

// A reading of fib_trie that routes deleted while it ran have torn — records
// skipped, table local lost in part or whole, or records repeated by routes
// added — answers yes for what it shows, and no "no" at all: three such
// readings leave every address it does not show unknown, and the error says
// the table changed. Each case is the fixture with records skipped or
// repeated, as the kernel serves a reading that resumed at the wrong record.
func TestProcFibTrieTornReadingsNeverSayNo(t *testing.T) {
	recs, local := procRecords(t, procFixtureTrie(t))
	at := func(prefix string) int {
		for i, r := range recs {
			if strings.Contains(r, prefix) {
				return i
			}
		}
		t.Fatalf("no record holds %q", prefix)
		return 0
	}
	subtree := at("+-- 192.0.0.0/5")
	for _, tc := range []struct {
		name string
		trie string
		want map[string]Tri
	}{
		{"the Local: section lost whole", procWithout(recs, local, len(recs)), map[string]Tri{
			"192.0.2.10": TriUnknown, "127.0.0.1": TriUnknown, "8.8.8.8": TriUnknown,
			"203.0.113.7": TriYes, // table 100's LOCAL line was read
		}},
		{"a subtree of Local: lost, with its header and 127.0.0.1 kept", procWithout(recs, subtree, subtree+3), map[string]Tri{
			"192.0.2.10": TriUnknown, "198.51.100.77": TriUnknown, "127.0.0.1": TriYes, "10.0.0.5": TriYes,
		}},
		{"an inner node lost, its leaves left without a parent", procWithout(recs, at("+-- 127.0.0.0/31"), at("+-- 127.0.0.0/31")+1), map[string]Tri{
			"127.0.0.1": TriYes, "192.0.2.10": TriYes, "8.8.8.8": TriUnknown,
		}},
		{"a leaf repeated", strings.Join(slices.Insert(slices.Clone(recs), at("|-- 10.0.0.5")+1, recs[at("|-- 10.0.0.5")]), ""), map[string]Tri{
			"10.0.0.5": TriYes, "192.0.2.10": TriYes, "8.8.8.8": TriUnknown,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &procCountFS{FS: fstest.MapFS{"net/fib_trie": {Data: []byte(tc.trie)}}}
			l, err := Proc{FS: c}.Locals(context.Background())
			if !errors.Is(err, errFibTrieTorn) {
				t.Errorf("Locals error = %v, want errFibTrieTorn", err)
			}
			if got := c.opened("net/fib_trie"); got != procTrieReadings {
				t.Errorf("fib_trie read %d times, want %d", got, procTrieReadings)
			}
			procExpect(t, l, tc.want)
		})
	}
}

// Every skip a deletion can cause — any run of whole records — that reaches
// the Local: section leaves the reading not whole, and one that does not
// leaves it whole. Over two real kernels' dumps, the tables unmerged and
// merged.
func TestProcFibTrieCatchesEverySkipIntoLocal(t *testing.T) {
	merged, err := os.ReadFile("testdata/fib_trie.merged")
	if err != nil {
		t.Fatal(err)
	}
	for name, trie := range map[string]string{"unmerged": procFixtureTrie(t), "merged": string(merged)} {
		recs, local := procRecords(t, trie)
		for i := range recs {
			for j := i + 1; j <= len(recs); j++ {
				_, whole, err := procReadFibTrie(context.Background(), fstest.MapFS{"net/fib_trie": {Data: []byte(procWithout(recs, i, j))}})
				if err != nil {
					t.Fatal(err)
				}
				if want := j <= local; whole != want {
					t.Errorf("%s: records %d..%d of %d skipped (Local: starts at %d): whole = %v, want %v",
						name, i, j-1, len(recs), local, whole, want)
				}
			}
		}
		if _, whole, _ := procReadFibTrie(context.Background(), fstest.MapFS{"net/fib_trie": {Data: []byte(trie)}}); !whole {
			t.Errorf("%s: the dump itself is not whole", name)
		}
	}
}

// Each rule of the Local: section's check, broken alone; and kept.
func TestProcFibTrieChecksLocalRuleByRule(t *testing.T) {
	const (
		root  = "Local:\n  +-- 127.0.0.0/8 2 0 2\n"
		inner = "     +-- 127.0.0.0/31 1 0 0\n"
		zero  = "        |-- 127.0.0.0\n           /8 host LOCAL\n"
		one   = "        |-- 127.0.0.1\n           /32 host LOCAL\n"
		bcast = "     |-- 127.255.255.255\n        /32 link BROADCAST\n"
	)
	for _, tc := range []struct {
		name  string
		trie  string
		whole bool
	}{
		{"whole", root + inner + zero + one + bcast, true},
		{"whole, after another table", "Main:\n  |-- 0.0.0.0\n     /0 universe UNICAST\n" + root + inner + zero + one + bcast, true},
		{"whole, a root that is a leaf", "Local:\n  |-- 127.0.0.1\n     /32 host LOCAL\n", true},
		{"no Local: header", "Main:\n" + root[len("Local:\n"):] + inner + zero + one + bcast, false},
		{"a child missing", root + inner + zero + bcast, false},
		{"a child too many", root + inner + zero + one + "        |-- 127.0.0.2\n" + bcast, false},
		{"a child outside its parent", root + inner + zero + "        |-- 127.0.0.9\n" + bcast, false},
		{"children out of order", root + inner + one + zero + bcast, false},
		{"an inner child no longer than its parent", root + "     +-- 127.0.0.0/8 1 0 0\n" + zero + one + bcast, false},
		{"a node whose parent is not open", "Local:\n  |-- 127.0.0.1\n     /32 host LOCAL\n     |-- 127.0.0.2\n", false},
		{"two roots", root + inner + zero + one + bcast + "  |-- 192.0.2.10\n", false},
		{"an indentation that is no depth", root + inner + zero + "         |-- 127.0.0.1\n" + bcast, false},
		{"a node that does not parse", root + inner + zero + "        |-- 127.0.0.x\n" + bcast, false},
		{"counts that do not parse", root + "     +-- 127.0.0.0/31 1 0 z\n" + zero + one + bcast, false},
	} {
		local, whole, err := procReadFibTrie(context.Background(), fstest.MapFS{"net/fib_trie": {Data: []byte(tc.trie)}})
		if err != nil || whole != tc.whole {
			t.Errorf("%s: whole = %v (%v), want %v", tc.name, whole, err, tc.whole)
		}
		if !procCovered(local, probeV4) {
			t.Errorf("%s: 127.0.0.1 not read as local: %v", tc.name, local)
		}
	}
}

// A torn reading is followed by another; the answer comes from the first
// whole one, and an address a torn reading shows is yes at once.
func TestTickRereadsATornFibTrie(t *testing.T) {
	trie := procFixtureTrie(t)
	recs, local := procRecords(t, trie)
	torn := procWithout(recs, local, len(recs))

	c := &procCountFS{FS: procFixture(t), seq: map[string][]string{"net/fib_trie": {torn, trie}}}
	tick := Proc{FS: c}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"192.0.2.10": TriYes, "192.0.2.11": TriNo, "203.0.113.7": TriYes})
	if got := c.opened("net/fib_trie"); got != 2 {
		t.Errorf("fib_trie read %d times, want 2: the torn reading, then a whole one", got)
	}
	if err := tick.Err(); err != nil {
		t.Errorf("Err = %v, want nil: the second reading was whole", err)
	}

	c = &procCountFS{FS: procFixture(t), seq: map[string][]string{"net/fib_trie": {torn, trie}}}
	tick = Proc{FS: c}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"203.0.113.7": TriYes})
	if got := c.opened("net/fib_trie"); got != 1 {
		t.Errorf("fib_trie read %d times for an address the first reading shows, want 1", got)
	}

	c = &procCountFS{FS: procFixture(t), seq: map[string][]string{"net/fib_trie": {torn}}}
	tick = Proc{FS: c}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"192.0.2.10": TriUnknown, "192.0.2.11": TriUnknown, "203.0.113.7": TriYes})
	if got := c.opened("net/fib_trie"); got != procTrieReadings {
		t.Errorf("fib_trie read %d times, want %d and no more", got, procTrieReadings)
	}
	if err := tick.Err(); !errors.Is(err, errFibTrieTorn) {
		t.Errorf("Err = %v, want errFibTrieTorn", err)
	}

	// What any reading showed counts: table 100 is in the first reading
	// only, and its address is still yes after the third.
	torn100 := procWithout(recs, 0, local) // Id 100: and Main: lost; Local: is torn below
	torn100 = strings.Replace(torn100, "     +-- 192.0.0.0/5 2 0 2\n", "", 1)
	c = &procCountFS{FS: procFixture(t), seq: map[string][]string{"net/fib_trie": {torn, torn100}}}
	tick = Proc{FS: c}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"192.0.2.11": TriUnknown})
	procTickExpect(t, tick, map[string]Tri{"203.0.113.7": TriYes, "192.0.2.10": TriYes})
	if got := c.opened("net/fib_trie"); got != procTrieReadings {
		t.Errorf("fib_trie read %d times, want %d", got, procTrieReadings)
	}
}

// ipv6_route cannot be checked whole, so an address only it could hold is not
// held only when two readings agree.
func TestTickConfirmsAnIPv6NoWithASecondReading(t *testing.T) {
	fixture := procFixture(t)
	routes := string(fixture["net/ipv6_route"].Data)
	var lost []string // the fixture without its AnyIP route, as a torn reading
	for _, line := range strings.SplitAfter(routes, "\n") {
		if !strings.HasPrefix(line, "20010db8000200000000000000000000 40") {
			lost = append(lost, line)
		}
	}
	for _, tc := range []struct {
		name     string
		seq      []string
		failRead bool
		want     Tri
		opens    int
	}{
		{"the first reading shows it", []string{routes}, false, TriYes, 1},
		{"only the second shows it", []string{strings.Join(lost, ""), routes}, false, TriYes, 2},
		{"neither shows it", []string{strings.Join(lost, "")}, false, TriNo, 2},
		{"the readings fail", []string{routes}, true, TriUnknown, 1},
	} {
		c := &procCountFS{FS: fixture, seq: map[string][]string{"net/ipv6_route": tc.seq}}
		if tc.failRead {
			c.failRead = map[string]error{"net/ipv6_route": errors.New("read failed")}
		}
		tick := Proc{FS: c}.Tick(context.Background(), DefaultPort)
		if got := tick.Local(procAddr("2001:db8:2::5")); got != tc.want {
			t.Errorf("%s: Local(2001:db8:2::5) = %v, want %v", tc.name, got, tc.want)
		}
		if got := c.opened("net/ipv6_route"); got != tc.opens {
			t.Errorf("%s: ipv6_route read %d times, want %d", tc.name, got, tc.opens)
		}
	}
}

// A tick reads only what an address needs, each source once: the interface
// list for an IPv4 address it lists; fib_trie for one it does not; if_inet6
// for an IPv6 address, and ipv6_route only for one if_inet6 does not list
// usable; the TCP tables only when Listening is asked.
func TestTickReadsOnlyWhatAnAddressNeeds(t *testing.T) {
	fsys := procFixture(t)
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false, procSock{"192.0.2.10:443", procListen})}
	fsys["net/tcp6"] = &fstest.MapFile{Data: procTCP(true)}
	c := &procCountFS{FS: fsys}
	ifaces := &procInterfaces{addrs: []string{"127.0.0.1", "10.0.0.5", "192.0.2.10"}}
	tick := Proc{FS: c, Ifaddrs4: ifaces.list}.Tick(context.Background(), DefaultPort)
	opened := func(when string, want map[string]int) {
		t.Helper()
		for name, n := range want {
			if got := c.opened(name); got != n {
				t.Errorf("%s: %s opened %d times, want %d", when, name, got, n)
			}
		}
	}

	for range 3 {
		procTickExpect(t, tick, map[string]Tri{"192.0.2.10": TriYes, "::ffff:127.0.0.1": TriYes})
	}
	opened("an interface's IPv4 address", map[string]int{"net/fib_trie": 0, "net/if_inet6": 0, "net/ipv6_route": 0})

	procTickExpect(t, tick, map[string]Tri{"198.51.100.77": TriYes, "192.0.2.11": TriNo, "203.0.113.7": TriYes})
	opened("an AnyIP range, an address that is gone", map[string]int{"net/fib_trie": 1, "net/if_inet6": 0, "net/ipv6_route": 0})

	procTickExpect(t, tick, map[string]Tri{"2001:db8::10": TriYes, "::1": TriYes})
	opened("an IPv6 address if_inet6 lists usable", map[string]int{"net/fib_trie": 1, "net/if_inet6": 1, "net/ipv6_route": 0})

	procTickExpect(t, tick, map[string]Tri{"2001:db8:2::ffff": TriYes})
	opened("an IPv6 AnyIP range", map[string]int{"net/if_inet6": 1, "net/ipv6_route": 1})

	procTickExpect(t, tick, map[string]Tri{"2001:db8:3::1": TriNo, "2001:db8:3::2": TriNo})
	opened("IPv6 addresses that are gone", map[string]int{"net/if_inet6": 1, "net/ipv6_route": 2, "net/tcp": 0, "net/tcp6": 0})

	for range 3 {
		if got := tick.Listening(procAddr("192.0.2.10")); got != TriYes {
			t.Fatalf("Listening(192.0.2.10) = %v, want yes", got)
		}
	}
	opened("Listening", map[string]int{"net/tcp": 1, "net/tcp6": 1})
	if n := ifaces.calls.Load(); n != 1 {
		t.Errorf("the interface list was read %d times, want once", n)
	}
	if err := tick.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
}

// The interface list answers yes alone; fib_trie answers what it does not
// list, and everything when it fails. An IPv6 question asks neither.
func TestTickAsksTheInterfaceListFirst(t *testing.T) {
	c := &procCountFS{FS: procFixture(t), fail: map[string]error{"net/fib_trie": fs.ErrPermission}}
	ifaces := &procInterfaces{addrs: []string{"192.0.2.10"}}
	tick := Proc{FS: c, Ifaddrs4: ifaces.list}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"192.0.2.10": TriYes})
	if err := tick.Err(); err != nil {
		t.Errorf("Err = %v, want nil: fib_trie was not needed", err)
	}
	procTickExpect(t, tick, map[string]Tri{"198.51.100.77": TriUnknown, "192.0.2.11": TriUnknown})
	if err := tick.Err(); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Err = %v, want fib_trie's failure", err)
	}

	broken := errors.New("SIOCGIFCONF failed")
	ifaces = &procInterfaces{err: broken}
	tick = Proc{FS: procFixture(t), Ifaddrs4: ifaces.list}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"192.0.2.10": TriYes, "192.0.2.11": TriNo})
	if err := tick.Err(); !errors.Is(err, broken) {
		t.Errorf("Err = %v, want the interface list's failure", err)
	}

	ifaces = &procInterfaces{addrs: []string{"192.0.2.10"}}
	c = &procCountFS{FS: procFixture(t)}
	tick = Proc{FS: c, Ifaddrs4: ifaces.list}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, tick, map[string]Tri{"::1": TriYes, "2001:db8:3::1": TriNo})
	if n, opens := ifaces.calls.Load(), c.opened("net/fib_trie"); n != 0 || opens != 0 {
		t.Errorf("IPv6 questions: the interface list read %d times, fib_trie %d, want neither", n, opens)
	}
}

// A Proc with a tree of its own and no Ifaddrs4 answers from that tree alone,
// even on a Linux host whose interfaces hold the address.
func TestProcOwnTreeIsNotMixedWithTheHost(t *testing.T) {
	fsys := procFixture(t)
	delete(fsys, "net/fib_trie")
	tick := Proc{FS: fsys}.Tick(context.Background(), DefaultPort)
	if got := tick.Local(probeV4); got != TriUnknown {
		t.Errorf("Local(127.0.0.1) with the tree's fib_trie gone = %v, want unknown: the host's interfaces were asked", got)
	}
	if (Proc{}).ifaddrs4() == nil || HostProc().Ifaddrs4 == nil {
		t.Error("the host's Proc does not ask the host's interfaces")
	}
}

// On Linux, the host's interface list holds 127.0.0.1, and a tick answers it
// from that list without reading fib_trie. Elsewhere there is no list.
func TestProcIfaddrs4OnThisHost(t *testing.T) {
	addrs, err := procIfaddrs4()
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatalf("procIfaddrs4 off Linux = %v, want an error", addrs)
		}
		return
	}
	if err != nil {
		t.Fatalf("procIfaddrs4: %v", err)
	}
	if !slices.Contains(addrs, probeV4) {
		t.Fatalf("procIfaddrs4 = %v, want 127.0.0.1 among them", addrs)
	}
	for _, a := range addrs {
		if !a.Is4() {
			t.Errorf("procIfaddrs4 listed %v, not an IPv4 address", a)
		}
	}
	c := &procCountFS{FS: os.DirFS("/proc")}
	if got := (Proc{FS: c, Ifaddrs4: procIfaddrs4}).Tick(context.Background(), DefaultPort).Local(probeV4); got != TriYes {
		t.Fatalf("Local(127.0.0.1) = %v, want yes", got)
	}
	if n := c.opened("net/fib_trie"); n != 0 {
		t.Errorf("fib_trie read %d times for an interface's address, want none", n)
	}
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
		l, err := Proc{FS: fsys}.Listeners(context.Background(), port)
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
	l, err := Proc{FS: fsys}.Listeners(context.Background(), 443)
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
	if l, err = (Proc{FS: fsys}).Listeners(context.Background(), 443); err != nil {
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
	l, err := Proc{FS: fsys}.Listeners(context.Background(), 443)
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
		l, err := Proc{FS: &procCountFS{FS: fsys, fail: tc.fail, failRead: tc.failRead}}.Listeners(context.Background(), 443)
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

	// A missing stat is "gone" only in a tree that shows this reader the
	// whole process table. /proc mounted hidepid=invisible shows a reader
	// other than root its own processes — self among them — and hides the
	// rest, pid 1 and a live master of root's alike.
	delete(fsys, "1")
	if got := (Proc{FS: fsys}).Process(999); got != (Process{}) {
		t.Errorf("Process(999) with self but without pid 1 (hidepid=invisible) = %+v, want unknown", got)
	}
	delete(fsys, "self")
	if got := (Proc{FS: fsys}).Process(999); got != (Process{}) {
		t.Errorf("Process(999) without self or pid 1 = %+v, want unknown", got)
	}
	unreadable := &procCountFS{FS: procFixture(t), fail: map[string]error{"100/stat": fs.ErrPermission}}
	if got := (Proc{FS: unreadable}).Process(100); got != (Process{}) {
		t.Errorf("Process(100) unreadable = %+v, want unknown", got)
	}
}

func TestTickIsSafeForConcurrentUse(t *testing.T) {
	fsys := procFixture(t)
	fsys["net/tcp"] = &fstest.MapFile{Data: procTCP(false, procSock{"0.0.0.0:443", procListen})}
	recs, local := procRecords(t, procFixtureTrie(t))
	c := &procCountFS{
		FS:   fsys,
		fail: map[string]error{"net/tcp6": fs.ErrPermission},
		// A torn reading first, so that the goroutines meet a re-reading.
		seq: map[string][]string{"net/fib_trie": {procWithout(recs, local, len(recs)), procFixtureTrie(t)}},
	}
	ifaces := &procInterfaces{addrs: []string{"10.0.0.5"}}
	tick := Proc{FS: c, Ifaddrs4: ifaces.list}.Tick(context.Background(), DefaultPort)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_ = tick.Err()
			for addr, want := range map[string]Tri{
				"192.0.2.10": TriYes, "192.0.2.11": TriNo, "10.0.0.5": TriYes,
				"2001:db8::10": TriYes, "2001:db8:3::1": TriNo,
			} {
				if got := tick.Local(procAddr(addr)); got != want {
					t.Errorf("Local(%s) = %v, want %v", addr, got, want)
				}
			}
			if got := tick.Listening(procAddr("192.0.2.10")); got != TriUnknown {
				t.Errorf("Listening with tcp6 unreadable = %v, want unknown", got)
			}
			_ = tick.Err()
		})
	}
	wg.Wait()
	for name, want := range map[string]int{"net/fib_trie": 2, "net/if_inet6": 1, "net/ipv6_route": 2, "net/tcp": 1, "net/tcp6": 1} {
		if got := c.opened(name); got != want {
			t.Errorf("%s opened %d times, want %d", name, got, want)
		}
	}
	if n := ifaces.calls.Load(); n != 1 {
		t.Errorf("the interface list was read %d times, want once", n)
	}
}

// Err joins the failures of the reads this tick made, and only of those.
func TestTickErrJoinsTheReadsMade(t *testing.T) {
	c := &procCountFS{FS: procFixture(t), fail: map[string]error{"net/tcp": fs.ErrNotExist}}
	tick := Proc{FS: c}.Tick(context.Background(), DefaultPort)
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

	broken := &procCountFS{FS: procFixture(t), fail: map[string]error{"net/fib_trie": fs.ErrPermission, "net/if_inet6": fs.ErrPermission}}
	tick = Proc{FS: broken}.Tick(context.Background(), DefaultPort)
	if got := tick.Local(probeV4); got != TriUnknown {
		t.Fatalf("Local without fib_trie = %v, want unknown", got)
	}
	if err := tick.Err(); !errors.Is(err, fs.ErrPermission) || strings.Contains(err.Error(), "if_inet6") {
		t.Fatalf("Err = %v, want the fib_trie failure alone: if_inet6 was not read", err)
	}

	noIPv6 := procFixture(t)
	delete(noIPv6, "net/if_inet6")
	delete(noIPv6, "net/ipv6_route")
	tick = Proc{FS: noIPv6}.Tick(context.Background(), DefaultPort)
	if got := tick.Local(probeV6); got != TriNo {
		t.Fatalf("Local(::1) on a kernel without IPv6 = %v, want no", got)
	}
	if err := tick.Err(); err != nil {
		t.Fatalf("Err = %v on a kernel without IPv6, want nil", err)
	}
}

// procCancelFS calls cancel at every read() of any file it opened, and counts
// the read()s, and the openings of fib_trie.
type procCancelFS struct {
	fs.FS
	cancel     context.CancelFunc
	reads      atomic.Int32
	trieOpened atomic.Int32
}

func (c *procCancelFS) Open(name string) (fs.File, error) {
	if name == "net/fib_trie" {
		c.trieOpened.Add(1)
	}
	f, err := c.FS.Open(name)
	if err != nil {
		return nil, err
	}
	return procCancelFile{File: f, c: c}, nil
}

type procCancelFile struct {
	fs.File
	c *procCancelFS
}

func (f procCancelFile) Read(b []byte) (int, error) {
	f.c.reads.Add(1)
	f.c.cancel()
	return f.File.Read(b)
}

// The tick's ctx bounds its file readings: a reading stops at the first
// read() after ctx ends, what only it could tell is unknown, and Err says
// why. The interface list is no file, and still answers.
func TestTickStopsReadingWhenItsContextEnds(t *testing.T) {
	files := func() fstest.MapFS {
		f := procFixture(t)
		f["net/tcp"] = &fstest.MapFile{Data: procTCP(false, procSock{"0.0.0.0:443", procListen})}
		f["net/tcp6"] = &fstest.MapFile{Data: procTCP(true)}
		return f
	}
	// The control: the same files under a ctx that never ends answer.
	live := Proc{FS: &procCancelFS{FS: files(), cancel: func() {}}}.Tick(context.Background(), DefaultPort)
	procTickExpect(t, live, map[string]Tri{"127.0.0.1": TriYes, "::1": TriYes})
	if got := live.Listening(probeV4); got != TriYes {
		t.Fatalf("control: Listening = %v, want yes", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &procCancelFS{FS: files(), cancel: cancel}
	tick := Proc{FS: c}.Tick(ctx, DefaultPort)
	if got := tick.Local(probeV4); got != TriUnknown {
		t.Fatalf("Local(127.0.0.1) with ctx ended during the reading = %v, want unknown", got)
	}
	if n := c.reads.Load(); n != 1 {
		t.Fatalf("fib_trie was read %d times, want once: the scan stops at the first read() after ctx ends", n)
	}
	if n := c.trieOpened.Load(); n != 1 {
		t.Fatalf("fib_trie was opened %d times, want once: a reading cut short is not made again", n)
	}
	if got := tick.Local(probeV6); got != TriUnknown {
		t.Fatalf("Local(::1) after ctx ended = %v, want unknown", got)
	}
	if got := tick.Listening(probeV4); got != TriUnknown {
		t.Fatalf("Listening after ctx ended = %v, want unknown", got)
	}
	if n := c.reads.Load(); n != 1 {
		t.Fatalf("%d read()s in all, want 1: nothing is read after ctx ends", n)
	}
	err := tick.Err()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Err = %v, want context.Canceled", err)
	}
	for _, name := range []string{"net/fib_trie", "net/if_inet6", "net/tcp"} {
		if want := "read " + name + ": " + context.Canceled.Error(); !strings.Contains(err.Error(), want) {
			t.Fatalf("Err = %v, want %q among its errors", err, want)
		}
	}

	ifaces := &procInterfaces{addrs: []string{"192.0.2.10"}}
	tick = Proc{FS: procFixture(t), Ifaddrs4: ifaces.list}.Tick(ctx, DefaultPort)
	if got := tick.Local(procAddr("192.0.2.10")); got != TriYes {
		t.Fatalf("Local of an interface's address after ctx ended = %v, want yes: the list is no file", got)
	}
	if err := tick.Err(); err != nil {
		t.Fatalf("Err = %v, want nil: no file was read", err)
	}

	l, err := Proc{FS: files()}.Locals(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Locals with ctx ended: err = %v, want context.Canceled", err)
	}
	procExpect(t, l, map[string]Tri{"127.0.0.1": TriUnknown, "::1": TriUnknown})
	if _, err := (Proc{FS: files()}).Listeners(ctx, DefaultPort); !errors.Is(err, context.Canceled) {
		t.Fatalf("Listeners with ctx ended: err = %v, want context.Canceled", err)
	}
}

// On Linux, the real /proc: this box holds 127.0.0.1, a listener the test
// opens is listed until it closes, and this process is alive.
func TestProcReadsThisLinuxHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is Linux's; TestProcWithoutProcKnowsNothing covers this host")
	}
	p := HostProc()
	l, err := p.Locals(context.Background())
	if err != nil {
		t.Fatalf("Locals: %v", err)
	}
	if got := l.Has(probeV4); got != TriYes {
		t.Fatalf("Has(127.0.0.1) = %v, want yes", got)
	}
	if got := p.Tick(context.Background(), DefaultPort).Local(probeV4); got != TriYes {
		t.Fatalf("Tick.Local(127.0.0.1) = %v, want yes", got)
	}
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probePort(ln)
	ls, err := p.Listeners(context.Background(), port)
	if err != nil {
		t.Fatalf("Listeners: %v", err)
	}
	if got := ls.Covers(probeV4); got != TriYes {
		t.Fatalf("with a listener on 127.0.0.1:%d, Covers(127.0.0.1) = %v, want yes", port, got)
	}
	_ = ln.Close()
	if ls, err = p.Listeners(context.Background(), port); err != nil || ls.Covers(probeV4) != TriNo {
		t.Fatalf("after closing it, Covers(127.0.0.1) = %v (%v), want no", ls.Covers(probeV4), err)
	}
	if got := p.Process(os.Getpid()); got != (Process{State: PIDAlive}) {
		t.Fatalf("Process(self) = %+v, want alive", got)
	}
	// A /proc mounted hidepid=invisible hides pid 1 from a reader other than
	// root, and a pid it cannot see is unknown, not gone.
	gone := Process{State: PIDGone}
	if _, err := os.Stat("/proc/1"); err != nil {
		gone = Process{}
	}
	if got := p.Process(1 << 30); got != gone {
		t.Fatalf("Process(1<<30) = %+v, want %+v", got, gone)
	}
}

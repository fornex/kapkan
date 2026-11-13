package steer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"sync"
)

// Proc reads the kernel's view of this box: its /proc tree and, as the cheap
// first answer for an IPv4 address, its interfaces' IPv4 addresses
// (SIOCGIFCONF: an ioctl on an AF_INET socket). Never netlink (D5): the unit
// grants no AF_NETLINK, which is worth keeping. And never a bare bind(),
// which is blind under ip_nonlocal_bind=1, a common setting on anycast and
// keepalived hosts. The zero value reads the host.
//
// Every fact here is Linux's. Where no /proc exists — a darwin development
// host — every file is missing, and every answer is TriUnknown or
// PIDUnknown: unknown holds, so a host without /proc can delay a join and
// never withdraw anything.
type Proc struct {
	// FS is rooted at /proc: os.DirFS("/proc") on a node, an fstest.MapFS of
	// fixture files ("net/fib_trie", "net/if_inet6", "net/ipv6_route",
	// "net/tcp", "net/tcp6", "<pid>/stat") in a test.
	FS fs.FS
	// Ifaddrs4 lists the IPv4 addresses on this box's interfaces, secondaries
	// included, as SIOCGIFCONF does — never an AnyIP range, which is a route.
	// An address it lists is held, and no file is read for it; one it does
	// not list is fib_trie's to answer. HostProc's asks the kernel, and so
	// does a nil one in the zero Proc (off Linux, that is an error, and
	// fib_trie answers). Beside an FS of the caller's, nil lists nothing: a
	// fixture tree answers alone, never mixed with the host's interfaces.
	Ifaddrs4 func() ([]netip.Addr, error)
}

// HostProc reads the host: its /proc and its interfaces.
func HostProc() Proc { return Proc{FS: os.DirFS("/proc"), Ifaddrs4: procIfaddrs4} }

func (p Proc) fsys() fs.FS {
	if p.FS == nil {
		return os.DirFS("/proc")
	}
	return p.FS
}

// ifaddrs4 is the interface list a Tick asks first, nil when there is none.
func (p Proc) ifaddrs4() func() ([]netip.Addr, error) {
	if p.Ifaddrs4 == nil && p.FS == nil {
		return procIfaddrs4
	}
	return p.Ifaddrs4
}

// The kernel's flag values these readers test.
const (
	// if_inet6's IFA_F_TENTATIVE and IFA_F_DADFAILED: duplicate address
	// detection has not finished, or found the address in use elsewhere.
	procTentative = 0x40
	procDADFailed = 0x08
	// ipv6_route's RTF_LOCAL: the route's addresses are delivered to this box.
	procRTFLocal = 0x80000000
	// net/tcp's st for TCP_LISTEN.
	procListen = 0x0A
)

// How often one tick reads a route table that is not a snapshot (Tick.Local).
const (
	// procTrieReadings: fib_trie is read again while no reading was whole.
	procTrieReadings = 3
	// procRouteReadings: this many readings of ipv6_route must agree before
	// an address it alone could hold is not held.
	procRouteReadings = 2
)

// errFibTrieTorn is the error of a tick whose readings of fib_trie were
// none of them whole: every IPv4 address no reading listed is TriUnknown.
var errFibTrieTorn = errors.New("read net/fib_trie: the table changed while it was read")

// Locals is the kernel's local address space, from one reading of every
// file Tick.Local may need (Proc.Locals). The zero value has read nothing,
// and answers TriUnknown for every address.
type Locals struct {
	t *Tick
}

// Has reports whether the kernel holds addr, by Tick.Local's rules, from
// what Proc.Locals read.
func (l Locals) Has(addr netip.Addr) Tri {
	if l.t == nil {
		return TriUnknown
	}
	return l.t.Local(addr)
}

// Locals reads, from the files alone, everything Tick.Local may need for any
// address: fib_trie until a reading is whole (at most three), if_inet6, and
// ipv6_route twice. The sampler uses a Tick instead, which reads only what
// the asked addresses need: on a box whose kernel carries a full table, one
// reading of fib_trie or ipv6_route takes seconds to minutes (Tick.Local).
//
// A file that cannot be read leaves unknown what only it could have told,
// and its error is returned beside a Locals that still answers from the
// others — except that if_inet6 and ipv6_route both absent (fs.ErrNotExist)
// beside a fib_trie means the kernel runs without IPv6 (ipv6.disable=1):
// every IPv6 address is then TriNo, and that is no error. Readings of
// fib_trie none of which was whole return errFibTrieTorn. Malformed lines
// are skipped, never fatal. ctx bounds the readings, as for Proc.Tick.
func (p Proc) Locals(ctx context.Context) (Locals, error) {
	t := &Tick{p: p, ctx: ctx}
	t.readAll()
	return Locals{t: t}, t.Err()
}

// procReadFibTrie makes one reading of fib_trie: the LOCAL prefixes of every
// table, and whether its Local: section was whole (procFibTrie). A reading
// cut short — by an error or by ctx — lists nothing.
func procReadFibTrie(ctx context.Context, fsys fs.FS) ([]netip.Prefix, bool, error) {
	var t procFibTrie
	if err := procScan(ctx, fsys, "net/fib_trie", t.line); err != nil {
		return nil, false, err
	}
	return t.local, t.whole(), nil
}

// procReadIfInet6 reads if_inet6: one address per line, 32 hex digits, then
// ifindex, prefix length, scope and flags in hex, then the device name. It
// returns the addresses listed usable.
func procReadIfInet6(ctx context.Context, fsys fs.FS) (map[netip.Addr]bool, error) {
	usable := make(map[netip.Addr]bool)
	err := procScan(ctx, fsys, "net/if_inet6", func(line []byte) {
		if addr, ok := procUsableAddr6(line); ok {
			usable[addr] = true
		}
	})
	if err != nil {
		return nil, err
	}
	return usable, nil
}

// procReadIPv6Route reads ipv6_route — one route per line: destination (32
// hex digits), its prefix length (hex), source, its length, next hop,
// metric, refcount, use, flags (hex; RTF_LOCAL is 0x80000000), device — and
// returns its RTF_LOCAL prefixes.
func procReadIPv6Route(ctx context.Context, fsys fs.FS) ([]netip.Prefix, error) {
	var local []netip.Prefix
	err := procScan(ctx, fsys, "net/ipv6_route", func(line []byte) {
		if p, ok := procLocalRoute6(line); ok {
			local = append(local, p)
		}
	})
	if err != nil {
		return nil, err
	}
	return local, nil
}

// procFibTrie is one reading of fib_trie, line by line. Each table is a
// section: its header ("Main:", "Local:", "Id 100:"), then its trie, one
// record per node in depth-first order. An inner node, "+-- 10.0.0.0/24 2 0
// 1", gives its prefix, the bits it indexes, and its full and empty slots: it
// has 2^bits − empty children. A leaf, "|-- 10.0.0.5", is followed by a line
// per route on that key, "/32 host LOCAL" (a tos=N may follow). A node at
// depth d is indented 3d+2 spaces, and its children are at depth d+1.
//
// Every "/<len> <scope> LOCAL" line under a leaf makes <leaf>/<len> local,
// whatever its table: reading more as local can only hold an address in. An
// inner node ends a leaf's routes. Lines it does not recognise are passed
// over.
//
// The file is not a snapshot. The kernel serves it a page per read(), whole
// records only, and finds where to go on by counting records from the start.
// So routes deleted between two read()s make the reading skip as many
// records, and table local, printed last, can be lost whole. That is why the
// Local: section is checked as it streams. It must have its header, which the
// kernel prints only together with the section's root. It must have exactly
// one root. Every inner node must get exactly the children it counts, each at
// the next depth, inside its prefix, and in ascending order. A skip that
// reaches the section breaks one of these rules. A skip that stays in another
// table is not looked for: IPv4 bind() and source selection consult table
// local alone, so an address only another table makes local can be neither
// probed nor served from this box.
type procFibTrie struct {
	leaf    []byte
	hasLeaf bool
	local   []netip.Prefix

	// inLocal: the section being read is table local's, and is checked.
	inLocal bool
	// open are its inner nodes still owed children, the root first.
	open []procTrieNode
	// roots counts its nodes at depth 0; a whole section has one.
	roots int
	// broken: it broke a rule.
	broken bool
	// localWhole: a Local: section of this reading ended whole.
	localWhole bool
}

// procTrieNode is an inner node of the section being checked.
type procTrieNode struct {
	prefix netip.Prefix
	// owed counts the children still to come.
	owed uint64
	// last is the key of its latest child; the zero Addr before the first.
	last netip.Addr
}

func (t *procFibTrie) line(raw []byte) {
	line := bytes.TrimLeft(raw, " ")
	indent := len(raw) - len(line)
	switch {
	case indent == 0 && bytes.HasSuffix(line, []byte(":")):
		t.endSection()
		t.inLocal = string(line) == "Local:"
	case bytes.HasPrefix(line, []byte("|--")):
		t.leaf = append(t.leaf[:0], bytes.TrimSpace(line[len("|--"):])...)
		t.hasLeaf = true
		if t.inLocal {
			key, ok := procParse4(t.leaf)
			t.node(indent, key, netip.Prefix{}, 0, ok)
		}
	case bytes.HasPrefix(line, []byte("+--")):
		t.hasLeaf = false
		if t.inLocal {
			prefix, children, ok := procInnerNode(line[len("+--"):])
			t.node(indent, prefix.Addr(), prefix, children, ok)
		}
	case t.hasLeaf && bytes.HasPrefix(line, []byte("/")):
		if p, ok := procLocalRoute4(t.leaf, line); ok {
			t.local = append(t.local, p)
		}
	}
}

// node checks one node of the Local: section at the depth its indentation
// gives. Reaching that depth closes every inner node open at it or below, and
// each of them must have had all its children. A node at depth 0 is the
// section's one root. Any other node is a child of the inner node open one
// depth up, which must still owe one. It must lie inside that node's prefix,
// after its previous child, and an inner child must have a longer prefix.
// prefix is the zero Prefix for a leaf; ok says the line parsed.
func (t *procFibTrie) node(indent int, key netip.Addr, prefix netip.Prefix, children uint64, ok bool) {
	if t.broken {
		return
	}
	if !ok || indent < 2 || (indent-2)%3 != 0 {
		t.broken = true
		return
	}
	depth := (indent - 2) / 3
	for len(t.open) > depth {
		if t.open[len(t.open)-1].owed != 0 {
			t.broken = true
			return
		}
		t.open = t.open[:len(t.open)-1]
	}
	inner := prefix.IsValid()
	if depth == 0 {
		t.roots++
		t.broken = t.roots > 1
	} else {
		if len(t.open) < depth {
			t.broken = true // its parent is not open
			return
		}
		parent := &t.open[depth-1]
		if parent.owed == 0 || !parent.prefix.Contains(key) ||
			(inner && prefix.Bits() <= parent.prefix.Bits()) ||
			(parent.last.IsValid() && key.Compare(parent.last) <= 0) {
			t.broken = true
			return
		}
		parent.owed--
		parent.last = key
	}
	if inner && !t.broken {
		t.open = append(t.open, procTrieNode{prefix: prefix, owed: children})
	}
}

// endSection closes the section being read. A Local: one is whole when it
// had one root and every inner node got all its children.
func (t *procFibTrie) endSection() {
	if t.inLocal && !t.broken && t.roots == 1 {
		whole := true
		for _, n := range t.open {
			whole = whole && n.owed == 0
		}
		t.localWhole = t.localWhole || whole
	}
	t.inLocal, t.open, t.roots, t.broken = false, t.open[:0], 0, false
}

// whole ends the reading, and reports whether a Local: section in it was
// whole.
func (t *procFibTrie) whole() bool {
	t.endSection()
	return t.localWhole
}

// procInnerNode reads the fields of an inner node's line after "+--": its
// prefix, the bits it indexes, its full and its empty slots. It returns the
// prefix and the number of children, 2^bits − empty.
func procInnerNode(fields []byte) (netip.Prefix, uint64, bool) {
	addr, length, found := bytes.Cut(procField(fields, 0), []byte("/"))
	key, okKey := procParse4(addr)
	bitsLen, okLen := procDecimal(length, 32)
	bits, okBits := procDecimal(procField(fields, 1), 32)
	empty, okEmpty := procDecimal(procField(fields, 3), 1<<32)
	if !found || !okKey || !okLen || !okBits || !okEmpty || bitsLen+bits > 32 || empty > 1<<bits {
		return netip.Prefix{}, 0, false
	}
	return netip.PrefixFrom(key, int(bitsLen)), 1<<bits - empty, true
}

// procLocalRoute4 reads one route line, "/<len> <scope> <type>[ tos=N]",
// under leaf: <leaf>/<len> when the type is LOCAL. Only LOCAL lines are
// parsed further — they are a handful among what can be a million routes.
func procLocalRoute4(leaf, line []byte) (netip.Prefix, bool) {
	if string(procField(line, 2)) != "LOCAL" {
		return netip.Prefix{}, false
	}
	bits, okBits := procDecimal(procField(line, 0)[1:], 32)
	addr, okAddr := procParse4(leaf)
	if !okBits || !okAddr {
		return netip.Prefix{}, false
	}
	p, err := addr.Prefix(int(bits))
	return p, err == nil
}

// procParse4 reads a dotted-quad IPv4 address without allocating: fib_trie
// prints one for each of what can be millions of nodes.
func procParse4(b []byte) (netip.Addr, bool) {
	var a [4]byte
	for i := range a {
		if i > 0 {
			if len(b) == 0 || b[0] != '.' {
				return netip.Addr{}, false
			}
			b = b[1:]
		}
		n := 0
		for n < len(b) && n < 3 && '0' <= b[n] && b[n] <= '9' {
			n++
		}
		v, ok := procDecimal(b[:n], 255)
		if !ok {
			return netip.Addr{}, false
		}
		a[i], b = byte(v), b[n:]
	}
	if len(b) != 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(a), true
}

// procDecimal reads a non-empty run of decimal digits no greater than max.
func procDecimal(b []byte, max uint64) (uint64, bool) {
	if len(b) == 0 || len(b) > 10 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, v <= max
}

// procUsableAddr6 reads one if_inet6 line and returns its address unless the
// flags say tentative or dadfailed.
func procUsableAddr6(line []byte) (netip.Addr, bool) {
	addr, ok := procAddr6(procField(line, 0))
	flags, err := strconv.ParseUint(string(procField(line, 4)), 16, 32)
	if !ok || err != nil || flags&(procTentative|procDADFailed) != 0 {
		return netip.Addr{}, false
	}
	return addr, true
}

// procLocalRoute6 reads one ipv6_route line and returns its destination
// prefix when the flags carry RTF_LOCAL.
func procLocalRoute6(line []byte) (netip.Prefix, bool) {
	flags, err := strconv.ParseUint(string(procField(line, 8)), 16, 32)
	if err != nil || flags&procRTFLocal == 0 {
		return netip.Prefix{}, false
	}
	addr, ok := procAddr6(procField(line, 0))
	bits, err := strconv.ParseUint(string(procField(line, 1)), 16, 8)
	if !ok || err != nil {
		return netip.Prefix{}, false
	}
	p, err := addr.Prefix(int(bits))
	return p, err == nil
}

// Listeners are the LISTEN sockets on one TCP port at one reading. The zero
// value has read nothing, and answers TriUnknown.
type Listeners struct {
	// addrs are the sockets' local addresses, unmapped, wildcards included.
	addrs []netip.Addr
	known bool
}

// Covers reports whether a LISTEN socket covers addr: one bound to addr
// itself (IPv4-mapped compared as IPv4), to 0.0.0.0 for an IPv4 addr, or to ::
// for any addr — a dual-stack socket's IPV6_V6ONLY cannot be read here, and
// covering too much can only make a refusal hold. TriUnknown when the table
// could not be read, or addr is invalid.
func (l Listeners) Covers(addr netip.Addr) Tri {
	if !l.known || !addr.IsValid() {
		return TriUnknown
	}
	addr = addr.Unmap().WithZone("")
	for _, a := range l.addrs {
		if a == addr || a == netip.IPv6Unspecified() || (a == netip.IPv4Unspecified() && addr.Is4()) {
			return TriYes
		}
	}
	return TriNo
}

// Listeners reads the LISTEN sockets on port (0 means DefaultPort, as for
// Prober.Port) from net/tcp and net/tcp6. A line is "sl: local rem st …":
// local is <hex address>:<hex port>, state 0A is LISTEN (01BB is :443). The
// address is printed as the kernel's 32-bit words in host byte order — one
// word for IPv4 ("0100007F" is 127.0.0.1 on a little-endian host), four for
// IPv6 — so it is decoded with binary.NativeEndian. net/tcp6 absent
// (fs.ErrNotExist) while net/tcp was read means no IPv6 sockets exist; any
// other failure leaves the Listeners unknown, with the error.
//
// The file lists every TCP socket on the box, and an edge node under load has
// many: read it only when a probe was refused (Tick.Listening), never on
// every tick. ctx bounds the reading, as for Proc.Tick.
func (p Proc) Listeners(ctx context.Context, port uint16) (Listeners, error) {
	if port == 0 {
		port = DefaultPort
	}
	fsys := p.fsys()
	var l Listeners
	collect := func(line []byte) {
		if addr, ok := procListener(line, port); ok {
			l.addrs = append(l.addrs, addr)
		}
	}
	if err := procScan(ctx, fsys, "net/tcp", collect); err != nil {
		return Listeners{}, err
	}
	if err := procScan(ctx, fsys, "net/tcp6", collect); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Listeners{}, err
	}
	l.known = true
	return l, nil
}

// procListener reads one net/tcp{,6} line and returns its local address when
// the socket is in LISTEN on port. The state is looked at first: on a loaded
// box nearly every line is an established connection.
func procListener(line []byte, port uint16) (netip.Addr, bool) {
	st, err := strconv.ParseUint(string(procField(line, 3)), 16, 8)
	if err != nil || st != procListen {
		return netip.Addr{}, false
	}
	hexAddr, hexPort, ok := bytes.Cut(procField(line, 1), []byte(":"))
	if !ok {
		return netip.Addr{}, false
	}
	p, err := strconv.ParseUint(string(hexPort), 16, 16)
	if err != nil || uint16(p) != port {
		return netip.Addr{}, false
	}
	return procWordsAddr(hexAddr)
}

// Process is the terminator master's state, for the report only.
type Process struct {
	State PIDState
	// Frozen: the state letter is T (stopped), t (tracing stop) or Z
	// (zombie). It catches SIGSTOP and ptrace, not a real hang (D3).
	Frozen bool
}

// Process reads <pid>/stat. A pid of 0 or less (no pid file, or none read) is
// PIDUnknown. A missing stat (fs.ErrNotExist) is PIDGone only in a tree that
// shows this reader the whole process table — it lists pid 1, which is
// root's — and PIDUnknown in one that does not: a darwin host's absent /proc,
// or a /proc mounted hidepid=invisible (systemd's ProtectProc=invisible) read
// by a user other than root, which hides pid 1 as it hides a live master of
// root's. self is no such sign: every reader sees its own. The dead state X
// (x on old kernels) is PIDGone too. Another failure to read or parse is
// PIDUnknown; otherwise PIDAlive. The state letter is the first field after
// the LAST ')': the command name in parentheses may itself hold spaces and
// parentheses.
func (p Proc) Process(pid int) Process {
	if pid <= 0 {
		return Process{}
	}
	fsys := p.fsys()
	raw, err := fs.ReadFile(fsys, strconv.Itoa(pid)+"/stat")
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := fs.Stat(fsys, "1"); err != nil {
			return Process{}
		}
		return Process{State: PIDGone}
	}
	if err != nil {
		return Process{}
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return Process{}
	}
	f := bytes.Fields(raw[end+1:])
	if len(f) == 0 || len(f[0]) != 1 {
		return Process{}
	}
	switch c := f[0][0]; {
	case c == 'X' || c == 'x':
		return Process{State: PIDGone}
	case c == 'T' || c == 't' || c == 'Z':
		return Process{State: PIDAlive, Frozen: true}
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z':
		return Process{State: PIDAlive}
	}
	return Process{}
}

// Tick is one tick's view of the kernel through a Proc, shared by every
// target that tick. Each source is read on first need, and only when an
// asked address needs it: the interface list, then fib_trie, for an IPv4
// address; if_inet6, then ipv6_route, for an IPv6 one; the listener table
// only when Listening is asked — after a refused probe. Each is read once,
// except that a route table is read again while its readings left an answer
// open (Local). Safe for concurrent use: targets are observed concurrently.
type Tick struct {
	p    Proc
	port uint16
	// ctx is the tick's: it bounds every file reading the tick makes (Proc.Tick).
	ctx context.Context
	// ifaddrs4 is the interface list; nil when there is none.
	ifaddrs4 func() ([]netip.Addr, error)

	addrs4    procLazy[map[netip.Addr]bool]
	trie      procReread
	inet6     procLazy[map[netip.Addr]bool]
	routes    procReread
	v6Off     procLazy[bool]
	listeners procLazy[Listeners]

	// errMu guards what Err reads — each source's error and the re-read
	// tables' state — which a reading in another goroutine may be writing.
	errMu sync.Mutex
}

var _ Kernel = (*Tick)(nil)

// Tick starts one tick's view; port is the probed port (DefaultPort on a
// node). ctx bounds the tick's file readings, every target's alike: it is
// looked at before each read(), and the kernel serves these files a page per
// read(), so a reading stops within a page of ctx's end. A reading cut short
// is that source's error (Err) for the rest of the tick, and what only it
// could have told is TriUnknown, which holds. The interface list is no file,
// and is asked whatever ctx says.
//
// So a ctx shorter than one reading of a full table (Local) leaves an AnyIP
// address, or one that is gone, unknown at every tick, never Unbound: a
// sampler that must see those on such a box reads the table off its ticks'
// deadline.
func (p Proc) Tick(ctx context.Context, port uint16) *Tick {
	return &Tick{p: p, port: port, ctx: ctx, ifaddrs4: p.ifaddrs4()}
}

// procLazy is one reading a tick makes at most once, on first need.
type procLazy[T any] struct {
	once sync.Once
	v    T
	err  error
}

// procGet makes l's reading on first call, and returns it. The values are
// written under t.errMu, so Err may read the error at any time.
func procGet[T any](t *Tick, l *procLazy[T], read func() (T, error)) (T, error) {
	l.once.Do(func() {
		v, err := read()
		t.errMu.Lock()
		l.v, l.err = v, err
		t.errMu.Unlock()
	})
	return l.v, l.err
}

// procReread is a route table a tick reads again while an answer stays open:
// the LOCAL prefixes its readings listed, and whether a "no" can be answered
// yet. mu serialises the readings; every field is written under both mu and
// the Tick's errMu.
type procReread struct {
	mu       sync.Mutex
	readings int
	local    []netip.Prefix
	// settled: an address no reading listed is not held.
	settled bool
	// err is the failure that ended the readings.
	err error
}

// answer is TriYes when a reading listed a prefix covering addr, TriNo when
// none did and the readings settled, and TriUnknown otherwise.
func (r *procReread) answer(addr netip.Addr) Tri {
	switch {
	case procCovered(r.local, addr):
		return TriYes
	case r.settled:
		return TriNo
	}
	return TriUnknown
}

// Local reports whether the kernel holds addr; an IPv4-mapped address is
// taken as the IPv4 address it maps, and a zone is dropped. An invalid addr
// is TriUnknown.
//
//   - IPv4: TriYes when the interface list (Proc.Ifaddrs4) has it, and then
//     no file is read; or when a LOCAL entry of fib_trie covers it — a
//     host's own /32, or a whole local prefix (AnyIP: `ip route add local P
//     dev lo`). TriNo only from a whole reading of fib_trie (procFibTrie)
//     with no such entry. A reading that is not whole is followed by
//     another, up to three in all, and the prefixes of every reading count.
//     TriUnknown when none was whole, or fib_trie could not be read.
//   - IPv6: TriYes when if_inet6 lists it usable, or when an RTF_LOCAL route
//     of ipv6_route covers it; ipv6_route is read only for an address
//     if_inet6 does not list usable. A listing flagged tentative (0x40) or
//     dadfailed (0x08) counts as absent: such an address has no local route
//     and receives nothing — unless it is optimistic, and already has its
//     /128 local route, or lies in an AnyIP range; ipv6_route says yes for
//     those, as the kernel does. ipv6_route is no snapshot either, and has
//     nothing to check it by, so TriNo needs if_inet6 and two readings of it
//     that both lack the address; and the kernel without IPv6 — neither file
//     exists, beside a fib_trie — holds no IPv6 address. TriUnknown
//     otherwise.
//
// The files are streamed, never held whole. That bounds the memory a full
// table costs, not the time. The kernel serves fib_trie and ipv6_route one
// page per read(), and walks its table from the start for each, so one
// reading of n routes costs O(n²): about 30 s for 1M IPv4 routes, several
// times that with the tables merged (no ip rule: Main: and Local: print the
// same trie), and about 15 s for 100k IPv6 routes. That is why the steady
// state reads neither. A VIP on an interface is answered by the interface
// list or by if_inet6, and only an AnyIP range or an address that is gone
// sends a tick to a route table.
func (t *Tick) Local(addr netip.Addr) Tri {
	if !addr.IsValid() {
		return TriUnknown
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return t.local4(addr)
	}
	return t.local6(addr)
}

func (t *Tick) local4(addr netip.Addr) Tri {
	if listed, err := t.interfaces(); err == nil && listed[addr] {
		return TriYes
	}
	r := &t.trie
	r.mu.Lock()
	defer r.mu.Unlock()
	for !procCovered(r.local, addr) && t.trieOpen() {
		t.readTrie()
	}
	return r.answer(addr)
}

func (t *Tick) local6(addr netip.Addr) Tri {
	usable, errUsable := t.ifInet6()
	if errUsable == nil && usable[addr] {
		return TriYes
	}
	r := &t.routes
	r.mu.Lock()
	defer r.mu.Unlock()
	// A reading after the first only confirms a "no", and a "no" needs
	// if_inet6 read too.
	for !procCovered(r.local, addr) && t.routesOpen() && (r.readings == 0 || errUsable == nil) {
		t.readRoutes()
	}
	switch r.answer(addr) {
	case TriYes:
		return TriYes
	case TriNo:
		if errUsable == nil {
			return TriNo
		}
	}
	if t.ipv6Off(errUsable, r.err) {
		return TriNo
	}
	return TriUnknown
}

// interfaces is the interface list as a set, read once; nil without a list.
func (t *Tick) interfaces() (map[netip.Addr]bool, error) {
	if t.ifaddrs4 == nil {
		return nil, nil
	}
	return procGet(t, &t.addrs4, func() (map[netip.Addr]bool, error) {
		addrs, err := t.ifaddrs4()
		if err != nil {
			return nil, err
		}
		set := make(map[netip.Addr]bool, len(addrs))
		for _, a := range addrs {
			set[a.Unmap().WithZone("")] = true
		}
		return set, nil
	})
}

func (t *Tick) ifInet6() (map[netip.Addr]bool, error) {
	return procGet(t, &t.inet6, func() (map[netip.Addr]bool, error) { return procReadIfInet6(t.ctx, t.p.fsys()) })
}

// trieOpen reports whether another reading of fib_trie may still settle an
// answer. The caller holds t.trie.mu, as for readTrie.
func (t *Tick) trieOpen() bool {
	return !t.trie.settled && t.trie.err == nil && t.trie.readings < procTrieReadings
}

func (t *Tick) readTrie() {
	local, whole, err := procReadFibTrie(t.ctx, t.p.fsys())
	t.record(&t.trie, local, whole, err)
}

// routesOpen and readRoutes are trieOpen and readTrie for ipv6_route, which
// settles on its second reading. The caller holds t.routes.mu.
func (t *Tick) routesOpen() bool {
	return !t.routes.settled && t.routes.err == nil && t.routes.readings < procRouteReadings
}

func (t *Tick) readRoutes() {
	local, err := procReadIPv6Route(t.ctx, t.p.fsys())
	t.record(&t.routes, local, t.routes.readings+1 == procRouteReadings, err)
}

// record adds one reading to r, whose mu the caller holds: its prefixes and
// whether it settles r, or the error that ends r's readings.
func (t *Tick) record(r *procReread, local []netip.Prefix, settles bool, err error) {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	r.readings++
	if err != nil {
		r.err = err
		return
	}
	r.local = append(r.local, local...)
	r.settled = settles
}

// ipv6Off reports whether the kernel runs without IPv6 (booted with
// ipv6.disable=1): if_inet6 and ipv6_route both absent, beside a fib_trie —
// which is what tells such a /proc from no /proc at all. A stat, not a
// reading: an IPv6 question never reads the IPv4 table.
func (t *Tick) ipv6Off(errUsable, errRoutes error) bool {
	if !errors.Is(errUsable, fs.ErrNotExist) || !errors.Is(errRoutes, fs.ErrNotExist) {
		return false
	}
	off, _ := procGet(t, &t.v6Off, func() (bool, error) {
		_, err := fs.Stat(t.p.fsys(), "net/fib_trie")
		return err == nil, nil
	})
	return off
}

// readAll makes every reading Local could make for some address: fib_trie
// until one is whole, if_inet6, and ipv6_route twice.
func (t *Tick) readAll() {
	t.trie.mu.Lock()
	for t.trieOpen() {
		t.readTrie()
	}
	t.trie.mu.Unlock()
	_, errUsable := t.ifInet6()
	t.routes.mu.Lock()
	defer t.routes.mu.Unlock()
	for t.routesOpen() && (t.routes.readings == 0 || errUsable == nil) {
		t.readRoutes()
	}
	t.ipv6Off(errUsable, t.routes.err)
}

// Listening is Listeners.Covers over this tick's reading of the port.
func (t *Tick) Listening(addr netip.Addr) Tri {
	l, _ := procGet(t, &t.listeners, func() (Listeners, error) { return t.p.Listeners(t.ctx, t.port) })
	return l.Covers(addr)
}

// Err joins the errors of the reads this tick made (nil when none failed), for
// Report.ProcErr: a source that could not be read, and errFibTrieTorn when
// three readings of fib_trie were none of them whole. Both IPv6 files absent
// from a kernel without IPv6 are no error.
func (t *Tick) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	errs := []error{t.addrs4.err, t.trie.err}
	if t.trie.err == nil && !t.trie.settled && t.trie.readings == procTrieReadings {
		errs = append(errs, errFibTrieTorn)
	}
	if !t.v6Off.v {
		errs = append(errs, t.inet6.err, t.routes.err)
	}
	return errors.Join(append(errs, t.listeners.err)...)
}

// procScan hands each line of the file name to fn, which must not keep it.
// The file is streamed, never held whole, and ctx is looked at before each
// read(): once it has ended, the scan stops with its error.
func procScan(ctx context.Context, fsys fs.FS, name string, fn func(line []byte)) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(procCtxReader{ctx: ctx, r: f})
	for s.Scan() {
		fn(s.Bytes())
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
}

// procCtxReader is r, read only while ctx has not ended.
type procCtxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c procCtxReader) Read(b []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(b)
}

// procField is the i-th (from 0) space-separated field of line — the kernel
// pads these files with spaces only — or nil when there are fewer. It
// allocates nothing: the files can run to hundreds of thousands of lines.
func procField(line []byte, i int) []byte {
	for {
		line = bytes.TrimLeft(line, " ")
		if len(line) == 0 {
			return nil
		}
		end := bytes.IndexByte(line, ' ')
		if end < 0 {
			end = len(line)
		}
		if i == 0 {
			return line[:end]
		}
		line, i = line[end:], i-1
	}
}

// procAddr6 decodes 32 hex digits printed in network byte order (%pi6), as
// if_inet6 and ipv6_route print addresses.
func procAddr6(h []byte) (netip.Addr, bool) {
	var b [16]byte
	if len(h) != 2*len(b) {
		return netip.Addr{}, false
	}
	if _, err := hex.Decode(b[:], h); err != nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16(b), true
}

// procWordsAddr decodes net/tcp{,6}'s address: the kernel prints each 32-bit
// word of the network-order address with %08X, as an integer in its own byte
// order, so each word goes back to bytes through binary.NativeEndian. One
// word is IPv4; four are IPv6, unmapped when they hold an IPv4-mapped address.
func procWordsAddr(h []byte) (netip.Addr, bool) {
	if len(h) != 8 && len(h) != 32 {
		return netip.Addr{}, false
	}
	var b [16]byte
	for i := range len(h) / 8 {
		w, err := strconv.ParseUint(string(h[8*i:8*i+8]), 16, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		binary.NativeEndian.PutUint32(b[4*i:], uint32(w))
	}
	if len(h) == 8 {
		return netip.AddrFrom4([4]byte(b[:4])), true
	}
	return netip.AddrFrom16(b).Unmap(), true
}

// procCovered reports whether a prefix of prefixes contains addr.
func procCovered(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

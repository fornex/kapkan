package steer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"sync"
)

// Proc reads the kernel's view of this box from a /proc tree — never netlink
// (D5): the unit grants no AF_NETLINK, which is worth keeping, and a bare
// bind() would be blind under ip_nonlocal_bind=1, a common setting on anycast
// and keepalived hosts. The zero value reads the host's /proc.
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
}

// HostProc reads the host's /proc.
func HostProc() Proc { return Proc{FS: os.DirFS("/proc")} }

func (p Proc) fsys() fs.FS {
	if p.FS == nil {
		return os.DirFS("/proc")
	}
	return p.FS
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

// Locals is the kernel's local address space at one reading. The zero value
// has read nothing, and answers TriUnknown for every address.
type Locals struct {
	// v4 are fib_trie's LOCAL prefixes, from every table.
	v4      []netip.Prefix
	v4Known bool
	// v6 holds the addresses if_inet6 lists usable: neither tentative nor
	// dadfailed.
	v6      map[netip.Addr]bool
	v6Known bool
	// v6Routes are ipv6_route's RTF_LOCAL prefixes: every usable address's
	// own /128, an optimistic address's (still tentative, and already
	// receiving), and the AnyIP ranges (`ip -6 route add local P dev lo`)
	// that if_inet6 does not list.
	v6Routes      []netip.Prefix
	v6RoutesKnown bool
	// v6Off: neither IPv6 file exists — the kernel runs without IPv6.
	v6Off bool
}

// Has reports whether the kernel holds addr (an IPv4-mapped address is taken
// as the IPv4 address it maps):
//
//   - IPv4: TriYes when a LOCAL entry of fib_trie covers it — a host's own
//     /32, or a whole local prefix (AnyIP: `ip route add local P dev lo`);
//     TriNo when none does; TriUnknown when fib_trie could not be read.
//   - IPv6: TriYes when if_inet6 lists it usable, or when an RTF_LOCAL route
//     of ipv6_route covers it. A listing flagged tentative (0x40) or
//     dadfailed (0x08) counts as absent: such an address has no local route
//     and receives nothing — unless it is optimistic, and already has its
//     /128 local route, or lies in an AnyIP range; ipv6_route says yes for
//     those, as the kernel does. TriNo when both files were read and neither
//     says yes, or when the kernel runs without IPv6; TriUnknown otherwise:
//     a file that could have said yes was not read.
//
// An invalid addr is TriUnknown.
func (l Locals) Has(addr netip.Addr) Tri {
	if !addr.IsValid() {
		return TriUnknown
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		if !l.v4Known {
			return TriUnknown
		}
		return procTri(procCovered(l.v4, addr))
	}
	switch {
	case l.v6Off:
		return TriNo
	case l.v6Known && l.v6[addr], l.v6RoutesKnown && procCovered(l.v6Routes, addr):
		return TriYes
	case l.v6Known && l.v6RoutesKnown:
		return TriNo
	}
	return TriUnknown
}

// Locals reads the local address space from net/fib_trie (IPv4), and
// net/if_inet6 and net/ipv6_route (IPv6).
//
// fib_trie is a tree per table ("Main:", "Local:", "Id 100:"); a leaf line
// "|-- 192.0.2.10" is followed by one line per route on that key, "/32 host
// LOCAL" (a tos=N may follow). Every "/<len> <scope> LOCAL" line makes
// <leaf>/<len> local, whatever its table — reading more as local can only
// hold an address in. if_inet6 has one address per line: 32 hex digits, then
// ifindex, prefix length, scope and flags in hex, then the device name.
// ipv6_route has one route per line: destination (32 hex digits), its prefix
// length (hex), source, its length, next hop, metric, refcount, use, flags
// (hex; RTF_LOCAL is 0x80000000), device.
//
// A file that cannot be read leaves unknown what only it could have told,
// and its error is returned beside a Locals that still answers from the
// others — except that if_inet6 and ipv6_route both absent (fs.ErrNotExist)
// while fib_trie was read means the kernel runs without IPv6
// (ipv6.disable=1): every IPv6 address is then TriNo, and that is no error.
// Malformed lines are skipped, never fatal.
//
// The files are streamed, never held whole: a box that carries a full table
// in its kernel lists every route of it in fib_trie and ipv6_route.
func (p Proc) Locals() (Locals, error) {
	fsys := p.fsys()
	var l Locals

	var trie procFibTrie
	errTrie := procScan(fsys, "net/fib_trie", trie.line)
	if errTrie == nil {
		l.v4, l.v4Known = trie.local, true
	}

	usable := make(map[netip.Addr]bool)
	errAddrs := procScan(fsys, "net/if_inet6", func(line []byte) {
		if addr, ok := procUsableAddr6(line); ok {
			usable[addr] = true
		}
	})
	if errAddrs == nil {
		l.v6, l.v6Known = usable, true
	}

	var routes []netip.Prefix
	errRoutes := procScan(fsys, "net/ipv6_route", func(line []byte) {
		if p, ok := procLocalRoute6(line); ok {
			routes = append(routes, p)
		}
	})
	if errRoutes == nil {
		l.v6Routes, l.v6RoutesKnown = routes, true
	}

	if errTrie == nil && errors.Is(errAddrs, fs.ErrNotExist) && errors.Is(errRoutes, fs.ErrNotExist) {
		// Booted with ipv6.disable=1: there is no IPv6 to hold anything with.
		// fib_trie read is what tells this from a tree with no files at all.
		l.v6Off = true
		return l, nil
	}
	return l, errors.Join(errTrie, errAddrs, errRoutes)
}

// procFibTrie reads fib_trie's lines in order, remembering the last leaf: a
// route line belongs to the leaf above it. An inner node ("+-- 10.0.0.0/8 2 0
// 2") ends a leaf's routes; anything it does not recognise is passed over.
type procFibTrie struct {
	leaf    []byte
	hasLeaf bool
	local   []netip.Prefix
}

func (t *procFibTrie) line(raw []byte) {
	line := bytes.TrimLeft(raw, " ")
	switch {
	case bytes.HasPrefix(line, []byte("|--")):
		t.leaf = append(t.leaf[:0], bytes.TrimSpace(line[len("|--"):])...)
		t.hasLeaf = true
	case bytes.HasPrefix(line, []byte("+--")):
		t.hasLeaf = false
	case t.hasLeaf && bytes.HasPrefix(line, []byte("/")):
		if p, ok := procLocalRoute4(t.leaf, line); ok {
			t.local = append(t.local, p)
		}
	}
}

// procLocalRoute4 reads one route line, "/<len> <scope> <type>[ tos=N]",
// under leaf: <leaf>/<len> when the type is LOCAL. Only LOCAL lines are
// parsed further — they are a handful among what can be a million routes.
func procLocalRoute4(leaf, line []byte) (netip.Prefix, bool) {
	if string(procField(line, 2)) != "LOCAL" {
		return netip.Prefix{}, false
	}
	bits, err := strconv.Atoi(string(procField(line, 0)[1:]))
	if err != nil {
		return netip.Prefix{}, false
	}
	addr, err := netip.ParseAddr(string(leaf))
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	p, err := addr.Prefix(bits)
	return p, err == nil
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
// every tick.
func (p Proc) Listeners(port uint16) (Listeners, error) {
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
	if err := procScan(fsys, "net/tcp", collect); err != nil {
		return Listeners{}, err
	}
	if err := procScan(fsys, "net/tcp6", collect); err != nil && !errors.Is(err, fs.ErrNotExist) {
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
// PIDUnknown. A missing stat (fs.ErrNotExist) is PIDGone in a tree that is a
// process table — it has self — and PIDUnknown in one that is not, such as a
// darwin host's absent /proc; the dead state X (x on old kernels) is PIDGone
// too. Another failure to read or parse is PIDUnknown; otherwise PIDAlive.
// The state letter is the first field after the LAST ')': the command name in
// parentheses may itself hold spaces and parentheses.
func (p Proc) Process(pid int) Process {
	if pid <= 0 {
		return Process{}
	}
	fsys := p.fsys()
	raw, err := fs.ReadFile(fsys, strconv.Itoa(pid)+"/stat")
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := fs.Stat(fsys, "self"); err != nil {
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
// target that tick: the local addresses are read on first use, the listener
// table only when Listening is asked — after a refused probe — and each at
// most once. Safe for concurrent use: targets are observed concurrently.
type Tick struct {
	p    Proc
	port uint16

	localsOnce sync.Once
	locals     Locals
	localsErr  error

	listenersOnce sync.Once
	listeners     Listeners
	listenersErr  error

	// errMu guards the two errors: Err may run while another goroutine is
	// inside one of the Onces.
	errMu sync.Mutex
}

var _ Kernel = (*Tick)(nil)

// Tick starts one tick's view; port is the probed port (DefaultPort on a
// node).
func (p Proc) Tick(port uint16) *Tick { return &Tick{p: p, port: port} }

// Local is Locals.Has over this tick's reading.
func (t *Tick) Local(addr netip.Addr) Tri {
	t.localsOnce.Do(func() {
		l, err := t.p.Locals()
		t.locals = l
		t.errMu.Lock()
		t.localsErr = err
		t.errMu.Unlock()
	})
	return t.locals.Has(addr)
}

// Listening is Listeners.Covers over this tick's reading of the port.
func (t *Tick) Listening(addr netip.Addr) Tri {
	t.listenersOnce.Do(func() {
		l, err := t.p.Listeners(t.port)
		t.listeners = l
		t.errMu.Lock()
		t.listenersErr = err
		t.errMu.Unlock()
	})
	return t.listeners.Covers(addr)
}

// Err joins the errors of the reads this tick made (nil when none failed), for
// Report.ProcErr.
func (t *Tick) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return errors.Join(t.localsErr, t.listenersErr)
}

// procScan hands each line of the file name to fn, which must not keep it.
// The file is streamed, never held whole.
func procScan(fsys fs.FS, name string, fn func(line []byte)) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fn(s.Bytes())
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
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

func procTri(yes bool) Tri {
	if yes {
		return TriYes
	}
	return TriNo
}

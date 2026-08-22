//go:build linux

package dataplane

// Kernel-side smoke tests. They load the committed object into a real kernel
// and drive it with BPF_PROG_TEST_RUN, which is the only way to find out
// whether the verifier accepts the program — "it compiles" says nothing.
//
// On the macOS development host these do not build (the file is linux-only)
// and smoke_other_test.go skips in their place. To run them:
//
//	cd engine
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/dp.test ./internal/dataplane/
//	docker run --rm --privileged -e KAPKAN_DATAPLANE=require \
//	    -v "$PWD/..:/w" -w /w/engine/internal/dataplane \
//	    alpine:3.20 /tmp/dp.test -test.v
//
// KAPKAN_DATAPLANE=require is not decoration: without it, a container that has
// quietly stopped being privileged runs this file as a few dozen skips and
// exits 0. See kernelgate_linux_test.go.
//
// (see engine/bpf/README.md for the full recipe, including the mount that lets
// the drift tests read the C header).

import (
	"encoding/binary"
	"errors"
	"regexp"
	"strconv"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	xdpAborted  = 0
	xdpDrop     = 1
	xdpPass     = 2
	xdpRedirect = 4
)

func verdictName(v uint32) string {
	switch v {
	case xdpAborted:
		return "XDP_ABORTED"
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	case 3:
		return "XDP_TX"
	case xdpRedirect:
		return "XDP_REDIRECT"
	}
	return "XDP_?"
}

// loadObjects loads the embedded object into the kernel. Failure here is a
// verifier rejection nine times out of ten, so the log is dumped verbatim.
//
// The one failure that is NOT a bug is EPERM: loading an XDP program needs
// CAP_BPF (or CAP_SYS_ADMIN), and `make test` runs unprivileged on CI. That
// case skips. Everything else — and in particular a *ebpf.VerifierError, which
// the kernel reports as EACCES and which is the exact thing these tests exist
// to catch — is fatal. The two are checked in that order so a rejection can
// never be mistaken for a missing capability and quietly skipped.
func loadObjects(t *testing.T) *kapkanXDPObjects {
	t.Helper()

	// The gate first, so a host with no right to call bpf(2) declines here with
	// one clear message instead of at whichever syscall happens to be next.
	// See kernelgate_linux_test.go.
	requireBPF(t)

	if err := rlimit.RemoveMemlock(); err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("RemoveMemlock: %v", err)
	}

	var objs kapkanXDPObjects
	err := loadKapkanXDPObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected the program:\n%+v", ve)
		}
		skipIfUnprivileged(t, err)
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// skipIfUnprivileged skips the test when the kernel refused for lack of
// CAP_BPF/CAP_SYS_ADMIN. Deliberately narrow: only EPERM, never EACCES (which
// is what a verifier rejection looks like).
//
// Still reachable after requireBPF has passed, and that is not redundant: the
// gate proves this process may CREATE MAPS (CAP_BPF), while loading an XDP
// program additionally needs CAP_NET_ADMIN and CAP_PERFMON. A process holding
// the first and not the others lands here. It exits through skipOrFail so that
// case cannot silently deflate the `require` runs either.
func skipIfUnprivileged(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) {
		skipOrFail(t, "need CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON to load an XDP program (%v); "+
			"run `make dataplane-test` for the privileged-container loop", err)
	}
}

// setCfg writes kapkan_cfg[0]. Every test sets it explicitly so a test never
// depends on the zero value meaning what it happens to mean today. It goes
// through the production helper so the strides and the schema version are the
// ones the manager will write, not a second opinion.
func setCfg(t *testing.T, objs *kapkanXDPObjects, dryRun, dropMalformed bool) {
	t.Helper()
	if err := PutConfig(objs.MapSet(), ConfigSpec{
		DryRun:        dryRun,
		DropMalformed: dropMalformed,
	}); err != nil {
		t.Fatalf("write kapkan_cfg[0]: %v", err)
	}
}

// readStat sums a PERCPU_ARRAY counter across every CPU.
func readStat(t *testing.T, objs *kapkanXDPObjects, s Stat) (pkts, bytes uint64) {
	t.Helper()
	var per []kapkanXDPKapkanCounter
	if err := objs.KapkanStats.Lookup(uint32(s), &per); err != nil {
		t.Fatalf("read stat %s: %v", s, err)
	}
	for _, c := range per {
		pkts += c.Pkts
		bytes += c.Bytes
	}
	return pkts, bytes
}

/* ------------------------------------------------------------- packets */

var (
	dstMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	srcMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

func eth(etherType uint16) []byte {
	p := make([]byte, 0, 14)
	p = append(p, dstMAC...)
	p = append(p, srcMAC...)
	return binary.BigEndian.AppendUint16(p, etherType)
}

func vlanTag(p []byte, vid uint16, inner uint16) []byte {
	p = binary.BigEndian.AppendUint16(p, vid)
	return binary.BigEndian.AppendUint16(p, inner)
}

// ipv4 builds a 20-byte IPv4 header. fragOff is the raw frag_off field
// (flags + offset), so a caller can construct a non-first fragment.
func ipv4(proto uint8, fragOff uint16, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, ihl 5
	binary.BigEndian.PutUint16(h[2:], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(h[6:], fragOff)
	h[8] = 64 // ttl
	h[9] = proto
	copy(h[12:], []byte{198, 51, 100, 7}) // src, TEST-NET-2
	copy(h[16:], []byte{203, 0, 113, 9})  // dst, TEST-NET-3
	return h
}

func ipv6(nextHdr uint8, payloadLen int) []byte {
	h := make([]byte, 40)
	h[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(h[4:], uint16(payloadLen))
	h[6] = nextHdr
	h[7] = 64 // hop limit
	// 2001:db8::1 -> 2001:db8::2, the documentation prefix.
	copy(h[8:], []byte{0x20, 0x01, 0x0d, 0xb8})
	h[23] = 1
	copy(h[24:], []byte{0x20, 0x01, 0x0d, 0xb8})
	h[39] = 2
	return h
}

func tcp(sport, dport uint16, flags uint8) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = 5 << 4 // data offset
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:], 65535)
	return h
}

func udp(sport, dport uint16, payload int) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+payload))
	return h
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeARP  = 0x0806
	etherTypeVLAN = 0x8100
)

/* --------------------------------------------------------------- tests */

// TestLoadAndPass is the load-bearing one: it proves the verifier accepts the
// program and that the whole map set is created. Everything else in this file
// builds on it.
func TestLoadAndPass(t *testing.T) {
	objs := loadObjects(t)
	setCfg(t, objs, false, false)

	pkt := cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(12345, 80, 0x02))
	ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("verdict = %s, want XDP_PASS", verdictName(ret))
	}

	pkts, bytes := readStat(t, objs, StatPassDefault)
	if pkts != 1 {
		t.Errorf("%s pkts = %d, want 1", StatPassDefault, pkts)
	}
	if bytes != uint64(len(pkt)) {
		t.Errorf("%s bytes = %d, want %d", StatPassDefault, bytes, len(pkt))
	}
}

// TestAllMapsCreated proves the maps that the program does not yet reference
// still exist in the kernel after load. They are freeze point F6 and the
// userspace encoder will open them by name, so a map that clang drops as
// unused would only be discovered much later.
func TestAllMapsCreated(t *testing.T) {
	objs := loadObjects(t)

	byName := map[string]*ebpf.Map{
		MapAllow4:    objs.KapkanAllow4,
		MapAllow6:    objs.KapkanAllow6,
		MapProtect4:  objs.KapkanProtect4,
		MapProtect6:  objs.KapkanProtect6,
		MapVictims4:  objs.KapkanVictims4,
		MapVictims6:  objs.KapkanVictims6,
		MapPolicies:  objs.KapkanPolicies,
		MapStatics:   objs.KapkanStatics,
		MapRLSrc4:    objs.KapkanRlSrc4,
		MapRLSrc6:    objs.KapkanRlSrc6,
		MapProfiles:  objs.KapkanProfiles,
		MapCfg:       objs.KapkanCfg,
		MapStats:     objs.KapkanStats,
		MapRuleStats: objs.KapkanRuleStats,
		MapFPEvents:  objs.KapkanFpEvents,
		MapFPSampler: objs.KapkanFpSampler,
	}
	if len(byName) != len(AllMaps) {
		t.Fatalf("this test checks %d maps, AllMaps has %d", len(byName), len(AllMaps))
	}
	for _, name := range AllMaps {
		m, ok := byName[name]
		if !ok || m == nil {
			t.Errorf("map %q was not created", name)
			continue
		}
		info, err := m.Info()
		if err != nil {
			t.Errorf("map %q Info: %v", name, err)
			continue
		}
		t.Logf("%-18s type=%-14v key=%-4d value=%-6d max_entries=%d",
			name, info.Type, info.KeySize, info.ValueSize, info.MaxEntries)
	}

	// The double-buffered maps must be sized for both generations, or a
	// generation flip writes over the live half.
	if got := objs.KapkanPolicies.MaxEntries() % Generations; got != 0 {
		t.Errorf("kapkan_policies max_entries is not a multiple of %d", Generations)
	}
	if got := objs.KapkanStatics.MaxEntries() % Generations; got != 0 {
		t.Errorf("kapkan_statics max_entries is not a multiple of %d", Generations)
	}
	if got := objs.KapkanStats.MaxEntries(); got != uint32(StatMax) {
		t.Errorf("kapkan_stats max_entries = %d, want StatMax = %d", got, StatMax)
	}
}

// TestParserVerdicts drives one packet of each shape the parser knows and
// checks both the verdict and which counter moved. Per the charter, EVERY case
// here must be XDP_PASS: with no rules installed there is nothing that could
// legitimately drop.
func TestParserVerdicts(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		stat Stat
	}{
		{
			name: "ipv4/tcp",
			pkt:  cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(1024, 443, 0x02)),
			stat: StatPassDefault,
		},
		{
			name: "ipv4/udp",
			pkt:  cat(eth(etherTypeIPv4), ipv4(17, 0, 16), udp(53, 33333, 8), make([]byte, 8)),
			stat: StatPassDefault,
		},
		{
			name: "ipv4/icmp",
			pkt:  cat(eth(etherTypeIPv4), ipv4(1, 0, 8), make([]byte, 8)),
			stat: StatPassDefault,
		},
		{
			name: "vlan/ipv4/tcp",
			pkt: cat(vlanTag(eth(etherTypeVLAN), 100, etherTypeIPv4),
				ipv4(6, 0, 20), tcp(1024, 443, 0x12)),
			stat: StatPassDefault,
		},
		{
			// Offset 0x00b9 == 185*8 bytes in, MF clear: a trailing
			// fragment, so there is no L4 header to read.
			name: "ipv4/fragment/non-first",
			pkt:  cat(eth(etherTypeIPv4), ipv4(17, 0x00b9, 32), make([]byte, 32)),
			stat: StatPassFragNoPorts,
		},
		{
			name: "ipv6/tcp",
			pkt:  cat(eth(etherTypeIPv6), ipv6(6, 20), tcp(1024, 80, 0x02)),
			stat: StatPassDefault,
		},
		{
			name: "ipv6/udp",
			pkt:  cat(eth(etherTypeIPv6), ipv6(17, 8), udp(53, 33333, 0)),
			stat: StatPassDefault,
		},
		{
			// One hop-by-hop options header (8 bytes, hdrlen 0) then TCP.
			name: "ipv6/hopopts/tcp",
			pkt: cat(eth(etherTypeIPv6), ipv6(0, 28),
				[]byte{6, 0, 0, 0, 0, 0, 0, 0}, tcp(1024, 80, 0x02)),
			stat: StatPassDefault,
		},
		{
			// A fragment header whose offset is non-zero: no L4.
			name: "ipv6/fragment/non-first",
			pkt: cat(eth(etherTypeIPv6), ipv6(44, 40),
				[]byte{17, 0, 0x0b, 0x98, 0, 0, 0, 1}, make([]byte, 32)),
			stat: StatPassFragNoPorts,
		},
		{
			name: "arp",
			pkt:  cat(eth(etherTypeARP), make([]byte, 28)),
			stat: StatPassNotIP,
		},
		{
			// Nine chained destination-options headers: one more than
			// KAPKAN_MAX_EXT_HDRS, so the walk gives up and passes.
			name: "ipv6/exthdr-cap",
			pkt:  ipv6ExtChain(9),
			stat: StatPassExtHdrCap,
		},
		{
			// A second VLAN tag: QinQ, which the parser counts and passes
			// rather than walking.
			name: "qinq",
			pkt: cat(vlanTag(eth(etherTypeVLAN), 100, etherTypeVLAN),
				[]byte{0x00, 0x64}, []byte{0x08, 0x00},
				ipv4(6, 0, 20), tcp(1024, 443, 0x02)),
			stat: StatPassVLANDepth,
		},
		{
			// Ethernet says IPv4 but only 10 bytes follow.
			name: "truncated-ipv4",
			pkt:  cat(eth(etherTypeIPv4), make([]byte, 10)),
			stat: StatPassMalformed,
		},
		{
			// TCP header cut in half.
			name: "truncated-tcp",
			pkt:  cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(1, 2, 0)[:10]),
			stat: StatPassMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadObjects(t)
			setCfg(t, objs, false, false)

			ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: tc.pkt})
			if err != nil {
				t.Fatalf("PROG_TEST_RUN: %v", err)
			}
			if ret != xdpPass {
				t.Fatalf("verdict = %s, want XDP_PASS (the charter forbids "+
					"dropping with no rules installed)", verdictName(ret))
			}
			if pkts, _ := readStat(t, objs, tc.stat); pkts != 1 {
				t.Errorf("%s = %d, want 1; counters: %s",
					tc.stat, pkts, dumpStats(t, objs))
			}
		})
	}
}

// ipv6ExtChain builds an IPv6 packet with n destination-options headers, used
// to walk past KAPKAN_MAX_EXT_HDRS.
func ipv6ExtChain(n int) []byte {
	var chain []byte
	for i := 0; i < n; i++ {
		next := byte(60) // another dstopts
		if i == n-1 {
			next = 6 // TCP
		}
		chain = append(chain, next, 0, 0, 0, 0, 0, 0, 0)
	}
	body := cat(chain, tcp(1024, 80, 0x02))
	return cat(eth(etherTypeIPv6), ipv6(60, len(body)), body)
}

// dumpStats renders every non-zero counter, so a failing assertion says which
// branch the packet actually took instead of only which one it did not.
func dumpStats(t *testing.T, objs *kapkanXDPObjects) string {
	t.Helper()
	out := ""
	for s := Stat(0); s < StatMax; s++ {
		if p, _ := readStat(t, objs, s); p != 0 {
			out += " " + s.String() + "=" + itoa(p)
		}
	}
	if out == "" {
		return " (all zero)"
	}
	return out
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// TestDropMalformed is the only path in this revision that can return
// XDP_DROP, and only because the operator asked for it.
func TestDropMalformed(t *testing.T) {
	pkt := cat(eth(etherTypeIPv4), make([]byte, 10))

	t.Run("off", func(t *testing.T) {
		objs := loadObjects(t)
		setCfg(t, objs, false, false)
		ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpPass {
			t.Errorf("verdict = %s, want XDP_PASS", verdictName(ret))
		}
		if p, _ := readStat(t, objs, StatPassMalformed); p != 1 {
			t.Errorf("pass_malformed = %d, want 1", p)
		}
	})

	t.Run("on", func(t *testing.T) {
		objs := loadObjects(t)
		setCfg(t, objs, false, true)
		ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpDrop {
			t.Errorf("verdict = %s, want XDP_DROP", verdictName(ret))
		}
		if p, _ := readStat(t, objs, StatDropMalformed); p != 1 {
			t.Errorf("drop_malformed = %d, want 1", p)
		}
	})

	// dry_run rewrites the drop to a pass at the very last moment, AFTER the
	// accounting: drop_malformed must still show the packet, and
	// dryrun_would_drop must show it too, so an operator sees exactly what
	// would have been dropped.
	t.Run("on+dry_run", func(t *testing.T) {
		objs := loadObjects(t)
		setCfg(t, objs, true, true)
		ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{Data: pkt})
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpPass {
			t.Errorf("verdict = %s, want XDP_PASS under dry_run", verdictName(ret))
		}
		if p, _ := readStat(t, objs, StatDropMalformed); p != 1 {
			t.Errorf("drop_malformed = %d, want 1 (dry_run must not skip accounting)", p)
		}
		if p, _ := readStat(t, objs, StatDryRunWouldDrop); p != 1 {
			t.Errorf("dryrun_would_drop = %d, want 1", p)
		}
	})
}

// verifierComplexityBudget is the kernel's cap on instructions PROCESSED
// during verification for a privileged program (BPF_COMPLEXITY_LIMIT_INSNS).
// It is not a cap on program length: the verifier walks every reachable path,
// so a loop with branches inside it costs far more than its size suggests.
//
// This is the number that nearly stopped the packet path. A first cut with the
// decision helpers inlined processed 979,105 of these — 97.9% — and a later
// revision actually blew the limit outright ("BPF program is too large.
// Processed 1000001 insn"). The fix was structural, not cosmetic: see the
// function-shape note at the top of kapkan_xdp.c. The test prints the headroom
// on every run precisely because that headroom is the thing that silently
// erodes.
const verifierComplexityBudget = 1_000_000

// processedInsnsRe pulls the instruction count out of the verifier's own log.
//
// This is the PORTABLE source for that number, and the reason it exists rather
// than reading bpf_prog_info alone: `verified_insns` was added to
// bpf_prog_info in 5.16 (aba64c7da983), which is ABOVE kapkan's 5.15 floor. On
// 5.15 the field reads back as zero and Info().VerifiedInstructions() reports
// "not available", so a test that insisted on it failed on the exact kernel
// the project promises to support. The verifier's trailing summary line —
// "processed N insns (limit 1000000) max_states_per_insn ..." — is emitted at
// log_level>=1 on every kernel in the matrix, 5.15 included.
var processedInsnsRe = regexp.MustCompile(`processed (\d+) insns`)

// logTail returns the last n bytes of s, for putting a verifier log into a
// failure message without printing all of it.
func logTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// TestProgramSize reports the three numbers that matter and fails only if the
// verifier is already close to its limit.
func TestProgramSize(t *testing.T) {
	spec, err := loadKapkanXDP()
	if err != nil {
		t.Fatal(err)
	}
	insns := spec.Programs[ProgramName].Instructions
	slots := insns.Size() / 8 // raw 8-byte slots; a 64-bit imm load takes two

	objs := loadObjects(t)

	// loadObjects asks for LogLevelInstruction, so the program carries the
	// verifier's log even though the load succeeded.
	log := objs.KapkanXdpFilter.VerifierLog
	m := processedInsnsRe.FindStringSubmatch(log)
	if m == nil {
		t.Fatalf("verifier log has no 'processed N insns' line; "+
			"cannot measure complexity. Log tail:\n%s", logTail(log, 512))
	}
	processed, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatalf("parsing %q from the verifier log: %v", m[1], err)
	}

	// Cross-check against bpf_prog_info where the kernel offers it. Kept as a
	// consistency check rather than the primary source: see processedInsnsRe.
	info, err := objs.KapkanXdpFilter.Info()
	if err != nil {
		t.Fatalf("program Info: %v", err)
	}
	if reported, ok := info.VerifiedInstructions(); !ok {
		t.Logf("bpf_prog_info.verified_insns is unavailable on this kernel "+
			"(added in 5.16, below it is zero); using the verifier log's %d",
			processed)
	} else if uint64(reported) != processed {
		t.Errorf("bpf_prog_info says %d verified insns, the verifier log says %d",
			reported, processed)
	}

	t.Logf("kapkan_xdp_filter: %d instructions (%d raw slots) in the ELF; "+
		"verifier processed %d insns = %.1f%% of the %d budget",
		len(insns), slots, processed,
		100*float64(processed)/float64(verifierComplexityBudget),
		verifierComplexityBudget)

	// A tripwire, not a target. The whole packet path currently sits around
	// 8% of the budget; anything that pushes it past half means a change has
	// reintroduced the path multiplication the global functions exist to
	// prevent, and that needs fixing before more code goes in, not after.
	if processed > verifierComplexityBudget/2 {
		t.Errorf("verifier processed %d insns, over half the %d budget — "+
			"something has reintroduced per-path re-verification of the rule "+
			"scans; see the function-shape note in kapkan_xdp.c",
			processed, verifierComplexityBudget)
	}
}

// BenchmarkXDPFilter measures the datapath with the kernel's own repeat loop,
// which is the same path used for capacity numbers.
func BenchmarkXDPFilter(b *testing.B) {
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	var objs kapkanXDPObjects
	if err := loadKapkanXDPObjects(&objs, nil); err != nil {
		b.Fatalf("load: %v", err)
	}
	defer func() { _ = objs.Close() }()

	if err := PutConfig(objs.MapSet(), ConfigSpec{}); err != nil {
		b.Fatal(err)
	}

	pkt := cat(eth(etherTypeIPv4), ipv4(6, 0, 20), tcp(1024, 443, 0x02))

	b.ResetTimer()
	ret, err := objs.KapkanXdpFilter.Run(&ebpf.RunOptions{
		Data:   pkt,
		Repeat: uint32(b.N),
	})
	if err != nil {
		b.Fatal(err)
	}
	if ret != xdpPass {
		b.Fatalf("verdict = %s", verdictName(ret))
	}
}

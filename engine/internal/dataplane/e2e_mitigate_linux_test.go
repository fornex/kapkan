//go:build linux

// Package dataplane_test holds the ONE test that spans the whole feature:
// synthetic telemetry in, a dropped packet out.
//
// It is an EXTERNAL test package (dataplane_test, not dataplane) for a
// structural reason, not a stylistic one: internal/mitigate imports
// internal/dataplane, so a file in `package dataplane` that imported the
// mitigator would be an import cycle. An external test package sits outside
// both and can drive the real detector, the real mitigator and the real kernel
// in one process. It compiles into the same test binary, so `make
// dataplane-test` runs it with everything else.
//
// It reaches the loaded program through its BPFFS PIN rather than through any
// accessor, which is a happy accident of the same constraint: nothing here can
// see a Manager's private fields, so the program under test is necessarily the
// pinned one an operator's kernel would be running.
package dataplane_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/pkg/flowgen"
	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

const (
	xdpDrop = 1
	xdpPass = 2
)

func verdict(v uint32) string {
	switch v {
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	default:
		return fmt.Sprintf("XDP_%d", v)
	}
}

// e2eYAML is a LIVE (not dry-run) config whose global ladder drops in the
// kernel, with thresholds low enough that a couple of seconds of synthetic
// telemetry trips them.
func e2eYAML(pinPath string) string {
	return fmt.Sprintf(`dry_run: false
listen:
  netflow: ":0"
sampling:
  default_rate: 1
networks:
  - "203.0.113.0/24"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 1000
  mbps: 100000
  flows_per_sec: 1000000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 1
  max_active_bans: 10
escalation:
  - {after_seconds: 0, action: dataplane}
dataplane:
  enabled: true
  interfaces: ["lo"]
  xdp_mode: generic
  pin_path: %q
  on_exit: detach
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:0"
`, pinPath)
}

// TestEndToEndDetectionDropsAPacketInTheKernel is the headline: an NTP
// amplification in synthetic NetFlow-shaped telemetry drives real detection,
// the ban installs real rules in a real kernel, and a crafted reflection packet
// that PASSED before is DROPPED after — while the victim's legitimate traffic
// keeps passing. Then the ban is withdrawn and the attack packet passes again.
func TestEndToEndDetectionDropsAPacketInTheKernel(t *testing.T) {
	dir := e2ePinDir(t)
	cfg, err := config.Parse([]byte(e2eYAML(dir)))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(&testWriter{t}, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if !mitigate.SupportsDataplane() {
		t.Fatal("SupportsDataplane() is false; the ladder rung would resolve to an alert")
	}

	/* ---- the data plane: load, size, attach, install static policy ---- */

	opts, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	opts.Log = log
	opts.WatchInterval = -1
	dataplane.RequireBPF(t)
	mgr, err := dataplane.Open(opts)
	if err != nil {
		// Narrow, not blanket. The gate above already established that bpf(2)
		// works here; the one remaining environment failure is a process that
		// may create maps but not load an XDP program (CAP_BPF without
		// CAP_NET_ADMIN/CAP_PERFMON). Anything else is a bug in the data plane
		// and must stay red — the previous unconditional Skipf turned exactly
		// that into a green run.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, dataplane.ErrMissingCapability) {
			dataplane.SkipOrFail(t, "cannot bring up the data plane here (%v); run `make dataplane-test`", err)
		}
		t.Fatalf("dataplane.Open: %v", err)
	}
	defer func() { _ = mgr.Close(config.OnExitDetach) }()
	t.Logf("data plane: %s", mgr.Health().Summary())

	prog := pinnedProgram(t, dir)
	defer func() { _ = prog.Close() }()

	victim := netip.MustParseAddr("203.0.113.66")
	attack := mustBuild(t, reflectionFrame(victim, 123))
	legit := mustBuild(t, reflectionFrame(victim, 53000))

	/* ---- BEFORE: nothing is installed, so everything passes ---- */

	if got := runPacket(t, prog, attack); got != xdpPass {
		t.Fatalf("BEFORE the ban: attack packet verdict %s, want XDP_PASS", verdict(got))
	}
	t.Logf("BEFORE  attack packet (udp 123 -> %s): %s", victim, verdict(xdpPass))

	/* ---- the mitigator, wired to the data plane ---- */

	mit, err := mitigate.New(store, log, mitigate.WithDataplane(dataplane.NewInstaller(mgr, log)))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mit.Start(ctx); err != nil {
		t.Fatalf("mitigate.Start: %v", err)
	}
	defer mit.Stop()

	/* ---- detection, from synthetic telemetry ---- */

	eng := engine.New(store, engine.WithLogger(log), engine.WithWindow(2))
	go eng.Run(ctx)

	ev := driveAttack(t, ctx, eng, victim)
	t.Logf("DETECTED %s on %s: %s %.0f (threshold %.0f), classification %q",
		ev.Kind, ev.Target, ev.Metric, ev.Rate, ev.Threshold, classOf(ev))

	ban := mit.OnAttackStarted(ev)
	if ban == nil || ban.State != mitigate.BanActive {
		t.Fatalf("ban = %+v, want an active ban", ban)
	}
	if ban.Method != config.MitigateDataplane {
		t.Fatalf("ban method = %q (fell back from %q: %s), want %q — the rules were not installed "+
			"in the kernel", ban.Method, ban.FellBackFrom, ban.FellBackReason, config.MitigateDataplane)
	}
	t.Logf("BANNED  %s -> %s", ban.Target, ban.Route)

	/* ---- AFTER: the attack is dropped, the legitimate traffic is not ---- */

	if got := runPacket(t, prog, attack); got != xdpDrop {
		t.Fatalf("AFTER the ban: attack packet verdict %s, want XDP_DROP — detection reached a ban "+
			"but the ban did not reach a dropped packet", verdict(got))
	}
	t.Logf("AFTER   attack packet (udp 123 -> %s): %s", victim, verdict(xdpDrop))

	if got := runPacket(t, prog, legit); got != xdpPass {
		t.Fatalf("AFTER the ban: the victim's legitimate udp/53000 got %s, want XDP_PASS — a "+
			"surgical mitigation that drops everything is a blackhole with extra steps", verdict(got))
	}
	t.Logf("AFTER   legit packet  (udp 53000 -> %s): %s", victim, verdict(xdpPass))

	logCounters(t, mgr)

	/* ---- WITHDRAWN: the map entries go, and the packet passes again ---- */

	if _, err := mit.ManualUnban(victim); err != nil {
		t.Fatalf("ManualUnban: %v", err)
	}
	if got := runPacket(t, prog, attack); got != xdpPass {
		t.Fatalf("AFTER the withdraw: attack packet verdict %s, want XDP_PASS — the rules outlived "+
			"the ban that installed them", verdict(got))
	}
	t.Logf("WITHDRAWN attack packet (udp 123 -> %s): %s", victim, verdict(xdpPass))
}

/* ------------------------------------------------------------- detection */

// driveAttack feeds NTP-amplification telemetry into the engine until it reports
// an attack, and returns that event.
//
// The records come from pkg/flowgen, the same generator the docs' screenshots
// and the app-level end-to-end test use, so the classification under test is
// driven by the shape of a real reflection attack rather than by a hand-picked
// Classification struct.
func driveAttack(t *testing.T, ctx context.Context, eng *engine.Engine, victim netip.Addr) engine.Event {
	t.Helper()
	recs := flowgen.PatternParams{
		Pattern:          flowgen.NTPAmplification,
		Victim:           victim,
		Records:          200,
		PacketsPerRecord: 500,
		BytesPerRecord:   500 * 468,
	}.Build()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range recs {
			eng.Process(flow.Flow{
				SrcAddr:      r.SrcAddr,
				DstAddr:      r.DstAddr,
				SrcPort:      r.SrcPort,
				DstPort:      r.DstPort,
				IPProto:      r.Proto,
				TCPFlags:     r.TCPFlags,
				Bytes:        uint64(r.Bytes),
				Packets:      uint64(r.Packets),
				SamplingRate: 1,
				Wire:         flow.ProtoNetFlow9,
			})
		}
		select {
		case ev := <-eng.Events():
			if ev.Kind == engine.AttackStarted && ev.Target == victim {
				return ev
			}
		case <-ctx.Done():
			t.Fatal("context cancelled before detection")
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatal("the engine never reported an attack; the telemetry did not trip the thresholds")
	return engine.Event{}
}

func classOf(ev engine.Event) string {
	if ev.Classification == nil {
		return "(none)"
	}
	return string(ev.Classification.Type)
}

/* ----------------------------------------------------------------- packets */

// reflectionFrame is a UDP datagram from a reflector to the victim. srcPort 123
// is the NTP attack; anything else is the victim's ordinary traffic.
func reflectionFrame(victim netip.Addr, srcPort uint16) pktgen.Frame {
	return pktgen.Frame{
		SrcMAC:  [6]byte{0x02, 0, 0, 0, 0, 2},
		DstMAC:  [6]byte{0x02, 0, 0, 0, 0, 1},
		SrcIP:   netip.MustParseAddr("198.51.100.7"),
		DstIP:   victim,
		Proto:   pktgen.ProtoUDP,
		SrcPort: srcPort,
		DstPort: 40000,
		Payload: make([]byte, 440),
	}
}

func mustBuild(t *testing.T, f pktgen.Frame) []byte {
	t.Helper()
	b, err := f.Build()
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}
	return b
}

// pinnedProgram opens the program the Manager pinned, which is the only handle
// on the datapath this package can reach — and the right one: it is the program
// an operator's kernel is actually running.
func pinnedProgram(t *testing.T, dir string) *ebpf.Program {
	t.Helper()
	path := filepath.Join(dir, "prog")
	p, err := ebpf.LoadPinnedProgram(path, nil)
	if err != nil {
		t.Fatalf("open the pinned program at %s: %v", path, err)
	}
	return p
}

func runPacket(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("PROG_TEST_RUN: %v", err)
	}
	return ret
}

// logCounters prints the terminal verdict counters, so the pasted output shows
// WHY each packet got the verdict it did and not just that it did.
func logCounters(t *testing.T, mgr *dataplane.Manager) {
	t.Helper()
	snap, err := mgr.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	for s := dataplane.Stat(0); s < dataplane.StatMax; s++ {
		if c := snap.Counters[s]; c.Pkts != 0 {
			t.Logf("counter %-20s pkts=%d bytes=%d", s, c.Pkts, c.Bytes)
		}
	}
}

/* ------------------------------------------------------------- test setup */

// e2ePinDir returns a fresh pin directory on bpffs, mounting it if needed, and
// skips when there is none — the macOS developer loop, where this test cannot
// run at all.
func e2ePinDir(t *testing.T) string {
	t.Helper()
	// Through the package's shared gate rather than assuming /sys/fs/bpf: it
	// checks that the mount is one this process can create pins in, honours
	// KAPKAN_BPFFS for the CI job that cannot write the stock one, and turns
	// its skip into a failure under KAPKAN_DATAPLANE=require.
	root := dataplane.BpffsRoot(t)
	dir := filepath.Join(root, "kapkan-e2e-"+t.Name())
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// testWriter routes slog output through t.Log so the narration appears in the
// test output next to the assertions it explains.
type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

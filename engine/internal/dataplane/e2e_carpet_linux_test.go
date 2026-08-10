//go:build linux

package dataplane_test

// THE CARPET-BOMB KERNEL PROOF.
//
// ==========================================================================
// WHY THIS TEST IS SEPARATE FROM THE HOST ONE
// ==========================================================================
// A carpet ban is the WIDEST thing kapkan installs. Every other mitigation it
// puts in this kernel is anchored on a single host (/32 or /128); a carpet ban
// is anchored on the aggregation prefix, so ONE rule now covers 256 addresses
// on IPv4 and 2^80 on IPv6.
//
// Everything the host path proved therefore has to be re-proved here on real
// frames, because "it worked for a /32" is not evidence about a /24 — the
// prefix is longer in the LPM trie, it overlaps other hosts' traffic, and the
// precedence rules above it now have to protect people the operator never
// mentioned in connection with this attack.
//
// The three claims, each with its own frame:
//
//	1. the attack vector to a host inside the banned /24 is DROPPED;
//	2. that host's ordinary (non-vector) traffic still PASSES — a prefix rule
//	   that drops everything to the /24 is a blackhole with extra steps;
//	3. a PROTECTED host inside the SAME banned /24 keeps receiving even the
//	   attack-shaped traffic, because kapkan_protect4 (precedence 2) outranks
//	   every dynamic rule below it.
//
// Claim 3 is the one that only exists for prefixes. banPrefix refuses a prefix
// containing a protected_whitelist address outright, so under a steady config
// this situation cannot arise. It arises on a RELOAD: an operator adds a
// protected address to a /24 that is already banned — which is exactly when
// someone notices their resolver is inside the blast radius. The Go side
// notices too and withdraws on the next sweep, but "the next sweep" is up to a
// second away, and the kernel must not need that second. Precedence 2 is what
// makes the whitelist guarantee hold in the gap.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/pkg/flowgen"
	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

// carpetNet is the aggregation prefix under attack. Every host below is inside
// it, which is the whole point: one rule, many addresses.
var carpetNet = netip.MustParsePrefix("203.0.113.0/24")

const (
	// carpetVictim is an ordinary member of the /24: attacked, not protected.
	carpetVictim = "203.0.113.10"
	// carpetProtected is another member of the SAME /24. It is added to the
	// protected list mid-ban, and must keep receiving from that moment on.
	carpetProtected = "203.0.113.77"
	// carpetHosts is how many distinct members carry attack traffic. It must
	// clear carpet.min_hosts below, or the fan-out gate refuses to call this a
	// carpet bomb (correctly — one heavy host is a host attack).
	carpetHosts = 8
)

// e2eCarpetYAML is a LIVE config whose CARPET mitigation drops in this box's
// kernel. The per-host thresholds are set absurdly high on purpose: nothing
// here may be detected as a host attack, or the ban under test would be a /32
// ban wearing a /24's name.
func e2eCarpetYAML(pinPath string) string {
	return fmt.Sprintf(`dry_run: false
listen:
  netflow: ":0"
sampling:
  default_rate: 1
networks:
  - %q
protected_whitelist: []
thresholds:
  pps: 100000000
  mbps: 1000000
  flows_per_sec: 100000000
carpet:
  aggregation_prefix_v4: 24
  min_hosts: 4
  mitigation: dataplane
  thresholds:
    pps: 1000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 1
  max_active_bans: 10
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
`, carpetNet.String(), pinPath)
}

// TestCarpetBombDropsAPrefixInTheKernel is the headline for carpet.mitigation:
// dataplane — real carpet detection over eight under-threshold hosts, a real
// ban on the /24, real rules in a real kernel, and frames that prove exactly
// what the rule covers and what still outranks it.
func TestCarpetBombDropsAPrefixInTheKernel(t *testing.T) {
	dir := e2ePinDir(t)
	cfg, err := config.Parse([]byte(e2eCarpetYAML(dir)))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if got := cfg.Carpet.Method(); got != config.MitigateDataplane {
		t.Fatalf("carpet method = %q, want %q — the config did not select the kernel at all",
			got, config.MitigateDataplane)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(&testWriter{t}, &slog.HandlerOptions{Level: slog.LevelInfo}))

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

	victim := netip.MustParseAddr(carpetVictim)
	protected := netip.MustParseAddr(carpetProtected)

	attackVictim := mustBuild(t, reflectionFrame(victim, 123))
	// The legitimate frame is TCP, not UDP on another port. The real classifier
	// calls this telemetry a udp_flood, and the rule generateCarpetRules writes
	// for that vector is "all UDP to the /24" — so a UDP frame on a different
	// port is attack traffic by the product's own definition, not a false
	// positive. The claim being made here is the one that matters to a member of
	// the prefix: their non-vector traffic survives.
	legitVictim := mustBuild(t, tcpFrame(victim, 443))
	attackProtected := mustBuild(t, reflectionFrame(protected, 123))

	/* ---- BEFORE: nothing installed, everything passes ------------------- */

	for _, c := range []struct {
		label string
		pkt   []byte
	}{
		{"attack -> " + carpetVictim, attackVictim},
		{"attack -> " + carpetProtected, attackProtected},
		{"legit (tcp) -> " + carpetVictim, legitVictim},
	} {
		if got := runPacket(t, prog, c.pkt); got != xdpPass {
			t.Fatalf("BEFORE the ban: %s got %s, want XDP_PASS", c.label, verdict(got))
		}
	}
	t.Logf("BEFORE  every frame to %s: XDP_PASS (no policy installed)", carpetNet)

	/* ---- real carpet detection, then the real mitigator ----------------- */

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mit, err := mitigate.New(store, log, mitigate.WithDataplane(dataplane.NewInstaller(mgr, log)))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	if err := mit.Start(ctx); err != nil {
		t.Fatalf("mitigate.Start: %v", err)
	}
	defer mit.Stop()

	eng := engine.New(store, engine.WithLogger(log), engine.WithWindow(2))
	go eng.Run(ctx)

	ev := driveCarpetAttack(t, ctx, eng)
	t.Logf("DETECTED carpet bomb on %s across %d hosts: %s %.0f (threshold %.0f), classification %q",
		ev.Prefix, ev.Hosts, ev.Metric, ev.Rate, ev.Threshold, classOf(ev))
	if !ev.BanEnabled {
		t.Fatal("the carpet event has BanEnabled=false; carpet.mitigation was not honoured")
	}

	ban := mit.OnAttackStarted(ev)
	if ban == nil || ban.State != mitigate.BanActive {
		t.Fatalf("carpet ban = %+v, want an active ban", ban)
	}
	if ban.Method != config.MitigateDataplane {
		t.Fatalf("carpet ban method = %q (fell back from %q: %s), want %q. A carpet fallback "+
			"BLACKHOLES the whole %s — 256 addresses offline in answer to a request for a "+
			"surgical in-kernel drop",
			ban.Method, ban.FellBackFrom, ban.FellBackReason, config.MitigateDataplane, carpetNet)
	}
	if ban.Prefix != carpetNet {
		t.Fatalf("the ban covers %s, want the whole aggregation prefix %s", ban.Prefix, carpetNet)
	}
	t.Logf("BANNED  %s -> %s", ban.Prefix, ban.Route)

	/* ---- 1 and 2: the prefix rule drops the vector, and only it --------- */

	if got := runPacket(t, prog, attackVictim); got != xdpDrop {
		t.Fatalf("AFTER the ban: attack to %s got %s, want XDP_DROP — carpet detection reached a "+
			"ban but the ban did not reach a dropped packet", carpetVictim, verdict(got))
	}
	t.Logf("AFTER   attack (udp 123 -> %s, inside the banned /24): %s", carpetVictim, verdict(xdpDrop))

	if got := runPacket(t, prog, legitVictim); got != xdpPass {
		t.Fatalf("AFTER the ban: legitimate tcp/443 to %s got %s, want XDP_PASS — a /24 rule "+
			"that takes the members' real traffic with the attack is a blackhole with extra steps",
			carpetVictim, verdict(got))
	}
	t.Logf("AFTER   legit  (tcp 443 -> %s, same /24):              %s", carpetVictim, verdict(xdpPass))

	// Right now the protected host is NOT yet protected, and it is inside the
	// banned /24 — so it is dropped, exactly like any other member. Asserting
	// this is what makes the next step meaningful: without it, a PASS after the
	// reload could just mean the rule never covered this address.
	if got := runPacket(t, prog, attackProtected); got != xdpDrop {
		t.Fatalf("AFTER the ban: attack to %s got %s, want XDP_DROP. The /24 rule must cover "+
			"every member, or the protection test below proves nothing", carpetProtected, verdict(got))
	}
	t.Logf("AFTER   attack (udp 123 -> %s, same /24, unprotected): %s",
		carpetProtected, verdict(xdpDrop))

	/* ---- 3: precedence 2 outranks the prefix rule ----------------------- */

	// The reload an operator performs at the worst possible moment: a protected
	// address appears inside a /24 that is already banned. Done through the REAL
	// reload path, so what is exercised is what a SIGHUP does.
	next, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	next.Log = log
	next.WatchInterval = -1
	next.Policy.Protected = append(next.Policy.Protected,
		netip.PrefixFrom(protected, protected.BitLen()))
	rep, err := mgr.Reload(next)
	if err != nil {
		t.Fatalf("Reload with a protected member of the banned /24: %v", err)
	}
	t.Logf("RELOAD  %s", rep.Summary())

	before := statCount(t, mgr, dataplane.StatPassProtectDst)
	if got := runPacket(t, prog, attackProtected); got != xdpPass {
		t.Fatalf("A PROTECTED HOST INSIDE A BANNED /24 WAS DROPPED (%s). protected_whitelist is "+
			"an absolute guarantee: precedence 2 must outrank every dynamic rule, including a "+
			"prefix rule that legitimately covers this address", verdict(got))
	}
	if after := statCount(t, mgr, dataplane.StatPassProtectDst); after != before+1 {
		t.Errorf("pass_protect_dst %d -> %d, want +1: the frame passed for some OTHER reason, so "+
			"this is not evidence that precedence 2 is what saved it", before, after)
	}
	t.Logf("PROTECTED attack (udp 123 -> %s, same /24): %s via pass_protect_dst (precedence 2)",
		carpetProtected, verdict(xdpPass))

	// And the rest of the /24 is still being mitigated: protecting one member
	// must not lift the prefix rule off everybody else.
	if got := runPacket(t, prog, attackVictim); got != xdpDrop {
		t.Fatalf("after protecting %s, the attack to %s got %s, want XDP_DROP — one protected "+
			"member disarmed the whole prefix rule", carpetProtected, carpetVictim, verdict(got))
	}
	t.Logf("STILL   attack (udp 123 -> %s): %s (the rest of the /24 is still mitigated)",
		carpetVictim, verdict(xdpDrop))

	logCounters(t, mgr)

	/* ---- WITHDRAWN: the /24 of rules comes down ------------------------- */

	mit.OnAttackEnded(engine.Event{
		Kind: engine.AttackEnded, Scope: engine.ScopePrefix,
		Prefix: carpetNet.String(), At: time.Now(),
	})
	if n := len(mit.ActiveBans()); n != 0 {
		t.Errorf("active bans = %d after the carpet attack ended, want 0", n)
	}
	if got := runPacket(t, prog, attackVictim); got != xdpPass {
		t.Fatalf("AFTER the withdraw: attack to %s got %s, want XDP_PASS — a /24 of rules "+
			"outlived the ban that installed them", carpetVictim, verdict(got))
	}
	t.Logf("WITHDRAWN attack (udp 123 -> %s): %s", carpetVictim, verdict(xdpPass))
}

// tcpFrame is an established-looking TCP segment to a member of the prefix:
// traffic the carpet rule must NOT touch.
func tcpFrame(dst netip.Addr, dstPort uint16) pktgen.Frame {
	return pktgen.Frame{
		SrcMAC:   [6]byte{0x02, 0, 0, 0, 0, 2},
		DstMAC:   [6]byte{0x02, 0, 0, 0, 0, 1},
		SrcIP:    netip.MustParseAddr("198.51.100.9"),
		DstIP:    dst,
		Proto:    pktgen.ProtoTCP,
		SrcPort:  34567,
		DstPort:  dstPort,
		TCPFlags: pktgen.TCPAck | pktgen.TCPPsh,
		Payload:  make([]byte, 512),
	}
}

/* ------------------------------------------------------------- detection */

// driveCarpetAttack feeds a UDP flood spread over carpetHosts members of the
// /24 — each far under the per-host thresholds — until the engine reports the
// PREFIX-scoped attack, and returns that event.
//
// Spreading it is the fixture. A carpet bomb is defined by what per-host
// detection cannot see, so telemetry concentrated on one host would trip the
// host path and never exercise this code at all.
func driveCarpetAttack(t *testing.T, ctx context.Context, eng *engine.Engine) engine.Event {
	t.Helper()

	var recs []flowgen.Record
	for h := 0; h < carpetHosts; h++ {
		victim := carpetNet.Addr().Next()
		for i := 0; i < 9+h; i++ { // .10, .11, ... one member per host
			victim = victim.Next()
		}
		recs = append(recs, flowgen.PatternParams{
			Pattern:          flowgen.UDPFlood,
			Victim:           victim,
			Records:          40,
			PacketsPerRecord: 40,
			BytesPerRecord:   40 * 512,
		}.Build()...)
	}

	deadline := time.Now().Add(30 * time.Second)
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
			if ev.Kind == engine.AttackStarted && ev.Scope == engine.ScopePrefix &&
				ev.Prefix == carpetNet.String() {
				return ev
			}
			if ev.Kind == engine.AttackStarted && ev.Scope == engine.ScopeHost {
				t.Fatalf("a HOST attack was reported for %s: the per-host thresholds are not high "+
					"enough, so this fixture is not exercising the carpet path at all", ev.Target)
			}
		case <-ctx.Done():
			t.Fatal("context cancelled before carpet detection")
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("the engine never reported a carpet-bomb attack; the aggregate thresholds or the " +
		"fan-out gate were not tripped")
	return engine.Event{}
}

// statCount reads one terminal verdict counter.
func statCount(t *testing.T, mgr *dataplane.Manager, s dataplane.Stat) uint64 {
	t.Helper()
	snap, err := mgr.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	return snap.Counters[s].Pkts
}

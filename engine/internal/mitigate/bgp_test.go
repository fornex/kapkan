package mitigate

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/engine"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"log/slog"
)

// bgpYAML builds a live config whose speaker dials a test receiver on
// recvPort over loopback and never listens itself.
func bgpYAML(recvPort uint32) string {
	return fmt.Sprintf(`dry_run: false
listen:
  netflow: ":2055"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
  - "2001:db8::/32"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 80000
  mbps: 1000
  flows_per_sec: 35000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 120
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "1.1.1.1"
  next_hop: "192.0.2.1"
  next_hop6: "100::1"
  community: "65000:666"
  listen_port: -1
  neighbors:
    - address: "127.0.0.1"
      remote_asn: 65000
      port: %d
notify: {}
api:
  listen: "127.0.0.1:8080"
`, recvPort)
}

func bothFamilies() []*api.AfiSafi {
	return []*api.AfiSafi{
		{Config: &api.AfiSafiConfig{Family: familyV4, Enabled: true}},
		{Config: &api.AfiSafiConfig{Family: familyV6, Enabled: true}},
	}
}

// listV4 returns the GLOBAL-RIB IPv4 prefixes currently held by srv.
func listPrefixes(t *testing.T, srv *server.BgpServer, family *api.Family) map[string]*api.Destination {
	t.Helper()
	out := map[string]*api.Destination{}
	err := srv.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    family,
	}, func(d *api.Destination) { out[d.Prefix] = d })
	if err != nil {
		t.Fatalf("ListPath: %v", err)
	}
	return out
}

func waitForPrefix(t *testing.T, srv *server.BgpServer, family *api.Family, prefix string, want bool) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, ok := listPrefixes(t, srv, family)[prefix]
		if ok == want {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// TestBGPAnnounceWithdrawLifecycle stands up a receiving gobgp peer in-process
// and verifies that a live (non-dry-run) ban announces a /32 blackhole with
// the configured community and next-hop, and that ending the attack withdraws
// it. This is the M3 acceptance test against an in-process peer.
func TestBGPAnnounceWithdrawLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in -short mode")
	}
	ctx := context.Background()
	const recvPort = 17979

	// Receiver: the "router" we peer with. Passive, listens on a high port.
	recv := server.NewBgpServer()
	go recv.Serve()
	defer recv.Stop()
	if err := recv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 65000, RouterId: "2.2.2.2", ListenPort: recvPort, ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatalf("receiver StartBgp: %v", err)
	}
	if err := recv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{PassiveMode: true},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		AfiSafis:  bothFamilies(),
	}}); err != nil {
		t.Fatalf("receiver AddPeer: %v", err)
	}

	// Speaker: our mitigator, dialing the receiver.
	store := storeFrom(t, bgpYAML(recvPort))
	m, err := New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("mitigator Start: %v", err)
	}
	defer m.Stop()

	if !m.speaker.waitEstablished(ctx, 20*time.Second) {
		t.Fatal("BGP session never established")
	}

	// Announce via a live ban.
	const prefix = "203.0.113.66/32"
	ban := m.OnAttackStarted(startedEvent("203.0.113.66"))
	if ban.State != BanActive {
		t.Fatalf("ban state = %s, want active", ban.State)
	}
	if !waitForPrefix(t, recv, familyV4, prefix, true) {
		t.Fatalf("receiver never saw announced prefix %s", prefix)
	}

	// Verify community and next-hop on the received path.
	dst := listPrefixes(t, recv, familyV4)[prefix]
	if dst == nil || len(dst.Paths) == 0 {
		t.Fatalf("no path for %s on receiver", prefix)
	}
	assertBlackholeAttrs(t, dst.Paths[0])

	// Withdraw via attack ended.
	m.OnAttackEnded(engine.Event{Kind: engine.AttackEnded, Target: ban.Target, At: time.Now()})
	if !waitForPrefix(t, recv, familyV4, prefix, false) {
		t.Fatalf("receiver still has prefix %s after withdraw", prefix)
	}
}

func assertBlackholeAttrs(t *testing.T, p *api.Path) {
	t.Helper()
	attrs, err := apiutil.GetNativePathAttributes(p)
	if err != nil {
		t.Fatalf("GetNativePathAttributes: %v", err)
	}
	var sawNextHop, sawCommunity bool
	for _, a := range attrs {
		switch v := a.(type) {
		case *bgp.PathAttributeNextHop:
			sawNextHop = true
			if v.Value.String() != "192.0.2.1" {
				t.Errorf("next-hop = %s, want 192.0.2.1", v.Value.String())
			}
		case *bgp.PathAttributeCommunities:
			sawCommunity = true
			want := uint32(65000)<<16 | 666
			found := false
			for _, c := range v.Value {
				if c == want {
					found = true
				}
			}
			if !found {
				t.Errorf("communities %v missing 65000:666 (%d)", v.Value, want)
			}
		}
	}
	if !sawNextHop {
		t.Error("received path has no NEXT_HOP attribute")
	}
	if !sawCommunity {
		t.Error("received path has no COMMUNITIES attribute")
	}
}

// flowSpecPaths lists the FlowSpec paths the receiver holds, returning each
// decoded NLRI string mapped to its action (decoded from the traffic-rate
// extended community). This round-trips our encoding through gobgp's real
// wire encoder and decoder — the strongest check on the op-byte encoding.
func flowSpecPaths(t *testing.T, srv *server.BgpServer, family *api.Family) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := srv.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_GLOBAL, Family: family,
	}, func(d *api.Destination) {
		for _, p := range d.Paths {
			nlri, err := apiutil.GetNativeNlri(p)
			if err != nil {
				continue
			}
			action := ""
			attrs, _ := apiutil.GetNativePathAttributes(p)
			for _, a := range attrs {
				if ext, ok := a.(*bgp.PathAttributeExtendedCommunities); ok {
					for _, c := range ext.Value {
						if tr, ok := c.(*bgp.TrafficRateExtended); ok {
							action = tr.String()
						}
					}
				}
			}
			out[nlri.String()] = action
		}
	})
	if err != nil {
		t.Fatalf("ListPath flowspec: %v", err)
	}
	return out
}

func waitFlowSpec(t *testing.T, srv *server.BgpServer, family *api.Family, match func(map[string]string) bool) map[string]string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last map[string]string
	for time.Now().Before(deadline) {
		last = flowSpecPaths(t, srv, family)
		if match(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last
}

func hasRule(paths map[string]string, substrs ...string) (string, string, bool) {
	for nlri, action := range paths {
		all := true
		for _, s := range substrs {
			if !strings.Contains(nlri, s) {
				all = false
				break
			}
		}
		if all {
			return nlri, action, true
		}
	}
	return "", "", false
}

func TestFlowSpecAnnounceWithdraw(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in -short mode")
	}
	ctx := context.Background()
	const recvPort = 17981

	recv := server.NewBgpServer()
	go recv.Serve()
	defer recv.Stop()
	if err := recv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 65000, RouterId: "2.2.2.2", ListenPort: recvPort, ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatalf("receiver StartBgp: %v", err)
	}
	if err := recv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
		Transport: &api.Transport{PassiveMode: true},
		Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: familyV4FS, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: familyV6FS, Enabled: true}},
		},
	}}); err != nil {
		t.Fatalf("receiver AddPeer: %v", err)
	}

	store := storeFrom(t, bgpYAML(recvPort))
	m, err := New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New mitigator: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("mitigator Start: %v", err)
	}
	defer m.Stop()
	if !m.speaker.waitEstablished(ctx, 20*time.Second) {
		t.Fatal("BGP session never established")
	}

	// IPv4 NTP-amplification discard: dst /32, UDP, source-port 123.
	v4 := FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.66/32"), Proto: 17, SrcPort: 123, Action: "discard"}
	if err := m.speaker.AnnounceFlowSpec(ctx, v4); err != nil {
		t.Fatalf("AnnounceFlowSpec v4: %v", err)
	}
	paths := waitFlowSpec(t, recv, familyV4FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "203.0.113.66/32", "protocol: ==udp", "source-port: ==123")
		return ok
	})
	nlri, action, ok := hasRule(paths, "203.0.113.66/32", "protocol: ==udp", "source-port: ==123")
	if !ok {
		t.Fatalf("receiver never saw the v4 flowspec rule; got %v", paths)
	}
	if action != "discard" {
		t.Errorf("v4 action = %q, want discard; nlri=%s", action, nlri)
	}

	// IPv6 rate-limit: dst /128, TCP, SYN flag — proves v4/v6 parity. The
	// decoded NLRI must show the SYN flag precisely (=S), and the action
	// must carry the exact rate, not merely "some rate".
	v6 := FlowSpecRule{Dst: netip.MustParsePrefix("2001:db8::42/128"), Proto: 6, TCPFlags: tcpSYN, Action: "rate_limit", RateBytes: 1_250_000}
	if err := m.speaker.AnnounceFlowSpec(ctx, v6); err != nil {
		t.Fatalf("AnnounceFlowSpec v6: %v", err)
	}
	paths = waitFlowSpec(t, recv, familyV6FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "2001:db8::42/128", "protocol: ==tcp", "tcp-flags: =S")
		return ok
	})
	_, action, ok = hasRule(paths, "2001:db8::42/128", "protocol: ==tcp", "tcp-flags: =S")
	if !ok {
		t.Fatalf("v6 syn rule wrong; want tcp-flags =S, got %v", paths)
	}
	// rate: 1250000.000000 (TrafficRateExtended.String formats bytes/s).
	if action != "rate: 1250000.000000" {
		t.Errorf("v6 action = %q, want the exact rate 1250000.000000", action)
	}

	// Fragment discard: round-trips the FRAGMENT component op/bitmask.
	frag := FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.67/32"), Fragment: true, Action: "discard"}
	if err := m.speaker.AnnounceFlowSpec(ctx, frag); err != nil {
		t.Fatalf("AnnounceFlowSpec frag: %v", err)
	}
	paths = waitFlowSpec(t, recv, familyV4FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "203.0.113.67/32", "fragment")
		return ok
	})
	if _, _, ok := hasRule(paths, "203.0.113.67/32", "fragment"); !ok {
		t.Fatalf("fragment rule never round-tripped: %v", paths)
	}

	// Source-anchored (outgoing) rule: matches the host as SOURCE, proving
	// the type-2 source-prefix encoding for compromised-host mitigation.
	out := FlowSpecRule{Src: netip.MustParsePrefix("203.0.113.88/32"), Proto: 17, Action: "discard"}
	if err := m.speaker.AnnounceFlowSpec(ctx, out); err != nil {
		t.Fatalf("AnnounceFlowSpec source: %v", err)
	}
	paths = waitFlowSpec(t, recv, familyV4FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "source: 203.0.113.88/32", "protocol: ==udp")
		return ok
	})
	if _, _, ok := hasRule(paths, "source: 203.0.113.88/32"); !ok {
		t.Fatalf("source-anchored rule never round-tripped: %v", paths)
	}

	// Composite victim+attacker rule: dst = victim, src = a dominant attacker.
	// Proves both the type-1 destination and type-2 source prefix encode in ONE
	// rule — the #5 source-anchored surgical-mitigation path.
	comp := FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.70/32"), Src: netip.MustParsePrefix("198.51.100.10/32"), Action: "discard"}
	if err := m.speaker.AnnounceFlowSpec(ctx, comp); err != nil {
		t.Fatalf("AnnounceFlowSpec composite: %v", err)
	}
	paths = waitFlowSpec(t, recv, familyV4FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "203.0.113.70/32", "source: 198.51.100.10/32")
		return ok
	})
	if _, _, ok := hasRule(paths, "203.0.113.70/32", "source: 198.51.100.10/32"); !ok {
		t.Fatalf("composite victim+attacker rule never round-tripped: %v", paths)
	}

	// Withdraw both the v4 and v6 rules and confirm each leaves the RIB.
	if err := m.speaker.WithdrawFlowSpec(ctx, v4); err != nil {
		t.Fatalf("WithdrawFlowSpec v4: %v", err)
	}
	if err := m.speaker.WithdrawFlowSpec(ctx, v6); err != nil {
		t.Fatalf("WithdrawFlowSpec v6: %v", err)
	}
	paths = waitFlowSpec(t, recv, familyV4FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "203.0.113.66/32")
		return !ok
	})
	if _, _, ok := hasRule(paths, "203.0.113.66/32"); ok {
		t.Fatalf("v4 flowspec rule still present after withdraw: %v", paths)
	}
	paths = waitFlowSpec(t, recv, familyV6FS, func(p map[string]string) bool {
		_, _, ok := hasRule(p, "2001:db8::42/128")
		return !ok
	})
	if _, _, ok := hasRule(paths, "2001:db8::42/128"); ok {
		t.Fatalf("v6 flowspec rule still present after withdraw: %v", paths)
	}
}

package mitigate

import (
	"context"
	"fmt"
	"io"
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

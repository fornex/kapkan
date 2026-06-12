package mitigate

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// bgpSpeaker wraps an embedded gobgp server configured as a dial-out-only
// RTBH announcer. It peers with the configured neighbors and announces or
// withdraws /32 and /128 blackhole paths.
type bgpSpeaker struct {
	srv         *server.BgpServer
	log         *slog.Logger
	cfg         *config.Config
	watchCancel context.CancelFunc
}

var (
	familyV4 = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
	familyV6 = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
)

// newBGPSpeaker builds (but does not start) the embedded speaker. No gRPC
// listener is created, so the speaker opens no management sockets.
func newBGPSpeaker(cfg *config.Config, log *slog.Logger) (*bgpSpeaker, error) {
	srv := server.NewBgpServer(server.LoggerOption(newSlogAdapter(log)))
	return &bgpSpeaker{srv: srv, log: log.With("component", "bgp"), cfg: cfg}, nil
}

// start runs the gobgp event loop, starts BGP, and adds the configured peers.
func (b *bgpSpeaker) start(ctx context.Context) error {
	go b.srv.Serve() // mandatory: every API call funnels through this loop

	listenPort := b.cfg.BGP.ListenPort
	if listenPort == 0 {
		listenPort = -1 // dial-out only by default; never accept connections
	}
	global := &api.Global{
		Asn:        b.cfg.BGP.LocalASN,
		RouterId:   b.cfg.BGP.RouterID,
		ListenPort: listenPort,
	}
	if listenPort > 0 {
		// Bind the listener to loopback in test/dev to avoid firewall prompts
		// and accidental exposure; production runs dial-out only.
		global.ListenAddresses = []string{"127.0.0.1"}
	}
	if err := b.srv.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
		return fmt.Errorf("StartBgp: %w", err)
	}

	// Log peer state transitions for operability.
	watchCtx, cancel := context.WithCancel(ctx)
	b.watchCancel = cancel
	if err := b.srv.WatchEvent(watchCtx, &api.WatchEventRequest{Peer: &api.WatchEventRequest_Peer{}},
		func(r *api.WatchEventResponse) {
			p := r.GetPeer()
			if p == nil || p.Type != api.WatchEventResponse_PeerEvent_STATE || p.Peer == nil || p.Peer.State == nil {
				return
			}
			b.log.Info("bgp peer state",
				"neighbor", p.Peer.State.NeighborAddress,
				"state", p.Peer.State.SessionState.String())
		}); err != nil {
		return fmt.Errorf("WatchEvent: %w", err)
	}

	for _, n := range b.cfg.BGP.Neighbors {
		if err := b.addPeer(ctx, n); err != nil {
			return fmt.Errorf("add peer %s: %w", n.Address, err)
		}
	}
	return nil
}

func (b *bgpSpeaker) addPeer(ctx context.Context, n config.Neighbor) error {
	transport := &api.Transport{}
	if n.Port != 0 {
		transport.RemotePort = n.Port
	}
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: n.Address,
			PeerAsn:         n.RemoteASN,
		},
		Transport: transport,
		Timers: &api.Timers{Config: &api.TimersConfig{
			// Defaults (120s/30s) are uselessly slow; tighten reconnect.
			ConnectRetry:           5,
			IdleHoldTimeAfterReset: 5,
		}},
		// Negotiate both v4 and v6 unicast so /128 blackholes can ride an
		// IPv4 session; without explicit AfiSafis a v4 neighbor is v4-only.
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: familyV4, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: familyV6, Enabled: true}},
		},
	}
	return b.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: peer})
}

// stop tears down peers (CEASE) and stops the server.
func (b *bgpSpeaker) stop() {
	if b.watchCancel != nil {
		b.watchCancel()
	}
	if b.srv != nil {
		b.srv.Stop()
	}
}

// Announce installs a blackhole path for prefix with the given next-hop and
// community. Origin INCOMPLETE is required by gobgp on every path.
func (b *bgpSpeaker) Announce(ctx context.Context, prefix netip.Prefix, nextHop string, community uint32) error {
	origin, err := apb.New(&api.OriginAttribute{Origin: 2}) // 2 = INCOMPLETE
	if err != nil {
		return err
	}
	comms, err := apb.New(&api.CommunitiesAttribute{Communities: []uint32{community}})
	if err != nil {
		return err
	}
	nlri, err := apb.New(&api.IPAddressPrefix{
		Prefix:    prefix.Addr().String(),
		PrefixLen: uint32(prefix.Bits()),
	})
	if err != nil {
		return err
	}

	var pattrs []*apb.Any
	family := familyV4
	if prefix.Addr().Is6() {
		family = familyV6
		mp, err := apb.New(&api.MpReachNLRIAttribute{
			Family:   familyV6,
			NextHops: []string{nextHop},
			Nlris:    []*apb.Any{nlri},
		})
		if err != nil {
			return err
		}
		pattrs = []*apb.Any{origin, mp, comms}
	} else {
		nh, err := apb.New(&api.NextHopAttribute{NextHop: nextHop})
		if err != nil {
			return err
		}
		pattrs = []*apb.Any{origin, nh, comms}
	}

	_, err = b.srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
		Family: family,
		Nlri:   nlri,
		Pattrs: pattrs,
	}})
	return err
}

// Withdraw removes the blackhole path for prefix. Identification is by NLRI
// with IsWithdraw set (the robust, UUID-free path per gobgp's API).
func (b *bgpSpeaker) Withdraw(ctx context.Context, prefix netip.Prefix) error {
	nlri, err := apb.New(&api.IPAddressPrefix{
		Prefix:    prefix.Addr().String(),
		PrefixLen: uint32(prefix.Bits()),
	})
	if err != nil {
		return err
	}
	family := familyV4
	if prefix.Addr().Is6() {
		family = familyV6
	}
	return b.srv.DeletePath(ctx, &api.DeletePathRequest{Path: &api.Path{
		Family:     family,
		Nlri:       nlri,
		IsWithdraw: true,
	}})
}

// waitEstablished blocks until at least one configured neighbor reaches the
// ESTABLISHED state or the timeout elapses. Used by tests and optionally at
// startup to confirm peering.
func (b *bgpSpeaker) waitEstablished(ctx context.Context, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		established := false
		_ = b.srv.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
			if p.State != nil && p.State.SessionState == api.PeerState_ESTABLISHED {
				established = true
			}
		})
		if established {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

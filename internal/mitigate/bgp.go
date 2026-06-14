package mitigate

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
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

	familyV4FS = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}
	familyV6FS = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}
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
		// Negotiate v4/v6 unicast (so /128 blackholes can ride an IPv4
		// session) and v4/v6 FlowSpec unicast. A peer that does not support
		// a family simply won't negotiate it; advertising costs nothing.
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: familyV4, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: familyV6, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: familyV4FS, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: familyV6FS, Enabled: true}},
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

// Announce installs a blackhole path for prefix with the given next-hop,
// community set, and optional LOCAL_PREF. Origin INCOMPLETE is required by
// gobgp on every path.
func (b *bgpSpeaker) Announce(ctx context.Context, prefix netip.Prefix, attrs blackholeAttrs) error {
	origin, err := apb.New(&api.OriginAttribute{Origin: 2}) // 2 = INCOMPLETE
	if err != nil {
		return err
	}
	comms, err := apb.New(&api.CommunitiesAttribute{Communities: attrs.communities})
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
			NextHops: []string{attrs.nextHop},
			Nlris:    []*apb.Any{nlri},
		})
		if err != nil {
			return err
		}
		pattrs = []*apb.Any{origin, mp, comms}
	} else {
		nh, err := apb.New(&api.NextHopAttribute{NextHop: attrs.nextHop})
		if err != nil {
			return err
		}
		pattrs = []*apb.Any{origin, nh, comms}
	}

	// LOCAL_PREF is meaningful to iBGP peers; attach it only when configured.
	if attrs.localPref > 0 {
		lp, err := apb.New(&api.LocalPrefAttribute{LocalPref: attrs.localPref})
		if err != nil {
			return err
		}
		pattrs = append(pattrs, lp)
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

// flowSpecNLRI builds the gobgp FlowSpec NLRI (and its family) for a rule.
// Match components are appended in ascending RFC 8955 component-type order
// (dst-prefix 1, ip-proto 3, dst-port 5, src-port 6, tcp-flag 9,
// fragment 12). gobgp computes the operator length/eol bytes from the
// values via NewFlowSpecComponentItem.
func flowSpecNLRI(rule FlowSpecRule) (*apb.Any, *api.Family, error) {
	// Exactly one of Dst/Src anchors the rule on the victim. Source-anchored
	// rules (RFC 8955 type 2 / RFC 8956 type 2) carry an outgoing attacker's
	// own address so the rule matches its outbound flood.
	anchor, source := rule.Dst, false
	if rule.Src.IsValid() {
		anchor, source = rule.Src, true
	}
	addr := anchor.Addr()
	bits := uint8(anchor.Bits())
	var comps []bgp.FlowSpecComponentInterface
	family := familyV4FS
	switch {
	case addr.Is6():
		family = familyV6FS
		// The trailing 0 is the RFC 8956 IPv6 prefix offset (match from bit 0).
		p := bgp.NewIPv6AddrPrefix(bits, addr.String())
		if source {
			comps = append(comps, bgp.NewFlowSpecSourcePrefix6(p, 0))
		} else {
			comps = append(comps, bgp.NewFlowSpecDestinationPrefix6(p, 0))
		}
	default:
		p := bgp.NewIPAddrPrefix(bits, addr.String())
		if source {
			comps = append(comps, bgp.NewFlowSpecSourcePrefix(p))
		} else {
			comps = append(comps, bgp.NewFlowSpecDestinationPrefix(p))
		}
	}

	numEq := func(t bgp.BGPFlowSpecType, v uint64) {
		comps = append(comps, bgp.NewFlowSpecComponent(t,
			[]*bgp.FlowSpecComponentItem{bgp.NewFlowSpecComponentItem(bgp.DEC_NUM_OP_EQ|bgp.DEC_NUM_OP_END, v)}))
	}
	bitMatch := func(t bgp.BGPFlowSpecType, v uint64) {
		comps = append(comps, bgp.NewFlowSpecComponent(t,
			[]*bgp.FlowSpecComponentItem{bgp.NewFlowSpecComponentItem(bgp.BITMASK_FLAG_OP_MATCH|bgp.BITMASK_FLAG_OP_END, v)}))
	}

	if rule.Proto != 0 {
		numEq(bgp.FLOW_SPEC_TYPE_IP_PROTO, uint64(rule.Proto))
	}
	if rule.DstPort != 0 {
		numEq(bgp.FLOW_SPEC_TYPE_DST_PORT, uint64(rule.DstPort))
	}
	if rule.SrcPort != 0 {
		numEq(bgp.FLOW_SPEC_TYPE_SRC_PORT, uint64(rule.SrcPort))
	}
	if rule.TCPFlags != 0 {
		bitMatch(bgp.FLOW_SPEC_TYPE_TCP_FLAG, uint64(rule.TCPFlags))
	}
	if rule.Fragment {
		bitMatch(bgp.FLOW_SPEC_TYPE_FRAGMENT, uint64(bgp.FRAG_FLAG_IS))
	}

	rules, err := apiutil.MarshalFlowSpecRules(comps)
	if err != nil {
		return nil, nil, err
	}
	nlri, err := apb.New(&api.FlowSpecNLRI{Rules: rules})
	if err != nil {
		return nil, nil, err
	}
	return nlri, family, nil
}

// AnnounceFlowSpec installs a FlowSpec path for rule. The action rides a
// traffic-rate extended community: rate 0 means discard, a positive rate
// (bytes/sec) means rate-limit.
func (b *bgpSpeaker) AnnounceFlowSpec(ctx context.Context, rule FlowSpecRule) error {
	nlri, family, err := flowSpecNLRI(rule)
	if err != nil {
		return err
	}
	origin, err := apb.New(&api.OriginAttribute{Origin: 2}) // INCOMPLETE
	if err != nil {
		return err
	}
	var rate float32
	if rule.Action == "rate_limit" {
		rate = float32(rule.RateBytes)
	}
	trafficRate, err := apb.New(&api.TrafficRateExtended{Asn: 0, Rate: rate})
	if err != nil {
		return err
	}
	extComms, err := apb.New(&api.ExtendedCommunitiesAttribute{Communities: []*apb.Any{trafficRate}})
	if err != nil {
		return err
	}
	// FlowSpec is a non-unicast AFI/SAFI, so the NLRI rides MP_REACH_NLRI.
	// The next-hop is semantically irrelevant for FlowSpec (the action lives
	// in the extended community) but gobgp requires one whose family matches
	// the NLRI's — derive it from the resolved family, not the rule's Dst
	// (which is empty for source-anchored outgoing rules).
	nextHop := "0.0.0.0"
	if family == familyV6FS {
		nextHop = "::"
	}
	mp, err := apb.New(&api.MpReachNLRIAttribute{
		Family:   family,
		NextHops: []string{nextHop},
		Nlris:    []*apb.Any{nlri},
	})
	if err != nil {
		return err
	}
	_, err = b.srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
		Family: family,
		Nlri:   nlri,
		Pattrs: []*apb.Any{origin, mp, extComms},
	}})
	return err
}

// WithdrawFlowSpec removes the FlowSpec path for rule, identified by NLRI.
func (b *bgpSpeaker) WithdrawFlowSpec(ctx context.Context, rule FlowSpecRule) error {
	nlri, family, err := flowSpecNLRI(rule)
	if err != nil {
		return err
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

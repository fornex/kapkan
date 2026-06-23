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

// start runs the gobgp event loop and starts BGP. Peers are added separately by
// addPeers, AFTER the caller has re-announced any rehydrated routes into the
// RIB, so a peer's initial advertisement (and its End-of-RIB) includes them.
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

	return nil
}

// addPeers adds the configured BGP neighbors. It is called after any rehydrated
// mitigation routes are already in the RIB so each peer's initial advertisement
// — and the End-of-RIB that follows — carries them, letting a Graceful Restart
// helper refresh the routes it retained across a restart instead of purging
// them. Adding the routes before the peers makes that ordering structural.
func (b *bgpSpeaker) addPeers(ctx context.Context) error {
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
		AfiSafis: b.afiSafis(),
	}
	// Graceful Restart: advertise the capability so a helper peer retains
	// kapkan's routes across a restart. NotificationEnabled (RFC 8538) makes
	// retention survive the CEASE NOTIFICATION that a clean shutdown sends —
	// the exact path Stop() takes — instead of being flushed as a hard reset.
	if gr := b.cfg.BGP.GracefulRestart; gr.Enabled {
		peer.GracefulRestart = &api.GracefulRestart{
			Enabled:             true,
			RestartTime:         gr.RestartSeconds,
			NotificationEnabled: true,
			LonglivedEnabled:    gr.LongLived,
		}
	}
	return b.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: peer})
}

// afiSafis builds the per-neighbor address families. When Graceful Restart is
// enabled, each family is flagged GR-capable (per-AFI forwarding-state) so a
// helper peer retains its routes across a restart; LLGR is layered on only when
// explicitly enabled.
func (b *bgpSpeaker) afiSafis() []*api.AfiSafi {
	gr := b.cfg.BGP.GracefulRestart
	families := []*api.Family{familyV4, familyV6, familyV4FS, familyV6FS}
	out := make([]*api.AfiSafi, len(families))
	for i, f := range families {
		as := &api.AfiSafi{Config: &api.AfiSafiConfig{Family: f, Enabled: true}}
		if gr.Enabled {
			as.MpGracefulRestart = &api.MpGracefulRestart{Config: &api.MpGracefulRestartConfig{Enabled: true}}
			if gr.LongLived {
				as.LongLivedGracefulRestart = &api.LongLivedGracefulRestart{
					Config: &api.LongLivedGracefulRestartConfig{Enabled: true, RestartTime: gr.LongLivedStaleSeconds},
				}
			}
		}
		out[i] = as
	}
	return out
}

// stop tears down peers (CEASE) and stops the server. gobgp's StopBgp deletes
// each neighbor with a Cease/peer-deconfigured notification which, once the
// Graceful Restart "N" capability is negotiated, it escalates to a Hard Reset
// (RFC 8538) — telling the peer to FLUSH kapkan's routes. That is correct for a
// deliberate teardown but wrong for a restart; use signalRestart for that.
func (b *bgpSpeaker) stop() {
	if b.watchCancel != nil {
		b.watchCancel()
	}
	if b.srv != nil {
		b.srv.Stop()
	}
}

// signalRestart issues an Administrative Reset (BGP_ERROR_SUB_ADMINISTRATIVE_-
// RESET) to every neighbor. Unlike the peer-deconfigured cease that stop()
// triggers, gobgp does not escalate an administrative reset to a Hard Reset, so
// with the Graceful Restart capability negotiated the peer RETAINS kapkan's
// routes as stale (RFC 8538) across the session gap instead of flushing them
// immediately. The speaker is left running and the routes left installed; the
// caller exits the process next. Even if the reset notification does not flush
// to the wire before exit, the resulting bare TCP close is itself a
// non-Hard-Reset drop the peer retains across — so the one outcome this avoids,
// an immediate Hard Reset flush, never happens.
//
// This bridges the gap while the session is down. A stock RFC 4724 helper holds
// the stale routes only until the reconnecting instance signals End-of-RIB, then
// purges any it has not re-advertised. Because bans are not yet rehydrated on
// startup, fully covering an upgrade restart needs the new instance to
// re-announce active bans before End-of-RIB — see SignalRestart.
func (b *bgpSpeaker) signalRestart(ctx context.Context) {
	for _, n := range b.cfg.BGP.Neighbors {
		if err := b.srv.ResetPeer(ctx, &api.ResetPeerRequest{Address: n.Address}); err != nil {
			b.log.Warn("bgp restart-reset failed; peer may flush routes on restart",
				"neighbor", n.Address, "err", err)
		}
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
	nlri, err := apb.New(&api.IPAddressPrefix{
		Prefix:    prefix.Addr().String(),
		PrefixLen: uint32(prefix.Bits()),
	})
	if err != nil {
		return err
	}

	pattrs := []*apb.Any{origin}
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
		pattrs = append(pattrs, mp)
	} else {
		nh, err := apb.New(&api.NextHopAttribute{NextHop: attrs.nextHop})
		if err != nil {
			return err
		}
		pattrs = append(pattrs, nh)
	}

	// Attach COMMUNITIES only when non-empty; a divert route may carry none
	// (the next-hop does the rerouting), and an empty attribute is malformed.
	if len(attrs.communities) > 0 {
		comms, err := apb.New(&api.CommunitiesAttribute{Communities: attrs.communities})
		if err != nil {
			return err
		}
		pattrs = append(pattrs, comms)
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
	// A rule is anchored by its destination (victim, for an incoming attack),
	// its source (victim-as-source for an outgoing attack, or the attacker for a
	// source-anchored rule — RFC 8955 type 2 / RFC 8956 type 2), or BOTH (a
	// composite victim-dst + attacker-src rule). At least one is required.
	if !rule.Dst.IsValid() && !rule.Src.IsValid() {
		return nil, nil, fmt.Errorf("flowspec rule has no destination or source prefix")
	}
	is6 := false
	if rule.Dst.IsValid() {
		is6 = rule.Dst.Addr().Is6()
	} else {
		is6 = rule.Src.Addr().Is6()
	}
	family := familyV4FS
	if is6 {
		family = familyV6FS
	}
	var comps []bgp.FlowSpecComponentInterface
	// Components are appended in ascending RFC 8955 type order: dst-prefix (1)
	// before src-prefix (2). The trailing 0 on the IPv6 builders is the RFC 8956
	// prefix offset (match from bit 0).
	if rule.Dst.IsValid() {
		a := rule.Dst
		if is6 {
			comps = append(comps, bgp.NewFlowSpecDestinationPrefix6(bgp.NewIPv6AddrPrefix(uint8(a.Bits()), a.Addr().String()), 0))
		} else {
			comps = append(comps, bgp.NewFlowSpecDestinationPrefix(bgp.NewIPAddrPrefix(uint8(a.Bits()), a.Addr().String())))
		}
	}
	if rule.Src.IsValid() {
		a := rule.Src
		if is6 {
			comps = append(comps, bgp.NewFlowSpecSourcePrefix6(bgp.NewIPv6AddrPrefix(uint8(a.Bits()), a.Addr().String()), 0))
		} else {
			comps = append(comps, bgp.NewFlowSpecSourcePrefix(bgp.NewIPAddrPrefix(uint8(a.Bits()), a.Addr().String())))
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

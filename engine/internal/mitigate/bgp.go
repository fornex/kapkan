package mitigate

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
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

// The address families the speaker negotiates and announces in.
const (
	familyV4 = bgp.RF_IPv4_UC
	familyV6 = bgp.RF_IPv6_UC

	familyV4FS = bgp.RF_FS_IPv4_UC
	familyV6FS = bgp.RF_FS_IPv6_UC
)

// apiFamily is f as gobgp's peer configuration (a protobuf message) spells it.
func apiFamily(f bgp.Family) *api.Family { return apiutil.ToApiFamily(f.Afi(), f.Safi()) }

// newBGPSpeaker builds (but does not start) the embedded speaker. No gRPC
// listener is created, so the speaker opens no management sockets. gobgp logs
// through log/slog and discards everything unless handed a logger, so it gets
// the brain's, tagged component=gobgp; its level stays the brain's, since the
// only way to change it (gobgp's SetLogLevel) is a gRPC call.
func newBGPSpeaker(cfg *config.Config, log *slog.Logger) (*bgpSpeaker, error) {
	srv := server.NewBgpServer(server.LoggerOption(log.With("component", "gobgp"), nil))
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
	if err := b.srv.WatchEvent(watchCtx, server.WatchEventMessageCallbacks{
		OnPeerUpdate: func(ev *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if ev.Type != apiutil.PEER_EVENT_STATE {
				return
			}
			b.log.Info("bgp peer state",
				"neighbor", ev.Peer.State.NeighborAddress.String(),
				"state", peerStateName(ev.Peer.State.SessionState))
		},
	}, server.WatchPeer()); err != nil {
		return fmt.Errorf("WatchEvent: %w", err)
	}

	return nil
}

// peerStateName renders a session state as this log line has always carried
// it and as the operator docs tell people to grep for it: ESTABLISHED, not
// gobgp v4's BGP_FSM_ESTABLISHED.
func peerStateName(s bgp.FSMState) string {
	return strings.TrimPrefix(s.String(), "BGP_FSM_")
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
	families := []bgp.Family{familyV4, familyV6, familyV4FS, familyV6FS}
	out := make([]*api.AfiSafi, len(families))
	for i, f := range families {
		as := &api.AfiSafi{Config: &api.AfiSafiConfig{Family: apiFamily(f), Enabled: true}}
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
//
// gobgp's path calls take no context (v3's took one and ignored it); each
// returns once gobgp's event loop has applied the change, as before.
func (b *bgpSpeaker) Announce(_ context.Context, prefix netip.Prefix, attrs blackholeAttrs) error {
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return err
	}
	nextHop, err := netip.ParseAddr(attrs.nextHop)
	if err != nil {
		return fmt.Errorf("next-hop: %w", err)
	}

	pattrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)}
	family := familyV4
	if prefix.Addr().Is6() {
		family = familyV6
		mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
		if err != nil {
			return err
		}
		pattrs = append(pattrs, mp)
	} else {
		nh, err := bgp.NewPathAttributeNextHop(nextHop)
		if err != nil {
			return err
		}
		pattrs = append(pattrs, nh)
	}

	// Attach COMMUNITIES only when non-empty; a divert route may carry none
	// (the next-hop does the rerouting), and an empty attribute is malformed.
	if len(attrs.communities) > 0 {
		pattrs = append(pattrs, bgp.NewPathAttributeCommunities(attrs.communities))
	}

	// LOCAL_PREF is meaningful to iBGP peers; attach it only when configured.
	if attrs.localPref > 0 {
		pattrs = append(pattrs, bgp.NewPathAttributeLocalPref(attrs.localPref))
	}

	return b.addPath(family, nlri, pattrs)
}

// Withdraw removes the blackhole path for prefix. Identification is by NLRI
// with Withdrawal set (the robust, UUID-free path per gobgp's API).
func (b *bgpSpeaker) Withdraw(_ context.Context, prefix netip.Prefix) error {
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return err
	}
	family := familyV4
	if prefix.Addr().Is6() {
		family = familyV6
	}
	return b.deletePath(family, nlri)
}

// addPath hands gobgp one locally originated path. gobgp replaces a path it
// already holds for the same NLRI (an implicit withdraw), which is how an
// escalation moves a victim from blackhole to divert without a gap. The age is
// the time of the call, as gobgp's v3 API stamped it.
func (b *bgpSpeaker) addPath(family bgp.Family, nlri bgp.NLRI, attrs []bgp.PathAttributeInterface) error {
	_, err := b.srv.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{{
		Family: family,
		Nlri:   nlri,
		Attrs:  attrs,
		Age:    time.Now().Unix(),
	}}})
	return err
}

// deletePath withdraws the locally originated path for nlri.
func (b *bgpSpeaker) deletePath(family bgp.Family, nlri bgp.NLRI) error {
	return b.srv.DeletePath(apiutil.DeletePathRequest{Paths: []*apiutil.Path{{
		Family:     family,
		Nlri:       nlri,
		Withdrawal: true,
	}}})
}

// flowSpecNLRI builds the gobgp FlowSpec NLRI (and its family) for a rule.
// Match components are appended in ascending RFC 8955 component-type order
// (dst-prefix 1, ip-proto 3, dst-port 5, src-port 6, tcp-flag 9,
// fragment 12). gobgp computes the operator length/eol bytes from the
// values via NewFlowSpecComponentItem.
func flowSpecNLRI(rule FlowSpecRule) (*bgp.FlowSpecNLRI, bgp.Family, error) {
	// A rule is anchored by its destination (victim, for an incoming attack),
	// its source (victim-as-source for an outgoing attack, or the attacker for a
	// source-anchored rule — RFC 8955 type 2 / RFC 8956 type 2), or BOTH (a
	// composite victim-dst + attacker-src rule). At least one is required.
	if !rule.Dst.IsValid() && !rule.Src.IsValid() {
		return nil, 0, fmt.Errorf("flowspec rule has no destination or source prefix")
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
		p, err := bgp.NewIPAddrPrefix(rule.Dst)
		if err != nil {
			return nil, 0, err
		}
		if is6 {
			comps = append(comps, bgp.NewFlowSpecDestinationPrefix6(p, 0))
		} else {
			comps = append(comps, bgp.NewFlowSpecDestinationPrefix(p))
		}
	}
	if rule.Src.IsValid() {
		p, err := bgp.NewIPAddrPrefix(rule.Src)
		if err != nil {
			return nil, 0, err
		}
		if is6 {
			comps = append(comps, bgp.NewFlowSpecSourcePrefix6(p, 0))
		} else {
			comps = append(comps, bgp.NewFlowSpecSourcePrefix(p))
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

	nlri, err := bgp.NewFlowSpecUnicast(family, comps)
	if err != nil {
		return nil, 0, err
	}
	return nlri, family, nil
}

// AnnounceFlowSpec installs a FlowSpec path for rule. The action rides a
// traffic-rate extended community: rate 0 means discard, a positive rate
// (bytes/sec) means rate-limit.
func (b *bgpSpeaker) AnnounceFlowSpec(_ context.Context, rule FlowSpecRule) error {
	nlri, family, err := flowSpecNLRI(rule)
	if err != nil {
		return err
	}
	var rate float32
	if rule.Action == "rate_limit" {
		rate = float32(rule.RateBytes)
	}
	// FlowSpec is a non-unicast AFI/SAFI, so the NLRI rides MP_REACH_NLRI.
	// The next-hop is semantically irrelevant for FlowSpec (the action lives
	// in the extended community, and gobgp encodes no next-hop for it). The
	// path still carries the unspecified address of the NLRI's family, as
	// gobgp v3 required — derived from the resolved family, not the rule's
	// Dst (which is empty for source-anchored outgoing rules).
	nextHop := netip.IPv4Unspecified()
	if family == familyV6FS {
		nextHop = netip.IPv6Unspecified()
	}
	mp, err := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nextHop)
	if err != nil {
		return err
	}
	return b.addPath(family, nlri, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		mp,
		bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{
			bgp.NewTrafficRateExtended(0, rate),
		}),
	})
}

// WithdrawFlowSpec removes the FlowSpec path for rule, identified by NLRI.
func (b *bgpSpeaker) WithdrawFlowSpec(_ context.Context, rule FlowSpecRule) error {
	nlri, family, err := flowSpecNLRI(rule)
	if err != nil {
		return err
	}
	return b.deletePath(family, nlri)
}

// waitEstablished blocks until at least one configured neighbor reaches the
// ESTABLISHED state or the timeout elapses. Used by tests and optionally at
// startup to confirm peering.
func (b *bgpSpeaker) waitEstablished(ctx context.Context, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		established := false
		_ = b.srv.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
			if p.State != nil && p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED {
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

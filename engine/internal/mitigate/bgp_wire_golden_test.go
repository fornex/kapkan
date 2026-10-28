package mitigate

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

var update = flag.Bool("update", false, "rewrite testdata/bgp-wire.golden from the current speaker")

const wireGolden = "testdata/bgp-wire.golden"

// TestBGPWireGolden pins, byte for byte, what the brain's speaker sends a
// router: its OPEN, the initial advertisement up to End-of-RIB, the UPDATE
// for each RTBH, divert and FlowSpec announcement and withdrawal, and the
// NOTIFICATION each kind of teardown sends.
//
// The other BGP tests in this package read the speaker back through gobgp's
// own decoder, so they cannot see a change that gobgp makes to its encoder and
// decoder together, which is what a gobgp upgrade can do. This test compares
// against bytes the upgrade cannot rewrite, so a change in what reaches the
// router shows up as a diff in testdata/bgp-wire.golden, in review.
//
// `go test ./internal/mitigate -run TestBGPWireGolden -update` rewrites the
// file; review the diff like any other change to what a router receives.
func TestBGPWireGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping BGP integration test in -short mode")
	}
	var got strings.Builder
	for _, s := range []struct {
		name    string
		peerASN uint16 // the speaker is AS 65001 (bgpYAML)
		end     wireStep
		stops   bool // end stops the speaker
	}{
		{"eBGP", 65000, wireStep{
			"SignalRestart: Cease / Administrative Reset, which a Graceful Restart helper retains routes across",
			func(ctx context.Context, sp *bgpSpeaker) error { sp.signalRestart(ctx); return nil },
		}, false},
		{"iBGP", 65001, wireStep{
			"Stop: Cease / Peer De-configured, sent as a Hard Reset because the N bit was negotiated",
			func(_ context.Context, sp *bgpSpeaker) error { sp.stop(); return nil },
		}, true},
	} {
		if got.Len() > 0 {
			got.WriteString("\n")
		}
		fmt.Fprintf(&got, "## %s session\n", s.name)
		recordWireSession(t, &got, s.peerASN, s.end, s.stops)
	}

	if *update {
		if err := os.MkdirAll(filepath.Dir(wireGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(wireGolden, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(wireGolden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got.String() != string(want) {
		g, w := strings.Split(got.String(), "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(g) || i < len(w); i++ {
			if i >= len(g) || i >= len(w) || g[i] != w[i] {
				t.Fatalf("the speaker's wire output differs from %s from line %d:\n got: %s\nwant: %s\n"+
					"(run with -update and review the diff)", wireGolden, i+1, lineAt(g, i), lineAt(w, i))
			}
		}
	}
}

// wireStep is one thing the brain does to its speaker; the test records the
// message it puts on the wire.
type wireStep struct {
	name string
	act  func(ctx context.Context, sp *bgpSpeaker) error
}

var blackholeComm = []uint32{65000<<16 | 666}

// wireSteps are the announcements the brain makes, each answered by exactly
// one UPDATE. A per-hostgroup override and a divert reach the speaker as the
// same Announce with different attributes, so both appear here as such.
var wireSteps = []wireStep{
	{"RTBH 203.0.113.66/32 with the blackhole community",
		announceStep("203.0.113.66/32", blackholeAttrs{nextHop: "192.0.2.1", communities: blackholeComm})},
	{"RTBH 2001:db8::beef/128 via next_hop6 (rides MP_REACH_NLRI)",
		announceStep("2001:db8::beef/128", blackholeAttrs{nextHop: "100::1", communities: blackholeComm})},
	{"hostgroup override: its own next-hop, two communities, LOCAL_PREF 200 (sent on iBGP only)",
		announceStep("203.0.113.67/32", blackholeAttrs{
			nextHop: "192.0.2.7", communities: []uint32{65000<<16 | 666, 65000<<16 | 777}, localPref: 200})},
	{"divert 203.0.113.68/32: scrubbing next-hop, no community, LOCAL_PREF 300",
		announceStep("203.0.113.68/32", blackholeAttrs{nextHop: "192.0.2.9", localPref: 300})},
	{"divert 2001:db8::68/128: scrubbing next_hop6, no community",
		announceStep("2001:db8::68/128", blackholeAttrs{nextHop: "2001:db8:ffff::9"})},
	{"escalation re-announces 203.0.113.66/32 as a divert: one UPDATE replaces the RTBH route (implicit withdraw)",
		announceStep("203.0.113.66/32", blackholeAttrs{nextHop: "192.0.2.9"})},
	{"FlowSpec discard: dst 203.0.113.66/32, UDP, source port 123",
		flowSpecStep(true, FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.66/32"), Proto: 17, SrcPort: 123,
			Action: config.FlowSpecDiscard})},
	{"FlowSpec rate-limit 1250000 B/s: dst 2001:db8::42/128, TCP, SYN",
		flowSpecStep(true, FlowSpecRule{Dst: netip.MustParsePrefix("2001:db8::42/128"), Proto: 6, TCPFlags: tcpSYN,
			Action: config.FlowSpecRateLimit, RateBytes: 1_250_000})},
	{"FlowSpec discard: dst 203.0.113.67/32, fragments",
		flowSpecStep(true, FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.67/32"), Fragment: true,
			Action: config.FlowSpecDiscard})},
	{"FlowSpec discard, source-anchored (outgoing): src 203.0.113.88/32, UDP",
		flowSpecStep(true, FlowSpecRule{Src: netip.MustParsePrefix("203.0.113.88/32"), Proto: 17,
			Action: config.FlowSpecDiscard})},
	{"FlowSpec discard, victim and attacker: dst 203.0.113.70/32, src 198.51.100.10/32",
		flowSpecStep(true, FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.70/32"),
			Src: netip.MustParsePrefix("198.51.100.10/32"), Action: config.FlowSpecDiscard})},
	{"FlowSpec discard, source-anchored IPv6: src 2001:db8::88/128, UDP, destination port 53",
		flowSpecStep(true, FlowSpecRule{Src: netip.MustParsePrefix("2001:db8::88/128"), Proto: 17, DstPort: 53,
			Action: config.FlowSpecDiscard})},
	{"withdraw 203.0.113.66/32", withdrawStep("203.0.113.66/32")},
	{"withdraw 2001:db8::beef/128 (MP_UNREACH_NLRI)", withdrawStep("2001:db8::beef/128")},
	{"withdraw FlowSpec dst 203.0.113.66/32, UDP, source port 123",
		flowSpecStep(false, FlowSpecRule{Dst: netip.MustParsePrefix("203.0.113.66/32"), Proto: 17, SrcPort: 123,
			Action: config.FlowSpecDiscard})},
	{"withdraw FlowSpec dst 2001:db8::42/128, TCP, SYN",
		flowSpecStep(false, FlowSpecRule{Dst: netip.MustParsePrefix("2001:db8::42/128"), Proto: 6, TCPFlags: tcpSYN,
			Action: config.FlowSpecRateLimit, RateBytes: 1_250_000})},
}

func announceStep(prefix string, attrs blackholeAttrs) func(context.Context, *bgpSpeaker) error {
	return func(ctx context.Context, sp *bgpSpeaker) error {
		return sp.Announce(ctx, netip.MustParsePrefix(prefix), attrs)
	}
}

func withdrawStep(prefix string) func(context.Context, *bgpSpeaker) error {
	return func(ctx context.Context, sp *bgpSpeaker) error {
		return sp.Withdraw(ctx, netip.MustParsePrefix(prefix))
	}
}

func flowSpecStep(announce bool, r FlowSpecRule) func(context.Context, *bgpSpeaker) error {
	return func(ctx context.Context, sp *bgpSpeaker) error {
		if announce {
			return sp.AnnounceFlowSpec(ctx, r)
		}
		return sp.WithdrawFlowSpec(ctx, r)
	}
}

// recordWireSession runs one session between the speaker and a test peer of
// AS peerASN, writing every message the speaker sends to out. The session ends
// with end, which stops the speaker when endStops is set.
func recordWireSession(t *testing.T, out *strings.Builder, peerASN uint16, end wireStep, endStops bool) {
	t.Helper()
	ctx := context.Background()
	ln := listenPeer(t)
	yaml := strings.Replace(bgpYAML(uint32(ln.Addr().(*net.TCPAddr).Port)),
		"remote_asn: 65000", fmt.Sprintf("remote_asn: %d", peerASN), 1)
	sp, err := newBGPSpeaker(storeFrom(t, yaml).Get(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newBGPSpeaker: %v", err)
	}
	if err := sp.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			sp.stop()
		}
	})

	// Mitigator.Start re-announces the bans it rehydrated before it adds the
	// peers, so they ride the initial advertisement ahead of End-of-RIB and a
	// Graceful Restart helper refreshes them instead of purging them.
	if err := sp.Announce(ctx, netip.MustParsePrefix("203.0.113.99/32"),
		blackholeAttrs{nextHop: "192.0.2.1", communities: blackholeComm}); err != nil {
		t.Fatalf("Announce before the peer: %v", err)
	}
	if err := sp.addPeers(ctx); err != nil {
		t.Fatalf("addPeers: %v", err)
	}

	p := acceptPeer(t, ln, inProcess{})
	typ, body := p.next(30 * time.Second)
	writeWireStep(out, "the speaker's OPEN", typ, body)
	p.send(goldenPeerOpen(peerASN))
	p.send(bgpMessage(bgpMsgKeepalive, nil))
	recordInitialAdvertisement(t, out, p)

	for _, st := range wireSteps {
		if err := st.act(ctx, sp); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		typ, body := p.next(10 * time.Second)
		writeWireStep(out, st.name, typ, body)
	}

	// A teardown can wait on the session it is ending, so it runs beside the
	// read rather than ahead of it.
	done := make(chan error, 1)
	go func() { done <- end.act(ctx, sp) }()
	typ, body = p.next(10 * time.Second)
	writeWireStep(out, end.name, typ, body)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", end.name, err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("%s did not return", end.name)
	}
	stopped = endStops
}

// wireFamilies are the families the speaker and goldenPeerOpen negotiate, in
// the order the golden file lists them.
var wireFamilies = []string{"IPv4 unicast", "IPv6 unicast", "IPv4 FlowSpec", "IPv6 FlowSpec"}

// recordInitialAdvertisement reads what the speaker sends once the session is
// up, until it has signalled End-of-RIB for every family, and writes it one
// family at a time. gobgp packs each family on its own and sends the packs in
// map order, so the order ACROSS families differs between runs. The order
// WITHIN a family (its routes, then its End-of-RIB) is what Graceful Restart
// rests on, and is written as sent.
func recordInitialAdvertisement(t *testing.T, out *strings.Builder, p *testPeer) {
	t.Helper()
	sent := map[string][]string{}
	for eors := 0; eors < len(wireFamilies); {
		typ, body := p.next(10 * time.Second)
		if typ != bgpMsgUpdate {
			t.Fatalf("initial advertisement: the speaker sent its %s: % x", bgpMsgName(typ), body)
		}
		f := updateFamily(body)
		sent[f] = append(sent[f], wireText(typ, body))
		if isEndOfRIB(body) {
			eors++
		}
	}
	for _, f := range wireFamilies {
		fmt.Fprintf(out, "\n# initial advertisement, %s\n", f)
		for _, m := range sent[f] {
			out.WriteString(m)
		}
		delete(sent, f)
	}
	for f := range sent {
		t.Errorf("initial advertisement: UPDATE for a family nobody negotiated: %s", f)
	}
}

func writeWireStep(out *strings.Builder, name string, typ byte, body []byte) {
	fmt.Fprintf(out, "\n# %s\n%s", name, wireText(typ, body))
}

// goldenPeerOpen is a router that negotiates everything the speaker offers:
// IPv4 and IPv6 unicast and FlowSpec, route refresh, 4-octet AS, and Graceful
// Restart as a helper with the N bit (RFC 8538), so End-of-RIB and the Hard
// Reset escalation reach the wire to be pinned.
func goldenPeerOpen(asn uint16) []byte {
	caps := []byte{
		1, 4, 0, 1, 0, 1, // Multiprotocol: IPv4 unicast
		1, 4, 0, 2, 0, 1, // Multiprotocol: IPv6 unicast
		1, 4, 0, 1, 0, 133, // Multiprotocol: IPv4 FlowSpec
		1, 4, 0, 2, 0, 133, // Multiprotocol: IPv6 FlowSpec
		2, 0, // Route Refresh
		65, 4, 0, 0, byte(asn >> 8), byte(asn), // 4-octet AS
		// Graceful Restart: N bit, restart time 120 s, the four families with
		// no forwarding state preserved.
		64, 18, 0x40, 120, 0, 1, 1, 0, 0, 2, 1, 0, 0, 1, 133, 0, 0, 2, 133, 0,
	}
	return bgpOpen(asn, caps)
}

/* --------------------------------------------- rendering the golden file */

// wireText renders one message for the golden file. It splits the message
// into the fields the speaker chose (capabilities, path attributes, NLRI) and
// leaves each value as the bytes on the wire, so the file pins the encoding
// itself rather than what a decoder makes of it.
func wireText(typ byte, body []byte) string {
	var b strings.Builder
	switch typ {
	case bgpMsgOpen:
		writeOpen(&b, body)
	case bgpMsgUpdate:
		writeUpdate(&b, body)
	case bgpMsgNotification:
		if len(body) < 2 {
			fmt.Fprintf(&b, "NOTIFICATION (short): %s\n", wireHex(body))
			break
		}
		fmt.Fprintf(&b, "NOTIFICATION code %d subcode %d, data: %s\n", body[0], body[1], wireHex(body[2:]))
	default:
		fmt.Fprintf(&b, "%s: %s\n", bgpMsgName(typ), wireHex(body))
	}
	return b.String()
}

func writeOpen(b *strings.Builder, body []byte) {
	if len(body) < 10 || len(body) < 10+int(body[9]) {
		fmt.Fprintf(b, "OPEN (malformed): %s\n", wireHex(body))
		return
	}
	fmt.Fprintf(b, "OPEN version %d, AS %d, hold time %d, BGP identifier %s\n",
		body[0], binary.BigEndian.Uint16(body[1:3]), binary.BigEndian.Uint16(body[3:5]),
		netip.AddrFrom4([4]byte(body[5:9])))
	params := body[10 : 10+int(body[9])]
	for len(params) > 0 {
		if len(params) < 2 || len(params) < 2+int(params[1]) {
			fmt.Fprintf(b, "  optional parameters (malformed): %s\n", wireHex(params))
			return
		}
		ptype, val := params[0], params[2:2+int(params[1])]
		params = params[2+int(params[1]):]
		if ptype != 2 {
			fmt.Fprintf(b, "  optional parameter %d: %s\n", ptype, wireHex(val))
			continue
		}
		for len(val) > 0 {
			if len(val) < 2 || len(val) < 2+int(val[1]) {
				fmt.Fprintf(b, "  capabilities (malformed): %s\n", wireHex(val))
				break
			}
			code, cv := val[0], val[2:2+int(val[1])]
			val = val[2+int(val[1]):]
			fmt.Fprintf(b, "  capability %s: %s\n", capabilityName(code), capabilityValue(code, cv))
		}
	}
}

// capabilityValue leaves every capability as bytes except the two that name
// the host and the gobgp release: those are the machine's and the library's,
// not the speaker's configuration.
func capabilityValue(code byte, v []byte) string {
	switch code {
	case 73:
		return "<this host's name>"
	case 75:
		return "<gobgp's version string>"
	}
	return wireHex(v)
}

func capabilityName(code byte) string {
	switch code {
	case 1:
		return "Multiprotocol (1)"
	case 2:
		return "Route Refresh (2)"
	case 5:
		return "Extended Next Hop Encoding (5)"
	case 6:
		return "Extended Message (6)"
	case 64:
		return "Graceful Restart (64)"
	case 65:
		return "4-octet AS (65)"
	case 69:
		return "ADD-PATH (69)"
	case 71:
		return "Long-Lived Graceful Restart (71)"
	case 73:
		return "FQDN (73)"
	case 75:
		return "Software Version (75)"
	}
	return fmt.Sprintf("code %d", code)
}

// wireAttr is one path attribute as framed on the wire.
type wireAttr struct {
	flags, code byte
	value       []byte
}

// splitUpdate frames an UPDATE body (RFC 4271 §4.3) into its withdrawn
// routes, path attributes and NLRI.
func splitUpdate(body []byte) (withdrawn []byte, attrs []wireAttr, nlri []byte, ok bool) {
	if len(body) < 2 {
		return nil, nil, nil, false
	}
	wl := int(binary.BigEndian.Uint16(body))
	if len(body) < 2+wl+2 {
		return nil, nil, nil, false
	}
	withdrawn, rest := body[2:2+wl], body[2+wl:]
	al := int(binary.BigEndian.Uint16(rest))
	if len(rest) < 2+al {
		return nil, nil, nil, false
	}
	raw, nlri := rest[2:2+al], rest[2+al:]
	for len(raw) > 0 {
		if len(raw) < 3 {
			return nil, nil, nil, false
		}
		flags, code, hdr, l := raw[0], raw[1], 3, int(raw[2])
		if flags&0x10 != 0 { // Extended Length
			if len(raw) < 4 {
				return nil, nil, nil, false
			}
			hdr, l = 4, int(binary.BigEndian.Uint16(raw[2:4]))
		}
		if len(raw) < hdr+l {
			return nil, nil, nil, false
		}
		attrs = append(attrs, wireAttr{flags, code, raw[hdr : hdr+l]})
		raw = raw[hdr+l:]
	}
	return withdrawn, attrs, nlri, true
}

func writeUpdate(b *strings.Builder, body []byte) {
	withdrawn, attrs, nlri, ok := splitUpdate(body)
	if !ok {
		fmt.Fprintf(b, "UPDATE (malformed): %s\n", wireHex(body))
		return
	}
	if isEndOfRIB(body) {
		b.WriteString("UPDATE: End-of-RIB\n")
	} else {
		b.WriteString("UPDATE\n")
	}
	if len(withdrawn) > 0 {
		fmt.Fprintf(b, "  withdrawn routes: %s\n", wireHex(withdrawn))
	}
	for _, a := range attrs {
		fmt.Fprintf(b, "  %s, flags %02x: %s\n", attrName(a.code), a.flags, attrValue(a))
	}
	if len(nlri) > 0 {
		fmt.Fprintf(b, "  NLRI: %s\n", wireHex(nlri))
	}
}

func attrName(code byte) string {
	switch code {
	case 1:
		return "ORIGIN"
	case 2:
		return "AS_PATH"
	case 3:
		return "NEXT_HOP"
	case 4:
		return "MULTI_EXIT_DISC"
	case 5:
		return "LOCAL_PREF"
	case 8:
		return "COMMUNITIES"
	case 14:
		return "MP_REACH_NLRI"
	case 15:
		return "MP_UNREACH_NLRI"
	case 16:
		return "EXTENDED_COMMUNITIES"
	}
	return fmt.Sprintf("attribute %d", code)
}

// attrValue splits the two multiprotocol attributes (RFC 4760 §3, §4) into
// their family, next hop and NLRI, the fields a router checks first; every
// other attribute is its bytes.
func attrValue(a wireAttr) string {
	v := a.value
	switch {
	case a.code == 14 && len(v) >= 5 && len(v) >= 5+int(v[3]):
		nh := v[4 : 4+int(v[3])]
		return fmt.Sprintf("%s, next hop %s, reserved %02x, NLRI %s",
			familyName(binary.BigEndian.Uint16(v[:2]), v[2]), wireHex(nh), v[4+len(nh)], wireHex(v[5+len(nh):]))
	case a.code == 15 && len(v) >= 3:
		return fmt.Sprintf("%s, withdrawn %s", familyName(binary.BigEndian.Uint16(v[:2]), v[2]), wireHex(v[3:]))
	}
	return wireHex(v)
}

// updateFamily is the family an UPDATE carries: the one its multiprotocol
// attribute names, or IPv4 unicast for a plain UPDATE.
func updateFamily(body []byte) string {
	_, attrs, _, _ := splitUpdate(body)
	for _, a := range attrs {
		if (a.code == 14 || a.code == 15) && len(a.value) >= 3 {
			return familyName(binary.BigEndian.Uint16(a.value[:2]), a.value[2])
		}
	}
	return familyName(1, 1)
}

// isEndOfRIB reports whether an UPDATE is an End-of-RIB marker (RFC 4724
// §2): an empty UPDATE for IPv4 unicast; for any other family, an UPDATE
// whose only attribute is an MP_UNREACH_NLRI naming the family and nothing
// else.
func isEndOfRIB(body []byte) bool {
	withdrawn, attrs, nlri, ok := splitUpdate(body)
	if !ok || len(withdrawn) > 0 || len(nlri) > 0 {
		return false
	}
	return len(attrs) == 0 || len(attrs) == 1 && attrs[0].code == 15 && len(attrs[0].value) == 3
}

func familyName(afi uint16, safi byte) string {
	a := map[uint16]string{1: "IPv4", 2: "IPv6"}[afi]
	s := map[byte]string{1: "unicast", 133: "FlowSpec"}[safi]
	if a == "" || s == "" {
		return fmt.Sprintf("AFI %d SAFI %d", afi, safi)
	}
	return a + " " + s
}

func wireHex(b []byte) string {
	if len(b) == 0 {
		return "(empty)"
	}
	return fmt.Sprintf("% x", b)
}

func lineAt(lines []string, i int) string {
	if i >= len(lines) {
		return "(end of file)"
	}
	return lines[i]
}

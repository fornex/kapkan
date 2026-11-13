package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

// steeringListen is the status_listen an enabled steering block needs.
const steeringListen = "status_listen: 127.0.0.1:9102\n"

// steeringVIPs is a steering block body listing addrs, each quoted: an
// IPv6 address or a mapped one is not a plain YAML scalar.
func steeringVIPs(addrs ...string) string {
	q := make([]string, len(addrs))
	for i, a := range addrs {
		q[i] = fmt.Sprintf("%q", a)
	}
	return "  vips: [" + strings.Join(q, ", ") + "]\n"
}

// steeringAddrs is n distinct documentation addresses, 192.0.2.1 upwards.
func steeringAddrs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}).String()
	}
	return out
}

func TestEdgeSteeringDefaults(t *testing.T) {
	e, err := ParseEdgeNode([]byte(edgeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if e.Steering.Enabled || e.Steering.VIPAddrs != nil {
		t.Fatalf("absent block: %+v, want off with no addresses", e.Steering)
	}
	if got := e.Steering.SteerConfig(); got != steer.DefaultConfig() {
		t.Fatalf("absent block: SteerConfig %+v, want steer's defaults %+v", got, steer.DefaultConfig())
	}

	full := edgeYAML + steeringListen + `steering:
  enabled: true
  interval_seconds: 2
  fail_after: 2
  fail_window: 4
  recover_after: 5
  hold_down:
    min_seconds: 3
    max_seconds: 120
  vips: ["::ffff:192.0.2.10", "2001:db8::10"]
`
	e, err = ParseEdgeNode([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Steering.Enabled {
		t.Fatal("enabled: true parsed as off")
	}
	want := steer.Config{
		Interval:     2 * time.Second,
		FailAfter:    2,
		FailWindow:   4,
		RecoverAfter: 5,
		HoldDownMin:  3 * time.Second,
		HoldDownMax:  120 * time.Second,
		LevelReset:   steer.DefaultLevelReset,
	}
	if got := e.Steering.SteerConfig(); got != want {
		t.Fatalf("every key set: SteerConfig %+v, want %+v", got, want)
	}
	// The mapped spelling is the IPv4 address it maps: netip's == tells
	// ::ffff:192.0.2.10 from 192.0.2.10, so this pins the unmapping.
	wantVIPs := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	if !slices.Equal(e.Steering.VIPAddrs, wantVIPs) {
		t.Fatalf("VIPAddrs %v, want %v", e.Steering.VIPAddrs, wantVIPs)
	}

	// A key set to 0, or left out, keeps steer's default beside the ones set.
	some := edgeYAML + "steering:\n  interval_seconds: 5\n  fail_after: 0\n"
	e, err = ParseEdgeNode([]byte(some))
	if err != nil {
		t.Fatal(err)
	}
	want = steer.DefaultConfig()
	want.Interval = 5 * time.Second
	if got := e.Steering.SteerConfig(); got != want {
		t.Fatalf("one key set: SteerConfig %+v, want %+v", got, want)
	}
}

// TestEdgeSteeringRejects has a row per validation rule. The bounds rows
// run twice, with the block off and on: a block staged with enabled: false
// must already be valid, so turning it on changes nothing else.
func TestEdgeSteeringRejects(t *testing.T) {
	bounds := []struct {
		name string
		// top goes beside the block, at the top level; body is the block's.
		top, body, want string
	}{
		{"a prefix", "", steeringVIPs("192.0.2.0/24"), `steering.vips[0] "192.0.2.0/24" is not an address (a VIP is one address, never a prefix)`},
		{"a zone", "", steeringVIPs("2001:db8::1%eth0"), `steering.vips[0] "2001:db8::1%eth0" carries a zone; a VIP is a global address`},
		{"loopback v4", "", steeringVIPs("127.0.0.1"), "steering.vips[0] 127.0.0.1 is not a unicast address this box can carry"},
		{"loopback v6", "", steeringVIPs("::1"), "steering.vips[0] ::1 is not a unicast address this box can carry"},
		{"unspecified v4", "", steeringVIPs("0.0.0.0"), "steering.vips[0] 0.0.0.0 is not a unicast address this box can carry"},
		{"unspecified v6", "", steeringVIPs("::"), "steering.vips[0] :: is not a unicast address this box can carry"},
		{"multicast v4", "", steeringVIPs("224.0.0.1"), "steering.vips[0] 224.0.0.1 is not a unicast address this box can carry"},
		{"multicast v6", "", steeringVIPs("ff02::1"), "steering.vips[0] ff02::1 is not a unicast address this box can carry"},
		{"link-local v4", "", steeringVIPs("169.254.1.1"), "steering.vips[0] 169.254.1.1 is not a unicast address this box can carry"},
		{"link-local v6", "", steeringVIPs("fe80::1"), "steering.vips[0] fe80::1 is not a unicast address this box can carry"},
		{"broadcast", "", steeringVIPs("255.255.255.255"), "steering.vips[0] 255.255.255.255 is not a unicast address this box can carry"},
		// Unmapped before the check: the mapped loopback is the loopback.
		{"mapped loopback", "", steeringVIPs("192.0.2.10", "::ffff:127.0.0.1"), "steering.vips[1] 127.0.0.1 is not a unicast address this box can carry"},
		{"listed twice", "", steeringVIPs("192.0.2.10", "::ffff:192.0.2.10"), `steering.vips[1] 192.0.2.10 is listed twice (as "192.0.2.10" and "::ffff:192.0.2.10")`},
		{"listed twice in two spellings of IPv6", "", steeringVIPs("2001:db8::10", "2001:DB8:0:0::10"), `steering.vips[1] 2001:db8::10 is listed twice (as "2001:db8::10" and "2001:DB8:0:0::10")`},
		{"IPv6 under disable_ipv6", "disable_ipv6: true\n", steeringVIPs("192.0.2.10", "2001:db8::10"), "steering.vips[1] 2001:db8::10 is IPv6 and disable_ipv6 is true: the node renders no [::]:443, so nothing could answer its probe"},
		{"65 VIPs", "", steeringVIPs(steeringAddrs(MaxSteeringVIPs + 1)...), "steering.vips lists 65 addresses; at most 64"},
		{"negative interval_seconds", "", "  interval_seconds: -1\n", "steering.interval_seconds must not be negative (0 means the default), got -1"},
		{"negative fail_after", "", "  fail_after: -1\n", "steering.fail_after must not be negative (0 means the default), got -1"},
		{"negative fail_window", "", "  fail_window: -2\n", "steering.fail_window must not be negative (0 means the default), got -2"},
		{"negative recover_after", "", "  recover_after: -3\n", "steering.recover_after must not be negative (0 means the default), got -3"},
		{"negative hold_down.min_seconds", "", "  hold_down:\n    min_seconds: -1\n", "steering.hold_down.min_seconds must not be negative (0 means the default), got -1"},
		{"negative hold_down.max_seconds", "", "  hold_down:\n    max_seconds: -1\n", "steering.hold_down.max_seconds must not be negative (0 means the default), got -1"},
		// 9999999999 s × time.Second wraps to a negative duration, which steer
		// would read as its default: without the bound this key would pass.
		{"interval_seconds that overflows", "", "  interval_seconds: 9999999999\n", "steering.interval_seconds 9999999999 is out of range"},
		{"hold_down.min_seconds that overflows", "", "  hold_down:\n    min_seconds: 9999999999\n", "steering.hold_down.min_seconds 9999999999 is out of range"},
		{"hold_down.max_seconds that overflows", "", "  hold_down:\n    max_seconds: 9999999999\n", "steering.hold_down.max_seconds 9999999999 is out of range"},
		{"interval_seconds a second past a day", "", "  interval_seconds: 86401\n", "steering.interval_seconds 86401 is out of range"},
		// A day itself is steer's to refuse, by its own bound.
		{"interval_seconds of a day", "", "  interval_seconds: 86400\n", "steering: steer: interval 24h0m0s is outside 1s..10s"},
		{"interval_seconds above 10", "", "  interval_seconds: 11\n", "steering: steer: interval 11s is outside 1s..10s"},
		{"recover_after below 3", "", "  recover_after: 2\n", "steering: steer: recover_after 2 is outside 3..120"},
		{"fail_after above fail_window", "", "  fail_after: 6\n  fail_window: 5\n", "steering: steer: fail_after 6 exceeds fail_window 5"},
		{"hold_down.max_seconds above the ceiling", "", "  hold_down:\n    max_seconds: 601\n", "steering: steer: hold_down max 10m1s exceeds the 10m0s ceiling"},
		{"hold_down.min_seconds above max", "", "  hold_down:\n    min_seconds: 70\n    max_seconds: 60\n", "steering: steer: hold_down min 1m10s exceeds hold_down max 1m0s"},
		{"a misspelled key", "", "  intervall_seconds: 2\n", "field intervall_seconds not found"},
	}
	for _, c := range bounds {
		for _, on := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enabled=%v", c.name, on), func(t *testing.T) {
				y := edgeYAML + c.top + "steering:\n" + c.body
				if on {
					y = edgeYAML + steeringListen + c.top + "steering:\n  enabled: true\n" + c.body
				}
				_, err := ParseEdgeNode([]byte(y))
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("err = %v, want %q", err, c.want)
				}
			})
		}
	}

	// The two rules that bind an enabled block alone.
	enabledOnly := []struct{ name, yaml, want string }{
		{"enabled without status_listen", edgeYAML + "steering:\n  enabled: true\n", "steering.enabled needs status_listen: GET /steer is served there (keep it on loopback)"},
		{"enabled with omit_catch_all", edgeYAML + steeringListen + "omit_catch_all: true\nsteering:\n  enabled: true\n", "steering.enabled refuses omit_catch_all: true in this release"},
	}
	for _, c := range enabledOnly {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseEdgeNode([]byte(c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestEdgeSteeringAccepts(t *testing.T) {
	cases := []struct {
		name, yaml string
		enabled    bool
		vips       []string
	}{
		// omit_catch_all is refused only beside an enabled block, so the
		// configs that set it today, steering off, stay valid.
		{"off under omit_catch_all", edgeYAML + "omit_catch_all: true\nsteering:\n  enabled: false\n" + steeringVIPs("192.0.2.10"), false, []string{"192.0.2.10"}},
		{"off without status_listen", edgeYAML + "steering:\n  enabled: false\n  interval_seconds: 2\n", false, nil},
		// Private and unique-local addresses are carried as any other: an
		// internal anycast service uses them.
		{"on with IPv4 and IPv6 VIPs", edgeYAML + steeringListen + "steering:\n  enabled: true\n" + steeringVIPs("192.0.2.10", "2001:db8::10", "10.0.0.1", "fd00::1"), true, []string{"192.0.2.10", "2001:db8::10", "10.0.0.1", "fd00::1"}},
		{"on with an IPv4 VIP under disable_ipv6", edgeYAML + steeringListen + "disable_ipv6: true\nsteering:\n  enabled: true\n" + steeringVIPs("::ffff:192.0.2.10"), true, []string{"192.0.2.10"}},
		{"on with no VIPs", edgeYAML + steeringListen + "steering:\n  enabled: true\n  vips: []\n", true, nil},
		{"on with 64 VIPs", edgeYAML + steeringListen + "steering:\n  enabled: true\n" + steeringVIPs(steeringAddrs(MaxSteeringVIPs)...), true, steeringAddrs(MaxSteeringVIPs)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := ParseEdgeNode([]byte(c.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if e.Steering.Enabled != c.enabled {
				t.Fatalf("enabled %v, want %v", e.Steering.Enabled, c.enabled)
			}
			var want []netip.Addr
			for _, v := range c.vips {
				want = append(want, netip.MustParseAddr(v))
			}
			if !slices.Equal(e.Steering.VIPAddrs, want) {
				t.Fatalf("VIPAddrs %v, want %v", e.Steering.VIPAddrs, want)
			}
		})
	}
}

// TestEdgeExampleParses pins the shipped example against KnownFields: a key
// the parser does not know fails here, not on an operator's first start.
func TestEdgeExampleParses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "edge.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := ParseEdgeNode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Steering.Enabled {
		t.Fatal("the example must ship steering off: watch first")
	}
	// Every damping key the example spells out is steer's default, so the
	// comments beside them stay true.
	if got := e.Steering.SteerConfig(); got != steer.DefaultConfig() {
		t.Fatalf("the example's steering block gives %+v, want steer's defaults %+v", got, steer.DefaultConfig())
	}
	// Turning the staged block on is the one change an operator makes: the
	// example's status_listen and catch-all already allow it.
	on := strings.Replace(string(raw), "\nsteering:\n  enabled: false\n", "\nsteering:\n  enabled: true\n", 1)
	if on == string(raw) {
		t.Fatal("the example has no `steering:` block starting with `enabled: false`")
	}
	if e, err = ParseEdgeNode([]byte(on)); err != nil || !e.Steering.Enabled {
		t.Fatalf("the example with steering turned on: %v", err)
	}
	// Listing the sample addresses is deleting the comment mark on their
	// lines, whichever way an editor deletes it. Under `vips: []` each way
	// is a YAML error that names the `steering:` line, not the `[]`; under
	// `vips:`, which lists none just as `[]` does, each is a list.
	wantVIPs := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	for _, mark := range []string{"#", "# ", "#  "} {
		listed := strings.ReplaceAll(on, "\n  #  - ", "\n  "+strings.TrimPrefix("#  - ", mark))
		if e, err = ParseEdgeNode([]byte(listed)); err != nil {
			t.Errorf("the example with its sample VIPs uncommented (%q deleted): %v", mark, err)
			continue
		}
		if !slices.Equal(e.Steering.VIPAddrs, wantVIPs) {
			t.Errorf("the example with its sample VIPs uncommented (%q deleted): VIPAddrs %v, want %v", mark, e.Steering.VIPAddrs, wantVIPs)
		}
	}
}

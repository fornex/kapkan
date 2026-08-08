package app

// Tests for the startup refusal that closes debt (b): a ladder rung that says
// "drop this in the kernel" while the mitigator has no backend for it would be
// announced as an alert-only stage, and nothing about the running system would
// say so.
//
// These are host-independent on purpose. The refusal has to fire on the macOS
// development box and in CI, not only on a machine that could actually attach an
// XDP program — the point is that the configuration never reaches a serving
// state, whatever the kernel can do.

import (
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

const ladderBase = `
listen:
  sflow: ":6343"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
thresholds:
  pps: 1000
  mbps: 100
  flows_per_sec: 500
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 60
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  neighbors:
    - address: "10.0.0.254"
      remote_asn: 65000
api:
  listen: "127.0.0.1:8080"
dataplane:
  interfaces: ["eth0"]
`

func parseLadder(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(ladderBase + extra))
	if err != nil {
		t.Fatalf("config.Parse: %v\n%s", err, ladderBase+extra)
	}
	return cfg
}

// TestCheckDataplaneLadder covers every spelling that resolves to the dataplane
// action, because the silent-alert-only failure does not care how the operator
// got there.
func TestCheckDataplaneLadder(t *testing.T) {
	if mitigate.SupportsDataplane() {
		t.Skip("the mitigator has a data-plane backend now; this refusal should have been deleted " +
			"along with SupportsDataplane — see the comment on it")
	}

	cases := []struct {
		name       string
		extra      string
		wantGroups []string
	}{
		{
			name:  "a ladder with no dataplane rung is fine",
			extra: "escalation:\n  - {after_seconds: 0, action: flowspec}\n",
		},
		{
			name:  "no ladder at all is fine",
			extra: "",
		},
		{
			name:       "a global escalation rung",
			extra:      "escalation:\n  - {after_seconds: 0, action: dataplane}\n  - {after_seconds: 60, action: blackhole}\n",
			wantGroups: []string{config.GlobalGroup},
		},
		{
			// mitigation: dataplane synthesizes a one-rung ladder, so an operator
			// who never wrote an escalation block reaches exactly the same silent
			// alert-only. This is the spelling most likely to be used.
			name:       "mitigation: dataplane, no escalation block",
			extra:      "mitigation: dataplane\n",
			wantGroups: []string{config.GlobalGroup},
		},
		{
			name: "a hostgroup overrides with dataplane",
			extra: "escalation:\n  - {after_seconds: 0, action: flowspec}\n" +
				"hostgroups:\n  - name: web\n    networks: [\"203.0.113.0/25\"]\n" +
				"    escalation:\n      - {after_seconds: 0, action: dataplane}\n",
			wantGroups: []string{"web"},
		},
		{
			// The group inherits the global ladder and has no escalation block of
			// its own, which is why the check reads the RESOLVED groups: looking at
			// the YAML would miss this entirely.
			name: "a hostgroup inherits a global dataplane rung",
			extra: "escalation:\n  - {after_seconds: 0, action: dataplane}\n" +
				"hostgroups:\n  - name: web\n    networks: [\"203.0.113.0/25\"]\n",
			wantGroups: []string{config.GlobalGroup, "web"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := parseLadder(t, tc.extra)
			gotGroups := groupsUsingDataplane(cfg)
			err := checkDataplaneLadder(cfg)

			if len(tc.wantGroups) == 0 {
				if err != nil {
					t.Fatalf("refused a configuration with no dataplane rung: %v", err)
				}
				if len(gotGroups) != 0 {
					t.Errorf("groupsUsingDataplane = %v, want none", gotGroups)
				}
				return
			}

			if err == nil {
				t.Fatalf("ACCEPTED a ladder using the dataplane action; it would be announced "+
					"as an alert-only stage and the traffic would not be dropped (groups: %v)", gotGroups)
			}
			if strings.Join(gotGroups, ",") != strings.Join(tc.wantGroups, ",") {
				t.Errorf("groupsUsingDataplane = %v, want %v", gotGroups, tc.wantGroups)
			}
			// The message has to be actionable: name the groups and the one line to
			// change. A refusal an operator cannot act on is only a slower failure.
			for _, want := range append([]string{"ALERT-ONLY", "flowspec"}, tc.wantGroups...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not mention %q:\n%v", want, err)
				}
			}
			t.Logf("refused: %v", err)
		})
	}
}

// TestConfigStillAcceptsTheLadder pins the boundary this refusal sits on.
//
// config.validate() ACCEPTS `action: dataplane` with a valid dataplane block —
// correctly, since the configuration describes something the feature will
// support and the config package compiles to wasm where it cannot know what a
// build can execute. That is precisely why the refusal has to live in app, and
// this test fails if someone "fixes" it by teaching config to reject the action
// (which would break the config builder and every future release that does
// support it).
func TestConfigStillAcceptsTheLadder(t *testing.T) {
	cfg := parseLadder(t, "escalation:\n  - {after_seconds: 0, action: dataplane}\n")
	if !cfg.DataplaneEnabled() {
		t.Fatal("the dataplane block did not resolve as enabled")
	}
	if len(groupsUsingDataplane(cfg)) == 0 {
		t.Fatal("config resolved a dataplane ladder into no group using it")
	}
}

// TestConfigRefusesADataplaneRungWithoutTheBlock is the layer above: config
// itself refuses the same class of mistake when the block is missing or off.
// Quoted here because it is the precedent the app-level refusal is modelled on —
// if this ever became a warning, the argument for refusing in app would need
// revisiting.
func TestConfigRefusesADataplaneRungWithoutTheBlock(t *testing.T) {
	withoutBlock := strings.Replace(ladderBase,
		"dataplane:\n  interfaces: [\"eth0\"]\n", "", 1)
	_, err := config.Parse([]byte(withoutBlock +
		"escalation:\n  - {after_seconds: 0, action: dataplane}\n"))
	if err == nil {
		t.Fatal("config accepted a dataplane rung with no dataplane block")
	}
	if !strings.Contains(err.Error(), "requires a dataplane block") {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("config refuses: %v", err)
}

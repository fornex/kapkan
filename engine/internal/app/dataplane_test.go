package app

// What survives of the `action: dataplane` guards, now that the mitigator has a
// backend and the app-level startup refusal has been deleted.
//
// The refusal (checkDataplaneLadder) and its table test are GONE, along with
// groupsUsingDataplane: mitigate.SupportsDataplane() is true, stageView resolves
// the rung to a real method, and the function returned nil for every input. The
// tests below are the two layers that are still live, and both were always about
// something other than the deleted function:
//
//   - config.Parse still ACCEPTS `action: dataplane` with a valid dataplane
//     block, and still REFUSES it without one. That boundary is what makes the
//     feature configurable at all, and it is enforced in a package that compiles
//     to wasm for the config builder.
//
// What is NOT here, deliberately: a test that a dataplane rung installs. That
// lives where it can be proven — internal/dataplane's e2e against a real kernel —
// rather than being asserted against a mock on a host with no eBPF.
//
// These stay host-independent: they must pass on the macOS development box and
// in CI, not only on a machine that can attach an XDP program.

import (
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/config"
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

// TestConfigStillAcceptsTheLadder pins the accepting half of the config
// boundary.
//
// config.validate() ACCEPTS `action: dataplane` with a valid dataplane block,
// and resolves it onto every group that inherits it. This fails if someone
// "fixes" a dataplane problem by teaching config to reject the action, which
// would break the config builder and every deployment already running one.
func TestConfigStillAcceptsTheLadder(t *testing.T) {
	cfg := parseLadder(t, "escalation:\n  - {after_seconds: 0, action: dataplane}\n"+
		"hostgroups:\n  - name: web\n    networks: [\"203.0.113.0/25\"]\n")
	if !cfg.DataplaneEnabled() {
		t.Fatal("the dataplane block did not resolve as enabled")
	}
	// The RESOLVED groups, not the YAML: `web` has no escalation block of its
	// own and inherits the global ladder, which is the case a YAML-level check
	// would miss.
	var withRung []string
	for _, g := range cfg.Groups {
		for _, s := range g.Escalation {
			if s.Action == config.EscalateDataplane {
				withRung = append(withRung, g.Name)
				break
			}
		}
	}
	if len(withRung) != 2 {
		t.Fatalf("resolved groups carrying the dataplane rung = %v, want the global group and web", withRung)
	}
}

// TestConfigRefusesADataplaneRungWithoutTheBlock is the refusal that is still
// live: config itself rejects a ladder naming the action when there is no
// dataplane block to install into. This is the layer that survived — it refuses
// a configuration that could never work, rather than one this build could not
// execute.
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

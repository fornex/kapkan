//go:build linux

package app

// The whole chain, on a real kernel, ending in the JSON an operator's console
// receives.
//
// Everything upstream of this is proven elsewhere: internal/dataplane's e2e
// shows that a detected attack installs rules and that a packet which passed
// before is dropped after. What has never been proven is the LAST hop — that the
// per-rule counters the datapath bumps come back out of /api/v1/bans and
// /api/v1/attacks, correctly scoped for the token that asked.
//
// It reaches the datapath through its BPFFS PIN, exactly as
// e2e_mitigate_linux_test.go does and for the same reason: the program that gets
// packets run through it is the one an operator's kernel is actually running,
// not a second copy loaded for the test.
//
// Runs under `make dataplane-test`, which executes this package inside a
// privileged container on a real kernel. On a host that cannot bring up a data
// plane it SKIPS rather than fails — a macOS `make test` must not go red for a
// missing kernel feature — but a skip is not a pass, which is why the target
// exists.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/pkg/pktgen"
)

const (
	xdpDrop = 1
	xdpPass = 2
)

// dpAPIYAML is a LIVE config: a global ladder that drops in the kernel, an
// operator and a viewer token, and a data plane pinned under a private bpffs
// directory.
func dpAPIYAML(pinPath string) string {
	return fmt.Sprintf(`dry_run: false
listen:
  netflow: ":0"
sampling:
  default_rate: 1
networks:
  - "203.0.113.0/24"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 1000
  mbps: 100000
  flows_per_sec: 1000000
ban:
  ttl_seconds: 600
  unban_hysteresis_seconds: 1
  max_active_bans: 10
escalation:
  - {after_seconds: 0, action: dataplane}
dataplane:
  enabled: true
  interfaces: ["lo"]
  xdp_mode: generic
  pin_path: %q
  on_exit: detach
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:0"
  tokens:
    - {name: rw, token_env: KAPKAN_DPAPI_RW, role: operator}
    - {name: ro, token_env: KAPKAN_DPAPI_RO, role: viewer}
`, pinPath)
}

// TestMeasuredDropsReachTheAPI drives the real thing end to end:
//
//	ban -> real rules in real maps -> real packets through the pinned XDP
//	program -> real kapkan_rule_stats -> the scraper -> the ban record ->
//	/api/v1/bans and /api/v1/attacks, for an operator token and a viewer token.
func TestMeasuredDropsReachTheAPI(t *testing.T) {
	t.Setenv("KAPKAN_DPAPI_RW", "op-secret")
	t.Setenv("KAPKAN_DPAPI_RO", "view-secret")

	dir := dpAPIPinDir(t)
	cfg, err := config.Parse([]byte(dpAPIYAML(dir)))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(&dpAPIWriter{t}, &slog.HandlerOptions{Level: slog.LevelInfo}))

	opts, err := dataplane.OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig: %v", err)
	}
	opts.Log = log
	opts.WatchInterval = -1
	mgr, err := dataplane.Open(opts)
	if err != nil {
		t.Skipf("cannot bring up the data plane here (%v); run `make dataplane-test`", err)
	}
	defer func() { _ = mgr.Close(config.OnExitDetach) }()
	t.Logf("data plane: %s", mgr.Health().Summary())

	// The same wiring app.New builds, assembled by hand because New would also
	// bind listeners and start goroutines this test has no use for.
	inst := dataplane.NewInstaller(mgr, log)
	mit, err := mitigate.New(store, log, mitigate.WithDataplane(inst))
	if err != nil {
		t.Fatalf("mitigate.New: %v", err)
	}
	eng := engine.New(store, engine.WithLogger(log))
	srv := api.New(store, eng, mit, log)
	h := srv.Handler()
	scraper := newBanCounterScraper(inst, mit, log, nil)

	victim := netip.MustParseAddr("203.0.113.66")

	/* ---- the ban: real rules, in this kernel ---- */

	// Through OnAttackStarted rather than ManualBan, so the ban is NARROWED by
	// the classification the way a detected attack's is: the installed rule
	// matches udp src-port 123 and not merely "everything to the victim". That
	// is what makes the "legitimate traffic keeps flowing" assertion below mean
	// something — against a manual ban's anchor-only rule it would be vacuous.
	ev := engine.Event{
		Kind: engine.AttackStarted, Scope: engine.ScopeHost, Target: victim,
		Group: "global", Direction: engine.DirIncoming, Metric: "pps",
		Rate: 200000, Threshold: 1000, At: time.Now(), BanEnabled: true,
		Classification: &engine.Classification{
			Type: engine.AttackNTPAmplification, Confidence: 0.9, SrcPort: 123,
		},
	}
	ban := mit.OnAttackStarted(ev)
	if ban == nil || ban.State != mitigate.BanActive || ban.Method != config.MitigateDataplane {
		t.Fatalf("ban = %+v, want an active dataplane ban", ban)
	}
	t.Logf("BANNED  %s -> %s", victim, ban.Route)

	// The same event on the API side, so /api/v1/attacks has something to join
	// the live counters onto.
	srv.RecordAttackStarted(ev, ban)

	/* ---- real packets through the pinned program ---- */

	prog := dpAPIPinnedProgram(t, dir)
	defer func() { _ = prog.Close() }()

	attack := dpAPIFrame(t, victim, 123)  // matches the installed rule
	legit := dpAPIFrame(t, victim, 53000) // the victim's ordinary traffic
	const attackPackets = 25
	for i := 0; i < attackPackets; i++ {
		if got := dpAPIRun(t, prog, attack); got != xdpDrop {
			t.Fatalf("attack packet %d: verdict %d, want XDP_DROP", i, got)
		}
	}
	if got := dpAPIRun(t, prog, legit); got != xdpPass {
		t.Fatalf("the victim's legitimate udp/53000 got verdict %d, want XDP_PASS", got)
	}
	t.Logf("ran %d attack packets (all XDP_DROP) and 1 legitimate packet (XDP_PASS) of %d bytes each",
		attackPackets, len(attack))

	/* ---- the scrape ---- */

	scraper.tick()

	/* ---- what the API serves ---- */

	for _, tok := range []struct{ name, token string }{{"operator", "op-secret"}, {"viewer", "view-secret"}} {
		bansBody := dpAPIGet(t, h, "/api/v1/bans", tok.token)
		t.Logf("=== %s token: GET /api/v1/bans ===\n%s", tok.name, bansBody)

		var bansResp struct {
			Bans []struct {
				Target    string                 `json:"target"`
				Method    string                 `json:"method"`
				Route     string                 `json:"route"`
				FlowSpec  []map[string]any       `json:"flowspec"`
				Dataplane *mitigate.BanDataplane `json:"dataplane"`
			} `json:"bans"`
		}
		if err := json.Unmarshal([]byte(bansBody), &bansResp); err != nil {
			t.Fatalf("%s: parse /api/v1/bans: %v", tok.name, err)
		}
		if len(bansResp.Bans) != 1 {
			t.Fatalf("%s: %d bans, want 1", tok.name, len(bansResp.Bans))
		}
		b := bansResp.Bans[0]
		if b.Method != "dataplane" {
			t.Errorf("%s: method = %q, want dataplane", tok.name, b.Method)
		}
		if b.Dataplane == nil {
			t.Fatalf("%s: the ban carries no measured drops", tok.name)
		}
		if b.Dataplane.Packets != attackPackets {
			t.Errorf("%s: measured %d packets, want the %d the kernel actually dropped",
				tok.name, b.Dataplane.Packets, attackPackets)
		}
		if b.Dataplane.Bytes != uint64(attackPackets*len(attack)) {
			t.Errorf("%s: measured %d bytes, want %d", tok.name, b.Dataplane.Bytes,
				attackPackets*len(attack))
		}
		if b.Dataplane.Stale {
			t.Errorf("%s: a just-taken measurement is marked stale", tok.name)
		}
		// The join the console relies on.
		if len(b.Dataplane.Rules) != len(b.FlowSpec) {
			t.Errorf("%s: %d rule counters for %d flowspec rules; the console joins them by index",
				tok.name, len(b.Dataplane.Rules), len(b.FlowSpec))
		}

		atkBody := dpAPIGet(t, h, "/api/v1/attacks", tok.token)
		t.Logf("=== %s token: GET /api/v1/attacks (active[0]) ===\n%s", tok.name,
			dpAPIFirstActive(t, atkBody))
		var atkResp struct {
			Active []struct {
				Target    string                 `json:"target"`
				Dataplane *mitigate.BanDataplane `json:"dataplane"`
			} `json:"active"`
		}
		if err := json.Unmarshal([]byte(atkBody), &atkResp); err != nil {
			t.Fatalf("%s: parse /api/v1/attacks: %v", tok.name, err)
		}
		if len(atkResp.Active) != 1 || atkResp.Active[0].Dataplane == nil {
			t.Fatalf("%s: the active attack carries no measured drops: %s", tok.name, atkBody)
		}
		if atkResp.Active[0].Dataplane.Packets != attackPackets {
			t.Errorf("%s: /api/v1/attacks reports %d packets, want %d",
				tok.name, atkResp.Active[0].Dataplane.Packets, attackPackets)
		}
	}

	/* ---- more traffic: the numbers must keep moving ---- */

	for i := 0; i < 5; i++ {
		dpAPIRun(t, prog, attack)
	}
	scraper.tick()
	var after mitigate.BanDataplane
	for _, b := range mit.ActiveBans() {
		if b.Dataplane != nil {
			after = *b.Dataplane
		}
	}
	if after.Packets != attackPackets+5 {
		t.Errorf("after 5 more drops the total is %d, want %d", after.Packets, attackPackets+5)
	}
	t.Logf("after 5 more attack packets: %d packets / %d bytes", after.Packets, after.Bytes)

	/* ---- withdraw: the final tally survives, nothing is installed ---- */

	if _, err := mit.ManualUnban(victim); err != nil {
		t.Fatalf("ManualUnban: %v", err)
	}
	if got := dpAPIRun(t, prog, attack); got != xdpPass {
		t.Fatalf("after the withdraw the attack packet got verdict %d, want XDP_PASS", got)
	}
	scraper.tick()
	body := dpAPIGet(t, h, "/api/v1/bans", "op-secret")
	if !strings.Contains(body, `"state": "withdrawn"`) && !strings.Contains(body, `"state":"withdrawn"`) {
		t.Errorf("the ban is not recorded as withdrawn:\n%s", body)
	}
	t.Logf("=== after the withdraw: GET /api/v1/bans ===\n%s", body)
}

/* ------------------------------------------------------------------ helpers */

type dpAPIWriter struct{ t *testing.T }

func (w *dpAPIWriter) Write(p []byte) (int, error) {
	w.t.Logf("  %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// bpfFSMagic identifies bpffs in statfs(2) (linux/magic.h BPF_FS_MAGIC).
const bpfFSMagic = 0xcafe4a11

// dpAPIPinDir returns a private directory on bpffs, MOUNTING one if the
// container has none. Mirrors internal/dataplane's bpffsRoot rather than
// requiring the caller to mount: `make dataplane-test` runs a bare alpine image
// where nothing has mounted /sys/fs/bpf, and a test that only works when the
// operator remembers an extra shell command is a test that stops being run.
//
// It skips (never fails) when there is no kernel to do this on, so `make test`
// on the macOS developer box stays green.
func dpAPIPinDir(t *testing.T) string {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise RLIMIT_MEMLOCK (%v); run `make dataplane-test`", err)
	}
	const base = "/sys/fs/bpf"
	var st syscall.Statfs_t
	if err := syscall.Statfs(base, &st); err != nil || uint64(st.Type) != bpfFSMagic {
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Skipf("no bpffs and cannot create %s (%v); run `make dataplane-test`", base, err)
		}
		if err := syscall.Mount("bpffs", base, "bpf", 0, ""); err != nil {
			t.Skipf("no bpffs at %s and mounting one failed (%v); run `make dataplane-test`", base, err)
		}
	}
	dir := filepath.Join(base, "kapkan-dpapi-"+t.Name())
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func dpAPIPinnedProgram(t *testing.T, dir string) *ebpf.Program {
	t.Helper()
	p, err := ebpf.LoadPinnedProgram(filepath.Join(dir, "prog"), nil)
	if err != nil {
		t.Fatalf("open the pinned program: %v", err)
	}
	return p
}

func dpAPIRun(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

// dpAPIFrame is a UDP datagram from a reflector to the victim; srcPort 123 is
// the NTP reflection the ban's rule matches.
func dpAPIFrame(t *testing.T, victim netip.Addr, srcPort uint16) []byte {
	t.Helper()
	b, err := pktgen.Frame{
		SrcMAC:  [6]byte{0x02, 0, 0, 0, 0, 2},
		DstMAC:  [6]byte{0x02, 0, 0, 0, 0, 1},
		SrcIP:   netip.MustParseAddr("198.51.100.7"),
		DstIP:   victim,
		Proto:   pktgen.ProtoUDP,
		SrcPort: srcPort,
		DstPort: 40000,
		Payload: make([]byte, 440),
	}.Build()
	if err != nil {
		t.Fatalf("build frame: %v", err)
	}
	return b
}

func dpAPIGet(t *testing.T, h http.Handler, path, token string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, rec.Code, rec.Body.String())
	}
	var pretty any
	if err := json.Unmarshal(rec.Body.Bytes(), &pretty); err != nil {
		t.Fatalf("GET %s: invalid JSON: %v", path, err)
	}
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return string(out)
}

// dpAPIFirstActive pretty-prints just active[0], so the log shows the object
// under test rather than a page of flow sample.
func dpAPIFirstActive(t *testing.T, body string) string {
	t.Helper()
	var doc struct {
		Active []json.RawMessage `json:"active"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil || len(doc.Active) == 0 {
		return body
	}
	var pretty any
	_ = json.Unmarshal(doc.Active[0], &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	return string(out)
}

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/pkg/flowgen"

	"log/slog"
	"net/netip"
)

// e2eYAML is a dry-run config with low thresholds and a short ban TTL so the
// end-to-end flow completes quickly.
func e2eYAML(sflowPort, apiPort int) string {
	return fmt.Sprintf(`dry_run: true
listen:
  sflow: ":%d"
sampling:
  default_rate: 1000
networks:
  - "203.0.113.0/24"
protected_whitelist:
  - "203.0.113.1"
thresholds:
  pps: 1000
  mbps: 100
  flows_per_sec: 1000
ban:
  ttl_seconds: 3
  unban_hysteresis_seconds: 2
  max_active_bans: 50
bgp:
  local_asn: 65001
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65000:666"
  listen_port: -1
  neighbors: []
notify: {}
api:
  listen: "127.0.0.1:%d"
`, sflowPort, apiPort)
}

type statusResp struct {
	DryRun        bool `json:"dry_run"`
	ActiveAttacks int  `json:"active_attacks"`
	ActiveBans    int  `json:"active_bans"`
}

type attacksResp struct {
	Active []struct {
		Target string `json:"target"`
		Metric string `json:"metric"`
		DryRun bool   `json:"dry_run"`
	} `json:"active"`
}

func getJSON(t *testing.T, url string, into any) bool {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx // test helper
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.Unmarshal(body, into) == nil
}

// TestEndToEndNTPAmplification replays an NTP-amplification pattern over a
// real UDP socket against a dry-run instance and asserts the attack appears
// in the API with a virtual ban that later expires by TTL.
func TestEndToEndNTPAmplification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in -short mode")
	}
	sflowPort := freeUDPPort(t)
	apiPort := freeTCPPort(t)

	cfg, err := config.Parse([]byte(e2eYAML(sflowPort, apiPort)))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	store := config.NewStore("", cfg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	application, err := New(store, log)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := application.Start(ctx); err != nil {
		t.Fatalf("app.Start: %v", err)
	}
	defer application.Stop()

	// Give the UDP listener and API a moment to bind.
	time.Sleep(500 * time.Millisecond)

	victim := netip.MustParseAddr("203.0.113.66")
	stopFlood := make(chan struct{})
	floodDone := make(chan struct{})
	go func() {
		defer close(floodDone)
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", sflowPort))
		if err != nil {
			t.Errorf("dial sflow udp: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		// NTP amplification: source port 123, large reflected responses.
		recs := flowgen.PatternParams{
			Pattern: flowgen.NTPAmplification,
			Victim:  victim,
			Records: 40,
		}.Build()
		payload := flowgen.BuildSFlowV5(recs, flowgen.SFlowOptions{
			AgentIP:      netip.MustParseAddr("198.51.100.1"),
			SamplingRate: 1000,
		})
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopFlood:
				return
			case <-ticker.C:
				_, _ = conn.Write(payload)
			}
		}
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", apiPort)

	// 1) Wait for the attack to appear in the API.
	if !waitFor(t, 20*time.Second, func() bool {
		var a attacksResp
		if !getJSON(t, base+"/api/v1/attacks", &a) {
			return false
		}
		for _, at := range a.Active {
			if at.Target == victim.String() {
				if at.Metric == "" {
					t.Errorf("active attack has empty metric")
				}
				return true
			}
		}
		return false
	}) {
		close(stopFlood)
		<-floodDone
		t.Fatal("attack never appeared in /api/v1/attacks")
	}

	// 2) A virtual (dry-run) ban must have been created.
	var st statusResp
	if !waitFor(t, 5*time.Second, func() bool {
		return getJSON(t, base+"/api/v1/status", &st) && st.ActiveBans >= 1
	}) {
		close(stopFlood)
		<-floodDone
		t.Fatalf("virtual ban never created; status=%+v", st)
	}
	if !st.DryRun {
		t.Error("status dry_run = false, want true")
	}

	// 3) The ban must auto-expire by TTL (3s), even though the flood
	// continues — proving no permanent bans.
	if !waitFor(t, 10*time.Second, func() bool {
		return getJSON(t, base+"/api/v1/status", &st) && st.ActiveBans == 0
	}) {
		close(stopFlood)
		<-floodDone
		t.Fatalf("ban never expired; status=%+v", st)
	}

	close(stopFlood)
	<-floodDone
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// freeUDPPort returns an available UDP port.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

// freeTCPPort returns an available TCP port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

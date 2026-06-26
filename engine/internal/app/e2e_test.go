package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
		Sample *struct {
			TopSrcPorts []struct {
				Key string `json:"key"`
			} `json:"top_src_ports"`
			Flows []struct {
				SrcPort uint16 `json:"src_port"`
			} `json:"flows"`
		} `json:"sample"`
		Classification *struct {
			Type    string `json:"type"`
			SrcPort uint16 `json:"src_port"`
		} `json:"classification"`
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
				// The attack must carry a flow sample showing the NTP
				// amplification signature (source port 123).
				if at.Sample == nil {
					t.Errorf("active attack has no sample")
				} else if len(at.Sample.TopSrcPorts) == 0 || at.Sample.TopSrcPorts[0].Key != "123" {
					t.Errorf("sample top src port = %+v, want 123 (NTP)", at.Sample.TopSrcPorts)
				}
				// And be classified as NTP amplification.
				if at.Classification == nil || at.Classification.Type != "ntp_amplification" {
					t.Errorf("classification = %+v, want ntp_amplification", at.Classification)
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

	// 3) While the flood continues the ban must PERSIST past its 3s TTL: the
	// engine re-reports the ongoing attack every window (AttackOngoing), which
	// refreshes the ban so the victim stays protected for the whole attack.
	// Regression guard: a sustained attack that outlives ban.ttl_seconds must
	// not be left exposed by the ban lapsing mid-attack.
	persistDeadline := time.Now().Add(8 * time.Second) // > 2× TTL
	for time.Now().Before(persistDeadline) {
		ok := getJSON(t, base+"/api/v1/status", &st)
		// The ban must stay up, and the per-window AttackOngoing heartbeat must
		// NOT be recorded as additional attacks (it is routed to mitigation only,
		// never to the API/storage/notify) — active attacks stays exactly 1.
		if !ok || st.ActiveBans < 1 || st.ActiveAttacks != 1 {
			close(stopFlood)
			<-floodDone
			t.Fatalf("sustained-attack state wrong (want ban up, exactly 1 active attack); status=%+v", st)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 4) Once the flood stops, the ban must auto-withdraw — proving no permanent
	// bans. The attack ends after the window drains and hysteresis elapses, the
	// TTL is no longer refreshed, and the route comes down.
	close(stopFlood)
	<-floodDone
	if !waitFor(t, 20*time.Second, func() bool {
		return getJSON(t, base+"/api/v1/status", &st) && st.ActiveBans == 0
	}) {
		t.Fatalf("ban never withdrawn after flood stopped; status=%+v", st)
	}
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

// fakeClickHouse records the table names of INSERTs it receives.
type fakeClickHouse struct {
	mu     sync.Mutex
	tables map[string]int
}

func (f *fakeClickHouse) count(table string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tables[table]
}

// TestEndToEndStorage replays an attack against a dry-run instance whose
// storage points at a fake ClickHouse, and asserts an attack_events row and
// a traffic snapshot are persisted — the full ingest→detect→persist path.
func TestEndToEndStorage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in -short mode")
	}
	fake := &fakeClickHouse{tables: map[string]int{}}
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(q, "INSERT INTO") {
			table := strings.Fields(q)[2]
			if i := strings.IndexByte(table, '.'); i >= 0 {
				table = table[i+1:]
			}
			n := strings.Count(strings.TrimSpace(string(body)), "\n") + 1
			fake.mu.Lock()
			fake.tables[table] += n
			fake.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ch.Close()

	sflowPort := freeUDPPort(t)
	apiPort := freeTCPPort(t)
	yaml := e2eYAML(sflowPort, apiPort) + fmt.Sprintf(`storage:
  clickhouse:
    url: %q
    flush_interval_seconds: 1
    traffic_interval_seconds: 1
`, ch.URL)

	cfg, err := config.Parse([]byte(yaml))
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
	time.Sleep(500 * time.Millisecond)

	victim := netip.MustParseAddr("203.0.113.66")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", sflowPort))
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		payload := flowgen.BuildSFlowV5(flowgen.PatternParams{
			Pattern: flowgen.NTPAmplification, Victim: victim, Records: 40,
		}.Build(), flowgen.SFlowOptions{AgentIP: netip.MustParseAddr("198.51.100.1"), SamplingRate: 1000})
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _ = conn.Write(payload)
			}
		}
	}()

	ok := waitFor(t, 20*time.Second, func() bool {
		return fake.count("attack_events") >= 1 && fake.count("traffic") >= 1
	})
	close(stop)
	<-done
	if !ok {
		t.Fatalf("storage did not receive rows: attack_events=%d traffic=%d",
			fake.count("attack_events"), fake.count("traffic"))
	}
}

// TestEndToEndFlowSpec replays an NTP-amplification attack against a dry-run
// instance whose global mitigation method is flowspec, and asserts the API
// surfaces generated FlowSpec rules (surgical drops) instead of a blackhole.
func TestEndToEndFlowSpec(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end test in -short mode")
	}
	sflowPort := freeUDPPort(t)
	apiPort := freeTCPPort(t)
	yaml := strings.Replace(e2eYAML(sflowPort, apiPort), "thresholds:",
		"mitigation: flowspec\nflowspec:\n  action: discard\nthresholds:", 1)

	cfg, err := config.Parse([]byte(yaml))
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
	time.Sleep(500 * time.Millisecond)

	victim := netip.MustParseAddr("203.0.113.66")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", sflowPort))
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		payload := flowgen.BuildSFlowV5(flowgen.PatternParams{
			Pattern: flowgen.NTPAmplification, Victim: victim, Records: 40,
		}.Build(), flowgen.SFlowOptions{AgentIP: netip.MustParseAddr("198.51.100.1"), SamplingRate: 1000})
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _ = conn.Write(payload)
			}
		}
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	ok := waitFor(t, 20*time.Second, func() bool {
		var a struct {
			Active []struct {
				Target   string `json:"target"`
				Method   string `json:"method"`
				FlowSpec []struct {
					Proto   uint8  `json:"proto"`
					SrcPort uint16 `json:"src_port"`
				} `json:"flowspec"`
			} `json:"active"`
		}
		if !getJSON(t, base+"/api/v1/attacks", &a) {
			return false
		}
		for _, at := range a.Active {
			if at.Target != victim.String() {
				continue
			}
			if at.Method != "flowspec" {
				t.Errorf("method = %q, want flowspec", at.Method)
			}
			// NTP amplification → a UDP src-port 123 rule.
			for _, r := range at.FlowSpec {
				if r.Proto == 17 && r.SrcPort == 123 {
					return true
				}
			}
		}
		return false
	})
	close(stop)
	<-done
	if !ok {
		t.Fatal("API never surfaced the expected FlowSpec rule for the attack")
	}
}

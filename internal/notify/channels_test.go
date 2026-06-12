package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/netip"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/mitigate"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// yamlNotify builds a config whose notify section is exactly the given
// block (indented two spaces per line already).
func yamlNotify(block string) string {
	base := yamlWith("")
	return strings.Replace(base, "notify:\n  telegram:\n    token_env: \"KAPKAN_TEST_TG_TOKEN\"\n    chat_id: \"-100123\"\n  webhook:\n    url: \"\"\n",
		"notify:\n"+block, 1)
}

func TestSlackNotification(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(storeFrom(t, yamlNotify("  slack:\n    webhook_url: \""+srv.URL+"\"\n")), discardLogger())
	ev := sampleEvent()
	ev.Direction = "outgoing"
	n.NotifyAttackStarted(context.Background(), ev, nil)

	select {
	case body := <-got:
		var msg struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatalf("unmarshal slack body: %v", err)
		}
		for _, want := range []string{"*DDoS attack STARTED*", "`203.0.113.50`", "OUTGOING"} {
			if !strings.Contains(msg.Text, want) {
				t.Errorf("slack text missing %q:\n%s", want, msg.Text)
			}
		}
		if strings.Contains(msg.Text, "<b>") {
			t.Error("slack text contains HTML; want mrkdwn")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("slack webhook not called")
	}
}

// fakeSMTP runs a minimal in-process SMTP server for one session and
// captures the DATA body, envelope recipients and any AUTH command.
type fakeSMTP struct {
	addr  string
	rcpts chan []string
	data  chan string
	auth  chan string
}

// fakeSMTPOpts shapes the fake server's behavior.
type fakeSMTPOpts struct {
	// starttls advertises and performs a STARTTLS upgrade with a
	// self-signed certificate.
	starttls bool
	// dropAfterData closes the connection right after accepting the
	// message, before the client can QUIT.
	dropAfterData bool
}

// selfSignedCert builds an in-memory certificate for the fake server.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startFakeSMTP(t *testing.T, opts fakeSMTPOpts) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeSMTP{
		addr:  ln.Addr().String(),
		rcpts: make(chan []string, 1),
		data:  make(chan string, 1),
		auth:  make(chan string, 1),
	}
	var cert tls.Certificate
	if opts.starttls {
		cert = selfSignedCert(t)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		// say writes to conn through the closure so the STARTTLS upgrade
		// (rebinding conn) is picked up automatically.
		say := func(s string) { _, _ = fmt.Fprintf(conn, "%s\r\n", s) }

		say("220 fake ESMTP")
		var rcpts []string
		var body strings.Builder
		inData := false
		upgraded := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					f.rcpts <- rcpts
					f.data <- body.String()
					say("250 ok")
					if opts.dropAfterData {
						return // hang up before QUIT
					}
					continue
				}
				body.WriteString(line + "\n")
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				say("250-fake")
				if opts.starttls && !upgraded {
					say("250-STARTTLS")
				}
				say("250 AUTH PLAIN")
			case line == "STARTTLS" && opts.starttls && !upgraded:
				say("220 go ahead")
				tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
				conn = tc
				r = bufio.NewReader(conn)
				upgraded = true
			case strings.HasPrefix(line, "AUTH "):
				f.auth <- line
				say("235 ok")
			case strings.HasPrefix(line, "MAIL FROM"):
				say("250 ok")
			case strings.HasPrefix(line, "RCPT TO:"):
				rcpts = append(rcpts, strings.Trim(strings.TrimPrefix(line, "RCPT TO:"), "<> "))
				say("250 ok")
			case line == "DATA":
				inData = true
				say("354 go")
			case line == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return f
}

func TestEmailNotification(t *testing.T) {
	smtp := startFakeSMTP(t, fakeSMTPOpts{})
	block := "  email:\n    smtp_host: \"" + smtp.addr + "\"\n" +
		"    from: \"kapkan@example.com\"\n    to: [\"ops@example.com\", \"noc@example.com\"]\n"
	n := New(storeFrom(t, yamlNotify(block)), discardLogger())
	n.NotifyAttackStarted(context.Background(), sampleEvent(), nil)

	select {
	case rcpts := <-smtp.rcpts:
		if len(rcpts) != 2 || rcpts[0] != "ops@example.com" {
			t.Errorf("rcpts = %v, want both configured recipients", rcpts)
		}
		body := <-smtp.data
		for _, want := range []string{
			"Subject: [kapkan] DDoS attack STARTED - 203.0.113.50",
			"Trigger: pps = 200000",
			"To: ops@example.com, noc@example.com",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("email missing %q:\n%s", want, body)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("email never delivered to the fake SMTP server")
	}
}

func TestExecHookReceivesPayload(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "payload.json")
	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > \""+outFile+"\"\necho \"$1\" >> \""+outFile+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	n := New(storeFrom(t, yamlNotify("  exec:\n    command: \""+script+"\"\n")), discardLogger())
	ev := sampleEvent()
	n.NotifyAttackStarted(context.Background(), ev, nil)

	var raw []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ = os.ReadFile(outFile)
		if strings.Contains(string(raw), "attack_started\n") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(raw), "attack_started\n") {
		t.Fatalf("hook never ran; captured: %q", raw)
	}

	jsonPart := string(raw[:strings.LastIndex(string(raw), "attack_started")])
	var p Payload
	if err := json.Unmarshal([]byte(jsonPart), &p); err != nil {
		t.Fatalf("hook stdin is not valid payload JSON: %v\n%s", err, jsonPart)
	}
	if p.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d, want %d", p.SchemaVersion, SchemaVersion)
	}
	if p.Event != "attack_started" || p.Target != "203.0.113.50" {
		t.Errorf("payload = %+v, want event/target preserved", p)
	}
}

func TestExecHookTimeoutKills(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "done")
	script := filepath.Join(dir, "slow.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\ntouch \""+marker+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	n := New(storeFrom(t, yamlNotify("  exec:\n    command: \""+script+"\"\n    timeout_seconds: 1\n")), discardLogger())
	start := time.Now()
	n.runExec(context.Background(), n.store.Get().Notify.Exec, n.buildPayload("attack_started", sampleEvent(), nil))
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runExec took %v; the 1s timeout did not kill the hook", elapsed)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("hook ran to completion despite the timeout")
	}
}

// schemaNode walks a parsed JSON schema along path, failing the test if any
// segment is missing.
func schemaNode(t *testing.T, node map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := node
	for _, p := range path {
		next, ok := cur[p].(map[string]any)
		if !ok {
			t.Fatalf("schema path %v: segment %q missing", path, p)
		}
		cur = next
	}
	return cur
}

// keysMatch asserts that two key sets are identical (both directions).
func keysMatch(t *testing.T, what string, got map[string]any, documented map[string]any) {
	t.Helper()
	for k := range got {
		if _, ok := documented[k]; !ok {
			t.Errorf("%s: produced key %q is not documented in docs/callback-schema.json", what, k)
		}
	}
	for k := range documented {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: schema documents %q but a fully-populated payload does not produce it", what, k)
		}
	}
}

// TestPayloadMatchesPublishedSchema: the published schema and the code
// cannot drift silently — top level, the nested sample object, flow
// records, counters, the metric enum and the required list are all
// cross-checked against real marshaled payloads.
func TestPayloadMatchesPublishedSchema(t *testing.T) {
	raw, err := os.ReadFile("../../docs/callback-schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	// A maximally-populated event/ban so no omitempty field is dropped.
	ev := sampleEvent()
	ev.Scope = engine.ScopeHost
	ev.Group = "web"
	ev.Direction = engine.DirIncoming
	ev.Sample = &engine.AttackSample{
		Flows: []engine.SampleFlow{{
			Src: "198.51.100.7", Dst: "203.0.113.50",
			SrcPort: 123, DstPort: 53, Proto: "udp",
			TCPFlags: 0x02, Fragment: true,
			Bytes: 468, Packets: 1, SamplingRate: 1000,
		}},
		TopSources:  []engine.Counter{{Key: "198.51.100.7", Packets: 1, Bytes: 468}},
		TopSrcPorts: []engine.Counter{{Key: "123", Packets: 1, Bytes: 468}},
		TopDstPorts: []engine.Counter{{Key: "53", Packets: 1, Bytes: 468}},
		Protocols:   []engine.Counter{{Key: "udp", Packets: 1, Bytes: 468}},
	}
	ev.Classification = &engine.Classification{Type: engine.AttackNTPAmplification, Confidence: 0.9, SrcPort: 123}
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	ban := &mitigate.Ban{State: mitigate.BanActive, Route: "203.0.113.50/32 next-hop 192.0.2.1", DryRun: true}
	body, err := json.Marshal(n.buildPayload("attack_started", ev, ban))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}

	// Top level.
	keysMatch(t, "payload", got, schemaNode(t, schema, "properties"))

	// Classification object and its attack-type enum.
	gotCls, ok := got["classification"].(map[string]any)
	if !ok {
		t.Fatal("payload classification missing")
	}
	keysMatch(t, "classification", gotCls, schemaNode(t, schema, "properties", "classification", "properties"))
	typeEnum := schemaNode(t, schema, "properties", "classification", "properties", "type")["enum"].([]any)
	documentedTypes := map[string]bool{}
	for _, v := range typeEnum {
		documentedTypes[v.(string)] = true
	}
	for _, at := range engine.AttackTypes() {
		if !documentedTypes[string(at)] {
			t.Errorf("attack type %q missing from the schema enum", at)
		}
	}
	if len(documentedTypes) != len(engine.AttackTypes()) {
		t.Errorf("schema enum has %d attack types, engine defines %d", len(documentedTypes), len(engine.AttackTypes()))
	}

	// Nested sample object.
	gotSample, ok := got["sample"].(map[string]any)
	if !ok {
		t.Fatal("payload sample missing")
	}
	keysMatch(t, "sample", gotSample, schemaNode(t, schema, "properties", "sample", "properties"))

	// Flow records.
	gotFlow := gotSample["flows"].([]any)[0].(map[string]any)
	keysMatch(t, "sample.flows[]", gotFlow,
		schemaNode(t, schema, "properties", "sample", "properties", "flows", "items", "properties"))

	// Counters ($defs shared by the four top-K lists).
	gotCounter := gotSample["top_sources"].([]any)[0].(map[string]any)
	keysMatch(t, "counters", gotCounter, schemaNode(t, schema, "$defs", "counters", "items", "properties"))

	// The metric enum must equal the engine's full metric set.
	enumRaw := schemaNode(t, schema, "properties", "metric")["enum"].([]any)
	documented := map[string]bool{}
	for _, v := range enumRaw {
		documented[v.(string)] = true
	}
	for _, m := range engine.Metrics() {
		if !documented[string(m)] {
			t.Errorf("engine metric %q missing from the schema enum", m)
		}
	}
	if len(documented) != len(engine.Metrics()) {
		t.Errorf("schema enum has %d metrics, engine defines %d", len(documented), len(engine.Metrics()))
	}

	// Every schema-required field must survive even a minimally-populated
	// payload (omitempty regressions on required fields).
	minimal, err := json.Marshal(n.buildPayload("attack_ended", engine.Event{Kind: engine.AttackEnded, At: time.Now()}, nil))
	if err != nil {
		t.Fatal(err)
	}
	var gotMin map[string]any
	if err := json.Unmarshal(minimal, &gotMin); err != nil {
		t.Fatal(err)
	}
	for _, req := range schema["required"].([]any) {
		if _, ok := gotMin[req.(string)]; !ok {
			t.Errorf("required field %q absent from a minimal payload (omitempty regression?)", req)
		}
	}
}

// counterDelta reads the notifications counter for (channel, result).
func counterValue(channel, result string) float64 {
	return testutil.ToFloat64(metrics.NotificationsTotal.WithLabelValues(channel, result))
}

// TestEmailSTARTTLSAndAuth: the upgrade path and AUTH PLAIN actually run —
// the session is upgraded with the server's certificate and credentials
// from the environment arrive in the AUTH command.
func TestEmailSTARTTLSAndAuth(t *testing.T) {
	smtp := startFakeSMTP(t, fakeSMTPOpts{starttls: true})
	t.Setenv("KAPKAN_TEST_SMTP_USER", "mailuser")
	t.Setenv("KAPKAN_TEST_SMTP_PASS", "mailpass")

	block := "  email:\n    smtp_host: \"" + smtp.addr + "\"\n" +
		"    from: \"kapkan@example.com\"\n    to: [\"ops@example.com\"]\n" +
		"    username_env: \"KAPKAN_TEST_SMTP_USER\"\n    password_env: \"KAPKAN_TEST_SMTP_PASS\"\n"
	n := New(storeFrom(t, yamlNotify(block)), discardLogger())
	n.smtpTLS = &tls.Config{InsecureSkipVerify: true} // self-signed test cert

	n.NotifyAttackStarted(context.Background(), sampleEvent(), nil)

	select {
	case authLine := <-smtp.auth:
		parts := strings.Fields(authLine) // AUTH PLAIN <b64>
		if len(parts) != 3 || parts[1] != "PLAIN" {
			t.Fatalf("auth line = %q, want AUTH PLAIN <b64>", authLine)
		}
		raw, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if want := "\x00mailuser\x00mailpass"; string(raw) != want {
			t.Errorf("AUTH PLAIN payload = %q, want %q", raw, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AUTH never reached the server")
	}
	select {
	case body := <-smtp.data:
		if !strings.Contains(body, "DDoS attack STARTED") {
			t.Errorf("delivered body missing content:\n%s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("message never delivered over the upgraded session")
	}
}

// TestEmailRefusesWithoutTLSWhenRequired: a STARTTLS-stripping downgrade
// (or require_tls against a plaintext server) yields a loud refusal — and
// the same applies when credentials are configured.
func TestEmailRefusesWithoutTLSWhenRequired(t *testing.T) {
	for _, tc := range []struct{ name, extra string }{
		{"require_tls", "    require_tls: true\n"},
		{"credentials imply TLS", "    username_env: \"KAPKAN_TEST_SMTP_USER\"\n    password_env: \"KAPKAN_TEST_SMTP_PASS\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KAPKAN_TEST_SMTP_USER", "u")
			t.Setenv("KAPKAN_TEST_SMTP_PASS", "p")
			smtp := startFakeSMTP(t, fakeSMTPOpts{}) // no STARTTLS offered
			block := "  email:\n    smtp_host: \"" + smtp.addr + "\"\n" +
				"    from: \"a@b\"\n    to: [\"c@d\"]\n" + tc.extra
			n := New(storeFrom(t, yamlNotify(block)), discardLogger())

			err := n.smtpSend(n.store.Get().Notify.Email, n.buildPayload("attack_started", sampleEvent(), nil))
			if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
				t.Fatalf("smtpSend error = %v, want STARTTLS refusal", err)
			}
			select {
			case <-smtp.data:
				t.Fatal("message was sent despite the TLS requirement")
			default:
			}
		})
	}
}

// TestQuitFailureIsNotDeliveryFailure: a server hanging up right after
// accepting DATA must still count as a successful delivery.
func TestQuitFailureIsNotDeliveryFailure(t *testing.T) {
	smtp := startFakeSMTP(t, fakeSMTPOpts{dropAfterData: true})
	block := "  email:\n    smtp_host: \"" + smtp.addr + "\"\n    from: \"a@b\"\n    to: [\"c@d\"]\n"
	n := New(storeFrom(t, yamlNotify(block)), discardLogger())

	if err := n.smtpSend(n.store.Get().Notify.Email, n.buildPayload("attack_started", sampleEvent(), nil)); err != nil {
		t.Fatalf("smtpSend error = %v, want nil: the message was accepted before the hangup", err)
	}
}

// TestEmailFailureRecorded: an unreachable SMTP server records an error
// instead of panicking the delivery goroutine.
func TestEmailFailureRecorded(t *testing.T) {
	before := counterValue("email", "error")
	// A listener we immediately close: connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	block := "  email:\n    smtp_host: \"" + addr + "\"\n    from: \"a@b\"\n    to: [\"c@d\"]\n"
	n := New(storeFrom(t, yamlNotify(block)), discardLogger())
	n.sendEmail(n.store.Get().Notify.Email, n.buildPayload("attack_started", sampleEvent(), nil))

	if after := counterValue("email", "error"); after != before+1 {
		t.Errorf("email error counter = %v, want %v", after, before+1)
	}
}

// TestNon2xxRecordedAsError: a 500 from the webhook endpoint must be
// recorded as a delivery error.
func TestNon2xxRecordedAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	before := counterValue("webhook", "error")
	n := New(storeFrom(t, yamlWith(srv.URL)), discardLogger())
	n.sendWebhook(context.Background(), srv.URL, n.buildPayload("attack_started", sampleEvent(), nil))
	if after := counterValue("webhook", "error"); after != before+1 {
		t.Errorf("webhook error counter = %v, want %v (non-2xx must be an error)", after, before+1)
	}
}

// TestExecHookEndedEventArg: attack_ended reaches the hook with the right
// argv[1] and payload event.
func TestExecHookEndedEventArg(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "payload.json")
	script := filepath.Join(dir, "hook.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > \""+outFile+"\"\necho \"$1\" >> \""+outFile+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(storeFrom(t, yamlNotify("  exec:\n    command: \""+script+"\"\n")), discardLogger())
	n.NotifyAttackEnded(context.Background(), sampleEvent(), nil)

	var raw []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ = os.ReadFile(outFile)
		if strings.HasSuffix(strings.TrimSpace(string(raw)), "attack_ended") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(raw)), "attack_ended") {
		t.Fatalf("hook argv for ended event wrong; captured: %q", raw)
	}
	if !strings.Contains(string(raw), `"event":"attack_ended"`) {
		t.Errorf("payload event mismatch; captured: %q", raw)
	}
}

// TestExecHookFailureRecordsError: a nonzero exit (with chatty output) is
// recorded as an error and the bounded buffer keeps the daemon safe.
func TestExecHookFailureRecordsError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fail.sh")
	// ~64KB of output, then fail: exercises the bounded buffer + truncate.
	if err := os.WriteFile(script, []byte("#!/bin/sh\ni=0; while [ $i -lt 1024 ]; do printf '0123456789012345678901234567890123456789012345678901234567890123'; i=$((i+1)); done\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := counterValue("exec", "error")
	n := New(storeFrom(t, yamlNotify("  exec:\n    command: \""+script+"\"\n")), discardLogger())
	n.runExec(context.Background(), n.store.Get().Notify.Exec, n.buildPayload("attack_started", sampleEvent(), nil))
	if after := counterValue("exec", "error"); after != before+1 {
		t.Errorf("exec error counter = %v, want %v", after, before+1)
	}
}

// TestExecHookEnvScrubbed: the hook sees a minimal environment without the
// daemon's notification secrets.
func TestExecHookEnvScrubbed(t *testing.T) {
	t.Setenv("KAPKAN_TG_TOKEN", "super-secret-token")
	dir := t.TempDir()
	outFile := filepath.Join(dir, "env.txt")
	script := filepath.Join(dir, "env.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nenv > \""+outFile+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(storeFrom(t, yamlNotify("  exec:\n    command: \""+script+"\"\n")), discardLogger())
	n.runExec(context.Background(), n.store.Get().Notify.Exec, n.buildPayload("attack_started", sampleEvent(), nil))

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("hook never wrote env: %v", err)
	}
	if strings.Contains(string(raw), "super-secret-token") || strings.Contains(string(raw), "KAPKAN_TG_TOKEN") {
		t.Error("hook environment contains the daemon's secrets")
	}
	if !strings.Contains(string(raw), "PATH=") {
		t.Error("hook environment lost PATH")
	}
}

// TestDispatchDropsWhenSaturated: with every delivery slot taken, dispatch
// drops instead of piling up goroutines.
func TestDispatchDropsWhenSaturated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	n := New(storeFrom(t, yamlWith(srv.URL)), discardLogger())

	for i := 0; i < maxConcurrentPerChannel; i++ {
		n.slots["webhook"] <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxConcurrentPerChannel; i++ {
			<-n.slots["webhook"]
		}
	}()

	before := counterValue("webhook", "dropped")
	n.NotifyAttackStarted(context.Background(), sampleEvent(), nil)
	if after := counterValue("webhook", "dropped"); after != before+1 {
		t.Errorf("dropped counter = %v, want %v when slots are saturated", after, before+1)
	}
}

// TestGroupScopedFormatting: group events render as hostgroup totals in the
// Slack text and the email subject/body.
func TestGroupScopedFormatting(t *testing.T) {
	ev := sampleEvent()
	ev.Scope = engine.ScopeGroup
	ev.Group = "pool"
	ev.Target = netip.Addr{}
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	p := n.buildPayload("attack_started", ev, nil)

	slack := formatSlack(p)
	if !strings.Contains(slack, "hostgroup `pool` (total traffic)") {
		t.Errorf("slack group rendering wrong:\n%s", slack)
	}
	mail := string(emailMessage(config.Email{From: "a@b", To: []string{"c@d"}}, p))
	if !strings.Contains(mail, "Subject: [kapkan] DDoS attack STARTED - hostgroup pool") {
		t.Errorf("email subject for group event wrong:\n%s", mail)
	}
	if !strings.Contains(mail, "Target: hostgroup pool") {
		t.Errorf("email body for group event wrong:\n%s", mail)
	}
}

// TestSlackEscapesReservedChars: &, < and > are escaped per Slack's API.
func TestSlackEscapesReservedChars(t *testing.T) {
	p := Payload{Event: "attack_started", Scope: "host", Target: "203.0.113.50", Group: "r-d", BanState: "active", Route: "x <y> & z"}
	text := formatSlack(p)
	if strings.Contains(text, "<y>") || strings.Contains(text, "& z") {
		t.Errorf("unescaped slack metacharacters:\n%s", text)
	}
	if !strings.Contains(text, "&lt;y&gt;") {
		t.Errorf("expected escaped sequence in:\n%s", text)
	}
}

// TestClassificationInMessages: the inferred vector renders in Telegram,
// Slack and email texts, including the reflected port for amplification.
func TestClassificationInMessages(t *testing.T) {
	ev := sampleEvent()
	ev.Classification = &engine.Classification{Type: engine.AttackNTPAmplification, Confidence: 0.94, SrcPort: 123}
	n := New(storeFrom(t, yamlWith("")), discardLogger())
	p := n.buildPayload("attack_started", ev, nil)

	want := "Type: ntp_amplification (94% confidence, reflected from port 123)"
	if text := formatTelegram(p); !strings.Contains(text, want) {
		t.Errorf("telegram missing classification:\n%s", text)
	}
	if text := formatSlack(p); !strings.Contains(text, want) {
		t.Errorf("slack missing classification:\n%s", text)
	}
	mail := string(emailMessage(config.Email{From: "a@b", To: []string{"c@d"}}, p))
	if !strings.Contains(mail, want) {
		t.Errorf("email missing classification:\n%s", mail)
	}

	// Non-amplification vectors omit the port note.
	p.Classification = &engine.Classification{Type: engine.AttackSYNFlood, Confidence: 0.8}
	if text := formatTelegram(p); !strings.Contains(text, "Type: syn_flood (80% confidence)") {
		t.Errorf("telegram syn classification wrong:\n%s", text)
	}
}

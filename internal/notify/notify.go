// Package notify delivers attack lifecycle notifications to Telegram and a
// generic JSON webhook. Delivery is best-effort and asynchronous: a slow or
// failing notification channel must never stall detection or mitigation.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// maxConcurrentPerChannel bounds simultaneous deliveries per channel. A
// carpet-bomb attack emits one event per attacked host; without a cap that
// becomes an unbounded fork/connection storm on the detection host at the
// exact moment it is busiest.
const maxConcurrentPerChannel = 16

// Notifier sends notifications for attack events. The zero value is not
// usable; construct with New.
type Notifier struct {
	store  *config.Store
	log    *slog.Logger
	client *http.Client
	// slots is the per-channel delivery semaphore (see launch).
	slots map[string]chan struct{}
	// tgAPIBase overrides the Telegram API base URL (tests).
	tgAPIBase string
	// smtpTLS overrides the STARTTLS client configuration (tests).
	smtpTLS *tls.Config
}

// New creates a Notifier reading channel configuration from store.
func New(store *config.Store, log *slog.Logger) *Notifier {
	slots := make(map[string]chan struct{})
	for _, ch := range []string{"telegram", "webhook", "slack", "email", "exec"} {
		slots[ch] = make(chan struct{}, maxConcurrentPerChannel)
	}
	return &Notifier{
		store:     store,
		log:       log.With("component", "notify"),
		client:    &http.Client{Timeout: 10 * time.Second},
		slots:     slots,
		tgAPIBase: "https://api.telegram.org",
	}
}

// SchemaVersion identifies the payload shape for webhook and exec-hook
// consumers. Bump it on any breaking change and update
// docs/callback-schema.json accordingly.
const SchemaVersion = 1

// Payload is the structured notification body. It is the exact shape POSTed
// to the generic webhook and piped to the exec hook's stdin, documented in
// docs/callback-schema.json, and the basis for the chat message texts.
type Payload struct {
	// SchemaVersion is always set; consumers should check it.
	SchemaVersion int    `json:"schema_version"`
	Event         string `json:"event"` // "attack_started" | "attack_ended"
	// Scope is "host" or "group". Target is empty for group-scoped events;
	// Group names the hostgroup whose total traffic is under attack.
	Scope  string `json:"scope"`
	Target string `json:"target,omitempty"`
	Group  string `json:"group,omitempty"`
	// Direction is "incoming" for attacks on the target, "outgoing" when
	// the target originates the attack (compromised host).
	Direction   string    `json:"direction,omitempty"`
	Metric      string    `json:"metric,omitempty"`
	Rate        float64   `json:"rate,omitempty"`
	Threshold   float64   `json:"threshold,omitempty"`
	PPS         float64   `json:"pps"`
	Mbps        float64   `json:"mbps"`
	FlowsPerSec float64   `json:"flows_per_sec"`
	BanState    string    `json:"ban_state,omitempty"`
	Route       string    `json:"route,omitempty"`
	DryRun      bool      `json:"dry_run"`
	At          time.Time `json:"at"`
	// Sample carries the attack's flow sample (attack_started only).
	Sample *engine.AttackSample `json:"sample,omitempty"`
}

// NotifyAttackStarted dispatches start notifications for ev and the resulting
// ban. It returns immediately; delivery runs in the background.
func (n *Notifier) NotifyAttackStarted(ctx context.Context, ev engine.Event, ban *mitigate.Ban) {
	n.dispatch(ctx, n.buildPayload("attack_started", ev, ban))
}

// NotifyAttackEnded dispatches end notifications for ev and the final ban.
func (n *Notifier) NotifyAttackEnded(ctx context.Context, ev engine.Event, ban *mitigate.Ban) {
	n.dispatch(ctx, n.buildPayload("attack_ended", ev, ban))
}

func (n *Notifier) buildPayload(event string, ev engine.Event, ban *mitigate.Ban) Payload {
	p := Payload{
		SchemaVersion: SchemaVersion,
		Event:         event,
		Scope:         string(ev.Scope),
		Group:         ev.Group,
		Direction:     string(ev.Direction),
		Metric:        string(ev.Metric),
		Rate:          ev.Rate,
		Threshold:     ev.Threshold,
		PPS:           ev.Rates.PPS,
		Mbps:          ev.Rates.Mbps,
		FlowsPerSec:   ev.Rates.FlowsPerSec,
		At:            ev.At,
		Sample:        ev.Sample,
	}
	if ev.Target.IsValid() {
		p.Target = ev.Target.String()
	}
	if ban != nil {
		p.BanState = string(ban.State)
		p.Route = ban.Route
		p.DryRun = ban.DryRun
	} else {
		p.DryRun = n.store.Get().DryRun
	}
	return p
}

// dispatch sends the payload to every configured channel concurrently.
// Deliveries are detached from the caller's context: graceful shutdown must
// not abort a half-sent alert (every channel bounds itself with its own
// timeout instead).
func (n *Notifier) dispatch(ctx context.Context, p Payload) {
	cfg := n.store.Get()
	ctx = context.WithoutCancel(ctx)
	if tok := telegramToken(cfg); tok != "" && cfg.Notify.Telegram.ChatID != "" {
		n.launch("telegram", func() { n.sendTelegram(ctx, cfg, tok, p) })
	}
	if cfg.Notify.Webhook.URL != "" {
		n.launch("webhook", func() { n.sendWebhook(ctx, cfg.Notify.Webhook.URL, p) })
	}
	if cfg.Notify.Slack.WebhookURL != "" {
		n.launch("slack", func() { n.sendSlack(ctx, cfg.Notify.Slack.WebhookURL, p) })
	}
	if cfg.Notify.Email.SMTPHost != "" {
		n.launch("email", func() { n.sendEmail(cfg.Notify.Email, p) })
	}
	if cfg.Notify.Exec.Command != "" {
		n.launch("exec", func() { n.runExec(ctx, cfg.Notify.Exec, p) })
	}
}

// launch runs deliver on one of the channel's bounded worker slots. When
// the channel is saturated the notification is dropped and counted:
// notification backpressure must never reach detection, and an attack storm
// must not pile up unbounded goroutines, sockets or hook processes.
func (n *Notifier) launch(channel string, deliver func()) {
	select {
	case n.slots[channel] <- struct{}{}:
		go func() {
			defer func() { <-n.slots[channel] }()
			deliver()
		}()
	default:
		n.log.Warn("notification dropped: delivery slots saturated", "channel", channel)
		metrics.NotificationsTotal.WithLabelValues(channel, "dropped").Inc()
	}
}

// telegramToken reads the bot token from the configured environment variable.
// The token is never read from the config file itself.
func telegramToken(cfg *config.Config) string {
	if cfg.Notify.Telegram.TokenEnv == "" {
		return ""
	}
	return os.Getenv(cfg.Notify.Telegram.TokenEnv)
}

func (n *Notifier) sendTelegram(ctx context.Context, cfg *config.Config, token string, p Payload) {
	text := formatTelegram(p)
	body, err := json.Marshal(map[string]any{
		"chat_id":    cfg.Notify.Telegram.ChatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	if err != nil {
		n.recordResult("telegram", err)
		return
	}
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", n.tgAPIBase, token)
	n.recordResult("telegram", n.post(ctx, endpoint, "application/json", body))
}

func (n *Notifier) sendWebhook(ctx context.Context, rawURL string, p Payload) {
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		n.recordResult("webhook", fmt.Errorf("invalid webhook url: %w", err))
		return
	}
	body, err := json.Marshal(p)
	if err != nil {
		n.recordResult("webhook", err)
		return
	}
	n.recordResult("webhook", n.post(ctx, rawURL, "application/json", body))
}

// post sends a POST with a bounded timeout and treats non-2xx as an error.
func (n *Notifier) post(ctx context.Context, endpoint, contentType string, body []byte) error {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) recordResult(channel string, err error) {
	result := "ok"
	if err != nil {
		result = "error"
		n.log.Warn("notification delivery failed", "channel", channel, "err", err)
	}
	metrics.NotificationsTotal.WithLabelValues(channel, result).Inc()
}

// formatTelegram renders a human-readable HTML message for Telegram.
func formatTelegram(p Payload) string {
	emoji := "🔴"
	verb := "STARTED"
	if p.Event == "attack_ended" {
		emoji = "🟢"
		verb = "ENDED"
	}
	mode := "LIVE"
	if p.DryRun {
		mode = "DRY-RUN"
	}
	msg := fmt.Sprintf("%s <b>DDoS attack %s</b> [%s]\n", emoji, verb, mode)
	if p.Scope == "group" {
		msg += fmt.Sprintf("Target: hostgroup <code>%s</code> (total traffic)\n", p.Group)
	} else {
		msg += fmt.Sprintf("Target: <code>%s</code>\n", p.Target)
		if p.Group != "" && p.Group != "global" {
			msg += fmt.Sprintf("Group: %s\n", p.Group)
		}
	}
	if p.Direction == "outgoing" {
		msg += "⚠️ OUTGOING attack — the host is attacking others (likely compromised)\n"
	}
	if p.Metric != "" {
		msg += fmt.Sprintf("Trigger: %s = %.0f (threshold %.0f)\n", p.Metric, p.Rate, p.Threshold)
	}
	msg += fmt.Sprintf("Rates: %.0f pps / %.1f Mbps / %.0f fps\n", p.PPS, p.Mbps, p.FlowsPerSec)
	if s := formatSample(p.Sample); s != "" {
		msg += s
	}
	if p.BanState != "" {
		msg += fmt.Sprintf("Ban: %s", p.BanState)
		if p.Route != "" {
			msg += fmt.Sprintf(" (%s)", p.Route)
		}
	}
	return msg
}

// formatSample renders a compact one-line summary of the attack sample for
// Telegram: protocol mix, dominant sources and the busiest destination port.
func formatSample(s *engine.AttackSample) string {
	if s == nil {
		return ""
	}
	var parts []string
	if len(s.Protocols) > 0 {
		parts = append(parts, s.Protocols[0].Key)
	}
	if len(s.TopSources) > 0 {
		n := len(s.TopSources)
		if n > 3 {
			n = 3
		}
		srcs := make([]string, 0, n)
		for _, c := range s.TopSources[:n] {
			srcs = append(srcs, c.Key)
		}
		parts = append(parts, "top src "+strings.Join(srcs, ", "))
	}
	if len(s.TopDstPorts) > 0 {
		parts = append(parts, "dst port "+s.TopDstPorts[0].Key)
	}
	if len(parts) == 0 {
		return ""
	}
	return "Sample: " + strings.Join(parts, " | ") + "\n"
}

// Package notify delivers attack lifecycle notifications to Telegram and a
// generic JSON webhook. Delivery is best-effort and asynchronous: a slow or
// failing notification channel must never stall detection or mitigation.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/metrics"
	"github.com/kapkan-io/kapkan/internal/mitigate"
)

// Notifier sends notifications for attack events. The zero value is not
// usable; construct with New.
type Notifier struct {
	store  *config.Store
	log    *slog.Logger
	client *http.Client
	// tgAPIBase overrides the Telegram API base URL (tests).
	tgAPIBase string
}

// New creates a Notifier reading channel configuration from store.
func New(store *config.Store, log *slog.Logger) *Notifier {
	return &Notifier{
		store:     store,
		log:       log.With("component", "notify"),
		client:    &http.Client{Timeout: 10 * time.Second},
		tgAPIBase: "https://api.telegram.org",
	}
}

// Payload is the structured notification body. It is the exact shape POSTed
// to the generic webhook and the basis for the Telegram message text.
type Payload struct {
	Event string `json:"event"` // "attack_started" | "attack_ended"
	// Scope is "host" or "group". Target is empty for group-scoped events;
	// Group names the hostgroup whose total traffic is under attack.
	Scope       string    `json:"scope"`
	Target      string    `json:"target,omitempty"`
	Group       string    `json:"group,omitempty"`
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
		Event:       event,
		Scope:       string(ev.Scope),
		Group:       ev.Group,
		Metric:      string(ev.Metric),
		Rate:        ev.Rate,
		Threshold:   ev.Threshold,
		PPS:         ev.Rates.PPS,
		Mbps:        ev.Rates.Mbps,
		FlowsPerSec: ev.Rates.FlowsPerSec,
		At:          ev.At,
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
func (n *Notifier) dispatch(ctx context.Context, p Payload) {
	cfg := n.store.Get()
	if tok := telegramToken(cfg); tok != "" && cfg.Notify.Telegram.ChatID != "" {
		go n.sendTelegram(ctx, cfg, tok, p)
	}
	if cfg.Notify.Webhook.URL != "" {
		go n.sendWebhook(ctx, cfg.Notify.Webhook.URL, p)
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
	if p.Metric != "" {
		msg += fmt.Sprintf("Trigger: %s = %.0f (threshold %.0f)\n", p.Metric, p.Rate, p.Threshold)
	}
	msg += fmt.Sprintf("Rates: %.0f pps / %.1f Mbps / %.0f fps\n", p.PPS, p.Mbps, p.FlowsPerSec)
	if p.BanState != "" {
		msg += fmt.Sprintf("Ban: %s", p.BanState)
		if p.Route != "" {
			msg += fmt.Sprintf(" (%s)", p.Route)
		}
	}
	return msg
}

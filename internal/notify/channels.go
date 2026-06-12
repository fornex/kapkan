package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
)

// sendSlack posts the payload to a Slack incoming webhook as mrkdwn text.
func (n *Notifier) sendSlack(ctx context.Context, webhookURL string, p Payload) {
	body, err := json.Marshal(map[string]string{"text": formatSlack(p)})
	if err != nil {
		n.recordResult("slack", err)
		return
	}
	n.recordResult("slack", n.post(ctx, webhookURL, "application/json", body))
}

// formatSlack renders the notification as Slack mrkdwn.
func formatSlack(p Payload) string {
	emoji := ":red_circle:"
	verb := "STARTED"
	if p.Event == "attack_ended" {
		emoji = ":large_green_circle:"
		verb = "ENDED"
	}
	mode := "LIVE"
	if p.DryRun {
		mode = "DRY-RUN"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s *DDoS attack %s* [%s]\n", emoji, verb, mode)
	if p.Scope == "group" {
		fmt.Fprintf(&b, "Target: hostgroup `%s` (total traffic)\n", p.Group)
	} else {
		fmt.Fprintf(&b, "Target: `%s`\n", p.Target)
		if p.Group != "" && p.Group != "global" {
			fmt.Fprintf(&b, "Group: %s\n", p.Group)
		}
	}
	if p.Direction == "outgoing" {
		b.WriteString(":warning: OUTGOING attack — the host is attacking others (likely compromised)\n")
	}
	if c := formatClassification(p.Classification); c != "" {
		b.WriteString(c)
	}
	if p.Metric != "" {
		fmt.Fprintf(&b, "Trigger: %s = %.0f (threshold %.0f)\n", p.Metric, p.Rate, p.Threshold)
	}
	fmt.Fprintf(&b, "Rates: %.0f pps / %.1f Mbps / %.0f fps\n", p.PPS, p.Mbps, p.FlowsPerSec)
	if s := formatSample(p.Sample); s != "" {
		b.WriteString(s)
	}
	if p.BanState != "" {
		fmt.Fprintf(&b, "Ban: %s", p.BanState)
		if p.Route != "" {
			fmt.Fprintf(&b, " (`%s`)", p.Route)
		}
	}
	// Slack requires &, < and > escaped in message text; none of our own
	// formatting uses them, so escaping the whole text is safe.
	return slackEscaper.Replace(b.String())
}

// slackEscaper escapes the three characters Slack's API reserves.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// sendEmail delivers the notification over SMTP with a bounded dial and
// session, using STARTTLS when the server offers it and AUTH PLAIN when
// credentials are configured.
func (n *Notifier) sendEmail(cfg config.Email, p Payload) {
	n.recordResult("email", n.smtpSend(cfg, p))
}

func (n *Notifier) smtpSend(cfg config.Email, p Payload) error {
	conn, err := net.DialTimeout("tcp", cfg.SMTPHost, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	// A session deadline bounds every subsequent read/write: a stalled
	// server cannot pin the goroutine.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	host, _, _ := net.SplitHostPort(cfg.SMTPHost)
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = client.Close() }()

	user := ""
	if cfg.UsernameEnv != "" {
		user = os.Getenv(cfg.UsernameEnv)
	}

	hasTLS, _ := client.Extension("STARTTLS")
	switch {
	case hasTLS:
		tlsCfg := n.smtpTLS
		if tlsCfg == nil {
			tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	case cfg.RequireTLS || user != "":
		// Refusing here (instead of letting AUTH fail or sending plaintext)
		// turns an active STARTTLS-stripping downgrade into a loud error
		// rather than silent cleartext or silent alert suppression.
		return fmt.Errorf("smtp server %s does not offer STARTTLS, which is required by require_tls or configured credentials", cfg.SMTPHost)
	case !isLoopback(host):
		n.log.Warn("sending email notification without TLS", "smtp_host", cfg.SMTPHost)
	}

	if user != "" {
		if err := client.Auth(smtp.PlainAuth("", user, os.Getenv(cfg.PasswordEnv), host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range cfg.To {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(emailMessage(cfg, p)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	// The server accepted the message when DATA completed; a failed QUIT
	// must not report a delivered mail as an error.
	if err := client.Quit(); err != nil {
		n.log.Debug("smtp quit after successful delivery", "err", err)
	}
	return nil
}

// isLoopback reports whether host is the local machine, best-effort (named
// hosts other than localhost are treated as remote).
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// emailMessage renders the RFC 5322 message: a compact subject and a
// plain-text body mirroring the other channels.
func emailMessage(cfg config.Email, p Payload) []byte {
	verb := "STARTED"
	if p.Event == "attack_ended" {
		verb = "ENDED"
	}
	target := p.Target
	if p.Scope == "group" {
		target = "hostgroup " + p.Group
	}
	mode := ""
	if p.DryRun {
		mode = " [DRY-RUN]"
	}

	// Headers are plain US-ASCII by construction (no RFC 2047 encoding is
	// done here): interpolated values are IPs, validated group names and
	// validated config addresses. headerSafe strips CR/LF as defense in
	// depth behind that validation.
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(cfg.From))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(cfg.To, ", ")))
	fmt.Fprintf(&b, "Subject: [kapkan] DDoS attack %s - %s%s\r\n", verb, headerSafe(target), mode)
	fmt.Fprintf(&b, "Date: %s\r\n", p.At.Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")

	fmt.Fprintf(&b, "DDoS attack %s%s\r\n\r\n", verb, mode)
	fmt.Fprintf(&b, "Target: %s\r\n", target)
	if p.Group != "" && p.Group != "global" && p.Scope != "group" {
		fmt.Fprintf(&b, "Group: %s\r\n", p.Group)
	}
	if p.Direction != "" {
		fmt.Fprintf(&b, "Direction: %s\r\n", p.Direction)
	}
	if c := formatClassification(p.Classification); c != "" {
		b.WriteString(strings.ReplaceAll(c, "\n", "\r\n"))
	}
	if p.Metric != "" {
		fmt.Fprintf(&b, "Trigger: %s = %.0f (threshold %.0f)\r\n", p.Metric, p.Rate, p.Threshold)
	}
	fmt.Fprintf(&b, "Rates: %.0f pps / %.1f Mbps / %.0f fps\r\n", p.PPS, p.Mbps, p.FlowsPerSec)
	if s := formatSample(p.Sample); s != "" {
		b.WriteString(strings.ReplaceAll(s, "\n", "\r\n"))
	}
	if p.BanState != "" {
		fmt.Fprintf(&b, "Ban: %s\r\n", p.BanState)
		if p.Route != "" {
			fmt.Fprintf(&b, "Route: %s\r\n", p.Route)
		}
	}
	fmt.Fprintf(&b, "At: %s\r\n", p.At.Format(time.RFC3339))
	return b.Bytes()
}

// runExec invokes the operator's hook with the payload JSON on stdin and
// the event name as the only argument. The command runs directly (no
// shell) and its whole process group is killed when the configured timeout
// elapses.
func (n *Notifier) runExec(ctx context.Context, hook config.Exec, p Payload) {
	body, err := json.Marshal(p)
	if err != nil {
		n.recordResult("exec", err)
		return
	}
	runCtx, cancel := context.WithTimeout(ctx, hook.Timeout())
	defer cancel()

	cmd := exec.CommandContext(runCtx, hook.Command, p.Event)
	cmd.Stdin = bytes.NewReader(body)
	// The hook gets a minimal environment. The daemon's environment carries
	// every notification secret (bot tokens, SMTP credentials, per the
	// env-only secrets rule), which third-party hook scripts and their
	// children have no business inheriting.
	cmd.Env = minimalEnv()
	// Kill the hook's whole process group on timeout so grandchildren do
	// not survive as orphans; WaitDelay is the backstop if something still
	// holds the output pipes open.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second

	// Output is captured only as error context, with a hard cap: a chatty
	// hook must not hold daemon memory during an attack storm.
	out := &boundedBuffer{max: 4096}
	cmd.Stdout = out
	cmd.Stderr = out

	err = cmd.Run()
	if err != nil {
		switch {
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			err = fmt.Errorf("hook timed out after %s", hook.Timeout())
		case runCtx.Err() != nil:
			err = fmt.Errorf("hook canceled: %w", context.Cause(runCtx))
		case len(out.b) > 0:
			err = fmt.Errorf("%w: %s", err, truncate(string(out.b), 512))
		}
	}
	n.recordResult("exec", err)
}

// minimalEnv passes through only benign variables to hooks.
func minimalEnv() []string {
	env := make([]string, 0, 6)
	for _, k := range []string{"PATH", "HOME", "TZ", "LANG", "USER", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// boundedBuffer keeps the first max bytes written and discards the rest,
// reporting full writes so the writer never errors.
type boundedBuffer struct {
	b   []byte
	max int
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	if rem := w.max - len(w.b); rem > 0 {
		take := p
		if len(take) > rem {
			take = take[:rem]
		}
		w.b = append(w.b, take...)
	}
	return len(p), nil
}

// truncate bounds hook output quoted in error logs.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// headerSafe strips CR/LF from a value interpolated into an email header.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

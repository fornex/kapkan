// Package exporter implements `kapkan nginx-exporter` — the reference feeder
// for the source-block channel, and a supported component rather than a
// disposable example, because it is the embryo of the future edge role.
//
// The division of labour is the edge charter in miniature: nginx already
// terminates the victim's traffic and sees every request; this process reads
// its access log, measures per-source request rates and status mixes over a
// fixed window, and hands the verdict to the brain's source-block API, which
// enforces it in the XDP data plane. HTTP awareness without Kapkan parsing
// HTTP — the decision is made where requests are visible, the enforcement
// happens at the cheapest layer that can express it.
//
// WHAT IT DELIBERATELY IS NOT. It is not a WAF (it never reads request
// content — only source, destination and status), not a detector (no
// baselines, no classification: a fixed threshold an operator wrote), and not
// a daemon with its own API (verdicts flow one way, to the brain, which
// audits every one). Every guarantee lives brain-side: TTL bounds, dry-run,
// tenant scoping, the allowlist/whitelist refusals — this process cannot
// bypass any of them, by construction, because it is just another API caller.
//
// The log contract is a documented nginx log_format (JSON, one object per
// line):
//
//	log_format kapkan escape=json
//	    '{"src":"$remote_addr","dst":"$server_addr","status":"$status"}';
//	access_log /var/log/nginx/kapkan.json.log kapkan;
//
// Extra fields are ignored, so an operator may fold in anything else they
// log. "dst" names the victim the block is scoped to; a -victim flag
// overrides it for setups where $server_addr is not the protected address
// (a proxy_protocol hop, a unix-socket upstream).
package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"log/slog"
)

// Config is the exporter's whole surface, filled from flags by cmd/kapkan.
type Config struct {
	// LogPath is the nginx access log in the documented JSON format.
	LogPath string
	// APIBase is the brain, e.g. "http://127.0.0.1:8080".
	APIBase string
	// Token is the operator bearer token (read from an env var by the caller;
	// never from a flag, so it cannot leak into `ps`).
	Token string
	// Victim, when valid, overrides the log's "dst" for every line.
	Victim netip.Addr
	// Window is the measurement window.
	Window time.Duration
	// RPS arms a block when a source's request rate over the window reaches
	// it. Requests per second, of whatever nginx logged — including requests
	// nginx itself refused (4xx/5xx): those are exactly the flood's shape.
	RPS float64
	// MinRequests is the floor a pair must clear in a window before any rate
	// arithmetic happens: a rate computed from three requests is noise.
	MinRequests int
	// ErrorRatio, when > 0, additionally requires at least this share of the
	// pair's requests to be 4xx/5xx. 0 disables the axis: a flood of
	// well-formed 200s is still a flood.
	ErrorRatio float64
	// TTL is the block TTL posted to the brain; a still-hot source is
	// re-posted before it lapses (the refresh contract the API documents).
	TTL time.Duration
	// Observe stops short of POSTing: decisions are logged, nothing is sent.
	// The brain's own dry_run gives deployment-wide record-only semantics;
	// this is the exporter-local trial knob for a brain that is already live.
	Observe bool

	Log *slog.Logger
}

// Validate applies the same philosophy as the daemon config: refuse loudly
// rather than run with a surface the operator did not mean.
func (c *Config) Validate() error {
	if c.LogPath == "" {
		return fmt.Errorf("-log is required: the nginx access log in the documented JSON format")
	}
	if c.APIBase == "" {
		return fmt.Errorf("-api is required: the brain's API base URL")
	}
	if !c.Observe && c.Token == "" {
		return fmt.Errorf("the API token is empty: set the token env var, or run with -observe")
	}
	if c.Window < time.Second || c.Window > time.Minute {
		return fmt.Errorf("-window must be within [1s, 1m], got %s", c.Window)
	}
	if c.RPS <= 0 {
		return fmt.Errorf("-rps must be > 0, got %g", c.RPS)
	}
	if c.MinRequests < 1 {
		return fmt.Errorf("-min-requests must be >= 1, got %d", c.MinRequests)
	}
	if c.ErrorRatio < 0 || c.ErrorRatio > 1 {
		return fmt.Errorf("-error-ratio must be within [0, 1], got %g", c.ErrorRatio)
	}
	// The brain's own bounds, checked here too so a misconfiguration fails at
	// startup instead of as a 400 on the first attack.
	if c.TTL < time.Second || c.TTL > 24*time.Hour {
		return fmt.Errorf("-ttl must be within [1s, 24h], got %s", c.TTL)
	}
	// The refresh contract ("a still-hot source is re-posted before its TTL
	// lapses") is only true when at least two window ticks fit inside one
	// TTL; a TTL shorter than that would let blocks flap on and off under a
	// steady flood, so refuse the combination instead of documenting a lie.
	if c.TTL < 2*c.Window {
		return fmt.Errorf("-ttl (%s) must be at least twice -window (%s), or a still-hot "+
			"source's block lapses between refreshes", c.TTL, c.Window)
	}
	u, err := url.Parse(c.APIBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-api must be an http(s) URL like http://127.0.0.1:8080, got %q "+
			"(a bad URL would otherwise surface only as the FIRST verdict failing, mid-attack)", c.APIBase)
	}
	return nil
}

// isLoopbackAPI reports whether the API base points at this machine — the one
// place a cleartext operator token is not on a wire.
func isLoopbackAPI(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// pair is the measurement key: the block the API takes is per (victim,
// source), so the counters are too.
type pair struct {
	victim netip.Addr
	source netip.Addr
}

type counts struct {
	total  int
	errors int // status 4xx/5xx
}

// verdict is one hot pair a window produced, with the numbers that made it
// hot (they become the audited reason).
type verdict struct {
	p     pair
	rate  float64
	ratio float64
}

// evaluate applies the thresholds to a closed window. Pure, so the decision
// arithmetic is testable without a log file, a clock or a server.
//
// elapsed is the REAL time the window covered, not the nominal cfg.Window —
// the difference is a false-block bug, not pedantry. When the loop stalls
// (a partitioned brain making POSTs eat their timeouts), the log backlog
// drains into one oversized window; dividing that by the nominal duration
// inflates every source's rate by the stall factor, and the first thing an
// inflated rate does is push a steady, legitimate client over the threshold.
func evaluate(window map[pair]*counts, cfg *Config, elapsed time.Duration) []verdict {
	if elapsed < cfg.Window {
		elapsed = cfg.Window
	}
	var out []verdict
	for p, c := range window {
		rate := float64(c.total) / elapsed.Seconds()
		ratio := 0.0
		if c.total > 0 {
			ratio = float64(c.errors) / float64(c.total)
		}
		if c.total >= cfg.MinRequests && rate >= cfg.RPS &&
			(cfg.ErrorRatio == 0 || ratio >= cfg.ErrorRatio) {
			out = append(out, verdict{p: p, rate: rate, ratio: ratio})
		}
	}
	return out
}

// maxWindowPairs bounds the per-window measurement map. The sources behind it
// are real HTTP clients, but "real" includes a routed IPv6 /64 handing one
// attacker 2^64 addresses to rotate through — without a cap that is an OOM of
// the exporter during exactly the flood it exists to watch. 64Ki pairs is a
// few MB; everything past it is counted and reported, not silently eaten.
const maxWindowPairs = 64 << 10

// logLine is the documented log contract. Unknown fields are ignored on
// purpose — the operator's log_format may carry more.
type logLine struct {
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Status string `json:"status"`
}

// parseLine turns one log line into a measurement, or reports why not.
// Garbage is counted by the caller and never fatal: a log is an untrusted
// input that rotates, truncates and interleaves, and one bad line must not
// stop the loop.
func parseLine(raw []byte, override netip.Addr) (pair, bool, error) {
	var l logLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return pair{}, false, fmt.Errorf("not the documented JSON log_format: %w", err)
	}
	src, err := netip.ParseAddr(l.Src)
	if err != nil {
		return pair{}, false, fmt.Errorf("src %q: %w", l.Src, err)
	}
	victim := override
	if !victim.IsValid() {
		if victim, err = netip.ParseAddr(l.Dst); err != nil {
			return pair{}, false, fmt.Errorf("dst %q (and no -victim override): %w", l.Dst, err)
		}
	}
	if victim.Unmap().Is4() != src.Unmap().Is4() {
		// The brain refuses mixed-family pairs (a v4 rule cannot name a v6
		// end); skipping here keeps a v6 client behind a v4 -victim override
		// from costing one doomed, audited 400 per hot window.
		return pair{}, false, fmt.Errorf("src %s and victim %s are different address families", src, victim)
	}
	isErr := len(l.Status) > 0 && (l.Status[0] == '4' || l.Status[0] == '5')
	return pair{victim: victim.Unmap(), source: src.Unmap()}, isErr, nil
}

// Run tails the log and posts verdicts until ctx ends. It returns only on
// context cancellation or a startup-class failure (the log file unopenable);
// everything after startup is retried, logged and survived.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "nginx-exporter")

	t, err := newTailer(cfg.LogPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", cfg.LogPath, err)
	}
	defer t.close()

	cl := newClient(cfg.APIBase, cfg.Token)
	if !cfg.Observe && strings.HasPrefix(cfg.APIBase, "http://") && !isLoopbackAPI(cfg.APIBase) {
		log.Warn("the operator token will cross the network in CLEARTEXT: -api is plain http " +
			"to a non-loopback host — put the brain behind TLS for anything but a lab")
	}

	log.Info("nginx-exporter started",
		"log", cfg.LogPath, "api", cfg.APIBase, "window", cfg.Window.String(),
		"rps", cfg.RPS, "min_requests", cfg.MinRequests, "error_ratio", cfg.ErrorRatio,
		"ttl", cfg.TTL.String(), "observe", cfg.Observe)

	var (
		window   = make(map[pair]*counts)
		blocked  = make(map[pair]time.Time) // pair -> expiry of the last posted TTL
		retryAt  = make(map[pair]time.Time) // pair -> when a FAILED post may retry
		overflow int                        // pairs the window cap refused this window
		garbage  int
		ticker   = time.NewTicker(cfg.Window)
		lastNote time.Time
		lastEval = time.Now()
	)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case raw, ok := <-t.lines(ctx):
			if !ok {
				// The pump closes its channel only on context cancellation;
				// returning here (rather than spinning on a closed channel
				// until the ctx.Done case happens to win the select) is the
				// same exit, taken deterministically.
				return ctx.Err()
			}
			p, isErr, err := parseLine(raw, cfg.Victim)
			if err != nil {
				// Throttled: a wrong log_format garbles EVERY line, and one
				// note per window says so without drowning the journal.
				garbage++
				if time.Since(lastNote) > cfg.Window {
					log.Warn("unparseable log lines (wrong log_format?)",
						"since_last_note", garbage, "example_err", err.Error())
					garbage, lastNote = 0, time.Now()
				}
				continue
			}
			c := window[p]
			if c == nil {
				if len(window) >= maxWindowPairs {
					overflow++
					continue
				}
				c = &counts{}
				window[p] = c
			}
			c.total++
			if isErr {
				c.errors++
			}

		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastEval)
			lastEval = now
			if overflow > 0 {
				log.Warn("window pair cap reached; excess pairs were counted but not measured",
					"cap", maxWindowPairs, "overflow", overflow)
				overflow = 0
			}
			for _, v := range evaluate(window, &cfg, elapsed) {
				p, rate, ratio := v.p, v.rate, v.ratio
				// Refresh only when the last posted TTL has burned below
				// half, so a persistent offender costs two POSTs per TTL,
				// not one per window.
				if exp, ok := blocked[p]; ok && exp.Sub(now) > cfg.TTL/2 {
					continue
				}
				// A pair whose last post FAILED waits out a backoff before
				// another attempt: with a partitioned brain, retrying every
				// hot pair every window turns each tick into N client
				// timeouts back to back, and the stalled loop is what turns
				// backlogs into oversized windows in the first place.
				if ra, ok := retryAt[p]; ok && now.Before(ra) {
					continue
				}
				reason := fmt.Sprintf("nginx-exporter: %.0f rps, %d%% errors over %s",
					rate, int(ratio*100), elapsed.Round(time.Second))
				if cfg.Observe {
					log.Warn("OBSERVE: would block source (not sent)",
						"source", p.source.String(), "victim", p.victim.String(), "reason", reason)
					blocked[p] = now.Add(cfg.TTL)
					continue
				}
				if err := cl.blockSource(ctx, p.victim, p.source, cfg.TTL, reason); err != nil {
					// Refusals are the BRAIN's judgement (allowlisted source,
					// protected victim, tenant scope) — log them verbatim; the
					// next attempt re-decides against fresh policy after the
					// backoff.
					log.Error("source block refused or failed",
						"source", p.source.String(), "victim", p.victim.String(), "err", err)
					retryAt[p] = now.Add(2 * cfg.Window)
					continue
				}
				delete(retryAt, p)
				blocked[p] = now.Add(cfg.TTL)
				log.Warn("source block posted",
					"source", p.source.String(), "victim", p.victim.String(),
					"ttl", cfg.TTL.String(), "reason", reason)
			}
			// The window is fixed, not sliding: simple to reason about, and
			// the brain-side TTL padding covers the boundary seams. A FRESH
			// map rather than clear(): clear keeps the grown bucket array,
			// which after one hostile window is hundreds of MB held forever.
			window = make(map[pair]*counts)
			for p, exp := range blocked {
				if now.After(exp) {
					delete(blocked, p)
				}
			}
			for p, ra := range retryAt {
				if now.After(ra) {
					delete(retryAt, p)
				}
			}
		}
	}
}

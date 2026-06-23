// Package update implements the OPTIONAL, opt-in check for a newer kapkan
// release. kapkan never phones home by default; when enabled this polls the
// GitHub Releases API on an interval, compares the latest tag to the running
// version, and exposes the result on /api/v1/status, the kapkan_update_available
// metric and a rate-limited log line. It transmits only the HTTP request (source
// IP + a generic User-Agent) — no node identity, config, attack data or ban
// state — and is meant to run on a detached goroutine with a bounded timeout, so
// a firewalled or slow endpoint never delays startup or BGP bring-up.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/metrics"
)

// repoAPI is the GitHub REST base for this repository's releases.
const repoAPI = "https://api.github.com/repos/fornex/kapkan"

// Status is the latest known update-check result, served to the API.
type Status struct {
	Available     bool      // a strictly newer, comparable release exists
	LatestVersion string    // the latest release tag seen (e.g. "v1.3.0")
	Security      bool      // the latest release is flagged security-relevant
	URL           string    // the release's html_url
	CheckedAt     time.Time // when the latest successful check completed
}

// Config configures a Checker.
type Config struct {
	Enabled   bool          // gate the periodic Run loop (CheckOnce ignores it)
	Interval  time.Duration // poll interval; <=0 defaults to 6h
	Channel   string        // "stable" (default) or "prerelease"
	URL       string        // endpoint override; empty derives from Channel
	Current   string        // the running version (from internal/buildinfo)
	UserAgent string        // empty derives "kapkan/<version> (update-check)"
}

// Checker polls for releases and holds the latest result.
type Checker struct {
	cfg    Config
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	mu         sync.Mutex
	status     Status
	etag       string // last 200's ETag, for If-None-Match
	lastLogged string // last tag we emitted the "update available" log for
}

// New builds a Checker, applying defaults.
func New(cfg Config, log *slog.Logger) *Checker {
	if cfg.Interval <= 0 {
		cfg.Interval = 6 * time.Hour
	}
	if cfg.Channel == "" {
		cfg.Channel = "stable"
	}
	if cfg.URL == "" {
		cfg.URL = defaultURL(cfg.Channel)
	}
	if cfg.UserAgent == "" {
		// Send only a COARSE version (MAJOR.MINOR.PATCH, or "dev"): the raw
		// buildinfo version can be a git-describe with a commit SHA and a -dirty
		// flag, which must not leak to the endpoint. The privacy promise is that
		// the request carries nothing identifying beyond the public repo.
		cfg.UserAgent = "kapkan/" + uaVersion(cfg.Current) + " (update-check)"
	}
	return &Checker{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		log:    log.With("component", "update"),
		now:    time.Now,
	}
}

// uaVersion renders the coarse version for the User-Agent: vMAJOR.MINOR.PATCH
// when the build version has a parseable core (dropping any prerelease / commit
// SHA / -dirty suffix), else "dev". This keeps a git-describe or dirty build
// from transmitting identifying detail.
func uaVersion(v string) string {
	if c, ok := parseCore(v); ok {
		return fmt.Sprintf("v%d.%d.%d", c[0], c[1], c[2])
	}
	return "dev"
}

func defaultURL(channel string) string {
	if channel == "prerelease" {
		return repoAPI + "/releases?per_page=30"
	}
	return repoAPI + "/releases/latest"
}

// Status returns a copy of the latest known result (thread-safe).
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Run polls until ctx is cancelled. The first check runs immediately but, being
// on this (caller's) goroutine, never blocks the daemon's startup. A no-op when
// disabled.
func (c *Checker) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	c.checkAndRecord(ctx)
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.checkAndRecord(ctx)
		}
	}
}

func (c *Checker) checkAndRecord(ctx context.Context) {
	rel, notModified, err := c.fetch(ctx, true)
	if err != nil {
		// 6h cadence — a single WARN is informative, not noisy. A firewalled box
		// simply never sees a new version here; that is an accepted posture.
		c.log.Warn("update check failed", "err", err)
		return
	}
	if notModified {
		return // 304: nothing changed since the last successful check
	}
	st := c.statusFor(rel)
	metrics.SetUpdateAvailable(st.Available, st.LatestVersion, st.Security)

	c.mu.Lock()
	c.status = st
	shouldLog := st.Available && st.LatestVersion != c.lastLogged
	if shouldLog {
		c.lastLogged = st.LatestVersion
	}
	c.mu.Unlock()

	if shouldLog {
		c.log.Warn("update available",
			"current", c.cfg.Current, "latest", st.LatestVersion,
			"security", st.Security, "url", st.URL)
	}
}

// CheckOnce performs a single check (no ETag state, ignores Enabled) for the
// `kapkan -check-update` CLI.
func (c *Checker) CheckOnce(ctx context.Context) (Status, error) {
	rel, _, err := c.fetch(ctx, false)
	if err != nil {
		return Status{}, err
	}
	return c.statusFor(rel), nil
}

// statusFor builds a Status from the chosen release, deciding availability only
// when BOTH the running version and the tag are comparable release versions — a
// dev/snapshot/between-tags build is never compared, so it never false-alarms.
func (c *Checker) statusFor(rel release) Status {
	st := Status{
		LatestVersion: rel.Tag,
		URL:           rel.HTMLURL,
		Security:      detectSecurity(rel.Body),
		CheckedAt:     c.now(),
	}
	if isComparable(c.cfg.Current) && isComparable(rel.Tag) && newer(c.cfg.Current, rel.Tag) {
		st.Available = true
	}
	return st
}

// release is the subset of a GitHub release we use.
type release struct {
	Tag        string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// fetch GETs the configured endpoint and returns the chosen release. With
// useETag it sends If-None-Match and reports notModified on a 304. The stable
// channel reads one release object; the prerelease channel reads the list and
// picks the newest comparable tag.
func (c *Checker) fetch(ctx context.Context, useETag bool) (rel release, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL, nil)
	if err != nil {
		return release{}, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if useETag {
		c.mu.Lock()
		etag := c.etag
		c.mu.Unlock()
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return release{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return release{}, true, nil
	case http.StatusOK:
		// ok
	default:
		// Surface rate-limit exhaustion specifically; it is the common 403.
		if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return release{}, false, fmt.Errorf("github rate limit exhausted (resets at %s)", resp.Header.Get("X-RateLimit-Reset"))
		}
		return release{}, false, fmt.Errorf("github returned %s", resp.Status)
	}

	body, err := readBody(resp.Body, maxBodyBytes)
	if err != nil {
		return release{}, false, err
	}
	rel, err = c.parse(body)
	if err != nil {
		return release{}, false, err
	}
	if useETag {
		if et := resp.Header.Get("ETag"); et != "" {
			c.mu.Lock()
			c.etag = et
			c.mu.Unlock()
		}
	}
	return rel, false, nil
}

// maxBodyBytes caps the response we read. Generous (8 MiB) because the
// prerelease channel reads a /releases LIST whose full notes/assets for active
// repos run a couple of MiB; readBody errors EXPLICITLY on overflow rather than
// silently truncating (which would masquerade as a recurring decode failure).
const maxBodyBytes = 8 << 20

// readBody reads up to limit bytes, returning a distinct error if the body would
// exceed it — so an oversized response fails loudly instead of being truncated
// mid-JSON and then failing to decode on every poll.
func readBody(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("release response exceeds %d bytes; refusing to parse a truncated body", limit)
	}
	return b, nil
}

// parse decodes the endpoint payload per channel: a single object for stable, a
// list (newest comparable tag wins) for prerelease.
func (c *Checker) parse(body []byte) (release, error) {
	if c.cfg.Channel == "prerelease" {
		var list []release
		if err := json.Unmarshal(body, &list); err != nil {
			return release{}, fmt.Errorf("decode releases list: %w", err)
		}
		var best release
		for _, r := range list {
			if r.Draft || !isComparable(r.Tag) {
				continue
			}
			if best.Tag == "" || newer(best.Tag, r.Tag) {
				best = r
			}
		}
		if best.Tag == "" {
			return release{}, fmt.Errorf("no comparable release in list")
		}
		return best, nil
	}
	var r release
	if err := json.Unmarshal(body, &r); err != nil {
		return release{}, fmt.Errorf("decode release: %w", err)
	}
	return r, nil
}

// detectSecurity reports whether the release notes carry a "Security" heading —
// the machine-readable marker documented in CHANGELOG.md.
var securityHeadingRe = regexp.MustCompile(`(?mi)^#{1,6}\s*security\b`)

func detectSecurity(body string) bool { return securityHeadingRe.MatchString(body) }

// devVersionRe matches a `git describe` "N commits past a tag" suffix
// (e.g. v1.2.0-3-g8fb4d6d) — an unreleased build we must not compare.
var devVersionRe = regexp.MustCompile(`-\d+-g[0-9a-f]{7,}`)

// isComparable reports whether v is a clean release tag we can order against
// another. Dev/snapshot/between-tags builds are excluded so a developer or
// source build never gets a spurious "update available".
func isComparable(v string) bool {
	switch {
	case v == "", v == "(devel)", v == "unknown":
		return false
	case strings.Contains(v, "SNAPSHOT"):
		return false
	case devVersionRe.MatchString(v):
		return false
	}
	_, ok := parseCore(v)
	return ok
}

// parseCore extracts the numeric MAJOR.MINOR.PATCH from vX.Y.Z[-pre][+build].
func parseCore(v string) ([3]int, bool) {
	s := strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func prereleaseOf(v string) string {
	s := strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// newer reports whether b is a strictly newer release than a (both comparable).
// Core fields compared numerically; on a tie, a final release outranks any
// prerelease, and two prereleases compare per SemVer identifier rules.
func newer(a, b string) bool {
	ca, _ := parseCore(a)
	cb, _ := parseCore(b)
	for i := 0; i < 3; i++ {
		if cb[i] != ca[i] {
			return cb[i] > ca[i]
		}
	}
	pa, pb := prereleaseOf(a), prereleaseOf(b)
	switch {
	case pa == pb:
		return false
	case pa == "": // a is final, b is a prerelease of the same core => b older
		return false
	case pb == "": // b is final, a is a prerelease => b newer
		return true
	default:
		return comparePre(pb, pa) > 0
	}
}

// comparePre compares two SemVer prerelease strings (dot-separated identifiers):
// numeric identifiers rank below non-numeric, numerics compare numerically, and
// a longer set outranks its prefix.
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if ai != bi {
				return sign(ai - bi)
			}
		case aerr == nil:
			return -1 // numeric < non-numeric
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(as) - len(bs))
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

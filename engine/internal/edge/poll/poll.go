// Package poll is the node's long-poll of a brain document — the scrub agent's
// loop (internal/scrub) generalised over the document (edge-spec §2.3): GET
// with the node's identity and the last ETag, a 200 hands the body to the
// caller, a 304 means "nothing new, ask again", anything else is a failure
// that backs off exponentially. The poll is the node's liveness signal, so it
// runs as fast as the brain lets it and never busy-loops: a 200 without an
// ETag (a proxy stripping headers) backs off instead of hammering.
package poll

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	// DefaultPollTimeout must exceed the brain's hold (25 s) with room for a
	// slow network; the brain answers 304 on its own deadline.
	DefaultPollTimeout = 40 * time.Second
	DefaultBackoffMin  = time.Second
	DefaultBackoffMax  = 30 * time.Second
	// maxBody bounds a document.
	maxBody = 8 << 20
)

// Options configures a Poller.
type Options struct {
	// BaseURL is the brain's API base (no trailing slash needed).
	BaseURL string
	// Path is the document's route, e.g. "/api/v1/edge/zones".
	Path string
	// Token is the agent bearer; Node the identity sent as ?node=.
	Token string
	Node  string
	// OnDocument receives every new document (a 200) with its ETag. An error
	// means the caller refused it; the poll still advances to that ETag — the
	// brain has nothing newer, re-fetching the same bytes every backoff would
	// only make the node look dead — and records the refusal (LastRefusal).
	// Retrying what was refused is the caller's job; it holds the bytes.
	OnDocument func(body []byte, etag string) error
	// ETag seeds the first poll (a document restored from disk), so a brain
	// with nothing new answers 304 at once.
	ETag        string
	PollTimeout time.Duration
	BackoffMin  time.Duration
	BackoffMax  time.Duration
	Logger      *slog.Logger
	// Client may be nil; redirects are never followed either way (a redirect
	// would re-send the bearer wherever Location points).
	Client *http.Client
}

// Poller long-polls one document.
type Poller struct {
	opt    Options
	client *http.Client
	log    *slog.Logger

	mu   sync.Mutex
	etag string
	// lastOK is when a poll last reached the brain (200 or 304, whatever the
	// caller made of the document): the node's own view of whether the brain
	// is reachable.
	lastOK time.Time
	// lastRefusal is the last document the caller refused, "" when the last
	// delivered document was accepted.
	lastRefusal string
}

// New validates the options and returns a Poller.
func New(opt Options) (*Poller, error) {
	if opt.BaseURL == "" || opt.Path == "" {
		return nil, errors.New("poll: base URL and path are required")
	}
	if opt.OnDocument == nil {
		return nil, errors.New("poll: OnDocument is required")
	}
	if opt.PollTimeout <= 0 {
		opt.PollTimeout = DefaultPollTimeout
	}
	if opt.BackoffMin <= 0 {
		opt.BackoffMin = DefaultBackoffMin
	}
	if opt.BackoffMax < opt.BackoffMin {
		opt.BackoffMax = DefaultBackoffMax
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{Timeout: opt.PollTimeout}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Poller{opt: opt, client: client, log: opt.Logger.With("component", "edge-poll"), etag: opt.ETag}, nil
}

// ETag is the ETag of the last document accepted.
func (p *Poller) ETag() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.etag
}

// LastOK is when a poll last reached the brain; zero when never.
func (p *Poller) LastOK() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastOK
}

// LastRefusal is the refusal message for the last delivered document, "" when
// it was accepted.
func (p *Poller) LastRefusal() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastRefusal
}

// Run polls until ctx is done. A healthy poll (200 or 304) is followed at
// once by the next; a failure backs off, doubling to BackoffMax.
func (p *Poller) Run(ctx context.Context) {
	backoff := p.opt.BackoffMin
	for ctx.Err() == nil {
		if p.Once(ctx) {
			backoff = p.opt.BackoffMin
			continue
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if backoff *= 2; backoff > p.opt.BackoffMax {
			backoff = p.opt.BackoffMax
		}
	}
}

// Once performs one poll; true means healthy (200 accepted, or 304).
func (p *Poller) Once(ctx context.Context) bool {
	target := p.opt.BaseURL + p.opt.Path
	if p.opt.Node != "" {
		target += "?node=" + url.QueryEscape(p.opt.Node)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		p.log.Error("building the poll request failed", "err", err)
		return false
	}
	if p.opt.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.opt.Token)
	}
	if et := p.ETag(); et != "" {
		req.Header.Set("If-None-Match", et)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return true // shutdown, not a brain failure
		}
		p.log.Warn("document poll failed; the node keeps serving the last document", "err", err)
		return false
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			p.log.Error("reading the document failed", "err", err)
			return false
		}
		et := resp.Header.Get("ETag")
		if et == "" {
			p.log.Warn("document response carried no ETag (a proxy stripping it?); backing off instead of busy-polling")
			return false
		}
		// The brain answered: it is reachable whatever the document's fate.
		p.mu.Lock()
		p.lastOK = time.Now()
		p.mu.Unlock()
		refusal := ""
		if err := p.opt.OnDocument(body, et); err != nil {
			refusal = err.Error()
			p.log.Error("document refused; the terminator keeps serving the previous one", "etag", et, "err", err)
		}
		p.mu.Lock()
		p.etag = et
		p.lastRefusal = refusal
		p.mu.Unlock()
		return true
	case http.StatusNotModified:
		p.mu.Lock()
		p.lastOK = time.Now()
		p.mu.Unlock()
		return true
	case http.StatusUnauthorized, http.StatusForbidden:
		p.log.Error("the brain refused this node's credentials; check the agent token and its role", "status", resp.StatusCode)
		return false
	case http.StatusNotFound:
		p.log.Error("the brain does not know this node — controller.name must equal an edge.nodes[] entry", "node", p.opt.Node)
		return false
	default:
		p.log.Warn("unexpected poll status", "status", resp.StatusCode)
		return false
	}
}

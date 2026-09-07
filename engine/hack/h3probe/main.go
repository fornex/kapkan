// Command h3probe makes one HTTP/3 request over QUIC v1 and reports what the
// handshake did, as a single JSON object on stdout.
//
// It exists for the edge track's acceptance rigs (edge-spec §8, milestone E5):
// curl proves that a stock client speaks h3 to a rendered terminator, but it
// cannot say whether the server sent a Retry, and it cannot be made to resume a
// session issued by a different node. Those two facts are what E5's Retry and
// shared-ticket-key arms have to assert, so they get their own client.
//
// This is a TEST tool and lives in its own Go module on purpose: decision D10
// of the E5 plan keeps QUIC out of the product's dependency graph, so nothing
// under engine/ may import quic-go. The engine module does not see this
// directory (`go build ./...` skips nested modules) and
// internal/edge/render/deps_guard_test.go fails if a quic-go requirement ever
// appears in engine/go.mod.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const usage = `h3probe - an HTTP/3 (QUIC v1) test client for the Kapkan edge.

usage:
  h3probe get -url https://host:port/path [flags]

flags:
  -url string         request URL, https only (required)
  -sni name           server name to send and to verify the certificate against
                      (default: the URL's host)
  -ca file            PEM file of root certificates to trust
  -insecure           accept any server certificate
  -timeout duration   budget for the whole run, both connections (default 5s)
  -resume             make a second connection in the same process, sharing a
                      TLS session cache, and report whether it resumed
  -resume-url string  send the second connection to this URL instead of -url,
                      keeping the same SNI and session cache (implies -resume)

h3probe prints one JSON object on stdout and exits 0 even when the request
fails; only a usage error exits non-zero (2). Fields:

  status         HTTP status of the first response, 0 when the request failed
  alpn           ALPN negotiated on the first connection ("h3" when h3 is served)
  proto          response protocol ("HTTP/3.0" on a served h3 request)
  alt_svc        the response's Alt-Svc header, omitted when the header is absent
  retry_seen     true when the FIRST connection received a QUIC Retry packet
  resumed        TLS session resumption on the SECOND connection (-resume only)
  resume_status  HTTP status of the second response (present only with -resume)
  error          why the run failed, empty on success
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// options is the parsed command line of the one subcommand, `get`.
type options struct {
	url       string
	sni       string
	ca        string
	insecure  bool
	timeout   time.Duration
	resume    bool
	resumeURL string
}

// result is the JSON object h3probe prints. Field order here is the order on
// the wire; shell arms parse it with jq, so names are part of the contract.
type result struct {
	Status       int    `json:"status"`
	ALPN         string `json:"alpn"`
	Proto        string `json:"proto"`
	AltSvc       string `json:"alt_svc,omitempty"`
	RetrySeen    bool   `json:"retry_seen"`
	Resumed      bool   `json:"resumed"`
	ResumeStatus *int   `json:"resume_status,omitempty"`
	Error        string `json:"error"`
}

// run is main without the exit: 2 on a usage error (nothing on stdout), 0
// otherwise, with the result object on stdout even when the request failed.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "get" {
		printUsage(stderr)
		return 2
	}

	fs := flag.NewFlagSet("h3probe get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUsage(stderr) }
	var o options
	fs.StringVar(&o.url, "url", "", "request URL (https)")
	fs.StringVar(&o.sni, "sni", "", "server name to send and verify against")
	fs.StringVar(&o.ca, "ca", "", "PEM file of root certificates to trust")
	fs.BoolVar(&o.insecure, "insecure", false, "accept any server certificate")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second, "budget for the whole run")
	fs.BoolVar(&o.resume, "resume", false, "make a second, resuming connection")
	fs.StringVar(&o.resumeURL, "resume-url", "", "URL for the second connection")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		warnf(stderr, "h3probe: unexpected argument %q\n\n", fs.Arg(0))
		printUsage(stderr)
		return 2
	}
	if err := o.normalize(); err != nil {
		warnf(stderr, "h3probe: %v\n\n", err)
		printUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	res := probe(ctx, o)
	if err := json.NewEncoder(stdout).Encode(res); err != nil {
		warnf(stderr, "h3probe: encoding the result: %v\n", err)
		return 2
	}
	return 0
}

func printUsage(w io.Writer) { _, _ = io.WriteString(w, usage) }

// warnf writes a diagnostic. Its own error is dropped: a probe that cannot
// write to stderr has nowhere left to report that.
func warnf(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

// normalize validates the flags and settles the defaults that depend on other
// flags. A URL h3probe cannot even dial is a usage error, not a result object:
// an arm that mistyped its URL should fail loudly rather than read a JSON
// "error" it would have accepted as a legitimate refusal.
func (o *options) normalize() error {
	if o.url == "" {
		return errors.New("-url is required")
	}
	if _, err := parseTarget(o.url, "-url"); err != nil {
		return err
	}
	if o.resumeURL != "" {
		if _, err := parseTarget(o.resumeURL, "-resume-url"); err != nil {
			return err
		}
		o.resume = true
	}
	if o.timeout <= 0 {
		return fmt.Errorf("-timeout must be positive, got %s", o.timeout)
	}
	return nil
}

// parseTarget accepts only what an HTTP/3 request can be made to: an https URL
// with a host.
func parseTarget(raw, flagName string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flagName, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s: scheme must be https, got %q", flagName, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%s: no host in %q", flagName, raw)
	}
	return u, nil
}

// probe runs the request (and, under -resume, the second one) and fills in the
// result. Every failure lands in result.Error rather than in an exit code.
func probe(ctx context.Context, o options) result {
	var res result

	tlsConf, err := clientTLS(o)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	var cache *ticketCache
	if o.resume {
		cache = newTicketCache()
		tlsConf.ClientSessionCache = cache
	}

	first := newLeg(tlsConf)
	defer first.close()

	resp, err := first.do(ctx, o.url)
	if err != nil {
		// The Retry is worth reporting even when the request then failed: a
		// handshake that got as far as a Retry says something different from
		// one that never reached the server.
		res.RetrySeen = first.retry.seen()
		res.Error = err.Error()
		return res
	}
	res.Status = resp.StatusCode
	res.Proto = resp.Proto
	res.AltSvc = resp.Header.Get("Alt-Svc")
	res.RetrySeen = first.retry.seen()
	if state, ok := first.connState(); ok {
		res.ALPN = state.TLS.NegotiatedProtocol
	}
	if !o.resume {
		return res
	}

	// The server sends its session ticket after the handshake, which can land
	// after the response body does. Dialing the second connection before it
	// arrives would report resumed=false for a server that resumes perfectly
	// well, so wait for the cache to be filled. The first connection stays open
	// meanwhile (deferred close), which is what keeps the ticket arriving.
	if err := cache.wait(ctx); err != nil {
		res.Error = fmt.Sprintf("resume: %v", err)
		return res
	}

	target := o.url
	if o.resumeURL != "" {
		target = o.resumeURL
	}
	second := newLeg(tlsConf)
	defer second.close()

	resp2, err := second.do(ctx, target)
	if err != nil {
		res.Error = fmt.Sprintf("resume: %v", err)
		return res
	}
	status := resp2.StatusCode
	res.ResumeStatus = &status
	if state, ok := second.connState(); ok {
		res.Resumed = state.TLS.DidResume
	}
	return res
}

// clientTLS builds the TLS configuration both connections share. ServerName is
// always set explicitly, never left to the transport: Go keys the session cache
// by it, so it is what lets a ticket issued by one node be offered to another
// under -resume-url.
func clientTLS(o options) (*tls.Config, error) {
	u, err := parseTarget(o.url, "-url")
	if err != nil {
		return nil, err
	}
	name := o.sni
	if name == "" {
		name = u.Hostname()
	}
	conf := &tls.Config{
		ServerName: name,
		MinVersion: tls.VersionTLS13, // QUIC never negotiates below 1.3
		NextProtos: []string{http3.NextProtoH3},
		// A test client talking to lab terminators with throwaway certificates
		// needs this; the product has no such flag.
		InsecureSkipVerify: o.insecure, //nolint:gosec // -insecure is the point
	}
	if o.ca != "" {
		pem, err := os.ReadFile(o.ca)
		if err != nil {
			return nil, fmt.Errorf("-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-ca: no certificate found in %s", o.ca)
		}
		conf.RootCAs = pool
	}
	return conf, nil
}

// leg is one QUIC connection and the request made over it.
type leg struct {
	tr    *http3.Transport
	retry *retryWatcher

	mu   sync.Mutex
	conn *quic.Conn
}

func newLeg(tlsConf *tls.Config) *leg {
	l := &leg{retry: &retryWatcher{}}
	l.tr = &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{
			Versions: []quic.Version{quic.Version1},
			Tracer:   l.retry.trace,
		},
		// Dialing by hand is how the connection is kept: the transport only
		// hands back an http.Response, and the ALPN, the resumption bit and the
		// Retry all live on the QUIC connection underneath it.
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			conn, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			l.mu.Lock()
			l.conn = conn
			l.mu.Unlock()
			return conn, nil
		},
	}
	return l
}

// do makes the GET and drains the body, so the request is complete before the
// connection state is read.
func (l *leg) do(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := l.tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Bounded: a probe reads the body to finish the exchange, not to keep it.
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil {
		return nil, fmt.Errorf("reading the response body: %w", err)
	}
	return resp, nil
}

func (l *leg) connState() (quic.ConnectionState, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return quic.ConnectionState{}, false
	}
	return l.conn.ConnectionState(), true
}

func (l *leg) close() { _ = l.tr.Close() }

// retryWatcher answers one question about a connection: did the server send a
// Retry packet?
//
// quic-go v0.62 has no logging.ConnectionTracer any more - a connection's
// tracer is a qlog trace, and an accepted Retry is recorded as a
// qlog.PacketReceived carrying qlog.PacketTypeRetry (see the client's
// handleRetryPacket). Everything else recorded on the trace is dropped here.
type retryWatcher struct{ retry atomic.Bool }

func (w *retryWatcher) seen() bool { return w.retry.Load() }

func (w *retryWatcher) trace(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	return retryTrace{w}
}

type retryTrace struct{ w *retryWatcher }

func (t retryTrace) AddProducer() qlogwriter.Recorder { return retryRecorder(t) }

func (t retryTrace) SupportsSchemas(string) bool { return true }

type retryRecorder struct{ w *retryWatcher }

func (r retryRecorder) RecordEvent(ev qlogwriter.Event) {
	if pr, ok := ev.(qlog.PacketReceived); ok && pr.Header.PacketType == qlog.PacketTypeRetry {
		r.w.retry.Store(true)
	}
}

func (r retryRecorder) Close() error { return nil }

// ticketCache is an LRU session cache that also says when it first held a
// ticket, so -resume can wait for one instead of racing it.
type ticketCache struct {
	inner tls.ClientSessionCache

	once  sync.Once
	ready chan struct{}
}

func newTicketCache() *ticketCache {
	return &ticketCache{inner: tls.NewLRUClientSessionCache(4), ready: make(chan struct{})}
}

func (c *ticketCache) Put(key string, cs *tls.ClientSessionState) {
	c.inner.Put(key, cs)
	if cs != nil { // a nil session is a removal, not a ticket
		c.once.Do(func() { close(c.ready) })
	}
}

func (c *ticketCache) Get(key string) (*tls.ClientSessionState, bool) { return c.inner.Get(key) }

func (c *ticketCache) wait(ctx context.Context) error {
	select {
	case <-c.ready:
		return nil
	case <-ctx.Done():
		return errors.New("no session ticket arrived on the first connection")
	}
}

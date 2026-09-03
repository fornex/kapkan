// Package node is the `kapkan edge` role: the process on an edge box that
// wires together what E3.1–E3.4 built (edge-spec §2.1). It long-polls the
// brain's zone document, renders and installs the terminator's configuration
// behind `nginx -t`, runs the decision service, the access-log rollups and
// the ACME answerer on their unix sockets, issues and renews certificates,
// and reports itself. Nothing here decides anything about a request or
// forwards a byte: nginx does the first through the decision socket and the
// second by itself (the edge charter, §0.1).
//
// STARTUP ORDER. Sockets first — nginx may already be running and probing
// them; then the terminator is probed (kind, version) and any generation a
// crashed predecessor left untested is recovered; then the node starts FROM
// DISK: the last document it accepted is persisted with its ETag, so a box
// that reboots with the brain gone renders and serves exactly what it served
// before (§2.4, fail-static), and its first poll can answer 304. Only then
// does it poll. A component that fails at any point ends Run with its error:
// the process exits non-zero and systemd restarts it.
//
// TWO PATHS ON A NEW DOCUMENT. The fast path — the decision service's zone
// policies, the aggregator's zone set, the fanned-out challenges — is applied
// first and touches no file. Then the document is persisted, rendered and
// applied; since the render does not depend on policy.rate or on any verdict,
// a rate change never reloads the terminator (§2.2). A certificate issued or
// renewed re-renders and applies too — that is what reloads are for. The
// whole slow path is serialised and reads its inputs (document, certificates)
// inside that serialisation, so the newest state always renders last.
//
// TWO ETAGS. The ACCEPTED ETag names the document the fast path holds; the
// RENDERED ETag names the one the terminator serves (the last render that
// passed `nginx -t` and was installed). They differ while a document is
// refused — by the renderer, or by the terminator's test — and only the
// rendered one is reported to the brain and used to seed the first poll, so
// a refused document is offered again and retried here on a backoff until
// it applies or a newer one arrives.
//
// HEALTH. /healthz answers 200 while a tested generation of ours is live
// (and the terminator, when a pid file is configured, is alive), 503
// otherwise; a refused document does not flip it — the previous generation
// keeps serving (§2.4) — but shows as converged=false with the error.
//
// DRY-RUN is the node's default, as for every remote role: decisions are
// counted and marked, none enforced, until edge.yaml says otherwise.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/buildinfo"
	"github.com/kapkan-io/kapkan/internal/edge/acme"
	"github.com/kapkan-io/kapkan/internal/edge/apply"
	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/poll"
	"github.com/kapkan-io/kapkan/internal/edge/render"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
)

// Reload methods for the terminator.
const (
	ReloadExec    = "exec"    // <binary> -s reload [-c main_conf]
	ReloadSignal  = "signal"  // SIGHUP to the pid in pid_file
	ReloadCommand = "command" // an arbitrary argv, e.g. systemctl reload nginx
)

const (
	// DefaultRetryMin and DefaultRetryMax bound the local retry of a document
	// that was accepted but could not be rendered or applied: the first retry
	// after RetryMin, doubling to RetryMax, until it applies or a newer
	// document arrives. Each retry is a real `nginx -t`, so it is paced.
	DefaultRetryMin = time.Minute
	DefaultRetryMax = 10 * time.Minute
	// maxReportBytes keeps a self-report under the brain's 64 KiB body limit
	// with room for the fixed fields; the certificate list is what grows.
	maxReportBytes = 60 << 10
)

// Options is the node's resolved configuration (config.EdgeNodeConfig,
// validated and with the token read from its environment variable).
type Options struct {
	// Brain is the API base; Token the agent bearer; Name this node's name
	// as edge.nodes[] on the brain has it.
	Brain string
	Token string
	Name  string
	// DryRun is watch-only: decisions counted and marked, none enforced.
	DryRun bool
	// StateDir holds the document cache, the rendered generations, the ACME
	// account keys and certificates, and the empty root.
	StateDir string
	// SocketsDir holds the three unix sockets.
	SocketsDir string
	// SocketGroup is the terminator's worker group, chowned onto the decide
	// and log sockets ("" leaves them as created). The challenge socket is
	// world-connectable: it answers public tokens.
	SocketGroup string
	// Terminator names the binary ("" = nginx), its main configuration ("" =
	// the binary's default), the reload method and its parameters.
	Terminator Terminator
	// ACME is the node's default CA, fallback, contact and bindings.
	ACME ACME
	// ReportInterval is the self-report cadence; 0 = 10 s.
	ReportInterval time.Duration
	// RetryMin and RetryMax bound the local retry of a refused document; 0
	// means the defaults.
	RetryMin, RetryMax time.Duration
	// StatusListen, when set, serves /healthz and /metrics on this address
	// (loopback by default in the config).
	StatusListen string
	// OmitCatchAll and DisableIPv6 pass through to the renderer.
	OmitCatchAll bool
	DisableIPv6  bool
	Logger       *slog.Logger
	// HTTPClient talks to the brain (polls, reports, ACME coordination); nil
	// means a default client. Redirects are never followed on any of them —
	// a redirect would re-send the bearer wherever Location points. Tests
	// inject one.
	HTTPClient *http.Client
	// Tester and Reloader override the terminator adapters; Prober the
	// kind/version probe (tests).
	Tester   apply.Tester
	Reloader apply.Reloader
	Prober   func(ctx context.Context, binary string) (kind, version string, err error)
}

// Terminator is how the node drives nginx or Angie.
type Terminator struct {
	Binary   string
	MainConf string
	Reload   string
	// PIDFile is read for the signal reload method and, whenever set, for
	// the terminator-liveness check behind /healthz and the report.
	PIDFile string
	Command []string
}

// ACME is the node-level issuance configuration.
type ACME struct {
	Directory string
	Fallback  string
	Contact   []string
	// EAB holds External Account Binding credentials per directory URL, for
	// CAs that require one (ZeroSSL, Google Trust Services); resolved from
	// edge.yaml's acme.eab[] with the HMAC key read from its environment
	// variable.
	EAB map[string]acme.EAB
	// Disabled issues nothing: zones stay on :80 answering 503 (a lab that
	// exercises everything but issuance). Operator-supplied certificates are
	// not a feature yet.
	Disabled bool
}

// Node is a running edge role.
type Node struct {
	opt   Options
	log   *slog.Logger
	http  *http.Client
	files nodeFiles

	svc        *decide.Service
	agg        *rollup.Aggregator
	rules      *rollup.Rules
	challenges *acme.ChallengeTable
	certs      *acme.Manager
	applier    *apply.Applier
	prober     func(ctx context.Context, binary string) (string, string, error)

	// renderMu serialises the whole slow path (read inputs, render, apply).
	renderMu sync.Mutex

	mu           sync.Mutex
	poller       *poll.Poller
	doc          *edgedoc.Doc
	acceptedETag string
	renderedETag string
	last         apply.Result
	lastErr      string
	retryAt      time.Time
	retryBackoff time.Duration
	termKind     string
	termVer      string
	termAlive    *bool
	statusAddr   string
}

type nodeFiles struct {
	docPath, etagPath, confRoot, emptyRoot string
	decideSock, challengeSock, logSock     string
}

// New prepares a Node; nothing runs until Run.
func New(opt Options) (*Node, error) {
	if opt.Brain == "" || opt.Name == "" {
		return nil, errors.New("edge: brain URL and node name are required")
	}
	if !filepath.IsAbs(opt.StateDir) || !filepath.IsAbs(opt.SocketsDir) {
		return nil, errors.New("edge: state_dir and sockets_dir must be absolute")
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.HTTPClient == nil {
		opt.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opt.ReportInterval <= 0 {
		opt.ReportInterval = 10 * time.Second
	}
	if opt.RetryMin <= 0 {
		opt.RetryMin = DefaultRetryMin
	}
	if opt.RetryMax < opt.RetryMin {
		opt.RetryMax = DefaultRetryMax
		if opt.RetryMax < opt.RetryMin {
			opt.RetryMax = opt.RetryMin
		}
	}
	if opt.Terminator.Binary == "" {
		opt.Terminator.Binary = "nginx"
	}
	if opt.Terminator.Reload == "" {
		opt.Terminator.Reload = ReloadExec
	}
	if opt.Prober == nil {
		opt.Prober = apply.Probe
	}
	// One client for every brain call, and it never follows a redirect.
	hc := *opt.HTTPClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	n := &Node{opt: opt, log: opt.Logger.With("component", "edge"), http: &hc, prober: opt.Prober}
	n.files = nodeFiles{
		docPath:       filepath.Join(opt.StateDir, "zones.json"),
		etagPath:      filepath.Join(opt.StateDir, "zones.etag"),
		confRoot:      filepath.Join(opt.StateDir, "conf"),
		emptyRoot:     filepath.Join(opt.StateDir, "empty"),
		decideSock:    filepath.Join(opt.SocketsDir, "edge-decide.sock"),
		challengeSock: filepath.Join(opt.SocketsDir, "edge-challenge.sock"),
		logSock:       filepath.Join(opt.SocketsDir, "edge-log.sock"),
	}
	for _, d := range []string{opt.StateDir, opt.SocketsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(n.files.emptyRoot, 0o755); err != nil {
		return nil, err
	}

	n.svc = decide.New(decide.Options{DryRun: opt.DryRun, Logger: opt.Logger})
	n.rules = &rollup.Rules{}
	n.agg = &rollup.Aggregator{
		OnRecord: func(r rollup.Record) {
			if r.Decided() {
				n.svc.Complete(r.Zone, r.Src)
			}
		},
		OnWindowFull: func(w rollup.WindowStats) { n.rules.Apply(w, n.svc) },
	}
	n.challenges = acme.NewChallengeTable(nil)
	if !opt.ACME.Disabled {
		brain := &acme.BrainClient{BaseURL: strings.TrimRight(opt.Brain, "/"), Token: opt.Token, Node: opt.Name, HTTPClient: n.http}
		mgr, err := acme.New(acme.Options{
			StateDir:      opt.StateDir,
			NodeName:      opt.Name,
			Directory:     opt.ACME.Directory,
			Fallback:      opt.ACME.Fallback,
			Contact:       opt.ACME.Contact,
			EAB:           opt.ACME.EAB,
			Slots:         brain,
			Publish:       brain,
			Challenges:    n.challenges,
			OnCertificate: func(zone string) { n.onCertificate(zone) },
			Logger:        opt.Logger,
		})
		if err != nil {
			return nil, err
		}
		n.certs = mgr
	}
	tester, reloader := opt.Tester, opt.Reloader
	if tester == nil {
		tester = apply.ExecTester{Binary: opt.Terminator.Binary, MainConf: opt.Terminator.MainConf}
	}
	if reloader == nil {
		switch opt.Terminator.Reload {
		case ReloadSignal:
			if opt.Terminator.PIDFile == "" {
				return nil, errors.New("edge: terminator.reload signal needs terminator.pid_file")
			}
			reloader = apply.SignalReloader{PIDFile: opt.Terminator.PIDFile}
		case ReloadCommand:
			if len(opt.Terminator.Command) == 0 {
				return nil, errors.New("edge: terminator.reload command needs terminator.command")
			}
			reloader = commandReloader(opt.Terminator.Command)
		case ReloadExec:
			reloader = apply.ExecReloader{Binary: opt.Terminator.Binary, MainConf: opt.Terminator.MainConf}
		default:
			return nil, fmt.Errorf("edge: unknown terminator.reload %q", opt.Terminator.Reload)
		}
	}
	n.applier = &apply.Applier{Root: n.files.confRoot, Tester: tester, Reloader: reloader}
	return n, nil
}

// Run brings the node up and serves until ctx is done or a component fails;
// a component's failure is returned (and logged where it happened), never
// lost to shutdown ordering.
func (n *Node) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	spawn := func(name string, f func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(ctx); err != nil && ctx.Err() == nil {
				n.log.Error("component failed; shutting down", "component", name, "err", err)
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}
	// firstErr is the component failure that ends Run, if any: checked after
	// every startup step so a node whose sockets failed does not go on to run
	// nginx -t, install anything or poll with a cancelled context, and drained
	// after shutdown so it wins over ctx.Done() whatever the scheduling.
	finish := func() error {
		cancel()
		wg.Wait()
		select {
		case err := <-errs:
			return err
		default:
			return nil
		}
	}

	// 1. Sockets first: nginx may already be running and probing them.
	spawn("decision service", (&decide.Server{Service: n.svc, Path: n.files.decideSock, SocketGroup: n.opt.SocketGroup, Logger: n.opt.Logger}).ListenAndServe)
	spawn("challenge answerer", (&acme.ChallengeServer{Table: n.challenges, Path: n.files.challengeSock, SocketGroup: n.opt.SocketGroup, Logger: n.opt.Logger}).ListenAndServe)
	spawn("access-log listener", (&rollup.Listener{Path: n.files.logSock, SocketGroup: n.opt.SocketGroup, Handle: n.agg.Observe, Logger: n.opt.Logger}).Run)
	spawn("window ticker", func(ctx context.Context) error {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				n.agg.Tick()
			}
		}
	})
	if ctx.Err() != nil {
		return finish()
	}

	// 2. The terminator: what it is, and whether a predecessor left an
	// untested generation live.
	if kind, ver, err := n.prober(ctx, n.opt.Terminator.Binary); err == nil {
		n.mu.Lock()
		n.termKind, n.termVer = kind, ver
		n.mu.Unlock()
	} else if ctx.Err() == nil {
		n.log.Warn("terminator probe failed; kind and version will be missing from reports", "err", err)
	}
	if res, err := n.applier.Recover(ctx); err != nil {
		n.log.Error("recovering the live generation failed", "err", err)
		n.record(res, err)
	} else if res.Changed {
		n.log.Warn("recovered an untested generation left by a previous process", "generation", res.Generation, "test_ok", res.TestOK)
		n.record(res, nil)
	}
	if ctx.Err() != nil {
		return finish()
	}

	// 3. Start from disk. The poll is seeded with the cached ETag only when
	// the cached document actually applied; otherwise the first poll fetches
	// it again and the refusal/retry path takes over.
	seed := ""
	if body, etag, ok := n.loadCached(); ok {
		if err := n.acceptDocument(ctx, body, etag, false); err != nil {
			n.log.Error("the cached document did not apply; it will be retried and re-fetched", "etag", etag, "err", err)
		} else {
			seed = etag
			n.log.Info("serving the last accepted document from disk", "etag", etag)
		}
	}
	if ctx.Err() != nil {
		return finish()
	}

	// 4. Poll, report, renew.
	p, err := poll.New(poll.Options{
		BaseURL: strings.TrimRight(n.opt.Brain, "/"), Path: "/api/v1/edge/zones", Token: n.opt.Token, Node: n.opt.Name,
		ETag:   seed,
		Logger: n.opt.Logger, Client: n.pollClient(),
		OnDocument: func(body []byte, etag string) error { return n.acceptDocument(ctx, body, etag, true) },
	})
	if err != nil {
		_ = finish()
		return err
	}
	// Status() reads the poller from other goroutines.
	n.mu.Lock()
	n.poller = p
	n.mu.Unlock()
	spawn("poller", func(ctx context.Context) error { p.Run(ctx); return nil })
	spawn("reporter", n.reportLoop)
	if n.certs != nil {
		spawn("acme", func(ctx context.Context) error {
			err := n.certs.Run(ctx, n.zones)
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		})
	}
	if n.opt.StatusListen != "" {
		spawn("status listener", n.serveStatus)
	}
	n.log.Info("kapkan edge running", "brain", n.opt.Brain, "node", n.opt.Name, "dry_run", n.opt.DryRun,
		"state_dir", n.opt.StateDir, "sockets_dir", n.opt.SocketsDir, "terminator", n.opt.Terminator.Binary)

	<-ctx.Done()
	return finish()
}

func (n *Node) pollClient() *http.Client {
	// The poll client needs a timeout above the brain's hold; the shared
	// client's 30 s would cut a 25 s hold plus network too close.
	c := *n.http
	c.Timeout = poll.DefaultPollTimeout
	return &c
}

// acceptDocument applies a new document: fast path, persist, render, apply.
func (n *Node) acceptDocument(ctx context.Context, body []byte, etag string, persist bool) error {
	doc, err := edgedoc.Decode(body)
	if err != nil {
		return err
	}
	// Fast path: no file is touched.
	n.svc.SetZones(doc)
	names := make([]string, 0, len(doc.Zones))
	for _, z := range doc.Zones {
		names = append(names, z.Name)
	}
	n.agg.SetZones(names)
	n.challenges.SetFanned(doc.ACMEChallenges)
	n.mu.Lock()
	n.doc, n.acceptedETag = doc, etag
	n.mu.Unlock()
	if persist {
		if err := n.saveCached(body, etag); err != nil {
			n.log.Error("persisting the document failed; a restart with the brain gone would serve the previous one", "err", err)
		}
	}
	reloaded, err := n.renderAndApply(ctx)
	if err == nil && n.certs != nil {
		// A fresh node's first document, or a zone added later, is issued now
		// rather than at the manager's next hourly pass — but only once the
		// document is RENDERED and live: the :80 listener that answers the
		// CA's HTTP-01 fetch is part of it, and an order placed before the
		// first reload would fail its validation and back off for an hour.
		// A reload is asynchronous — the old workers keep answering for a
		// moment, and they know nothing of a new zone — so give the
		// terminator that moment before a CA is asked to fetch from it.
		if reloaded {
			time.AfterFunc(reloadSettle, n.certs.Wake)
		} else {
			n.certs.Wake()
		}
	}
	return err
}

// reloadSettle is how long a reloaded terminator gets to bring its new
// workers up before the ACME manager is woken to order for a new zone.
const reloadSettle = 2 * time.Second

// renderAndApply is the slow path: the terminator's configuration from the
// document and the certificates this node holds, read INSIDE the
// serialisation so two callers (the poller, the certificate hook) converge
// on the newest state whatever their order. A failure schedules a local
// retry. It reports whether the terminator was reloaded.
func (n *Node) renderAndApply(ctx context.Context) (reloaded bool, err error) {
	n.renderMu.Lock()
	defer n.renderMu.Unlock()
	n.mu.Lock()
	doc, etag := n.doc, n.acceptedETag
	n.mu.Unlock()
	if doc == nil {
		return false, nil
	}
	certs := map[string]render.Cert{}
	if n.certs != nil {
		for _, c := range n.certs.Inventory() {
			// The serial is what makes a renewal a new generation: the paths
			// go through the store's `current` link and never change.
			certs[c.Zone] = render.Cert{Fullchain: c.Fullchain, Key: c.Key, Serial: c.Serial}
		}
	}
	files, err := render.Render(render.Inputs{Doc: doc, Certs: certs, Node: render.Node{
		DecideSocket: n.files.decideSock, ChallengeSocket: n.files.challengeSock, LogSocket: n.files.logSock,
		EmptyRoot: n.files.emptyRoot, DisableIPv6: n.opt.DisableIPv6, OmitCatchAll: n.opt.OmitCatchAll,
	}})
	if err != nil {
		err = fmt.Errorf("render: %w", err)
		n.record(apply.Result{}, err)
		n.scheduleRetry()
		return false, err
	}
	res, err := n.applier.Apply(ctx, files)
	n.record(res, err)
	if err != nil {
		if ctx.Err() == nil {
			n.scheduleRetry()
		}
		return false, err
	}
	n.mu.Lock()
	n.renderedETag = etag
	n.retryAt, n.retryBackoff = time.Time{}, 0
	n.mu.Unlock()
	if res.Changed {
		n.log.Info("configuration installed", "generation", res.Generation, "reloaded", res.Reloaded, "zones", len(doc.Zones), "etag", etag)
	}
	return res.Reloaded, nil
}

// scheduleRetry arms the local retry of a document that did not apply,
// doubling the interval up to RetryMax.
func (n *Node) scheduleRetry() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.retryBackoff == 0 {
		n.retryBackoff = n.opt.RetryMin
	} else if n.retryBackoff *= 2; n.retryBackoff > n.opt.RetryMax {
		n.retryBackoff = n.opt.RetryMax
	}
	n.retryAt = time.Now().Add(n.retryBackoff)
}

// retryIfDue re-runs the slow path when a refused document's retry is due.
func (n *Node) retryIfDue(ctx context.Context) {
	n.mu.Lock()
	due := !n.retryAt.IsZero() && !time.Now().Before(n.retryAt)
	n.mu.Unlock()
	if !due {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	reloaded, err := n.renderAndApply(rctx)
	if err != nil && ctx.Err() == nil {
		n.log.Warn("retrying the refused document failed; will retry again", "err", err)
	}
	if err == nil && n.certs != nil {
		// The retried document may carry a new zone too.
		if reloaded {
			time.AfterFunc(reloadSettle, n.certs.Wake)
		} else {
			n.certs.Wake()
		}
	}
}

// onCertificate is the ACME manager's hook: a new certificate re-renders.
func (n *Node) onCertificate(zone string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := n.renderAndApply(ctx); err != nil {
		n.log.Error("re-rendering after a certificate change failed", "zone", zone, "err", err)
	}
}

// zones is what the ACME manager renews: the current document's zones.
func (n *Node) zones() []edgedoc.Zone {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.doc == nil {
		return nil
	}
	out := make([]edgedoc.Zone, len(n.doc.Zones))
	copy(out, n.doc.Zones)
	return out
}

// record keeps the last apply result and error. The result is kept only
// when it says something about a generation (a render error carries none).
func (n *Node) record(res apply.Result, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if res.Generation != 0 || res.Changed {
		n.last = res
	}
	if err != nil {
		n.lastErr = err.Error()
	} else {
		n.lastErr = ""
	}
}

// loadCached reads the persisted document and its ETag.
func (n *Node) loadCached() ([]byte, string, bool) {
	body, err := os.ReadFile(n.files.docPath)
	if err != nil {
		return nil, "", false
	}
	etag, err := os.ReadFile(n.files.etagPath)
	if err != nil {
		return nil, "", false
	}
	return body, strings.TrimSpace(string(etag)), true
}

// saveCached persists the document and its ETag, each written whole, 0600:
// nothing but this process reads them, and the document may carry material
// later milestones would rather not leave world-readable.
func (n *Node) saveCached(body []byte, etag string) error {
	if err := writeAtomic(n.files.docPath, body); err != nil {
		return err
	}
	return writeAtomic(n.files.etagPath, []byte(etag+"\n"))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// terminatorAlive reads the pid file and signals 0 to it; nil when no pid
// file is configured (nothing to check).
func (n *Node) terminatorAlive() *bool {
	if n.opt.Terminator.PIDFile == "" {
		return nil
	}
	alive := false
	if raw, err := os.ReadFile(n.opt.Terminator.PIDFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
			alive = syscall.Kill(pid, 0) == nil || errors.Is(syscall.Kill(pid, 0), syscall.EPERM)
		}
	}
	return &alive
}

// report assembles the node's self-report; the certificate list is cut to
// what fits the brain's body limit, the count of dropped entries reported.
func (n *Node) report() api.EdgeReport {
	n.mu.Lock()
	rep := api.EdgeReport{
		Version:   buildinfo.Version(),
		DryRun:    n.opt.DryRun,
		ZonesETag: n.renderedETag,
		Terminator: &api.EdgeReportTerminator{
			Kind: n.termKind, Version: n.termVer,
			Generation: n.last.Generation, TestOK: n.last.TestOK, TestError: n.last.TestError,
			Alive: n.termAlive,
		},
	}
	n.mu.Unlock()
	if n.certs != nil {
		for _, c := range n.certs.Inventory() {
			rep.Certs = append(rep.Certs, api.EdgeReportCert{Zone: c.Zone, NotAfter: c.NotAfter, Issuer: c.Issuer})
		}
		sort.Slice(rep.Certs, func(i, j int) bool { return rep.Certs[i].Zone < rep.Certs[j].Zone })
	}
	return trimReport(rep)
}

// trimReport drops certificate entries from the (zone-sorted) tail until the
// report fits the brain's body limit, counting what went.
func trimReport(rep api.EdgeReport) api.EdgeReport {
	for {
		body, err := json.Marshal(rep)
		if err != nil || len(body) <= maxReportBytes || len(rep.Certs) == 0 {
			return rep
		}
		drop := len(rep.Certs) / 10
		if drop == 0 {
			drop = 1
		}
		rep.Certs = rep.Certs[:len(rep.Certs)-drop]
		rep.CertsTruncated += drop
	}
}

// reportLoop posts the self-report on a fixed cadence; on the same tick it
// refreshes the terminator-liveness check and retries a refused document
// when due. Best-effort: a report never affects the poll, and the poll — not
// the report — is liveness.
func (n *Node) reportLoop(ctx context.Context) error {
	t := time.NewTicker(n.opt.ReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			alive := n.terminatorAlive()
			n.mu.Lock()
			n.termAlive = alive
			n.mu.Unlock()
			n.retryIfDue(ctx)
			n.postReport(ctx)
		}
	}
}

func (n *Node) postReport(ctx context.Context) {
	rep := n.report()
	if rep.CertsTruncated > 0 {
		n.log.Warn("self-report certificate list truncated to fit the brain's body limit", "dropped", rep.CertsTruncated)
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(n.opt.Brain, "/")+"/api/v1/edge/nodes/"+n.opt.Name+"/report", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.opt.Token)
	resp, err := n.http.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			n.log.Warn("self-report failed", "err", err)
		}
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		n.log.Warn("self-report refused", "status", resp.StatusCode)
	}
}

// Status is the node's own view, for /healthz and tests.
type Status struct {
	// Healthy: a tested generation of ours is live and, when a pid file is
	// configured, the terminator is alive. A refused document does not clear
	// it — the previous generation keeps serving — but clears Converged.
	Healthy bool `json:"healthy"`
	// Converged: the last accepted document is the one rendered and live,
	// with no pending error.
	Converged bool `json:"converged"`
	// ZonesETag is the RENDERED document's ETag; AcceptedETag the one the
	// fast path holds. They differ while a document is refused.
	ZonesETag    string    `json:"zones_etag,omitempty"`
	AcceptedETag string    `json:"accepted_etag,omitempty"`
	Zones        int       `json:"zones"`
	Generation   uint64    `json:"generation"`
	TestOK       bool      `json:"test_ok"`
	TestError    string    `json:"test_error,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	RetryAt      time.Time `json:"retry_at,omitempty"`
	BrainSeen    time.Time `json:"brain_seen,omitempty"`
	DryRun       bool      `json:"dry_run"`
	Terminator   string    `json:"terminator,omitempty"`
	// TerminatorAlive is nil when no pid file is configured.
	TerminatorAlive *bool `json:"terminator_alive,omitempty"`
}

// Status snapshots the node.
func (n *Node) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := Status{
		ZonesETag: n.renderedETag, AcceptedETag: n.acceptedETag,
		Generation: n.last.Generation, TestOK: n.last.TestOK, TestError: n.last.TestError,
		LastError: n.lastErr, RetryAt: n.retryAt, DryRun: n.opt.DryRun,
		Terminator: strings.TrimSpace(n.termKind + " " + n.termVer), TerminatorAlive: n.termAlive,
	}
	st.Healthy = n.last.Generation != 0 && n.doc != nil && (n.termAlive == nil || *n.termAlive)
	st.Converged = st.Healthy && n.lastErr == "" && n.renderedETag == n.acceptedETag
	if n.doc != nil {
		st.Zones = len(n.doc.Zones)
	}
	if n.poller != nil {
		st.BrainSeen = n.poller.LastOK()
	}
	return st
}

// StatusAddr is the address the status listener bound, "" until it has.
func (n *Node) StatusAddr() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.statusAddr
}

// statusHandler serves /healthz (200 when Status().Healthy, 503 otherwise,
// the status as JSON either way) and /metrics.
func (n *Node) statusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		st := n.Status()
		w.Header().Set("Content-Type", "application/json")
		if !st.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(st)
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	return mux
}

// serveStatus exposes the status handler on StatusListen.
func (n *Node) serveStatus(ctx context.Context) error {
	ln, err := net.Listen("tcp", n.opt.StatusListen)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.statusAddr = ln.Addr().String()
	n.mu.Unlock()
	srv := &http.Server{Handler: n.statusHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

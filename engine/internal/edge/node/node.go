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
// does it poll.
//
// TWO PATHS ON A NEW DOCUMENT. The fast path — the decision service's zone
// policies, the aggregator's zone set, the fanned-out challenges — is applied
// first and touches no file. Then the document is persisted, rendered and
// applied; since the render does not depend on policy.rate or on any verdict,
// a rate change never reloads the terminator (§2.2). A certificate issued or
// renewed re-renders and applies too — that is what reloads are for.
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
	"strings"
	"sync"
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
	// SocketsDir holds the three unix sockets (the renderer's defaults are
	// under /run/kapkan).
	SocketsDir string
	// SocketGroup is the terminator's worker group, chowned onto the decide
	// and log sockets ("" leaves them as created).
	SocketGroup string
	// Terminator names the binary ("" = nginx), its main configuration ("" =
	// the binary's default), the reload method and its parameters.
	Terminator Terminator
	// ACME is the node's default CA, fallback and contact.
	ACME ACME
	// ReportInterval is the self-report cadence; 0 = 10 s.
	ReportInterval time.Duration
	// StatusListen, when set, serves /healthz and /metrics on this address
	// (loopback by default in the config).
	StatusListen string
	// OmitCatchAll and DisableIPv6 pass through to the renderer.
	OmitCatchAll bool
	DisableIPv6  bool
	Logger       *slog.Logger
	// HTTPClient talks to the brain (polls, reports, ACME coordination); nil
	// means a default client. Tests inject one.
	HTTPClient *http.Client
	// Tester and Reloader override the terminator adapters (tests).
	Tester   apply.Tester
	Reloader apply.Reloader
}

// Terminator is how the node drives nginx or Angie.
type Terminator struct {
	Binary   string
	MainConf string
	Reload   string
	PIDFile  string
	Command  []string
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
	// Disabled turns issuance off (a lab with its own certificates).
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
	poller     *poll.Poller

	mu       sync.Mutex
	doc      *edgedoc.Doc
	etag     string
	last     apply.Result
	lastErr  string
	termKind string
	termVer  string
	healthy  bool
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
	if opt.Terminator.Binary == "" {
		opt.Terminator.Binary = "nginx"
	}
	if opt.Terminator.Reload == "" {
		opt.Terminator.Reload = ReloadExec
	}
	n := &Node{opt: opt, log: opt.Logger.With("component", "edge"), http: opt.HTTPClient}
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
		brain := &acme.BrainClient{BaseURL: strings.TrimRight(opt.Brain, "/"), Token: opt.Token, Node: opt.Name, HTTPClient: opt.HTTPClient}
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

// Run brings the node up and serves until ctx is done.
func (n *Node) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	spawn := func(name string, f func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(ctx); err != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}

	// 1. Sockets first: nginx may already be running and probing them.
	spawn("decision service", (&decide.Server{Service: n.svc, Path: n.files.decideSock, SocketGroup: n.opt.SocketGroup, Logger: n.opt.Logger}).ListenAndServe)
	spawn("challenge answerer", (&acme.ChallengeServer{Table: n.challenges, Path: n.files.challengeSock, Mode: 0o660, Logger: n.opt.Logger}).ListenAndServe)
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

	// 2. The terminator: what it is, and whether a predecessor left an
	// untested generation live.
	if kind, ver, err := apply.Probe(ctx, n.opt.Terminator.Binary); err == nil {
		n.mu.Lock()
		n.termKind, n.termVer = kind, ver
		n.mu.Unlock()
	} else {
		n.log.Warn("terminator probe failed; kind and version will be missing from reports", "err", err)
	}
	if res, err := n.applier.Recover(ctx); err != nil {
		n.log.Error("recovering the live generation failed", "err", err)
		n.record(res, err)
	} else if res.Changed {
		n.log.Warn("recovered an untested generation left by a previous process", "generation", res.Generation, "test_ok", res.TestOK)
		n.record(res, nil)
	}

	// 3. Start from disk.
	if body, etag, ok := n.loadCached(); ok {
		if err := n.acceptDocument(ctx, body, etag, false); err != nil {
			n.log.Error("the cached document did not apply; waiting for the brain", "err", err)
		} else {
			n.log.Info("serving the last accepted document from disk", "etag", etag)
		}
	}

	// 4. Poll, report, renew.
	p, err := poll.New(poll.Options{
		BaseURL: strings.TrimRight(n.opt.Brain, "/"), Path: "/api/v1/edge/zones", Token: n.opt.Token, Node: n.opt.Name,
		ETag:   n.currentETag(),
		Logger: n.opt.Logger, Client: n.pollClient(),
		OnDocument: func(body []byte, etag string) error { return n.acceptDocument(ctx, body, etag, true) },
	})
	if err != nil {
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

	var firstErr error
	select {
	case <-ctx.Done():
	case firstErr = <-errs:
		n.log.Error("a component failed; shutting down", "err", firstErr)
	}
	cancel()
	wg.Wait()
	return firstErr
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
	n.doc, n.etag = doc, etag
	n.mu.Unlock()
	if persist {
		if err := n.saveCached(body, etag); err != nil {
			n.log.Error("persisting the document failed; a restart with the brain gone would serve the previous one", "err", err)
		}
	}
	return n.renderAndApply(ctx, doc)
}

// renderAndApply is the slow path: the terminator's configuration from the
// document and the certificates this node holds.
func (n *Node) renderAndApply(ctx context.Context, doc *edgedoc.Doc) error {
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
		return fmt.Errorf("render: %w", err)
	}
	res, err := n.applier.Apply(ctx, files)
	n.record(res, err)
	if err != nil {
		return err
	}
	if res.Changed {
		n.log.Info("configuration installed", "generation", res.Generation, "reloaded", res.Reloaded, "zones", len(doc.Zones))
	}
	return nil
}

// onCertificate is the ACME manager's hook: a new certificate re-renders.
func (n *Node) onCertificate(zone string) {
	n.mu.Lock()
	doc := n.doc
	n.mu.Unlock()
	if doc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := n.renderAndApply(ctx, doc); err != nil {
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
	n.healthy = err == nil
}

func (n *Node) currentETag() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.etag
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

// saveCached persists the document and its ETag, each written whole.
func (n *Node) saveCached(body []byte, etag string) error {
	if err := writeAtomic(n.files.docPath, body); err != nil {
		return err
	}
	return writeAtomic(n.files.etagPath, []byte(etag+"\n"))
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// report assembles the node's self-report.
func (n *Node) report() api.EdgeReport {
	n.mu.Lock()
	rep := api.EdgeReport{
		Version:   buildinfo.Version(),
		DryRun:    n.opt.DryRun,
		ZonesETag: n.etag,
		Terminator: &api.EdgeReportTerminator{
			Kind: n.termKind, Version: n.termVer,
			Generation: n.last.Generation, TestOK: n.last.TestOK, TestError: n.last.TestError,
		},
	}
	n.mu.Unlock()
	if n.certs != nil {
		for _, c := range n.certs.Inventory() {
			rep.Certs = append(rep.Certs, api.EdgeReportCert{Zone: c.Zone, NotAfter: c.NotAfter, Issuer: c.Issuer})
		}
		sort.Slice(rep.Certs, func(i, j int) bool { return rep.Certs[i].Zone < rep.Certs[j].Zone })
	}
	return rep
}

// reportLoop posts the self-report on a fixed cadence. Best-effort: a report
// never affects the poll, and the poll — not the report — is liveness.
func (n *Node) reportLoop(ctx context.Context) error {
	t := time.NewTicker(n.opt.ReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			n.postReport(ctx)
		}
	}
}

func (n *Node) postReport(ctx context.Context) {
	body, err := json.Marshal(n.report())
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
	Healthy    bool      `json:"healthy"`
	ZonesETag  string    `json:"zones_etag,omitempty"`
	Zones      int       `json:"zones"`
	Generation uint64    `json:"generation"`
	TestOK     bool      `json:"test_ok"`
	TestError  string    `json:"test_error,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	BrainSeen  time.Time `json:"brain_seen,omitempty"`
	DryRun     bool      `json:"dry_run"`
	Terminator string    `json:"terminator,omitempty"`
}

// Status snapshots the node.
func (n *Node) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := Status{Healthy: n.healthy && n.doc != nil, ZonesETag: n.etag, Generation: n.last.Generation, TestOK: n.last.TestOK, TestError: n.last.TestError,
		LastError: n.lastErr, DryRun: n.opt.DryRun, Terminator: strings.TrimSpace(n.termKind + " " + n.termVer)}
	if n.doc != nil {
		st.Zones = len(n.doc.Zones)
	}
	if n.poller != nil {
		st.BrainSeen = n.poller.LastOK()
	}
	return st
}

// serveStatus exposes /healthz (200 when a tested generation is live, 503
// otherwise) and /metrics on StatusListen.
func (n *Node) serveStatus(ctx context.Context) error {
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
	ln, err := net.Listen("tcp", n.opt.StatusListen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
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

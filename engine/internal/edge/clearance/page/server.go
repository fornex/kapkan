// Package page is the clearance page: the proof-of-work rung's face
// (edge-spec §5; milestone E4.3), served by the edge node itself over the
// fourth unix socket the renderer points every decide-mode zone at.
//
// THE CONTRACT is what the renderer emits (internal/edge/render). Two ways in:
//
//   - The named location @kapkan_clearance, entered when the decision service
//     answered 401. It forwards the request's own URI unchanged, plus
//     X-Kapkan-Zone, -Client, -Method, -URI, -Reason (only this entry sets
//     it — the header, not a path, is how the page knows the entry),
//     Accept-Language. The page answers the CHALLENGE: an HTML page with
//     the puzzle for a GET or HEAD, a compact JSON refusal for anything else
//     (a browser form or an API client has nothing to solve a puzzle with).
//     Status 403 with Cache-Control: no-store (D5): to a cache it is a
//     refusal, to a client it is an answer it can act on.
//   - The public prefix /_kapkan/clearance/: the answer (POST), the no-JS
//     ticket (GET) and the assets, with kapkan's headers plus the client's
//     Content-Type and Accept-Language, a 4 KiB body at most.
//
// WHAT IT KNOWS. Only what the decision service tells it per zone: the keys
// to sign with (the document's, or the node's own) and the rung's policy
// (difficulty, lifetimes). Nothing per client: the puzzle and the ticket are
// stateless (internal/edge/clearance), so a fleet of nodes behind one address
// serves one client's challenge and answer on different nodes. The one piece
// of state is the ISSUANCE CAP — clearances minted per source key and per
// zone per minute — bounded, swept, and there to keep a solver farm from
// turning the page into a cookie mint.
//
// WHERE A CLIENT MAY BE SENT. Only to the path the terminator said it came
// from, which the puzzle and the ticket carry signed: the answer endpoint
// cannot be made into an open redirect.
package page

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/unixsock"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// Zones is what the page needs from the decision service.
type Zones interface {
	// Keys returns the zone's clearance keys, the document's first and the
	// node's own last; nil for an unknown zone.
	Keys(zone string) []clearance.Key
	// Rung returns the zone's resolved challenge policy; false when the zone
	// is unknown or its rung is off.
	Rung(zone string) (clearance.Policy, bool)
}

const (
	// DefaultSocketMode is owner and group only, like the decision service's:
	// the page mints clearances, so only the terminator's worker may ask it.
	DefaultSocketMode = 0o660

	// Prefix is the kapkan-reserved public prefix the renderer routes here.
	// The challenge entry has no path of its own: it is any request that
	// arrives with X-Kapkan-Reason (set only by the named location).
	Prefix      = "/_kapkan/clearance/"
	answerPath  = Prefix + "answer"
	nojsPath    = Prefix + "nojs"
	assetPrefix = Prefix + "a/"

	// CookieName is the clearance cookie (D2): host-only, Path=/, Secure,
	// HttpOnly, SameSite=Lax.
	CookieName = "kapkan_clr"

	// DefaultIssuePerSource and DefaultIssuePerZone cap clearances minted per
	// minute for one source key and for one zone (D8: a solver farm must not
	// turn the page into a cookie mint; a real visitor needs one).
	DefaultIssuePerSource = 6
	DefaultIssuePerZone   = 6000
	maxCapEntries         = 64 << 10

	maxBody        = 8 << 10
	maxHeaderBytes = 64 << 10

	headerZone      = "X-Kapkan-Zone"
	headerClient    = "X-Kapkan-Client"
	headerMethod    = "X-Kapkan-Method"
	headerURI       = "X-Kapkan-URI"
	headerReason    = "X-Kapkan-Reason"
	headerClearance = "X-Kapkan-Clearance"
)

//go:embed assets/app.js assets/style.css
var assetFS embed.FS

// Server serves the clearance page over a unix socket.
type Server struct {
	Zones Zones
	// Path is the socket; the renderer's Node.ClearanceSocket must name it.
	Path string
	// Mode is the socket's permission bits; 0 means DefaultSocketMode.
	Mode os.FileMode
	// SocketGroup is the group the socket is chowned to (the terminator's
	// worker group); "" keeps the process's group.
	SocketGroup string
	Logger      *slog.Logger
	// Now is the clock; nil means time.Now. Tests inject one.
	Now func() time.Time
	// IssuePerSource and IssuePerZone are the per-minute issuance caps; 0
	// means the defaults.
	IssuePerSource, IssuePerZone int

	once   sync.Once
	assets map[string]asset // by URL path
	appURL string
	cssURL string

	mu        sync.Mutex
	perSource map[capKey]*capWindow
	perZone   map[string]*capWindow
	lastSweep time.Time
}

type asset struct {
	body        []byte
	contentType string
}

type capKey struct {
	zone string
	src  string
}

type capWindow struct {
	start time.Time
	count int
}

func (s *Server) init() {
	s.once.Do(func() {
		if s.Logger == nil {
			s.Logger = slog.Default()
		}
		s.Logger = s.Logger.With("component", "edge-clearance-page")
		if s.Now == nil {
			s.Now = time.Now
		}
		if s.IssuePerSource <= 0 {
			s.IssuePerSource = DefaultIssuePerSource
		}
		if s.IssuePerZone <= 0 {
			s.IssuePerZone = DefaultIssuePerZone
		}
		s.perSource = make(map[capKey]*capWindow)
		s.perZone = make(map[string]*capWindow)
		s.assets = make(map[string]asset)
		s.appURL = s.addAsset("app", "js", "text/javascript; charset=utf-8")
		s.cssURL = s.addAsset("style", "css", "text/css; charset=utf-8")
	})
}

// addAsset registers an embedded file under a content-hashed name, so a new
// binary is a new URL and the old one may be cached for a year.
func (s *Server) addAsset(name, ext, contentType string) string {
	body, err := assetFS.ReadFile("assets/" + name + "." + ext)
	if err != nil {
		panic("clearance page: embedded asset missing: " + err.Error())
	}
	sum := sha256.Sum256(body)
	url := assetPrefix + name + "." + hex.EncodeToString(sum[:6]) + "." + ext
	s.assets[url] = asset{body: body, contentType: contentType}
	return url
}

// Handler is the HTTP side, for tests and for embedding.
func (s *Server) Handler() http.Handler {
	s.init()
	return http.HandlerFunc(s.serve)
}

// ListenAndServe serves on the unix socket until ctx is done, then removes
// it. A stale socket from a dead process is replaced; one another process
// serves is refused, not stolen.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.init()
	if s.Path == "" {
		return errors.New("clearance page: no socket path")
	}
	if s.Zones == nil {
		return errors.New("clearance page: no zones source")
	}
	mode := s.Mode
	if mode == 0 {
		mode = DefaultSocketMode
	}
	gid, err := unixsock.GroupID(s.SocketGroup)
	if err != nil {
		return fmt.Errorf("clearance page: %w", err)
	}
	sock, release, err := unixsock.Listen("unix", s.Path, mode, gid)
	if err != nil {
		return fmt.Errorf("clearance page: %w", err)
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.Logger.Info("clearance page listening", "socket", s.Path, "mode", fmt.Sprintf("%o", mode), "group", s.SocketGroup)
	err = srv.Serve(sock.(net.Listener))
	release()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// request is what the renderer's headers say about the client's request.
type request struct {
	zone      string
	src       netip.Addr
	sourceKey string
	method    string // the ORIGINAL request's method (X-Kapkan-Method)
	uri       string // the original request target (X-Kapkan-URI)
	reason    string
	lang      *locale
	pol       clearance.Policy
	keys      []clearance.Key
	now       time.Time
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	now := s.Now()
	if strings.HasPrefix(r.URL.Path, assetPrefix) {
		s.serveAsset(w, r)
		return
	}
	zone := r.Header.Get(headerZone)
	src, err := netip.ParseAddr(r.Header.Get(headerClient))
	if zone == "" || err != nil {
		metrics.EdgeClearanceTotal.WithLabelValues("unknown", "bad_request").Inc()
		http.Error(w, "off the contract: X-Kapkan-Zone and X-Kapkan-Client are required", http.StatusBadRequest)
		return
	}
	pol, ok := s.Zones.Rung(zone)
	if !ok {
		// A zone this node does not serve, or one whose rung is off: nothing to
		// offer. The zone label stays bounded by what the document names.
		metrics.EdgeClearanceTotal.WithLabelValues("unknown", "unknown_zone").Inc()
		http.NotFound(w, r)
		return
	}
	req := &request{
		zone: zone, src: src.Unmap(), method: r.Header.Get(headerMethod), uri: r.Header.Get(headerURI),
		reason: r.Header.Get(headerReason), lang: pickLocale(r.Header.Get("Accept-Language")), pol: pol, now: now,
	}
	req.sourceKey = edgedoc.SourceKey(req.src).String()
	req.keys = s.Zones.Keys(zone)
	if req.reason != "" {
		// The challenge entry: @kapkan_clearance proxies the request with its
		// OWN URI (a rewrite there would follow a fallen-back request to the
		// origin) and is the only location that sets X-Kapkan-Reason, so the
		// header, not the path, names this entry.
		s.serveChallenge(w, r, req)
		return
	}
	switch r.URL.Path {
	case answerPath:
		s.serveAnswer(w, r, req)
	case nojsPath:
		s.serveNoJS(w, r, req)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	a, ok := s.assets[r.URL.Path]
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.contentType)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", fmt.Sprint(len(a.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(a.body)
	}
}

// issuingKey picks the key new clearances are signed with: the newest live
// key the document gave (verifiable fleet-wide), else the node's own.
func issuingKey(keys []clearance.Key, now time.Time) (clearance.Key, bool) {
	var best clearance.Key
	found := false
	for _, k := range keys {
		if !k.Live(now) {
			continue
		}
		if k.ID == "local" {
			if !found {
				best, found = k, true
			}
			continue
		}
		if !found || best.ID == "local" || k.NotBefore.After(best.NotBefore) {
			best, found = k, true
		}
	}
	return best, found
}

func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Cookie")
	h.Set("X-Content-Type-Options", "nosniff")
}

// serveChallenge is the entry from @kapkan_clearance: the decision service
// said 401 and nginx proxied the request here with its own method and URI.
// The ORIGINAL method (X-Kapkan-Method) decides the shape of the answer; the
// proxied request itself is whatever nginx made of it.
func (s *Server) serveChallenge(w http.ResponseWriter, r *http.Request, req *request) {
	noStore(w)
	if req.method != http.MethodGet && req.method != http.MethodHead {
		// A form post, an XHR, an API call: nothing on that side can solve
		// a puzzle. Say so compactly, so a client library reads a refusal.
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "page_json").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"challenge_required"}` + "\n"))
		return
	}
	key, ok := issuingKey(req.keys, req.now)
	if !ok {
		// No live key: the rung cannot be cleared; the decider would not have
		// challenged, so this is a race with a key set change. Refuse plainly.
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "bad_request").Inc()
		http.Error(w, "no clearance key", http.StatusServiceUnavailable)
		return
	}
	ret := req.uri
	if !clearance.ValidReturnPath(ret) {
		ret = "/"
	}
	puzzle, err := clearance.NewPuzzle(key, req.zone, req.sourceKey, ret, req.pol.Difficulty, req.now)
	if err != nil {
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "bad_request").Inc()
		http.Error(w, "puzzle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ticket, err := clearance.NewTicket(key, req.zone, req.sourceKey, ret, req.now)
	if err != nil {
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "bad_request").Inc()
		http.Error(w, "ticket: "+err.Error(), http.StatusInternalServerError)
		return
	}
	metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "page").Inc()
	s.renderChallenge(w, r, req, puzzle, ticket, ret)
}

// answer is what the client's form or script posts.
type answer struct {
	Nonce    string `json:"nonce"`
	Solution string `json:"solution"`
	Return   string `json:"return"`
}

func (s *Server) readAnswer(w http.ResponseWriter, r *http.Request) (answer, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var a answer
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			return answer{}, false
		}
		return a, true
	}
	if err := r.ParseForm(); err != nil {
		return answer{}, false
	}
	return answer{Nonce: r.PostForm.Get("nonce"), Solution: r.PostForm.Get("solution"), Return: r.PostForm.Get("return")}, true
}

// serveAnswer checks a solution and, if it is right, mints the clearance and
// sends the client back where it came from.
func (s *Server) serveAnswer(w http.ResponseWriter, r *http.Request, req *request) {
	noStore(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the answer is a POST", http.StatusMethodNotAllowed)
		return
	}
	a, ok := s.readAnswer(w, r)
	if !ok || len(a.Nonce) > 128 || len(a.Solution) > 64 || !clearance.ValidReturnPath(a.Return) {
		s.refuse(w, req, "invalid")
		return
	}
	if !clearance.Check(req.keys, req.zone, req.sourceKey, a.Return, req.pol.Difficulty, a.Nonce, a.Solution, req.now) {
		s.refuse(w, req, "invalid")
		return
	}
	s.issue(w, req, clearance.KindPoW, req.pol.CookieTTL, a.Return, "issued")
}

// serveNoJS redeems the timed ticket a client without JavaScript waited on.
func (s *Server) serveNoJS(w http.ResponseWriter, r *http.Request, req *request) {
	noStore(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "the ticket is a GET", http.StatusMethodNotAllowed)
		return
	}
	ret, ok := clearance.CheckTicket(req.keys, req.zone, req.sourceKey, r.URL.Query().Get("t"), req.now)
	if !ok {
		// Too early, too late or not ours. A no-JS client cannot read JSON:
		// a small page says to wait and try again, or to start over.
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "invalid").Inc()
		s.renderTooEarly(w, req, req.uri)
		return
	}
	s.issue(w, req, clearance.KindNoJS, req.pol.NoJSTTL, ret, "issued_nojs")
}

// issue mints the clearance cookie under the issuing key and answers 303 to
// the return path — after the issuance caps have had their say.
func (s *Server) issue(w http.ResponseWriter, req *request, kind string, ttl time.Duration, ret, result string) {
	if !s.allowIssue(req.zone, req.sourceKey, req.now) {
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "rate_limited").Inc()
		w.Header().Set("Retry-After", "10")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited"}` + "\n"))
		return
	}
	key, ok := issuingKey(req.keys, req.now)
	if !ok {
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "bad_request").Inc()
		http.Error(w, "no clearance key", http.StatusServiceUnavailable)
		return
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	tok, err := clearance.Issue(key, req.zone, req.sourceKey, kind, req.now.Add(ttl), req.now)
	if err != nil {
		metrics.EdgeClearanceTotal.WithLabelValues(req.zone, "bad_request").Inc()
		http.Error(w, "issue: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: tok, Path: "/", MaxAge: int(ttl / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	metrics.EdgeClearanceTotal.WithLabelValues(req.zone, result).Inc()
	w.Header().Set("Location", ret)
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) refuse(w http.ResponseWriter, req *request, result string) {
	metrics.EdgeClearanceTotal.WithLabelValues(req.zone, result).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"` + result + `"}` + "\n"))
}

// allowIssue spends one issuance for (zone, source) and for zone in the
// current minute; false when either cap is reached. Windows are per minute
// and the maps are bounded and swept, so a rotating attacker cannot grow
// them without bound — and when the per-source map is full, a NEW source is
// refused rather than let through untracked: minting is the one place the
// edge fails toward "no".
func (s *Server) allowIssue(zone, src string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastSweep) >= time.Minute {
		s.lastSweep = now
		for k, cw := range s.perSource {
			if now.Sub(cw.start) >= time.Minute {
				delete(s.perSource, k)
			}
		}
		for k, cw := range s.perZone {
			if now.Sub(cw.start) >= time.Minute {
				delete(s.perZone, k)
			}
		}
	}
	zw := s.perZone[zone]
	if zw == nil || now.Sub(zw.start) >= time.Minute {
		zw = &capWindow{start: now}
		s.perZone[zone] = zw
	}
	if zw.count >= s.IssuePerZone {
		return false
	}
	k := capKey{zone: zone, src: src}
	sw := s.perSource[k]
	if sw == nil || now.Sub(sw.start) >= time.Minute {
		if sw == nil && len(s.perSource) >= maxCapEntries {
			return false
		}
		sw = &capWindow{start: now}
		s.perSource[k] = sw
	}
	if sw.count >= s.IssuePerSource {
		return false
	}
	sw.count++
	zw.count++
	return true
}

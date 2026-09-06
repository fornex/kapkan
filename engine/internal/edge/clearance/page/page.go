package page

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
)

// locale is the page's handful of strings in one language. No images, no
// external requests, no CAPTCHA (edge-spec §7): the page is text, a
// progress line and a form.
type locale struct {
	Tag      string
	Title    string
	Heading  string
	Lead     string
	Working  string // the status line while solving (announced once)
	Done     string // the status line when the answer is being sent
	Fallback string // above the Continue form: JavaScript off, or the solver could not run
	Continue string // the button of the no-JS form
	TooEarly string // the ticket redeemed too soon: wait, it retries by itself
	Expired  string // the ticket or the answer aged out: start over from the page
	Busy     string // the issuance cap held: wait a minute
	Again    string // the link that retries the ticket
	Retry    string // the link back to the page the client came from
	Stopped  string // the title and heading of a notice that ends the attempt (expired, busy)
	Footer   string
}

var locales = map[string]*locale{
	"en": {Tag: "en", Title: "One moment", Heading: "Checking your browser",
		Lead:    "This site is under heavier load than usual. Your browser is doing a short calculation to show it is a browser; the page continues by itself.",
		Working: "Working…", Done: "Done, continuing…",
		Fallback: "If this page does not continue by itself, wait a few seconds and press Continue.",
		Continue: "Continue", TooEarly: "Not yet. Wait a few seconds and try again.",
		Expired: "This took too long. Go back to the page and start over.",
		Busy:    "Too many attempts from your network right now. Wait a minute and try again.",
		Again:   "Try again", Retry: "Start over",
		Stopped: "Could not continue",
		Footer:  "Protected by Kapkan. No cookies other than the one that lets you through, no tracking."},
	"ru": {Tag: "ru", Title: "Одну секунду", Heading: "Проверяем браузер",
		Lead:    "На сайт сейчас повышенная нагрузка. Ваш браузер выполняет короткое вычисление, чтобы показать, что это браузер; страница продолжится сама.",
		Working: "Считаем…", Done: "Готово, продолжаем…",
		Fallback: "Если страница не продолжится сама, подождите несколько секунд и нажмите «Продолжить».",
		Continue: "Продолжить", TooEarly: "Пока рано. Подождите несколько секунд и попробуйте ещё раз.",
		Expired: "Прошло слишком много времени. Вернитесь на страницу и начните заново.",
		Busy:    "Слишком много попыток из вашей сети. Подождите минуту и попробуйте ещё раз.",
		Again:   "Попробовать ещё раз", Retry: "Начать заново",
		Stopped: "Не удалось продолжить",
		Footer:  "Под защитой Kapkan. Никаких cookie, кроме пропуска, никакого отслеживания."},
	"de": {Tag: "de", Title: "Einen Moment", Heading: "Ihr Browser wird geprüft",
		Lead:    "Diese Website ist stärker belastet als sonst. Ihr Browser führt eine kurze Berechnung aus, um zu zeigen, dass er ein Browser ist; die Seite geht von selbst weiter.",
		Working: "Wird berechnet…", Done: "Fertig, weiter geht es…",
		Fallback: "Wenn die Seite nicht von selbst weitergeht, warten Sie ein paar Sekunden und drücken Sie auf Weiter.",
		Continue: "Weiter", TooEarly: "Noch nicht. Warten Sie ein paar Sekunden und versuchen Sie es erneut.",
		Expired: "Das hat zu lange gedauert. Gehen Sie zur Seite zurück und beginnen Sie von vorn.",
		Busy:    "Zu viele Versuche aus Ihrem Netz. Warten Sie eine Minute und versuchen Sie es erneut.",
		Again:   "Erneut versuchen", Retry: "Von vorn beginnen",
		Stopped: "Es ging nicht weiter",
		Footer:  "Geschützt von Kapkan. Kein Cookie außer dem Passierschein, kein Tracking."},
	"fr": {Tag: "fr", Title: "Un instant", Heading: "Vérification de votre navigateur",
		Lead:    "Ce site est plus sollicité que d'habitude. Votre navigateur effectue un court calcul pour montrer qu'il est un navigateur ; la page continue toute seule.",
		Working: "Calcul en cours…", Done: "Terminé, on continue…",
		Fallback: "Si la page ne continue pas toute seule, attendez quelques secondes puis appuyez sur Continuer.",
		Continue: "Continuer", TooEarly: "Pas encore. Attendez quelques secondes et réessayez.",
		Expired: "Cela a pris trop de temps. Revenez à la page et recommencez.",
		Busy:    "Trop de tentatives depuis votre réseau. Attendez une minute et réessayez.",
		Again:   "Réessayer", Retry: "Recommencer",
		Stopped: "Impossible de continuer",
		Footer:  "Protégé par Kapkan. Aucun cookie autre que le laissez-passer, aucun pistage."},
	"es": {Tag: "es", Title: "Un instante", Heading: "Comprobando su navegador",
		Lead:    "Este sitio tiene más carga de lo habitual. Su navegador hace un breve cálculo para demostrar que es un navegador; la página continúa por sí sola.",
		Working: "Calculando…", Done: "Listo, continuamos…",
		Fallback: "Si la página no continúa por sí sola, espere unos segundos y pulse Continuar.",
		Continue: "Continuar", TooEarly: "Todavía no. Espere unos segundos y vuelva a intentarlo.",
		Expired: "Ha tardado demasiado. Vuelva a la página y empiece de nuevo.",
		Busy:    "Demasiados intentos desde su red. Espere un minuto y vuelva a intentarlo.",
		Again:   "Intentar de nuevo", Retry: "Empezar de nuevo",
		Stopped: "No se pudo continuar",
		Footer:  "Protegido por Kapkan. Ninguna cookie salvo el pase, ningún rastreo."},
}

// pickLocale reads Accept-Language (a bounded, client-controlled header) and
// returns the first language the page speaks, English otherwise.
func pickLocale(header string) *locale {
	if len(header) > 512 {
		header = header[:512]
	}
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(part)
		if i := strings.IndexByte(tag, ';'); i >= 0 {
			tag = tag[:i]
		}
		if i := strings.IndexByte(tag, '-'); i >= 0 {
			tag = tag[:i]
		}
		if l, ok := locales[strings.ToLower(tag)]; ok {
			return l
		}
	}
	return locales["en"]
}

// The no-JS timer. TicketMinWait is 4 s; the refresh fires later than that
// so a node whose clock runs a couple of seconds behind the issuing node's
// (a fleet behind one address) still finds the wait served. The too-early
// page retries on its own after the same margin.
const (
	nojsRefreshSeconds = 7
	tooEarlyRetrySecs  = 5
)

// The page. Semantic HTML, the puzzle as a data block (not executed, so it
// needs no CSP allowance), one script and one stylesheet by content hash,
// a status line announced once and a counter assistive technology does not
// read, and a FALLBACK that does not depend on the script: the timed ticket
// (a <noscript> meta refresh for JavaScript off) and its Continue form, which
// is VISIBLE unless the script hides it — its first act, before anything can
// fail — so JavaScript off, a blocked or broken script, and an engine that
// fails the solver's self-check all leave the button in place; the script
// puts it back on every bail-out and beside a solve that runs long. The
// block is a live region, so its appearance is announced. The script is not
// deferred: it sits after the form and runs while the page parses, so the
// button is hidden before the first paint. Nobody depends on the timer, the
// script or the button alone (§5: accessibility is a review gate).
var challengeTmpl = template.Must(template.New("challenge").Parse(`<!DOCTYPE html>
<html lang="{{.L.Tag}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.L.Title}}</title>
<link rel="stylesheet" href="{{.CSS}}">
<noscript><meta http-equiv="refresh" content="{{.Refresh}};url={{.NoJSURL}}"></noscript>
</head>
<body>
<main>
<h1>{{.L.Heading}}</h1>
<p>{{.L.Lead}}</p>
<p id="kapkan-status" role="status"></p>
<p id="kapkan-count" aria-hidden="true"></p>
<div id="kapkan-fallback" role="status">
<p>{{.L.Fallback}}</p>
<form method="get" action="{{.NoJSPath}}">
<input type="hidden" name="t" value="{{.Ticket}}">
<button type="submit">{{.L.Continue}}</button>
</form>
</div>
<form id="kapkan-answer" method="post" action="{{.AnswerPath}}" hidden>
<input type="hidden" name="nonce" value="{{.Puzzle.Nonce}}">
<input type="hidden" name="solution" value="">
<input type="hidden" name="return" value="{{.Puzzle.Return}}">
</form>
<script type="application/json" id="kapkan-puzzle">{{.PuzzleJSON}}</script>
<script src="{{.JS}}"></script>
</main>
<footer><p>{{.L.Footer}}</p></footer>
</body>
</html>
`))

// noticeTmpl is every answer that is not the page or the clearance: a
// sentence and one link, optionally retried by a timer.
var noticeTmpl = template.Must(template.New("notice").Parse(`<!DOCTYPE html>
<html lang="{{.L.Tag}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
<link rel="stylesheet" href="{{.CSS}}">
{{if .Refresh}}<meta http-equiv="refresh" content="{{.Refresh}};url={{.RefreshURL}}">
{{end}}</head>
<body>
<main>
<h1>{{.Heading}}</h1>
<p>{{.Message}}</p>
<p><a href="{{.Link}}">{{.LinkText}}</a></p>
</main>
<footer><p>{{.L.Footer}}</p></footer>
</body>
</html>
`))

type challengeData struct {
	L          *locale
	CSS, JS    string
	NoJSCSS    string
	Puzzle     clearance.Puzzle
	PuzzleJSON template.JS
	Ticket     string
	NoJSPath   string
	NoJSURL    template.URL
	Refresh    int
	AnswerPath string
}

type noticeData struct {
	L          *locale
	CSS        string
	Title      string
	Heading    string
	Message    string
	Link       string
	LinkText   string
	Refresh    int
	RefreshURL template.URL
}

// selfLink reports whether link is the page's own no-JS ticket URL — the
// public path, a query of one ticket in the characters a ticket is made of,
// no longer than a ticket may be. Only such a link skips the return-path
// check (a ticket carries a return path of up to 2048 bytes and so outgrows
// that bound).
func selfLink(link string) bool {
	rest, ok := strings.CutPrefix(link, nojsPath+"?t=")
	if !ok || rest == "" || len(rest) > 4096 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if !ticketByte(rest[i]) {
			return false
		}
	}
	return true
}

// ticketByte reports whether c may appear in a ticket as it travels in a URL:
// base64url, dots, and the percent an escaper may add.
func ticketByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '.' || c == '_' || c == '-' || c == '%'
}

// csp is the page's own policy: its script and stylesheet by hash-named
// URL on this host, a form to this host, nothing else — no frames, no
// images, no third parties. The script starts a Worker from its own URL,
// which script-src 'self' covers (there is no worker-src, so it inherits).
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func (s *Server) renderChallenge(w http.ResponseWriter, r *http.Request, req *request, p clearance.Puzzle, ticket, ret string) {
	raw, _ := json.Marshal(p)
	// A data block is not executed, but "</script>" inside it would end it:
	// json.Marshal escapes '<' and '>' as < / >, so it cannot.
	data := challengeData{
		L: req.lang, CSS: s.cssURL, JS: s.appURL, Puzzle: p, PuzzleJSON: template.JS(raw), Ticket: ticket,
		NoJSPath: nojsPath, NoJSURL: template.URL(nojsPath + "?t=" + ticket), Refresh: nojsRefreshSeconds, AnswerPath: answerPath,
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", csp)
	h.Set("Content-Language", req.lang.Tag)
	h.Set("Vary", "Cookie, Accept-Language")
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return
	}
	if err := challengeTmpl.Execute(w, data); err != nil {
		s.Logger.Error("rendering the challenge page failed", "zone", req.zone, "err", err)
	}
}

// renderNotice answers status with a sentence and a link; a refresh of n
// seconds to the link retries it by itself (the too-early ticket). A notice
// that ENDS the attempt (stopped: expired, wrong, the cap) says so in its
// title and heading; one that only asks to wait keeps the challenge's.
func (s *Server) renderNotice(w http.ResponseWriter, req *request, status int, stopped bool, message, linkText, link string, refresh int) {
	// A link the page composed itself — the ticket's own URL, longer than a
	// return path may be — is trusted as such; anything else must be a
	// same-host return path.
	if !selfLink(link) && !clearance.ValidReturnPath(link) {
		link = "/"
	}
	title, heading := req.lang.Title, req.lang.Heading
	if stopped {
		title, heading = req.lang.Stopped, req.lang.Stopped
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", csp)
	h.Set("Content-Language", req.lang.Tag)
	w.WriteHeader(status)
	_ = noticeTmpl.Execute(w, noticeData{
		L: req.lang, CSS: s.cssURL, Title: title, Heading: heading, Message: message, Link: link, LinkText: linkText,
		Refresh: refresh, RefreshURL: template.URL(link),
	})
}

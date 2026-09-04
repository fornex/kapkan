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
	Working  string // aria-live progress while solving
	Done     string // aria-live when the answer is being sent
	NoScript string // shown when JavaScript is off
	Continue string // the button of the no-JS form
	TooEarly string // the ticket redeemed too soon or too late
	Retry    string // the link back to start over
	Footer   string
}

var locales = map[string]*locale{
	"en": {Tag: "en", Title: "One moment", Heading: "Checking your browser",
		Lead:    "This site is under heavier load than usual. Your browser is doing a short calculation to show it is a browser; the page continues by itself.",
		Working: "Working…", Done: "Done, continuing…",
		NoScript: "JavaScript is off in your browser. Wait a few seconds, then press Continue.",
		Continue: "Continue", TooEarly: "Not yet. Wait a few seconds and try again.", Retry: "Start over",
		Footer: "Protected by Kapkan. No cookies other than the one that lets you through, no tracking."},
	"ru": {Tag: "ru", Title: "Одну секунду", Heading: "Проверяем браузер",
		Lead:    "На сайт сейчас повышенная нагрузка. Ваш браузер выполняет короткое вычисление, чтобы показать, что это браузер; страница продолжится сама.",
		Working: "Считаем…", Done: "Готово, продолжаем…",
		NoScript: "В браузере выключен JavaScript. Подождите несколько секунд и нажмите «Продолжить».",
		Continue: "Продолжить", TooEarly: "Пока рано. Подождите несколько секунд и попробуйте ещё раз.", Retry: "Начать заново",
		Footer: "Под защитой Kapkan. Никаких cookie, кроме пропуска, никакого отслеживания."},
	"de": {Tag: "de", Title: "Einen Moment", Heading: "Ihr Browser wird geprüft",
		Lead:    "Diese Website ist stärker belastet als sonst. Ihr Browser führt eine kurze Berechnung aus, um zu zeigen, dass er ein Browser ist; die Seite geht von selbst weiter.",
		Working: "Wird berechnet…", Done: "Fertig, weiter geht es…",
		NoScript: "JavaScript ist in Ihrem Browser ausgeschaltet. Warten Sie ein paar Sekunden und drücken Sie dann auf Weiter.",
		Continue: "Weiter", TooEarly: "Noch nicht. Warten Sie ein paar Sekunden und versuchen Sie es erneut.", Retry: "Von vorn beginnen",
		Footer: "Geschützt von Kapkan. Kein Cookie außer dem Passierschein, kein Tracking."},
	"fr": {Tag: "fr", Title: "Un instant", Heading: "Vérification de votre navigateur",
		Lead:    "Ce site est plus sollicité que d'habitude. Votre navigateur effectue un court calcul pour montrer qu'il est un navigateur ; la page continue toute seule.",
		Working: "Calcul en cours…", Done: "Terminé, on continue…",
		NoScript: "JavaScript est désactivé dans votre navigateur. Attendez quelques secondes, puis appuyez sur Continuer.",
		Continue: "Continuer", TooEarly: "Pas encore. Attendez quelques secondes et réessayez.", Retry: "Recommencer",
		Footer: "Protégé par Kapkan. Aucun cookie autre que le laissez-passer, aucun pistage."},
	"es": {Tag: "es", Title: "Un instante", Heading: "Comprobando su navegador",
		Lead:    "Este sitio tiene más carga de lo habitual. Su navegador hace un breve cálculo para demostrar que es un navegador; la página continúa por sí sola.",
		Working: "Calculando…", Done: "Listo, continuamos…",
		NoScript: "JavaScript está desactivado en su navegador. Espere unos segundos y pulse Continuar.",
		Continue: "Continuar", TooEarly: "Todavía no. Espere unos segundos y vuelva a intentarlo.", Retry: "Empezar de nuevo",
		Footer: "Protegido por Kapkan. Ninguna cookie salvo el pase, ningún rastreo."},
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

// The page. Semantic HTML, the puzzle as a data block (not executed, so it
// needs no CSP allowance), one script and one stylesheet by content hash,
// aria-live progress, and a no-JS path that is both timed (meta refresh)
// and manual (the form), so nobody depends on the timer (§5: accessibility is
// a review gate).
var challengeTmpl = template.Must(template.New("challenge").Parse(`<!DOCTYPE html>
<html lang="{{.L.Tag}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.L.Title}}</title>
<link rel="stylesheet" href="{{.CSS}}">
<noscript><meta http-equiv="refresh" content="5;url={{.NoJSURL}}"></noscript>
</head>
<body>
<main>
<h1>{{.L.Heading}}</h1>
<p>{{.L.Lead}}</p>
<p id="kapkan-status" role="status" aria-live="polite"></p>
<noscript>
<p>{{.L.NoScript}}</p>
<form method="get" action="{{.NoJSPath}}">
<input type="hidden" name="t" value="{{.Ticket}}">
<button type="submit">{{.L.Continue}}</button>
</form>
</noscript>
<form id="kapkan-answer" method="post" action="{{.AnswerPath}}" hidden>
<input type="hidden" name="nonce" value="{{.Puzzle.Nonce}}">
<input type="hidden" name="solution" value="">
<input type="hidden" name="return" value="{{.Puzzle.Return}}">
</form>
<script type="application/json" id="kapkan-puzzle">{{.PuzzleJSON}}</script>
<script src="{{.JS}}" defer></script>
</main>
<footer><p>{{.L.Footer}}</p></footer>
</body>
</html>
`))

var tooEarlyTmpl = template.Must(template.New("tooearly").Parse(`<!DOCTYPE html>
<html lang="{{.L.Tag}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.L.Title}}</title>
<link rel="stylesheet" href="{{.CSS}}">
</head>
<body>
<main>
<h1>{{.L.Heading}}</h1>
<p>{{.L.TooEarly}}</p>
<p><a href="{{.Return}}">{{.L.Retry}}</a></p>
</main>
<footer><p>{{.L.Footer}}</p></footer>
</body>
</html>
`))

type challengeData struct {
	L          *locale
	CSS, JS    string
	Puzzle     clearance.Puzzle
	PuzzleJSON template.JS
	Ticket     string
	NoJSPath   string
	NoJSURL    template.URL
	AnswerPath string
}

// csp is the page's own policy: its script and stylesheet by hash-named
// URL on this host, a form to this host, nothing else — no frames, no
// images, no third parties.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func (s *Server) renderChallenge(w http.ResponseWriter, r *http.Request, req *request, p clearance.Puzzle, ticket, ret string) {
	raw, _ := json.Marshal(p)
	// A data block is not executed, but "</script>" inside it would end it:
	// json.Marshal escapes '<' and '>' as < / >, so it cannot.
	data := challengeData{
		L: req.lang, CSS: s.cssURL, JS: s.appURL, Puzzle: p, PuzzleJSON: template.JS(raw), Ticket: ticket,
		NoJSPath: nojsPath, NoJSURL: template.URL(nojsPath + "?t=" + ticket), AnswerPath: answerPath,
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

func (s *Server) renderTooEarly(w http.ResponseWriter, req *request, ret string) {
	if !clearance.ValidReturnPath(ret) {
		ret = "/"
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", csp)
	h.Set("Content-Language", req.lang.Tag)
	w.WriteHeader(http.StatusForbidden)
	_ = tooEarlyTmpl.Execute(w, struct {
		L      *locale
		CSS    string
		Return string
	}{req.lang, s.cssURL, ret})
}

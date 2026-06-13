package api

import (
	"embed"
	"net/http"
)

// dashboardFS holds the embedded single-page UI. It is a handful of static
// files (no build step, no framework) served from the API listener so the
// whole product — detector and UI — ships as one binary.
//
//go:embed static/index.html static/app.js static/style.css
var dashboardFS embed.FS

// dashboardAsset describes one served file.
type dashboardAsset struct {
	file        string
	contentType string
}

// dashboardAssets is an explicit allowlist: serving named files (not an
// http.FileServer over the FS) removes any path-traversal surface.
var dashboardAssets = map[string]dashboardAsset{
	"GET /{$}":       {"static/index.html", "text/html; charset=utf-8"},
	"GET /app.js":    {"static/app.js", "text/javascript; charset=utf-8"},
	"GET /style.css": {"static/style.css", "text/css; charset=utf-8"},
}

// dashboardCSP locks the UI down: no inline scripts or styles execute (the
// app's JS/CSS are separate same-origin files), and the page may only talk
// back to its own origin — so even if attack-derived data slipped past the
// DOM-text rendering, it could neither run nor exfiltrate.
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// registerDashboard mounts the embedded UI. Each handler re-checks the
// config per request, so a reload that toggles api.dashboard takes effect
// without a restart.
func (s *Server) registerDashboard(mux *http.ServeMux) {
	for pattern, a := range dashboardAssets {
		asset := a
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.store.Get().API.DashboardEnabled() {
				http.NotFound(w, r)
				return
			}
			b, err := dashboardFS.ReadFile(asset.file)
			if err != nil {
				http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
				return
			}
			h := w.Header()
			h.Set("Content-Type", asset.contentType)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Content-Security-Policy", dashboardCSP)
			h.Set("Referrer-Policy", "no-referrer")
			_, _ = w.Write(b)
		})
	}
}

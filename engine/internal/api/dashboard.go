package api

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strings"
)

// dashboardFS holds the embedded single-page UI. It is a handful of static
// files (no build step, no framework) served from the API listener so the
// whole product — detector and UI — ships as one binary.
//
//go:embed static/index.html static/*.js static/*.css static/*.svg static/locales/*.js
var dashboardFS embed.FS

// dashboardAsset describes one served file.
type dashboardAsset struct {
	file        string
	contentType string
}

// dashboardAssets is an explicit allowlist: serving named files (not an
// http.FileServer over the FS) removes any path-traversal surface.
var dashboardAssets = map[string]dashboardAsset{
	"GET /{$}":            {"static/index.html", "text/html; charset=utf-8"},
	"GET /favicon.svg":    {"static/favicon.svg", "image/svg+xml; charset=utf-8"},
	"GET /app.js":         {"static/app.js", "text/javascript; charset=utf-8"},
	"GET /api.js":         {"static/api.js", "text/javascript; charset=utf-8"},
	"GET /components.js":  {"static/components.js", "text/javascript; charset=utf-8"},
	"GET /i18n.js":        {"static/i18n.js", "text/javascript; charset=utf-8"},
	"GET /icons.js":       {"static/icons.js", "text/javascript; charset=utf-8"},
	"GET /views.js":       {"static/views.js", "text/javascript; charset=utf-8"},
	"GET /views2.js":      {"static/views2.js", "text/javascript; charset=utf-8"},
	"GET /style.css":      {"static/style.css", "text/css; charset=utf-8"},
	"GET /components.css": {"static/components.css", "text/css; charset=utf-8"},
	"GET /locales/en.js":  {"static/locales/en.js", "text/javascript; charset=utf-8"},
	"GET /locales/de.js":  {"static/locales/de.js", "text/javascript; charset=utf-8"},
	"GET /locales/ru.js":  {"static/locales/ru.js", "text/javascript; charset=utf-8"},
	"GET /locales/fr.js":  {"static/locales/fr.js", "text/javascript; charset=utf-8"},
	"GET /locales/es.js":  {"static/locales/es.js", "text/javascript; charset=utf-8"},
}

// dashboardCSP locks the UI down: no inline scripts or styles execute (the
// app's JS/CSS are separate same-origin files), and the page may only talk
// back to its own origin — so even if attack-derived data slipped past the
// DOM-text rendering, it could neither run nor exfiltrate.
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// registerDashboard mounts the embedded UI. Each handler re-checks the
// config per request, so a reload that toggles api.dashboard takes effect
// without a restart.
//
// Assets are sent with Cache-Control: no-cache plus a content-hash ETag. The
// embedded bytes are immutable per build, so the ETag is stable while the
// binary runs (cheap 304s) but changes the moment a redeployed binary embeds a
// new console — which forces the browser to drop its cached JS/CSS instead of
// silently running the old UI after an upgrade.
func (s *Server) registerDashboard(mux *http.ServeMux) {
	for pattern, a := range dashboardAssets {
		asset := a
		var etag string
		if b, err := dashboardFS.ReadFile(asset.file); err == nil {
			sum := sha256.Sum256(b)
			etag = `"` + hex.EncodeToString(sum[:16]) + `"`
		}
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if !s.store.Get().API.DashboardEnabled() {
				http.NotFound(w, r)
				return
			}
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Content-Security-Policy", dashboardCSP)
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cache-Control", "no-cache")
			if etag != "" {
				h.Set("ETag", etag)
				if etagMatches(r.Header.Get("If-None-Match"), etag) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			b, err := dashboardFS.ReadFile(asset.file)
			if err != nil {
				http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
				return
			}
			h.Set("Content-Type", asset.contentType)
			_, _ = w.Write(b)
		})
	}
}

// etagMatches reports whether an If-None-Match header lists the given strong
// ETag (or "*"). Browsers echo back exactly what we sent; the weak prefix is
// tolerated for completeness.
func etagMatches(ifNoneMatch, etag string) bool {
	for _, part := range strings.Split(ifNoneMatch, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}

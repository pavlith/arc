package gate

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// SvelteKit's screen-reader route announcer uses a fixed visually hidden style.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"style-src-attr 'unsafe-hashes' 'sha256-S8qMpvofolR8Mpjy4kQvEm7m1q8clzU4dfDH0AmvZjo='; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func (g *Gate) serveUI(w http.ResponseWriter, r *http.Request) bool {
	if g.cfg.UI == nil || r.URL.RawPath != "" || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	var name string
	switch {
	case r.URL.Path == "/":
		name = "index.html"
	case r.URL.Path == "/_app/version.json":
		name = "_app/version.json"
	case strings.HasPrefix(r.URL.Path, "/_app/immutable/"):
		name = strings.TrimPrefix(r.URL.Path, "/")
	case strings.HasPrefix(r.URL.Path, "/assets/"):
		asset := strings.TrimPrefix(r.URL.Path, "/assets/")
		if strings.Contains(asset, "/") {
			return false
		}
		name = "assets/" + asset
	default:
		return false
	}
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return false
	}
	if name != "index.html" && name != "_app/version.json" && path.Ext(name) != ".js" && path.Ext(name) != ".css" {
		return false
	}
	if info, err := fs.Stat(g.cfg.UI, name); err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Security-Policy", uiCSP)
	http.ServeFileFS(w, r, g.cfg.UI, name)
	return true
}

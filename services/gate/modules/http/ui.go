package gate

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

func (g *Gate) serveUI(w http.ResponseWriter, r *http.Request) bool {
	if g.cfg.UI == nil || r.URL.RawPath != "" || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	name := "index.html"
	if r.URL.Path != "/" {
		asset, ok := strings.CutPrefix(r.URL.Path, "/assets/")
		if !ok || !fs.ValidPath(asset) || strings.ContainsAny(asset, `/\`) || path.Ext(asset) != ".js" && path.Ext(asset) != ".css" {
			return false
		}
		name = "assets/" + asset
	}
	if info, err := fs.Stat(g.cfg.UI, name); err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	http.ServeFileFS(w, r, g.cfg.UI, name)
	return true
}

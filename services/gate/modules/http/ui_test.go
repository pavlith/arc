package gate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestServeUIAssets(t *testing.T) {
	const origin = "https://arc.example"
	g, err := New(Config{
		Backend:      closedBackend{},
		PublicOrigin: origin,
		UI: fstest.MapFS{
			"index.html":                        {Data: []byte("<!doctype html><title>Arc</title>")},
			"_app/immutable/entry/start.abc.js": {Data: []byte("export {}")},
			"_app/immutable/assets/app.abc.css": {Data: []byte("body {}")},
			"_app/version.json":                 {Data: []byte(`{"version":"abc"}`)},
			"_app/immutable/internal.json":      {Data: []byte("{}")},
			"assets/legacy.js":                  {Data: []byte("export {}")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	g.routes.current.Store(&table{})

	for _, tc := range []struct {
		method, path, contentType string
		status                    int
	}{
		{http.MethodGet, "/", "text/html", http.StatusOK},
		{http.MethodGet, "/_app/immutable/entry/start.abc.js", "text/javascript", http.StatusOK},
		{http.MethodHead, "/_app/immutable/assets/app.abc.css", "text/css", http.StatusOK},
		{http.MethodGet, "/_app/version.json", "application/json", http.StatusOK},
		{http.MethodGet, "/assets/legacy.js", "text/javascript", http.StatusOK},
		{http.MethodGet, "/_app/immutable/internal.json", "", http.StatusNotFound},
		{http.MethodGet, "/_app/immutable/missing.js", "", http.StatusNotFound},
		{http.MethodPost, "/_app/immutable/entry/start.abc.js", "", http.StatusNotFound},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			g.ServeHTTP(w, httptest.NewRequest(tc.method, origin+tc.path, nil))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if tc.contentType != "" && !strings.HasPrefix(w.Header().Get("Content-Type"), tc.contentType) {
				t.Errorf("unexpected content type %q", w.Header().Get("Content-Type"))
			}
			if tc.path == "/" {
				policy := w.Header().Get("Content-Security-Policy")
				if !strings.Contains(policy, "script-src 'self';") ||
					!strings.Contains(policy, "style-src-attr 'unsafe-hashes' 'sha256-") ||
					strings.Contains(policy, "'unsafe-inline'") {
					t.Errorf("unexpected CSP %q", policy)
				}
			}
		})
	}
}

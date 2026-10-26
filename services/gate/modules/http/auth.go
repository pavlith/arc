package gate

import (
	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
	"net/http"
	"time"
)

func (g *Gate) auth(w http.ResponseWriter, r *http.Request, id, client string) {
	endpoint := r.URL.Path
	ctx := r.Context()
	if endpoint == "/api/v1/arc/auth/login" && r.Method == "POST" {
		if !g.origins[r.Header.Get("Origin")] {
			writeError(w, id, fault(rpc.CodePermissionDenied))
			return
		}
		if !g.rate(client, "login", g.cfg.LoginsPerMinute) {
			writeError(w, id, fault(rpc.CodeRateLimited))
			return
		}
		obj, e := readObject(r)
		if e != nil {
			g.inputError(w, id, e)
			return
		}
		raw, _ := json.Marshal(obj)
		var q identity.LoginRequest
		if contract.Strict(raw, &q) != nil {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		result, e := g.cfg.Backend.Login(ctx, q)
		if e != nil {
			writeError(w, id, e)
			return
		}
		g.cookies(w, result, true)
		writeJSON(w, 200, map[string]any{"session": result.Session, "csrf": result.CSRF, "access_token": result.AccessToken})
		return
	}
	if endpoint == "/api/v1/arc/auth/session" && r.Method == "GET" {
		a, e := g.external(r, false)
		if e != nil {
			writeError(w, id, e)
			return
		}
		s, e := g.cfg.Backend.Authenticate(ctx, a)
		if e != nil {
			writeError(w, id, e)
			return
		}
		writeJSON(w, 200, s)
		return
	}
	if (endpoint == "/api/v1/arc/auth/refresh" || endpoint == "/api/v1/arc/auth/logout") && r.Method == "POST" {
		obj, e := readObject(r)
		if e != nil {
			g.inputError(w, id, e)
			return
		}
		if len(obj) != 0 {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		a, e := g.external(r, true)
		if e != nil {
			writeError(w, id, e)
			return
		}
		if _, e = g.cfg.Backend.Authenticate(ctx, a); e != nil {
			writeError(w, id, e)
			return
		}
		if endpoint == "/api/v1/arc/auth/logout" {
			if e = g.cfg.Backend.Logout(ctx, identity.SessionRequest{Session: a.Session, AccessToken: a.AccessToken}); e != nil {
				writeError(w, id, e)
				return
			}
			for _, name := range []string{"__Host-arc_session", csrfCookie, refreshCookie} {
				http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: name != csrfCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
			}
			w.WriteHeader(204)
			return
		}
		refresh, e := r.Cookie(refreshCookie)
		if e != nil || a.AccessToken != "" {
			writeError(w, id, fault(rpc.CodeUnauthenticated))
			return
		}
		res, e := g.cfg.Backend.Refresh(ctx, identity.RefreshRequest{Session: a.Session, Token: refresh.Value})
		if e != nil {
			writeError(w, id, e)
			return
		}
		g.cookies(w, res, false)
		writeJSON(w, 200, map[string]any{"session": res.Session, "access_token": res.AccessToken})
		return
	}
	writeError(w, id, fault(rpc.CodeNotFound))
}
func (g *Gate) cookies(w http.ResponseWriter, r identity.LoginResult, initial bool) {
	if initial {
		http.SetCookie(w, identity.SessionCookie(r.Secret, r.Session.ExpiresAt))
		http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: r.CSRF, Path: "/", Secure: true, SameSite: http.SameSiteLaxMode, Expires: r.Session.ExpiresAt})
	}
	http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: r.Refresh, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: r.Session.ExpiresAt})
}

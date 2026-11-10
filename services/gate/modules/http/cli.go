package gate

import (
	"encoding/json"
	"net/http"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
)

func (g *Gate) cli(w http.ResponseWriter, r *http.Request, id, client string) {
	if r.Method != http.MethodPost {
		writeError(w, id, fault(rpc.CodeNotFound))
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" {
		writeError(w, id, fault(rpc.CodePermissionDenied))
		return
	}
	ctx := r.Context()
	if r.URL.Path == "/api/v1/arc/cli/logout" {
		a, err := g.external(r, true)
		if err != nil {
			writeError(w, id, err)
			return
		}
		if err := g.cfg.Backend.Logout(ctx, identity.SessionRequest{AccessToken: a.AccessToken}); err != nil {
			writeError(w, id, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path != "/api/v1/arc/cli/token" && r.URL.Path != "/api/v1/arc/cli/refresh" {
		writeError(w, id, fault(rpc.CodeNotFound))
		return
	}
	if !g.rate(client, "cli-auth", g.cfg.LoginsPerMinute) {
		writeError(w, id, fault(rpc.CodeRateLimited))
		return
	}
	obj, err := readObject(r)
	if err != nil {
		g.inputError(w, id, err)
		return
	}
	raw, _ := json.Marshal(obj)
	var res identity.LoginResult
	if r.URL.Path == "/api/v1/arc/cli/token" {
		var q identity.LoginRequest
		if contract.Strict(raw, &q) != nil || q.Channel != "" {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		q.Channel = "cli"
		res, err = g.cfg.Backend.Login(ctx, q)
	} else {
		var q struct {
			RefreshToken string `json:"refresh_token"`
		}
		if contract.Strict(raw, &q) != nil || q.RefreshToken == "" {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		res, err = g.cfg.Backend.Refresh(ctx, identity.RefreshRequest{Token: q.RefreshToken, Channel: "cli"})
	}
	if err != nil {
		writeError(w, id, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session": res.Session, "access_token": res.AccessToken,
		"refresh_token": res.Refresh, "token_type": "Bearer",
	})
}

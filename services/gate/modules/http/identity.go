package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
)

type identityRoute struct {
	read  bool
	query []string
}

// The reserved Identity namespace maps only these methods to private RPC.
// Core checks the operator-signed bootstrap approval for the exact operation.
var identityRoutes = map[string]identityRoute{
	"profile":               {read: true},
	"workspaces/list":       {read: true, query: []string{"after"}},
	"workspaces/create":     {},
	"workspaces/archive":    {},
	"workspaces/get":        {read: true, query: []string{"workspace_id"}},
	"workspaces/update":     {},
	"workspaces/leave":      {},
	"users/provision":       {},
	"invitations/create":    {},
	"invitations/revoke":    {},
	"invitations/accept":    {},
	"members/list":          {read: true, query: []string{"workspace_id", "after"}},
	"members/set":           {},
	"members/remove":        {},
	"groups/list":           {read: true, query: []string{"workspace_id", "after"}},
	"task_roots/list":       {read: true, query: []string{"workspace_id", "after"}},
	"groups/create":         {},
	"groups/update":         {},
	"groups/delete":         {},
	"groups/members/list":   {read: true, query: []string{"workspace_id", "group_id", "after"}},
	"groups/members/add":    {},
	"groups/members/remove": {},
}

type productIdentityBackend interface {
	ProductIdentity(context.Context, string, identity.ProductRequest[json.RawMessage], string) (json.RawMessage, error)
}

func (r *Remote) ProductIdentity(ctx context.Context, operation string, req identity.ProductRequest[json.RawMessage], idem string) (json.RawMessage, error) {
	client := r.Client
	client.IdempotencyKey = idem
	return identity.Call[identity.ProductRequest[json.RawMessage], json.RawMessage](ctx, client, operation, req)
}

func (g *Gate) productIdentity(w http.ResponseWriter, r *http.Request, id string) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/arc/identity/")
	route, ok := identityRoutes[name]
	if !ok || r.URL.RawPath != "" || route.read && r.Method != http.MethodGet || !route.read && r.Method != http.MethodPost {
		writeError(w, id, fault(rpc.CodeNotFound))
		return
	}
	auth, err := g.external(r, !route.read)
	if err != nil {
		writeError(w, id, err)
		return
	}
	if auth.Session.Secret == "" {
		writeError(w, id, fault(rpc.CodeUnauthenticated))
		return
	}
	backend, ok := g.cfg.Backend.(productIdentityBackend)
	if !ok {
		writeError(w, id, fault(rpc.CodeUnavailable))
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, id, fault(rpc.CodeValidation))
		return
	}
	input := map[string]any{}
	for field, values := range query {
		if !slices.Contains(route.query, field) || len(values) != 1 || len(values[0]) > 128 {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		input[field] = values[0]
	}
	idem := ""
	if !route.read {
		idem = r.Header.Get("Idempotency-Key")
		if !requestIDPattern.MatchString(idem) {
			writeError(w, id, fault(rpc.CodeValidation))
			return
		}
		input, err = readObject(r)
		if err != nil {
			g.inputError(w, id, err)
			return
		}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		writeError(w, id, fault(rpc.CodeValidation))
		return
	}
	op := "identity.v1.product." + strings.ReplaceAll(name, "/", ".")
	data, err := backend.ProductIdentity(r.Context(), op, identity.ProductRequest[json.RawMessage]{Session: auth.Session, Input: raw}, idem)
	if err != nil {
		writeError(w, id, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}

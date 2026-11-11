// Package resources adapts authorized cross-domain reads without owning content or SQL.
package resources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/nats-io/nuid"
	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

type Resolver struct{ Identity identity.Client }

func (s Resolver) Lookup(ctx context.Context, ref resource.Ref) (resource.Summary, error) {
	var empty resource.Summary
	cl, verified := rpc.VerifiedClaims(ctx)
	incoming, ok := rpc.InvocationToken(ctx)
	if !verified || !ok || cl.SessionID == "" {
		return empty, security.ErrUnauthenticated
	}
	if !ref.Valid() || ref.WorkspaceID != cl.WorkspaceID {
		return empty, security.ErrDenied
	}
	meta, _ := rpc.Metadata(ctx)
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
	audience, operation, _, field := ref.Target()
	token, err := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, s.Identity, "identity.v1.invocations.exchange_service", identity.ServiceExchange{IncomingToken: incoming, IncomingOperation: cl.Operation, Target: identity.Target{Audience: audience, Operation: operation, WorkspaceID: cl.WorkspaceID}})
	if err != nil {
		return empty, err
	}
	parts := strings.Split(token.Token, ".")
	if len(parts) != 3 {
		return empty, security.ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return empty, security.ErrUnauthenticated
	}
	var target security.Claims
	if json.Unmarshal(raw, &target) != nil || target.JTI == "" {
		return empty, security.ErrUnauthenticated
	}
	outgoing := rpc.WithCredentials(ctx, rpc.Credentials{Token: token.Token, Proof: func(subject string, body []byte) (security.Proof, error) {
		return security.SignProof(s.Identity.PrivateKey, subject, body, target.JTI, security.Proof{Kid: s.Identity.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: nuid.Next()})
	}})
	service := strings.Split(audience, "/")[0]
	subject := "rpc." + service + ".v1." + strings.TrimPrefix(operation, service+".")
	q := map[string]string{"workspace_id": ref.WorkspaceID, "acl_root_id": ref.RootID, field: ref.ID}
	rawResult, err := rpc.Call[map[string]string, json.RawMessage](outgoing, s.Identity.RPC, operation, subject, q)
	var result struct {
		ID          string `json:"id"`
		WorkspaceID string `json:"workspace_id"`
		RootID      string `json:"acl_root_id"`
		Title       string `json:"title"`
		Filename    string `json:"filename"`
		Revision    int64  `json:"revision"`
	}
	if err == nil && json.Unmarshal(rawResult, &result) != nil {
		return empty, security.ErrUnavailable
	}

	if err != nil {
		return empty, err
	}
	if result.ID != ref.ID || result.WorkspaceID != ref.WorkspaceID || result.RootID != ref.RootID || result.Revision < 1 {
		return empty, security.ErrUnavailable
	}
	title := result.Title
	if ref.Kind == "file" {
		title = result.Filename
	}
	if len(title) > 1200 {
		return empty, security.ErrUnavailable
	}
	return resource.Summary{Ref: ref, Title: title, Revision: result.Revision}, nil
}

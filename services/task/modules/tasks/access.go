package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"strings"
	"time"
)

// InvocationContext exchanges only the verified incoming actor and current workspace.
func InvocationContext(ctx context.Context, client identity.Client, target identity.Target) (context.Context, error) {
	q := identity.ServiceExchange{Target: target}
	if token, ok := rpc.InvocationToken(ctx); ok {
		cl, _ := rpc.VerifiedClaims(ctx)
		q.IncomingToken = token
		q.IncomingOperation = cl.Operation
		q.Target.WorkspaceID = cl.WorkspaceID
	}
	v, e := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, client, "identity.v1.invocations.exchange_service", q)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(v.Token, ".")
	if len(parts) != 3 {
		return nil, security.ErrUnauthenticated
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return nil, e
	}
	var cl security.Claims
	if json.Unmarshal(b, &cl) != nil || cl.JTI == "" {
		return nil, security.ErrUnauthenticated
	}
	meta, _ := rpc.Metadata(ctx)
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
	return rpc.WithCredentials(ctx, rpc.Credentials{Token: v.Token, IdempotencyKey: client.IdempotencyKey, Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(client.PrivateKey, subject, raw, cl.JTI, security.Proof{Kid: client.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: NewID()})
	}}), nil
}
func OnlineCheck(client identity.Client) func(context.Context, string, string) error {
	return func(ctx context.Context, root, action string) error {
		ctx, e := InvocationContext(ctx, client, identity.Target{Audience: "access/v1", Operation: "access.v1.check"})
		if e != nil {
			return e
		}
		d, e := (&access.Client{RPC: client.RPC}).Check(ctx, access.CheckRequest{ResourceID: root, Action: action})
		if e != nil {
			return e
		}
		if !d.Allowed {
			return security.ErrDenied
		}
		return nil
	}
}

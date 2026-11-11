package resources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/nats-io/nuid"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
)

func Invocation(ctx context.Context, client identity.Client, audience, operation string) (context.Context, error) {
	cl, verified := rpc.VerifiedClaims(ctx)
	incoming, ok := rpc.InvocationToken(ctx)
	if !verified || !ok || cl.SessionID == "" {
		return nil, security.ErrUnauthenticated
	}
	v, err := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, client, "identity.v1.invocations.exchange_service", identity.ServiceExchange{IncomingToken: incoming, IncomingOperation: cl.Operation, Target: identity.Target{Audience: audience, Operation: operation, WorkspaceID: cl.WorkspaceID}})
	if err != nil {
		return nil, err
	}
	parts := strings.Split(v.Token, ".")
	if len(parts) != 3 {
		return nil, security.ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var target security.Claims
	if json.Unmarshal(raw, &target) != nil || target.JTI == "" {
		return nil, security.ErrUnauthenticated
	}
	meta, _ := rpc.Metadata(ctx)
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
	return rpc.WithCredentials(ctx, rpc.Credentials{Token: v.Token, IdempotencyKey: client.IdempotencyKey, Proof: func(subject string, body []byte) (security.Proof, error) {
		return security.SignProof(client.PrivateKey, subject, body, target.JTI, security.Proof{Kid: client.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: nuid.Next()})
	}}), nil
}
func OnlineCheck(client identity.Client) func(context.Context, string, string) error {
	return func(ctx context.Context, root, action string) error {
		next, err := Invocation(ctx, client, "access/v1", "access.v1.check")
		if err != nil {
			return err
		}
		result, err := (&access.Client{RPC: client.RPC}).Check(next, access.CheckRequest{ResourceID: root, Action: action})
		if err != nil {
			return err
		}
		if !result.Allowed {
			return security.ErrDenied
		}
		return nil
	}
}

package folders

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
)

// OnlineCheck obtains an exact downstream user token, then calls live
// Access.Check without reusing or caching a previous ACL decision.
func OnlineCheck(client identity.Client) func(context.Context, string, string) error {
	return func(ctx context.Context, root, action string) error {
		q := identity.ServiceExchange{Target: identity.Target{Audience: "access/v1", Operation: "access.v1.check"}}
		if incoming, ok := rpc.InvocationToken(ctx); ok {
			cl, _ := rpc.VerifiedClaims(ctx)
			q.IncomingToken = incoming
			q.IncomingOperation = cl.Operation
			q.Target.WorkspaceID = cl.WorkspaceID
		} else {
			return security.ErrUnauthenticated
		}
		result, err := identity.Call[identity.ServiceExchange, identity.TokenResult](
			ctx, client, "identity.v1.invocations.exchange_service", q)
		if err != nil {
			return err
		}
		parts := strings.Split(result.Token, ".")
		if len(parts) != 3 {
			return security.ErrUnauthenticated
		}
		data, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return security.ErrUnauthenticated
		}
		var claims security.Claims
		if json.Unmarshal(data, &claims) != nil || claims.JTI == "" {
			return security.ErrUnauthenticated
		}
		meta, _ := rpc.Metadata(ctx)
		outgoing := rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
		outgoing = rpc.WithCredentials(outgoing, rpc.Credentials{
			Token: result.Token, Proof: func(subject string, raw []byte) (security.Proof, error) {
				return security.SignProof(client.PrivateKey, subject, raw, claims.JTI, security.Proof{
					Kid: client.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: NewID(),
				})
			},
		})
		decision, err := (&access.Client{RPC: client.RPC}).Check(
			outgoing, access.CheckRequest{ResourceID: root, Action: action})
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return security.ErrDenied
		}
		return nil
	}
}

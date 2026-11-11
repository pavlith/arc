package folders

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	v1 "github.com/pavlith/arc/services/files/api/v1"
	"gorm.io/gorm"
)

// invocationContext exchanges only the verified incoming actor and current workspace.
func invocationContext(ctx context.Context, client identity.Client, target identity.Target) (context.Context, error) {
	token, ok := rpc.InvocationToken(ctx)
	if !ok {
		return nil, security.ErrUnauthenticated
	}
	q := identity.ServiceExchange{Target: target}
	cl, verified := rpc.VerifiedClaims(ctx)
	if !verified {
		return nil, security.ErrUnauthenticated
	}
	q.IncomingToken = token
	q.IncomingOperation = cl.Operation
	q.Target.WorkspaceID = cl.WorkspaceID
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
	var outgoing security.Claims
	if json.Unmarshal(b, &outgoing) != nil || outgoing.JTI == "" {
		return nil, security.ErrUnauthenticated
	}
	meta, _ := rpc.Metadata(ctx)
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
	return rpc.WithCredentials(ctx, rpc.Credentials{Token: v.Token, IdempotencyKey: client.IdempotencyKey, Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(client.PrivateKey, subject, raw, outgoing.JTI, security.Proof{Kid: client.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: NewID()})
	}}), nil
}
func (s *Service) grants(ctx context.Context, _ *gorm.DB, q v1.GrantRequest) (v1.GrantResult, error) {
	op := "grants.add"
	if q.GrantID != "" {
		op = "grants.revoke"
		if q.Action != "" || q.PrincipalID != "" {
			return v1.GrantResult{}, invalid()
		}
	} else if q.PrincipalID == "" || q.Action == "" {
		return v1.GrantResult{}, invalid()
	}
	client := s.Identity
	meta, _ := rpc.Metadata(ctx)
	cl, _ := rpc.VerifiedClaims(ctx)
	sum := sha256.Sum256([]byte(cl.Subject + ":" + cl.Operation + ":" + meta.IdempotencyKey))
	client.IdempotencyKey = "files-grants:" + hex.EncodeToString(sum[:])
	next, err := invocationContext(ctx, client, identity.Target{Audience: "access/v1", Operation: "access.v1." + op})
	if err != nil {
		return v1.GrantResult{}, err
	}
	ac := &access.Client{RPC: client.RPC}
	var result access.MutationResult
	if q.GrantID != "" {
		result, err = ac.RevokeGrant(next, access.RevokeRequest{GrantID: q.GrantID, ResourceID: q.RootID})
	} else {
		result, err = ac.AddGrant(next, access.GrantRequest{ResourceID: q.RootID, PrincipalKind: "user", PrincipalID: q.PrincipalID, Action: q.Action})
	}
	return v1.GrantResult{ResourceID: result.ResourceID, GrantID: result.GrantID, State: result.State, Revision: result.Revision}, err
}

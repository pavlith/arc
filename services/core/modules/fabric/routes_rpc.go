package fabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

const RoutesSubject = "ctl.arc.fabric.routes"
const RoutesChangedSubject = "evt.arc.fabric.routes.changed"

type RouteBundle struct {
	RequestID string         `json:"request_id"`
	ExpiresAt time.Time      `json:"expires_at"`
	Snapshot  SignedSnapshot `json:"snapshot"`
	Keys      security.JWKS  `json:"keys"`
	Signature []byte         `json:"signature"`
}

func bundleMessage(b RouteBundle) []byte {
	b.Signature = nil
	raw, _ := json.Marshal(b)
	out, _ := json.Marshal([]json.RawMessage{json.RawMessage(`"arc.route_bundle.v1"`), raw})
	out, _ = security.CanonicalJSON(out)
	return out
}
func VerifyBundle(root ed25519.PublicKey, b RouteBundle, requestID string) error {
	if len(root) != 32 || b.RequestID != requestID || !b.ExpiresAt.After(time.Now()) || b.ExpiresAt.After(time.Now().Add(30*time.Second)) || !ed25519.Verify(root, bundleMessage(b), b.Signature) {
		return security.ErrUnauthenticated
	}
	return nil
}

// BindRoutes exposes an exact authenticated control operation, never public HTTP.
func (c *Core) BindRoutes(s *sdk.Service) error {
	if e := c.ready(); e != nil {
		return e
	}
	if s == nil || s.Connection() == nil || c.Identity.Policy == nil || c.SnapshotKid == "" || len(c.SnapshotKey) != 64 || len(c.RouteTrustKey) != 64 {
		return security.ErrUnavailable
	}
	c.RoutesChanged = func() { _ = s.Connection().Publish(RoutesChangedSubject, nil) }
	return rpc.Handle(s, rpc.Operation{ID: "fabric.v1.routes", Endpoint: "fabric_routes", Subject: RoutesSubject, QueueGroup: "q.fabric.v1", Timeout: 5 * time.Second, Protected: true, Authorize: rpc.AssertionAuthorizerFor(c.Identity.Verifier(), RoutesSubject, func(ctx context.Context, caller, op string) error {
		if c.Identity.Policy == nil {
			return security.ErrUnavailable
		}
		return c.Identity.Policy.Authorize(ctx, identity.Authorization{Caller: caller, Audience: "fabric/v1", Operation: op})
	})}, func(ctx context.Context, _ identity.Empty) (RouteBundle, error) {
		snapshot, e := c.Routes(ctx)
		if e != nil {
			return RouteBundle{}, rpc.SecurityError(e)
		}
		keys, e := c.Identity.JWKS(ctx)
		if e != nil {
			return RouteBundle{}, rpc.SecurityError(e)
		}
		meta, ok := rpc.Metadata(ctx)
		if !ok {
			return RouteBundle{}, rpc.SecurityError(security.ErrUnavailable)
		}
		b := RouteBundle{RequestID: meta.RequestID, ExpiresAt: time.Now().UTC().Add(10 * time.Second), Snapshot: snapshot, Keys: keys}
		b.Signature = ed25519.Sign(c.RouteTrustKey, bundleMessage(b))
		return b, nil
	})
}

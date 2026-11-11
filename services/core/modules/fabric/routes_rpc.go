package fabric

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
)

const RoutesSubject = "ctl.arc.fabric.routes"
const RoutesChangedSubject = "evt.arc.fabric.routes.changed"

type RouteBundle struct {
	CompressedSnapshot []byte         `json:"compressed_snapshot,omitempty"`
	RequestID          string         `json:"request_id"`
	ExpiresAt          time.Time      `json:"expires_at"`
	Snapshot           SignedSnapshot `json:"snapshot"`
	Keys               security.JWKS  `json:"keys"`
	Signature          []byte         `json:"signature"`
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
		if e := compressBundle(&b); e != nil {
			return RouteBundle{}, rpc.SecurityError(e)
		}
		b.Signature = ed25519.Sign(c.RouteTrustKey, bundleMessage(b))
		return b, nil
	})
}

const maxExpandedSnapshot = 1 << 20
const maxCompressedSnapshot = 128 << 10

func compressBundle(b *RouteBundle) error {
	raw, err := json.Marshal(b.Snapshot)
	if err != nil || len(raw) > maxExpandedSnapshot {
		return security.ErrUnavailable
	}
	if len(raw) <= maxCompressedSnapshot {
		return nil
	}
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err = w.Write(raw); err != nil {
		return security.ErrUnavailable
	}
	if err = w.Close(); err != nil || out.Len() > maxCompressedSnapshot {
		return security.ErrUnavailable
	}
	b.CompressedSnapshot = out.Bytes()
	b.Snapshot = SignedSnapshot{}
	return nil
}

// BundleSnapshot is called only after VerifyBundle authenticates the wire bytes.
// The snapshot's own Identity signature and route digest are verified by Gate.
func BundleSnapshot(b RouteBundle) (SignedSnapshot, error) {
	if len(b.CompressedSnapshot) == 0 {
		if len(b.Snapshot.Payload) > maxExpandedSnapshot {
			return SignedSnapshot{}, security.ErrDenied
		}
		return b.Snapshot, nil
	}
	if len(b.CompressedSnapshot) > maxCompressedSnapshot || (len(b.Snapshot.Payload) != 0 && !bytes.Equal(bytes.TrimSpace(b.Snapshot.Payload), []byte("null"))) || len(b.Snapshot.Signature) != 0 {
		return SignedSnapshot{}, security.ErrDenied
	}
	r, err := gzip.NewReader(bytes.NewReader(b.CompressedSnapshot))
	if err != nil {
		return SignedSnapshot{}, security.ErrDenied
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, maxExpandedSnapshot+1))
	if err != nil || len(raw) > maxExpandedSnapshot {
		return SignedSnapshot{}, security.ErrDenied
	}
	var out SignedSnapshot
	if contract.Strict(raw, &out) != nil || len(out.Payload) == 0 || len(out.Signature) != ed25519.SignatureSize {
		return SignedSnapshot{}, security.ErrDenied
	}
	return out, nil
}

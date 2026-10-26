package fabric

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
)

type Route struct {
	Method        string             `json:"method"`
	Path          string             `json:"path"`
	Service       string             `json:"service"`
	Operation     string             `json:"operation"`
	Subject       string             `json:"subject"`
	Digest        string             `json:"digest"`
	SuccessStatus int                `json:"success_status"`
	APIMajor      int                `json:"api_major"`
	Bindings      []contract.Binding `json:"bindings,omitempty"`
}
type RouteSnapshot struct {
	Kid       string                       `json:"kid"`
	Digest    string                       `json:"digest"`
	Artifacts map[string]contract.Artifact `json:"artifacts"`
	Revision  int64                        `json:"revision"`
	IssuedAt  time.Time                    `json:"issued_at"`
	Routes    []Route                      `json:"routes"`
}
type SignedSnapshot struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func (c *Core) Routes(ctx context.Context) (SignedSnapshot, error) {
	return c.routesGORM(ctx)
}

func ContentDigest(s RouteSnapshot) (string, error) {
	raw, e := json.Marshal(struct {
		Routes    []Route                      `json:"routes"`
		Artifacts map[string]contract.Artifact `json:"artifacts"`
	}{s.Routes, s.Artifacts})
	if e != nil {
		return "", e
	}
	raw, e = security.CanonicalJSON(raw)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func snapshotMessage(raw []byte) []byte {
	out, _ := json.Marshal([]json.RawMessage{json.RawMessage(`"arc.route_snapshot.v1"`), raw})
	out, _ = security.CanonicalJSON(out)
	return out
}
func SignSnapshot(s RouteSnapshot, kid string, key ed25519.PrivateKey) (SignedSnapshot, error) {
	if kid == "" || len(key) != 64 {
		return SignedSnapshot{}, security.ErrUnavailable
	}
	s.Kid = kid
	var e error
	s.Digest, e = ContentDigest(s)
	if e != nil {
		return SignedSnapshot{}, e
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return SignedSnapshot{}, e
	}
	raw, e = security.CanonicalJSON(raw)
	if e != nil {
		return SignedSnapshot{}, e
	}
	return SignedSnapshot{raw, ed25519.Sign(key, snapshotMessage(raw))}, nil
}

// VerifySnapshot retains the pinned-key API; Gate additionally checks live JWKS
// and same-revision content through VerifySnapshotJWKS and its atomic table.
func VerifySnapshot(key ed25519.PublicKey, s SignedSnapshot, minRevision int64) (RouteSnapshot, error) {
	var snap RouteSnapshot
	raw, e := security.CanonicalJSON(s.Payload)
	if len(key) != 32 || e != nil || !ed25519.Verify(key, snapshotMessage(raw), s.Signature) {
		return snap, security.ErrUnauthenticated
	}
	if contract.Strict(raw, &snap) != nil || snap.Kid == "" || snap.Revision < minRevision {
		return RouteSnapshot{}, security.ErrDenied
	}
	digest, e := ContentDigest(snap)
	if e != nil || digest != snap.Digest {
		return RouteSnapshot{}, security.ErrDenied
	}
	return snap, nil
}
func VerifySnapshotJWKS(keys security.JWKS, s SignedSnapshot, minRevision int64) (RouteSnapshot, error) {
	var untrusted struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(s.Payload, &untrusted) != nil {
		return RouteSnapshot{}, security.ErrUnauthenticated
	}
	key, e := keys.PublicKey(untrusted.Kid)
	if e != nil {
		return RouteSnapshot{}, e
	}
	return VerifySnapshot(key, s, minRevision)
}

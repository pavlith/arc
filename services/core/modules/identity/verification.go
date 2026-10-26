package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
)

// VerifyRequest carries the original proof-bound envelope, never identity headers.
type VerifyRequest struct {
	Subject string          `json:"subject"`
	Request json.RawMessage `json:"request"`
}
type Verification struct {
	Claims    security.Claims `json:"claims"`
	Hash      []byte          `json:"hash"`
	Subject   string          `json:"subject"`
	ExpiresAt time.Time       `json:"expires_at"`
	Signature []byte          `json:"signature"`
}

func verificationBytes(v Verification) []byte { v.Signature = nil; b, _ := json.Marshal(v); return b }
func (c *Core) verifyRequest(ctx context.Context, q VerifyRequest) (Verification, error) {
	if len(c.PrivateKey) != 64 {
		return Verification{}, ErrUnavailable
	}
	caller, ok := rpc.VerifiedClaims(ctx)
	if !ok {
		return Verification{}, ErrUnauthenticated
	}
	var definition string
	if e := c.DB.QueryRowContext(ctx, `SELECT service_definition FROM identity.service_accounts WHERE id::text=$1 AND disabled_at IS NULL`, caller.Caller).Scan(&definition); e != nil {
		return Verification{}, keyError(e)
	}
	verified, e := rpc.InvocationAuthorizer(c.Verifier(), definition+"/v1")(ctx, q.Subject, q.Request)
	if e != nil {
		return Verification{}, e
	}
	cl, _ := rpc.VerifiedClaims(verified)
	// Bind the exact transport subject to the operation and API major.
	if !strings.HasPrefix(cl.Operation, definition+".") || q.Subject != "rpc."+definition+".v1."+strings.TrimPrefix(cl.Operation, definition+".") {
		return Verification{}, ErrDenied
	}
	h := sha256.Sum256(q.Request)
	v := Verification{Claims: cl, Hash: h[:], Subject: q.Subject, ExpiresAt: c.now().Add(5 * time.Second)}
	v.Signature = ed25519.Sign(c.PrivateKey, verificationBytes(v))
	return v, nil
}

// RemoteAuthorizer verifies Core's signed decision, bound to the complete request.
// Core checks live keys/session/membership and consumes the original request nonce.
func RemoteAuthorizer(client Client, core ed25519.PublicKey, audience string) func(context.Context, string, []byte) (context.Context, error) {
	return rpc.RemoteInvocationAuthorizer(func(ctx context.Context, subject string, raw []byte) (security.Claims, error) {
		v, e := Call[VerifyRequest, Verification](ctx, client, "identity.v1.invocations.verify", VerifyRequest{subject, raw})
		if e != nil {
			return security.Claims{}, e
		}
		h := sha256.Sum256(raw)
		if len(core) != 32 || !ed25519.Verify(core, verificationBytes(v), v.Signature) || string(h[:]) != string(v.Hash) || v.Subject != subject || v.Claims.Audience != audience || !v.ExpiresAt.After(time.Now()) || v.ExpiresAt.After(time.Now().Add(6*time.Second)) {
			return security.Claims{}, ErrUnauthenticated
		}
		return v.Claims, nil
	})
}

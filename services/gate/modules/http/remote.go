// Package gate implements the public ingress, with no database dependency.
package gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"time"
)

type Backend interface {
	Fetch(context.Context) (fabric.SignedSnapshot, security.JWKS, error)
	Login(context.Context, identity.LoginRequest) (identity.LoginResult, error)
	Authenticate(context.Context, identity.Authentication) (identity.Session, error)
	Refresh(context.Context, identity.RefreshRequest) (identity.LoginResult, error)
	Logout(context.Context, identity.SessionRequest) error
	Exchange(context.Context, identity.UserExchange) (identity.TokenResult, error)
	Invoke(context.Context, *contract.Compiled, contract.Operation, json.RawMessage, string, string) (json.RawMessage, error)
}
type Remote struct {
	Client    identity.Client
	TrustRoot ed25519.PublicKey
}

func NewID() string { return rand.Text() }
func (r *Remote) Fetch(ctx context.Context) (fabric.SignedSnapshot, security.JWKS, error) {
	credentials, e := r.Client.Credentials(fabric.RoutesSubject)
	if e != nil {
		return fabric.SignedSnapshot{}, security.JWKS{}, e
	}
	id := NewID()
	ctx = rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: id})
	ctx = rpc.WithCredentials(ctx, credentials)
	b, e := rpc.Call[identity.Empty, fabric.RouteBundle](ctx, r.Client.RPC, "fabric.v1.routes", fabric.RoutesSubject, identity.Empty{})
	if e != nil {
		return fabric.SignedSnapshot{}, security.JWKS{}, e
	}
	if e = fabric.VerifyBundle(r.TrustRoot, b, id); e != nil {
		return fabric.SignedSnapshot{}, security.JWKS{}, rpc.SecurityError(e)
	}
	return b.Snapshot, b.Keys, nil
}
func (r *Remote) Login(ctx context.Context, q identity.LoginRequest) (identity.LoginResult, error) {
	return identity.Call[identity.LoginRequest, identity.LoginResult](ctx, r.Client, "identity.v1.sessions.login", q)
}
func (r *Remote) Authenticate(ctx context.Context, q identity.Authentication) (identity.Session, error) {
	return identity.Call[identity.Authentication, identity.Session](ctx, r.Client, "identity.v1.sessions.validate", q)
}
func (r *Remote) Refresh(ctx context.Context, q identity.RefreshRequest) (identity.LoginResult, error) {
	return identity.Call[identity.RefreshRequest, identity.LoginResult](ctx, r.Client, "identity.v1.sessions.refresh", q)
}
func (r *Remote) Logout(ctx context.Context, q identity.SessionRequest) error {
	_, e := identity.Call[identity.SessionRequest, identity.Empty](ctx, r.Client, "identity.v1.sessions.logout", q)
	return e
}
func (r *Remote) Exchange(ctx context.Context, q identity.UserExchange) (identity.TokenResult, error) {
	return identity.Call[identity.UserExchange, identity.TokenResult](ctx, r.Client, "identity.v1.invocations.exchange_user", q)
}
func (r *Remote) Invoke(ctx context.Context, m *contract.Compiled, o contract.Operation, payload json.RawMessage, token, idem string) (json.RawMessage, error) {
	parts, e := tokenJTI(token)
	if e != nil {
		return nil, rpc.SecurityError(e)
	}
	ctx = rpc.WithCredentials(ctx, rpc.Credentials{Token: token, IdempotencyKey: idem, Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(r.Client.PrivateKey, subject, raw, parts, security.Proof{Kid: r.Client.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: NewID()})
	}})
	return rpc.CallValidated[json.RawMessage, json.RawMessage](ctx, r.Client.RPC, o.ID, o.Subject, payload, func(b []byte) error { return m.Validate(o.RequestSchema, b) }, func(b []byte) error { return m.Validate(o.ResponseSchema, b) })
}
func tokenJTI(token string) (string, error) {
	var parts []string
	start := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return "", security.ErrUnauthenticated
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return "", security.ErrUnauthenticated
	}
	var cl security.Claims
	if json.Unmarshal(b, &cl) != nil || cl.JTI == "" {
		return "", security.ErrUnauthenticated
	}
	return cl.JTI, nil
}

// Notifications are hints only: every update is fetched and cryptographically checked.
func SubscribeChanges(nc *nats.Conn) (<-chan struct{}, func(), error) {
	ch := make(chan struct{}, 1)
	s, e := nc.Subscribe(fabric.RoutesChangedSubject, func(*nats.Msg) {
		select {
		case ch <- struct{}{}:
		default:
		}
	})
	if e != nil {
		return nil, nil, e
	}
	if e = nc.FlushTimeout(3 * time.Second); e != nil {
		_ = s.Unsubscribe()
		return nil, nil, e
	}
	return ch, func() { _ = s.Unsubscribe() }, nil
}

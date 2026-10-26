package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type RefreshRequest struct {
	Token string `json:"token"`
}
type SessionRequest struct {
	Session UserSession `json:"session"`
}
type RecoverRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}
type RevokeSessionRequest struct {
	Session UserSession `json:"session"`
	ID      string      `json:"id"`
}
type IntrospectRequest struct {
	Secret string `json:"secret"`
}
type DelegationRequest struct {
	Session    UserSession `json:"session"`
	Delegation Delegation  `json:"delegation"`
}
type DelegationIDRequest struct {
	Session UserSession `json:"session"`
	ID      string      `json:"id"`
}
type Empty struct{}
type RecoveryResult struct {
	Code string `json:"code"`
}

func wireError(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, ErrConflict) {
		return &rpc.Error{Code: rpc.CodeConflict, Message: "idempotency payload conflict"}
	}
	if errors.Is(e, ErrRateLimited) {
		return &rpc.Error{Code: rpc.CodeRateLimited, Message: "rate limited"}
	}
	if errors.Is(e, ErrUnauthenticated) || errors.Is(e, ErrDenied) || errors.Is(e, ErrUnavailable) {
		return rpc.SecurityError(e)
	}
	return &rpc.Error{Code: rpc.CodeInternal, Message: "internal error"}
}
func bind[Req, Res any](service *sdk.Service, c *Core, name string, h func(context.Context, Req) (Res, error)) error {
	id := "identity.v1." + name
	mutation := name == "delegations.create" || name == "delegations.revoke"
	return rpc.Handle(service, rpc.Operation{ID: id, Endpoint: strings.ReplaceAll(name, ".", "_"), Subject: "rpc." + id, QueueGroup: "q.identity.v1", Timeout: 10 * time.Second, Protected: true, Mutation: mutation, Authorize: rpc.AssertionAuthorizer(c.Verifier(), func(ctx context.Context, caller, op string) error {
		if e := c.rate(ctx, "rpc:"+caller+":"+op); e != nil {
			return wireError(e)
		}
		return c.allow(ctx, Authorization{Caller: caller, Audience: "identity/v1", Operation: op})
	})}, func(ctx context.Context, r Req) (Res, error) {
		var out Res
		var e error
		if mutation {
			out, e = command(ctx, c, id, r, h)
		} else {
			out, e = h(ctx, r)
		}
		return out, wireError(e)
	})
}

// BindInternal registers only NATS endpoints, on a preconfigured private service
// connection. Deployment must restrict subjects to approved internal credentials.
func (c *Core) BindInternal(s *sdk.Service) error {
	if e := c.ready(); e != nil {
		return e
	}
	if c.Policy == nil {
		return ErrUnavailable
	}
	registrations := []func() error{
		func() error {
			return bind(s, c, "sessions.login", func(ctx context.Context, r LoginRequest) (LoginResult, error) {
				return c.Login(ctx, r.Email, r.Password)
			})
		},
		func() error {
			return bind(s, c, "sessions.refresh", func(ctx context.Context, r RefreshRequest) (LoginResult, error) { return c.Refresh(ctx, r.Token) })
		},
		func() error {
			return bind(s, c, "sessions.logout", func(ctx context.Context, r SessionRequest) (Empty, error) { return Empty{}, c.Logout(ctx, r.Session) })
		},
		func() error {
			return bind(s, c, "sessions.revoke", func(ctx context.Context, r RevokeSessionRequest) (Empty, error) {
				return Empty{}, c.RevokeSession(ctx, r.Session, r.ID)
			})
		},
		func() error {
			return bind(s, c, "sessions.introspect", func(ctx context.Context, r IntrospectRequest) (Session, error) { return c.Introspect(ctx, r.Secret) })
		},
		func() error {
			return bind(s, c, "users.recover", func(ctx context.Context, r RecoverRequest) (RecoveryResult, error) {
				code, e := c.Recover(ctx, r.Email, r.Code, r.Password)
				return RecoveryResult{code}, e
			})
		},
		func() error {
			return bind(s, c, "keys.jwks", func(ctx context.Context, r Empty) (security.JWKS, error) { return c.JWKS(ctx) })
		},
		func() error {
			return bind(s, c, "delegations.create", func(ctx context.Context, r DelegationRequest) (Delegation, error) {
				return c.CreateDelegation(ctx, r.Session, r.Delegation)
			})
		},
		func() error {
			return bind(s, c, "delegations.get", func(ctx context.Context, r DelegationIDRequest) (Delegation, error) {
				return c.GetDelegation(ctx, r.Session, r.ID)
			})
		},
		func() error {
			return bind(s, c, "delegations.revoke", func(ctx context.Context, r DelegationIDRequest) (Empty, error) {
				return Empty{}, c.RevokeDelegation(ctx, r.Session, r.ID)
			})
		},
		func() error {
			return bind(s, c, "invocations.exchange_user", func(ctx context.Context, r UserExchange) (TokenResult, error) {
				a, ok := rpc.VerifiedClaims(ctx)
				if !ok {
					return TokenResult{}, ErrUnauthenticated
				}
				return c.exchangeUser(ctx, r, a)
			})
		},
		func() error {
			return bind(s, c, "invocations.exchange_service", func(ctx context.Context, r ServiceExchange) (TokenResult, error) {
				a, ok := rpc.VerifiedClaims(ctx)
				if !ok {
					return TokenResult{}, ErrUnauthenticated
				}
				return c.exchangeService(ctx, r, a)
			})
		},
	}
	for _, register := range registrations {
		if e := register(); e != nil {
			return e
		}
	}
	return nil
}

// TestClient holds only a service instance key, never Core's signing key.
// It is suitable for the internal CLI/harness before Gate is implemented.
type TestClient struct {
	RPC            *rpc.Client
	ServiceID, Kid string
	IdempotencyKey string
	PrivateKey     ed25519.PrivateKey
	Now            func() time.Time
}

func TestCall[Req, Res any](ctx context.Context, client TestClient, operation string, request Req) (Res, error) {
	var zero Res
	now := time.Now()
	if client.Now != nil {
		now = client.Now()
	}
	j, e := uuid()
	if e != nil {
		return zero, e
	}
	claims := security.Claims{Issuer: client.ServiceID, Subject: client.ServiceID, Audience: "identity.exchange_service", JTI: j, IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Unix() + 30, Confirmation: security.Confirmation{Kid: client.Kid}}
	token, e := security.Sign(client.PrivateKey, client.Kid, claims)
	if e != nil {
		return zero, e
	}
	idempotency := client.IdempotencyKey
	if idempotency == "" {
		idempotency, e = uuid()
		if e != nil {
			return zero, e
		}
	}
	ctx = rpc.WithCredentials(ctx, rpc.Credentials{Token: token, IdempotencyKey: idempotency, Proof: func(subject string, raw []byte) (security.Proof, error) {
		nonce, e := secret()
		if e != nil {
			return security.Proof{}, e
		}
		return security.SignProof(client.PrivateKey, subject, raw, j, security.Proof{Kid: client.Kid, Timestamp: now.UTC().Format(time.RFC3339Nano), Nonce: nonce})
	}})
	return rpc.Call[Req, Res](ctx, client.RPC, operation, "rpc."+operation, request)
}

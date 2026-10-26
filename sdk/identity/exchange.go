package identity

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

type Target struct {
	Audience    string `json:"audience"`
	Operation   string `json:"operation"`
	WorkspaceID string `json:"workspace_id,omitempty"`
}
type UserExchange struct {
	Assertion   string      `json:"assertion"`
	Session     UserSession `json:"session"`
	AccessToken string      `json:"access_token,omitempty"`
	Target      Target      `json:"target"`
}
type ServiceExchange struct {
	Assertion         string `json:"assertion"`
	IncomingToken     string `json:"incoming_token,omitempty"`
	IncomingOperation string `json:"incoming_operation,omitempty"`
	DelegationID      string `json:"delegation_id,omitempty"`
	Target            Target `json:"target"`
}
type TokenResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Core) ExchangeUser(ctx context.Context, r UserExchange) (TokenResult, error) {
	a, e := c.Verifier().Assertion(ctx, r.Assertion)
	if e != nil {
		return TokenResult{}, e
	}
	return c.exchangeUser(ctx, r, a)
}
func (c *Core) exchangeUser(ctx context.Context, r UserExchange, a security.Claims) (TokenResult, error) {
	var e error
	if e = c.allow(ctx, Authorization{Caller: a.Issuer, Operation: "identity.v1.invocations.exchange_user", Audience: "identity/v1"}); e != nil {
		return TokenResult{}, e
	}
	var sid, user string
	if r.AccessToken != "" {
		cl, e := c.Verifier().Access(ctx, r.AccessToken)
		if e != nil {
			return TokenResult{}, e
		}
		sid = cl.SessionID
		user = cl.Subject
	} else {
		s, e := c.user(ctx, r.Session)
		if e != nil {
			return TokenResult{}, e
		}
		sid = s.ID
		user = "user:" + s.UserID
	}
	cl := security.Claims{Subject: user, SessionID: sid, Caller: a.Issuer, Confirmation: a.Confirmation, WorkspaceID: r.Target.WorkspaceID}
	return c.issue(ctx, cl, r.Target, nil)
}
func (c *Core) ExchangeService(ctx context.Context, r ServiceExchange) (TokenResult, error) {
	a, e := c.Verifier().Assertion(ctx, r.Assertion)
	if e != nil {
		return TokenResult{}, e
	}
	return c.exchangeService(ctx, r, a)
}
func (c *Core) exchangeService(ctx context.Context, r ServiceExchange, a security.Claims) (TokenResult, error) {
	var e error
	if e = c.allow(ctx, Authorization{Caller: a.Issuer, Operation: "identity.v1.invocations.exchange_service", Audience: "identity/v1"}); e != nil {
		return TokenResult{}, e
	}
	cl := security.Claims{Subject: "service:" + a.Issuer, Caller: a.Issuer, Confirmation: a.Confirmation, WorkspaceID: r.Target.WorkspaceID}
	var incoming *security.Claims
	if r.IncomingToken != "" {
		var definition string
		if e = c.DB.QueryRowContext(ctx, `SELECT service_definition FROM identity.service_accounts WHERE id::text=$1 AND disabled_at IS NULL`, a.Issuer).Scan(&definition); e != nil {
			return TokenResult{}, keyError(e)
		}
		prev, e := c.Verifier().Recipient(ctx, r.IncomingToken, definition+"/v1", r.IncomingOperation)
		if e != nil {
			return TokenResult{}, e
		}
		if r.Target.WorkspaceID != prev.WorkspaceID || r.DelegationID != "" && r.DelegationID != prev.DelegationID {
			return TokenResult{}, ErrDenied
		}
		// Proof of possession was checked on receipt by the service SDK; the assertion
		// authenticates that exact approved recipient during exchange.
		cl.Subject = prev.Subject
		cl.SessionID = prev.SessionID
		cl.DelegationID = prev.DelegationID
		cl.OnBehalfOf = prev.OnBehalfOf
		incoming = &prev
	} else if r.DelegationID != "" {
		d, e := c.delegation(ctx, r.DelegationID)
		if e != nil {
			return TokenResult{}, e
		}
		cl.Subject = d.GranteeKind + ":" + d.GranteeID
		cl.DelegationID = d.ID
		cl.OnBehalfOf = d.Grantor
		if d.GranteeKind == "service" && d.GranteeID != a.Issuer {
			return TokenResult{}, ErrDenied
		}
		if e = c.checkDelegation(ctx, security.Claims{Subject: cl.Subject, Caller: cl.Caller, DelegationID: d.ID, OnBehalfOf: d.Grantor, Audience: r.Target.Audience, Operation: r.Target.Operation, WorkspaceID: r.Target.WorkspaceID}); e != nil {
			return TokenResult{}, e
		}
	}
	return c.issue(ctx, cl, r.Target, incoming)
}
func (c *Core) issue(ctx context.Context, cl security.Claims, target Target, incoming *security.Claims) (TokenResult, error) {
	if target.Audience == "" || target.Operation == "" || len(c.PrivateKey) != 64 || c.SigningKid == "" {
		return TokenResult{}, ErrUnavailable
	}
	if e := c.allow(ctx, Authorization{Caller: cl.Caller, Actor: cl.Subject, Audience: target.Audience, Operation: target.Operation, WorkspaceID: target.WorkspaceID, DelegationID: cl.DelegationID, Incoming: incoming}); e != nil {
		return TokenResult{}, e
	}
	cl.Audience = target.Audience
	cl.Operation = target.Operation
	if e := c.CheckInvocation(ctx, cl); e != nil {
		return TokenResult{}, e
	}
	now := c.now()
	expiry := now.Add(60 * time.Second)
	if incoming != nil && time.Unix(incoming.ExpiresAt, 0).Before(expiry) {
		expiry = time.Unix(incoming.ExpiresAt, 0)
	}
	if cl.DelegationID != "" {
		d, e := c.delegation(ctx, cl.DelegationID)
		if e != nil {
			return TokenResult{}, e
		}
		if d.ExpiresAt.Before(expiry) {
			expiry = d.ExpiresAt
		}
	}
	k, e := c.SigningKey(ctx, c.SigningKid)
	if e != nil {
		return TokenResult{}, e
	}
	if k.Revoked || now.Before(k.NotBefore) || !now.Before(k.ExpiresAt) {
		return TokenResult{}, ErrUnauthenticated
	}
	if k.ExpiresAt.Before(expiry) {
		expiry = k.ExpiresAt
	}
	ck, e := c.CallerKey(ctx, cl.Caller, cl.Confirmation.Kid)
	if e != nil {
		return TokenResult{}, e
	}
	if ck.Revoked || now.Before(ck.NotBefore) || !now.Before(ck.ExpiresAt) {
		return TokenResult{}, ErrUnauthenticated
	}
	if ck.ExpiresAt.Before(expiry) {
		expiry = ck.ExpiresAt
	}
	cl.Issuer = "arc-core"
	cl.IssuedAt = now.Unix()
	cl.NotBefore = cl.IssuedAt
	cl.ExpiresAt = expiry.Unix()
	cl.JTI, e = uuid()
	if e != nil {
		return TokenResult{}, e
	}
	token, e := security.Sign(c.PrivateKey, c.SigningKid, cl)
	if e != nil {
		return TokenResult{}, e
	}
	if e = audit(ctx, c.DB, cl.Subject, "invocations.issue", target.Audience+":"+target.Operation, "ok"); e != nil {
		return TokenResult{}, e
	}
	return TokenResult{token, expiry}, nil
}

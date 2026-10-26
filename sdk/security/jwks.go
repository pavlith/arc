package security

import (
	"context"
	"time"
)

// JWKSKeys fetches the protected internal JWKS on each verification. Fetch must
// authenticate Core and return only currently active keys; there is no positive
// cache in M0. CallerKey must independently query current credential status.
type JWKSKeys struct {
	Fetch  func(context.Context) (JWKS, error)
	Caller func(context.Context, string, string) (Key, error)
}

func (k JWKSKeys) SigningKey(ctx context.Context, kid string) (Key, error) {
	if k.Fetch == nil {
		return Key{}, ErrUnavailable
	}
	j, e := k.Fetch(ctx)
	if e != nil {
		return Key{}, ErrUnavailable
	}
	p, e := j.PublicKey(kid)
	if e != nil {
		return Key{}, e
	}
	// Validity/revocation is enforced by the live JWKS owner before publication.
	return Key{Kid: kid, Public: p, ExpiresAt: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}
func (k JWKSKeys) CallerKey(ctx context.Context, caller, kid string) (Key, error) {
	if k.Caller == nil {
		return Key{}, ErrUnavailable
	}
	return k.Caller(ctx, caller, kid)
}

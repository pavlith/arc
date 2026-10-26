package rpc

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/pavlith/arc/sdk/security"
)

type credentialsKey struct{}
type claimsKey struct{}
type Credentials struct {
	Token          string
	IdempotencyKey string
	Proof          func(string, []byte) (security.Proof, error)
}

func WithCredentials(ctx context.Context, c Credentials) context.Context {
	return context.WithValue(ctx, credentialsKey{}, c)
}
func VerifiedClaims(ctx context.Context) (security.Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(security.Claims)
	return c, ok
}
func SecurityError(err error) error {
	var typed *Error
	if errors.As(err, &typed) {
		return publicError(typed)
	}
	code := CodeUnauthenticated
	if errors.Is(err, security.ErrUnavailable) {
		code = CodeUnavailable
	}
	if errors.Is(err, security.ErrDenied) {
		code = CodePermissionDenied
	}
	return &Error{Code: code, Message: string(code)}
}

// InvocationAuthorizer reads identity only from a signed token and a verified proof.
func InvocationAuthorizer(v security.Verifier, audience string) func(context.Context, string, []byte) (context.Context, error) {
	return func(ctx context.Context, subject string, raw []byte) (context.Context, error) {
		var env requestEnvelope
		if decodeStrict(raw, &env) != nil || env.Proof == nil {
			return nil, SecurityError(security.ErrUnauthenticated)
		}
		// Caller is a verification expectation, never a trusted header.
		c, err := v.Recipient(ctx, env.Auth, audience, env.Operation)
		if err != nil {
			return nil, SecurityError(err)
		}
		if err = v.Proof(ctx, subject, raw, c, *env.Proof); err != nil {
			return nil, SecurityError(err)
		}
		verified := context.WithValue(ctx, claimsKey{}, c)
		return context.WithValue(verified, metadataKey{}, RequestMetadata{IdempotencyKey: env.IdempotencyKey, Payload: env.Payload}), nil
	}
}

// AssertionAuthorizer is for the closed Identity bootstrap API; policy must
// independently authorize the verified service for the exact endpoint.
func AssertionAuthorizer(v security.Verifier, allow func(context.Context, string, string) error) func(context.Context, string, []byte) (context.Context, error) {
	return func(ctx context.Context, subject string, raw []byte) (context.Context, error) {
		var env requestEnvelope
		if decodeStrict(raw, &env) != nil || env.Proof == nil {
			return nil, SecurityError(security.ErrUnauthenticated)
		}
		if allow == nil {
			return nil, SecurityError(security.ErrUnavailable)
		}
		c, err := v.Assertion(ctx, env.Auth)
		if err != nil {
			return nil, SecurityError(err)
		}
		c.Caller = c.Issuer
		if err = v.Proof(ctx, subject, raw, c, *env.Proof); err != nil {
			return nil, SecurityError(err)
		}
		if err = allow(ctx, c.Caller, env.Operation); err != nil {
			return nil, SecurityError(err)
		}
		verified := context.WithValue(ctx, claimsKey{}, c)
		return context.WithValue(verified, metadataKey{}, RequestMetadata{IdempotencyKey: env.IdempotencyKey, Payload: env.Payload}), nil
	}
}

// DecodeEnvelope is exposed for contract clients without exporting wire internals.
func DecodeEnvelope(raw []byte) (string, string, *security.Proof, error) {
	var e requestEnvelope
	err := json.Unmarshal(raw, &e)
	return e.Operation, e.Auth, e.Proof, err
}

type metadataKey struct{}
type RequestMetadata struct {
	IdempotencyKey string
	Payload        json.RawMessage
}

func Metadata(ctx context.Context) (RequestMetadata, bool) {
	m, ok := ctx.Value(metadataKey{}).(RequestMetadata)
	return m, ok
}

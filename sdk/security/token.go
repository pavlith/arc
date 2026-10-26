// Package security implements the Arc invocation boundary, independent of transport headers.
package security

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrUnauthenticated = errors.New("unauthenticated")
var ErrUnavailable = errors.New("security dependency unavailable")
var ErrDenied = errors.New("permission denied")

type Confirmation struct {
	Kid string `json:"kid"`
}
type Claims struct {
	Issuer       string       `json:"iss"`
	Audience     string       `json:"aud"`
	Subject      string       `json:"sub"`
	Caller       string       `json:"caller,omitempty"`
	Operation    string       `json:"op,omitempty"`
	IssuedAt     int64        `json:"iat"`
	NotBefore    int64        `json:"nbf"`
	ExpiresAt    int64        `json:"exp"`
	JTI          string       `json:"jti"`
	Confirmation Confirmation `json:"cnf"`
	SessionID    string       `json:"sid,omitempty"`
	DelegationID string       `json:"delegation_id,omitempty"`
	OnBehalfOf   string       `json:"on_behalf_of,omitempty"`
	WorkspaceID  string       `json:"workspace_id,omitempty"`
}
type Key struct {
	Kid                  string
	Public               ed25519.PublicKey
	NotBefore, ExpiresAt time.Time
	Revoked              bool
}
type Keys interface {
	SigningKey(context.Context, string) (Key, error)
	CallerKey(context.Context, string, string) (Key, error)
}
type LiveState interface {
	CheckInvocation(context.Context, Claims) error
}
type Nonces interface {
	Consume(context.Context, string, string, time.Time) error
}
type Verifier struct {
	Keys   Keys
	State  LiveState
	Nonces Nonces
	Now    func() time.Time
}

func (v Verifier) Time() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}
func validKey(k Key, now time.Time) bool {
	return len(k.Public) == ed25519.PublicKeySize && !k.Revoked && !now.Before(k.NotBefore) && now.Before(k.ExpiresAt)
}

var b64 = base64.RawURLEncoding

func Sign(key ed25519.PrivateKey, kid string, c Claims) (string, error) {
	if len(key) != ed25519.PrivateKeySize || kid == "" {
		return "", ErrUnauthenticated
	}
	h, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{"EdDSA", "JWT", kid})
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	body := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return body + "." + b64.EncodeToString(ed25519.Sign(key, []byte(body))), nil
}
func parse(token string) (Claims, string, string, []byte, error) {
	var c Claims
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if len(token) > 16384 {
		return c, "", "", nil, ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, "", "", nil, ErrUnauthenticated
	}
	hb, e := b64.DecodeString(parts[0])
	if e != nil {
		return c, "", "", nil, ErrUnauthenticated
	}
	pb, e := b64.DecodeString(parts[1])
	if e != nil {
		return c, "", "", nil, ErrUnauthenticated
	}
	sig, e := b64.DecodeString(parts[2])
	if e != nil || json.Unmarshal(hb, &h) != nil || json.Unmarshal(pb, &c) != nil || h.Alg != "EdDSA" || h.Typ != "JWT" || h.Kid == "" {
		return c, "", "", nil, ErrUnauthenticated
	}
	return c, h.Kid, parts[0] + "." + parts[1], sig, nil
}
func lifetime(c Claims, now time.Time, max int64) bool {
	n := now.Unix()
	return c.JTI != "" && c.IssuedAt <= n && c.NotBefore <= n && c.NotBefore >= c.IssuedAt && c.ExpiresAt > n && c.ExpiresAt > c.IssuedAt && c.ExpiresAt-c.IssuedAt <= max
}
func (v Verifier) Invocation(ctx context.Context, token, audience, operation, caller string) (Claims, error) {
	c, kid, body, sig, e := parse(token)
	if e != nil {
		return Claims{}, e
	}
	if v.Keys == nil || v.State == nil {
		return Claims{}, ErrUnavailable
	}
	now := v.Time()
	k, e := v.Keys.SigningKey(ctx, kid)
	if e != nil {
		return Claims{}, e
	}
	if !validKey(k, now) || k.Kid != kid || !ed25519.Verify(k.Public, []byte(body), sig) || c.Issuer != "arc-core" || audience == "" || operation == "" || caller == "" || c.Audience != audience || c.Operation != operation || c.Caller != caller || !lifetime(c, now, 60) || c.Confirmation.Kid == "" || !validPrincipal(c.Subject) {
		return Claims{}, ErrUnauthenticated
	}
	if (c.OnBehalfOf != "") != (c.DelegationID != "") {
		return Claims{}, ErrUnauthenticated
	}
	ck, e := v.Keys.CallerKey(ctx, caller, c.Confirmation.Kid)
	if e != nil {
		return Claims{}, e
	}
	if ck.Kid != c.Confirmation.Kid || !validKey(ck, now) {
		return Claims{}, ErrUnauthenticated
	}
	if e = v.State.CheckInvocation(ctx, c); e != nil {
		return Claims{}, e
	}
	return c, nil
}
func validPrincipal(s string) bool {
	p := strings.Split(s, ":")
	return len(p) == 2 && p[1] != "" && (p[0] == "user" || p[0] == "agent" || p[0] == "service")
}
func (v Verifier) Assertion(ctx context.Context, token string) (Claims, error) {
	c, kid, body, sig, e := parse(token)
	if e != nil {
		return Claims{}, e
	}
	if v.Keys == nil || v.Nonces == nil {
		return Claims{}, ErrUnavailable
	}
	k, e := v.Keys.CallerKey(ctx, c.Issuer, kid)
	if e != nil {
		return Claims{}, e
	}
	if !validKey(k, v.Time()) || k.Kid != kid || !ed25519.Verify(k.Public, []byte(body), sig) || c.Issuer == "" || c.Subject != c.Issuer || c.Audience != "identity.exchange_service" || c.Confirmation.Kid != kid || !lifetime(c, v.Time(), 30) {
		return Claims{}, ErrUnauthenticated
	}
	if e = v.Nonces.Consume(ctx, "assertion:"+c.Issuer, c.JTI, time.Unix(c.ExpiresAt, 0)); e != nil {
		return Claims{}, e
	}
	return c, nil
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func PublicJWKS(keys []Key, now time.Time) JWKS {
	j := JWKS{Keys: []JWK{}}
	for _, k := range keys {
		if validKey(k, now) {
			j.Keys = append(j.Keys, JWK{"OKP", "Ed25519", "EdDSA", "sig", k.Kid, b64.EncodeToString(k.Public)})
		}
	}
	return j
}
func (j JWKS) PublicKey(kid string) (ed25519.PublicKey, error) {
	var found ed25519.PublicKey
	for _, k := range j.Keys {
		if k.Kid == kid {
			if found != nil || k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.Use != "sig" {
				return nil, ErrUnauthenticated
			}
			p, e := b64.DecodeString(k.X)
			if e != nil || len(p) != 32 {
				return nil, ErrUnauthenticated
			}
			found = p
		}
	}
	if found == nil {
		return nil, ErrUnauthenticated
	}
	return found, nil
}

// Recipient obtains caller only as a signature-verified claim, then checks live state.
func (v Verifier) Recipient(ctx context.Context, token, audience, operation string) (Claims, error) {
	c, _, _, _, e := parse(token)
	if e != nil {
		return Claims{}, e
	}
	return v.Invocation(ctx, token, audience, operation, c.Caller)
}

// Access checks the external JWT and its live server-side session, without treating it as an invocation.
func (v Verifier) Access(ctx context.Context, token string) (Claims, error) {
	c, kid, body, sig, e := parse(token)
	if e != nil {
		return Claims{}, e
	}
	if v.Keys == nil || v.State == nil {
		return Claims{}, ErrUnavailable
	}
	k, e := v.Keys.SigningKey(ctx, kid)
	if e != nil {
		return Claims{}, e
	}
	if !validKey(k, v.Time()) || k.Kid != kid || !ed25519.Verify(k.Public, []byte(body), sig) || c.Issuer != "arc-core" || c.Audience != "gate" || !strings.HasPrefix(c.Subject, "user:") || c.SessionID == "" || c.Caller != "" || c.OnBehalfOf != "" || c.DelegationID != "" || !lifetime(c, v.Time(), 600) {
		return Claims{}, ErrUnauthenticated
	}
	if e = v.State.CheckInvocation(ctx, c); e != nil {
		return Claims{}, e
	}
	return c, nil
}

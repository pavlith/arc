package security

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type boundary struct {
	signing, caller Key
	revokedSession  bool
	seen            map[string]bool
}

func (b *boundary) SigningKey(context.Context, string) (Key, error) { return b.signing, nil }
func (b *boundary) CallerKey(_ context.Context, caller, kid string) (Key, error) {
	if caller != "svc" || kid != "caller-key" {
		return Key{}, ErrUnauthenticated
	}
	return b.caller, nil
}
func (b *boundary) CheckInvocation(context.Context, Claims) error {
	if b.revokedSession {
		return ErrUnauthenticated
	}
	return nil
}
func (b *boundary) Consume(_ context.Context, ns, n string, _ time.Time) error {
	k := ns + ":" + n
	if b.seen[k] {
		return ErrUnauthenticated
	}
	b.seen[k] = true
	return nil
}
func fixture() (Verifier, *boundary, ed25519.PrivateKey, ed25519.PrivateKey, Claims) {
	now := time.Unix(1800000000, 0).UTC()
	core := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	caller := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	b := &boundary{signing: Key{Kid: "core-key", Public: core.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}, caller: Key{Kid: "caller-key", Public: caller.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}, seen: map[string]bool{}}
	c := Claims{Issuer: "arc-core", Audience: "task/v1", Subject: "user:user-id", Caller: "svc", Operation: "task.create", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Unix() + 60, JTI: "token-id", Confirmation: Confirmation{"caller-key"}, SessionID: "session"}
	return Verifier{Keys: b, State: b, Nonces: b, Now: func() time.Time { return now }}, b, core, caller, c
}
func TestInvocationGuardrails(t *testing.T) {
	ctx := context.Background()
	v, b, core, _, c := fixture()
	token, e := Sign(core, "core-key", c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.Invocation(ctx, token, c.Audience, c.Operation, c.Caller); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct{ name, aud, op, caller string }{{"audience", "calendar/v1", c.Operation, c.Caller}, {"operation", c.Audience, "task.delete", c.Caller}, {"caller", c.Audience, c.Operation, "other"}} {
		t.Run(test.name, func(t *testing.T) {
			if _, e = v.Invocation(ctx, token, test.aud, test.op, test.caller); e == nil {
				t.Fatal("accepted mismatch")
			}
		})
	}
	for _, mutate := range []func(*Claims){func(c *Claims) { c.ExpiresAt = c.IssuedAt }, func(c *Claims) { c.ExpiresAt = c.IssuedAt + 61 }, func(c *Claims) { c.NotBefore++ }, func(c *Claims) { c.Issuer = "evil" }, func(c *Claims) { c.Confirmation.Kid = "other" }, func(c *Claims) { c.OnBehalfOf = "user" }} {
		bad := c
		mutate(&bad)
		tok, _ := Sign(core, "core-key", bad)
		if _, e = v.Invocation(ctx, tok, c.Audience, c.Operation, c.Caller); e == nil {
			t.Fatal("accepted invalid claims")
		}
	}
	b.signing.Revoked = true
	if _, e = v.Invocation(ctx, token, c.Audience, c.Operation, c.Caller); e == nil {
		t.Fatal("accepted revoked signing key")
	}
	b.signing.Revoked = false
	b.caller.Revoked = true
	if _, e = v.Invocation(ctx, token, c.Audience, c.Operation, c.Caller); e == nil {
		t.Fatal("accepted revoked caller key")
	}
	b.caller.Revoked = false
	b.revokedSession = true
	if _, e = v.Invocation(ctx, token, c.Audience, c.Operation, c.Caller); e == nil {
		t.Fatal("accepted revoked session")
	}
	parts := strings.Split(token, ".")
	parts[0] = b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"core-key"}`))
	if _, e = v.Invocation(ctx, strings.Join(parts, "."), c.Audience, c.Operation, c.Caller); e == nil {
		t.Fatal("accepted alg substitution")
	}
	v.State = nil
	if _, e = v.Invocation(ctx, token, c.Audience, c.Operation, c.Caller); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("not fail closed: %v", e)
	}
}
func TestJCSAndProofVectors(t *testing.T) {
	a := []byte(`{"z":1.0,"a":{"b":2,"a":"€"}}`)
	b := []byte(`{"a":{"a":"€","b":2},"z":1}`)
	ca, e := CanonicalJSON(a)
	if e != nil {
		t.Fatal(e)
	}
	cb, e := CanonicalJSON(b)
	if e != nil || !bytes.Equal(ca, cb) {
		t.Fatalf("JCS mismatch: %s %s %v", ca, cb, e)
	}
	if string(ca) != `{"a":{"a":"€","b":2},"z":1}` {
		t.Fatalf("unexpected canonical vector: %s", ca)
	}
	for _, invalid := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"n":1e999}`} {
		if _, e := CanonicalJSON([]byte(invalid)); e == nil {
			t.Fatalf("accepted invalid I-JSON: %s", invalid)
		}
	}
	v, _, _, key, c := fixture()
	ctx := context.Background()
	raw := []byte(`{"request_id":"request-1","operation":"task.create","payload":{"b":2,"a":1}}`)
	p, e := SignProof(key, "rpc.task.v1.create", raw, c.JTI, Proof{Kid: c.Confirmation.Kid, Timestamp: v.Time().Format(time.RFC3339Nano), Nonce: "0123456789abcdef"})
	if e != nil {
		t.Fatal(e)
	}
	msg, e := ProofMessage("rpc.task.v1.create", raw, c.JTI, p)
	if e != nil {
		t.Fatal(e)
	}
	// Stable vector prevents changing the proof serialization accidentally.
	const expectedMessage = `["proof_v1","rpc.task.v1.create","request-1","142b71c332d69dfa594ee86b7347db1ed9ab79c82954b380a1c02075e77fb486","token-id","2027-01-15T08:00:00Z","0123456789abcdef"]`
	if string(msg) != expectedMessage {
		t.Fatalf("proof vector mismatch: %s", msg)
	}
	changed := []byte(`{"request_id":"request-1","operation":"task.create","payload":{"b":3,"a":1}}`)
	if e = v.Proof(ctx, "rpc.task.v1.create", changed, c, p); e == nil {
		t.Fatal("accepted altered payload")
	}
	if e = v.Proof(ctx, "rpc.task.v1.other", raw, c, p); e == nil {
		t.Fatal("accepted altered subject")
	}
	reordered := []byte(`{"payload":{"a":1,"b":2},"operation":"task.create","request_id":"request-1"}`)
	if e = v.Proof(ctx, "rpc.task.v1.create", reordered, c, p); e != nil {
		t.Fatal(e)
	}
	if e = v.Proof(ctx, "rpc.task.v1.create", raw, c, p); e == nil {
		t.Fatal("accepted replay")
	}
	v.Nonces = nil
	if e = v.Proof(ctx, "rpc.task.v1.create", raw, c, p); !errors.Is(e, ErrUnavailable) {
		t.Fatal("not fail closed")
	}
}
func TestAssertionReplayAndTTL(t *testing.T) {
	v, _, _, caller, _ := fixture()
	ctx := context.Background()
	c := Claims{Issuer: "svc", Subject: "svc", Audience: "identity.exchange_service", IssuedAt: v.Time().Unix(), NotBefore: v.Time().Unix(), ExpiresAt: v.Time().Unix() + 30, JTI: "once", Confirmation: Confirmation{"caller-key"}}
	tok, _ := Sign(caller, "caller-key", c)
	if _, e := v.Assertion(ctx, tok); e != nil {
		t.Fatal(e)
	}
	if _, e := v.Assertion(ctx, tok); e == nil {
		t.Fatal("accepted assertion replay")
	}
	c.JTI = "other"
	c.ExpiresAt++
	tok, _ = Sign(caller, "caller-key", c)
	if _, e := v.Assertion(ctx, tok); e == nil {
		t.Fatal("accepted assertion TTL>30")
	}
}
func TestJWKS(t *testing.T) {
	v, b, _, _, _ := fixture()
	j := PublicJWKS([]Key{b.signing}, v.Time())
	wire, _ := json.Marshal(j)
	if strings.Contains(string(wire), `"d"`) {
		t.Fatal("private key leaked")
	}
	k, e := j.PublicKey("core-key")
	if e != nil || !bytes.Equal(k, b.signing.Public) {
		t.Fatal("JWKS roundtrip failed")
	}
	b.signing.Revoked = true
	if len(PublicJWKS([]Key{b.signing}, v.Time()).Keys) != 0 {
		t.Fatal("revoked key published")
	}
}

func TestJWTVerificationThroughLiveJWKS(t *testing.T) {
	v, b, core, _, claims := fixture()
	ctx := context.Background()
	token, e := Sign(core, "core-key", claims)
	if e != nil {
		t.Fatal(e)
	}
	v.Keys = JWKSKeys{Fetch: func(context.Context) (JWKS, error) { return PublicJWKS([]Key{b.signing}, v.Time()), nil }, Caller: b.CallerKey}
	if _, e = v.Invocation(ctx, token, claims.Audience, claims.Operation, claims.Caller); e != nil {
		t.Fatal(e)
	}
	b.signing.Revoked = true
	if _, e = v.Invocation(ctx, token, claims.Audience, claims.Operation, claims.Caller); e == nil {
		t.Fatal("cached JWKS accepted revoked key")
	}
	v.Keys = JWKSKeys{}
	if _, e = v.Invocation(ctx, token, claims.Audience, claims.Operation, claims.Caller); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("missing JWKS did not fail closed: %v", e)
	}
}

package fabric

import (
	"bytes"
	"crypto/ed25519"

	"encoding/json"
	"github.com/pavlith/arc/pkgs/security"
	"strings"
	"testing"
	"time"
)

func TestSnapshotSignatureAndRollback(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	s, e := SignSnapshot(RouteSnapshot{Revision: 8, Routes: []Route{}}, "snapshot-test", key)
	if e != nil {
		t.Fatal(e)
	}
	pub := key.Public().(ed25519.PublicKey)
	if _, e := VerifySnapshot(pub, s, 8); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifySnapshot(pub, s, 9); e == nil {
		t.Fatal("rollback accepted")
	}
	s.Signature[0] ^= 1
	if _, e := VerifySnapshot(pub, s, 8); e == nil {
		t.Fatal("forged snapshot accepted")
	}
}

func TestSnapshotDigestKidAndDomainSeparation(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32))
	s, e := SignSnapshot(RouteSnapshot{Revision: 1, Routes: []Route{}}, "snapshot-digest", key)
	if e != nil {
		t.Fatal(e)
	}
	var snap RouteSnapshot
	if json.Unmarshal(s.Payload, &snap) != nil {
		t.Fatal("decode")
	}
	snap.Digest = strings.Repeat("0", 64)
	raw, _ := json.Marshal(snap)
	raw, _ = security.CanonicalJSON(raw)
	wrong := SignedSnapshot{Payload: raw, Signature: ed25519.Sign(key, snapshotMessage(raw))}
	if _, e = VerifySnapshot(key.Public().(ed25519.PublicKey), wrong, 0); e == nil {
		t.Fatal("signed wrong digest accepted")
	}
	old := SignedSnapshot{Payload: s.Payload, Signature: ed25519.Sign(key, s.Payload)}
	if _, e = VerifySnapshot(key.Public().(ed25519.PublicKey), old, 0); e == nil {
		t.Fatal("missing domain separation accepted")
	}
	if _, e = VerifySnapshotJWKS(security.JWKS{}, s, 0); e == nil {
		t.Fatal("unknown/revoked signing key accepted")
	}
}

func TestRouteBundleBindsNonceKeysAndExpiry(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	b := RouteBundle{RequestID: "fresh-request", ExpiresAt: time.Now().UTC().Add(10 * time.Second)}
	b.Signature = ed25519.Sign(key, bundleMessage(b))
	pub := key.Public().(ed25519.PublicKey)
	if e := VerifyBundle(pub, b, "fresh-request"); e != nil {
		t.Fatal(e)
	}
	if e := VerifyBundle(pub, b, "other-request"); e == nil {
		t.Fatal("bundle replay across request IDs")
	}
	b.Keys = security.JWKS{Keys: []security.JWK{{Kid: "injected"}}}
	if e := VerifyBundle(pub, b, "fresh-request"); e == nil {
		t.Fatal("tampered JWKS accepted")
	}
	b.Keys = security.JWKS{}
	b.ExpiresAt = time.Now().Add(-time.Second)
	b.Signature = ed25519.Sign(key, bundleMessage(b))
	if e := VerifyBundle(pub, b, "fresh-request"); e == nil {
		t.Fatal("expired bundle accepted")
	}
}

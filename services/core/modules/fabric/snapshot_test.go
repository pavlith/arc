package fabric

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"

	"encoding/json"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
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

func TestCompressedBundlePreservesSignedSnapshotAndBounds(t *testing.T) {
	k := key(94)
	snapshot, e := SignSnapshot(RouteSnapshot{Revision: 1, Routes: []Route{{Path: strings.Repeat("x", 300<<10)}}}, "snapshot", k)
	if e != nil {
		t.Fatal(e)
	}
	b := RouteBundle{RequestID: "request", ExpiresAt: time.Now().UTC().Add(10 * time.Second), Snapshot: snapshot}
	if e = compressBundle(&b); e != nil || len(b.CompressedSnapshot) == 0 || len(b.Snapshot.Payload) != 0 {
		t.Fatal("compression", e)
	}
	b.Signature = ed25519.Sign(k, bundleMessage(b))
	wire, _ := json.Marshal(b)
	if e = json.Unmarshal(wire, &b); e != nil {
		t.Fatal(e)
	}
	if e = VerifyBundle(k.Public().(ed25519.PublicKey), b, "request"); e != nil {
		t.Fatal(e)
	}
	got, e := BundleSnapshot(b)
	if e != nil || !bytes.Equal(got.Payload, snapshot.Payload) || !bytes.Equal(got.Signature, snapshot.Signature) {
		t.Fatal("snapshot changed", e)
	}
	if _, e = VerifySnapshot(k.Public().(ed25519.PublicKey), got, 0); e != nil {
		t.Fatal(e)
	}
	if len(got.Payload) <= 256<<10 || contract.Strict(got.Payload, &RouteSnapshot{}) == nil {
		t.Fatal("ordinary RPC JSON limit was widened")
	}
	bad := b
	bad.CompressedSnapshot = append([]byte(nil), b.CompressedSnapshot...)
	bad.CompressedSnapshot[0] ^= 1
	if VerifyBundle(k.Public().(ed25519.PublicKey), bad, "request") == nil {
		t.Fatal("wire signature bypassed")
	}
	if _, e = BundleSnapshot(bad); e == nil {
		t.Fatal("bad gzip accepted")
	}
	bad = b
	bad.Snapshot = snapshot
	if _, e = BundleSnapshot(bad); e == nil {
		t.Fatal("ambiguous encoding accepted")
	}
	// Expansion keeps strict JSON checks after transport authentication.
	for _, raw := range [][]byte{
		bytes.Replace(wireSnapshot(t, snapshot), []byte(`"signature":`), []byte(`"unknown":true,"signature":`), 1),
		append(wireSnapshot(t, snapshot), []byte(` {}`)...),
		bytes.Replace(wireSnapshot(t, snapshot), []byte(`"signature":`), []byte(`"signature":null,"signature":`), 1),
	} {
		var encoded bytes.Buffer
		writer := gzip.NewWriter(&encoded)
		_, _ = writer.Write(raw)
		_ = writer.Close()
		malformed := b
		malformed.CompressedSnapshot = encoded.Bytes()
		malformed.Signature = ed25519.Sign(k, bundleMessage(malformed))
		if VerifyBundle(k.Public().(ed25519.PublicKey), malformed, "request") != nil {
			t.Fatal("fixture bundle signature")
		}
		if _, e = BundleSnapshot(malformed); e == nil {
			t.Fatal("malformed expanded snapshot accepted")
		}
	}
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(bytes.Repeat([]byte("x"), maxExpandedSnapshot+1))
	w.Close()
	bad = b
	bad.CompressedSnapshot = out.Bytes()
	if _, e = BundleSnapshot(bad); e == nil {
		t.Fatal("decompression bomb accepted")
	}
	bad = b
	bad.CompressedSnapshot = make([]byte, maxCompressedSnapshot+1)
	if _, e = BundleSnapshot(bad); e == nil {
		t.Fatal("oversized compressed payload accepted")
	}
	oversized := RouteBundle{Snapshot: SignedSnapshot{Payload: json.RawMessage(`"` + strings.Repeat("x", maxExpandedSnapshot) + `"`)}}
	if compressBundle(&oversized) == nil {
		t.Fatal("oversized signed snapshot accepted")
	}
}

func wireSnapshot(t *testing.T, snapshot SignedSnapshot) []byte {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

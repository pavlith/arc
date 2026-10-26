package fabric

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/pavlith/arc/sdk/security"
	"testing"
)

func TestSnapshotSignatureAndRollback(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	raw, _ := json.Marshal(RouteSnapshot{Revision: 8, Routes: []Route{}})
	raw, _ = security.CanonicalJSON(raw)
	s := SignedSnapshot{raw, ed25519.Sign(key, raw)}
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

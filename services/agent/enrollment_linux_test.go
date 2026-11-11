package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	contract "github.com/pavlith/arc/sdk/agent"
)

func TestSignEnrollmentFileNeverExportsToken(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "service.seed")
	var seed [ed25519.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seedPath, seed[:], 0600); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed[:])
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	signature, err := SignEnrollmentFile(seedPath, "enroll-test-one", token)
	if err != nil || signature == "" || signature == token {
		t.Fatalf("failed to sign protected ticket: %v", err)
	}
	claim := contract.EnrollmentClaim{OfferID: "enroll-test-one", Token: token, Signature: signature}
	if !contract.VerifyEnrollmentClaim(claim, key.Public().(ed25519.PublicKey)) {
		t.Fatal("signature failed local public-key verification")
	}
	if _, err := SignEnrollmentFile(seedPath, "enroll-test-one", "bad"); err == nil {
		t.Fatal("malformed ticket signed")
	}
	if err := os.Chmod(seedPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnrollmentFile(seedPath, "enroll-test-one", token); err == nil {
		t.Fatal("world-readable private key accepted")
	}
}

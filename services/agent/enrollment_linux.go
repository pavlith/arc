package agent

import (
	"crypto/ed25519"
	"os"

	contract "github.com/pavlith/arc/sdk/agent"
)

// SignEnrollmentFile signs a short-lived offer with the host's private seed.
// The caller retains the ticket; the returned signature never includes it.
func SignEnrollmentFile(seedPath, offerID, token string) (string, error) {
	info, err := os.Lstat(seedPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrInvalid
	}
	seed, err := readOwned(seedPath, true, ed25519.SeedSize)
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", ErrInvalid
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	claim, err := contract.SignEnrollmentClaim(offerID, token, key)
	if err != nil {
		return "", ErrInvalid
	}
	return claim.Signature, nil
}

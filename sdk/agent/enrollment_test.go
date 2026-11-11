package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/pavlith/arc/sdk/agent"
)

func TestEnrollmentClaimProofOfPossession(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	claim, err := agent.SignEnrollmentClaim("enroll-offer-one", token, private)
	if err != nil || !agent.VerifyEnrollmentClaim(claim, public) {
		t.Fatalf("valid claim rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*agent.EnrollmentClaim)
	}{
		{"different offer", func(c *agent.EnrollmentClaim) { c.OfferID = "enroll-offer-two" }},
		{"modified token", func(c *agent.EnrollmentClaim) {
			last := "A"
			if c.Token[42:] == "A" {
				last = "B"
			}
			c.Token = c.Token[:42] + last
		}},
		{"forged signature", func(c *agent.EnrollmentClaim) { c.Signature = "bad" }},
		{"malformed base64", func(c *agent.EnrollmentClaim) { c.Token = "broken" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := claim
			tc.edit(&bad)
			if agent.VerifyEnrollmentClaim(bad, public) {
				t.Fatal("tampered enrollment claim accepted")
			}
		})
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if agent.VerifyEnrollmentClaim(claim, other) {
		t.Fatal("unapproved service key accepted")
	}
}

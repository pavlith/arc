package agent

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// EnrollmentClaim proves possession of the exact public key pinned by an
// administrator to a single-use ticket. The ticket is transferred out-of-band,
// never over the regular node RPC, and never stored in cleartext by Core.
type EnrollmentClaim struct {
	OfferID   string `json:"offer_id"`
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

const enrollmentDomain = "arc.runtime.enrollment.claim.v1\n"

func enrollmentMessage(offerID, token string) []byte {
	return []byte(enrollmentDomain + offerID + "\n" + token)
}

// SignEnrollmentClaim is run only by the bootstrap host holding the private
// service-signing key. It does not grant NATS access or install anything.
func SignEnrollmentClaim(offerID, token string, key ed25519.PrivateKey) (EnrollmentClaim, error) {
	if !ValidID(offerID) || len(token) != 43 || strings.ContainsAny(token, "\r\n") ||
		len(key) != ed25519.PrivateKeySize {
		return EnrollmentClaim{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return EnrollmentClaim{}, ErrInvalid
	}
	sig := ed25519.Sign(key, enrollmentMessage(offerID, token))
	return EnrollmentClaim{
		OfferID: offerID, Token: token,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// VerifyEnrollmentClaim checks canonical token encoding and proof of possession.
// Core must additionally check the one-time token hash, binding and TTL in a
// single database transaction before issuing a service credential.
func VerifyEnrollmentClaim(claim EnrollmentClaim, public ed25519.PublicKey) bool {
	if !ValidID(claim.OfferID) || len(public) != ed25519.PublicKeySize ||
		len(claim.Token) != 43 || len(claim.Signature) != 86 {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(claim.Token)
	if err != nil || len(token) != 32 ||
		subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(token)), []byte(claim.Token)) != 1 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(claim.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(public, enrollmentMessage(claim.OfferID, claim.Token), signature)
}

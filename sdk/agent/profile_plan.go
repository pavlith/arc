package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

// ProfilePlanRequest is a node-scoped, read-only request for an already
// administrator-approved profile. It is not an apply instruction.
type ProfilePlanRequest struct {
	NodeID    string `json:"node_id"`
	ProfileID string `json:"profile_id"`
	Revision  int64  `json:"revision"`
	RequestID string `json:"request_id"`
}

type ProfilePlanSnapshot struct {
	Version   int         `json:"version"`
	NodeID    string      `json:"node_id"`
	RequestID string      `json:"request_id"`
	IssuedAt  int64       `json:"issued_at"`
	ExpiresAt int64       `json:"expires_at"`
	Profile   NodeProfile `json:"profile"`
}

type SignedProfilePlan struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

const profilePlanDomain = "arc.runtime.profile-plan.v1\n"

func validPlanSnapshot(s ProfilePlanSnapshot) bool {
	return s.Version == 1 && ValidID(s.NodeID) && len(s.RequestID) >= 16 &&
		len(s.RequestID) <= 128 && s.ExpiresAt > s.IssuedAt &&
		s.ExpiresAt-s.IssuedAt <= 30 && s.Profile.Validate() == nil
}

// SignProfilePlan is for Core only; signing an approved profile does not grant
// permission to install packages. A distinct domain separates it from effects.
func SignProfilePlan(s ProfilePlanSnapshot, key ed25519.PrivateKey) (SignedProfilePlan, error) {
	if len(key) != ed25519.PrivateKeySize || !validPlanSnapshot(s) {
		return SignedProfilePlan{}, ErrInvalid
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return SignedProfilePlan{}, ErrInvalid
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		return SignedProfilePlan{}, ErrInvalid
	}
	sig := ed25519.Sign(key, append([]byte(profilePlanDomain), raw...))
	return SignedProfilePlan{Payload: raw, Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

// VerifyProfilePlan checks signature, audience, single-request binding, expiry,
// and the complete immutable profile prior to read-only local APT simulation.
func VerifyProfilePlan(raw []byte, key ed25519.PublicKey, node, requestID string, now time.Time) (ProfilePlanSnapshot, error) {
	var signed SignedProfilePlan
	if len(key) != ed25519.PublicKeySize || strict(raw, &signed) != nil {
		return ProfilePlanSnapshot{}, security.ErrUnauthenticated
	}
	canonical, err := security.CanonicalJSON(signed.Payload)
	if err != nil {
		return ProfilePlanSnapshot{}, security.ErrUnauthenticated
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(profilePlanDomain), canonical...), signature) {
		return ProfilePlanSnapshot{}, security.ErrUnauthenticated
	}
	var snapshot ProfilePlanSnapshot
	if strict(canonical, &snapshot) != nil || !validPlanSnapshot(snapshot) ||
		snapshot.NodeID != node || snapshot.RequestID != requestID ||
		snapshot.IssuedAt > now.Unix() || snapshot.ExpiresAt <= now.Unix() {
		return ProfilePlanSnapshot{}, ErrInvalid
	}
	return snapshot, nil
}

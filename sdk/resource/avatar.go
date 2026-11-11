package resource

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/pavlith/arc/sdk/security"
	"time"
)

type AvatarClaim struct {
	Ref       Ref       `json:"ref"`
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Provider  string    `json:"provider"`
	Kid       string    `json:"kid"`
	ExpiresAt time.Time `json:"expires_at"`
}
type AvatarEnvelope struct {
	Claim     AvatarClaim `json:"claim"`
	Signature string      `json:"signature"`
}

func avatarMessage(c AvatarClaim) []byte {
	raw, _ := json.Marshal(c)
	raw, _ = security.CanonicalJSON(raw)
	return append([]byte("arc.avatar.v1\x00"), raw...)
}
func SignAvatar(key ed25519.PrivateKey, c AvatarClaim) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", security.ErrUnavailable
	}
	raw, err := json.Marshal(AvatarEnvelope{Claim: c, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, avatarMessage(c)))})
	return base64.RawURLEncoding.EncodeToString(raw), err
}
func ParseAvatar(raw string) (AvatarEnvelope, error) {
	var out AvatarEnvelope
	if len(raw) > 4096 {
		return out, security.ErrDenied
	}
	b, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil || json.Unmarshal(b, &out) != nil {
		return out, security.ErrDenied
	}
	return out, nil
}
func VerifyAvatar(key ed25519.PublicKey, e AvatarEnvelope, now time.Time) error {
	c := e.Claim
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(key) != 32 || !ed25519.Verify(key, avatarMessage(c), sig) || !c.Ref.Valid() || c.Ref.Kind != "file" || c.Ref.WorkspaceID != "" || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(65*time.Second)) {
		return security.ErrDenied
	}
	return nil
}

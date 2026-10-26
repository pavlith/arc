package access

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/pavlith/arc/pkgs/security"
	"time"
)

// DomainReceipt attests a committed domain root; it grants no ACL permissions.
type DomainReceipt struct {
	Provider  string    `json:"provider"`
	Root      string    `json:"root"`
	Operation string    `json:"operation"`
	Kid       string    `json:"kid"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte    `json:"signature"`
}

func receiptBytes(r DomainReceipt) []byte { r.Signature = nil; b, _ := json.Marshal(r); return b }
func SignDomainReceipt(key ed25519.PrivateKey, r DomainReceipt) (string, error) {
	if len(key) != 64 {
		return "", ErrUnavailable
	}
	r.Signature = ed25519.Sign(key, receiptBytes(r))
	b, e := json.Marshal(r)
	return base64.RawURLEncoding.EncodeToString(b), e
}

// ReceiptVerifier obtains the provider key online from Identity. The trusted
// provider signs only after its domain root transaction commits.
type ReceiptVerifier struct{ Keys security.Keys }

func (v ReceiptVerifier) Confirm(ctx context.Context, provider, root, op, receipt string) error {
	b, e := base64.RawURLEncoding.DecodeString(receipt)
	if e != nil {
		return ErrDenied
	}
	var r DomainReceipt
	if json.Unmarshal(b, &r) != nil || r.Provider != provider || r.Root != root || r.Operation != op || !r.ExpiresAt.After(time.Now()) || r.ExpiresAt.After(time.Now().Add(5*time.Minute)) {
		return ErrDenied
	}
	if v.Keys == nil {
		return ErrUnavailable
	}
	k, e := v.Keys.CallerKey(ctx, provider, r.Kid)
	if e != nil {
		return e
	}
	if k.Revoked || time.Now().Before(k.NotBefore) || !time.Now().Before(k.ExpiresAt) || len(k.Public) != 32 || !ed25519.Verify(k.Public, receiptBytes(r), r.Signature) {
		return ErrDenied
	}
	return nil
}

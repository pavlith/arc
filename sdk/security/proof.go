package security

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type Proof struct {
	Kid       string `json:"kid"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

func CanonicalJSON(raw []byte) ([]byte, error) { return jsoncanonicalizer.Transform(raw) }

// proof_v1 hashes the complete envelope with only the proof member removed.
// The signed message is an RFC8785 canonical JSON array, avoiding delimiter ambiguity.
func ProofMessage(subject string, envelope []byte, jti string, p Proof) ([]byte, error) {
	var fields map[string]json.RawMessage
	// Canonicalization first rejects duplicate names and invalid Unicode.
	canonical, e := CanonicalJSON(envelope)
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(canonical, &fields); e != nil {
		return nil, e
	}
	delete(fields, "proof")
	raw, e := json.Marshal(fields)
	if e != nil {
		return nil, e
	}
	raw, e = CanonicalJSON(raw)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(raw)
	var id string
	if json.Unmarshal(fields["request_id"], &id) != nil || id == "" || subject == "" || jti == "" || p.Kid == "" || p.Nonce == "" {
		return nil, ErrUnauthenticated
	}
	msg, e := json.Marshal([]string{"proof_v1", subject, id, hex.EncodeToString(sum[:]), jti, p.Timestamp, p.Nonce})
	if e != nil {
		return nil, e
	}
	return CanonicalJSON(msg)
}
func SignProof(key ed25519.PrivateKey, subject string, envelope []byte, jti string, p Proof) (Proof, error) {
	if len(key) != 64 {
		return Proof{}, ErrUnauthenticated
	}
	m, e := ProofMessage(subject, envelope, jti, p)
	if e != nil {
		return Proof{}, e
	}
	p.Signature = b64.EncodeToString(ed25519.Sign(key, m))
	return p, nil
}
func (v Verifier) Proof(ctx context.Context, subject string, envelope []byte, c Claims, p Proof) error {
	if v.Keys == nil || v.Nonces == nil {
		return ErrUnavailable
	}
	if p.Kid != c.Confirmation.Kid || len(p.Nonce) < 16 || len(p.Nonce) > 128 {
		return ErrUnauthenticated
	}
	ts, e := time.Parse(time.RFC3339Nano, p.Timestamp)
	if e != nil || ts.Before(v.Time().Add(-30*time.Second)) || ts.After(v.Time().Add(5*time.Second)) {
		return ErrUnauthenticated
	}
	k, e := v.Keys.CallerKey(ctx, c.Caller, p.Kid)
	if e != nil {
		return e
	}
	if k.Kid != p.Kid || !validKey(k, v.Time()) {
		return ErrUnauthenticated
	}
	m, e := ProofMessage(subject, envelope, c.JTI, p)
	if e != nil {
		return ErrUnauthenticated
	}
	sig, e := b64.DecodeString(p.Signature)
	if e != nil || !ed25519.Verify(k.Public, m, sig) {
		return ErrUnauthenticated
	}
	return v.Nonces.Consume(ctx, "proof:"+c.Caller+":"+p.Kid, p.Nonce, time.Unix(c.ExpiresAt, 0).Add(30*time.Second))
}

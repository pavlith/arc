// Package credentials seals credential submissions and encrypts owner-local data.
// Plaintext never becomes an RPC request or a persisted replay fingerprint.
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"unicode"
	"unicode/utf8"

	"github.com/pavlith/arc/sdk/contract"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var ErrInvalid = errors.New("mail: credential unavailable")

const Algorithm = "nacl-box-anonymous-v1"

type Binding struct {
	AccountID  string `json:"account_id"`
	OwnerID    string `json:"owner_id"`
	Generation int64  `json:"generation"`
	Revision   int64  `json:"revision"`
}
type PublicInfo struct {
	Binding
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}
type submission struct {
	Binding
	Password []byte `json:"password"`
}
type Vault struct {
	private, public [32]byte
	storage         cipher.AEAD
	id              string
}

func New(master []byte) (*Vault, error) {
	if len(master) != 32 {
		return nil, ErrInvalid
	}
	zero := true
	for _, b := range master {
		zero = zero && b == 0
	}
	if zero {
		return nil, ErrInvalid
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, master)
		mac.Write([]byte("arc.mail.credentials.v1/" + label))
		return mac.Sum(nil)
	}
	v := &Vault{}
	private := derive("sealing")
	copy(v.private[:], private)
	clear(private)
	curve25519.ScalarBaseMult(&v.public, &v.private)
	key := derive("storage")
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, ErrInvalid
	}
	v.storage, err = cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(v.public[:])
	v.id = hex.EncodeToString(sum[:])
	return v, nil
}
func Load(path string) (*Vault, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() != 32 {
		return nil, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() != 32 {
		return nil, ErrInvalid
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	defer clear(key)
	if err != nil {
		return nil, ErrInvalid
	}
	return New(key)
}
func (v *Vault) Public(binding Binding) PublicInfo {
	return PublicInfo{Binding: binding, KeyID: v.id, Algorithm: Algorithm, PublicKey: base64.RawURLEncoding.EncodeToString(v.public[:])}
}
func validPassword(p []byte) bool {
	if len(p) == 0 || len(p) > 4096 || !utf8.Valid(p) {
		return false
	}
	for _, r := range string(p) {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Seal is a caller-side helper. The randomized sealed box, not the password,
// enters the ordinary signed operation and its canonical request hash.
func Seal(info PublicInfo, password []byte) (string, error) {
	if info.Algorithm != Algorithm || !validPassword(password) {
		return "", ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(info.PublicKey)
	if err != nil || len(raw) != 32 {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != info.KeyID {
		return "", ErrInvalid
	}
	var public [32]byte
	copy(public[:], raw)
	message, err := json.Marshal(submission{Binding: info.Binding, Password: password})
	defer clear(message)
	if err != nil {
		return "", ErrInvalid
	}
	sealed, err := box.SealAnonymous(nil, message, &public, rand.Reader)
	if err != nil {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (v *Vault) Unseal(keyID, sealed string, want Binding) ([]byte, error) {
	if keyID != v.id || len(sealed) > 16384 {
		return nil, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) > 12000 {
		return nil, ErrInvalid
	}
	plain, ok := box.OpenAnonymous(nil, raw, &v.public, &v.private)
	defer clear(plain)
	if !ok {
		return nil, ErrInvalid
	}
	var msg submission
	if contract.Strict(plain, &msg) != nil || msg.Binding != want || !validPassword(msg.Password) {
		clear(msg.Password)
		return nil, ErrInvalid
	}
	return msg.Password, nil
}
func aad(binding Binding, version int64) []byte {
	// Revision protects ingress CAS only; stored data survives nonbinding edits.
	raw, _ := json.Marshal(struct {
		AccountID, OwnerID  string
		Generation, Version int64
		Purpose             string
	}{binding.AccountID, binding.OwnerID, binding.Generation, version, "mail.personal.password.v1"})
	return raw
}
func (v *Vault) Encrypt(binding Binding, version int64, password []byte) (string, []byte, error) {
	if !validPassword(password) || version < 1 {
		return "", nil, ErrInvalid
	}
	nonce := make([]byte, v.storage.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, ErrInvalid
	}
	return v.id, v.storage.Seal(nonce, nonce, password, aad(binding, version)), nil
}
func (v *Vault) Decrypt(binding Binding, version int64, keyID string, data []byte) ([]byte, error) {
	if keyID != v.id || len(data) < v.storage.NonceSize()+v.storage.Overhead() || len(data) > 4096+v.storage.NonceSize()+v.storage.Overhead() {
		return nil, ErrInvalid
	}
	nonce := data[:v.storage.NonceSize()]
	plain, err := v.storage.Open(nil, nonce, data[len(nonce):], aad(binding, version))
	if err != nil || !validPassword(plain) {
		clear(plain)
		return nil, ErrInvalid
	}
	return plain, nil
}

// ReadPassword accepts a file or pipe; CR/LF are never trimmed or silently changed.
func ReadPassword(r io.Reader) ([]byte, error) {
	p, err := io.ReadAll(io.LimitReader(r, 4097))
	if err != nil || !validPassword(p) {
		clear(p)
		return nil, ErrInvalid
	}
	return p, nil
}

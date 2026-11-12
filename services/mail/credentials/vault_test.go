package credentials

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestSealScopeVersionStorageAndKeyIsolation(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	v, err := New(master)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{AccountID: "account", OwnerID: "owner", Generation: 1, Revision: 1}
	info := v.Public(b)
	password := []byte("a password \\\" with spaces")
	a, err := Seal(info, password)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Seal(info, password)
	if err != nil || a == other {
		t.Fatal("seal is not randomized", err)
	}
	got, err := v.Unseal(info.KeyID, a, b)
	if err != nil || !bytes.Equal(got, password) {
		t.Fatal("unseal", err)
	}
	defer clear(got)
	for _, bad := range []Binding{{AccountID: "other", OwnerID: b.OwnerID, Generation: 1, Revision: 1}, {AccountID: b.AccountID, OwnerID: "other", Generation: 1, Revision: 1}, {AccountID: b.AccountID, OwnerID: b.OwnerID, Generation: 2, Revision: 1}, {AccountID: b.AccountID, OwnerID: b.OwnerID, Generation: 1, Revision: 2}} {
		if _, err := v.Unseal(info.KeyID, a, bad); err == nil {
			t.Fatal("ingress binding bypass")
		}
	}
	key, ciphertext, err := v.Encrypt(b, 1, password)
	if err != nil || bytes.Contains(ciphertext, password) {
		t.Fatal("at-rest encryption", err)
	}
	b.Revision = 4
	got, err = v.Decrypt(b, 1, key, ciphertext)
	if err != nil || !bytes.Equal(got, password) {
		t.Fatal("cosmetic edit invalidated credential", err)
	}
	if _, err := v.Decrypt(b, 2, key, ciphertext); err == nil {
		t.Fatal("stored version binding bypass")
	}
	b.Generation = 2
	if _, err := v.Decrypt(b, 1, key, ciphertext); err == nil {
		t.Fatal("stored generation binding bypass")
	}
	b.Generation = 1
	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := v.Decrypt(b, 1, key, ciphertext); err == nil {
		t.Fatal("tampering accepted")
	}
	master[0] ^= 1
	wrong, _ := New(master)
	if _, err := wrong.Unseal(info.KeyID, a, info.Binding); err == nil {
		t.Fatal("wrong master unsealed")
	}
	if _, err := wrong.Decrypt(b, 1, key, ciphertext); err == nil {
		t.Fatal("wrong master decrypted")
	}
}
func TestPrivateKeyFileAndPasswordBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	key := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("public master accepted")
	}
	for _, p := range [][]byte{nil, []byte("bad\r\n"), {0}, bytes.Repeat([]byte{'a'}, 4097), {255}} {
		if _, err := ReadPassword(bytes.NewReader(p)); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
}

package enrollment

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestCreatePrivateKeyFileAndPreventReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.seed")
	pub, err := CreateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != ed25519.SeedSize {
		t.Fatalf("invalid seed: %v", err)
	}
	expected := ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)
	decoded, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || string(decoded) != string(expected) {
		t.Fatal("wrong published key")
	}
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		t.Fatal("secret file must be private")
	}
	if _, err := CreateKeyFile(path); err == nil {
		t.Fatal("existing secret overwritten")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || string(unchanged) != string(raw) {
		t.Fatal("existing secret was changed")
	}
	link := filepath.Join(dir, "link.seed")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateKeyFile(link); err == nil {
		t.Fatal("symlink destination accepted")
	}
	if _, err := CreateKeyFile("relative.seed"); err == nil {
		t.Fatal("relative secret path accepted")
	}
}

func TestCreateKeyRequiresPrivateOwnerDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateKeyFile(filepath.Join(dir, "test.seed")); err == nil {
		t.Fatal("world-readable key parent accepted")
	}
}

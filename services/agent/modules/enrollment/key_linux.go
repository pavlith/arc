// Package enrollment handles local, offline bootstrap key material. It never
// grants permissions or connects to Core or NATS.
package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var ErrInvalid = errors.New("enrollment: invalid private key location")
var ErrUnavailable = errors.New("enrollment: local key generation unavailable")

// CreateKeyFile creates a new host-owned Ed25519 service seed with mode 0600.
// It requires a private, existing, process-owned directory and refuses to
// replace existing files (including symlinks). Only the public key is returned.
func CreateKeyFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrInvalid
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return "", ErrInvalid
	}
	stat, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", ErrInvalid
	}
	var seed [ed25519.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return "", ErrUnavailable
	}
	defer clear(seed[:])
	key := ed25519.NewKeyFromSeed(seed[:])
	defer clear(key)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", ErrUnavailable
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if n, err := file.Write(seed[:]); err != nil || n != len(seed) {
		return "", ErrUnavailable
	}
	if file.Sync() != nil || file.Close() != nil {
		return "", ErrUnavailable
	}
	complete = true
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

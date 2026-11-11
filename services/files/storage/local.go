// Package storage provides a private, bounded local byte store for Files.
// It is an internal adapter only: the caller must authenticate and authorize
// every upload/download and bind keys to its own scoped SQL upload records.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

const (
	MaxObjectSize = int64(1 << 30)
	MaxChunkSize  = int64(8 << 20)
)

var (
	ErrInvalid  = errors.New("files storage: invalid key, size or input")
	ErrConflict = errors.New("files storage: existing object or wrong offset")
	ErrMissing  = errors.New("files storage: object unavailable")

	keyPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Object struct {
	Key    string
	Size   int64
	SHA256 string
}

// Local uses os.Root-relative paths. No browser-supplied paths, names or
// absolute paths are ever concatenated into the storage namespace.
type Local struct {
	root *os.Root
	mu sync.Mutex // serializes offset checks, appends, promotion and abort
}

func validKey(key string) bool { return keyPattern.MatchString(key) }
func pendingPath(key string) string { return "pending/" + key + ".part" }
func objectPath(key string) string { return "objects/" + key + ".blob" }

// OpenLocal requires an absolute, private directory owned by the Files process.
// These storage directories must not be publicly served by Gate.
func OpenLocal(path string) (*Local, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, fmt.Errorf("%w: create root: %v", ErrMissing, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open root: %v", ErrMissing, err)
	}
	for _, name := range []string{"pending", "objects"} {
		if err := root.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			_ = root.Close()
			return nil, fmt.Errorf("%w: create directory: %v", ErrMissing, err)
		}
		stat, err := root.Lstat(name)
		if err != nil || !stat.IsDir() || stat.Mode().Perm()&0077 != 0 {
			_ = root.Close()
			return nil, ErrInvalid
		}
	}
	return &Local{root: root}, nil
}

func (s *Local) Close() error {
	if s == nil { return nil }
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil { return nil }
	err := s.root.Close()
	s.root = nil
	return err
}

func (s *Local) check(ctx context.Context, key string) error {
	if s == nil || s.root == nil || ctx == nil || !validKey(key) { return ErrInvalid }
	return ctx.Err()
}

func (s *Local) regular(name string) error {
	info, err := s.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) { return ErrMissing }
	if err != nil { return fmt.Errorf("%w: lstat: %v", ErrMissing, err) }
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 { return ErrInvalid }
	return nil
}

// Prepare creates a new, empty pending object. It must be called only after
// a scoped upload record is committed. Existing keys are never truncated.
func (s *Local) Prepare(ctx context.Context, uploadID string) error {
	if err := s.check(ctx, uploadID); err != nil { return err }
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.root.OpenFile(pendingPath(uploadID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) { return ErrConflict }
	if err != nil { return fmt.Errorf("%w: create pending: %v", ErrMissing, err) }
	return f.Close()
}

// Offset reports committed physical bytes. The SQL upload offset must be
// checked independently; an interrupted process may require reconciliation.
func (s *Local) Offset(ctx context.Context, uploadID string) (int64, error) {
	if err := s.check(ctx, uploadID); err != nil { return 0, err }
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.regular(pendingPath(uploadID)); err != nil { return 0, err }
	f, err := s.root.Open(pendingPath(uploadID))
	if err != nil { return 0, ErrMissing }
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() { return 0, ErrMissing }
	return info.Size(), nil
}

// Append writes exactly length bytes at the existing physical offset using
// at most 64 KiB in memory. On a short read, cancellation or write failure,
// it truncates back to the prior offset. No sparse writes or blind retries.
func (s *Local) Append(ctx context.Context, uploadID string, offset, length int64, body io.Reader) (int64, error) {
	if err := s.check(ctx, uploadID); err != nil { return 0, err }
	if body == nil || length <= 0 || length > MaxChunkSize || offset < 0 ||
		offset > MaxObjectSize || length > MaxObjectSize-offset { return 0, ErrInvalid }
	s.mu.Lock()
	defer s.mu.Unlock()
	path := pendingPath(uploadID)
	if err := s.regular(path); err != nil { return 0, err }
	f, err := s.root.OpenFile(path, os.O_RDWR, 0)
	if err != nil { return 0, ErrMissing }
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() { return 0, ErrMissing }
	if info.Size() != offset { return info.Size(), ErrConflict }
	if _, err := f.Seek(offset, io.SeekStart); err != nil { return offset, ErrMissing }
	rollback := func(err error) (int64,error) {
		if truncateErr := f.Truncate(offset); truncateErr != nil {
			return offset, fmt.Errorf("%w: rollback failed: %v", ErrMissing, truncateErr)
		}
		return offset, err
	}
	buf := make([]byte, 64<<10)
	remaining := length
	for remaining > 0 {
		if err := ctx.Err(); err != nil { return rollback(err) }
		want := int64(len(buf))
		if remaining < want { want = remaining }
		n, readErr := io.ReadFull(body, buf[:int(want)])
		if n > 0 {
			written, writeErr := f.Write(buf[:n])
			if writeErr != nil { return rollback(writeErr) }
			if written != n { return rollback(io.ErrShortWrite) }
			remaining -= int64(n)
		}
		if readErr != nil { return rollback(readErr) }
	}
	if err := ctx.Err(); err != nil { return rollback(err) }
	// A supplied body must end at the declared length, not conceal extra data.
	var one [1]byte
	n, err := body.Read(one[:])
	if n > 0 || err != nil && !errors.Is(err, io.EOF) { return rollback(ErrInvalid) }
	if err := f.Sync(); err != nil { return rollback(err) }
	return offset+length,nil
}

// Promote verifies the complete pending object's length and SHA-256, then
// hard-links it under a new, exclusive object key. A later SQL failure leaves
// a bounded orphan for reconciliation; this adapter cannot commit SQL.
func (s *Local) Promote(ctx context.Context, uploadID, objectID string, size int64, expectedSHA256 string) (Object,error) {
	if err := s.check(ctx, uploadID); err != nil { return Object{},err }
	if !validKey(objectID) || size < 0 || size > MaxObjectSize ||
		expectedSHA256 != "" && !hashPattern.MatchString(expectedSHA256) { return Object{},ErrInvalid }
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := pendingPath(uploadID)
	if err := s.regular(pending); err != nil { return Object{},err }
	f, err := s.root.Open(pending)
	if err != nil { return Object{},ErrMissing }
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() { return Object{},ErrMissing }
	if info.Size() != size { return Object{},ErrConflict }
	hash := sha256.New()
	buf := make([]byte,64<<10)
	for {
		if err := ctx.Err(); err != nil { return Object{},err }
		n, readErr := f.Read(buf)
		if n > 0 { _,_ = hash.Write(buf[:n]) }
		if errors.Is(readErr,io.EOF) { break }
		if readErr != nil { return Object{},ErrMissing }
		if n == 0 { return Object{},io.ErrNoProgress }
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	if expectedSHA256 != "" && sum != expectedSHA256 { return Object{},ErrConflict }
	if err := ctx.Err(); err != nil { return Object{},err }
	// Link never replaces an existing key; pending bytes remain on failure.
	if err := s.root.Link(pending,objectPath(objectID)); err != nil {
		if errors.Is(err,os.ErrExist) { return Object{},ErrConflict }
		return Object{},fmt.Errorf("%w: promote: %v",ErrMissing,err)
	}
	if err := s.root.Remove(pending); err != nil {
		return Object{},fmt.Errorf("%w: pending cleanup: %v",ErrMissing,err)
	}
	return Object{Key:objectID,Size:size,SHA256:sum},nil
}

// Open returns an owned read-only file descriptor. Caller must close it and
// periodically recheck its live stream permission during long downloads.
func (s *Local) Open(ctx context.Context, objectID string) (*os.File,error) {
	if err := s.check(ctx,objectID); err != nil { return nil,err }
	s.mu.Lock()
	defer s.mu.Unlock()
	path := objectPath(objectID)
	if err := s.regular(path); err != nil { return nil,err }
	f,err := s.root.Open(path)
	if err != nil { return nil,ErrMissing }
	info,err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil,ErrMissing
	}
	return f,nil
}

// Abort is safe to retry and cannot delete a promoted object.
func (s *Local) Abort(ctx context.Context, uploadID string) error {
	if err := s.check(ctx,uploadID); err != nil { return err }
	s.mu.Lock()
	defer s.mu.Unlock()
	path := pendingPath(uploadID)
	if err := s.root.Remove(path); err != nil && !errors.Is(err,os.ErrNotExist) {
		return fmt.Errorf("%w: abort: %v",ErrMissing,err)
	}
	return nil
}

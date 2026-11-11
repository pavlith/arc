// Package journal provides the Agent's private, exclusively locked durable state.
package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

// Store holds an OS lock for its full lifetime. A second process must fail
// before touching any host API. The directory must be dedicated to this Agent.
type Store struct {
	mu      sync.Mutex
	dir     string
	lock    *os.File
	records map[string]agent.Record
}

func Open(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, agent.ErrInvalid
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, owned := info.Sys().(*syscall.Stat_t)
	if !owned || stat.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, agent.ErrInvalid
	}
	lock, err := os.OpenFile(filepath.Join(dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	s := &Store{dir: dir, lock: lock, records: map[string]agent.Record{}}
	f, err := os.Open(filepath.Join(dir, "revisions.json"))
	if errors.Is(err, os.ErrNotExist) {
		if err := s.readRevisionFiles(); err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil || len(raw) > 16<<20 {
		s.Close()
		return nil, agent.ErrInvalid
	}
	_, err = security.CanonicalJSON(raw)
	if err != nil {
		s.Close()
		return nil, agent.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&s.records)
	if err == nil {
		if s.records == nil {
			err = agent.ErrInvalid
		}
		for id, r := range s.records {
			if !agent.ValidID(id) || r.Revision < 1 || len(r.Digest) != 64 || !agent.ValidID(r.OperationID) {
				err = agent.ErrInvalid
				break
			}
		}
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := s.readRevisionFiles(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Load(ctx context.Context, id string) (agent.Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return agent.Record{}, false, err
	}
	if s.lock == nil {
		return agent.Record{}, false, os.ErrClosed
	}
	r, ok := s.records[id]
	return r, ok, nil
}
func (s *Store) Save(ctx context.Context, id string, r agent.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.lock == nil {
		return os.ErrClosed
	}
	if !agent.ValidID(id) || r.Revision < 1 || len(r.Digest) != 64 || !agent.ValidID(r.OperationID) {
		return agent.ErrInvalid
	}
	if old, ok := s.records[id]; ok && (r.Revision < old.Revision || (r.Revision == old.Revision && (r.Digest != old.Digest || r.OperationID != old.OperationID))) {
		return agent.ErrStale
	}
	if old, ok := s.records[id]; ok && r.Revision == old.Revision && old.Complete && r != old {
		return agent.ErrStale
	}
	// Persist only the changed resource. Existing revisions.json is retained
	// as a read-only migration baseline; never rewrite the entire JSON map.
	if err := s.writeRevision(id, r); err != nil {
		return err
	}
	s.records[id] = r
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

const maxPendingSize = 32 << 10

// pendingPath is not influenced by a remote path: resource IDs are validated.
func (s *Store) pendingPath(id string) (string, error) {
	if !agent.ValidID(id) {
		return "", agent.ErrInvalid
	}
	return filepath.Join(s.dir, "pending-"+id+".json"), nil
}

// loadPending is called with s.mu held.
func (s *Store) loadPending(id string) (agent.Report, bool, error) {
	path, err := s.pendingPath(id)
	if err != nil {
		return agent.Report{}, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return agent.Report{}, false, nil
	}
	if err != nil {
		return agent.Report{}, false, security.ErrUnavailable
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return agent.Report{}, false, security.ErrDenied
	}
	f, err := os.Open(path)
	if err != nil {
		return agent.Report{}, false, security.ErrUnavailable
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPendingSize+1))
	if err != nil || len(raw) > maxPendingSize {
		return agent.Report{}, false, security.ErrUnavailable
	}
	if _, err := security.CanonicalJSON(raw); err != nil {
		return agent.Report{}, false, security.ErrUnavailable
	}
	var report agent.Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&report) != nil || dec.Decode(new(any)) != io.EOF ||
		!agent.ValidID(report.EventID) || !agent.ValidID(report.OperationID) ||
		report.Observation.ResourceID != id || !agent.ValidID(report.Observation.NodeID) {
		return agent.Report{}, false, security.ErrUnavailable
	}
	return report, true, nil
}

func (s *Store) LoadPending(ctx context.Context, id string) (agent.Report, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return agent.Report{}, false, err
	}
	if s.lock == nil {
		return agent.Report{}, false, os.ErrClosed
	}
	return s.loadPending(id)
}

// SavePending uses the same fsync/rename discipline as the revision journal.
// An unacknowledged receipt cannot be silently replaced with another event.
func (s *Store) SavePending(ctx context.Context, id string, report agent.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.lock == nil {
		return os.ErrClosed
	}
	path, err := s.pendingPath(id)
	if err != nil {
		return err
	}
	if !agent.ValidID(report.EventID) || !agent.ValidID(report.OperationID) ||
		report.Observation.ResourceID != id || !agent.ValidID(report.Observation.NodeID) {
		return agent.ErrInvalid
	}
	old, exists, err := s.loadPending(id)
	if err != nil {
		return err
	}
	if exists {
		if reflect.DeepEqual(old, report) {
			return nil
		}
		return agent.ErrStale
	}
	raw, err := json.Marshal(report)
	if err != nil || len(raw) > maxPendingSize {
		return agent.ErrInvalid
	}
	f, err := os.CreateTemp(s.dir, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Store) DeletePending(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.lock == nil {
		return os.ErrClosed
	}
	path, err := s.pendingPath(id)
	if err != nil {
		return err
	}
	if _, exists, err := s.loadPending(id); err != nil || !exists {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

var _ agent.ReportJournal = (*Store)(nil)

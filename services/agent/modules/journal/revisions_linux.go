package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

const maxRevisionFileSize = 4096

// revisionDirectory keeps each resource's high-water mark independent.
// Only per-resource revision files are supported.
func (s *Store) revisionDirectory() (string, error) {
	dir := filepath.Join(s.dir, "revisions")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", security.ErrDenied
	}
	return dir, nil
}

func validRecord(id string, r agent.Record) bool {
	return agent.ValidID(id) && r.Revision >= 1 && len(r.Digest) == 64 && agent.ValidID(r.OperationID)
}

func (s *Store) readRevisionFiles() error {
	dir, err := s.revisionDirectory()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".revision-") {
			// An interrupted temp write has never been committed by rename.
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return agent.ErrInvalid
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !agent.ValidID(id) {
			return agent.ErrInvalid
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return security.ErrDenied
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, maxRevisionFileSize+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(raw) > maxRevisionFileSize {
			return agent.ErrInvalid
		}
		if _, err := security.CanonicalJSON(raw); err != nil {
			return agent.ErrInvalid
		}
		var r agent.Record
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&r) != nil || dec.Decode(new(any)) != io.EOF || !validRecord(id, r) {
			return agent.ErrInvalid
		}
		if old, exists := s.records[id]; exists {
			if r.Revision < old.Revision || (r.Revision == old.Revision && (r.Digest != old.Digest || r.OperationID != old.OperationID || old.Complete && !r.Complete)) {
				return agent.ErrStale
			}
		}
		s.records[id] = r
	}
	return nil
}

func (s *Store) writeRevision(id string, r agent.Record) error {
	dir, err := s.revisionDirectory()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > maxRevisionFileSize {
		return agent.ErrInvalid
	}
	file, err := os.CreateTemp(dir, ".revision-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), filepath.Join(dir, id+".json")); err != nil {
		return err
	}
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

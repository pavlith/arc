package docker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/pavlith/arc/sdk/security"
)

const maxOwnershipSize = 32 << 10

var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)
var imageID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var containerName = regexp.MustCompile(`^arc-managed-[a-f0-9]{32}$`)

type ownership struct {
	Name  string `json:"name"`
	ID    string `json:"id,omitempty"`
	Image string `json:"image"`
}

func privateDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return security.ErrDenied
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func (d *Driver) load(resource string) ([]ownership, error) {
	file, err := os.Open(filepath.Join(d.dir, resource+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, security.ErrUnavailable
	}
	defer file.Close()
	var records []ownership
	raw, err := io.ReadAll(io.LimitReader(file, maxOwnershipSize+1))
	if err != nil || len(raw) > maxOwnershipSize || json.Unmarshal(raw, &records) != nil || records == nil || len(records) > 100 {
		return nil, security.ErrUnavailable
	}
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, record := range records {
		if !containerName.MatchString(record.Name) || names[record.Name] || !imageID.MatchString(record.Image) ||
			(record.ID != "" && (!containerID.MatchString(record.ID) || ids[record.ID])) {
			return nil, security.ErrUnavailable
		}
		names[record.Name] = true
		ids[record.ID] = true
	}
	return records, nil
}

func (d *Driver) save(ctx context.Context, resource string, records []ownership) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.write(resource, records); err != nil {
		return security.ErrUnavailable
	}
	return nil
}

func (d *Driver) write(resource string, records []ownership) error {
	raw, err := json.Marshal(records)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(d.dir, ".ownership-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(d.dir, resource+".json")); err != nil {
		return err
	}
	dir, err := os.Open(d.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

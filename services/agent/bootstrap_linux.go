package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pavlith/arc/sdk"
	contract "github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/agent/modules/docker"
	"github.com/pavlith/arc/services/agent/modules/host"
	"github.com/pavlith/arc/services/agent/modules/journal"
	"github.com/pavlith/arc/services/agent/modules/systemd"
)

// FileConfig contains references to independent Agent credentials, never keys.
type FileConfig struct {
	NodeID              string              `json:"node_id"`
	ServiceID           string              `json:"service_id"`
	Kid                 string              `json:"kid"`
	KeyFile             string              `json:"key_file"`
	CoreSnapshotKeyFile string              `json:"core_snapshot_key_file"`
	StateDirectory      string              `json:"state_directory"`
	NATS                sdk.Config          `json:"nats"`
	PollSeconds         int                 `json:"poll_seconds"`
	Templates           []contract.Template `json:"templates"`
}

func readOwned(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, ErrInvalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}
func ReadConfig(path string) (FileConfig, error) {
	var cfg FileConfig
	raw, err := readOwned(path, true, 256<<10)
	if err != nil {
		return cfg, ErrInvalid
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		return cfg, ErrInvalid
	}
	// Canonical JSON rejects duplicate names; decoding again rejects unknown fields.
	if err := strictConfig(raw, &cfg); err != nil {
		return cfg, ErrInvalid
	}
	if !contract.ValidID(cfg.NodeID) || cfg.ServiceID == "" || len(cfg.ServiceID) > 128 || cfg.Kid == "" || !filepath.IsAbs(cfg.StateDirectory) || cfg.PollSeconds < 1 || cfg.PollSeconds > 60 || !filepath.IsAbs(cfg.KeyFile) || !filepath.IsAbs(cfg.CoreSnapshotKeyFile) || len(cfg.Templates) > 100 {
		return cfg, ErrInvalid
	}
	seen := map[string]bool{}
	for _, t := range cfg.Templates {
		if t.Validate() != nil || seen[t.ID] {
			return cfg, ErrInvalid
		}
		switch t.Kind {
		case contract.Docker:
		case contract.Systemd:
			if t.Target != "arc-managed-"+t.ID+".service" {
				return cfg, ErrInvalid
			}
		default:
			return cfg, ErrInvalid
		}
		seen[t.ID] = true
	}
	if cfg.NATS.URL == "" || !filepath.IsAbs(cfg.NATS.NKeySeedFile) || !filepath.IsAbs(cfg.NATS.TLSCAFile) {
		return cfg, ErrInvalid
	}
	if cfg.NATS.InboxPrefix != "" && cfg.NATS.InboxPrefix != "_INBOX.runtime."+cfg.NodeID {
		return cfg, ErrInvalid
	}
	return cfg, nil
}
func RunFile(ctx context.Context, path string) error {
	cfg, err := ReadConfig(path)
	if err != nil {
		return ErrInvalid
	}
	store, err := journal.Open(cfg.StateDirectory)
	if err != nil {
		return ErrInvalid
	}
	defer store.Close()
	templates := make(map[string]contract.Template, len(cfg.Templates))
	drivers := map[contract.Kind]contract.Driver{contract.Systemd: systemd.New()}
	for _, t := range cfg.Templates {
		templates[t.ID] = t
		if t.Kind == contract.Docker && drivers[t.Kind] == nil {
			driver, err := docker.Open(cfg.StateDirectory, cfg.NodeID)
			if err != nil {
				return ErrInvalid
			}
			defer driver.Close()
			drivers[t.Kind] = driver
		}
	}
	link, err := openNodeClient(ctx, cfg)
	if err != nil {
		return err
	}
	defer link.Close()
	service, err := New(Config{
		NodeID: cfg.NodeID, Provider: link.provider, CoreKey: link.coreKey, Templates: templates,
		Journal: store, Drivers: drivers, PollInterval: time.Duration(cfg.PollSeconds) * time.Second, HostFacts: host.Collect,
		Observe: func(resource, code string) { slog.Warn("agent reconciliation", "resource_id", resource, "code", code) },
	})
	if err != nil {
		return err
	}
	slog.Info("agent started", "node_id", cfg.NodeID)
	return service.Run(ctx)
}

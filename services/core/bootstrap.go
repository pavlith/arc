package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/migrations"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
)

// BootstrapConfig references operator-provisioned files, never inline secrets.
// Runtime management and node RPC have no configuration switch: both stay off
// until a trusted live policy is supplied by a separate administrative adapter.
type BootstrapConfig struct {
	SQLitePath                  string     `json:"sqlite_path"`
	NATS                        sdk.Config `json:"nats"`
	IdentitySigningKid          string     `json:"identity_signing_kid"`
	IdentityKeyFile             string     `json:"identity_key_file"`
	IdentityKeyExpiresAt        time.Time  `json:"identity_key_expires_at"`
	InstallationApprovalKeyFile string     `json:"installation_approval_key_file"`
	ContractBootstrapFiles      []string   `json:"contract_bootstrap_files"`
	SnapshotKid                 string     `json:"snapshot_kid"`
	SnapshotKeyFile             string     `json:"snapshot_key_file"`
	RouteTrustKeyFile           string     `json:"route_trust_key_file"`
}

func readBootstrapFile(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 ||
		private && info.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}

func readBootstrapJSON(path string, out any) error {
	raw, err := readBootstrapFile(path, false, 256<<10)
	if err != nil || contract.Strict(raw, out) != nil {
		return ErrInvalid
	}
	return nil
}

func readBootstrapKey(path string) (ed25519.PrivateKey, error) {
	seed, err := readBootstrapFile(path, true, ed25519.SeedSize)
	defer clear(seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrInvalid
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func readBootstrapConfig(path string) (BootstrapConfig, error) {
	var cfg BootstrapConfig
	if err := readBootstrapJSON(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.IdentitySigningKid == "" || cfg.SnapshotKid == "" || !cfg.IdentityKeyExpiresAt.After(time.Now()) ||
		len(cfg.ContractBootstrapFiles) == 0 || len(cfg.ContractBootstrapFiles) > 32 {
		return cfg, ErrInvalid
	}
	for _, path := range append([]string{cfg.SQLitePath, cfg.IdentityKeyFile, cfg.InstallationApprovalKeyFile,
		cfg.SnapshotKeyFile, cfg.RouteTrustKeyFile, cfg.NATS.TLSCAFile, cfg.NATS.NKeySeedFile}, cfg.ContractBootstrapFiles...) {
		if !filepath.IsAbs(path) {
			return cfg, ErrInvalid
		}
	}
	u, err := url.Parse(cfg.NATS.URL)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return cfg, ErrInvalid
	}
	return cfg, nil
}

// requireCoreSchema checks migration history without creating/upgrading anything.
func requireCoreSchema(ctx context.Context, db *gorm.DB) error {
	var version int
	if db.WithContext(ctx).Raw("SELECT schema_version FROM core_schema_info WHERE singleton=1").Row().Scan(&version) != nil || version != 1 {
		return ErrInvalid
	}
	var ids []string
	if db.WithContext(ctx).Raw("SELECT id FROM schema_migrations ORDER BY id").Scan(&ids).Error != nil {
		return ErrInvalid
	}
	want := migrations.SQLite()
	if len(ids) != len(want) {
		return ErrInvalid
	}
	for i, id := range ids {
		if id != want[i].ID {
			return ErrInvalid
		}
	}
	return nil
}

// The configured expiry is absolute: a restart must not extend trust or revive
// a revoked key. A new kid is published once through the existing audited API.
func ensureBootstrapSigningKey(ctx context.Context, id *identity.Core, expires time.Time) error {
	key, err := id.SigningKey(ctx, id.SigningKid)
	if errors.Is(err, security.ErrUnauthenticated) {
		return id.PublishSigningKey(ctx, expires)
	}
	now := time.Now()
	if err != nil || key.Revoked || key.NotBefore.After(now) || !key.ExpiresAt.After(now) ||
		!key.ExpiresAt.Equal(expires) || !bytes.Equal(key.Public, id.PrivateKey.Public().(ed25519.PublicKey)) {
		return ErrInvalid
	}
	return nil
}

// Run owns Core's database and private NATS service. Migrations, user/service
// provisioning and signed domain installations remain separate operator steps.
func Run(ctx context.Context, path string) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	cfg, err := readBootstrapConfig(path)
	if err != nil {
		return ErrInvalid
	}
	var keys [3]ed25519.PrivateKey
	for i, path := range []string{cfg.IdentityKeyFile, cfg.SnapshotKeyFile, cfg.RouteTrustKeyFile} {
		keys[i], err = readBootstrapKey(path)
		if err != nil {
			return errors.New("core: signing seed unavailable securely")
		}
	}
	public, err := readBootstrapFile(cfg.InstallationApprovalKeyFile, false, 4096)
	var encoded string
	if err != nil || json.Unmarshal(public, &encoded) != nil {
		return errors.New("core: invalid operator trust root")
	}
	approvalKey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(approvalKey) != ed25519.PublicKeySize {
		return errors.New("core: invalid operator trust root")
	}
	var approvals []access.Approved
	for _, path := range cfg.ContractBootstrapFiles {
		var signed access.Approved
		var policy access.Approval
		if readBootstrapJSON(path, &signed) != nil || contract.Strict(signed.Payload, &policy) != nil {
			return errors.New("core: invalid bootstrap approval document")
		}
		approvals = append(approvals, signed)
	}
	if _, err := access.NewContracts(approvalKey, approvals); err != nil {
		return errors.New("core: invalid bootstrap approval signature or policy")
	}
	brokerSeed, err := readBootstrapFile(cfg.NATS.NKeySeedFile, true, 4096)
	clear(brokerSeed)
	if err != nil {
		return errors.New("core: broker seed unavailable securely")
	}
	if _, err := readBootstrapFile(cfg.NATS.TLSCAFile, false, 256<<10); err != nil {
		return errors.New("core: broker trust root unavailable securely")
	}
	// Require an existing, private owner file; database.Open alone would create it.
	info, err := os.Lstat(cfg.SQLitePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	db, err := database.Open(startup, cfg.SQLitePath)
	if err != nil {
		return errors.New("core: owner database unavailable")
	}
	defer database.Close(db)
	if requireCoreSchema(startup, db) != nil {
		return errors.New("core: explicit Core migrations required")
	}
	app, err := New(Config{
		GormDB: db, NATS: cfg.NATS, Version: "0.1.0",
		IdentitySigningKid: cfg.IdentitySigningKid, IdentitySigningKey: keys[0],
		InstallationApprovalKey: approvalKey, ContractBootstrap: approvals,
		SnapshotKid: cfg.SnapshotKid, SnapshotSigningKey: keys[1], RouteTrustKey: keys[2],
		RuntimeAuthorize: func(context.Context, string, string) error { return security.ErrDenied },
	})
	if err != nil {
		return ErrInvalid
	}
	defer app.Stop()
	// Verify both pinned bootstrap policy and every persisted active installation
	// before any NATS endpoint becomes reachable.
	if _, err := app.Fabric.LoadAccess(startup); err != nil {
		return errors.New("core: invalid signed approvals")
	}
	if ensureBootstrapSigningKey(startup, app.Identity, cfg.IdentityKeyExpiresAt) != nil {
		return errors.New("core: invalid Identity signing key metadata")
	}
	if err := app.Start(startup); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("core: private NATS startup failed")
	}
	cancel()
	slog.Info("core started")
	<-ctx.Done()
	if err := app.Stop(); err != nil {
		return errors.New("core: private NATS shutdown failed")
	}
	return nil
}

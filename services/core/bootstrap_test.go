package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/migrations"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskmigrations "github.com/pavlith/arc/services/task/migrations"
	"gorm.io/gorm"
)

func bootstrapMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func bootstrapJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	bootstrapMust(t, err)
	bootstrapMust(t, os.WriteFile(path, raw, 0600))
}

func bootstrapFixture(t *testing.T) (BootstrapConfig, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	_, operator, err := ed25519.GenerateKey(rand.Reader)
	bootstrapMust(t, err)
	cfg := BootstrapConfig{
		SQLitePath:         filepath.Join(dir, "core.sqlite"),
		NATS:               sdk.Config{URL: "tls://127.0.0.1:1", Name: "arc-core-test", TLSCAFile: filepath.Join(dir, "ca.crt"), NKeySeedFile: filepath.Join(dir, "nats.seed")},
		IdentitySigningKid: "identity-test", IdentityKeyFile: filepath.Join(dir, "identity.seed"),
		IdentityKeyExpiresAt:        time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		InstallationApprovalKeyFile: filepath.Join(dir, "operator.json"),
		ContractBootstrapFiles:      []string{filepath.Join(dir, "bootstrap.json")},
		SnapshotKid:                 "snapshot-test", SnapshotKeyFile: filepath.Join(dir, "snapshot.seed"),
		RouteTrustKeyFile: filepath.Join(dir, "route-trust.seed"),
	}
	for _, path := range []string{cfg.IdentityKeyFile, cfg.SnapshotKeyFile, cfg.RouteTrustKeyFile} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		bootstrapMust(t, err)
		bootstrapMust(t, os.WriteFile(path, key.Seed(), 0600))
	}
	bootstrapJSON(t, cfg.InstallationApprovalKeyFile, operator.Public())
	bootstrapPolicy(t, cfg.ContractBootstrapFiles[0], operator, access.Approval{})
	bootstrapMust(t, os.WriteFile(cfg.NATS.TLSCAFile, []byte("fixture CA"), 0600))
	bootstrapMust(t, os.WriteFile(cfg.NATS.NKeySeedFile, []byte("fixture NKey"), 0600))
	return cfg, operator
}

func bootstrapPolicy(t *testing.T, path string, key ed25519.PrivateKey, policy access.Approval) {
	t.Helper()
	raw, err := json.Marshal(policy)
	bootstrapMust(t, err)
	raw, err = security.CanonicalJSON(raw)
	bootstrapMust(t, err)
	bootstrapJSON(t, path, access.Approved{Payload: raw, Signature: ed25519.Sign(key, raw)})
}

func bootstrapDB(t *testing.T, cfg BootstrapConfig) *gorm.DB {
	t.Helper()
	db, err := database.Open(context.Background(), cfg.SQLitePath)
	bootstrapMust(t, err)
	t.Cleanup(func() { _ = database.Close(db) })
	return db
}

func TestBootstrapRejectsUnsafeInputsWithoutLeakingThem(t *testing.T) {
	tests := []struct {
		name string
		edit func(*testing.T, *BootstrapConfig, ed25519.PrivateKey)
	}{
		{"missing approvals", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) { c.ContractBootstrapFiles = nil }},
		{"plaintext broker", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) { c.NATS.URL = "nats://localhost:4222" }},
		{"inline broker password", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			c.NATS.URL = "tls://user:secret-marker@localhost:4222"
		}},
		{"relative key", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) { c.IdentityKeyFile = "relative.seed" }},
		{"expired key", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			c.IdentityKeyExpiresAt = time.Now().Add(-time.Minute)
		}},
		{"short seed", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			bootstrapMust(t, os.WriteFile(c.IdentityKeyFile, []byte("secret-marker"), 0600))
		}},
		{"public seed", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			bootstrapMust(t, os.Chmod(c.SnapshotKeyFile, 0644))
		}},
		{"public broker seed", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			bootstrapMust(t, os.Chmod(c.NATS.NKeySeedFile, 0644))
		}},
		{"missing trust root", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			c.InstallationApprovalKeyFile += ".missing"
		}},
		{"invalid trust root", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			bootstrapJSON(t, c.InstallationApprovalKeyFile, []byte("secret-marker"))
		}},
		{"forged approval", func(t *testing.T, c *BootstrapConfig, _ ed25519.PrivateKey) {
			bootstrapJSON(t, c.ContractBootstrapFiles[0], access.Approved{Payload: json.RawMessage(`{}`), Signature: make([]byte, ed25519.SignatureSize)})
		}},
		{"unknown policy field", func(t *testing.T, c *BootstrapConfig, key ed25519.PrivateKey) {
			raw := json.RawMessage(`{"secret-marker":true}`)
			bootstrapJSON(t, c.ContractBootstrapFiles[0], access.Approved{Payload: raw, Signature: ed25519.Sign(key, raw)})
		}},
		{"domain bootstrap rule", func(t *testing.T, c *BootstrapConfig, key ed25519.PrivateKey) {
			bootstrapPolicy(t, c.ContractBootstrapFiles[0], key, access.Approval{Rules: []access.Rule{{Caller: "00000000-0000-4000-8000-000000000001", Audience: "task/v1", Operation: "task.v1.create", ActorKinds: []string{"user"}}}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, operator := bootstrapFixture(t)
			db := bootstrapDB(t, cfg)
			bootstrapMust(t, database.Migrate(context.Background(), db, migrations.SQLite()))
			test.edit(t, &cfg, operator)
			path := filepath.Join(t.TempDir(), "core.json")
			bootstrapJSON(t, path, cfg)
			err := Run(context.Background(), path)
			if err == nil || strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), filepath.Dir(cfg.SQLitePath)) {
				t.Fatalf("unsafe configuration or error disclosure: %v", err)
			}
			var n int64
			bootstrapMust(t, db.Table("identity_signing_key_metadata").Count(&n).Error)
			if n != 0 {
				t.Fatal("invalid configuration changed Identity trust")
			}
		})
	}
}

func TestBootstrapStrictConfiguration(t *testing.T) {
	cfg, _ := bootstrapFixture(t)
	raw, err := json.Marshal(cfg)
	bootstrapMust(t, err)
	for _, input := range []string{
		string(raw) + `{}`,
		`{"runtime_node_rpc":true,` + string(raw[1:]),
		`{"sqlite_path":"secret-marker",` + string(raw[1:]),
		string(make([]byte, (256<<10)+1)),
	} {
		path := filepath.Join(t.TempDir(), "core.json")
		bootstrapMust(t, os.WriteFile(path, []byte(input), 0600))
		if _, err := readBootstrapConfig(path); err == nil || strings.Contains(err.Error(), "secret-marker") {
			t.Fatalf("ambiguous/unknown/oversized configuration accepted: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "core.json")
	bootstrapJSON(t, path, cfg)
	bootstrapMust(t, os.Chmod(path, 0666))
	if _, err := readBootstrapConfig(path); err == nil {
		t.Fatal("writable configuration accepted")
	}
}

func TestBootstrapRequiresExistingCompleteOwnerSchema(t *testing.T) {
	for _, state := range []string{"missing", "empty", "partial", "future", "task", "missing Fabric table"} {
		t.Run(state, func(t *testing.T) {
			cfg, _ := bootstrapFixture(t)
			path := filepath.Join(t.TempDir(), "core.json")
			bootstrapJSON(t, path, cfg)
			if state == "missing" {
				if err := Run(context.Background(), path); err == nil {
					t.Fatal("missing database accepted")
				}
				if _, err := os.Stat(cfg.SQLitePath); !os.IsNotExist(err) {
					t.Fatal("startup created a database", err)
				}
				return
			}
			db := bootstrapDB(t, cfg)
			switch state {
			case "partial":
				bootstrapMust(t, database.Migrate(context.Background(), db, migrations.SQLite()[:1]))
			case "future", "missing Fabric table":
				bootstrapMust(t, database.Migrate(context.Background(), db, migrations.SQLite()))
				if state == "future" {
					bootstrapMust(t, db.Exec("INSERT INTO schema_migrations(id) VALUES('000007_future')").Error)
				} else {
					bootstrapMust(t, db.Exec("DROP TABLE fabric_contracts").Error)
				}
			case "task":
				bootstrapMust(t, database.Migrate(context.Background(), db, taskmigrations.SQLite()))
			}
			var before, after int64
			bootstrapMust(t, db.Raw("SELECT count(*) FROM sqlite_master").Scan(&before).Error)
			if err := Run(context.Background(), path); err == nil {
				t.Fatal("invalid schema accepted")
			}
			bootstrapMust(t, db.Raw("SELECT count(*) FROM sqlite_master").Scan(&after).Error)
			if before != after {
				t.Fatal("startup changed schema")
			}
		})
	}
}

func TestBootstrapSigningKeyDoesNotRenewOrResurrectTrust(t *testing.T) {
	cfg, _ := bootstrapFixture(t)
	db := bootstrapDB(t, cfg)
	bootstrapMust(t, database.Migrate(context.Background(), db, migrations.SQLite()))
	key, err := readBootstrapKey(cfg.IdentityKeyFile)
	bootstrapMust(t, err)
	id := &identity.Core{GormDB: db, PrivateKey: key, SigningKid: cfg.IdentitySigningKid}
	ctx := context.Background()
	bootstrapMust(t, ensureBootstrapSigningKey(ctx, id, cfg.IdentityKeyExpiresAt))
	bootstrapMust(t, ensureBootstrapSigningKey(ctx, id, cfg.IdentityKeyExpiresAt))
	var n int64
	bootstrapMust(t, db.Table("identity_audit").Where("operation=?", "signing_keys.publish").Count(&n).Error)
	if n != 1 {
		t.Fatal("restart republished signing key", n)
	}
	if ensureBootstrapSigningKey(ctx, id, cfg.IdentityKeyExpiresAt.Add(time.Hour)) == nil {
		t.Fatal("restart extended expiry")
	}
	other := *id
	_, other.PrivateKey, err = ed25519.GenerateKey(rand.Reader)
	bootstrapMust(t, err)
	if ensureBootstrapSigningKey(ctx, &other, cfg.IdentityKeyExpiresAt) == nil {
		t.Fatal("kid rebound to different key")
	}
	bootstrapMust(t, db.Exec("UPDATE identity_signing_key_metadata SET revoked_at=? WHERE kid=?", time.Now(), id.SigningKid).Error)
	if ensureBootstrapSigningKey(ctx, id, cfg.IdentityKeyExpiresAt) == nil {
		t.Fatal("restart resurrected revoked key")
	}
}

func TestBootstrapRejectsPersistedInvalidInstallation(t *testing.T) {
	cfg, _ := bootstrapFixture(t)
	db := bootstrapDB(t, cfg)
	bootstrapMust(t, database.Migrate(context.Background(), db, migrations.SQLite()))
	bootstrapMust(t, db.Exec("INSERT INTO fabric_definitions(name,publisher) VALUES('task','fixture')").Error)
	bootstrapMust(t, db.Exec("INSERT INTO fabric_contracts(digest,service_name,api_major,artifact,installation,signature) VALUES(?,'task',1,'{}','{}',?)", strings.Repeat("a", 64), make([]byte, ed25519.SignatureSize)).Error)
	path := filepath.Join(t.TempDir(), "core.json")
	bootstrapJSON(t, path, cfg)
	if err := Run(context.Background(), path); err == nil || err.Error() != "core: invalid signed approvals" {
		t.Fatal("persisted invalid installation accepted", err)
	}
	var count int64
	bootstrapMust(t, db.Table("identity_signing_key_metadata").Count(&count).Error)
	if count != 0 {
		t.Fatal("invalid persisted installation changed signing trust")
	}
}

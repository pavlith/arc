package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	coremigrations "github.com/pavlith/arc/services/core/migrations"
	"gorm.io/gorm"
)

type sqliteAllowPolicy struct{}

func (sqliteAllowPolicy) Authorize(context.Context, Authorization) error { return nil }

func identitySQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "core.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(db) })
	if err := database.Migrate(context.Background(), db, coremigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSQLiteIdentitySigningMetadataAndLiveCredentials(t *testing.T) {
	ctx := context.Background()
	db := identitySQLiteDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	c := &Core{GormDB: db, PrivateKey: key, SigningKid: "core-sqlite", Now: func() time.Time { return now }}
	if err := c.PublishSigningKey(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := c.SigningKey(ctx, c.SigningKid)
	if err != nil || !bytes.Equal(got.Public, key.Public().(ed25519.PublicKey)) || got.Revoked {
		t.Fatalf("signing key metadata: %+v (%v)", got, err)
	}
	jwks, err := c.JWKS(ctx)
	if err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("JWKS: %+v (%v)", jwks, err)
	}
	if _, err := c.SigningKey(ctx, "unrecognized"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown kid accepted: %v", err)
	}
	if err := c.PublishSigningKey(ctx, now.Add(time.Hour)); err == nil {
		t.Fatal("duplicate signing key published without a rotation")
	}
	if err := db.Exec("UPDATE identity_signing_key_metadata SET revoked_at=? WHERE kid=?", now, c.SigningKid).Error; err != nil {
		t.Fatal(err)
	}
	jwks, err = c.JWKS(ctx)
	if err != nil || len(jwks.Keys) != 0 {
		t.Fatalf("revoked signing key in JWKS: %+v (%v)", jwks, err)
	}
	if err := db.Exec("INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES('svc','task','prod')").Error; err != nil {
		t.Fatal(err)
	}
	public := bytes.Repeat([]byte{4}, ed25519.PublicKeySize)
	if err := db.Exec(`INSERT INTO identity_service_credentials
		(kid,service_account_id,public_key,secret_reference,not_before,expires_at)
		VALUES(?,?,?,?,?,?)`, "worker-1", "svc", public, "mount:worker", now, now.Add(time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	worker, err := c.CallerKey(ctx, "svc", "worker-1")
	if err != nil || worker.Revoked || !bytes.Equal(worker.Public, public) {
		t.Fatalf("live worker key: %+v (%v)", worker, err)
	}
	if err := db.Exec("UPDATE identity_service_accounts SET disabled_at=? WHERE id='svc'", now).Error; err != nil {
		t.Fatal(err)
	}
	worker, err = c.CallerKey(ctx, "svc", "worker-1")
	if err != nil || !worker.Revoked {
		t.Fatalf("disabled worker key accepted: %+v (%v)", worker, err)
	}
}

func TestSQLiteIdentityNonceReplayAcrossConnections(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "core.sqlite")
	first, err := database.Open(ctx, path)
	if err != nil { t.Fatal(err) }
	defer database.Close(first)
	if err := database.Migrate(ctx, first, coremigrations.SQLite()); err != nil { t.Fatal(err) }
	second, err := database.Open(ctx, path)
	if err != nil { t.Fatal(err) }
	defer database.Close(second)
	now := time.Now().UTC()
	owners := []*Core{
		{GormDB: first, Now: func() time.Time { return now }},
		{GormDB: second, Now: func() time.Time { return now }},
	}
	const concurrent = 12
	var wg sync.WaitGroup
	outcomes := make(chan error, concurrent)
	start := make(chan struct{})
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			outcomes <- owners[index%2].Consume(ctx, "assertion:svc", "nonce", now.Add(time.Minute))
		}(i)
	}
	close(start)
	wg.Wait()
	close(outcomes)
	wins := 0
	for err := range outcomes {
		if err == nil { wins++; continue }
		if !errors.Is(err, ErrUnauthenticated) { t.Errorf("unexpected nonce error: %v", err) }
	}
	if wins != 1 { t.Fatalf("nonce replay yielded %d accepted assertions", wins) }
	if err := owners[0].Consume(ctx, "assertion:svc", "nonce", now.Add(time.Minute)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestSQLiteIdentityInvocationRechecksUserAndDelegation(t *testing.T) {
	ctx := context.Background()
	db := identitySQLiteDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	c := &Core{GormDB: db, Policy: sqliteAllowPolicy{}, Now: func() time.Time { return now }}
	queries := []string{
		"INSERT INTO identity_users(id,email) VALUES('u','user@example.test')",
		"INSERT INTO identity_workspaces(id,name) VALUES('w','team')",
		"INSERT INTO identity_memberships(workspace_id,user_id,role) VALUES('w','u','owner')",
		"INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES('svc','task','prod')",
	}
	for _, q := range queries {
		if err := db.Exec(q).Error; err != nil { t.Fatal(err) }
	}
	if err := db.Exec(`INSERT INTO identity_sessions
		(id,user_id,secret_hash,csrf_hash,expires_at) VALUES('s','u',?,?,?)`,
		[]byte("secret"), []byte("csrf"), now.Add(time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	claims := security.Claims{Subject: "user:u", SessionID: "s", WorkspaceID: "w", Audience: "gate"}
	if err := c.CheckInvocation(ctx, claims); err != nil {
		t.Fatalf("active user denied: %v", err)
	}
	if err := db.Exec("UPDATE identity_memberships SET revoked_at=? WHERE user_id='u'", now).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.CheckInvocation(ctx, claims); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked membership accepted: %v", err)
	}
	if err := db.Exec("UPDATE identity_sessions SET revoked_at=? WHERE id='s'", now).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.CheckInvocation(ctx, claims); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session accepted: %v", err)
	}
	if err := db.Exec(`INSERT INTO identity_delegations
		(id,grantor_user_id,grantee_kind,grantee_id,grantee_service_id,
		resource_ids,actions,expires_at,created_by,consent_method,created_at)
		VALUES('d','u','service','svc','svc','["root"]','["read"]',?,'u','interactive_session',?)`,
		now.Add(time.Hour), now).Error; err != nil {
		t.Fatal(err)
	}
	delegated := security.Claims{
		Subject: "service:svc", Caller: "svc", DelegationID: "d",
		OnBehalfOf: "u", Audience: "task/v1", Operation: "task.read",
	}
	if err := c.CheckInvocation(ctx, delegated); err != nil {
		t.Fatalf("active delegation denied: %v", err)
	}
	if err := db.Exec("UPDATE identity_delegations SET revoked_at=? WHERE id='d'", now).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.CheckInvocation(ctx, delegated); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked delegation accepted: %v", err)
	}
}

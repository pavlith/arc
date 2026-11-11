package migrations

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/database"
)

func TestRetiredLegacySessionsAreRevokedAndCannotBeRecreated(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "core.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	migrations := SQLite()
	if err := database.Migrate(ctx, db, migrations[:len(migrations)-1]); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO identity_users(id,email) VALUES('u','old@example.test')`,
		`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at,auth_channel)
		   VALUES('old','u',x'01',x'02',datetime('now','+1 day'),'legacy')`,
		`INSERT INTO identity_refresh_families(id,session_id,expires_at)
		   VALUES('f','old',datetime('now','+1 day'))`,
		`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at,auth_channel)
		   VALUES('current','u',x'03',x'04',datetime('now','+1 day'),'browser')`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := database.Migrate(ctx, db, SQLite()); err != nil {
			t.Fatal(err)
		}
	}
	var oldRevoked, familyRevoked, browserRevoked int
	if err := db.Raw(`SELECT revoked_at IS NOT NULL FROM identity_sessions WHERE id='old'`).Scan(&oldRevoked).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Raw(`SELECT revoked_at IS NOT NULL FROM identity_refresh_families WHERE id='f'`).Scan(&familyRevoked).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Raw(`SELECT revoked_at IS NOT NULL FROM identity_sessions WHERE id='current'`).Scan(&browserRevoked).Error; err != nil {
		t.Fatal(err)
	}
	if oldRevoked != 1 || familyRevoked != 1 || browserRevoked != 0 {
		t.Fatalf("channel migration: old=%d family=%d browser=%d", oldRevoked, familyRevoked, browserRevoked)
	}
	if err := db.Exec(`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at)
	   VALUES('bad','u',x'05',x'06',datetime('now','+1 day'))`).Error; err == nil {
		t.Fatal("implicit legacy login inserted after retirement")
	}
	if err := db.Exec(`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at,auth_channel)
	   VALUES('cli','u',x'07',x'08',datetime('now','+1 day'),'cli')`).Error; err != nil {
		t.Fatal(err)
	}
}

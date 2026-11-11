package identity

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
)

func invitedFixture(t *testing.T) (*Core, RegisterInvitedRequest) {
	t.Helper()
	db := identitySQLiteDB(t)
	c := &Core{GormDB: db}
	for _, query := range []string{
		`INSERT INTO identity_users(id,email) VALUES('issuer','issuer@example.test')`,
		`INSERT INTO identity_workspaces(id,name) VALUES('workspace','Team')`,
		`INSERT INTO identity_memberships(workspace_id,user_id,role) VALUES('workspace','issuer','owner')`,
	} {
		if err := db.Exec(query).Error; err != nil {
			t.Fatal(err)
		}
	}
	token, err := secret()
	if err != nil {
		t.Fatal(err)
	}
	q := RegisterInvitedRequest{Email: "new@example.test", Password: "invited account password", Token: token}
	_, err = c.createInvitation(context.Background(), Session{UserID: "issuer"}, ProductRequest[InvitationCreate]{Input: InvitationCreate{
		WorkspaceInput: WorkspaceInput{WorkspaceID: "workspace"}, Email: q.Email, Role: "guest", Token: token,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return c, q
}

func TestRegisterInvitedAtomicSuccess(t *testing.T) {
	c, q := invitedFixture(t)
	ctx := context.Background()
	q.Email = " NEW@example.test "
	result, err := c.RegisterInvited(ctx, q)
	if err != nil || result.UserID == "" || result.WorkspaceID != "workspace" || len(result.RecoveryCode) != 43 {
		t.Fatalf("registration failed: %v", err)
	}
	var email, role, password string
	var recovery []byte
	err = c.GormDB.Raw(`SELECT u.email,m.role,p.password_hash,p.recovery_hash FROM identity_users u
		JOIN identity_password_credentials p ON p.user_id=u.id JOIN identity_memberships m ON m.user_id=u.id WHERE u.id=?`, result.UserID).
		Row().Scan(&email, &role, &password, &recovery)
	if err != nil || email != "new@example.test" || role != "guest" || !CheckPassword(password, q.Password) || !bytes.Equal(recovery, hash(result.RecoveryCode)) {
		t.Fatal("credentials or invitation role were not persisted correctly", err)
	}
	if login, err := c.login(ctx, email, q.Password, "browser"); err != nil || login.Session.UserID != result.UserID || login.AccessToken != "" {
		t.Fatal("new account cannot use browser login", err)
	}
	if again, err := c.RegisterInvited(ctx, q); !errors.Is(err, ErrDenied) || again != (RegisterInvitedResult{}) {
		t.Fatal("invitation replay returned credentials", err)
	}
	if next, err := c.Recover(ctx, email, result.RecoveryCode, "replacement long password"); err != nil || next == "" || next == result.RecoveryCode {
		t.Fatal("recovery code cannot rotate credentials", err)
	}
}

func TestRegisterInvitedRejectsAndRollsBack(t *testing.T) {
	for _, name := range []string{"revoked", "expired", "consumed", "archived", "issuer_disabled", "issuer_demoted", "issuer_removed", "wrong_email", "bad_token", "weak_password", "existing_account", "audit_failure"} {
		t.Run(name, func(t *testing.T) {
			c, q := invitedFixture(t)
			query := ""
			switch name {
			case "revoked":
				query = `UPDATE identity_workspace_invitations SET revoked_at=CURRENT_TIMESTAMP`
			case "expired":
				query = `UPDATE identity_workspace_invitations SET expires_at='2000-01-01'`
			case "consumed":
				query = `UPDATE identity_workspace_invitations SET consumed_at=CURRENT_TIMESTAMP`
			case "archived":
				query = `UPDATE identity_workspaces SET archived_at=CURRENT_TIMESTAMP`
			case "issuer_disabled":
				query = `UPDATE identity_users SET status='disabled' WHERE id='issuer'`
			case "issuer_demoted":
				query = `UPDATE identity_memberships SET role='member' WHERE user_id='issuer'`
			case "issuer_removed":
				query = `UPDATE identity_memberships SET revoked_at=CURRENT_TIMESTAMP WHERE user_id='issuer'`
			case "wrong_email":
				q.Email = "someone-else@example.test"
			case "bad_token":
				q.Token = "bad"
			case "weak_password":
				q.Password = "short"
			case "existing_account":
				query = `INSERT INTO identity_users(id,email) VALUES('existing','new@example.test')`
			case "audit_failure":
				query = `CREATE TRIGGER fail_registration BEFORE INSERT ON identity_audit WHEN NEW.operation='users.register_invited' BEGIN SELECT RAISE(ABORT,'fixture failure'); END`
			}
			if query != "" {
				if err := c.GormDB.Exec(query).Error; err != nil {
					t.Fatal(err)
				}
			}
			var beforeUsers, beforeConsumed, beforeRevision int
			c.GormDB.Raw(`SELECT count(*) FROM identity_users`).Row().Scan(&beforeUsers)
			c.GormDB.Raw(`SELECT count(*) FROM identity_workspace_invitations WHERE consumed_at IS NOT NULL`).Row().Scan(&beforeConsumed)
			c.GormDB.Raw(`SELECT revision FROM identity_workspaces WHERE id='workspace'`).Row().Scan(&beforeRevision)
			result, err := c.RegisterInvited(context.Background(), q)
			want := ErrDenied
			if name == "audit_failure" {
				want = ErrUnavailable
			}
			if !errors.Is(err, want) || result != (RegisterInvitedResult{}) {
				t.Fatalf("expected safe rejection, got %v", err)
			}
			var users, credentials, consumed, revision, members int
			for query, target := range map[string]*int{
				`SELECT count(*) FROM identity_users`:                                               &users,
				`SELECT count(*) FROM identity_password_credentials`:                                &credentials,
				`SELECT count(*) FROM identity_workspace_invitations WHERE consumed_at IS NOT NULL`: &consumed,
				`SELECT revision FROM identity_workspaces WHERE id='workspace'`:                     &revision,
				`SELECT count(*) FROM identity_memberships WHERE user_id<>'issuer'`:                 &members,
			} {
				if err := c.GormDB.Raw(query).Row().Scan(target); err != nil {
					t.Fatal(err)
				}
			}
			if users != beforeUsers || credentials != 0 || consumed != beforeConsumed || revision != beforeRevision || members != 0 {
				t.Fatal("failed registration left partial account or invitation changes")
			}
		})
	}
}

func TestRegisterInvitedConcurrentRedemption(t *testing.T) {
	c, q := invitedFixture(t)
	var path string
	if err := c.GormDB.Raw(`SELECT file FROM pragma_database_list WHERE name='main'`).Row().Scan(&path); err != nil {
		t.Fatal(err)
	}
	second, err := database.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(second)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, owner := range []*Core{c, {GormDB: second}} {
		wg.Add(1)
		go func(owner *Core) {
			defer wg.Done()
			<-start
			_, err := owner.RegisterInvited(context.Background(), q)
			results <- err
		}(owner)
	}
	close(start)
	wg.Wait()
	close(results)
	successes, denied := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrDenied) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || denied != 1 {
		t.Fatalf("concurrent redemption: %d successes, %d denials", successes, denied)
	}
}

func TestRegisterInvitedRateLimit(t *testing.T) {
	c, _ := invitedFixture(t)
	c.Now = func() time.Time { return time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC) }
	for range 10 {
		if _, err := c.RegisterInvited(context.Background(), RegisterInvitedRequest{}); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if _, err := c.RegisterInvited(context.Background(), RegisterInvitedRequest{}); !errors.Is(err, ErrRateLimited) {
		t.Fatal("registration was not rate limited", err)
	}
}

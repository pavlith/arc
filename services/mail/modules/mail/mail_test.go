package mail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
	"github.com/pavlith/arc/services/mail/migrations"
	"github.com/pavlith/arc/test/imapfixture"
	"gorm.io/gorm"
)

const root = "40000000-0000-4000-8000-000000000002"
const owner = "40000000-0000-4000-8000-000000000003"

func fixture(t *testing.T) (*Module, v1.Scope, v1.AccountInput) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mail.sqlite")
	db, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	database.Close(db)
	db, err = database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(db) })
	if err = database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	server := imapfixture.New(t, "plain", map[string]string{"login": "unique sensitive fixture password"})
	probe, err := imapclient.New(imapclient.Config{Endpoints: []imapclient.Endpoint{{Host: server.Host, Port: server.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: server.Roots})
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	rand.Read(master)
	vault, err := credentials.New(master)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(v1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	s := &Module{DB: db, Vault: vault, Probe: probe, Contract: compiled, Check: func(context.Context, string, string) error { return nil }}
	scope := v1.Scope{RootID: root}
	input := v1.AccountInput{Name: "Personal", Host: server.Host, Port: server.Port, Login: "login", Email: "alice@example.test"}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = s.PrepareRoot(ctx, scope, owner, input, key, "key", newID()); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateRoot(ctx, scope); err != nil {
		t.Fatal(err)
	}
	return s, scope, input
}
func invocation(t *testing.T, op, workspace, key string, q any) context.Context {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"operation": op, "proof": security.Proof{}, "auth": "fixture", "payload": q, "idempotency_key": key})
	auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
		return security.Claims{Subject: "user:reader", SessionID: "session", Operation: op, WorkspaceID: workspace}, nil
	})
	ctx, err := auth(context.Background(), "fixture", raw)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}
func command[Q, R any](t *testing.T, s *Module, op, action, key string, q Q, fn func(context.Context, *gorm.DB, Q) (R, error)) (R, error) {
	t.Helper()
	var zero R
	raw, _ := json.Marshal(q)
	var scope v1.Scope
	json.Unmarshal(raw, &scope)
	ctx := invocation(t, op, scope.WorkspaceID, key, q)
	spec, err := s.Contract.Operation(op)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Contract.Validate(spec.RequestSchema, raw); err != nil {
		return zero, err
	}
	if err = s.Authorize(ctx, scope.RootID, action); err != nil {
		return zero, err
	}
	return events.Command(ctx, events.Store{DB: s.DB}, s.Contract, op, q, fn)
}
func TestCredentialsLifecycleReplayRollbackAndProbe(t *testing.T) {
	s, scope, in := fixture(t)
	ctx := context.Background()
	info, err := s.key(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := credentials.Seal(info.PublicInfo, []byte("unique sensitive fixture password"))
	if err != nil {
		t.Fatal(err)
	}
	q := v1.SetCredential{Scope: scope, Revision: 1, KeyID: info.KeyID, Sealed: sealed}
	saved, err := command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "credential", q, s.setCredentials)
	if err != nil || !saved.CredentialReady || saved.Revision != 2 || saved.CredentialVersion != 1 {
		t.Fatal(saved, err)
	}
	replay, err := command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "credential", q, s.setCredentials)
	if err != nil || replay.Revision != 2 {
		t.Fatal("replay", err)
	}
	mismatch := q
	mismatch.Sealed += "x"
	if _, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "credential", mismatch, s.setCredentials); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("payload mismatch", err)
	}
	result, err := s.checkConnection(ctx, scope)
	if err != nil || result.Status != "ok" {
		t.Fatal("real IMAP check", result, err)
	}
	update := v1.Update{Scope: scope, AccountInput: in, Revision: 2}
	update.Name = "Renamed"
	renamed, err := command(t, s, v1.UpdateAccount.ID, "mail.connection.manage", "rename", update, s.update)
	if err != nil || renamed.Generation != 1 || !renamed.CredentialReady {
		t.Fatal("cosmetic edit lost credential", renamed, err)
	}
	if result, err = s.checkConnection(ctx, scope); err != nil || result.Status != "ok" {
		t.Fatal("credential AAD after cosmetic edit", result, err)
	}
	if _, err = command(t, s, v1.UpdateAccount.ID, "mail.connection.manage", "stale", update, s.update); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("CAS", err)
	}
	if err = s.DB.Exec("CREATE TRIGGER deny_mail BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture'); END").Error; err != nil {
		t.Fatal(err)
	}
	state := v1.SetState{Scope: scope, Revision: 3, State: "disconnected"}
	if _, err = command(t, s, v1.SetAccountState.ID, "mail.connection.manage", "rollback", state, s.state); err == nil {
		t.Fatal("failed outbox committed")
	}
	current, err := s.get(ctx, scope)
	if err != nil || current.Revision != 3 || !current.CredentialReady {
		t.Fatal("rollback lost secret", current, err)
	}
	var count int64
	if err = s.DB.Table("command_results").Where("idempotency_key='rollback'").Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed replay retained", err)
	}
	if err = s.DB.Exec("DROP TRIGGER deny_mail").Error; err != nil {
		t.Fatal(err)
	}
	paused, err := command(t, s, v1.SetAccountState.ID, "mail.connection.manage", "pause", v1.SetState{Scope: scope, Revision: 3, State: "paused"}, s.state)
	if err != nil || !paused.CredentialReady {
		t.Fatal(paused, err)
	}
	if result, err = s.checkConnection(ctx, scope); err != nil || result.Status != "paused" {
		t.Fatal(result, err)
	}
	state.Revision = 4
	disconnected, err := command(t, s, v1.SetAccountState.ID, "mail.connection.manage", "disconnect", state, s.state)
	if err != nil || disconnected.CredentialReady || disconnected.Generation != 2 || disconnected.Revision != 5 {
		t.Fatal(disconnected, err)
	}
	replay, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "credential", q, s.setCredentials)
	if err != nil || !replay.CredentialReady {
		t.Fatal("historical replay", err)
	}
	current, err = s.get(ctx, scope)
	if err != nil || current.CredentialReady {
		t.Fatal("replay restored disconnected credential", err)
	}
	s.Check = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "credential", q, s.setCredentials); !errors.Is(err, security.ErrDenied) {
		t.Fatal("revoke-before-replay", err)
	}
	// No SQL row, response or event contains the password; only randomized sealed
	// ciphertext enters the persisted request fingerprint.
	for _, table := range []string{"accounts", "audit", "outbox", "command_results"} {
		var rows []map[string]any
		if err = s.DB.Table(table).Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rows)
		if bytes.Contains(raw, []byte("unique sensitive fixture password")) {
			t.Fatal("credential persisted in " + table)
		}
	}
}
func TestScopeSealingBindingAndGeneration(t *testing.T) {
	s, scope, in := fixture(t)
	ctx := context.Background()
	info, err := s.key(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	wrong := info.PublicInfo
	wrong.AccountID = newID()
	sealed, err := credentials.Seal(wrong, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	q := v1.SetCredential{Scope: scope, Revision: 1, KeyID: info.KeyID, Sealed: sealed}
	if _, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "wrong-scope", q, s.setCredentials); rpc.ErrorCode(err) != rpc.CodeValidation {
		t.Fatal("cross-account sealed credential accepted", err)
	}
	in.Login = "different login"
	updated, err := command(t, s, v1.UpdateAccount.ID, "mail.connection.manage", "rebind", v1.Update{Scope: scope, AccountInput: in, Revision: 1}, s.update)
	if err != nil || updated.Generation != 2 || updated.CredentialReady {
		t.Fatal(updated, err)
	}
	sealed, err = credentials.Seal(info.PublicInfo, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	q.Sealed = sealed
	q.Revision = 2
	if _, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "stale-binding", q, s.setCredentials); rpc.ErrorCode(err) != rpc.CodeValidation {
		t.Fatal("stale binding accepted", err)
	}
	if err = s.Authorize(ctx, root, "mail.read"); err == nil {
		t.Fatal("unverified actor accepted")
	}
	if err = s.Authorize(invocation(t, v1.GetAccount.ID, newID(), "", scope), root, "mail.read"); err == nil {
		t.Fatal("workspace substitution")
	}
	other := v1.Scope{RootID: newID()}
	if _, err = s.get(ctx, other); rpc.ErrorCode(err) != rpc.CodeNotFound {
		t.Fatal("unknown root readable", err)
	}
	// Authorization is performed again after network I/O, before returning results.
	info, err = s.key(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err = credentials.Seal(info.PublicInfo, []byte("unique sensitive fixture password"))
	if err != nil {
		t.Fatal(err)
	}
	q = v1.SetCredential{Scope: scope, Revision: 2, KeyID: info.KeyID, Sealed: sealed}
	_, err = command(t, s, v1.SetCredentials.ID, "mail.connection.manage", "new-secret", q, s.setCredentials)
	if err != nil {
		t.Fatal(err)
	}
	s.Check = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err = s.checkConnection(ctx, scope); !errors.Is(err, security.ErrDenied) {
		t.Fatal("post-network revoke allowed", err)
	}
}

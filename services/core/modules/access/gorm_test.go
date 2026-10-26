package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	coremigrations "github.com/pavlith/arc/services/core/migrations"
	"github.com/pavlith/arc/services/core/modules/identity"
	"gorm.io/gorm"
)

const (
	sqliteOwner         = "11111111-1111-4111-8111-111111111111"
	sqliteMember        = "22222222-2222-4222-8222-222222222222"
	sqliteProvider      = "33333333-3333-4333-8333-333333333333"
	sqliteSession       = "44444444-4444-4444-8444-444444444444"
	sqliteMemberSession = "55555555-5555-4555-8555-555555555555"
)

type sqliteReceipt struct{}

func (sqliteReceipt) Confirm(_ context.Context, _, _, _, receipt string) error {
	if receipt != "fixture-committed" {
		return ErrDenied
	}
	return nil
}

func sqliteAccessPolicy(t *testing.T) *Contracts {
	t.Helper()
	actions := []string{"access.grants.manage", "books.create", "books.read", "books.share", "books.delete"}
	digest := strings.Repeat("a", 64)
	rules := make([]Rule, 0)
	for _, op := range []string{
		"resource_types.register", "resources.reserve", "resources.activate",
		"resources.abort", "resources.begin_delete", "resources.finalize_delete",
		"check", "check_many", "list_accessible_roots", "grants.add", "grants.revoke",
	} {
		rules = append(rules, Rule{
			Caller: sqliteProvider, Audience: "access/v1", Operation: "access.v1." + op,
			ActorKinds: []string{"user"}, Actions: actions,
		})
	}
	approval := Approval{
		ContractDigests: map[string]string{"books.root": digest},
		Types: []TypeSpec{{
			Type: "books.root", Provider: sqliteProvider,
			Actions: actions, ShareAction: "books.share",
			CreateAction: "books.create", DeleteAction: "books.delete", AllowInheritance: true,
		}},
		Rules: rules,
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, ed25519.SeedSize))
	return signedContracts(t, key, approval)
}

func sqliteAccessFixture(t *testing.T, db *gorm.DB) *Core {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	queries := []struct {
		statement string
		values    []any
	}{
		{`INSERT INTO identity_users(id,email) VALUES(?,?)`, []any{sqliteOwner, "owner@arc.test"}},
		{`INSERT INTO identity_users(id,email) VALUES(?,?)`, []any{sqliteMember, "member@arc.test"}},
		{`INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES(?,'books','test')`, []any{sqliteProvider}},
		{`INSERT INTO identity_service_credentials(kid,service_account_id,public_key,secret_reference,not_before,expires_at)
		VALUES('test-kid',?,?,'mount:test',?,?)`,
			[]any{sqliteProvider, bytes.Repeat([]byte{7}, 32), now.Add(-time.Hour), now.Add(time.Hour)}},
		{`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at)
		VALUES(?,?,x'0102',x'0304',?)`, []any{sqliteSession, sqliteOwner, now.Add(time.Hour)}},
		{`INSERT INTO identity_sessions(id,user_id,secret_hash,csrf_hash,expires_at)
		VALUES(?,?,x'0506',x'0708',?)`, []any{sqliteMemberSession, sqliteMember, now.Add(time.Hour)}},
	}
	for _, query := range queries {
		if err := db.Exec(query.statement, query.values...).Error; err != nil {
			t.Fatalf("seed SQLite ACL: %v", err)
		}
	}
	return &Core{
		GormDB: db, Identity: &identity.Core{GormDB: db},
		Contracts: sqliteAccessPolicy(t), Domain: sqliteReceipt{},
		Now: func() time.Time { return now },
	}
}

// sqliteAccessContext supplies a test-only verified context through the same
// RPC security wrapper used in production. It does not accept claims from a
// public payload: production always verifies the signed access token and proof.
func sqliteAccessContext(t *testing.T, who, session, op, idem string, payload any) context.Context {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	claims := security.Claims{
		Caller: sqliteProvider, Subject: "user:" + who,
		Audience: "access/v1", Operation: "access.v1." + op,
		SessionID: session, Confirmation: security.Confirmation{Kid: "test-kid"},
	}
	wire, err := json.Marshal(map[string]any{
		"operation":       claims.Operation,
		"payload":         json.RawMessage(raw),
		"proof":           map[string]any{},
		"idempotency_key": idem,
	})
	if err != nil {
		t.Fatal(err)
	}
	authorize := rpc.RemoteInvocationAuthorizer(
		func(context.Context, string, []byte) (security.Claims, error) { return claims, nil })
	ctx, err := authorize(context.Background(), "rpc.access.v1."+op, wire)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func runSQLiteSchema(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := database.Migrate(context.Background(), db, coremigrations.SQLite()); err != nil {
		t.Fatal(err)
	}
}
func openSQLiteAccess(t *testing.T) (*gorm.DB, *Core) {
	t.Helper()
	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "core.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(db) })
	runSQLiteSchema(t, db)
	return db, sqliteAccessFixture(t, db)
}

func TestSQLiteAccessLifecycleGrantsAndSnapshots(t *testing.T) {
	db, c := openSQLiteAccess(t)
	typeRequest := RegisterRequest{Type: "books.root", ContractDigest: strings.Repeat("a", 64)}
	typeContext := sqliteAccessContext(t, sqliteOwner, sqliteSession, "resource_types.register", "type-1", typeRequest)
	reg, err := c.RegisterType(typeContext, typeRequest)
	if err != nil || reg.Revision != 1 {
		t.Fatalf("register: %+v %v", reg, err)
	}
	repeat, err := c.RegisterType(typeContext, typeRequest)
	if err != nil || repeat != reg {
		t.Fatalf("type replay: %+v %v", repeat, err)
	}
	conflictRequest := typeRequest
	conflictRequest.Type = "books.unknown"
	if _, err := c.RegisterType(typeContext, conflictRequest); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay not rejected: %v", err)
	}
	reserve := ReserveRequest{Type: "books.root", OwnerKind: "user", OwnerID: sqliteOwner, InheritACL: true}
	reserveCtx := sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.reserve", "root-1", reserve)
	root, err := c.Reserve(reserveCtx, reserve)
	if err != nil || root.ResourceID == "" || root.Revision != 2 {
		t.Fatalf("reserve: %+v %v", root, err)
	}
	rootAgain, err := c.Reserve(reserveCtx, reserve)
	if err != nil || rootAgain != root {
		t.Fatalf("reserve replay: %+v %v", rootAgain, err)
	}
	invalid := reserve
	invalid.OwnerID = sqliteMember
	if _, err := c.Reserve(sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.reserve", "bad-owner", invalid), invalid); !errors.Is(err, ErrDenied) {
		t.Fatalf("cross-owner reserve accepted: %v", err)
	}
	activate := LifecycleRequest{ResourceID: root.ResourceID, Receipt: "fixture-committed"}
	active, err := c.Activate(sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.activate", "activate-1", activate), activate)
	if err != nil || active.State != "active" || active.Revision != 3 {
		t.Fatalf("activate: %+v %v", active, err)
	}
	ownerCheck := CheckRequest{ResourceID: root.ResourceID, Action: "books.read"}
	d, err := c.Check(sqliteAccessContext(t, sqliteOwner, sqliteSession, "check", "", ownerCheck), ownerCheck)
	if err != nil || !d.Allowed || d.Revision != 3 {
		t.Fatalf("owner ACL: %+v %v", d, err)
	}
	memberCtx := sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "check", "", ownerCheck)
	d, err = c.Check(memberCtx, ownerCheck)
	if err != nil || d.Allowed {
		t.Fatalf("ungranted member allowed: %+v %v", d, err)
	}
	grant := GrantRequest{ResourceID: root.ResourceID, PrincipalKind: "user", PrincipalID: sqliteMember, Action: "books.read"}
	grantCtx := sqliteAccessContext(t, sqliteOwner, sqliteSession, "grants.add", "grant-1", grant)
	granted, err := c.AddGrant(grantCtx, grant)
	if err != nil || granted.GrantID == "" || granted.Revision != 4 {
		t.Fatalf("grant: %+v %v", granted, err)
	}
	grantedReplay, err := c.AddGrant(grantCtx, grant)
	if err != nil || grantedReplay != granted {
		t.Fatalf("grant replay: %+v %v", grantedReplay, err)
	}
	d, err = c.Check(memberCtx, ownerCheck)
	if err != nil || !d.Allowed || d.Revision != 4 {
		t.Fatalf("member ACL: %+v %v", d, err)
	}
	checks := CheckManyRequest{Checks: []CheckRequest{
		{ResourceID: root.ResourceID, Action: "books.read"},
		{ResourceID: root.ResourceID, Action: "books.share"},
	}}
	many, err := c.CheckMany(sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "check_many", "", checks), checks)
	if err != nil || len(many.Decisions) != 2 || !many.Decisions[0].Allowed || many.Decisions[1].Allowed || many.Revision != 4 {
		t.Fatalf("multi-check: %+v %v", many, err)
	}
	list := ListRequest{Action: "books.read", Limit: 5}
	roots, err := c.ListAccessibleRoots(sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "list_accessible_roots", "", list), list)
	if err != nil || len(roots.Resources) != 1 || roots.Resources[0].ID != root.ResourceID || roots.Revision != 4 {
		t.Fatalf("root list: %+v %v", roots, err)
	}
	childReserve := reserve
	childReserve.ParentID = root.ResourceID
	child, err := c.Reserve(sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.reserve", "child-1", childReserve), childReserve)
	if err != nil {
		t.Fatalf("child reserve: %v", err)
	}
	childActivate := LifecycleRequest{ResourceID: child.ResourceID, Receipt: "fixture-committed"}
	if _, err := c.Activate(sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.activate", "child-activate", childActivate), childActivate); err != nil {
		t.Fatal(err)
	}
	childCheck := CheckRequest{ResourceID: child.ResourceID, Action: "books.read"}
	d, err = c.Check(sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "check", "", childCheck), childCheck)
	if err != nil || !d.Allowed {
		t.Fatalf("inherited grant denied: %+v %v", d, err)
	}
	revoke := RevokeRequest{GrantID: granted.GrantID}
	revoked, err := c.RevokeGrant(sqliteAccessContext(t, sqliteOwner, sqliteSession, "grants.revoke", "revoke-1", revoke), revoke)
	if err != nil || revoked.State != "revoked" {
		t.Fatalf("revoke: %+v %v", revoked, err)
	}
	d, err = c.Check(memberCtx, ownerCheck)
	if err != nil || d.Allowed {
		t.Fatalf("revoked grant allowed: %+v %v", d, err)
	}
	d, err = c.Check(sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "check", "", childCheck), childCheck)
	if err != nil || d.Allowed {
		t.Fatalf("inherited revoked grant allowed: %+v %v", d, err)
	}
	var operations, audits, revision int64
	if err := db.Table("access_operations").Count(&operations).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Table("access_policy_audit").Count(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Raw("SELECT revision FROM access_policy_state WHERE singleton=1").Row().Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if operations != audits || revision != audits || operations != 7 {
		t.Fatalf("replay or failed tx changed history: operations=%d audits=%d revision=%d", operations, audits, revision)
	}
	if err := db.Exec("UPDATE identity_service_credentials SET revoked_at=? WHERE kid='test-kid'", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(memberCtx, ownerCheck); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("revoked caller key accepted: %v", err)
	}
}

func TestSQLiteAccessConcurrentReplayAcrossTwoConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.sqlite")
	ctx := context.Background()
	first, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(first)
	runSQLiteSchema(t, first)
	c := sqliteAccessFixture(t, first)
	second, err := database.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(second)
	secondCore := *c
	secondCore.GormDB = second
	secondCore.Identity = &identity.Core{GormDB: second}
	typeRequest := RegisterRequest{Type: "books.root", ContractDigest: strings.Repeat("a", 64)}
	if _, err := c.RegisterType(sqliteAccessContext(t, sqliteOwner, sqliteSession, "resource_types.register", "type", typeRequest), typeRequest); err != nil {
		t.Fatal(err)
	}
	reserve := ReserveRequest{Type: "books.root", OwnerKind: "user", OwnerID: sqliteOwner, InheritACL: true}
	callCtx := sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.reserve", "same-command", reserve)
	var wg sync.WaitGroup
	const n = 8
	start := make(chan struct{})
	results := make(chan MutationResult, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			target := c
			if index%2 == 0 {
				target = &secondCore
			}
			out, err := target.Reserve(callCtx, reserve)
			results <- out
			errs <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	var original MutationResult
	for out := range results {
		if original.ResourceID == "" {
			original = out
		}
		if out.ResourceID != original.ResourceID || out.Revision != original.Revision {
			t.Fatalf("concurrent dedup returned different resources: %+v / %+v", out, original)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent replay failed: %v", err)
		}
	}
	var count int64
	if err := first.Table("access_resources").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("duplicate resource created: count=%d error=%v", count, err)
	}
	var audit int64
	if err := first.Table("access_policy_audit").Count(&audit).Error; err != nil || audit != 2 {
		t.Fatalf("duplicate write changed audit: count=%d error=%v", audit, err)
	}
}

func TestSQLiteAccessShareExpiryCannotEscalate(t *testing.T) {
	db, core := openSQLiteAccess(t)
	now := core.now()
	typ := RegisterRequest{Type: "books.root", ContractDigest: strings.Repeat("a", 64)}
	if _, err := core.RegisterType(
		sqliteAccessContext(t, sqliteOwner, sqliteSession, "resource_types.register", "type", typ), typ,
	); err != nil {
		t.Fatal(err)
	}
	reserve := ReserveRequest{Type: "books.root", OwnerKind: "user", OwnerID: sqliteOwner}
	root, err := core.Reserve(
		sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.reserve", "root", reserve), reserve,
	)
	if err != nil {
		t.Fatal(err)
	}
	activate := LifecycleRequest{ResourceID: root.ResourceID, Receipt: "fixture-committed"}
	if _, err := core.Activate(
		sqliteAccessContext(t, sqliteOwner, sqliteSession, "resources.activate", "activate", activate), activate,
	); err != nil {
		t.Fatal(err)
	}
	until := now.Add(10 * time.Minute)
	for _, action := range []string{"books.share", "books.read"} {
		q := GrantRequest{
			ResourceID: root.ResourceID, PrincipalKind: "user",
			PrincipalID: sqliteMember, Action: action, ExpiresAt: &until,
		}
		if _, err := core.AddGrant(
			sqliteAccessContext(t, sqliteOwner, sqliteSession, "grants.add", "owner-"+action, q), q,
		); err != nil {
			t.Fatalf("owner granted %s: %v", action, err)
		}
	}
	const target = "66666666-6666-4666-8666-666666666666"
	if err := db.Exec(
		"INSERT INTO identity_users(id,email) VALUES(?,?)", target, "recipient@arc.test",
	).Error; err != nil {
		t.Fatal(err)
	}
	share := GrantRequest{
		ResourceID: root.ResourceID, PrincipalKind: "user", PrincipalID: target,
		Action: "books.read",
	}
	if _, err := core.AddGrant(
		sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "grants.add", "unlimited", share), share,
	); !errors.Is(err, ErrDenied) {
		t.Fatalf("shared permanent grant accepted: %v", err)
	}
	tooLate := now.Add(11 * time.Minute)
	share.ExpiresAt = &tooLate
	if _, err := core.AddGrant(
		sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "grants.add", "beyond", share), share,
	); !errors.Is(err, ErrDenied) {
		t.Fatalf("grant beyond share expiry accepted: %v", err)
	}
	var revision int64
	if err := db.Raw("SELECT revision FROM access_policy_state WHERE singleton=1").
		Row().Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != 5 {
		t.Fatalf("denied grants changed policy revision: %d", revision)
	}
	allowedUntil := now.Add(5 * time.Minute)
	share.ExpiresAt = &allowedUntil
	result, err := core.AddGrant(
		sqliteAccessContext(t, sqliteMember, sqliteMemberSession, "grants.add", "bounded", share), share,
	)
	if err != nil || result.GrantID == "" || result.Revision != 6 {
		t.Fatalf("bounded grant: %+v (%v)", result, err)
	}
}

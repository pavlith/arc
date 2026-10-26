package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pavlith/arc/internal/testdb"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
)

type testPolicy struct{ owner, gate, worker, resource string }

func (p *testPolicy) Authorize(_ context.Context, a Authorization) error {
	if a.NeedsApproval {
		return ErrDenied
	}
	if a.Actor == "user:"+p.owner && a.Caller == "" {
		switch a.Operation {
		case "identity.v1.service_accounts.register", "identity.v1.service_accounts.disable", "identity.v1.service_keys.rotate", "identity.v1.keys.revoke", "identity.v1.users.status", "identity.v1.agents.register", "deployment.approved":
			return nil
		case "identity.v1.delegations.create":
			if len(a.Resources) == 1 && a.Resources[0] == p.resource && len(a.Actions) == 1 && a.Actions[0] == "read" {
				return nil
			}
		}
	}
	if a.Audience == "identity/v1" && (a.Caller == p.gate || a.Caller == p.worker) {
		if a.Caller == p.gate {
			switch a.Operation {
			case "identity.v1.sessions.login", "identity.v1.sessions.refresh", "identity.v1.sessions.logout", "identity.v1.sessions.introspect", "identity.v1.invocations.exchange_user", "identity.v1.keys.jwks", "identity.v1.delegations.create", "identity.v1.delegations.get", "identity.v1.delegations.revoke":
				return nil
			}
		}
		if a.Caller == p.worker {
			switch a.Operation {
			case "identity.v1.invocations.exchange_service", "identity.v1.delegations.create", "identity.v1.keys.jwks":
				return nil
			}
		}
	}
	if a.Operation == "task.read" && a.Audience == "task/v1" && a.Caller == p.gate && a.Actor == "user:"+p.owner {
		return nil
	}
	if a.Operation == "calendar.read" && a.Audience == "calendar/v1" && a.Caller == p.worker && a.Actor == "user:"+p.owner {
		if a.Incoming != nil && (a.Incoming.Operation != "task.read" || a.Incoming.Subject != a.Actor) {
			return ErrDenied
		}
		return nil
	}
	if a.DelegationID != "" && a.Caller == p.worker && a.Operation == "task.read" && a.Audience == "task/v1" {
		if a.Actor == "service:"+p.worker {
			return nil
		}
		if a.Actor == "user:"+p.owner && len(a.Resources) == 1 && a.Resources[0] == p.resource && len(a.Actions) == 1 && a.Actions[0] == "read" {
			return nil
		}
	}
	return ErrDenied
}
func TestPasswordAndBrowserContract(t *testing.T) {
	encoded, e := HashPassword("a long test password")
	if e != nil {
		t.Fatal(e)
	}
	if !CheckPassword(encoded, "a long test password") || CheckPassword(encoded, "wrong password") {
		t.Fatal("password verification")
	}
	if _, e = HashPassword("short"); e == nil {
		t.Fatal("accepted short password")
	}
	cookie := SessionCookie("opaque", time.Now())
	if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != 2 {
		t.Fatal("cookie contract")
	}
	if CheckBrowserMutation("https://bad", "https://arc", "x", "x") == nil || CheckBrowserMutation("https://arc", "https://arc", "", "x") == nil {
		t.Fatal("CSRF/origin bypass")
	}
}
func TestFailClosed(t *testing.T) {
	c := &Core{}
	if _, e := c.Introspect(context.Background(), "secret"); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if e := c.allow(context.Background(), Authorization{}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}
func TestSigningSecretPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.seed")
	if e := os.WriteFile(path, bytes.Repeat([]byte{9}, 32), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadSigningKey(path); e != nil {
		t.Fatal(e)
	}
	os.Chmod(path, 0644)
	if _, e := LoadSigningKey(path); e == nil {
		t.Fatal("accepted public secret")
	}
}
func TestM0Identity(t *testing.T) {
	ownerDB, db := testdb.Open(t, "core")
	ctx := context.Background()
	var e error
	now := time.Now().UTC().Truncate(time.Second)
	policy := &testPolicy{resource: "10000000-0000-4000-8000-000000000001"}
	c := &Core{GormDB: ownerDB, Policy: policy, PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), SigningKid: "core-1", Now: func() time.Time { return now }}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	owner, recovery, e := c.BootstrapUser(ctx, "owner@example.test", "owner long password")
	must(e)
	policy.owner = owner
	member, _, e := c.BootstrapUser(ctx, "member@example.test", "member long password")
	must(e)
	must(c.PublishSigningKey(ctx, now.Add(time.Hour)))
	login, e := c.Login(ctx, "owner@example.test", "owner long password")
	must(e)
	auth := UserSession{login.Secret, login.CSRF}
	_, e = c.Verifier().Access(ctx, login.AccessToken)
	must(e)
	gate, e := c.RegisterService(ctx, auth, "gate", "test-gate")
	must(e)
	worker, e := c.RegisterService(ctx, auth, "task", "test-tasks")
	must(e)
	policy.gate = gate
	policy.worker = worker
	gateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	workerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	must(c.AddServiceKey(ctx, auth, gate, "gate-1", gateKey.Public().(ed25519.PublicKey), "mount:gate", now.Add(time.Hour)))
	must(c.AddServiceKey(ctx, auth, worker, "worker-1", workerKey.Public().(ed25519.PublicKey), "mount:tasks", now.Add(time.Hour)))
	assertion := func(service, kid string, key ed25519.PrivateKey) string {
		t.Helper()
		j, e := uuid()
		must(e)
		token, e := security.Sign(key, kid, security.Claims{Issuer: service, Subject: service, Audience: "identity.exchange_service", JTI: j, IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Unix() + 30, Confirmation: security.Confirmation{Kid: kid}})
		must(e)
		return token
	}
	target := Target{Audience: "task/v1", Operation: "task.read"}
	exchange := func() (TokenResult, error) {
		return c.ExchangeUser(ctx, UserExchange{Assertion: assertion(gate, "gate-1", gateKey), Session: auth, Target: target})
	}
	var original TokenResult
	t.Run("JWT_JWKS_proof_persistent_replay", func(t *testing.T) {
		var e error
		original, e = exchange()
		must(e)
		cl, e := c.Verifier().Invocation(ctx, original.Token, target.Audience, target.Operation, gate)
		must(e)
		jwks, e := c.JWKS(ctx)
		must(e)
		pub, e := jwks.PublicKey("core-1")
		must(e)
		if !bytes.Equal(pub, c.PrivateKey.Public().(ed25519.PublicKey)) {
			t.Fatal("JWKS mismatch")
		}
		raw := []byte(`{"request_id":"guardrail","operation":"task.read","payload":{"a":1}}`)
		p, e := security.SignProof(gateKey, "rpc.task.v1.read", raw, cl.JTI, security.Proof{Kid: "gate-1", Timestamp: now.Format(time.RFC3339Nano), Nonce: "persistent-nonce-0001"})
		must(e)
		must(c.Verifier().Proof(ctx, "rpc.task.v1.read", raw, cl, p))
		fresh := &Core{GormDB: ownerDB, Policy: policy, Now: c.Now}
		if e = fresh.Verifier().Proof(ctx, "rpc.task.v1.read", raw, cl, p); e == nil {
			t.Fatal("nonce replay survived new Core instance")
		}
		a := assertion(gate, "gate-1", gateKey)
		_, e = c.Verifier().Assertion(ctx, a)
		must(e)
		if _, e = fresh.Verifier().Assertion(ctx, a); e == nil {
			t.Fatal("assertion replay survived new Core instance")
		}
	})
	t.Run("audience_bound_propagation", func(t *testing.T) {
		next, e := c.ExchangeService(ctx, ServiceExchange{Assertion: assertion(worker, "worker-1", workerKey), IncomingToken: original.Token, IncomingOperation: "task.read", Target: Target{Audience: "calendar/v1", Operation: "calendar.read"}})
		must(e)
		cl, e := c.Verifier().Invocation(ctx, next.Token, "calendar/v1", "calendar.read", worker)
		must(e)
		if cl.Subject != "user:"+owner || cl.SessionID != login.Session.ID || cl.Confirmation.Kid != "worker-1" {
			t.Fatal("lost actor provenance")
		}
		if _, e = c.Verifier().Invocation(ctx, original.Token, "calendar/v1", "calendar.read", worker); e == nil {
			t.Fatal("reused upstream token")
		}
		if _, e = c.ExchangeService(ctx, ServiceExchange{Assertion: assertion(worker, "worker-1", workerKey), IncomingToken: original.Token, IncomingOperation: "task.read", Target: Target{Audience: "calendar/v1", Operation: "calendar.delete"}}); e == nil {
			t.Fatal("expanded downstream authority")
		}
		if _, e = c.ExchangeUser(ctx, UserExchange{Assertion: assertion(worker, "worker-1", workerKey), Session: auth, Target: target}); e == nil {
			t.Fatal("non-Gate user exchange")
		}
	})
	t.Run("memberships_groups_and_personal_identity", func(t *testing.T) {
		workspace, e := c.CreateWorkspace(ctx, auth, "Workspace")
		must(e)
		must(c.SetMembership(ctx, auth, workspace, member, "member", false))
		group, e := c.CreateGroup(ctx, auth, workspace, "Group")
		must(e)
		must(c.SetGroupMember(ctx, auth, workspace, group, member, false))
		other, e := c.CreateWorkspace(ctx, auth, "Other")
		must(e)
		if e = c.SetGroupMember(ctx, auth, other, group, member, false); e == nil {
			t.Fatal("cross-workspace group membership")
		}
		if e = c.SetMembership(ctx, auth, workspace, owner, "member", true); e == nil {
			t.Fatal("revoked last owner")
		}
		memberLogin, e := c.Login(ctx, "member@example.test", "member long password")
		must(e)
		memberAuth := UserSession{memberLogin.Secret, memberLogin.CSRF}
		if e = c.SetMembership(ctx, memberAuth, workspace, member, "owner", false); e == nil {
			t.Fatal("membership escalation")
		}
		must(c.SetMembership(ctx, auth, workspace, member, "member", true))
		if e = c.SetGroupMember(ctx, auth, workspace, group, member, false); e == nil {
			t.Fatal("revoked member joined group")
		}
		_, e = c.Introspect(ctx, memberLogin.Secret)
		must(e)
		must(c.SetMembership(ctx, auth, workspace, member, "owner", false))
		workspaceToken, e := c.ExchangeUser(ctx, UserExchange{Assertion: assertion(gate, "gate-1", gateKey), Session: auth, Target: Target{Audience: "task/v1", Operation: "task.read", WorkspaceID: workspace}})
		must(e)
		must(c.LeaveWorkspace(ctx, auth, workspace))
		if _, e = c.Verifier().Invocation(ctx, workspaceToken.Token, "task/v1", "task.read", gate); e == nil {
			t.Fatal("membership revoke did not invalidate workspace token")
		}
		_, e = c.Verifier().Invocation(ctx, original.Token, "task/v1", "task.read", gate)
		must(e)

	})
	t.Run("delegation_consent_scope_expiry_revoke", func(t *testing.T) {
		d := Delegation{GranteeKind: "service", GranteeID: worker, Resources: []string{policy.resource}, Actions: []string{"read"}}
		if _, e = c.CreateDelegation(ctx, UserSession{}, d); e == nil {
			t.Fatal("service self-delegation")
		}
		agent, e := c.RegisterAgent(ctx, auth, "", "read-tools")
		must(e)
		if _, e = c.CreateDelegation(ctx, UserSession{Secret: agent}, d); e == nil {
			t.Fatal("agent self-delegation")
		}
		bad := d
		bad.Actions = []string{"admin"}
		if _, e = c.CreateDelegation(ctx, auth, bad); e == nil {
			t.Fatal("delegated unauthorized rights")
		}
		bad = d
		bad.Grantor = member
		if _, e = c.CreateDelegation(ctx, auth, bad); e == nil {
			t.Fatal("forged grantor")
		}
		d, e = c.CreateDelegation(ctx, auth, d)
		must(e)
		delegated, e := c.ExchangeService(ctx, ServiceExchange{Assertion: assertion(worker, "worker-1", workerKey), DelegationID: d.ID, Target: target})
		must(e)
		cl, e := c.Verifier().Invocation(ctx, delegated.Token, "task/v1", "task.read", worker)
		must(e)
		if cl.OnBehalfOf != owner || cl.Subject != "service:"+worker {
			t.Fatal("delegation provenance")
		}
		must(c.RevokeDelegation(ctx, auth, d.ID))
		if _, e = c.Verifier().Invocation(ctx, delegated.Token, "task/v1", "task.read", worker); e == nil {
			t.Fatal("revoked delegation accepted")
		}
		exp, e := c.CreateDelegation(ctx, auth, Delegation{GranteeKind: "service", GranteeID: worker, Resources: d.Resources, Actions: d.Actions})
		must(e)
		_, e = db.ExecContext(ctx, `UPDATE identity_delegations SET created_at=?,expires_at=? WHERE id=?`, now.Add(-time.Hour), now.Add(-time.Second), exp.ID)
		must(e)
		if _, e = c.ExchangeService(ctx, ServiceExchange{Assertion: assertion(worker, "worker-1", workerKey), DelegationID: exp.ID, Target: target}); e == nil {
			t.Fatal("expired delegation accepted")
		}
	})
	t.Run("NATS_internal_client_and_unauthenticated_rejection", func(t *testing.T) {
		url := os.Getenv("ARC_IDENTITY_NATS_URL")
		dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
		if url == "" || dir == "" {
			t.Skip("run scripts/test-m0-02.sh for NATS guardrails")
		}
		cfg := sdk.Config{URL: url, Name: "identity-test", TLSCAFile: filepath.Join(dir, "ca.crt"), NKeySeedFile: filepath.Join(dir, "nats-echo-service.seed")}
		deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		service, e := sdk.NewService(deadline, sdk.ServiceConfig{Name: "arc-bootstrap", Version: "0.0.2", Connection: cfg})
		must(e)
		defer service.Stop()
		must(c.BindInternal(service))
		must(service.Connection().Flush())
		cfg.Name = "identity-client"
		cfg.NKeySeedFile = filepath.Join(dir, "nats-smoke-client.seed")
		nc, e := sdk.Connect(deadline, cfg)
		must(e)
		defer nc.Close()
		client, e := rpc.NewClient(nc)
		must(e)
		tc := TestClient{RPC: client, ServiceID: gate, Kid: "gate-1", PrivateKey: gateKey, Now: c.Now}
		got, e := TestCall[IntrospectRequest, Session](deadline, tc, "identity.v1.sessions.introspect", IntrospectRequest{login.Secret})
		must(e)
		if got.UserID != owner {
			t.Fatal("wrong RPC session")
		}
		exchanged, e := TestCall[UserExchange, TokenResult](deadline, tc, "identity.v1.invocations.exchange_user", UserExchange{Session: auth, Target: target})
		must(e)
		_, e = c.Verifier().Invocation(ctx, exchanged.Token, "task/v1", "task.read", gate)
		must(e)
		if _, e = rpc.Call[IntrospectRequest, Session](deadline, client, "identity.v1.sessions.introspect", "rpc.identity.v1.sessions.introspect", IntrospectRequest{login.Secret}); rpc.ErrorCode(e) != rpc.CodeUnauthenticated {
			t.Fatalf("unsigned NATS request accepted: %v", e)
		}

		tc.IdempotencyKey = "delegation-command-1"
		request := DelegationRequest{Session: auth, Delegation: Delegation{GranteeKind: "service", GranteeID: worker, Resources: []string{policy.resource}, Actions: []string{"read"}}}
		first, e := TestCall[DelegationRequest, Delegation](deadline, tc, "identity.v1.delegations.create", request)
		must(e)
		repeated, e := TestCall[DelegationRequest, Delegation](deadline, tc, "identity.v1.delegations.create", request)
		must(e)
		if first.ID != repeated.ID {
			t.Fatal("idempotent command created duplicate delegation")
		}
		var audits int
		must(db.QueryRowContext(ctx, `SELECT count(*) FROM identity_audit WHERE operation='delegations.create' AND target=?`, first.ID).Scan(&audits))
		if audits != 1 {
			t.Fatal("domain mutation/audit were repeated")
		}
		request.Delegation.Actions = []string{"admin"}
		if _, e = TestCall[DelegationRequest, Delegation](deadline, tc, "identity.v1.delegations.create", request); rpc.ErrorCode(e) != rpc.CodeConflict {
			t.Fatalf("idempotency conflict: %v", e)
		}
		tc.IdempotencyKey = ""
		tc.ServiceID = worker
		tc.Kid = "worker-1"
		tc.PrivateKey = workerKey
		if _, e = TestCall[DelegationRequest, Delegation](deadline, tc, "identity.v1.delegations.create", DelegationRequest{Delegation: Delegation{Grantor: owner, GranteeKind: "service", GranteeID: worker, Resources: []string{policy.resource}, Actions: []string{"read"}}}); rpc.ErrorCode(e) != rpc.CodeUnauthenticated {
			t.Fatalf("RPC self-delegation: %v", e)
		}
		must(service.Stop())
		if _, e = rpc.Call[IntrospectRequest, Session](deadline, client, "identity.v1.sessions.introspect", "rpc.identity.v1.sessions.introspect", IntrospectRequest{login.Secret}); rpc.ErrorCode(e) != rpc.CodeUnavailable {
			t.Fatalf("service stop did not synchronize subscriptions: %v", e)
		}

	})
	t.Run("session_revoke_blocks_access_and_invocation", func(t *testing.T) {
		must(c.Logout(ctx, auth))
		if _, e = c.Introspect(ctx, login.Secret); e == nil {
			t.Fatal("session survived logout")
		}
		if _, e = c.Verifier().Invocation(ctx, original.Token, "task/v1", "task.read", gate); e == nil {
			t.Fatal("invocation survived logout")
		}
		if _, e = c.Verifier().Access(ctx, login.AccessToken); e == nil {
			t.Fatal("access survived logout")
		}
	})
	login, e = c.Login(ctx, "owner@example.test", "owner long password")
	must(e)
	auth = UserSession{login.Secret, login.CSRF}
	t.Run("refresh_rotation_reuse_and_concurrency", func(t *testing.T) {
		rotated, e := c.Refresh(ctx, login.Refresh)
		must(e)
		if _, e = c.Refresh(ctx, login.Refresh); e == nil {
			t.Fatal("refresh reuse accepted")
		}
		if _, e = c.Refresh(ctx, rotated.Refresh); e == nil {
			t.Fatal("family not revoked")
		}
		if _, e = c.Introspect(ctx, login.Secret); e == nil {
			t.Fatal("reuse did not revoke session")
		}
		fresh, e := c.Login(ctx, "owner@example.test", "owner long password")
		must(e)
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, e := c.Refresh(ctx, fresh.Refresh); results <- e }()
		}
		wg.Wait()
		close(results)
		success := 0
		for e := range results {
			if e == nil {
				success++
			}
		}
		if success != 1 {
			t.Fatalf("concurrent refresh successes: %d", success)
		}
		if _, e = c.Introspect(ctx, fresh.Secret); e == nil {
			t.Fatal("concurrent reuse not revoked")
		}
	})
	login, e = c.Login(ctx, "owner@example.test", "owner long password")
	must(e)
	auth = UserSession{login.Secret, login.CSRF}
	t.Run("online_credential_and_service_revoke", func(t *testing.T) {
		tok, e := exchange()
		must(e)
		must(c.RevokeKey(ctx, auth, "gate-1", false))
		if _, e = c.Verifier().Invocation(ctx, tok.Token, "task/v1", "task.read", gate); e == nil {
			t.Fatal("revoked credential accepted")
		}
		must(c.DisableService(ctx, auth, worker))
		if _, e = c.Verifier().Assertion(ctx, assertion(worker, "worker-1", workerKey)); e == nil {
			t.Fatal("disabled service accepted")
		}
	})
	t.Run("offline_recovery_revokes_and_rotates", func(t *testing.T) {
		next, e := c.Recover(ctx, "owner@example.test", recovery, "new owner password")
		must(e)
		if next == recovery || next == "" {
			t.Fatal("recovery code not rotated")
		}
		if _, e = c.Introspect(ctx, login.Secret); e == nil {
			t.Fatal("recovery left session live")
		}
		if _, e = c.Recover(ctx, "owner@example.test", recovery, "another long password"); e == nil {
			t.Fatal("recovery code replay")
		}
	})
	t.Run("persistent_rate_limit", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			must(c.rate(ctx, "test:limit"))
		}
		if e = c.rate(ctx, "test:limit"); !errors.Is(e, ErrRateLimited) {
			t.Fatal("rate limit bypass")
		}
	})
}

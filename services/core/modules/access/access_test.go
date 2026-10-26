package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
)

func TestFailClosedAndDomainOwnerBinding(t *testing.T) {
	var c Core
	if _, e := c.Check(context.Background(), CheckRequest{}); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("missing Core did not fail closed: %v", e)
	}
	if _, e := c.CheckMany(context.Background(), CheckManyRequest{Checks: []CheckRequest{{"x", "calendar.read"}}}); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("missing Access did not fail closed: %v", e)
	}
	lookup := rootMap{"event-a": "root-a", "event-b": "root-b"}
	checker := fixedChecker{Decision{Allowed: true, Revision: 5}}
	if _, e := GuardObject(context.Background(), checker, lookup, "event-a", "root-b", "calendar.read"); !errors.Is(e, ErrDenied) {
		t.Fatalf("cross-root spoof allowed: %v", e)
	}
	if d, e := GuardObject(context.Background(), checker, lookup, "event-a", "root-a", "calendar.read"); e != nil || !d.Allowed {
		t.Fatalf("valid owner lookup rejected: %#v %v", d, e)
	}
	if _, e := GuardObject(context.Background(), nil, lookup, "event-a", "root-a", "calendar.read"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("missing ACL checker did not fail closed")
	}
}

type rootMap map[string]string

func (m rootMap) Root(_ context.Context, id string) (string, error) { return m[id], nil }

type fixedChecker struct{ decision Decision }

func (c fixedChecker) Check(context.Context, CheckRequest) (Decision, error) { return c.decision, nil }

type domainFixture struct {
	mu        sync.Mutex
	key       []byte
	committed map[string]bool
}

func (d *domainFixture) commit(id string, exists bool) {
	d.mu.Lock()
	d.committed[id] = exists
	d.mu.Unlock()
}
func (d *domainFixture) receipt(provider, id, op string) string {
	m := hmac.New(sha256.New, d.key)
	m.Write([]byte(provider + "|" + id + "|" + op))
	return hex.EncodeToString(m.Sum(nil))
}
func (d *domainFixture) Confirm(_ context.Context, provider, id, op, receipt string) error {
	if !hmac.Equal([]byte(receipt), []byte(d.receipt(provider, id, op))) {
		return ErrDenied
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	exists := d.committed[id]
	if op == "activate" && !exists || op == "abort" && exists || op == "finalize_delete" && exists {
		return ErrDenied
	}
	return nil
}

type fixture struct {
	t                             *testing.T
	ctx                           context.Context
	db                            *sql.DB
	id                            *identity.Core
	acl                           *Core
	client                        *rpc.Client
	nconn                         *nats.Conn
	service                       *pkgs.Service
	owner, member, gate, provider string
	gateKid, providerKid          string
	ownerAuth, memberAuth         identity.UserSession
	gateKey, providerKey          ed25519.PrivateKey
	domain                        *domainFixture
	now                           time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("ARC_ACCESS_TEST_DSN")
	if dsn == "" {
		t.Skip("run scripts/test-m0-03.sh for PostgreSQL/NATS guardrails")
	}
	ctx := context.Background()
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(16)
	if e = db.PingContext(ctx); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	id := &identity.Core{DB: db, PrivateKey: ed25519.NewKeyFromSeed(bytes32(31)), SigningKid: "access-core-1", Now: func() time.Time { return now }}
	if e = id.PublishSigningKey(ctx, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	owner, _, e := id.BootstrapUser(ctx, "acl-owner@example.test", "access owner password")
	if e != nil {
		t.Fatal(e)
	}
	member, _, e := id.BootstrapUser(ctx, "acl-member@example.test", "access member password")
	if e != nil {
		t.Fatal(e)
	}
	ownerLogin, e := id.Login(ctx, "acl-owner@example.test", "access owner password")
	if e != nil {
		t.Fatal(e)
	}
	memberLogin, e := id.Login(ctx, "acl-member@example.test", "access member password")
	if e != nil {
		t.Fatal(e)
	}
	authority := ed25519.NewKeyFromSeed(bytes32(41))
	deployments := []Deployment{{"gate", "m0-03-gate"}, {"calendar", "m0-03-calendar"}}
	adminApproval := Approval{AdminUsers: []string{owner}, Deployments: deployments}
	contracts := signedContracts(t, authority, adminApproval)
	domain := &domainFixture{key: bytes32(51), committed: map[string]bool{}}
	acl := &Core{DB: db, Identity: id, Contracts: contracts, Domain: domain, Now: func() time.Time { return now }}
	id.Policy = acl
	ownerAuth := identity.UserSession{Secret: ownerLogin.Secret, CSRF: ownerLogin.CSRF}
	memberAuth := identity.UserSession{Secret: memberLogin.Secret, CSRF: memberLogin.CSRF}
	gate, e := id.RegisterService(ctx, ownerAuth, "gate", "m0-03-gate")
	if e != nil {
		t.Fatal(e)
	}
	provider, e := id.RegisterService(ctx, ownerAuth, "calendar", "m0-03-calendar")
	if e != nil {
		t.Fatal(e)
	}
	gateKey := ed25519.NewKeyFromSeed(bytes32(61))
	providerKey := ed25519.NewKeyFromSeed(bytes32(71))
	gateKid := "gate-1-" + gate[:8]
	providerKid := "calendar-1-" + provider[:8]
	if e = id.AddServiceKey(ctx, ownerAuth, gate, gateKid, gateKey.Public().(ed25519.PublicKey), "mount:test-gate", now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = id.AddServiceKey(ctx, ownerAuth, provider, providerKid, providerKey.Public().(ed25519.PublicKey), "mount:test-calendar", now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	all := []string{"access.grants.manage", "calendar.create", "calendar.read", "calendar.free_busy", "calendar.share", "calendar.delete"}
	filesActions := []string{"access.grants.manage", "files.create", "files.read", "files.download", "files.share", "files.delete"}
	typ := TypeSpec{Type: "calendar.root", Provider: provider, Actions: all, ShareAction: "calendar.share", CreateAction: "calendar.create", DeleteAction: "calendar.delete", AllowInheritance: true}
	fileType := TypeSpec{Type: "files.root", Provider: provider, Actions: filesActions, ShareAction: "files.share", CreateAction: "files.create", DeleteAction: "files.delete", AllowInheritance: true}
	rules := []Rule{}
	add := func(caller, audience, operation string, actors, actions, downstream []string) {
		sourceActions := map[string][]string{}
		for _, source := range downstream {
			permitted := actions
			if operation == "access.v1.check" || operation == "access.v1.check_many" || operation == "access.v1.list_accessible_roots" {
				switch source {
				case "calendar/v1:calendar.read":
					permitted = []string{"calendar.read", "files.read", "files.download"}
				case "calendar/v1:calendar.free_busy":
					permitted = []string{"calendar.free_busy"}
				case "calendar/v1:calendar.create":
					permitted = []string{"calendar.create", "files.create"}
				case "calendar/v1:calendar.delete":
					permitted = []string{"calendar.delete", "files.delete"}
				}
			}
			sourceActions[source] = permitted
		}
		rules = append(rules, Rule{Caller: caller, Audience: audience, Operation: operation, ActorKinds: actors, Actions: actions, DownstreamFrom: downstream, DownstreamActions: sourceActions})
	}
	user := []string{"user"}
	userAgent := []string{"user", "agent", "service"}
	downstream := []string{}
	for _, source := range []string{"calendar.create", "calendar.read", "calendar.share", "calendar.free_busy", "calendar.delete"} {
		downstream = append(downstream, "calendar/v1:"+source)
	}

	add(gate, "calendar/v1", "calendar.create", user, all, nil)
	add(gate, "calendar/v1", "calendar.read", user, []string{"calendar.read"}, nil)
	add(gate, "calendar/v1", "calendar.share", user, []string{"calendar.share"}, nil)
	add(gate, "calendar/v1", "calendar.free_busy", user, []string{"calendar.free_busy"}, nil)
	add(gate, "calendar/v1", "calendar.delete", user, []string{"calendar.delete"}, nil)
	add(provider, "access/v1", "access.v1.resource_types.register", user, all, []string{"calendar/v1:calendar.create"})
	add(provider, "access/v1", "access.v1.resources.reserve", user, []string{"calendar.create", "files.create"}, []string{"calendar/v1:calendar.create"})
	add(provider, "access/v1", "access.v1.resources.activate", user, nil, []string{"calendar/v1:calendar.create"})
	add(provider, "access/v1", "access.v1.resources.abort", user, nil, []string{"calendar/v1:calendar.create"})
	add(provider, "access/v1", "access.v1.resources.begin_delete", user, []string{"calendar.delete"}, []string{"calendar/v1:calendar.delete"})
	add(provider, "access/v1", "access.v1.resources.finalize_delete", user, nil, []string{"calendar/v1:calendar.delete"})
	checks := []string{"access.grants.manage", "calendar.create", "calendar.read", "calendar.free_busy", "calendar.share", "calendar.delete", "files.download", "files.read", "files.share", "files.create", "files.delete"}
	add(provider, "access/v1", "access.v1.check", userAgent, checks, downstream)
	add(provider, "access/v1", "access.v1.check_many", user, checks, downstream)
	add(provider, "access/v1", "access.v1.list_accessible_roots", user, checks, downstream)
	add(provider, "access/v1", "access.v1.grants.add", user, checks, []string{"calendar/v1:calendar.share"})
	add(provider, "access/v1", "access.v1.grants.revoke", user, checks, []string{"calendar/v1:calendar.share"})
	add(gate, "identity/v1", "identity.v1.invocations.exchange_user", []string{"bootstrap"}, nil, nil)
	add(provider, "identity/v1", "identity.v1.invocations.exchange_service", []string{"bootstrap"}, nil, nil)
	approval := Approval{Deployments: deployments, Types: []TypeSpec{typ, fileType}, Rules: rules, AgentScopes: map[string][]string{"calendar-freebusy": {"calendar.free_busy"}}, AdminUsers: []string{owner}}
	acl.Contracts = signedContracts(t, authority, approval)
	url := os.Getenv("ARC_IDENTITY_NATS_URL")
	dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
	if url == "" || dir == "" {
		t.Fatal("NATS test broker fixtures required")
	}
	seed := filepath.Join(dir, "nats-echo-service.seed")
	service, e := pkgs.NewService(ctx, pkgs.ServiceConfig{Name: "arc-access", Version: "0.0.3", Connection: pkgs.Config{URL: url, Name: "arc-access", NKeySeedFile: seed, TLSCAFile: filepath.Join(dir, "ca.crt")}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = service.Stop() })
	if e = acl.BindInternal(service); e != nil {
		t.Fatal(e)
	}
	if e = service.Connection().Flush(); e != nil {
		t.Fatal(e)
	}
	nc, e := pkgs.Connect(ctx, pkgs.Config{URL: url, Name: "access-test-client", NKeySeedFile: filepath.Join(dir, "nats-smoke-client.seed"), TLSCAFile: filepath.Join(dir, "ca.crt")})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(nc.Close)
	client, e := rpc.NewClient(nc)
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{t: t, ctx: ctx, db: db, id: id, acl: acl, client: client, service: service, nconn: nc, owner: owner, member: member, gate: gate, provider: provider, gateKid: gateKid, providerKid: providerKid, ownerAuth: ownerAuth, memberAuth: memberAuth, gateKey: gateKey, providerKey: providerKey, domain: domain, now: now}
}
func bytes32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
func signedContracts(t *testing.T, key ed25519.PrivateKey, a Approval) *Contracts {
	t.Helper()
	raw, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	canonical, e := security.CanonicalJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	returnSigned, e := NewContracts(key.Public().(ed25519.PublicKey), []Approved{{Payload: canonical, Signature: ed25519.Sign(key, canonical)}})
	if e != nil {
		t.Fatal(e)
	}
	return returnSigned
}
func (f *fixture) assertion(service, kid string, key ed25519.PrivateKey) string {
	f.t.Helper()
	j, e := uuid()
	if e != nil {
		f.t.Fatal(e)
	}
	n := f.now.Unix()
	token, e := security.Sign(key, kid, security.Claims{Issuer: service, Subject: service, Audience: "identity.exchange_service", JTI: j, IssuedAt: n, NotBefore: n, ExpiresAt: n + 30, Confirmation: security.Confirmation{Kid: kid}})
	if e != nil {
		f.t.Fatal(e)
	}
	return token
}
func (f *fixture) userToken(auth identity.UserSession, sourceOp, workspace, targetOp string) string {
	f.t.Helper()
	source := identity.Target{Audience: "calendar/v1", Operation: sourceOp, WorkspaceID: workspace}
	user, e := f.id.ExchangeUser(f.ctx, identity.UserExchange{Assertion: f.assertion(f.gate, f.gateKid, f.gateKey), Session: auth, Target: source})
	if e != nil {
		f.t.Fatalf("exchange user %s: %v", sourceOp, e)
	}
	target := identity.Target{Audience: "access/v1", Operation: "access.v1." + targetOp, WorkspaceID: workspace}
	serviceToken, e := f.id.ExchangeService(f.ctx, identity.ServiceExchange{Assertion: f.assertion(f.provider, f.providerKid, f.providerKey), IncomingToken: user.Token, IncomingOperation: sourceOp, Target: target})
	if e != nil {
		f.t.Fatalf("exchange service access.%s: %v", targetOp, e)
	}
	return serviceToken.Token
}
func call[Req, Res any](f *fixture, auth identity.UserSession, source, workspace, op, key string, q Req) (Res, error) {
	f.t.Helper()
	var zero Res
	token := f.userToken(auth, source, workspace, op)
	claims, e := f.id.Verifier().Recipient(f.ctx, token, "access/v1", "access.v1."+op)
	if e != nil {
		return zero, e
	}
	nonce := make([]byte, 24)
	if _, e = rand.Read(nonce); e != nil {
		return zero, e
	}
	stamp := f.acl.now().Format(time.RFC3339Nano)
	subject := "rpc.access.v1." + op
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	ctx = rpc.WithCredentials(ctx, rpc.Credentials{Token: token, IdempotencyKey: key, Proof: func(s string, raw []byte) (security.Proof, error) {
		return security.SignProof(f.providerKey, s, raw, claims.JTI, security.Proof{Kid: f.providerKid, Timestamp: stamp, Nonce: hex.EncodeToString(nonce)})
	}})
	return rpc.Call[Req, Res](ctx, f.client, "access.v1."+op, subject, q)
}
func nextKey(f *fixture) string {
	f.t.Helper()
	s, e := uuid()
	if e != nil {
		f.t.Fatal(e)
	}
	return s
}
func reserve(t *testing.T, f *fixture, auth identity.UserSession, ownerKind, owner, workspace, parent, idem string) MutationResult {
	t.Helper()
	r, e := call[ReserveRequest, MutationResult](f, auth, "calendar.create", workspace, "resources.reserve", idem, ReserveRequest{Type: "calendar.root", OwnerKind: ownerKind, OwnerID: owner, WorkspaceID: workspace, ParentID: parent, InheritACL: true})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func check(t *testing.T, f *fixture, auth identity.UserSession, source, workspace, id, action string) Decision {
	t.Helper()
	r, e := call[CheckRequest, Decision](f, auth, source, workspace, "check", nextKey(f), CheckRequest{id, action})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func (f *fixture) accessCallRaw(token, kid string, key ed25519.PrivateKey, op, idem string, q any) error {
	f.t.Helper()
	deadline, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	nonce := make([]byte, 24)
	if _, e := rand.Read(nonce); e != nil {
		f.t.Fatal(e)
	}
	claims, e := f.id.Verifier().Recipient(f.ctx, token, "access/v1", "access.v1."+op)
	if e != nil {
		return e
	}
	ctx := rpc.WithCredentials(deadline, rpc.Credentials{Token: token, IdempotencyKey: idem, Proof: func(s string, raw []byte) (security.Proof, error) {
		return security.SignProof(key, s, raw, claims.JTI, security.Proof{Kid: kid, Timestamp: f.acl.now().Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)})
	}})
	_, e = rpc.Call[any, any](ctx, f.client, "access.v1."+op, "rpc.access.v1."+op, q)
	return e
}

type accessWireRequest struct {
	RequestID      string          `json:"request_id"`
	Operation      string          `json:"operation"`
	SchemaVersion  int             `json:"schema_version"`
	DeadlineAt     time.Time       `json:"deadline_at"`
	Auth           string          `json:"auth"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	Proof          *security.Proof `json:"proof,omitempty"`
}
type accessWireResponse struct {
	RequestID string          `json:"request_id"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     *rpc.Error      `json:"error,omitempty"`
}

func (f *fixture) rawInvoke(token, jti, kid string, key ed25519.PrivateKey, op, idem string, payload any, proofNonce string, requestID string) (accessWireResponse, error) {
	f.t.Helper()
	var out accessWireResponse
	rawPayload, e := json.Marshal(payload)
	if e != nil {
		return out, e
	}
	deadline := time.Now().Add(5 * time.Second).UTC()
	env := accessWireRequest{RequestID: requestID, Operation: "access.v1." + op, SchemaVersion: rpc.SchemaVersion, DeadlineAt: deadline, Auth: token, IdempotencyKey: idem, Payload: rawPayload}
	unsigned, e := json.Marshal(env)
	if e != nil {
		return out, e
	}
	p, e := security.SignProof(key, "rpc.access.v1."+op, unsigned, jti, security.Proof{Kid: kid, Timestamp: f.acl.now().Format(time.RFC3339Nano), Nonce: proofNonce})
	if e != nil {
		return out, e
	}
	env.Proof = &p
	wire, e := json.Marshal(env)
	if e != nil {
		return out, e
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	msg, e := f.nconn.RequestWithContext(ctx, "rpc.access.v1."+op, wire)
	if e != nil {
		return out, e
	}
	if msg.Header.Get("Nats-Service-Error-Code") != "" {
		return out, &rpc.Error{Code: rpc.Code(msg.Header.Get("Nats-Service-Error-Code")), Message: "service error"}
	}
	e = json.Unmarshal(msg.Data, &out)
	return out, e
}
func accessClaims(f *fixture, caller, audience, op, subject, sid string) security.Claims {
	now := f.now.Unix()
	j, e := uuid()
	if e != nil {
		f.t.Fatal(e)
	}
	return security.Claims{Issuer: "arc-core", Audience: audience, Subject: subject, Caller: caller, Operation: op, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60, JTI: j, Confirmation: security.Confirmation{Kid: f.providerKid}, SessionID: sid}
}

func TestM0Access(t *testing.T) {
	f := newFixture(t)
	if d, e := call[RegisterRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resource_types.register", nextKey(f), RegisterRequest{Type: "calendar.root", ContractDigest: f.acl.Contracts.digests["calendar.root"]}); e != nil || d.State != "registered" {
		t.Fatalf("register approved type: %#v %v", d, e)
	}
	if d, e := call[RegisterRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resource_types.register", nextKey(f), RegisterRequest{Type: "files.root", ContractDigest: f.acl.Contracts.digests["files.root"]}); e != nil || d.State != "registered" {
		t.Fatalf("register files type: %#v %v", d, e)
	}
	for _, q := range []RegisterRequest{{Type: "rogue.root", ContractDigest: f.acl.Contracts.digests["calendar.root"]}, {Type: "calendar.root", ContractDigest: "bad-digest"}} {
		if _, err := call[RegisterRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resource_types.register", nextKey(f), q); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("unapproved type: %v", err)
		}
	}
	root := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", nextKey(f))
	// Reserve is not visible until the domain owner confirms its committed object.
	if d := check(t, f, f.ownerAuth, "calendar.read", "", root.ResourceID, "calendar.read"); d.Allowed {
		t.Fatal("reserved resource was granted access")
	}
	if _, err := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", activatedKey(f, root.ResourceID), LifecycleRequest{ResourceID: root.ResourceID, Receipt: "unconfirmed"}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
		t.Fatalf("uncommitted activation: %v", err)
	}
	f.domain.commit(root.ResourceID, true)
	activated, e := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", activatedKey(f, root.ResourceID), LifecycleRequest{ResourceID: root.ResourceID, Receipt: f.domain.receipt(f.provider, root.ResourceID, "activate")})
	if e != nil || activated.State != "active" {
		t.Fatalf("activate: %#v %v", activated, e)
	}
	// Simulate Core restart after committed activation and a lost response.
	if err := f.service.Stop(); err != nil {
		t.Fatal(err)
	}
	replacement := *f.acl
	f.acl = &replacement
	f.id.Policy = f.acl
	dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
	f.service, e = pkgs.NewService(f.ctx, pkgs.ServiceConfig{Name: "arc-access", Version: "0.0.3", Connection: pkgs.Config{URL: os.Getenv("ARC_IDENTITY_NATS_URL"), Name: "access-restarted", NKeySeedFile: filepath.Join(dir, "nats-echo-service.seed"), TLSCAFile: filepath.Join(dir, "ca.crt")}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.service.Stop() })
	if e = f.acl.BindInternal(f.service); e != nil {
		t.Fatal(e)
	}
	if e = f.service.Connection().Flush(); e != nil {
		t.Fatal(e)
	}
	repeat, e := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", activatedKey(f, root.ResourceID), LifecycleRequest{ResourceID: root.ResourceID, Receipt: f.domain.receipt(f.provider, root.ResourceID, "activate")})
	if e != nil || repeat.State != "active" || repeat.Revision != activated.Revision {
		t.Fatalf("repeat activate: %#v %v", repeat, e)
	}
	if check(t, f, f.ownerAuth, "calendar.free_busy", "", root.ResourceID, "calendar.read").Allowed {
		t.Fatal("free_busy invocation expanded to read for resource owner")
	}
	if !check(t, f, f.ownerAuth, "calendar.read", "", root.ResourceID, "calendar.read").Allowed {
		t.Fatal("personal owner lost own resource")
	}
	if check(t, f, f.memberAuth, "calendar.read", "", root.ResourceID, "calendar.read").Allowed {
		t.Fatal("unshared personal resource leaked")
	}
	// Reserve retries preserve the original UUID; payload changes conflict.
	same := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", "reserve-stable-key")
	retry := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", "reserve-stable-key")
	if retry.ResourceID != same.ResourceID {
		t.Fatal("reserve retry allocated a second UUID")
	}
	_, e = call[ReserveRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.reserve", "reserve-stable-key", ReserveRequest{Type: "calendar.root", OwnerKind: "user", OwnerID: f.member, InheritACL: true})
	if rpc.ErrorCode(e) != rpc.CodeConflict {
		t.Fatalf("changed reserve payload: %v", e)
	}
	if _, e = call[ReserveRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.reserve", nextKey(f), ReserveRequest{Type: "calendar.root", OwnerKind: "workspace", OwnerID: f.owner, WorkspaceID: f.owner, ParentID: root.ResourceID, InheritACL: true}); e == nil {
		t.Fatal("workspace/user owner scope mismatch allowed")
	}
	// A member in two workspaces keeps B and personal access after leaving A.
	wsA, e := f.id.CreateWorkspace(f.ctx, f.ownerAuth, "A")
	if e != nil {
		t.Fatal(e)
	}
	wsB, e := f.id.CreateWorkspace(f.ctx, f.ownerAuth, "B")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.id.SetMembership(f.ctx, f.ownerAuth, wsA, f.member, "admin", false); e != nil {
		t.Fatal(e)
	}
	if e = f.id.SetMembership(f.ctx, f.ownerAuth, wsB, f.member, "member", false); e != nil {
		t.Fatal(e)
	}
	a := reserve(t, f, f.ownerAuth, "workspace", wsA, wsA, "", nextKey(f))
	b := reserve(t, f, f.ownerAuth, "workspace", wsB, wsB, "", nextKey(f))
	memberPersonal := reserve(t, f, f.memberAuth, "user", f.member, "", "", nextKey(f))
	f.domain.commit(memberPersonal.ResourceID, true)
	if _, e = call[LifecycleRequest, MutationResult](f, f.memberAuth, "calendar.create", "", "resources.activate", nextKey(f), LifecycleRequest{ResourceID: memberPersonal.ResourceID, Receipt: f.domain.receipt(f.provider, memberPersonal.ResourceID, "activate")}); e != nil {
		t.Fatal(e)
	}
	f.domain.commit(a.ResourceID, true)
	f.domain.commit(b.ResourceID, true)
	for _, entry := range []struct {
		resource  MutationResult
		workspace string
	}{{a, wsA}, {b, wsB}} {
		r := entry.resource
		if _, e = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", entry.workspace, "resources.activate", nextKey(f), LifecycleRequest{ResourceID: r.ResourceID, Receipt: f.domain.receipt(f.provider, r.ResourceID, "activate")}); e != nil {
			t.Fatal(e)
		}
	}
	// The workspace owner creates an explicit share to the member in B.
	grant, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", "grant-member-b", GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"})
	if e != nil {
		t.Fatal(e)
	}
	if !check(t, f, f.memberAuth, "calendar.read", wsB, b.ResourceID, "calendar.read").Allowed {
		t.Fatal("direct workspace grant not honored")
	}
	if _, e = call[GrantRequest, MutationResult](f, f.memberAuth, "calendar.share", wsB, "grants.add", "member-cannot-share", GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.owner, Action: "calendar.read"}); e == nil {
		t.Fatal("share expanded a member's own permissions")
	}
	grantA, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsA, "grants.add", nextKey(f), GrantRequest{ResourceID: a.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"})
	if e != nil {
		t.Fatal(e)
	}
	beforeLeave := f.userToken(f.memberAuth, "calendar.read", wsA, "check")
	beforeLeaveClaims, e := f.id.Verifier().Recipient(f.ctx, beforeLeave, "access/v1", "access.v1.check")
	if e != nil {
		t.Fatal(e)
	}
	if !check(t, f, f.memberAuth, "calendar.read", wsA, a.ResourceID, "calendar.read").Allowed {
		t.Fatal("A grant was not active before leave")
	}
	if e = f.id.LeaveWorkspace(f.ctx, f.memberAuth, wsA); e != nil {
		t.Fatal(e)
	}
	if _, e = f.accessCallDecision(beforeLeave, beforeLeaveClaims, "check", CheckRequest{a.ResourceID, "calendar.read"}); rpc.ErrorCode(e) != rpc.CodePermissionDenied {
		t.Fatalf("old workspace invocation survived membership revoke: %v", e)
	}
	if check(t, f, f.memberAuth, "calendar.read", "", a.ResourceID, "calendar.read").Allowed {
		t.Fatal("membership revoke did not deny A")
	}
	if !check(t, f, f.memberAuth, "calendar.read", wsB, b.ResourceID, "calendar.read").Allowed {
		t.Fatal("leaving A revoked B access")
	}
	if !check(t, f, f.ownerAuth, "calendar.read", "", root.ResourceID, "calendar.read").Allowed {
		t.Fatal("workspace leave changed personal root")
	}
	if !check(t, f, f.memberAuth, "calendar.read", "", memberPersonal.ResourceID, "calendar.read").Allowed {
		t.Fatal("leaving workspace removed member's personal resource")
	}
	// Restore A membership to test the administrator policy separately.
	if e = f.id.SetMembership(f.ctx, f.ownerAuth, wsA, f.member, "admin", false); e != nil {
		t.Fatal(e)
	}
	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsA, "grants.revoke", nextKey(f), RevokeRequest{GrantID: grantA.GrantID}); e != nil {
		t.Fatal(e)
	}
	// The workspace administrator gets ACL control, never implicit content access.
	if !check(t, f, f.memberAuth, "calendar.share", wsA, a.ResourceID, "access.grants.manage").Allowed {
		t.Fatal("workspace admin cannot manage ACL")
	}
	if check(t, f, f.memberAuth, "calendar.read", wsA, a.ResourceID, "calendar.read").Allowed {
		t.Fatal("workspace admin implicitly reads calendar content")
	}
	file, er := call[ReserveRequest, MutationResult](f, f.ownerAuth, "calendar.create", wsA, "resources.reserve", nextKey(f), ReserveRequest{Type: "files.root", OwnerKind: "workspace", OwnerID: wsA, WorkspaceID: wsA, InheritACL: true})
	if er != nil {
		t.Fatal(er)
	}
	f.domain.commit(file.ResourceID, true)
	if _, er = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", wsA, "resources.activate", nextKey(f), LifecycleRequest{ResourceID: file.ResourceID, Receipt: f.domain.receipt(f.provider, file.ResourceID, "activate")}); er != nil {
		t.Fatal(er)
	}
	if check(t, f, f.memberAuth, "calendar.read", wsA, file.ResourceID, "files.download").Allowed {
		t.Fatal("workspace administrator implicitly downloads files")
	}
	// Granting the admin a content right is an explicit, separately audited act.
	selfGrant, er := call[GrantRequest, MutationResult](f, f.memberAuth, "calendar.share", wsA, "grants.add", "admin-self-grant", GrantRequest{ResourceID: a.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"})
	if er != nil {
		t.Fatalf("admin self-grant should be explicit and allowed: %v", er)
	}
	if !check(t, f, f.memberAuth, "calendar.read", wsA, a.ResourceID, "calendar.read").Allowed {
		t.Fatal("explicit self-grant did not allow read")
	}
	auditCount := 0
	if er = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.policy_audit WHERE resource_id=$1 AND change_kind='self_grant' AND grant_id IS NOT NULL AND change->'grant'->>'action'='calendar.read'`, a.ResourceID).Scan(&auditCount); er != nil {
		t.Fatal(er)
	}
	if auditCount != 1 {
		t.Fatalf("self-grant audit count=%d", auditCount)
	}
	if _, er = call[RevokeRequest, MutationResult](f, f.memberAuth, "calendar.share", wsA, "grants.revoke", "admin-self-revoke", RevokeRequest{GrantID: selfGrant.GrantID}); er != nil {
		t.Fatal(er)
	}
	if check(t, f, f.memberAuth, "calendar.read", wsA, a.ResourceID, "calendar.read").Allowed {
		t.Fatal("revoked self-grant remained effective")
	}
	if _, er = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", "revoke-member-read", RevokeRequest{GrantID: grant.GrantID}); er != nil {
		t.Fatal(er)
	}
	if check(t, f, f.memberAuth, "calendar.read", wsB, b.ResourceID, "calendar.read").Allowed {
		t.Fatal("revoked direct grant remained effective")
	}

	// Workspace group and exact role grants use current Identity principals.
	group, e := f.id.CreateGroup(f.ctx, f.ownerAuth, wsB, "readers")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.id.SetGroupMember(f.ctx, f.ownerAuth, wsB, group, f.member, false); e != nil {
		t.Fatal(e)
	}
	groupGrant, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "group", PrincipalID: group, Action: "calendar.free_busy"})
	if e != nil {
		t.Fatal(e)
	}
	if !check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.free_busy").Allowed {
		t.Fatal("current group grant missing")
	}
	if e = f.id.SetGroupMember(f.ctx, f.ownerAuth, wsB, group, f.member, true); e != nil {
		t.Fatal(e)
	}
	if check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.free_busy").Allowed {
		t.Fatal("group revoke not visible")
	}
	for _, entry := range []struct{ kind, id string }{{"role", "member"}, {"service", f.provider}} {
		g, err := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: entry.kind, PrincipalID: entry.id, Action: "calendar.free_busy"})
		if err != nil {
			t.Fatal(err)
		}
		if entry.kind == "role" {
			if !check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.free_busy").Allowed {
				t.Fatal("member role grant missing")
			}
		} else {
			token, err := f.id.ExchangeService(f.ctx, identity.ServiceExchange{Assertion: f.assertion(f.provider, f.providerKid, f.providerKey), Target: identity.Target{Audience: "access/v1", Operation: "access.v1.check", WorkspaceID: wsB}})
			if err != nil {
				t.Fatal(err)
			}
			claims, err := f.id.Verifier().Recipient(f.ctx, token.Token, "access/v1", "access.v1.check")
			if err != nil {
				t.Fatal(err)
			}
			if decision, err := f.accessCallDecision(token.Token, claims, "check", CheckRequest{b.ResourceID, "calendar.free_busy"}); err != nil || !decision.Allowed {
				t.Fatalf("explicit service grant: %#v %v", decision, err)
			}
			if decision, err := f.accessCallDecision(token.Token, claims, "check", CheckRequest{b.ResourceID, "calendar.read"}); err != nil || decision.Allowed {
				t.Fatalf("service grant expanded: %#v %v", decision, err)
			}
		}
		if _, err := call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", nextKey(f), RevokeRequest{GrantID: g.GrantID}); err != nil {
			t.Fatal(err)
		}
	}
	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", nextKey(f), RevokeRequest{GrantID: groupGrant.GrantID}); e != nil {
		t.Fatal(e)
	}

	// A normal share preserves action and time limits of the actor's permissions.
	shareUntil, readUntil := f.now.Add(time.Hour), f.now.Add(time.Minute)
	sharePermission, err := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.share", ExpiresAt: &shareUntil})
	if err != nil {
		t.Fatal(err)
	}
	temporaryRead, err := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read", ExpiresAt: &readUntil})
	if err != nil {
		t.Fatal(err)
	}
	tooLate := readUntil.Add(time.Second)
	for _, until := range []*time.Time{nil, &tooLate} {
		if _, err := call[GrantRequest, MutationResult](f, f.memberAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.owner, Action: "calendar.read", ExpiresAt: until}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("share extended rights: %v", err)
		}
	}
	short := f.now.Add(30 * time.Second)
	shared, err := call[GrantRequest, MutationResult](f, f.memberAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.owner, Action: "calendar.read", ExpiresAt: &short})
	if err != nil {
		t.Fatalf("bounded share: %v", err)
	}
	for _, act := range []string{"access.grants.manage", "calendar.free_busy"} {
		if _, err := call[GrantRequest, MutationResult](f, f.memberAuth, "calendar.share", wsB, "grants.add", nextKey(f), GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.owner, Action: act, ExpiresAt: &short}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("share expanded action: %s %v", act, err)
		}
	}
	for _, g := range []MutationResult{shared, temporaryRead, sharePermission} {
		if _, err := call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", nextKey(f), RevokeRequest{GrantID: g.GrantID}); err != nil {
			t.Fatal(err)
		}
	}
	// free_busy and read stay separate; grants are principal/action-specific.
	expiry := f.acl.now().Add(time.Second)
	freebusy, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", "freebusy-grant", GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.free_busy", ExpiresAt: &expiry})
	if e != nil {
		t.Fatal(e)
	}
	if !check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.free_busy").Allowed {
		t.Fatal("free_busy grant not honored")
	}
	if check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.read").Allowed {
		t.Fatal("free_busy escalated to read")
	}
	ownerFree, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", "owner-freebusy-grant", GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.owner, Action: "calendar.free_busy"})
	if e != nil {
		t.Fatal(e)
	}
	agent, e := f.id.RegisterAgent(f.ctx, f.ownerAuth, wsB, "calendar-freebusy")
	if e != nil {
		t.Fatal(e)
	}
	delegation, e := f.id.CreateDelegation(f.ctx, f.ownerAuth, identity.Delegation{GranteeKind: "agent", GranteeID: agent, Resources: []string{b.ResourceID}, Actions: []string{"calendar.free_busy"}})
	if e != nil {
		t.Fatal(e)
	}
	shortDelegation, err := f.id.CreateDelegation(f.ctx, f.ownerAuth, identity.Delegation{GranteeKind: "agent", GranteeID: agent, Resources: []string{b.ResourceID}, Actions: []string{"calendar.free_busy"}, ExpiresAt: f.now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	shortToken, err := f.id.ExchangeService(f.ctx, identity.ServiceExchange{Assertion: f.assertion(f.provider, f.providerKid, f.providerKey), DelegationID: shortDelegation.ID, Target: identity.Target{Audience: "access/v1", Operation: "access.v1.check", WorkspaceID: wsB}})
	if err != nil {
		t.Fatal(err)
	}
	shortClaims, err := f.id.Verifier().Recipient(f.ctx, shortToken.Token, "access/v1", "access.v1.check")
	if err != nil {
		t.Fatal(err)
	}
	f.id.Now = func() time.Time { return f.now.Add(2 * time.Second) }
	f.acl.Now = f.id.Now
	if _, err = f.accessCallDecision(shortToken.Token, shortClaims, "check", CheckRequest{b.ResourceID, "calendar.free_busy"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
		t.Fatalf("expired delegation invocation accepted: %v", err)
	}
	f.id.Now = func() time.Time { return f.now }
	f.acl.Now = f.id.Now
	delegated, e := f.id.ExchangeService(f.ctx, identity.ServiceExchange{Assertion: f.assertion(f.provider, f.providerKid, f.providerKey), DelegationID: delegation.ID, Target: identity.Target{Audience: "access/v1", Operation: "access.v1.check", WorkspaceID: wsB}})
	if e != nil {
		t.Fatal(e)
	}
	dclaims, e := f.id.Verifier().Recipient(f.ctx, delegated.Token, "access/v1", "access.v1.check")
	if e != nil {
		t.Fatal(e)
	}
	if dclaims.Subject != "agent:"+agent || dclaims.OnBehalfOf != f.owner {
		t.Fatal("delegated actor provenance missing")
	}
	agentDecision, e := f.accessCallDecision(delegated.Token, dclaims, "check", CheckRequest{b.ResourceID, "calendar.free_busy"})
	if e != nil || !agentDecision.Allowed {
		t.Fatalf("delegated permitted action denied: %#v %v", agentDecision, e)
	}
	if denied, e := f.accessCallDecision(delegated.Token, dclaims, "check", CheckRequest{b.ResourceID, "calendar.read"}); e != nil || denied.Allowed {
		t.Fatalf("delegation/tool intersection expanded to read: %#v %v", denied, e)
	}
	if e = f.id.RevokeDelegation(f.ctx, f.ownerAuth, delegation.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", "revoke-owner-freebusy", RevokeRequest{GrantID: ownerFree.GrantID}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.accessCallDecision(delegated.Token, dclaims, "check", CheckRequest{b.ResourceID, "calendar.free_busy"}); rpc.ErrorCode(e) != rpc.CodePermissionDenied {
		t.Fatalf("revoked delegation still allowed: %v", e)
	}

	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", "revoke-freebusy", RevokeRequest{GrantID: freebusy.GrantID}); e != nil {
		t.Fatal(e)
	}
	if check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.free_busy").Allowed {
		t.Fatal("revoked grant remained effective")
	}
	// Expired grants are denied even when the user still belongs to the workspace.
	expired := f.acl.now().Add(time.Second)
	expGrant, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.add", "expired-grant", GrantRequest{ResourceID: b.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.free_busy", ExpiresAt: &expired})
	if e != nil {
		t.Fatal(e)
	}
	f.acl.Now = func() time.Time { return f.now.Add(2 * time.Second) }
	if check(t, f, f.memberAuth, "calendar.free_busy", wsB, b.ResourceID, "calendar.free_busy").Allowed {
		t.Fatal("expired grant remained effective")
	}
	// Reset the test clock and revoke the remaining grant by grant-admin.
	f.acl.Now = func() time.Time { return f.now }
	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", "revoke-expired", RevokeRequest{GrantID: expGrant.GrantID}); e != nil {
		t.Fatal(e)
	}
	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", wsB, "grants.revoke", nextKey(f), RevokeRequest{GrantID: grant.GrantID}); e != nil {
		t.Fatal(e)
	}

	// Parent grants stop at inherit_acl=false; parent and child retain same owner.
	parent := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", nextKey(f))
	f.domain.commit(parent.ResourceID, true)
	if _, e = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", nextKey(f), LifecycleRequest{ResourceID: parent.ResourceID, Receipt: f.domain.receipt(f.provider, parent.ResourceID, "activate")}); e != nil {
		t.Fatal(e)
	}
	parentGrant, e := call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", "", "grants.add", "parent-share", GrantRequest{ResourceID: parent.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"})
	if e != nil {
		t.Fatal(e)
	}
	child, e := call[ReserveRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.reserve", nextKey(f), ReserveRequest{Type: "calendar.root", OwnerKind: "user", OwnerID: f.owner, ParentID: parent.ResourceID, InheritACL: false})
	if e != nil {
		t.Fatal(e)
	}
	f.domain.commit(child.ResourceID, true)
	if _, e = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", nextKey(f), LifecycleRequest{ResourceID: child.ResourceID, Receipt: f.domain.receipt(f.provider, child.ResourceID, "activate")}); e != nil {
		t.Fatal(e)
	}
	if !check(t, f, f.memberAuth, "calendar.read", "", parent.ResourceID, "calendar.read").Allowed || check(t, f, f.memberAuth, "calendar.read", "", child.ResourceID, "calendar.read").Allowed {
		t.Fatal("inherit_acl=false boundary failed")
	}

	// The SQL invariant also forbids reparenting into a cycle.
	if _, err := f.db.ExecContext(f.ctx, `UPDATE access.resources SET acl_parent_id=$2 WHERE id=$1`, parent.ResourceID, child.ResourceID); err == nil {
		t.Fatal("SQL allowed an ACL cycle")
	}
	for _, q := range []ReserveRequest{
		{Type: "calendar.root", OwnerKind: "user", OwnerID: f.member, ParentID: parent.ResourceID, InheritACL: true},
		{Type: "calendar.root", OwnerKind: "user", OwnerID: f.owner, ParentID: "00000000-0000-4000-8000-000000000099", InheritACL: true},
	} {
		if _, err := call[ReserveRequest, MutationResult](f, f.memberAuth, "calendar.create", "", "resources.reserve", nextKey(f), q); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("invalid parent accepted: %v", err)
		}
	}
	// CheckMany is one repeatable-read snapshot with one revision for all pairs.
	many, e := call[CheckManyRequest, CheckManyResult](f, f.memberAuth, "calendar.read", "", "check_many", nextKey(f), CheckManyRequest{Checks: []CheckRequest{{parent.ResourceID, "calendar.read"}, {child.ResourceID, "calendar.read"}, {child.ResourceID, "calendar.free_busy"}}})
	if e != nil {
		t.Fatal(e)
	}
	if many.Revision <= 0 || len(many.Decisions) != 3 || !many.Decisions[0].Allowed || many.Decisions[1].Allowed || many.Decisions[2].Allowed {
		t.Fatalf("invalid CheckMany result: %#v", many)
	}
	for _, d := range many.Decisions {
		if d.Revision != many.Revision {
			t.Fatal("CheckMany mixed policy revisions")
		}
	}
	if _, e = call[CheckManyRequest, CheckManyResult](f, f.memberAuth, "calendar.read", "", "check_many", nextKey(f), CheckManyRequest{Checks: make([]CheckRequest, 101)}); rpc.ErrorCode(e) != rpc.CodeValidation {
		t.Fatalf("CheckMany accepted >100 entries: %v", e)
	}
	batch := CheckManyRequest{Checks: make([]CheckRequest, 100)}
	for i := range batch.Checks {
		batch.Checks[i] = CheckRequest{parent.ResourceID, "calendar.read"}
	}
	batchDone := make(chan struct {
		result CheckManyResult
		err    error
	}, 1)
	go func() {
		r, err := call[CheckManyRequest, CheckManyResult](f, f.memberAuth, "calendar.read", "", "check_many", nextKey(f), batch)
		batchDone <- struct {
			result CheckManyResult
			err    error
		}{r, err}
	}()
	if _, e = call[RevokeRequest, MutationResult](f, f.ownerAuth, "calendar.share", "", "grants.revoke", nextKey(f), RevokeRequest{GrantID: parentGrant.GrantID}); e != nil {
		t.Fatal(e)
	}
	concurrent := <-batchDone
	if concurrent.err != nil || len(concurrent.result.Decisions) != 100 {
		t.Fatalf("concurrent batch: %v", concurrent.err)
	}
	for _, d := range concurrent.result.Decisions {
		if d.Allowed != concurrent.result.Decisions[0].Allowed || d.Revision != concurrent.result.Revision {
			t.Fatal("batch mixed policy states during concurrent revoke")
		}
	}
	if check(t, f, f.memberAuth, "calendar.read", "", parent.ResourceID, "calendar.read").Allowed {
		t.Fatal("post-commit Check retained revoked parent grant")
	}
	if _, e = call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", "", "grants.add", nextKey(f), GrantRequest{ResourceID: parent.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"}); e != nil {
		t.Fatal(e)
	}
	pageRoot := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", nextKey(f))
	f.domain.commit(pageRoot.ResourceID, true)
	if _, e = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", nextKey(f), LifecycleRequest{ResourceID: pageRoot.ResourceID, Receipt: f.domain.receipt(f.provider, pageRoot.ResourceID, "activate")}); e != nil {
		t.Fatal(e)
	}
	if _, e = call[GrantRequest, MutationResult](f, f.ownerAuth, "calendar.share", "", "grants.add", nextKey(f), GrantRequest{ResourceID: pageRoot.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"}); e != nil {
		t.Fatal(e)
	}
	// Accessible-root listing returns only matching resource metadata and pages.
	listed, e := call[ListRequest, ListResult](f, f.memberAuth, "calendar.read", "", "list_accessible_roots", nextKey(f), ListRequest{Action: "calendar.read", OwnerKind: "user", OwnerID: f.owner, Type: "calendar.root", Limit: 1})
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range listed.Resources {
		d := check(t, f, f.memberAuth, "calendar.read", "", r.ID, "calendar.read")
		if !d.Allowed {
			t.Fatal("list disclosed an inaccessible resource")
		}
	}
	if len(listed.Resources) > 1 {
		t.Fatal("page exceeded limit")
	}
	if listed.NextCursor == "" {
		t.Fatal("accessible roots page omitted cursor")
	}
	second, e := call[ListRequest, ListResult](f, f.memberAuth, "calendar.read", "", "list_accessible_roots", nextKey(f), ListRequest{Action: "calendar.read", OwnerKind: "user", OwnerID: f.owner, Type: "calendar.root", Limit: 1, Cursor: listed.NextCursor})
	if e != nil {
		t.Fatal(e)
	}
	if len(second.Resources) != 1 || second.Resources[0].ID == listed.Resources[0].ID {
		t.Fatalf("second root page leaked/skipped roots: %#v", second)
	}

	// Cross-root object binding is resolved by the trusted domain-owner fixture.
	if _, e = GuardObject(f.ctx, apiChecker{f: f, auth: f.ownerAuth}, rootMap{parent.ResourceID: parent.ResourceID}, parent.ResourceID, child.ResourceID, "calendar.read"); !errors.Is(e, ErrDenied) {
		t.Fatalf("claimed foreign root accepted: %v", e)
	}

	// Invalid proof/JWT fails before handler mutation; no operation row is added.
	token := f.userToken(f.ownerAuth, "calendar.share", "", "grants.add")
	before := 0
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.operations`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	e = f.accessCallRaw(token, f.providerKid, ed25519.NewKeyFromSeed(bytes32(99)), "grants.add", nextKey(f), GrantRequest{ResourceID: root.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"})
	if rpc.ErrorCode(e) != rpc.CodeUnauthenticated {
		t.Fatalf("bad proof accepted: %v", e)
	}
	var after int
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.operations`).Scan(&after); e != nil {
		t.Fatal(e)
	}
	if after != before {
		t.Fatal("bad proof caused a mutation")
	}

	readSource, err := f.id.ExchangeUser(f.ctx, identity.UserExchange{Assertion: f.assertion(f.gate, f.gateKid, f.gateKey), Session: f.ownerAuth, Target: identity.Target{Audience: "calendar/v1", Operation: "calendar.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.id.ExchangeService(f.ctx, identity.ServiceExchange{Assertion: f.assertion(f.provider, f.providerKid, f.providerKey), IncomingToken: readSource.Token, IncomingOperation: "calendar.read", Target: identity.Target{Audience: "access/v1", Operation: "access.v1.grants.add"}}); !errors.Is(err, ErrDenied) {
		t.Fatalf("read invocation expanded into ACL mutation: %v", err)
	}
	// Signed but wrong caller/audience/operation proofs fail before state changes.
	proofTokenResult, e := f.id.ExchangeUser(f.ctx, identity.UserExchange{Assertion: f.assertion(f.gate, f.gateKid, f.gateKey), Session: f.ownerAuth, Target: identity.Target{Audience: "calendar/v1", Operation: "calendar.share"}})
	if e != nil {
		t.Fatal(e)
	}
	validSource, e := f.id.ExchangeService(f.ctx, identity.ServiceExchange{Assertion: f.assertion(f.provider, f.providerKid, f.providerKey), IncomingToken: proofTokenResult.Token, IncomingOperation: "calendar.share", Target: identity.Target{Audience: "access/v1", Operation: "access.v1.grants.add"}})
	if e != nil {
		t.Fatal(e)
	}
	validClaims, e := f.id.Verifier().Recipient(f.ctx, validSource.Token, "access/v1", "access.v1.grants.add")
	if e != nil {
		t.Fatal(e)
	}
	beforeOps := 0
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.operations`).Scan(&beforeOps); e != nil {
		t.Fatal(e)
	}
	for name, claims := range map[string]security.Claims{
		"caller":    accessClaims(f, "00000000-0000-4000-8000-000000000099", "access/v1", "access.v1.grants.add", "user:"+f.owner, validClaims.SessionID),
		"audience":  validClaims,
		"operation": validClaims,
	} {
		switch name {
		case "audience":
			claims.Audience = "wrong/v1"
		case "operation":
			claims.Operation = "access.v1.check"
		}
		bad, e := security.Sign(f.id.PrivateKey, f.id.SigningKid, claims)
		if e != nil {
			t.Fatal(e)
		}
		resp, e := f.rawInvoke(bad, claims.JTI, f.providerKid, f.providerKey, "grants.add", nextKey(f), GrantRequest{ResourceID: root.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"}, "invalid-proof-nonce-"+name, nextKey(f))
		if e != nil {
			t.Fatal(e)
		}
		if resp.Error == nil || resp.Error.Code != rpc.CodeUnauthenticated {
			t.Fatalf("invalid %s accepted: %#v", name, resp)
		}
	}
	afterOps := 0
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.operations`).Scan(&afterOps); e != nil || afterOps != beforeOps {
		t.Fatalf("invalid JWT caused state change: %d %d %v", beforeOps, afterOps, e)
	}
	// Replaying the exact signed command (same request id, proof nonce and
	// idempotency key) is rejected before it can reach the mutation handler.
	idem := "proof-replay-grant"
	requestID, _ := uuid()
	nonce := "proof-replay-nonce-00000001"
	payload := GrantRequest{ResourceID: root.ResourceID, PrincipalKind: "user", PrincipalID: f.member, Action: "calendar.read"}
	first, e := f.rawInvoke(validSource.Token, validClaims.JTI, f.providerKid, f.providerKey, "grants.add", idem, payload, nonce, requestID)
	if e != nil || first.Error != nil {
		t.Fatalf("initial signed command: %#v %v", first, e)
	}
	replay, e := f.rawInvoke(validSource.Token, validClaims.JTI, f.providerKid, f.providerKey, "grants.add", idem, payload, nonce, requestID)
	if e != nil || replay.Error == nil || replay.Error.Code != rpc.CodeUnauthenticated {
		t.Fatalf("exact proof replay accepted: %#v %v", replay, e)
	}
	replayCount := 0
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.operations WHERE operation='grants.add' AND idempotency_key=$1`, idem).Scan(&replayCount); e != nil || replayCount != 1 {
		t.Fatalf("replayed mutation count=%d error=%v", replayCount, e)
	}

	// Concurrent reserve retries serialize on the policy revision lock and reuse
	// the same durable idempotency result.
	q := ReserveRequest{Type: "calendar.root", OwnerKind: "user", OwnerID: f.owner, InheritACL: true}
	const key = "concurrent-reserve"
	results := make(chan MutationResult, 8)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := call[ReserveRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.reserve", key, q)
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	var id string
	var reserveRevision int64
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	for r := range results {
		if id == "" {
			id = r.ResourceID
			reserveRevision = r.Revision
		} else if id != r.ResourceID || reserveRevision != r.Revision {
			t.Fatal("concurrent reserve allocated more than one UUID")
		}
	}
	var count int
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.resources WHERE id=$1`, id).Scan(&count); e != nil || count != 1 {
		t.Fatalf("concurrent reserve rows=%d error=%v", count, e)
	}
	if e = f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM access.policy_audit WHERE resource_id=$1`, id).Scan(&count); e != nil || count != 1 {
		t.Fatalf("concurrent reserve audit count=%d error=%v", count, e)
	}

	// Abort and delete are confirmed, idempotent transitions; deleting blocks checks immediately.
	abort := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", nextKey(f))
	aborted, e := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.abort", nextKey(f), LifecycleRequest{ResourceID: abort.ResourceID, Receipt: f.domain.receipt(f.provider, abort.ResourceID, "abort")})
	if e != nil || aborted.State != "aborted" {
		t.Fatalf("abort: %#v %v", aborted, e)
	}
	if _, err := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.abort", nextKey(f), LifecycleRequest{ResourceID: abort.ResourceID, Receipt: f.domain.receipt(f.provider, abort.ResourceID, "abort")}); err != nil {
		t.Fatal(err)
	}
	del := reserve(t, f, f.ownerAuth, "user", f.owner, "", "", nextKey(f))
	f.domain.commit(del.ResourceID, true)
	if _, e = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.create", "", "resources.activate", nextKey(f), LifecycleRequest{ResourceID: del.ResourceID, Receipt: f.domain.receipt(f.provider, del.ResourceID, "activate")}); e != nil {
		t.Fatal(e)
	}
	if _, e = call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.delete", "", "resources.begin_delete", nextKey(f), LifecycleRequest{ResourceID: del.ResourceID}); e != nil {
		t.Fatal(e)
	}
	if check(t, f, f.ownerAuth, "calendar.read", "", del.ResourceID, "calendar.read").Allowed {
		t.Fatal("deleting resource remained accessible")
	}
	f.domain.commit(del.ResourceID, false)
	final, e := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.delete", "", "resources.finalize_delete", nextKey(f), LifecycleRequest{ResourceID: del.ResourceID, Receipt: f.domain.receipt(f.provider, del.ResourceID, "finalize_delete")})
	if e != nil || final.State != "deleted" {
		t.Fatalf("finalize delete: %#v %v", final, e)
	}
	for _, op := range []string{"begin_delete", "finalize_delete"} {
		if _, err := call[LifecycleRequest, MutationResult](f, f.ownerAuth, "calendar.delete", "", "resources."+op, nextKey(f), LifecycleRequest{ResourceID: del.ResourceID, Receipt: f.domain.receipt(f.provider, del.ResourceID, op)}); err != nil {
			t.Fatal(err)
		}
	}

	// A missing/closed Identity store makes the same signed request unavailable.
	badToken := f.userToken(f.ownerAuth, "calendar.read", "", "check")
	badClaims, err := f.id.Verifier().Recipient(f.ctx, badToken, "access/v1", "access.v1.check")
	if err != nil {
		t.Fatal(err)
	}
	memberToken := f.userToken(f.memberAuth, "calendar.read", "", "check")
	memberClaims, err := f.id.Verifier().Recipient(f.ctx, memberToken, "access/v1", "access.v1.check")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.id.Logout(f.ctx, f.memberAuth); err != nil {
		t.Fatal(err)
	}
	if _, err = f.accessCallDecision(memberToken, memberClaims, "check", CheckRequest{parent.ResourceID, "calendar.read"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
		t.Fatalf("revoked session accepted: %v", err)
	}
	if err = f.id.RevokeKey(f.ctx, f.ownerAuth, f.providerKid, false); err != nil {
		t.Fatal(err)
	}
	if _, err = f.accessCallDecision(badToken, badClaims, "check", CheckRequest{root.ResourceID, "calendar.read"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
		t.Fatalf("revoked caller key accepted: %v", err)
	}
	broken := *f.id
	broken.DB = nil
	f.acl.Identity = &broken
	if _, e = f.accessCallDecision(badToken, badClaims, "check", CheckRequest{root.ResourceID, "calendar.read"}); rpc.ErrorCode(e) != rpc.CodeUnavailable {
		t.Fatalf("missing Identity did not fail closed: %v", e)
	}
	if err = f.service.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err = f.accessCallDecision(badToken, badClaims, "check", CheckRequest{root.ResourceID, "calendar.read"}); rpc.ErrorCode(err) != rpc.CodeUnavailable {
		t.Fatalf("no Access responder: %v", err)
	}

}
func activatedKey(f *fixture, id string) string { return "activate:" + id }

type apiChecker struct {
	f    *fixture
	auth identity.UserSession
}

func (c apiChecker) Check(ctx context.Context, q CheckRequest) (Decision, error) {
	return check(c.f.t, c.f, c.auth, "calendar.read", "", q.ResourceID, q.Action), nil
}

func (f *fixture) accessCallDecision(token string, claims security.Claims, op string, q CheckRequest) (Decision, error) {
	nonce := make([]byte, 24)
	if _, e := rand.Read(nonce); e != nil {
		return Decision{}, e
	}
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	ctx = rpc.WithCredentials(ctx, rpc.Credentials{Token: token, Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(f.providerKey, subject, raw, claims.JTI, security.Proof{Kid: f.providerKid, Timestamp: f.acl.now().Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)})
	}})
	return (&Client{RPC: f.client}).Check(ctx, q)
}

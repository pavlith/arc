package fabric

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/events"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/internal/testcontract"
	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
)

func key(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
func sign(t *testing.T, k ed25519.PrivateKey, v any) (json.RawMessage, []byte) {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = security.CanonicalJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	return raw, ed25519.Sign(k, raw)
}
func approved(t *testing.T, k ed25519.PrivateKey, a access.Approval) access.Approved {
	raw, sig := sign(t, k, a)
	return access.Approved{Payload: raw, Signature: sig}
}
func assertion(t *testing.T, account, kid string, k ed25519.PrivateKey) string {
	t.Helper()
	now := time.Now()
	raw, e := security.Sign(k, kid, security.Claims{Issuer: account, Subject: account, Audience: "identity.exchange_service", JTI: randomID(), IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(25 * time.Second).Unix(), Confirmation: security.Confirmation{Kid: kid}})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

type request struct {
	RootID string `json:"root_id"`
	Value  string `json:"value"`
}
type response struct {
	Value string `json:"value"`
}

func credentials(t *testing.T, token, kid string, k ed25519.PrivateKey, idem string) rpc.Credentials {
	t.Helper()
	return rpc.Credentials{Token: token, IdempotencyKey: idem, Proof: func(subject string, raw []byte) (security.Proof, error) {
		// Decode only the JTI of an already issued token; verification remains server-side.
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return security.Proof{}, security.ErrUnauthenticated
		}
		b, e := decodeTokenPart(parts[1])
		if e != nil {
			return security.Proof{}, e
		}
		var cl security.Claims
		if json.Unmarshal(b, &cl) != nil {
			return security.Proof{}, security.ErrUnauthenticated
		}
		return security.SignProof(k, subject, raw, cl.JTI, security.Proof{Kid: kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: randomID()})
	}}
}

func TestM0Fabric(t *testing.T) {
	dsn := os.Getenv("ARC_ACCESS_TEST_DSN")
	if dsn == "" {
		t.Skip("run scripts/test-m0-04.sh")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	db, e := sql.Open("pgx", dsn)
	must(e)
	defer db.Close()
	db.SetMaxOpenConns(24)
	adminDB, e := sql.Open("pgx", strings.Replace(dsn, "user=arc_core", "user=arc_migrator", 1))
	must(e)
	defer adminDB.Close()
	_, e = adminDB.ExecContext(ctx, `CREATE SCHEMA books_fixture; CREATE TABLE books_fixture.command_results (LIKE fabric.command_results INCLUDING ALL); CREATE TABLE books_fixture.outbox (LIKE fabric.outbox INCLUDING ALL); CREATE TABLE books_fixture.inbox (LIKE fabric.inbox INCLUDING ALL); CREATE TABLE books_fixture.items (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,value text NOT NULL); GRANT USAGE ON SCHEMA books_fixture TO arc_core; GRANT ALL ON ALL TABLES IN SCHEMA books_fixture TO arc_core; GRANT ALL ON ALL SEQUENCES IN SCHEMA books_fixture TO arc_core`)
	must(e)
	operator := key(101)
	coreKey := key(102)
	gateKey := key(103)
	providerKey := key(104)
	secondKey := key(105)
	id := &identity.Core{DB: db, PrivateKey: coreKey, SigningKid: "fabric-core"}
	must(id.PublishSigningKey(ctx, time.Now().Add(time.Hour)))
	owner, _, e := id.BootstrapUser(ctx, "fabric-owner@example.test", "fabric owner password")
	must(e)
	login, e := id.Login(ctx, "fabric-owner@example.test", "fabric owner password")
	must(e)
	auth := identity.UserSession{Secret: login.Secret, CSRF: login.CSRF}
	baseline := access.Approval{AdminUsers: []string{owner}, Deployments: []access.Deployment{{Definition: "gate", Instance: "fabric-gate"}, {Definition: "books", Instance: "books-v1"}, {Definition: "books", Instance: "books-v2"}}}
	static, e := access.NewContracts(operator.Public().(ed25519.PublicKey), []access.Approved{approved(t, operator, baseline)})
	must(e)
	acl := &access.Core{DB: db, Identity: id, Contracts: static}
	id.Policy = acl
	gate, e := id.RegisterService(ctx, auth, "gate", "fabric-gate")
	must(e)
	provider, e := id.RegisterService(ctx, auth, "books", "books-v1")
	must(e)
	provider2, e := id.RegisterService(ctx, auth, "books", "books-v2")
	must(e)
	must(id.AddServiceKey(ctx, auth, gate, "fabric-gate-key", gateKey.Public().(ed25519.PublicKey), "mount:fixture", time.Now().Add(time.Hour)))
	must(id.AddServiceKey(ctx, auth, provider, "fabric-provider-key", providerKey.Public().(ed25519.PublicKey), "mount:fixture", time.Now().Add(time.Hour)))
	must(id.AddServiceKey(ctx, auth, provider2, "fabric-second-key", secondKey.Public().(ed25519.PublicKey), "mount:fixture", time.Now().Add(time.Hour)))
	baseline.Rules = []access.Rule{{Caller: gate, Audience: "identity/v1", Operation: "identity.v1.invocations.exchange_user", ActorKinds: []string{"bootstrap"}}, {Caller: provider, Audience: "identity/v1", Operation: "identity.v1.invocations.exchange_service", ActorKinds: []string{"bootstrap"}}, {Caller: provider2, Audience: "identity/v1", Operation: "identity.v1.invocations.exchange_service", ActorKinds: []string{"bootstrap"}}}
	f := &Core{DB: db, Identity: id, ApprovalKey: operator.Public().(ed25519.PublicKey), Bootstrap: []access.Approved{approved(t, operator, baseline)}, SnapshotKey: key(106)}
	acl.ContractSource = f
	dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
	url := os.Getenv("ARC_IDENTITY_NATS_URL")
	cfg := func(name, seed string) pkgs.Config {
		return pkgs.Config{URL: url, Name: name, NKeySeedFile: filepath.Join(dir, seed), TLSCAFile: filepath.Join(dir, "ca.crt")}
	}
	coreNC, e := pkgs.Connect(ctx, cfg("fabric-core", "nats-echo-service.seed"))
	must(e)
	defer coreNC.Close()
	closeControl, e := f.BindControl(coreNC)
	must(e)
	defer closeControl()
	accessSvc, e := pkgs.NewService(ctx, pkgs.ServiceConfig{Name: "arc-access", Version: "0.0.4", Connection: cfg("fabric-access", "nats-echo-service.seed")})
	must(e)
	defer accessSvc.Stop()
	must(acl.BindInternal(accessSvc))
	must(accessSvc.Connection().Flush())
	callerNC, e := pkgs.Connect(ctx, cfg("fabric-caller", "nats-smoke-client.seed"))
	must(e)
	defer callerNC.Close()
	caller, e := rpc.NewClient(callerNC)
	must(e)
	jsNC, e := pkgs.Connect(ctx, cfg("fabric-events", "nats-jetstream-admin.seed"))
	must(e)
	defer jsNC.Close()
	js, e := jsNC.JetStream(nats.MaxWait(time.Second))
	must(e)
	// M0-01 smoke already installed ARC_EVENTS; add an isolated DLQ stream.
	_, e = js.AddStream(&nats.StreamConfig{Name: "FABRIC_DLQ", Subjects: []string{"dlq.>"}, Storage: nats.MemoryStorage})
	must(e)
	install := func(major int, account, deployment string) (contract.Artifact, string) {
		t.Helper()
		a := testcontract.Artifact(major)
		compiled, e := contract.Compile(a)
		must(e)
		r := compiled.Manifest.Resources[0]
		p := access.Approval{ContractDigests: map[string]string{r.Type: compiled.Digest}, Types: []access.TypeSpec{{Type: r.Type, Provider: account, Actions: r.Actions, ShareAction: r.ShareAction, CreateAction: r.CreateAction, DeleteAction: r.DeleteAction, AllowInheritance: r.AllowInheritance}}}
		subjects := []string{}
		for _, o := range compiled.Manifest.Operations {
			subjects = append(subjects, o.Subject)
			p.Rules = append(p.Rules, access.Rule{Caller: gate, Audience: fmt.Sprintf("books/v%d", major), Operation: o.ID, ActorKinds: []string{"user"}, Actions: []string{o.Auth.Action}})
		}
		p.Rules = append(p.Rules, access.Rule{Caller: account, Audience: "access/v1", Operation: "access.v1.check", ActorKinds: []string{"user"}, Actions: []string{"books.read", "books.create"}, DownstreamFrom: []string{fmt.Sprintf("books/v%d:books.read", major), fmt.Sprintf("books/v%d:books.create", major)}, DownstreamActions: map[string][]string{fmt.Sprintf("books/v%d:books.read", major): {"books.read"}, fmt.Sprintf("books/v%d:books.create", major): {"books.create"}}})
		i := Installation{Publisher: "fixture-publisher", Account: account, Deployment: deployment, Artifact: a, Subjects: subjects, Policy: approved(t, operator, p)}
		raw, sig := sign(t, operator, i)
		digest, e := f.Approve(ctx, SignedInstallation{raw, sig})
		must(e)
		repeat, e := f.Approve(ctx, SignedInstallation{raw, sig})
		if e != nil || repeat != digest {
			t.Fatal("approval retry", e)
		}
		sig[0] ^= 1
		if _, e = f.Approve(ctx, SignedInstallation{raw, sig}); !errors.Is(e, security.ErrUnauthenticated) {
			t.Fatal("forged install accepted", e)
		}
		return a, digest
	}
	a, digest := install(1, provider, "books-v1")
	a2, digest2 := install(2, provider2, "books-v2")
	// Fixture ACL roots are bootstrapped only by the owning domain, then all RPCs use live Access.
	root := "b0000000-0000-4000-8000-000000000001"
	root2 := "b0000000-0000-4000-8000-000000000002"
	for n, row := range []struct{ id, typ, provider string }{{root, "books.root_v1", provider}, {root2, "books.root_v2", provider2}} {
		_, e = db.ExecContext(ctx, `INSERT INTO access.resources(id,type,provider_service,owner_kind,owner_id,owner_user_id,inherit_acl,state,policy_revision) VALUES($1,$2,$3,'user',$4,$4,true,'active',$5)`, row.id, row.typ, row.provider, owner, n+1)
		must(e)
	}
	var executed atomic.Int64
	store := events.Store{DB: db, Schema: "books_fixture"}
	start := func(artifact contract.Artifact, account, kid string, priv ed25519.PrivateKey, instance, expectedRoot string) (*pkgs.App, *Client) {
		t.Helper()
		registry := &Client{CoreKey: f.SnapshotKey.Public().(ed25519.PublicKey), Account: account, Kid: kid, Key: priv}
		compiled, e := contract.Compile(artifact)
		must(e)
		major := compiled.Manifest.Service.APIMajor
		app, e := pkgs.NewApp(pkgs.AppConfig{Connection: cfg("books-"+instance, "nats-echo-service.seed"), Artifact: artifact, Instance: instance, Registry: registry, SelfCheck: func(context.Context) error { return nil }, Authorize: rpc.InvocationAuthorizer(id.Verifier(), fmt.Sprintf("books/v%d", major)), Resource: func(ctx context.Context, root, action string) error {
			// A real owner resolves file/event IDs in its own DB; this fixture pins the root.
			if root != expectedRoot {
				return security.ErrDenied
			}
			incoming, ok := rpc.InvocationToken(ctx)
			if !ok {
				return security.ErrUnauthenticated
			}
			cl, ok := rpc.VerifiedClaims(ctx)
			if !ok {
				return security.ErrUnauthenticated
			}
			target, e := id.ExchangeService(ctx, identity.ServiceExchange{Assertion: assertion(t, account, kid, priv), IncomingToken: incoming, IncomingOperation: cl.Operation, IncomingAPIMajor: major, Target: identity.Target{Audience: "access/v1", Operation: "access.v1.check"}})
			if e != nil {
				return e
			}
			rc, e := rpc.NewClient(registry.NC)
			if e != nil {
				return e
			}
			tokenCtx := rpc.WithCredentials(ctx, credentials(t, target.Token, kid, priv, ""))
			d, e := (&access.Client{RPC: rc}).Check(tokenCtx, access.CheckRequest{ResourceID: root, Action: action})
			if e != nil {
				return e
			}
			if !d.Allowed {
				return security.ErrDenied
			}
			return nil
		}})
		must(e)
		must(pkgs.Handle(app, "books.read", func(_ context.Context, q request) (response, error) {
			executed.Add(1)
			if q.Value == "invalid-response" {
				return response{}, nil
			}
			return response{fmt.Sprintf("v%d:%s", major, q.Value)}, nil
		}))
		must(pkgs.HandleCommand(app, "books.create", store, func(ctx context.Context, tx *sql.Tx, q request) (response, error) {
			if _, e := tx.ExecContext(ctx, `INSERT INTO books_fixture.items(value) VALUES($1)`, q.Value); e != nil {
				return response{}, e
			}
			ev := events.Envelope{ID: fmt.Sprintf("c0000000-0000-4000-8000-%012d", executed.Add(1)), Type: "books.item.created", Version: 1, AggregateID: q.RootID, OccurredAt: time.Now().UTC(), Payload: json.RawMessage(`{"value":"created"}`)}
			if e := store.Enqueue(ctx, tx, compiled, fmt.Sprintf("evt.books.item.created.v%d", major), ev); e != nil {
				return response{}, e
			}
			if q.Value == "rollback" {
				return response{}, nil
			}
			return response{q.Value}, nil
		}))
		must(app.Start(ctx))
		t.Cleanup(func() { _ = app.Stop() })
		return app, registry
	}
	app, registry := start(a, provider, "fabric-provider-key", providerKey, "books-instance-v1", root)
	app2, _ := start(a2, provider2, "fabric-second-key", secondKey, "books-instance-v2", root2)
	_ = app2
	// Replay and request-proof tampering on the new control boundary have no effects.
	ctlAssertion := func(audience string) string {
		now := time.Now()
		tok, e := security.Sign(providerKey, "fabric-provider-key", security.Claims{Issuer: provider, Subject: provider, Audience: audience, JTI: randomID(), IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(25 * time.Second).Unix(), Confirmation: security.Confirmation{Kid: "fabric-provider-key"}})
		must(e)
		return tok
	}
	makeControl := func(audience string) controlRequest {
		q := controlRequest{RequestID: randomID(), Assertion: ctlAssertion(audience), Registration: pkgs.Registration{Service: "books", Instance: "proof-test-instance", Build: "1.0.0", Digest: digest}}
		parts := strings.Split(q.Assertion, ".")
		b, _ := decodeTokenPart(parts[1])
		var cl security.Claims
		must(json.Unmarshal(b, &cl))
		raw, _ := json.Marshal(q)
		q.Proof, e = security.SignProof(providerKey, RegisterSubject, raw, cl.JTI, security.Proof{Kid: "fabric-provider-key", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: randomID()})
		must(e)
		return q
	}
	rawControl := func(q controlRequest) controlResponse {
		raw, _ := json.Marshal(q)
		cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
		defer ccancel()
		msg, e := app.Connection().RequestWithContext(cctx, RegisterSubject, raw)
		must(e)
		var res controlResponse
		must(json.Unmarshal(msg.Data, &res))
		return res
	}
	validCtl := makeControl(RegisterSubject)
	if res := rawControl(validCtl); res.Error != nil {
		t.Fatal("valid control proof", res.Error)
	}
	if res := rawControl(validCtl); res.Error == nil || res.Error.Code != rpc.CodeUnauthenticated {
		t.Fatal("control replay accepted", res)
	}
	badCtl := makeControl(RegisterSubject)
	badCtl.Registration.Instance = "tampered-instance"
	if res := rawControl(badCtl); res.Error == nil || res.Error.Code != rpc.CodeUnauthenticated {
		t.Fatal("control payload tampering accepted", res)
	}
	if res := rawControl(makeControl("identity.exchange_service")); res.Error == nil || res.Error.Code != rpc.CodeUnauthenticated {
		t.Fatal("control audience mismatch accepted", res)
	}
	var mutations int
	must(db.QueryRowContext(ctx, `SELECT count(*) FROM fabric.instances WHERE instance_id='tampered-instance'`).Scan(&mutations))
	if mutations != 0 {
		t.Fatal("invalid control proof mutated registry")
	}

	token := func(major int, op string) string {
		t.Helper()
		res, e := id.ExchangeUser(ctx, identity.UserExchange{Assertion: assertion(t, gate, "fabric-gate-key", gateKey), Session: auth, Target: identity.Target{Audience: fmt.Sprintf("books/v%d", major), Operation: op}})
		must(e)
		return res.Token
	}
	call := func(tok, operation, subject, idem string, q any) (response, error) {
		cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
		defer ccancel()
		cctx = rpc.WithCredentials(cctx, credentials(t, tok, "fabric-gate-key", gateKey, idem))
		return rpc.Call[any, response](cctx, caller, operation, subject, q)
	}
	liveInstances, e := f.Discover(ctx, "books", 1)
	must(e)
	if len(liveInstances) != 1 || liveInstances[0].ID != "books-instance-v1" {
		t.Fatal("discovery did not isolate ready instances", liveInstances)
	}
	wrongCore := &Client{Account: provider, Kid: "fabric-provider-key", Key: providerKey, NC: app.Connection(), CoreKey: key(107).Public().(ed25519.PublicKey)}
	if e = wrongCore.Check(ctx, pkgs.Registration{Service: "books", Instance: "books-instance-v1", Build: "1.0.0", Digest: digest}); !errors.Is(e, security.ErrUnauthenticated) {
		t.Fatal("untrusted Core response accepted", e)
	}
	tok := token(1, "books.read")
	v, e := call(tok, "books.read", "rpc.books.v1.read", "", request{root, "hello"})
	if e != nil || v.Value != "v1:hello" {
		t.Fatal("approved live Identity+Access+Fabric RPC", v, e)
	}
	v, e = call(token(2, "books.read"), "books.read", "rpc.books.v2.read", "", request{root2, "hello"})
	if e != nil || v.Value != "v2:hello" {
		t.Fatal("major v2", v, e)
	}
	before := executed.Load()
	_, e = call(tok, "books.read", "rpc.books.v2.read", "", request{root2, "spoof"})
	if rpc.ErrorCode(e) != rpc.CodeUnauthenticated {
		t.Fatal("major isolation", e)
	}
	_, e = call(tok, "books.read", "rpc.books.v1.read", "", map[string]any{"root_id": root, "value": ""})
	if rpc.ErrorCode(e) != rpc.CodeValidation {
		t.Fatal("invalid request schema", e)
	}
	_, e = call(tok, "books.read", "rpc.books.v1.read", "", request{root2, "spoof"})
	if rpc.ErrorCode(e) != rpc.CodePermissionDenied {
		t.Fatal("cross-root", e)
	}
	if executed.Load() != before {
		t.Fatal("rejected request reached handler")
	}
	_, e = call(tok, "books.read", "rpc.books.v1.read", "", request{root, "invalid-response"})
	if rpc.ErrorCode(e) != rpc.CodeInternal {
		t.Fatal("invalid response schema", e)
	}
	createToken := token(1, "books.create")
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := call(createToken, "books.create", "rpc.books.v1.create", "stable-command", request{root, "created"})
			failures <- e
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		must(e)
	}
	var count int
	must(db.QueryRowContext(ctx, `SELECT count(*) FROM books_fixture.items WHERE value='created'`).Scan(&count))
	if count != 1 {
		t.Fatal("duplicate command effects", count)
	}
	_, e = call(createToken, "books.create", "rpc.books.v1.create", "stable-command", request{root, "different"})
	if rpc.ErrorCode(e) != rpc.CodeConflict {
		t.Fatal("changed idempotency payload", e)
	}
	_, e = call(createToken, "books.create", "rpc.books.v1.create", "rollback-command", request{root, "rollback"})
	if rpc.ErrorCode(e) != rpc.CodeInternal {
		t.Fatal("response validation before commit", e)
	}
	must(db.QueryRowContext(ctx, `SELECT count(*) FROM books_fixture.items WHERE value='rollback'`).Scan(&count))
	if count != 0 {
		t.Fatal("invalid response committed domain effect")
	}
	compiled, e := contract.Compile(a)
	must(e)
	delivery := events.Delivery{Store: store, Contract: compiled, Permit: func(ctx context.Context) error {
		return registry.Check(ctx, pkgs.Registration{Service: "books", Instance: "books-instance-v1", Build: "1.0.0", Digest: digest})
	}}
	n, e := delivery.PublishBatch(ctx, js, 100)
	if e != nil || n != 1 {
		t.Fatal("outbox publish", n, e)
	}
	eventSubject := "evt.books.item.created.v1"
	var raw []byte
	must(db.QueryRowContext(ctx, `SELECT envelope FROM books_fixture.outbox WHERE published_at IS NOT NULL LIMIT 1`).Scan(&raw))
	// Force broker redelivery with another message ID; the DB inbox still suppresses it.
	_, e = js.Publish(eventSubject, raw, nats.MsgId(randomID()))
	must(e)
	consume := func(ctx context.Context, tx *sql.Tx, ev events.Envelope) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO books_fixture.items(value) VALUES('consumed')`)
		return e
	}
	pctx, pcancel := context.WithTimeout(ctx, time.Second)
	e = delivery.Pull(pctx, js, eventSubject, "books-fixture-consumer", consume)
	pcancel()
	must(e)
	must(db.QueryRowContext(ctx, `SELECT count(*) FROM books_fixture.items WHERE value='consumed'`).Scan(&count))
	if count != 1 {
		t.Fatal("duplicate event effects", count)
	}
	if _, e = js.ConsumerInfo("ARC_EVENTS", "books-fixture-consumer"); e != nil {
		t.Fatal("durable consumer deleted after batch", e)
	}
	// Inbox rollback must let the next delivery retry the internal effect.
	var ev events.Envelope
	must(json.Unmarshal(raw, &ev))
	ev.ID = "c0000000-0000-4000-8000-000000009999"
	retryRaw, _ := json.Marshal(ev)
	e = store.Consume(ctx, "rollback-consumer", eventSubject, compiled, retryRaw, func(ctx context.Context, tx *sql.Tx, _ events.Envelope) error {
		_, e := tx.ExecContext(ctx, `INSERT INTO books_fixture.items(value) VALUES('rollback-effect')`)
		if e != nil {
			return e
		}
		return errors.New("fixture crash")
	})
	if e == nil {
		t.Fatal("crash not propagated")
	}
	must(store.Consume(ctx, "rollback-consumer", eventSubject, compiled, retryRaw, consume))
	must(db.QueryRowContext(ctx, `SELECT count(*) FROM books_fixture.items WHERE value='rollback-effect'`).Scan(&count))
	if count != 0 {
		t.Fatal("inbox/domain not atomic")
	}
	snap, e := f.Routes(ctx)
	must(e)
	routes, e := VerifySnapshot(f.SnapshotKey.Public().(ed25519.PublicKey), snap, 0)
	must(e)
	if len(routes.Routes) != 4 {
		t.Fatal("approved routes missing", routes)
	}
	// Unknown digest and stolen account cannot register business instances.
	bad := &Client{CoreKey: f.SnapshotKey.Public().(ed25519.PublicKey), Account: provider, Kid: "fabric-provider-key", Key: providerKey, NC: app.Connection()}
	e = bad.Register(ctx, app.Connection(), pkgs.Registration{Service: "books", Instance: "rogue", Build: "1.0.0", Digest: strings.Repeat("0", 64)})
	if !errors.Is(e, security.ErrDenied) {
		t.Fatal("rogue digest", e)
	}
	e = bad.Register(ctx, app.Connection(), pkgs.Registration{Service: "books", Instance: "rogue", Build: "1.0.0", Digest: digest2})
	if !errors.Is(e, security.ErrDenied) {
		t.Fatal("foreign account registration", e)
	}
	revRaw, revSig := sign(t, operator, Revocation{Digest: digest, Revoke: true})
	must(f.Revoke(ctx, revRaw, revSig))
	_, e = call(tok, "books.read", "rpc.books.v1.read", "", request{root, "after revoke"})
	if rpc.ErrorCode(e) != rpc.CodePermissionDenied {
		t.Fatal("revoked contract accepted", e)
	}
	if _, e = id.ExchangeUser(ctx, identity.UserExchange{Assertion: assertion(t, gate, "fabric-gate-key", gateKey), Session: auth, Target: identity.Target{Audience: "books/v1", Operation: "books.read"}}); !errors.Is(e, security.ErrDenied) {
		t.Fatal("revoked policy exchange", e)
	}
	v, e = call(token(2, "books.read"), "books.read", "rpc.books.v2.read", "", request{root2, "alive"})
	if e != nil || v.Value != "v2:alive" {
		t.Fatal("v1 revoke affected v2", e)
	}
	newSnap, e := f.Routes(ctx)
	must(e)
	newRoutes, e := VerifySnapshot(f.SnapshotKey.Public().(ed25519.PublicKey), newSnap, routes.Revision)
	must(e)
	if len(newRoutes.Routes) != 2 || newRoutes.Revision <= routes.Revision {
		t.Fatal("revoked routes remained published", newRoutes)
	}
	closeControl()
	_, e = call(token(2, "books.read"), "books.read", "rpc.books.v2.read", "", request{root2, "offline"})
	if rpc.ErrorCode(e) != rpc.CodeUnavailable {
		t.Fatal("Fabric unavailable did not fail closed", e)
	}
}

func decodeTokenPart(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

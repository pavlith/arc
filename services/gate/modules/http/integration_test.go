package gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/events"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/internal/testcontract"
	"github.com/pavlith/arc/pkgs/rpc"
	"github.com/pavlith/arc/pkgs/security"
)

func testKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
func signValue(t *testing.T, key ed25519.PrivateKey, v any) (json.RawMessage, []byte) {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = security.CanonicalJSON(raw)
	if e != nil {
		t.Fatal(e)
	}
	return raw, ed25519.Sign(key, raw)
}
func signApproval(t *testing.T, k ed25519.PrivateKey, a access.Approval) access.Approved {
	raw, sig := signValue(t, k, a)
	return access.Approved{Payload: raw, Signature: sig}
}
func gateArtifact() contract.Artifact {
	a := testcontract.Artifact(1)
	a.Manifest = bytes.ReplaceAll(a.Manifest, []byte("books"), []byte("tasks"))
	var m contract.Manifest
	_ = json.Unmarshal(a.Manifest, &m)
	for i := range m.Operations {
		m.Operations[i].HTTP.Bindings = []contract.Binding{{Source: "path", Name: "id", Field: "root_id", Type: "string"}}
		if m.Operations[i].Kind == "query" {
			m.Operations[i].HTTP.Bindings = append(m.Operations[i].HTTP.Bindings, contract.Binding{Source: "query", Name: "value", Field: "value", Type: "string"})
		} else {
			m.Operations[i].HTTP.Method = "POST"
			m.Operations[i].HTTP.SuccessStatus = 201
		}
	}
	accept := m.Operations[1]
	accept.ID = "tasks.accept"
	accept.Subject = "rpc.tasks.v1.accept"
	accept.HTTP.Path = "/api/v1/tasks/accept/{id}"
	accept.HTTP.SuccessStatus = 202
	m.Operations = append(m.Operations, accept)
	a.Manifest, _ = json.Marshal(m)
	return a
}

type taskRequest struct {
	RootID string `json:"root_id"`
	Value  string `json:"value"`
}
type taskResponse struct {
	Value string `json:"value"`
}

func TestM0Gate(t *testing.T) {
	dsn := os.Getenv("ARC_ACCESS_TEST_DSN")
	if dsn == "" {
		t.Skip("run scripts/test-m0-05.sh")
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
	migrator, e := sql.Open("pgx", strings.Replace(dsn, "user=arc_core", "user=arc_migrator", 1))
	must(e)
	defer migrator.Close()
	_, e = migrator.ExecContext(ctx, `CREATE SCHEMA gate_fixture; CREATE TABLE gate_fixture.command_results (LIKE fabric.command_results INCLUDING ALL); CREATE TABLE gate_fixture.items(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,value text NOT NULL); GRANT USAGE ON SCHEMA gate_fixture TO arc_core; GRANT ALL ON ALL TABLES IN SCHEMA gate_fixture TO arc_core; GRANT ALL ON ALL SEQUENCES IN SCHEMA gate_fixture TO arc_core`)
	must(e)
	operator, coreKey, gateKey, providerKey, trust := testKey(121), testKey(122), testKey(123), testKey(124), testKey(125)
	id := &identity.Core{DB: db, PrivateKey: coreKey, SigningKid: "gate-core-key"}
	must(id.PublishSigningKey(ctx, time.Now().Add(time.Hour)))
	owner, _, e := id.BootstrapUser(ctx, "gate-owner@example.test", "gate fixture password")
	must(e)
	login, e := id.Login(ctx, "gate-owner@example.test", "gate fixture password")
	must(e)
	session := identity.UserSession{Secret: login.Secret, CSRF: login.CSRF}
	baseline := access.Approval{AdminUsers: []string{owner}, Deployments: []access.Deployment{{Definition: "gate", Instance: "m005-gate"}, {Definition: "tasks", Instance: "m005-tasks"}}}
	static, e := access.NewContracts(operator.Public().(ed25519.PublicKey), []access.Approved{signApproval(t, operator, baseline)})
	must(e)
	acl := &access.Core{DB: db, Identity: id, Contracts: static}
	id.Policy = acl
	gateID, e := id.RegisterService(ctx, session, "gate", "m005-gate")
	must(e)
	provider, e := id.RegisterService(ctx, session, "tasks", "m005-tasks")
	must(e)
	must(id.AddServiceKey(ctx, session, gateID, "m005-gate-key", gateKey.Public().(ed25519.PublicKey), "mount:gate-test", time.Now().Add(time.Hour)))
	must(id.AddServiceKey(ctx, session, provider, "m005-provider-key", providerKey.Public().(ed25519.PublicKey), "mount:tasks-test", time.Now().Add(time.Hour)))
	for _, op := range []string{"sessions.login", "sessions.validate", "sessions.refresh", "sessions.logout", "invocations.exchange_user"} {
		baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
	}
	baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "fabric/v1", Operation: "fabric.v1.routes", ActorKinds: []string{"bootstrap"}}, access.Rule{Caller: provider, Audience: "identity/v1", Operation: "identity.v1.invocations.exchange_service", ActorKinds: []string{"bootstrap"}})
	f := &fabric.Core{DB: db, Identity: id, ApprovalKey: operator.Public().(ed25519.PublicKey), Bootstrap: []access.Approved{signApproval(t, operator, baseline)}, SnapshotKey: coreKey, SnapshotKid: id.SigningKid, RouteTrustKey: trust}
	acl.ContractSource = f
	dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
	natsURL := os.Getenv("ARC_IDENTITY_NATS_URL")
	cfg := func(name, seed string) pkgs.Config {
		return pkgs.Config{URL: natsURL, Name: name, NKeySeedFile: filepath.Join(dir, seed), TLSCAFile: filepath.Join(dir, "ca.crt")}
	}
	coreSvc, e := pkgs.NewService(ctx, pkgs.ServiceConfig{Name: "arc-bootstrap", Version: "0.0.5", Connection: cfg("m005-core", "nats-echo-service.seed")})
	must(e)
	defer coreSvc.Stop()
	must(id.BindInternal(coreSvc))
	must(f.BindRoutes(coreSvc))
	closeControl, e := f.BindControl(coreSvc.Connection())
	must(e)
	defer closeControl()
	must(coreSvc.Connection().Flush())
	accessSvc, e := pkgs.NewService(ctx, pkgs.ServiceConfig{Name: "arc-access", Version: "0.0.5", Connection: cfg("m005-access", "nats-echo-service.seed")})
	must(e)
	defer accessSvc.Stop()
	must(acl.BindInternal(accessSvc))
	must(accessSvc.Connection().Flush())
	a := gateArtifact()
	compiled, e := contract.Compile(a)
	must(e)
	r := compiled.Manifest.Resources[0]
	policy := access.Approval{ContractDigests: map[string]string{r.Type: compiled.Digest}, Types: []access.TypeSpec{{Type: r.Type, Provider: provider, Actions: r.Actions, ShareAction: r.ShareAction, CreateAction: r.CreateAction, DeleteAction: r.DeleteAction, AllowInheritance: r.AllowInheritance}}}
	subjects := []string{}
	from := []string{}
	downstream := map[string][]string{}
	for _, o := range compiled.Manifest.Operations {
		subjects = append(subjects, o.Subject)
		policy.Rules = append(policy.Rules, access.Rule{Caller: gateID, Audience: "tasks/v1", Operation: o.ID, ActorKinds: []string{"user"}, Actions: []string{o.Auth.Action}})
		source := "tasks/v1:" + o.ID
		from = append(from, source)
		downstream[source] = []string{o.Auth.Action}
	}
	policy.Rules = append(policy.Rules, access.Rule{Caller: provider, Audience: "access/v1", Operation: "access.v1.check", ActorKinds: []string{"user"}, Actions: []string{"tasks.read", "tasks.create"}, DownstreamFrom: from, DownstreamActions: downstream})
	install := fabric.Installation{Publisher: "gate-fixture", Account: provider, Deployment: "m005-tasks", Artifact: a, Subjects: subjects, Policy: signApproval(t, operator, policy)}
	raw, sig := signValue(t, operator, install)
	_, e = f.Approve(ctx, fabric.SignedInstallation{Payload: raw, Signature: sig})
	must(e)
	root := "d0000000-0000-4000-8000-000000000001"
	_, e = db.ExecContext(ctx, `INSERT INTO access.resources(id,type,provider_service,owner_kind,owner_id,owner_user_id,inherit_acl,state,policy_revision) VALUES($1,$2,$3,'user',$4,$4,true,'active',1)`, root, r.Type, provider, owner)
	must(e)
	gateNC, e := pkgs.Connect(ctx, cfg("m005-gate", "nats-smoke-client.seed"))
	must(e)
	defer gateNC.Close()
	client, e := rpc.NewClient(gateNC)
	must(e)
	remote := &Remote{Client: identity.Client{RPC: client, ServiceID: gateID, Kid: "m005-gate-key", PrivateKey: gateKey}, TrustRoot: trust.Public().(ed25519.PublicKey)}
	registry := &fabric.Client{Account: provider, Kid: "m005-provider-key", Key: providerKey, CoreKey: coreKey.Public().(ed25519.PublicKey)}
	var executions atomic.Int64
	var lastActor atomic.Value
	var lastRequestID atomic.Value
	var lastTrace atomic.Value
	var businessCalls atomic.Int64
	app, e := pkgs.NewApp(pkgs.AppConfig{Connection: cfg("m005-tasks", "nats-echo-service.seed"), Artifact: a, Instance: "m005-tasks-instance", Registry: registry, SelfCheck: func(context.Context) error { return nil }, Authorize: rpc.InvocationAuthorizer(id.Verifier(), "tasks/v1"), Resource: func(ctx context.Context, requested, action string) error {
		if requested != root {
			return security.ErrDenied
		}
		incoming, ok := rpc.InvocationToken(ctx)
		if !ok {
			return security.ErrUnauthenticated
		}
		claims, ok := rpc.VerifiedClaims(ctx)
		if !ok {
			return security.ErrUnauthenticated
		}
		credentials, e := (&identity.Client{ServiceID: provider, Kid: "m005-provider-key", PrivateKey: providerKey}).Credentials("identity.exchange_service")
		if e != nil {
			return e
		}
		token, e := id.ExchangeService(ctx, identity.ServiceExchange{Assertion: credentials.Token, IncomingToken: incoming, IncomingOperation: claims.Operation, Target: identity.Target{Audience: "access/v1", Operation: "access.v1.check"}})
		if e != nil {
			return e
		}
		providerClient, e := rpc.NewClient(registry.NC)
		if e != nil {
			return e
		}

		meta, _ := rpc.Metadata(ctx)
		checkCtx := rpc.WithOutgoing(ctx, rpc.Outgoing{RequestID: meta.RequestID, Traceparent: meta.Traceparent})
		jti, e := tokenJTI(token.Token)
		if e != nil {
			return e
		}
		checkCtx = rpc.WithCredentials(checkCtx, rpc.Credentials{Token: token.Token, Proof: func(subject string, raw []byte) (security.Proof, error) {
			return security.SignProof(providerKey, subject, raw, jti, security.Proof{Kid: "m005-provider-key", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: NewID()})
		}})
		decision, e := (&access.Client{RPC: providerClient}).Check(checkCtx, access.CheckRequest{ResourceID: root, Action: action})
		if e != nil {
			return e
		}
		if !decision.Allowed {
			return security.ErrDenied
		}
		return nil
	}})
	must(e)
	defer app.Stop()
	must(pkgs.Handle(app, "tasks.read", func(ctx context.Context, q taskRequest) (taskResponse, error) {
		executions.Add(1)
		cl, _ := rpc.VerifiedClaims(ctx)
		lastActor.Store(cl.Subject)
		meta, _ := rpc.Metadata(ctx)
		lastRequestID.Store(meta.RequestID)
		lastTrace.Store(meta.Traceparent)
		switch q.Value {
		case "denied":
			return taskResponse{}, fault(rpc.CodePermissionDenied)
		case "missing":
			return taskResponse{}, fault(rpc.CodeNotFound)
		case "conflict":
			return taskResponse{}, fault(rpc.CodeConflict)
		case "limited":
			return taskResponse{}, fault(rpc.CodeRateLimited)
		case "internal":
			return taskResponse{}, errors.New("postgres password secret stacktrace")
		case "slow":
			<-ctx.Done()
			return taskResponse{}, ctx.Err()
		}
		return taskResponse{Value: q.Value}, nil
	}))
	store := events.Store{DB: db, Schema: "gate_fixture"}
	for _, op := range []string{"tasks.create", "tasks.accept"} {
		must(pkgs.HandleCommand(app, op, store, func(ctx context.Context, tx *sql.Tx, q taskRequest) (taskResponse, error) {
			executions.Add(1)
			_, e := tx.ExecContext(ctx, `INSERT INTO gate_fixture.items(value) VALUES($1)`, q.Value)
			return taskResponse{Value: q.Value}, e
		}))
	}
	must(app.Start(ctx))
	g, e := New(Config{Backend: trackingBackend{Backend: remote, calls: &businessCalls}, PublicOrigin: "https://arc.example", ReconcileInterval: 50 * time.Millisecond, RequestsPerMinute: 500})
	must(e)
	server := httptest.NewTLSServer(g)
	defer server.Close()
	httpClient := server.Client()
	httpClient.Jar, _ = cookiejar.New(nil)
	do := func(method, path, body string, headers map[string]string) *http.Response {
		t.Helper()
		req, e := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		must(e)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, e := httpClient.Do(req)
		must(e)
		return res
	}
	expect := func(res *http.Response, status int) []byte {
		t.Helper()
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		must(e)
		if res.StatusCode != status {
			t.Fatalf("HTTP %d expected %d: %s", res.StatusCode, status, b)
		}
		return b
	}
	// Initial cold start is closed; valid signed snapshot opens only known paths.
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=cold", "", nil), 503)
	must(g.Reconcile(ctx))
	before := executions.Load()
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=noauth", "", nil), 401)
	expect(do("GET", "/api/v1/tasks/unapproved", "", nil), 404)
	if executions.Load() != before {
		t.Fatal("unauthorized HTTP reached handler")
	}
	expect(do("POST", "/api/v1/arc/auth/login", `{"email":"gate-owner@example.test","password":"gate fixture password"}`, map[string]string{"Origin": "https://evil.example"}), 403)
	res := do("POST", "/api/v1/arc/auth/login", `{"email":"gate-owner@example.test","password":"gate fixture password"}`, map[string]string{"Origin": "https://arc.example"})
	cookies := res.Cookies()
	data := expect(res, 200)
	var loginBody struct {
		CSRF        string           `json:"csrf"`
		AccessToken string           `json:"access_token"`
		Session     identity.Session `json:"session"`
	}
	must(json.Unmarshal(data, &loginBody))
	if bytes.Contains(data, []byte(`"secret"`)) || bytes.Contains(data, []byte(`"refresh"`)) {
		t.Fatal("browser credential exposed in response")
	}
	for _, c := range cookies {
		if !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Name != csrfCookie && !c.HttpOnly {
			t.Fatal("unsafe cookie", c.Name)
		}
	}
	expect(do("GET", "/api/v1/arc/auth/session", "", nil), 200)
	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=ok", "", map[string]string{"X-User-ID": "spoofed", "X-Actor": "service:rogue", "X-Service": "rogue", "X-Request-ID": "gate-request-1", "Traceparent": trace}), 200)
	if lastActor.Load() != "user:"+owner || lastRequestID.Load() != "gate-request-1" || lastTrace.Load() != trace {
		t.Fatal("HTTP identity or request id not bound", lastActor.Load(), lastRequestID.Load())
	}

	// Corrupt only the exchanged invocation/proof, keeping real Core auth online.
	for _, kind := range []string{"audience", "operation", "caller", "proof"} {
		corrupted := corruptBackend{Backend: remote, remote: remote, key: coreKey, kid: id.SigningKid, kind: kind}
		badGate, e := New(Config{Backend: corrupted, PublicOrigin: "https://arc.example"})
		must(e)
		must(badGate.Reconcile(ctx))
		req := httptest.NewRequest("GET", "https://arc.example/api/v1/tasks/read/"+root+"?value=invalid-invocation", nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		countBefore := executions.Load()
		badGate.ServeHTTP(w, req)
		if w.Code != 401 || executions.Load() != countBefore {
			t.Fatal("invalid invocation/proof reached domain handler", kind, w.Code)
		}
	}
	expiredJWT, e := security.Sign(coreKey, id.SigningKid, security.Claims{Issuer: "arc-core", Audience: "gate", Subject: "user:" + owner, SessionID: loginBody.Session.ID, JTI: NewID(), IssuedAt: time.Now().Add(-10 * time.Minute).Unix(), NotBefore: time.Now().Add(-10 * time.Minute).Unix(), ExpiresAt: time.Now().Add(-time.Second).Unix()})
	must(e)
	jarBefore := httpClient.Jar
	httpClient.Jar = nil
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=expired-bearer", "", map[string]string{"Authorization": "Bearer " + expiredJWT}), 401)
	httpClient.Jar = jarBefore
	expiredSession, e := id.Login(ctx, "gate-owner@example.test", "gate fixture password")
	must(e)
	_, e = db.ExecContext(ctx, `UPDATE identity.sessions SET expires_at=now()-interval '1 second' WHERE id=$1`, expiredSession.Session.ID)
	must(e)
	expiredRequest := httptest.NewRequest("GET", "https://arc.example/api/v1/tasks/read/"+root+"?value=expired-cookie", nil)
	expiredRequest.AddCookie(&http.Cookie{Name: "__Host-arc_session", Value: expiredSession.Secret})
	expiredRequest.AddCookie(&http.Cookie{Name: csrfCookie, Value: expiredSession.CSRF})
	expiredResult := httptest.NewRecorder()
	g.ServeHTTP(expiredResult, expiredRequest)
	if expiredResult.Code != 401 {
		t.Fatal("expired cookie session accepted", expiredResult.Code)
	}
	before = executions.Load()
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"no-csrf"}`, map[string]string{"Origin": "https://arc.example", "Idempotency-Key": "no-csrf"}), 403)
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"bad-origin"}`, map[string]string{"Origin": "https://evil.example", "X-CSRF-Token": loginBody.CSRF, "Idempotency-Key": "bad-origin"}), 403)
	mutation := map[string]string{"Origin": "https://arc.example", "X-CSRF-Token": loginBody.CSRF, "Idempotency-Key": "stable-http-command"}
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"created"}`, mutation), 201)
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"created"}`, mutation), 201)
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"changed"}`, mutation), 409)
	var count int
	must(db.QueryRowContext(ctx, `SELECT count(*) FROM gate_fixture.items WHERE value='created'`).Scan(&count))
	if count != 1 {
		t.Fatal("duplicate HTTP mutation", count)
	}
	mutation["Idempotency-Key"] = "accepted-http-command"
	expect(do("POST", "/api/v1/tasks/accept/"+root, `{"value":"accepted"}`, mutation), 202)
	badroot := "d0000000-0000-4000-8000-000000000099"
	expect(do("GET", "/api/v1/tasks/read/"+badroot+"?value=spoof", "", nil), 403)
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"x","actor":"user:spoof"}`, mutation), 400)
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=ok&subject=rpc.evil", "", nil), 400)
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":1}`, mutation), 400)
	expect(do("POST", "/api/v1/tasks/create/"+root, `{"value":"`+strings.Repeat("x", 210<<10)+`"}`, mutation), 413)
	for value, status := range map[string]int{"denied": 403, "missing": 404, "conflict": 409, "limited": 429, "internal": 500} {
		b := expect(do("GET", "/api/v1/tasks/read/"+root+"?value="+value, "", nil), status)
		if bytes.Contains(b, []byte("secret")) || bytes.Contains(b, []byte("postgres")) {
			t.Fatal("internal error leaked")
		}
	}
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=slow", "", map[string]string{"X-Request-Deadline": time.Now().Add(100 * time.Millisecond).UTC().Format(time.RFC3339Nano)}), 504)
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=expired", "", map[string]string{"X-Request-Deadline": time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}), 504)
	expect(do("OPTIONS", "/api/v1/tasks/read/"+root, "", map[string]string{"Origin": "https://arc.example", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "X-User-ID"}), 403)
	expect(do("OPTIONS", "/api/v1/tasks/read/"+root, "", map[string]string{"Origin": "https://arc.example", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "Authorization"}), 204)
	// Access JWT goes only to Core; a new invocation reaches the owner service.
	savedJar := httpClient.Jar
	httpClient.Jar = nil
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=bearer", "", map[string]string{"Authorization": "Bearer " + loginBody.AccessToken}), 200)
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=bad", "", map[string]string{"Authorization": "Bearer invalid"}), 401)
	httpClient.Jar = savedJar
	oldRefresh := ""
	for _, c := range cookies {
		if c.Name == refreshCookie {
			oldRefresh = c.Value
		}
	}
	expect(do("POST", "/api/v1/arc/auth/refresh", `{}`, map[string]string{"Origin": "https://arc.example", "X-CSRF-Token": loginBody.CSRF}), 200)
	// Missed notifications are repaired by the periodic fetch of signed snapshots.
	hints, closeHints, e := SubscribeChanges(gateNC)
	must(e)
	defer closeHints()
	go g.Run(ctx, hints)
	oldRevision := g.Revision()
	_, e = db.ExecContext(ctx, `UPDATE fabric.route_state SET revision=revision+1 WHERE singleton`)
	must(e)
	until := time.Now().Add(3 * time.Second)
	for g.Revision() <= oldRevision && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if g.Revision() <= oldRevision {
		t.Fatal("periodic reconciliation missed update")
	}
	_, e = db.ExecContext(ctx, `UPDATE fabric.route_state SET revision=revision+1 WHERE singleton`)
	must(e)
	must(coreSvc.Connection().Publish(fabric.RoutesChangedSubject, nil))
	must(coreSvc.Connection().Flush())
	until = time.Now().Add(3 * time.Second)
	for g.Revision() < oldRevision+2 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if g.Revision() < oldRevision+2 {
		t.Fatal("snapshot notification not reconciled")
	}
	// Reusing the consumed browser refresh cookie revokes the active family.
	oldJar := httpClient.Jar
	httpClient.Jar = nil
	replayReq := httptest.NewRequest("POST", "https://arc.example/api/v1/arc/auth/refresh", strings.NewReader(`{}`))
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set("Origin", "https://arc.example")
	replayReq.Header.Set("X-CSRF-Token", loginBody.CSRF)
	for _, cookie := range cookies {
		copy := *cookie
		if copy.Name == refreshCookie {
			copy.Value = oldRefresh
		}
		replayReq.AddCookie(&copy)
	}
	replayResult := httptest.NewRecorder()
	g.ServeHTTP(replayResult, replayReq)
	if replayResult.Code != 401 {
		t.Fatal("browser refresh replay accepted", replayResult.Code)
	}
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=refresh-revoked", "", map[string]string{"Authorization": "Bearer " + loginBody.AccessToken}), 401)
	httpClient.Jar = oldJar
	// A fresh login permits an independently tested CSRF-protected logout.
	res = do("POST", "/api/v1/arc/auth/login", `{"email":"gate-owner@example.test","password":"gate fixture password"}`, map[string]string{"Origin": "https://arc.example"})
	fresh := expect(res, 200)
	must(json.Unmarshal(fresh, &loginBody))
	expect(do("POST", "/api/v1/arc/auth/logout", `{}`, map[string]string{"Origin": "https://arc.example", "X-CSRF-Token": loginBody.CSRF}), 204)
	httpClient.Jar = nil
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=revoked", "", map[string]string{"Authorization": "Bearer " + loginBody.AccessToken}), 401)
	// Existing Identity refresh replay protection remains authoritative.
	if _, e = id.Refresh(ctx, oldRefresh); !errors.Is(e, identity.ErrUnauthenticated) {
		t.Fatal("refresh reuse accepted", e)
	}
	// Login again for outage/no-responder checks without a stale revoked session.
	httpClient.Jar, _ = cookiejar.New(nil)
	res = do("POST", "/api/v1/arc/auth/login", `{"email":"gate-owner@example.test","password":"gate fixture password"}`, map[string]string{"Origin": "https://arc.example"})
	expect(res, 200)
	must(app.Stop())
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=no-responder", "", nil), 503)
	before = executions.Load()
	callsBeforeOutage := businessCalls.Load()
	must(coreSvc.Stop())
	expect(do("GET", "/api/v1/tasks/read/"+root+"?value=core-down", "", nil), 503)
	if executions.Load() != before || businessCalls.Load() != callsBeforeOutage {
		t.Fatal("Core outage executed protected RPC")
	}
	signedBefore, e := f.Routes(ctx)
	must(e)
	must(id.RevokeKey(ctx, session, id.SigningKid, true))
	liveKeys, e := id.JWKS(ctx)
	must(e)
	if _, e = fabric.VerifySnapshotJWKS(liveKeys, signedBefore, 0); e == nil {
		t.Fatal("revoked snapshot key accepted")
	}
	if _, e = f.Routes(ctx); !errors.Is(e, security.ErrUnavailable) {
		t.Fatal("Core published snapshot with revoked signing key", e)
	}
}

// The fixture owns Core's key solely to test a recipient's independent checks.
type corruptBackend struct {
	Backend
	remote    *Remote
	key       ed25519.PrivateKey
	kid, kind string
}

func (b corruptBackend) Exchange(ctx context.Context, q identity.UserExchange) (identity.TokenResult, error) {
	r, e := b.Backend.Exchange(ctx, q)
	if e != nil || b.kind == "proof" {
		return r, e
	}
	parts := strings.Split(r.Token, ".")
	raw, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return r, e
	}
	var cl security.Claims
	if e = json.Unmarshal(raw, &cl); e != nil {
		return r, e
	}
	switch b.kind {
	case "audience":
		cl.Audience = "other/v1"
	case "operation":
		cl.Operation = "tasks.accept"
	case "caller":
		cl.Caller = "00000000-0000-4000-8000-000000000099"
	}
	r.Token, e = security.Sign(b.key, b.kid, cl)
	return r, e
}
func (b corruptBackend) Invoke(ctx context.Context, m *contract.Compiled, o contract.Operation, q json.RawMessage, token, idem string) (json.RawMessage, error) {
	if b.kind != "proof" {
		return b.Backend.Invoke(ctx, m, o, q, token, idem)
	}
	client := b.remote.Client
	client.PrivateKey = testKey(130)
	bad := &Remote{Client: client}
	return bad.Invoke(ctx, m, o, q, token, idem)
}

type trackingBackend struct {
	Backend
	calls *atomic.Int64
}

func (b trackingBackend) Invoke(ctx context.Context, m *contract.Compiled, o contract.Operation, q json.RawMessage, token, idem string) (json.RawMessage, error) {
	b.calls.Add(1)
	return b.Backend.Invoke(ctx, m, o, q, token, idem)
}

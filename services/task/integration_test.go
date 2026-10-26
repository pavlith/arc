package task_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/internal/testdb"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/bootstrap"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	gate "github.com/pavlith/arc/services/gate/modules/http"
	notifyservice "github.com/pavlith/arc/services/notify"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	notifyinbox "github.com/pavlith/arc/services/notify/modules/inbox"
	taskservice "github.com/pavlith/arc/services/task"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	tasks "github.com/pavlith/arc/services/task/modules/tasks"
	"gorm.io/gorm"
)

func key(v byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{v}, 32)) }
func signed(k ed25519.PrivateKey, v any) (json.RawMessage, []byte) {
	b, _ := json.Marshal(v)
	b, _ = security.CanonicalJSON(b)
	return b, ed25519.Sign(k, b)
}
func approval(k ed25519.PrivateKey, v access.Approval) access.Approved {
	b, s := signed(k, v)
	return access.Approved{Payload: b, Signature: s}
}
func TestM006(t *testing.T) {
	if os.Getenv("ARC_DOMAIN_BIN_DIR") == "" {
		t.Skip("run scripts/test-m0-06.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	coreDB, db := testdb.Open(t, "core")
	taskDB, tdb := testdb.Open(t, "task")
	notifyDB, ndb := testdb.Open(t, "notify")
	for _, d := range []*sql.DB{tdb, ndb} {
		for _, table := range []string{"identity_users", "access_grants", "fabric_contracts"} {
			var n int
			if d.QueryRow("SELECT count(*) FROM "+table).Scan(&n) == nil {
				t.Fatal("domain database contains Core table", table)
			}
		}
	}
	if _, e := tdb.Exec("SELECT * FROM notifications"); e == nil {
		t.Fatal("Task contains Notify table")
	}
	var e error
	operator, coreKey, gateKey, taskKey, notifyKey, trust := key(61), key(62), key(63), key(64), key(65), key(66)
	id := &identity.Core{GormDB: coreDB, PrivateKey: coreKey, SigningKid: "m006-core-key"}
	must(id.PublishSigningKey(ctx, time.Now().Add(time.Hour)))
	owner, _, e := id.BootstrapUser(ctx, "proof-owner@example.test", "proof fixture password")
	must(e)
	outsider, _, e := id.BootstrapUser(ctx, "proof-outsider@example.test", "proof fixture password")
	must(e)
	member, _, e := id.BootstrapUser(ctx, "proof-member@example.test", "proof fixture password")
	must(e)
	login, e := id.Login(ctx, "proof-owner@example.test", "proof fixture password")
	must(e)
	session := identity.UserSession{Secret: login.Secret, CSRF: login.CSRF}
	workspace, e := id.CreateWorkspace(ctx, session, "Proof")
	must(e)
	otherWorkspace, e := id.CreateWorkspace(ctx, session, "Other")
	must(e)
	must(id.SetMembership(ctx, session, workspace, member, "member", false))
	baseline := access.Approval{AdminUsers: []string{owner}, Deployments: []access.Deployment{{Definition: "gate", Instance: "m006-gate"}, {Definition: "task", Instance: "m006-task"}, {Definition: "notify", Instance: "m006-notify"}}}
	static, e := access.NewContracts(operator.Public().(ed25519.PublicKey), []access.Approved{approval(operator, baseline)})
	must(e)
	acl := &access.Core{GormDB: coreDB, Identity: id, Contracts: static, Domain: access.ReceiptVerifier{Keys: id.Verifier().Keys}}
	id.Policy = acl
	gateID, e := id.RegisterService(ctx, session, "gate", "m006-gate")
	must(e)
	provider, e := id.RegisterService(ctx, session, "task", "m006-task")
	must(e)
	consumer, e := id.RegisterService(ctx, session, "notify", "m006-notify")
	must(e)
	for _, v := range []struct {
		id, kid string
		k       ed25519.PrivateKey
	}{{gateID, "m006-gate-key", gateKey}, {provider, "m006-task-key", taskKey}, {consumer, "m006-notify-key", notifyKey}} {
		must(id.AddServiceKey(ctx, session, v.id, v.kid, v.k.Public().(ed25519.PublicKey), "mount:m006", time.Now().Add(time.Hour)))
	}
	for _, op := range []string{"sessions.login", "sessions.validate", "sessions.refresh", "sessions.logout", "invocations.exchange_user"} {
		baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
	}
	baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "fabric/v1", Operation: "fabric.v1.routes", ActorKinds: []string{"bootstrap"}})
	for _, account := range []string{provider, consumer} {
		for _, op := range []string{"invocations.verify", "invocations.exchange_service"} {
			baseline.Rules = append(baseline.Rules, access.Rule{Caller: account, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
		}
	}

	f := &fabric.Core{GormDB: coreDB, Identity: id, ApprovalKey: operator.Public().(ed25519.PublicKey), Bootstrap: []access.Approved{approval(operator, baseline)}, SnapshotKey: coreKey, SnapshotKid: id.SigningKid, RouteTrustKey: trust}
	acl.ContractSource = f
	dir := os.Getenv("ARC_IDENTITY_NATS_SECRETS")
	cfg := func(name, seed string) sdk.Config {
		return sdk.Config{URL: os.Getenv("ARC_IDENTITY_NATS_URL"), Name: name, NKeySeedFile: filepath.Join(dir, seed), TLSCAFile: filepath.Join(dir, "ca.crt")}
	}
	coreSvc, e := sdk.NewService(ctx, sdk.ServiceConfig{Name: "arc-bootstrap", Version: "0.0.6", Connection: cfg("m006-core", "nats-echo-service.seed")})
	must(e)
	t.Cleanup(func() { coreSvc.Stop() })
	must(id.BindInternal(coreSvc))
	must(f.BindRoutes(coreSvc))
	closeControl, e := f.BindControl(coreSvc.Connection())
	must(e)
	defer closeControl()
	must(coreSvc.Connection().Flush())
	accessSvc, e := sdk.NewService(ctx, sdk.ServiceConfig{Name: "arc-access", Version: "0.0.6", Connection: cfg("m006-access", "nats-echo-service.seed")})
	must(e)
	t.Cleanup(func() { accessSvc.Stop() })
	must(acl.BindInternal(accessSvc))
	must(accessSvc.Connection().Flush())
	gateNC, e := sdk.Connect(ctx, cfg("m006-gate", "nats-smoke-client.seed"))
	must(e)
	defer gateNC.Close()
	rc, e := rpc.NewClient(gateNC)
	must(e)
	gateClient := identity.Client{RPC: rc, ServiceID: gateID, Kid: "m006-gate-key", PrivateKey: gateKey}
	taskClient := identity.Client{RPC: rc, ServiceID: provider, Kid: "m006-task-key", PrivateKey: taskKey}
	tm, e := contract.Compile(taskv1.Artifact())
	must(e)
	install := func(a contract.Artifact, account, deployment string, subs []fabric.EventSubscription) {
		m, e := contract.Compile(a)
		must(e)
		r := m.Manifest.Resources[0]
		p := access.Approval{ContractDigests: map[string]string{r.Type: m.Digest}, Types: []access.TypeSpec{{Type: r.Type, Provider: account, Actions: r.Actions, ShareAction: r.ShareAction, CreateAction: r.CreateAction, DeleteAction: r.DeleteAction, AllowInheritance: r.AllowInheritance}}}
		subjects := []string{}
		from := []string{}
		down := map[string][]string{}
		for _, o := range m.Manifest.Operations {
			subjects = append(subjects, o.Subject)
			caller := gateID
			kinds := []string{"user"}
			if account == consumer {
				caller = consumer
				kinds = []string{"service"}
			}
			p.Rules = append(p.Rules, access.Rule{Caller: caller, Audience: m.Manifest.Service.Name + "/v1", Operation: o.ID, ActorKinds: kinds, Actions: []string{o.Auth.Action}})
			source := m.Manifest.Service.Name + "/v1:" + o.ID
			from = append(from, source)
			down[source] = []string{o.Auth.Action}
		}
		if account == provider {
			p.Rules = append(p.Rules, access.Rule{Caller: account, Audience: "access/v1", Operation: "access.v1.check", ActorKinds: []string{"user"}, Actions: []string{"task.read", "task.create", "access.grants.manage"}, DownstreamFrom: from, DownstreamActions: down})
			for _, op := range []string{"resources.reserve", "resources.activate"} {
				p.Rules = append(p.Rules, access.Rule{Caller: account, Audience: "access/v1", Operation: "access.v1." + op, ActorKinds: []string{"user"}, Actions: []string{"task.create"}, DownstreamFrom: []string{"task/v1:" + tasks.Create}, DownstreamActions: map[string][]string{"task/v1:" + tasks.Create: {"task.create"}}})
			}
			for _, op := range []string{"grants.add", "grants.revoke"} {
				p.Rules = append(p.Rules, access.Rule{Caller: account, Audience: "access/v1", Operation: "access.v1." + op, ActorKinds: []string{"user"}, Actions: []string{"access.grants.manage", "task.read", "task.create"}, DownstreamFrom: []string{"task/v1:" + tasks.Admin}, DownstreamActions: map[string][]string{"task/v1:" + tasks.Admin: {"access.grants.manage", "task.read", "task.create"}}})
			}

		}
		i := fabric.Installation{Publisher: "m006-fixture", Account: account, Deployment: deployment, Artifact: a, Subjects: subjects, Policy: approval(operator, p), Subscriptions: subs}
		raw, sig := signed(operator, i)
		_, e = f.Approve(ctx, fabric.SignedInstallation{Payload: raw, Signature: sig})
		must(e)
	}
	install(taskv1.Artifact(), provider, "m006-task", nil)
	subscription := fabric.EventSubscription{Provider: provider, Digest: tm.Digest, Subject: tasks.Created, Durable: notifyinbox.Durable}
	install(notifyv1.Artifact(), consumer, "m006-notify", []fabric.EventSubscription{subscription})
	// Provision roots through the real Reserve/domain receipt/Activate protocol.
	domain := &tasks.Service{GormDB: taskDB, Contract: tm}
	accessContext := func(workspace, op string) context.Context {
		source := tasks.Create
		if strings.HasPrefix(op, "grants.") {
			source = tasks.Admin
		}
		cred, e := gateClient.Credentials("identity.exchange_service")
		must(e)
		incoming, e := identity.Call[identity.UserExchange, identity.TokenResult](ctx, gateClient, "identity.v1.invocations.exchange_user", identity.UserExchange{Assertion: cred.Token, Session: session, Target: identity.Target{Audience: "task/v1", Operation: source, WorkspaceID: workspace}})
		must(e)
		v, e := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, taskClient, "identity.v1.invocations.exchange_service", identity.ServiceExchange{IncomingToken: incoming.Token, IncomingOperation: source, Target: identity.Target{Audience: "access/v1", Operation: "access.v1." + op, WorkspaceID: workspace}})
		must(e)
		return tokenContext(ctx, v.Token, taskClient, t)
	}
	provision := func(workspace string) tasks.Scope {
		ac := &access.Client{RPC: rc}
		q, e := ac.Reserve(accessContext(workspace, "resources.reserve"), access.ReserveRequest{Type: "task.workspace", OwnerKind: "workspace", OwnerID: workspace, WorkspaceID: workspace})
		must(e)
		scope := tasks.Scope{WorkspaceID: workspace, RootID: q.ResourceID}
		receipt, e := domain.PrepareRoot(ctx, scope, taskKey, taskClient.Kid, provider)
		must(e)
		verifier := access.ReceiptVerifier{Keys: id.Verifier().Keys}
		must(verifier.Confirm(ctx, provider, scope.RootID, "activate", receipt))
		if verifier.Confirm(ctx, provider, tasks.NewID(), "activate", receipt) == nil {
			t.Fatal("root receipt accepted for another root")
		}
		if verifier.Confirm(ctx, provider, scope.RootID, "activate", receipt+"x") == nil {
			t.Fatal("tampered root receipt accepted")
		}
		_, e = ac.Activate(accessContext(workspace, "resources.activate"), access.LifecycleRequest{ResourceID: q.ResourceID, Receipt: receipt})
		must(e)
		must(domain.ActivateRoot(ctx, scope))
		return scope
	}
	scope, otherScope := provision(workspace), provision(otherWorkspace)
	grantCtx := func(op string) context.Context { return accessContext(workspace, op) }

	grants := map[string]string{}
	for _, action := range []string{"task.read", "task.create"} {
		v, e := (&access.Client{RPC: rc}).AddGrant(grantCtx("grants.add"), access.GrantRequest{ResourceID: scope.RootID, PrincipalKind: "role", PrincipalID: "owner", Action: action})
		must(e)
		grants[action] = v.GrantID
		_, e = (&access.Client{RPC: rc}).AddGrant(grantCtx("grants.add"), access.GrantRequest{ResourceID: scope.RootID, PrincipalKind: "role", PrincipalID: "member", Action: action})
		must(e)
	}
	_, e = ndb.Exec(`INSERT INTO subscriptions(workspace_id,acl_root_id,recipient_user_id) VALUES(?,?,?)`, workspace, scope.RootID, owner)
	must(e)
	// Dedicated credentials are denied cross-service subscriptions/publications.
	taskNC, e := sdk.Connect(ctx, cfg("m006-task-fixture", "nats-task.seed"))
	must(e)
	defer taskNC.Close()
	deniedSub := func(nc *nats.Conn, subject string) {
		sub, e := nc.SubscribeSync(subject)
		if e == nil {
			defer sub.Unsubscribe()
			_, e = sub.NextMsg(time.Second)
		}
		if !errors.Is(e, nats.ErrPermissionViolation) {
			t.Fatalf("NKey permission for %s: %v", subject, e)
		}
	}
	deniedSub(taskNC, "rpc.notify.v1.health")
	notifyNC, e := sdk.Connect(ctx, cfg("m006-notify-fixture", "nats-notify.seed"))
	must(e)
	defer notifyNC.Close()
	deniedSub(notifyNC, "rpc.task.v1.task.create")
	adminNC, e := sdk.Connect(ctx, cfg("m006-js-admin", "nats-jetstream-admin.seed"))
	must(e)
	defer adminNC.Close()
	js, e := adminNC.JetStream()
	must(e)
	// Previous guardrails share this isolated broker; give the vertical fixture exact streams.
	for _, stream := range []string{"ARC_EVENTS", "FABRIC_DLQ"} {
		e = js.DeleteStream(stream)
		if !errors.Is(e, nats.ErrStreamNotFound) {
			must(e)
		}
	}
	_, e = js.AddStream(&nats.StreamConfig{Name: "TASK", Subjects: []string{tasks.Created}, Storage: nats.FileStorage})
	must(e)
	_, e = js.AddStream(&nats.StreamConfig{Name: "TASK_DLQ", Subjects: []string{"dlq." + tasks.Created + "." + notifyinbox.Durable}, Storage: nats.FileStorage})
	must(e)
	// Start actual standalone domain binaries, mounted credentials and domain roles.
	confDir := t.TempDir()
	write := func(name string, v any) string {
		b, e := json.Marshal(v)
		must(e)
		p := filepath.Join(confDir, name)
		must(os.WriteFile(p, b, 0600))
		return p
	}
	coreFile := write("core-public.json", coreKey.Public().(ed25519.PublicKey))
	start := func(kind, account, kid string, k ed25519.PrivateKey, sub fabric.EventSubscription) func() {
		keyFile := filepath.Join(confDir, kind+".seed")
		must(os.WriteFile(keyFile, k.Seed(), 0600))
		path := testdb.Path(t, tdb)
		if kind == "notify" {
			path = testdb.Path(t, ndb)
		}
		base := bootstrap.Config{NATS: cfg("m006-"+kind, "nats-"+kind+".seed"), SQLitePath: path, ServiceID: account, Kid: kid, KeyFile: keyFile, CoreKeyFile: coreFile, Instance: "m006-" + kind}
		var config any = taskservice.BootstrapConfig{Config: base}
		if kind == "notify" {
			config = notifyservice.BootstrapConfig{Config: base, Subscription: sub}
		}
		file := write(kind+".json", config)
		cmd := exec.Command(filepath.Join(os.Getenv("ARC_DOMAIN_BIN_DIR"), "arc-"+kind), "-config", file)
		logFile, e := os.Create(filepath.Join(confDir, kind+".log"))
		must(e)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		processStarted := time.Now().UTC()
		must(cmd.Start())
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		var once sync.Once
		stop := func() { once.Do(func() { cmd.Process.Kill(); <-done; logFile.Close() }) }
		t.Cleanup(stop)
		eventually(t, func() bool {
			var ready bool
			_ = db.QueryRow(`SELECT ready AND observed_at>? FROM fabric_instances WHERE instance_id=?`, processStarted, base.Instance).Scan(&ready)
			return ready
		}, func() string {
			b, _ := os.ReadFile(logFile.Name())
			info, _ := js.ConsumerInfo("TASK", notifyinbox.Durable)
			return fmt.Sprintf("%s consumer=%+v", b, info)
		})
		return stop
	}
	stopTasks := start("task", provider, taskClient.Kid, taskKey, fabric.EventSubscription{})
	remote := &gate.Remote{Client: gateClient, TrustRoot: trust.Public().(ed25519.PublicKey)}
	g, e := gate.New(gate.Config{Backend: remote, PublicOrigin: "https://arc.example", RequestsPerMinute: 1000})
	must(e)
	must(g.Reconcile(ctx))
	server := httptest.NewTLSServer(g)
	defer server.Close()
	client := server.Client()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	request := func(c *http.Client, method, path, body, token, idem string) (int, []byte) {
		t.Helper()
		r, e := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		must(e)
		r.Header.Set("Origin", "https://arc.example")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		if token == "" {
			r.Header.Del("Authorization")
		}
		r.Header.Set("Idempotency-Key", idem)
		r.Header.Set("X-Request-ID", "m006-request")
		r.Header.Set("Traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
		r.Header.Set("X-Actor", "user:"+outsider)
		res, e := c.Do(r)
		must(e)
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		must(e)
		return res.StatusCode, b
	}
	loginHTTP := func(email string) string {
		c, b := request(client, "POST", "/api/v1/arc/auth/login", fmt.Sprintf(`{"email":%q,"password":"proof fixture password"}`, email), "", "")
		if c != 200 {
			t.Fatalf("login HTTP %d: %s", c, b)
		}
		var v struct {
			Access string `json:"access_token"`
		}
		must(json.Unmarshal(b, &v))
		return v.Access
	}
	// Use HTTP login bearer token to avoid mixing browser cookies and bearer auth.
	token := loginHTTP("proof-owner@example.test")
	client.Jar = nil
	base := fmt.Sprintf("/api/v1/task/workspaces/%s/roots/%s/tasks", workspace, scope.RootID)
	var countsMu sync.Mutex
	counts := map[string]int{}
	observer, e := coreSvc.Connection().Subscribe("rpc.identity.v1.>", func(m *nats.Msg) { countsMu.Lock(); counts[m.Subject]++; countsMu.Unlock() })
	must(e)
	defer observer.Unsubscribe()
	ao, e := coreSvc.Connection().Subscribe("rpc.access.v1.check", func(m *nats.Msg) { countsMu.Lock(); counts[m.Subject]++; countsMu.Unlock() })
	must(e)
	defer ao.Unsubscribe()
	must(coreSvc.Connection().Flush())
	taskCount, notificationCount := 1, 1
	begun := time.Now()
	status, b := request(client, "POST", base, `{"title":"Proof"}`, token, "m006-create")
	if status != 201 {
		t.Fatalf("create HTTP %d: %s", status, b)
	}
	createLatency := time.Since(begun)
	countsMu.Lock()
	t.Logf("create latency=%s; Core RPC=%v (online checks; no permission cache)", createLatency, counts)
	countsMu.Unlock()
	var task tasks.Task
	must(json.Unmarshal(b, &task))
	if task.CreatedBy != owner || task.WorkspaceID != workspace {
		t.Fatal("untrusted actor/workspace accepted")
	}
	count := func(db *sql.DB, query string, args ...any) int {
		t.Helper()
		var n int
		must(db.QueryRow(query, args...).Scan(&n))
		return n
	}
	if count(tdb, `SELECT count(*) FROM audit WHERE actor=? AND request_id='m006-request' AND traceparent<>''`, owner) != 1 {
		t.Fatal("audit propagation")
	}
	status, b = request(client, "GET", base+"/"+task.ID, "", token, "")
	if status != 200 {
		t.Fatalf("get %d %s", status, b)
	}
	status, b = request(client, "GET", base+"?limit=10", "", token, "")
	if status != 200 {
		t.Fatalf("list %d %s", status, b)
	}
	status, b = request(client, "POST", base, `{"title":"Proof"}`, token, "m006-create")
	if status != 201 {
		t.Fatalf("replay %d %s", status, b)
	}
	var replay tasks.Task
	must(json.Unmarshal(b, &replay))
	if replay.ID != task.ID || count(tdb, `SELECT count(*) FROM tasks`) != taskCount {
		t.Fatal("command replay duplicated task")
	}
	status, b = request(client, "POST", base, `{"title":"Changed"}`, token, "m006-create")
	if status != 409 {
		t.Fatalf("changed payload %d %s", status, b)
	}
	// Consumer absent: committed event remains in JetStream until its first delivery.
	eventually(t, func() bool {
		return count(tdb, `SELECT count(*) FROM outbox WHERE published_at IS NOT NULL`) == 1
	}, nil)
	if count(ndb, `SELECT count(*) FROM notifications`) != 0 {
		t.Fatal("effect before consumer")
	}
	stopNotify := start("notify", consumer, "m006-notify-key", notifyKey, subscription)
	nm, e := contract.Compile(notifyv1.Artifact())
	must(e)
	notifyRegistry := &fabric.Client{NC: notifyNC, Account: consumer, Kid: "m006-notify-key", Key: notifyKey, CoreKey: coreKey.Public().(ed25519.PublicKey)}
	nr := sdk.Registration{Service: "notify", Instance: "m006-notify", Build: nm.Manifest.Service.BuildVersion, Digest: nm.Digest}
	// Every subscription dimension is bound to the operator-approved installation.
	for _, wrong := range []fabric.EventSubscription{
		{Provider: provider, Digest: tm.Digest, Subject: tasks.Created, Durable: "unapproved"},
		{Provider: consumer, Digest: tm.Digest, Subject: tasks.Created, Durable: notifyinbox.Durable},
		{Provider: provider, Digest: strings.Repeat("0", len(tm.Digest)), Subject: tasks.Created, Durable: notifyinbox.Durable},
		{Provider: provider, Digest: tm.Digest, Subject: "evt.task.task.deleted.v1", Durable: notifyinbox.Durable},
	} {
		if notifyRegistry.EventPermit(ctx, nr, wrong) == nil {
			t.Fatalf("unapproved subscription accepted: %+v", wrong)
		}
	}
	must(notifyRegistry.EventPermit(ctx, nr, subscription))

	eventually(t, func() bool { return count(ndb, `SELECT count(*) FROM notifications`) == 1 }, func() string {
		b, _ := os.ReadFile(filepath.Join(confDir, "notify.log"))
		info, _ := js.ConsumerInfo("TASK", notifyinbox.Durable)
		return fmt.Sprintf("%s consumer=%+v", b, info)
	})
	verticalLatency := time.Since(begun)
	eventually(t, func() bool {
		return count(ndb, `SELECT count(*) FROM delivery_intents WHERE delivered_at IS NOT NULL`) == 1
	}, nil)
	if count(ndb, `SELECT count(*) FROM inbox`) != 1 {
		t.Fatal("inbox missing")
	}
	t.Logf("login → Gate → Tasks → outbox → JetStream → notification: %s (includes delayed consumer start)", verticalLatency)
	// Measure one uninterrupted create-to-effect with both workers already running.
	controlObserver, e := coreSvc.Connection().Subscribe("ctl.arc.fabric.>", func(m *nats.Msg) { countsMu.Lock(); counts[m.Subject]++; countsMu.Unlock() })
	must(e)
	defer controlObserver.Unsubscribe()
	must(coreSvc.Connection().Flush())
	countsMu.Lock()
	counts = map[string]int{}
	countsMu.Unlock()
	warmStart := time.Now()
	status, b = request(client, "POST", base, `{"title":"Latency proof"}`, token, "latency-proof")
	if status != 201 {
		t.Fatalf("warm create %d %s", status, b)
	}
	taskCount++
	notificationCount++
	eventually(t, func() bool {
		return count(ndb, `SELECT count(*) FROM delivery_intents WHERE delivered_at IS NOT NULL`) == notificationCount
	}, nil)
	countsMu.Lock()
	t.Logf("warm create → notification + fake intent delivery latency=%s; observed Core RPC including background approval polls=%v; request path=5 actor RPC + 1 Fabric lease RPC", time.Since(warmStart), counts)
	countsMu.Unlock()
	// Report a sample distribution, not a one-off value that also included consumer startup.
	// Measure each request until its own durable fake-delivery intent completes.
	latencies := []time.Duration{time.Since(warmStart)}
	for i := 0; i < 9; i++ {
		started := time.Now()
		status, b = request(client, "POST", base, fmt.Sprintf(`{"title":"Running consumer sample %d"}`, i), token, fmt.Sprintf("latency-sample-%d", i))
		if status != 201 {
			t.Fatalf("sample %d create %d %s", i, status, b)
		}
		var created tasks.Task
		must(json.Unmarshal(b, &created))
		taskCount++
		notificationCount++
		eventually(t, func() bool {
			var eventID string
			if e := tdb.QueryRow(`SELECT event_id FROM outbox WHERE envelope->>'aggregate_id'=?`, created.ID).Scan(&eventID); e != nil {
				return false
			}
			return count(ndb, `SELECT count(*) FROM notifications n JOIN delivery_intents d ON d.notification_id=n.id WHERE n.event_id=? AND d.delivered_at IS NOT NULL`, eventID) == 1
		}, nil)
		latencies = append(latencies, time.Since(started))
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	percentile := func(n int) time.Duration { return latencies[(len(latencies)*n+99)/100-1] }
	t.Logf("running-consumer create -> notification -> fake delivery: samples=%d p50=%s p95=%s max=%s (25ms observation polling, 100ms worker ticks; not a load benchmark)", len(latencies), percentile(50), percentile(95), latencies[len(latencies)-1])
	if count(tdb, `SELECT count(*) FROM tasks`) != taskCount || count(ndb, `SELECT count(*) FROM delivery_intents WHERE delivered_at IS NOT NULL`) != notificationCount {
		t.Fatal("running-consumer samples lost an effect")
	}
	t.Run("missing-permit-fail-closed", func(t *testing.T) {
		blocked := events.Delivery{Store: events.Store{DB: notifyDB}, Contract: tm}
		if e := blocked.Pull(ctx, js, tasks.Created, notifyinbox.Durable, (&notifyinbox.Service{GormDB: notifyDB}).Effect); !errors.Is(e, security.ErrUnavailable) {
			t.Fatalf("pull without current approval: %v", e)
		}
		if _, e := (events.Delivery{Store: events.Store{DB: taskDB}, Contract: tm}).PublishBatch(ctx, js, 10); !errors.Is(e, security.ErrUnavailable) {
			t.Fatalf("publish without current approval: %v", e)
		}
	})
	t.Run("security", func(t *testing.T) {
		outsiderToken := loginHTTP("proof-outsider@example.test")
		for _, op := range []struct{ method, path, body string }{{"POST", base, `{"title":"denied"}`}, {"GET", base + "/" + task.ID, ""}} {
			s, b := request(client, op.method, op.path, op.body, outsiderToken, tasks.NewID())
			if s != 403 {
				t.Fatalf("outsider %d %s", s, b)
			}
		}

		// The internal provisioning operation is actually bound and replays its Access command.
		cred, e := gateClient.Credentials("identity.exchange_service")
		must(e)
		adminToken, e := remote.Exchange(ctx, identity.UserExchange{Assertion: cred.Token, Session: session, Target: identity.Target{Audience: "task/v1", Operation: tasks.Admin, WorkspaceID: workspace}})
		must(e)
		adminOp, e := tm.Operation(tasks.Admin)
		must(e)
		adminPayload, _ := json.Marshal(tasks.GrantCommand{Scope: scope, Action: "task.create", PrincipalKind: "user", PrincipalID: member})
		first, e := remote.Invoke(ctx, tm, adminOp, adminPayload, adminToken.Token, "admin-grant-proof")
		must(e)
		again, e := remote.Invoke(ctx, tm, adminOp, adminPayload, adminToken.Token, "admin-grant-proof")
		must(e)
		if !bytes.Equal(first, again) {
			t.Fatal("admin grant replay changed result")
		}
		// Valid workspace membership with no grants also denies.
		_, e = (&access.Client{RPC: rc}).RevokeGrant(grantCtx("grants.revoke"), access.RevokeRequest{GrantID: grants["task.read"]})
		must(e)
		s, b := request(client, "GET", base+"/"+task.ID, "", token, "")
		if s != 403 {
			t.Fatalf("grant revoke %d %s", s, b)
		}
		_, e = (&access.Client{RPC: rc}).AddGrant(grantCtx("grants.add"), access.GrantRequest{ResourceID: scope.RootID, PrincipalKind: "role", PrincipalID: "owner", Action: "task.read"})
		must(e)
		memberToken := loginHTTP("proof-member@example.test")
		s, b = request(client, "GET", base+"/"+task.ID, "", memberToken, "")
		if s != 200 {
			t.Fatalf("member %d %s", s, b)
		}
		must(id.SetMembership(ctx, session, workspace, member, "member", true))
		s, b = request(client, "GET", base+"/"+task.ID, "", memberToken, "")
		if s != 403 {
			t.Fatalf("membership revoke %d %s", s, b)
		}
		countsMu.Lock()
		checksBefore := counts["rpc.access.v1.check"]
		countsMu.Unlock()
		spoof := fmt.Sprintf("/api/v1/task/workspaces/%s/roots/%s/tasks/%s", otherWorkspace, otherScope.RootID, task.ID)
		s, b = request(client, "GET", spoof, "", token, "")
		if s != 403 {
			t.Fatalf("domain-owner spoof %d %s", s, b)
		}
		countsMu.Lock()
		checksAfter := counts["rpc.access.v1.check"]
		countsMu.Unlock()
		if checksAfter != checksBefore {
			t.Fatal("spoof reached Access instead of domain-owner rejection")
		}
		// Original envelopes with broken JWT/proof cannot reach mutation.
		creds, e := gateClient.Credentials("identity.exchange_service")
		must(e)
		v, e := remote.Exchange(ctx, identity.UserExchange{Assertion: creds.Token, Session: session, Target: identity.Target{Audience: "task/v1", Operation: tasks.Create, WorkspaceID: workspace}})
		must(e)
		op, _ := tm.Operation(tasks.Create)
		for _, kind := range []string{"jwt", "proof"} {
			raw := map[string]any{"request_id": tasks.NewID(), "operation": tasks.Create, "schema_version": 1, "deadline_at": time.Now().Add(time.Second), "idempotency_key": tasks.NewID(), "payload": tasks.CreateRequest{Scope: scope, Title: "forged"}, "auth": v.Token, "proof": security.Proof{Kid: gateClient.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: tasks.NewID(), Signature: "invalid"}}
			if kind == "jwt" {
				raw["auth"] = "invalid"
			}
			b, _ := json.Marshal(raw)
			reply, e := gateNC.Request(op.Subject, b, time.Second*3)
			must(e)
			var result struct {
				Error *rpc.Error `json:"error"`
			}
			must(json.Unmarshal(reply.Data, &result))
			if result.Error == nil || result.Error.Code != rpc.CodeUnauthenticated {
				t.Fatalf("forged %s accepted: %s", kind, reply.Data)
			}
		}
		if count(tdb, `SELECT count(*) FROM tasks`) != taskCount {
			t.Fatal("security failure mutated tasks")
		}
	})
	t.Run("outbox-rollback", func(t *testing.T) {
		_, e = tdb.Exec(`CREATE TRIGGER reject_fixture BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'fixture outbox failure'); END`)
		must(e)
		t.Cleanup(func() { _, _ = tdb.Exec(`DROP TRIGGER IF EXISTS reject_fixture`) })
		status, b := request(client, "POST", base, `{"title":"rollback"}`, token, "rollback-key")
		if status != 503 {
			t.Fatalf("rollback %d %s", status, b)
		}
		if count(tdb, `SELECT count(*) FROM tasks`) != taskCount || count(tdb, `SELECT count(*) FROM command_results WHERE operation=?`, tasks.Create) != taskCount {
			t.Fatal("rollback left partial domain/command effect")
		}
		_, e = tdb.Exec(`DROP TRIGGER reject_fixture`)
		must(e)
	})
	t.Run("inbox-replay-rollback-concurrent", func(t *testing.T) {
		var raw []byte
		must(tdb.QueryRow(`SELECT envelope FROM outbox`).Scan(&raw))
		notify := &notifyinbox.Service{GormDB: notifyDB}
		store := events.Store{DB: notifyDB}
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- store.Consume(ctx, notifyinbox.Durable, tasks.Created, tm, raw, notify.Effect)
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			must(e)
		}
		if count(ndb, `SELECT count(*) FROM notifications`) != notificationCount {
			t.Fatal("concurrent replay duplicated notification")
		}
		// Same event id with different payload is rejected, not silently deduplicated.
		var ev events.Envelope
		must(json.Unmarshal(raw, &ev))
		ev.Traceparent = "altered"
		changed, _ := json.Marshal(ev)
		if store.Consume(ctx, notifyinbox.Durable, tasks.Created, tm, changed, notify.Effect) == nil {
			t.Fatal("conflicting event id accepted")
		}
		ev.ID = tasks.NewID()
		changed, _ = json.Marshal(ev)
		e := store.Consume(ctx, notifyinbox.Durable, tasks.Created, tm, changed, func(c context.Context, tx *gorm.DB, v events.Envelope) error {
			if e := notify.Effect(c, tx, v); e != nil {
				return e
			}
			return errors.New("handler failure")
		})
		if e == nil {
			t.Fatal("handler failure ignored")
		}
		if count(ndb, `SELECT count(*) FROM inbox WHERE event_id=?`, ev.ID) != 0 || count(ndb, `SELECT count(*) FROM notifications WHERE event_id=?`, ev.ID) != 0 {
			t.Fatal("inbox rollback left effect")
		}
		must(store.Consume(ctx, notifyinbox.Durable, tasks.Created, tm, changed, notify.Effect))
		notificationCount++
		// Real JetStream re-publication bypasses broker dedup; consumer inbox still wins.
		_, e = js.Publish(tasks.Created, raw, nats.MsgId(tasks.NewID()))
		must(e)
		eventually(t, func() bool {
			info, e := js.ConsumerInfo("TASK", notifyinbox.Durable)
			return e == nil && info.NumAckPending == 0 && info.NumPending == 0
		}, nil)
		if count(ndb, `SELECT count(*) FROM notifications`) != notificationCount {
			t.Fatal("JetStream replay duplicated notification")
		}
	})
	t.Run("revoked-consumer-fail-closed", func(t *testing.T) {
		beforeInbox := count(ndb, `SELECT count(*) FROM inbox`)
		beforeEffects := count(ndb, `SELECT count(*) FROM notifications`)
		revocation, sig := signed(operator, fabric.Revocation{Digest: nm.Digest, Revoke: true})
		if e := f.Revoke(ctx, revocation, sig); e != nil {
			t.Fatal(e)
		}
		// Revocation is terminal: the DB explicitly forbids reactivation of a digest.
		// Run only after every positive consumer assertion, while its worker is alive.
		if notifyRegistry.EventPermit(ctx, nr, subscription) == nil {
			t.Fatal("revoked consumer still has event permit")
		}
		status, b := request(client, "POST", base, `{"title":"While consumer revoked"}`, token, "revoked-consumer-proof")
		if status != 201 {
			t.Fatalf("create while consumer revoked %d %s", status, b)
		}
		taskCount++
		var withheld tasks.Task
		if e := json.Unmarshal(b, &withheld); e != nil {
			t.Fatal(e)
		}
		eventually(t, func() bool {
			var published bool
			_ = tdb.QueryRow(`SELECT published_at IS NOT NULL FROM outbox WHERE envelope->>'aggregate_id'=?`, withheld.ID).Scan(&published)
			return published
		}, nil)
		// The running worker must not process or ACK a newly published event.
		time.Sleep(500 * time.Millisecond)
		if count(ndb, `SELECT count(*) FROM inbox`) != beforeInbox || count(ndb, `SELECT count(*) FROM notifications`) != beforeEffects {
			t.Fatal("revoked consumer committed a delivery effect")
		}
		info, e := js.ConsumerInfo("TASK", notifyinbox.Durable)
		if e != nil || info.NumPending == 0 {
			t.Fatalf("revoked consumer must leave message pending: info=%+v err=%v", info, e)
		}
	})
	t.Run("external-stable-key", func(t *testing.T) {
		// Stop the automatic worker before exercising an uncertain provider timeout.
		// Rows are already durable and the adapter is independently restartable.
		stopNotify()
		fake := &delivery.FakeProvider{Fail: true}
		notify := &delivery.Service{GormDB: notifyDB}
		_, e = ndb.Exec(`UPDATE delivery_intents SET delivered_at=NULL`)
		must(e)
		_, _ = notify.Deliver(ctx, fake)
		_, e = notify.Deliver(ctx, fake)
		must(e)
		if len(fake.Calls) < 2 {
			t.Fatal("adapter was not retried")
		}
		seen := map[string]int{}
		for _, k := range fake.Calls {
			seen[k]++
		}
		repeated := false
		for _, n := range seen {
			if n > 1 {
				repeated = true
			}
		}
		if !repeated {
			t.Fatal("dedup key changed across retry")
		}
	})
	t.Run("publisher-unavailable", func(t *testing.T) {
		stopTasks()
		// Requeue the committed outbox and prove retry keeps its event identity.
		_, e = tdb.Exec(`UPDATE outbox SET published_at=NULL`)
		must(e)
		delivery := events.Delivery{Store: events.Store{DB: taskDB}, Contract: tm, Permit: func(c context.Context) error {
			return (&fabric.Client{NC: taskNC, Account: provider, Kid: taskClient.Kid, Key: taskKey, CoreKey: coreKey.Public().(ed25519.PublicKey)}).Check(c, sdk.Registration{Service: "task", Instance: "m006-task", Build: tm.Manifest.Service.BuildVersion, Digest: tm.Digest})
		}}
		closed, e := sdk.Connect(ctx, cfg("closed", "nats-jetstream-admin.seed"))
		must(e)
		closedJS, e := closed.JetStream()
		must(e)
		closed.Close()
		if _, e = delivery.PublishBatch(ctx, closedJS, 10); e == nil {
			t.Fatal("closed publisher succeeded")
		}
		if count(tdb, `SELECT count(*) FROM outbox WHERE published_at IS NULL`) != taskCount {
			t.Fatal("event lost on publish failure")
		}
		// More than one publisher batch can be pending after the latency samples.
		n, e := delivery.PublishBatch(ctx, js, 100)
		must(e)
		if n != taskCount {
			t.Fatal("publisher retry did not recover")
		}
		if count(tdb, `SELECT count(*) FROM tasks`) != taskCount {
			t.Fatal("publish affected committed task")
		}
	})
	t.Run("core-fail-closed", func(t *testing.T) {
		must(controlObserver.Unsubscribe())
		must(observer.Unsubscribe())
		must(ao.Unsubscribe())
		must(coreSvc.Connection().Flush())
		start("task", provider, taskClient.Kid, taskKey, fabric.EventSubscription{})
		must(accessSvc.Stop())
		s, b := request(client, "POST", base, `{"title":"core down"}`, token, "core-down")
		if s != 503 {
			t.Fatalf("Access unavailable %d %s", s, b)
		}
		closeControl()
		s, b = request(client, "POST", base, `{"title":"fabric down"}`, token, "fabric-down")
		if s != 503 {
			t.Fatalf("Fabric unavailable %d %s", s, b)
		}
		must(coreSvc.Stop())
		s, b = request(client, "POST", base, `{"title":"identity down"}`, token, "identity-down")
		if s != 503 {
			t.Fatalf("Identity unavailable %d %s", s, b)
		}
		if count(tdb, `SELECT count(*) FROM tasks`) != taskCount {
			t.Fatal("Core outage mutated task")
		}
	})
}
func tokenContext(ctx context.Context, token string, c identity.Client, t *testing.T) context.Context {
	t.Helper()
	parts := strings.Split(token, ".")
	var cl security.Claims
	b, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &cl); e != nil {
		t.Fatal(e)
	}
	return rpc.WithCredentials(ctx, rpc.Credentials{Token: token, IdempotencyKey: tasks.NewID(), Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(c.PrivateKey, subject, raw, cl.JTI, security.Proof{Kid: c.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: tasks.NewID()})
	}})
}
func eventually(t *testing.T, check func() bool, diagnostic func() string) {
	t.Helper()
	end := time.Now().Add(12 * time.Second)
	for time.Now().Before(end) {
		if check() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	d := ""
	if diagnostic != nil {
		d = diagnostic()
	}
	t.Fatal("condition did not converge", d)
}

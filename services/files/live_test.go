package files_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	files "github.com/pavlith/arc/services/files"
	v1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/modules/folders"
	"github.com/pavlith/arc/services/files/storage"
	"github.com/pavlith/arc/services/files/stream"
	gate "github.com/pavlith/arc/services/gate/modules/http"
	"github.com/pavlith/arc/test/testdb"
	"github.com/pavlith/arc/test/testlog"
)

func liveKey() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }
func liveSigned(k ed25519.PrivateKey, v any) (json.RawMessage, []byte) {
	b, _ := json.Marshal(v)
	b, _ = security.CanonicalJSON(b)
	return b, ed25519.Sign(k, b)
}
func liveApproval(k ed25519.PrivateKey, v access.Approval) access.Approved {
	b, s := liveSigned(k, v)
	return access.Approved{Payload: b, Signature: s}
}

type liveStreamWriter struct {
	http.ResponseWriter
	hook *atomic.Pointer[func()]
}

func (w liveStreamWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if f := w.hook.Swap(nil); f != nil {
		(*f)()
	}
	return n, err
}

func TestFilesLive(t *testing.T) {
	if os.Getenv("ARC_FILES_LIVE") != "1" {
		t.Skip("run scripts/test-files-live.sh")
	}
	logs := testlog.Capture(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("RPC diagnostics: %s", logs.Bytes())
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		must(os.WriteFile(p, b, 0600))
		return p
	}
	caKey := liveKey()
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Files isolated live CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	must(err)
	ca, err = x509.ParseCertificate(der)
	must(err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile := write("ca.crt", caPEM)
	leaf := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string, tls.Certificate) {
		k := liveKey()
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost", "files.internal"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		d, e := x509.CreateCertificate(rand.Reader, c, ca, k.Public(), caKey)
		must(e)
		kb, e := x509.MarshalPKCS8PrivateKey(k)
		must(e)
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		must(e)
		return write(name+".crt", certPEM), write(name+".key", keyPEM), pair
	}
	certFile, keyFile, _ := leaf("server", 2, x509.ExtKeyUsageServerAuth)
	_, _, clientPair := leaf("gate", 3, x509.ExtKeyUsageClientAuth)
	pools := x509.NewCertPool()
	pools.AppendCertsFromPEM(caPEM)
	seedFiles := map[string]string{}
	pubs := map[string]string{}
	for _, role := range []string{"core", "gate", "files", "admin"} {
		kp, e := nkeys.CreateUser()
		must(e)
		seed, e := kp.Seed()
		must(e)
		pub, e := kp.PublicKey()
		must(e)
		seedFiles[role] = write(role+".seed", seed)
		pubs[role] = pub
	}
	sock, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	port := sock.Addr().(*net.TCPAddr).Port
	sock.Close()
	// Exact role RPC namespaces; the fixture admin alone may manage JetStream.
	conf := fmt.Sprintf(`host: "127.0.0.1"
port: %d
jetstream {store_dir: %q}
tls {cert_file: %q, key_file: %q}
authorization {users: [
 {nkey: %q, permissions: {publish: ["_INBOX.>","evt.arc.fabric.routes.changed","ctl.arc.fabric.probe.>","$SRV.>"], subscribe: ["rpc.identity.v1.>","rpc.access.v1.>","ctl.arc.fabric.>","$SRV.>","_INBOX.>"]}},
 {nkey: %q, permissions: {publish: ["rpc.identity.v1.>","rpc.access.v1.>","rpc.files.v1.>","ctl.arc.fabric.routes"], subscribe: ["_INBOX.>"]}},
 {nkey: %q, permissions: {publish: ["rpc.identity.v1.>","rpc.access.v1.>","ctl.arc.fabric.>","evt.files.catalog.changed.v1","_INBOX.>","$SRV.>"], subscribe: ["rpc.files.v1.>","ctl.arc.fabric.probe.>","_INBOX.>","$SRV.>"]}},
 {nkey: %q}
]}`, port, filepath.Join(dir, "js"), certFile, keyFile, pubs["core"], pubs["gate"], pubs["files"], pubs["admin"])
	confFile := write("nats.conf", []byte(conf))
	logFile, e := os.Create(filepath.Join(dir, "nats.log"))
	must(e)
	broker := exec.CommandContext(ctx, "nats-server", "-c", confFile)
	broker.Stdout = logFile
	broker.Stderr = logFile
	must(broker.Start())
	defer func() { broker.Process.Kill(); broker.Wait(); logFile.Close() }()
	for attempts := 0; ; attempts++ {
		conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if attempts > 100 {
			b, _ := os.ReadFile(logFile.Name())
			t.Fatalf("broker: %s", b)
		}
		time.Sleep(25 * time.Millisecond)
	}
	cfg := func(role string) sdk.Config {
		return sdk.Config{URL: fmt.Sprintf("tls://localhost:%d", port), Name: "files-live-" + role, NKeySeedFile: seedFiles[role], TLSCAFile: caFile}
	}
	coreDB, _ := testdb.Open(t, "core")
	fileDB, e := database.Open(ctx, filepath.Join(dir, "files.sqlite"))
	must(e)
	defer database.Close(fileDB)
	must(database.Migrate(ctx, fileDB, migrations.SQLite()))
	must(database.Migrate(ctx, fileDB, migrations.SQLite()))
	operator, coreKey, gateKey, filesKey, trust := liveKey(), liveKey(), liveKey(), liveKey(), liveKey()
	id := &identity.Core{GormDB: coreDB, PrivateKey: coreKey, SigningKid: "live-core"}
	must(id.PublishSigningKey(ctx, time.Now().Add(time.Hour)))
	alice, _, e := id.BootstrapUser(ctx, "alice@files.test", "live fixture password")
	must(e)
	bob, _, e := id.BootstrapUser(ctx, "bob@files.test", "live fixture password")
	must(e)
	la, e := id.Login(ctx, "alice@files.test", "live fixture password")
	must(e)
	sa := identity.UserSession{Secret: la.Secret, CSRF: la.CSRF}
	lb, e := id.Login(ctx, "bob@files.test", "live fixture password")
	must(e)
	sb := identity.UserSession{Secret: lb.Secret, CSRF: lb.CSRF}
	wa, e := id.CreateWorkspace(ctx, sa, "Alice workspace")
	must(e)
	wb, e := id.CreateWorkspace(ctx, sb, "Bob workspace")
	must(e)
	baseline := access.Approval{AdminUsers: []string{alice}, Deployments: []access.Deployment{{Definition: "gate", Instance: "live-gate"}, {Definition: "files", Instance: "live-files"}}}
	static, e := access.NewContracts(operator.Public().(ed25519.PublicKey), []access.Approved{liveApproval(operator, baseline)})
	must(e)
	acl := &access.Core{GormDB: coreDB, Identity: id, Contracts: static, Domain: access.ReceiptVerifier{Keys: id.Verifier().Keys}}
	id.Policy = acl
	gateID, e := id.RegisterService(ctx, sa, "gate", "live-gate")
	must(e)
	provider, e := id.RegisterService(ctx, sa, "files", "live-files")
	must(e)
	for _, v := range []struct {
		id, kid string
		k       ed25519.PrivateKey
	}{{gateID, "live-gate", gateKey}, {provider, "live-files", filesKey}} {
		must(id.AddServiceKey(ctx, sa, v.id, v.kid, v.k.Public().(ed25519.PublicKey), "mount:live", time.Now().Add(time.Hour)))
	}
	for _, op := range []string{"sessions.login", "sessions.validate", "sessions.logout", "invocations.exchange_user"} {
		baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
	}
	baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "fabric/v1", Operation: "fabric.v1.routes", ActorKinds: []string{"bootstrap"}})
	for _, op := range []string{"invocations.verify", "invocations.exchange_service"} {
		baseline.Rules = append(baseline.Rules, access.Rule{Caller: provider, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
	}

	f := &fabric.Core{GormDB: coreDB, Identity: id, ApprovalKey: operator.Public().(ed25519.PublicKey), Bootstrap: []access.Approved{liveApproval(operator, baseline)}, SnapshotKey: coreKey, SnapshotKid: id.SigningKid, RouteTrustKey: trust}
	acl.ContractSource = f
	coreSvc, e := sdk.NewService(ctx, sdk.ServiceConfig{Name: "arc-bootstrap", Version: "0.6.0", Connection: cfg("core")})
	must(e)
	defer coreSvc.Stop()
	must(id.BindInternal(coreSvc))
	must(acl.BindInternal(coreSvc))
	must(f.BindRoutes(coreSvc))
	closeControl, e := f.BindControl(coreSvc.Connection())
	must(e)
	defer closeControl()
	must(coreSvc.Connection().Flush())
	gateNC, e := sdk.Connect(ctx, cfg("gate"))
	must(e)
	defer gateNC.Close()
	rc, e := rpc.NewClient(gateNC)
	must(e)
	gateClient := identity.Client{RPC: rc, ServiceID: gateID, Kid: "live-gate", PrivateKey: gateKey}
	compiled, e := contract.Compile(v1.Artifact())
	must(e)
	policy := access.Approval{ContractDigests: map[string]string{}}
	for _, r := range compiled.Manifest.Resources {
		policy.ContractDigests[r.Type] = compiled.Digest
		policy.Types = append(policy.Types, access.TypeSpec{Type: r.Type, Provider: provider, Actions: r.Actions, ShareAction: r.ShareAction, CreateAction: r.CreateAction, DeleteAction: r.DeleteAction, AllowInheritance: r.AllowInheritance})
	}
	subjects, from := []string{}, []string{}
	down := map[string][]string{}
	actions := compiled.Manifest.Resources[0].Actions
	for _, op := range compiled.Manifest.Operations {
		subjects = append(subjects, op.Subject)
		policy.Rules = append(policy.Rules, access.Rule{Caller: gateID, Audience: "files/v1", Operation: op.ID, ActorKinds: []string{"user"}, Actions: []string{op.Auth.Action}})
		source := "files/v1:" + op.ID
		from = append(from, source)
		down[source] = []string{op.Auth.Action}
	}
	policy.Rules = append(policy.Rules, access.Rule{Caller: provider, Audience: "access/v1", Operation: "access.v1.check", ActorKinds: []string{"user"}, Actions: actions, DownstreamFrom: from, DownstreamActions: down})
	for _, target := range []string{"resources.reserve", "resources.activate", "grants.add", "grants.revoke"} {
		sources := []string{"files/v1:files.folders.create", "files/v1:files.personal.folders.create"}
		permitted := []string{"files.create"}
		if strings.HasPrefix(target, "grants.") {
			sources = []string{"files/v1:files.roots.grants", "files/v1:files.personal.roots.grants"}
			permitted = actions
		}
		bindings := map[string][]string{}
		for _, src := range sources {
			bindings[src] = permitted
		}
		policy.Rules = append(policy.Rules, access.Rule{Caller: provider, Audience: "access/v1", Operation: "access.v1." + target, ActorKinds: []string{"user"}, Actions: permitted, DownstreamFrom: sources, DownstreamActions: bindings})
	}
	installation := fabric.Installation{Publisher: "files-live-fixture", Account: provider, Deployment: "live-files", Artifact: v1.Artifact(), Subjects: subjects, Policy: liveApproval(operator, policy)}
	raw, sig := liveSigned(operator, installation)
	_, e = f.Approve(ctx, fabric.SignedInstallation{Payload: raw, Signature: sig})
	must(e)
	admin, e := sdk.Connect(ctx, cfg("admin"))
	must(e)
	defer admin.Close()
	js, e := admin.JetStream()
	must(e)
	_, e = js.AddStream(&nats.StreamConfig{Name: "FILES", Subjects: []string{v1.CatalogChangedSubject}, Storage: nats.FileStorage})
	must(e)
	store, e := storage.OpenLocal(filepath.Join(dir, "blobs"))
	must(e)
	defer store.Close()
	registry := &fabric.Client{Account: provider, Kid: "live-files", Key: filesKey, CoreKey: coreKey.Public().(ed25519.PublicKey)}
	fileNC, e := sdk.Connect(ctx, cfg("files"))
	must(e)
	defer fileNC.Close()
	frc, e := rpc.NewClient(fileNC)
	must(e)
	app, e := files.New(files.Config{GormDB: fileDB, Storage: store, CoreTrust: coreKey.Public().(ed25519.PublicKey), Identity: identity.Client{RPC: frc, ServiceID: provider, Kid: "live-files", PrivateKey: filesKey}, Runtime: sdk.AppConfig{Connection: cfg("files"), Instance: "live-files", Registry: registry}})
	must(e)
	must(app.Start(ctx))
	defer app.Stop()
	remote := &gate.Remote{Client: gateClient, TrustRoot: trust.Public().(ed25519.PublicKey)}
	private, e := stream.New(stream.Config{Listen: "127.0.0.1:0", TLSCertFile: certFile, TLSKeyFile: keyFile, ClientCAFile: caFile, Verify: identity.RemoteAuthorizer(app.Folders.Identity, coreKey.Public().(ed25519.PublicKey), "files/v1"), Objects: app.Objects, Contract: compiled})
	must(e)
	// Real mutual TLS over a loopback HTTPS listener, with the production handler.
	var streamHook atomic.Pointer[func()]
	ps := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		private.Handler().ServeHTTP(liveStreamWriter{ResponseWriter: w, hook: &streamHook}, r)
	}))
	ps.TLS = &tls.Config{Certificates: []tls.Certificate{}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pools, MinVersion: tls.VersionTLS13}
	pair, e := tls.LoadX509KeyPair(certFile, keyFile)
	must(e)
	ps.TLS.Certificates = []tls.Certificate{pair}
	ps.StartTLS()
	defer ps.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pools, Certificates: []tls.Certificate{clientPair}, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	g, e := gate.New(gate.Config{Backend: remote, PublicOrigin: "https://arc.files.test", RequestsPerMinute: 10000, PrivateFiles: &gate.PrivateFilesConfig{URL: ps.URL, Client: &http.Client{Transport: transport, Timeout: 60 * time.Second}, Sign: remote.SignPrivate}})
	must(e)
	must(g.Reconcile(ctx))
	server := httptest.NewTLSServer(g)
	defer server.Close()
	client := server.Client()
	client.Timeout = 60 * time.Second
	request := func(method, path, body, token, mime string) (int, []byte) {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		must(e)
		req.Header.Set("Content-Type", mime)
		req.Header.Set("Idempotency-Key", folders.NewID())
		req.Header.Set("Upload-Offset", "0")
		req.Header.Set("X-Actor", "user:"+alice)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, e := client.Do(req)
		must(e)
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		must(e)
		return resp.StatusCode, b
	}
	isDenied := func(status int) bool { return status == 401 || status == 403 || status == 404 }
	interrupted := func(path, token string, afterFirst func()) {
		streamHook.Store(&afterFirst)
		req, e := http.NewRequestWithContext(ctx, "GET", server.URL+path, nil)
		must(e)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := client.Do(req)
		must(e)
		b, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || readErr == nil || len(b) != 256<<10 {
			t.Fatalf("revocation did not truncate transfer after first block: status=%d bytes=%d error=%v", resp.StatusCode, len(b), readErr)
		}
	}
	login := func(email string) string {
		status, b := request("POST", "/api/v1/arc/cli/token", fmt.Sprintf(`{"email":%q,"password":"live fixture password"}`, email), "", "application/json")
		if status != 200 {
			t.Fatalf("HTTP login %d %s", status, b)
		}
		var v struct {
			Token string `json:"access_token"`
		}
		must(json.Unmarshal(b, &v))
		return v.Token
	}
	ta, tb := login("alice@files.test"), login("bob@files.test")
	accessCtx := func(session identity.UserSession, ws, op string) context.Context {
		source := "files.folders.create"
		if ws == "" {
			source = "files.personal.folders.create"
		}
		if strings.HasPrefix(op, "grants.") {
			source = "files.roots.grants"
			if ws == "" {
				source = "files.personal.roots.grants"
			}
		}
		cred, e := gateClient.Credentials("identity.exchange_user")
		must(e)
		token, e := identity.Call[identity.UserExchange, identity.TokenResult](ctx, gateClient, "identity.v1.invocations.exchange_user", identity.UserExchange{Assertion: cred.Token, Session: session, Target: identity.Target{Audience: "files/v1", Operation: source, WorkspaceID: ws}})
		must(e)

		providerClient := identity.Client{RPC: frc, ServiceID: provider, Kid: "live-files", PrivateKey: filesKey}
		token, e = identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, providerClient, "identity.v1.invocations.exchange_service", identity.ServiceExchange{IncomingToken: token.Token, IncomingOperation: source, Target: identity.Target{Audience: "access/v1", Operation: "access.v1." + op, WorkspaceID: ws}})
		must(e)
		parts := strings.Split(token.Token, ".")
		b, e := base64.RawURLEncoding.DecodeString(parts[1])
		must(e)
		var cl security.Claims
		must(json.Unmarshal(b, &cl))
		return rpc.WithCredentials(ctx, rpc.Credentials{Token: token.Token, IdempotencyKey: folders.NewID(), Proof: func(subject string, raw []byte) (security.Proof, error) {
			return security.SignProof(filesKey, subject, raw, cl.JTI, security.Proof{Kid: "live-files", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: folders.NewID()})
		}})
	}
	ac := &access.Client{RPC: rc}
	provision := func(user string, session identity.UserSession, ws string) v1.Scope {
		kind, typ, owner := "workspace", "files.workspace", ws
		if ws == "" {
			kind, typ, owner = "user", "files.personal", user
		}
		reserved, e := ac.Reserve(accessCtx(session, ws, "resources.reserve"), access.ReserveRequest{Type: typ, OwnerKind: kind, OwnerID: owner, WorkspaceID: ws})
		must(e)
		scope := v1.Scope{WorkspaceID: ws, RootID: reserved.ResourceID}
		var receipt string
		if ws == "" {
			receipt, e = app.Folders.PreparePersonalRoot(ctx, scope.RootID, user, filesKey, "live-files", provider)
		} else {
			receipt, e = app.Folders.PrepareRoot(ctx, scope, filesKey, "live-files", provider)
		}
		must(e)
		_, e = ac.Activate(accessCtx(session, ws, "resources.activate"), access.LifecycleRequest{ResourceID: scope.RootID, Receipt: receipt})
		must(e)
		must(app.Folders.ActivateRoot(ctx, scope))
		if ws != "" {
			for _, action := range []string{"files.read", "files.create", "files.write", "files.delete"} {
				_, e = ac.AddGrant(accessCtx(session, ws, "grants.add"), access.GrantRequest{ResourceID: scope.RootID, PrincipalKind: "user", PrincipalID: user, Action: action})
				must(e)
			}
		}
		return scope
	}
	pa, pb, wsa, wsb := provision(alice, sa, ""), provision(bob, sb, ""), provision(alice, sa, wa), provision(bob, sb, wb)
	base := func(s v1.Scope) string {
		if s.WorkspaceID == "" {
			return "/api/v1/files/personal/roots/" + s.RootID
		}
		return "/api/v1/files/workspaces/" + s.WorkspaceID + "/roots/" + s.RootID
	}
	upload := func(scope v1.Scope, token string) v1.File {
		prefix := base(scope)
		status, b := request("POST", prefix+"/uploads", `{"filename":"live.bin","mime":"application/octet-stream","expected_size":524288}`, token, "application/json")
		if status != 201 {
			t.Fatalf("initiate %d %s", status, b)
		}
		var u v1.Upload
		must(json.Unmarshal(b, &u))
		status, b = request("PATCH", prefix+"/uploads/"+u.ID+"/bytes", strings.Repeat("x", 524288), token, "application/octet-stream")
		if status != 200 {
			t.Fatalf("chunk %d %s", status, b)
		}
		status, b = request("POST", prefix+"/uploads/"+u.ID+"/complete", `{}`, token, "application/json")
		if status != 201 {
			t.Fatalf("complete %d %s", status, b)
		}
		var file v1.File
		must(json.Unmarshal(b, &file))
		return file
	}
	for _, tc := range []struct {
		scope        v1.Scope
		token, other string
	}{{pa, ta, tb}, {pb, tb, ta}, {wsa, ta, tb}, {wsb, tb, ta}} {
		file := upload(tc.scope, tc.token)
		path := base(tc.scope) + "/files/" + file.ID
		status, b := request("GET", path+"/content", "", tc.token, "")
		if status != 200 || !bytes.Equal(b, bytes.Repeat([]byte("x"), 524288)) {
			t.Fatalf("download mismatch: %d bytes=%d", status, len(b))
		}
		for _, suffix := range []string{"", "/content"} {
			status, b = request("GET", path+suffix, "", tc.other, "")
			if !isDenied(status) || bytes.Contains(b, []byte("live.bin")) {
				t.Fatalf("known-ID leak %s: %d", suffix, status)
			}
		}
	}
	// Share a personal file; revocation immediately denies the same known ID.
	shared := upload(pa, ta)
	path := base(pa) + "/files/" + shared.ID
	grantStatus, grantBody := request("POST", base(pa)+"/grants", fmt.Sprintf(`{"principal_id":%q,"action":"files.read"}`, bob), ta, "application/json")
	if grantStatus != 200 {
		t.Fatalf("grant through Gate: %d %s", grantStatus, grantBody)
	}
	var grant v1.GrantResult
	must(json.Unmarshal(grantBody, &grant))

	status, b := request("GET", path+"/content", "", tb, "")
	if status != 200 || len(b) != 524288 {
		t.Fatalf("shared download: %d %s", status, b)
	}
	// A root manager cannot revoke a known grant through a different root.
	status, b = request("POST", base(pb)+"/grants", fmt.Sprintf(`{"grant_id":%q}`, grant.GrantID), tb, "application/json")
	if !isDenied(status) {
		t.Fatalf("cross-root grant revoke: %d %s", status, b)
	}
	status, b = request("POST", base(pa)+"/grants", fmt.Sprintf(`{"principal_id":%q,"action":"files.write"}`, bob), tb, "application/json")
	if !isDenied(status) {
		t.Fatalf("read grantee escalated to manager: %d %s", status, b)
	}
	interrupted(path+"/content", tb, func() {
		hookStatus, hookBody := request("POST", base(pa)+"/grants", fmt.Sprintf(`{"grant_id":%q}`, grant.GrantID), ta, "application/json")
		if hookStatus != 200 {
			t.Errorf("revoke through Gate: %d %s", hookStatus, hookBody)
		}
	})

	status, _ = request("GET", path+"/content", "", tb, "")
	if !isDenied(status) {
		t.Fatal("revoked grant downloaded")
	}
	// Cross-root substitution and scope injection cannot authorize a known file.
	status, _ = request("GET", base(pb)+"/files/"+shared.ID+"/content", "", tb, "")
	if !isDenied(status) {
		t.Fatal("cross-root substitution downloaded")
	}
	status, _ = request("POST", base(pa)+"/uploads", fmt.Sprintf(`{"workspace_id":%q,"filename":"bad.bin","mime":"application/octet-stream","expected_size":0}`, wa), ta, "application/json")
	if status != 400 {
		t.Fatalf("workspace injection accepted: %d", status)
	}
	interrupted(path+"/content", ta, func() {
		hookStatus, _ := request("POST", "/api/v1/arc/cli/logout", `{}`, ta, "application/json")
		if hookStatus != 200 && hookStatus != 204 {
			t.Errorf("logout: %d", hookStatus)
		}
	})

	status, _ = request("GET", path+"/content", "", ta, "")
	if !isDenied(status) {
		t.Fatal("revoked session downloaded")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int64
		must(fileDB.Table("outbox").Where("published_at IS NULL").Count(&n).Error)
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("outbox not delivered")
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Log("PASS: two users/two workspaces + personal roots, signed approvals/routes, TLS/NKey NATS, mTLS bytes, known-ID isolation, grant/session revoke during transfers, cross-root grant protection, scope substitution, migration replay and outbox delivery")
}

package mail_test

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
	gate "github.com/pavlith/arc/services/gate/modules/http"
	mailservice "github.com/pavlith/arc/services/mail"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
	"github.com/pavlith/arc/services/mail/migrations"
	"github.com/pavlith/arc/services/mail/stream"
	"github.com/pavlith/arc/test/imapfixture"
	"github.com/pavlith/arc/test/testdb"
	"github.com/pavlith/arc/test/testlog"
)

func liveKey() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }
func uid() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func signed(key ed25519.PrivateKey, value any) (json.RawMessage, []byte) {
	raw, _ := json.Marshal(value)
	raw, _ = security.CanonicalJSON(raw)
	return raw, ed25519.Sign(key, raw)
}
func approved(key ed25519.PrivateKey, value access.Approval) access.Approved {
	raw, sig := signed(key, value)
	return access.Approved{Payload: raw, Signature: sig}
}
func TestMailLive(t *testing.T) {
	if os.Getenv("ARC_MAIL_LIVE") != "1" {
		t.Skip("run scripts/test-mail-live.sh")
	}
	logs := testlog.Capture(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("RPC diagnostics: %s", logs.Bytes())
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	passwordA, passwordB, passwordC := "Mail fixture sensitive A", "Mail fixture sensitive B", "Mail fixture sensitive C"
	imap := imapfixture.New(t, "plain", map[string]string{"a": passwordA, "b": passwordB, "c": passwordC})
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		must(os.WriteFile(p, data, 0600))
		return p
	}
	caKey := liveKey()
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mail isolated live CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	must(err)
	ca, err = x509.ParseCertificate(der)
	must(err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile := write("ca.crt", caPEM)
	leaf := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string, tls.Certificate) {
		k := liveKey()
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost", "mail.internal"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		d, e := x509.CreateCertificate(rand.Reader, c, ca, k.Public(), caKey)
		must(e)
		kb, e := x509.MarshalPKCS8PrivateKey(k)
		must(e)
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		must(e)
		return write(name+".crt", certPEM), write(name+".key", keyPEM), pair
	}
	certFile, keyFile, serverPair := leaf("server", 2, x509.ExtKeyUsageServerAuth)
	_, _, clientPair := leaf("gate", 3, x509.ExtKeyUsageClientAuth)
	pools := x509.NewCertPool()
	pools.AppendCertsFromPEM(caPEM)
	seeds, pubs := map[string]string{}, map[string]string{}
	for _, role := range []string{"core", "gate", "mail", "admin"} {
		kp, e := nkeys.CreateUser()
		must(e)
		seed, e := kp.Seed()
		must(e)
		pub, e := kp.PublicKey()
		must(e)
		seeds[role] = write(role+".seed", seed)
		pubs[role] = pub
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	conf := fmt.Sprintf(`host: "127.0.0.1"
port: %d
jetstream {store_dir: %q}
tls {cert_file: %q,key_file: %q}
authorization {users: [
 {nkey: %q,permissions:{publish:["_INBOX.>","evt.arc.fabric.routes.changed","ctl.arc.fabric.probe.>","$SRV.>"],subscribe:["rpc.identity.v1.>","rpc.access.v1.>","ctl.arc.fabric.>","$SRV.>","_INBOX.>"]}},
 {nkey: %q,permissions:{publish:["rpc.identity.v1.>","rpc.access.v1.>","rpc.mail.v1.>","ctl.arc.fabric.routes"],subscribe:["_INBOX.>"]}},
 {nkey: %q,permissions:{publish:["rpc.identity.v1.>","rpc.access.v1.>","ctl.arc.fabric.>","evt.mail.accounts.changed.v1","_INBOX.>","$SRV.>"],subscribe:["rpc.mail.v1.>","ctl.arc.fabric.probe.>","_INBOX.>","$SRV.>"]}},
 {nkey: %q}
]}`, port, filepath.Join(dir, "js"), imap.CertFile, imap.KeyFile, pubs["core"], pubs["gate"], pubs["mail"], pubs["admin"])
	configPath := write("nats.conf", []byte(conf))
	brokerLog, e := os.Create(filepath.Join(dir, "nats.log"))
	must(e)
	broker := exec.CommandContext(ctx, "nats-server", "-c", configPath)
	broker.Stdout = brokerLog
	broker.Stderr = brokerLog
	must(broker.Start())
	defer func() { broker.Process.Kill(); broker.Wait(); brokerLog.Close() }()
	for i := 0; ; i++ {
		conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if i > 100 {
			t.Fatal("broker unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cfg := func(role string) sdk.Config {
		return sdk.Config{URL: fmt.Sprintf("tls://127.0.0.1:%d", port), Name: "mail-live-" + role, NKeySeedFile: seeds[role], TLSCAFile: imap.CAFile}
	}
	coreDB, _ := testdb.Open(t, "core")
	mailDB, e := database.Open(ctx, filepath.Join(dir, "mail.sqlite"))
	must(e)
	defer database.Close(mailDB)
	must(database.Migrate(ctx, mailDB, migrations.SQLite()))
	must(database.Migrate(ctx, mailDB, migrations.SQLite()))
	operator, coreKey, gateKey, mailKey, trust := liveKey(), liveKey(), liveKey(), liveKey(), liveKey()
	id := &identity.Core{GormDB: coreDB, PrivateKey: coreKey, SigningKid: "live-core"}
	must(id.PublishSigningKey(ctx, time.Now().Add(time.Hour)))
	alice, _, e := id.BootstrapUser(ctx, "alice@mail.test", "live fixture password")
	must(e)
	bob, _, e := id.BootstrapUser(ctx, "bob@mail.test", "live fixture password")
	must(e)
	la, e := id.LoginBrowser(ctx, "alice@mail.test", "live fixture password")
	must(e)
	lb, e := id.LoginBrowser(ctx, "bob@mail.test", "live fixture password")
	must(e)
	sa, sb := identity.UserSession{Secret: la.Secret, CSRF: la.CSRF}, identity.UserSession{Secret: lb.Secret, CSRF: lb.CSRF}
	baseline := access.Approval{AdminUsers: []string{alice}, Deployments: []access.Deployment{{Definition: "gate", Instance: "live-gate"}, {Definition: "mail", Instance: "live-mail"}}}
	static, e := access.NewContracts(operator.Public().(ed25519.PublicKey), []access.Approved{approved(operator, baseline)})
	must(e)
	acl := &access.Core{GormDB: coreDB, Identity: id, Contracts: static, Domain: access.ReceiptVerifier{Keys: id.Verifier().Keys}}
	id.Policy = acl
	gateID, e := id.RegisterService(ctx, sa, "gate", "live-gate")
	must(e)
	provider, e := id.RegisterService(ctx, sa, "mail", "live-mail")
	must(e)
	must(id.AddServiceKey(ctx, sa, gateID, "live-gate", gateKey.Public().(ed25519.PublicKey), "mount:live", time.Now().Add(time.Hour)))
	must(id.AddServiceKey(ctx, sa, provider, "live-mail", mailKey.Public().(ed25519.PublicKey), "mount:live", time.Now().Add(time.Hour)))
	for _, op := range []string{"sessions.login", "sessions.validate", "sessions.logout", "invocations.exchange_user"} {
		baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
	}
	baseline.Rules = append(baseline.Rules, access.Rule{Caller: gateID, Audience: "fabric/v1", Operation: "fabric.v1.routes", ActorKinds: []string{"bootstrap"}})
	for _, op := range []string{"invocations.verify", "invocations.exchange_service"} {
		baseline.Rules = append(baseline.Rules, access.Rule{Caller: provider, Audience: "identity/v1", Operation: "identity.v1." + op, ActorKinds: []string{"bootstrap"}})
	}
	fabricCore := &fabric.Core{GormDB: coreDB, Identity: id, ApprovalKey: operator.Public().(ed25519.PublicKey), Bootstrap: []access.Approved{approved(operator, baseline)}, SnapshotKey: coreKey, SnapshotKid: id.SigningKid, RouteTrustKey: trust}
	acl.ContractSource = fabricCore
	coreSvc, e := sdk.NewService(ctx, sdk.ServiceConfig{Name: "arc-bootstrap", Version: "0.6.0", Connection: cfg("core")})
	must(e)
	defer coreSvc.Stop()
	must(id.BindInternal(coreSvc))
	must(acl.BindInternal(coreSvc))
	must(fabricCore.BindRoutes(coreSvc))
	closeControl, e := fabricCore.BindControl(coreSvc.Connection())
	must(e)
	defer closeControl()
	must(coreSvc.Connection().Flush())
	gateNC, e := sdk.Connect(ctx, cfg("gate"))
	must(e)
	defer gateNC.Close()
	gateRPC, e := rpc.NewClient(gateNC)
	must(e)
	gateClient := identity.Client{RPC: gateRPC, ServiceID: gateID, Kid: "live-gate", PrivateKey: gateKey}
	compiled, e := contract.Compile(v1.Artifact())
	must(e)
	resource := compiled.Manifest.Resources[0]
	policy := access.Approval{ContractDigests: map[string]string{resource.Type: compiled.Digest}, Types: []access.TypeSpec{{Type: resource.Type, Provider: provider, Actions: resource.Actions, ShareAction: resource.ShareAction, CreateAction: resource.CreateAction, DeleteAction: resource.DeleteAction}}}
	subjects, sources := []string{}, []string{}
	down := map[string][]string{}
	for _, op := range compiled.Manifest.Operations {
		subjects = append(subjects, op.Subject)
		sources = append(sources, "mail/v1:"+op.ID)
		down["mail/v1:"+op.ID] = []string{op.Auth.Action}
		policy.Rules = append(policy.Rules, access.Rule{Caller: gateID, Audience: "mail/v1", Operation: op.ID, ActorKinds: []string{"user"}, Actions: []string{op.Auth.Action}})
	}
	policy.Rules = append(policy.Rules, access.Rule{Caller: provider, Audience: "access/v1", Operation: "access.v1.check", ActorKinds: []string{"user"}, Actions: resource.Actions, DownstreamFrom: sources, DownstreamActions: down})
	for _, op := range []string{"resources.reserve", "resources.activate"} {
		acts := []string{"mail.connection.manage"}
		if strings.HasPrefix(op, "grants.") {
			acts = resource.Actions
		}
		src := "mail/v1:" + v1.UpdateAccount.ID
		policy.Rules = append(policy.Rules, access.Rule{Caller: provider, Audience: "access/v1", Operation: "access.v1." + op, ActorKinds: []string{"user"}, Actions: acts, DownstreamFrom: []string{src}, DownstreamActions: map[string][]string{src: acts}})
	}
	installation := fabric.Installation{Publisher: "mail-live-fixture", Account: provider, Deployment: "live-mail", Artifact: v1.Artifact(), Subjects: subjects, Policy: approved(operator, policy)}
	raw, sig := signed(operator, installation)
	_, e = fabricCore.Approve(ctx, fabric.SignedInstallation{Payload: raw, Signature: sig})
	must(e)
	admin, e := sdk.Connect(ctx, cfg("admin"))
	must(e)
	defer admin.Close()
	js, e := admin.JetStream()
	must(e)
	_, e = js.AddStream(&nats.StreamConfig{Name: "MAIL", Subjects: []string{v1.ChangedSubject}, Storage: nats.FileStorage})
	must(e)
	ownerNC, e := sdk.Connect(ctx, cfg("mail"))
	must(e)
	defer ownerNC.Close()
	ownerRPC, e := rpc.NewClient(ownerNC)
	must(e)
	mailClient := identity.Client{RPC: ownerRPC, ServiceID: provider, Kid: "live-mail", PrivateKey: mailKey}
	master := make([]byte, 32)
	rand.Read(master)
	vault, e := credentials.New(master)
	must(e)
	probe, e := imapclient.New(imapclient.Config{Endpoints: []imapclient.Endpoint{{Host: imap.Host, Port: imap.Port, CIDRs: []string{"127.0.0.1/32"}}}, RootCAs: imap.Roots})
	must(e)
	app, e := mailservice.New(mailservice.Config{GormDB: mailDB, Vault: vault, Probe: probe, Identity: mailClient, CoreTrust: coreKey.Public().(ed25519.PublicKey), Runtime: sdk.AppConfig{Connection: cfg("mail"), Instance: "live-mail", Registry: &fabric.Client{Account: provider, Kid: "live-mail", Key: mailKey, CoreKey: coreKey.Public().(ed25519.PublicKey)}}})
	must(e)
	must(app.Start(ctx))
	defer app.Stop()
	remote := &gate.Remote{Client: gateClient, TrustRoot: trust.Public().(ed25519.PublicKey)}
	private, e := stream.New(stream.Config{Listen: "127.0.0.1:0", TLSCertFile: certFile, TLSKeyFile: keyFile, ClientCAFile: caFile, Accounts: app.Accounts, Contract: compiled, Verify: identity.RemoteAuthorizer(mailClient, coreKey.Public().(ed25519.PublicKey), "mail/v1")})
	must(e)
	privateHTTP := httptest.NewUnstartedServer(private.Handler())
	privateHTTP.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pools}
	privateHTTP.StartTLS()
	defer privateHTTP.Close()
	privateTransport := &http.Transport{Proxy: nil, DisableCompression: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pools, Certificates: []tls.Certificate{clientPair}, ServerName: "mail.internal"}}
	defer privateTransport.CloseIdleConnections()
	privateClient := &http.Client{Transport: privateTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	g, e := gate.New(gate.Config{Backend: remote, PublicOrigin: "https://arc.mail.test", RequestsPerMinute: 10000, PrivateMail: &gate.PrivateMailConfig{URL: privateHTTP.URL, Client: privateClient, Sign: remote.SignPrivate}})
	must(e)
	must(g.Reconcile(ctx))
	httpServer := httptest.NewTLSServer(g)
	defer httpServer.Close()
	httpClient := httpServer.Client()
	request := func(method, path string, body any, token, key string) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			data, e := json.Marshal(body)
			must(e)
			// Go requests carry RPC scope; HTTP supplies the root in the path.
			var object map[string]json.RawMessage
			must(json.Unmarshal(data, &object))
			delete(object, "acl_root_id")
			data, e = json.Marshal(object)
			must(e)
			reader = bytes.NewReader(data)
		}
		req, e := http.NewRequestWithContext(ctx, method, httpServer.URL+path, reader)
		must(e)
		req.Header.Set("Content-Type", "application/json")
		if key == "" {
			key = uid()
		}
		req.Header.Set("Idempotency-Key", key)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("X-Actor", "user:"+alice)
		resp, e := httpClient.Do(req)
		must(e)
		defer resp.Body.Close()
		data, e := io.ReadAll(resp.Body)
		must(e)
		return resp.StatusCode, data
	}
	login := func(email string) string {
		status, data := request("POST", "/api/v1/arc/cli/token", map[string]string{"email": email, "password": "live fixture password"}, "", "")
		if status != 200 {
			t.Fatalf("CLI login %d %s", status, data)
		}
		var out struct {
			Token string `json:"access_token"`
		}
		must(json.Unmarshal(data, &out))
		return out.Token
	}
	ta, tb := login("alice@mail.test"), login("bob@mail.test")
	ac := &access.Client{RPC: ownerRPC}
	accessCtx := func(session identity.UserSession, op string) context.Context {
		return liveDomainAccess(t, ctx, gateClient, mailClient, session, "", v1.UpdateAccount.ID, op)
	}
	provision := func(owner string, session identity.UserSession, login string) v1.Scope {
		reserved, e := ac.Reserve(accessCtx(session, "resources.reserve"), access.ReserveRequest{Type: "mail.personal", OwnerKind: "user", OwnerID: owner})
		must(e)
		scope := v1.Scope{RootID: reserved.ResourceID}
		receipt, e := app.Accounts.PrepareRoot(ctx, scope, owner, v1.AccountInput{Name: "Mailbox", Host: imap.Host, Port: imap.Port, Login: login, Email: login + "@mail.test"}, mailKey, "live-mail", provider)
		must(e)
		_, e = ac.Activate(accessCtx(session, "resources.activate"), access.LifecycleRequest{ResourceID: scope.RootID, Receipt: receipt})
		must(e)
		must(app.Accounts.ActivateRoot(ctx, scope))
		return scope
	}
	a, b, c := provision(alice, sa, "a"), provision(bob, sb, "b"), provision(alice, sa, "c")
	base := func(q v1.Scope) string { return "/api/v1/mail/personal/accounts/" + q.RootID }
	for _, tc := range []struct {
		scope v1.Scope
		token string
	}{{a, tb}, {b, ta}} {
		status, data := request("GET", base(tc.scope), nil, tc.token, "")
		if status != 403 && status != 404 {
			t.Fatalf("known-ID leak %d %s", status, data)
		}
	}
	setCredential := func(scope v1.Scope, password, token string) (v1.SetCredential, v1.Account) {
		status, data := request("GET", base(scope)+"/credentials/key", nil, token, "")
		if status != 200 {
			t.Fatalf("key %d %s", status, data)
		}
		var info v1.KeyInfo
		must(json.Unmarshal(data, &info))
		sealed, e := credentials.Seal(info.PublicInfo, []byte(password))
		must(e)
		q := v1.SetCredential{Scope: scope, Revision: info.Revision, KeyID: info.KeyID, Sealed: sealed}
		status, data = request("PUT", base(scope)+"/credentials", q, token, "credential-"+scope.RootID)
		if status != 200 {
			t.Fatalf("credential %d %s", status, data)
		}
		var account v1.Account
		must(json.Unmarshal(data, &account))
		return q, account
	}
	original, accountA := setCredential(a, passwordA, ta)
	setCredential(b, passwordB, tb)
	setCredential(c, passwordC, ta)
	for _, tc := range []struct {
		scope v1.Scope
		token string
	}{{a, ta}, {b, tb}, {c, ta}} {
		status, data := request("POST", base(tc.scope)+"/check", nil, tc.token, "")
		var result v1.CheckResult
		must(json.Unmarshal(data, &result))
		if status != 200 || result.Status != "ok" {
			t.Fatalf("IMAP check %d %s", status, data)
		}
	}
	statusFolders, dataFolders := request("GET", base(a)+"/folders", nil, ta, "")
	var folderList v1.FolderList
	must(json.Unmarshal(dataFolders, &folderList))
	if statusFolders != 200 || folderList.Status != "ok" || len(folderList.Folders) != 4 || folderList.Folders[2].Name != "Почта" || folderList.Folders[1].Selectable || folderList.Folders[3].Name != "Reports" {
		t.Fatalf("folders %d %s", statusFolders, dataFolders)
	}

	messageQuery := v1.MessageListQuery{Generation: 1, MessageQuery: imapclient.MessageQuery{WireName: folderList.Folders[0].WireName, UIDWindow: 1}}
	statusMessages, dataMessages := request("POST", base(a)+"/messages/list", messageQuery, ta, "")
	var messageList v1.MessageList
	must(json.Unmarshal(dataMessages, &messageList))
	if statusMessages != 200 || messageList.Status != "ok" || messageList.UIDValidity != 77 || len(messageList.Messages) != 1 || messageList.Messages[0].Subject != "Привет" || messageList.Messages[0].UID != 102 {
		t.Fatalf("messages %d %s", statusMessages, dataMessages)
	}
	messageQuery.BeforeUID = messageList.NextBeforeUID
	messageQuery.UIDValidity = messageList.UIDValidity
	statusMessages, dataMessages = request("POST", base(a)+"/messages/list", messageQuery, ta, "")
	must(json.Unmarshal(dataMessages, &messageList))
	if statusMessages != 200 || messageList.Status != "ok" || len(messageList.Messages) != 1 || messageList.Messages[0].UID != 101 {
		t.Fatalf("message continuation %d %s", statusMessages, dataMessages)
	}
	staleQuery := messageQuery
	staleQuery.UIDValidity = 78
	statusMessages, dataMessages = request("POST", base(a)+"/messages/list", staleQuery, ta, "")
	must(json.Unmarshal(dataMessages, &messageList))
	if statusMessages != 200 || messageList.Status != "uidvalidity_changed" || len(messageList.Messages) != 0 {
		t.Fatalf("UIDVALIDITY guard %d %s", statusMessages, dataMessages)
	}
	staleQuery = messageQuery
	staleQuery.Generation = 2
	statusMessages, dataMessages = request("POST", base(a)+"/messages/list", staleQuery, ta, "")
	if statusMessages != 409 {
		t.Fatalf("binding generation guard %d %s", statusMessages, dataMessages)
	}

	structureQuery := v1.StructureQuery{Generation: 1, StructureQuery: imapclient.StructureQuery{WireName: folderList.Folders[0].WireName, UIDValidity: 77, UID: 102}}
	statusStructure, dataStructure := request("POST", base(a)+"/messages/structure", structureQuery, ta, "")
	var structure v1.Structure
	must(json.Unmarshal(dataStructure, &structure))
	if statusStructure != 200 || structure.Status != "ok" || len(structure.Parts) != 3 || len(structure.Attachments) != 1 || structure.Parts[2].Filename != "report final.pdf" {
		t.Fatalf("structure %d %s", statusStructure, dataStructure)
	}
	downloadQuery := v1.DownloadRequest{Generation: 1, DownloadQuery: imapclient.DownloadQuery{StructureQuery: structureQuery.StructureQuery}}
	statusDownload, dataDownload := request("POST", base(a)+"/messages/content", downloadQuery, ta, "")
	if statusDownload != 200 || !bytes.Equal(dataDownload, imapfixture.MessageContent()) {
		t.Fatalf("raw stream %d length %d", statusDownload, len(dataDownload))
	}
	downloadQuery.Section = "2"
	statusDownload, dataDownload = request("POST", base(a)+"/messages/content", downloadQuery, ta, "")
	if statusDownload != 200 || !bytes.Equal(dataDownload, imapfixture.AttachmentContent()) {
		t.Fatalf("attachment stream %d %q", statusDownload, dataDownload)
	}
	// The signed hidden operation never carries content through NATS.
	downloadRPC := downloadQuery
	downloadRPC.Scope = a
	downloadPayload, e := json.Marshal(downloadRPC)
	must(e)
	downloadOp, e := compiled.Operation(v1.PrivateDownload.ID)
	must(e)
	downloadToken, e := remote.Exchange(ctx, identity.UserExchange{AccessToken: ta, Target: identity.Target{Audience: "mail/v1", Operation: v1.PrivateDownload.ID}})
	must(e)
	if _, e = remote.Invoke(ctx, compiled, downloadOp, downloadPayload, downloadToken.Token, ""); rpc.ErrorCode(e) != rpc.CodePermissionDenied {
		t.Fatalf("NATS byte operation did not fail closed: %v", e)
	}
	staleDownload := downloadQuery
	staleDownload.UIDValidity = 78
	statusDownload, _ = request("POST", base(a)+"/messages/content", staleDownload, ta, "")
	if statusDownload != 403 {
		t.Fatalf("stream namespace guard %d", statusDownload)
	}

	staleStructure := structureQuery
	staleStructure.UIDValidity = 78
	statusStructure, dataStructure = request("POST", base(a)+"/messages/structure", staleStructure, ta, "")
	must(json.Unmarshal(dataStructure, &structure))
	if statusStructure != 200 || structure.Status != "uidvalidity_changed" || len(structure.Parts) != 0 {
		t.Fatalf("structure namespace guard %d %s", statusStructure, dataStructure)
	}
	staleStructure = structureQuery
	staleStructure.Generation = 2
	statusStructure, dataStructure = request("POST", base(a)+"/messages/structure", staleStructure, ta, "")
	if statusStructure != 409 {
		t.Fatalf("structure generation guard %d %s", statusStructure, dataStructure)
	}
	// Trusted Core fixture seed: Mail 0.1 has no grant-management endpoint or
	// downstream grant permission. All reads still exercise real online Access.
	grantID := uid()
	must(coreDB.Exec("INSERT INTO access_grants(id,resource_id,principal_kind,principal_id,action,created_by,created_at) VALUES(?,?,'user',?,'mail.read',?,?)", grantID, a.RootID, bob, "user:"+alice, time.Now().UTC()).Error)

	status, data := request("GET", base(a), nil, tb, "")
	if status != 200 {
		t.Fatalf("read grant %d %s", status, data)
	}
	status, data = request("GET", base(a)+"/folders", nil, tb, "")
	if status != 200 {
		t.Fatalf("reader folders %d %s", status, data)
	}

	status, data = request("POST", base(a)+"/messages/list", messageQuery, tb, "")
	if status != 200 {
		t.Fatalf("reader messages %d %s", status, data)
	}

	status, data = request("POST", base(a)+"/messages/structure", structureQuery, tb, "")
	if status != 200 {
		t.Fatalf("reader structure %d %s", status, data)
	}

	status, data = request("POST", base(a)+"/messages/content", downloadQuery, tb, "")
	if status != 200 || !bytes.Equal(data, imapfixture.AttachmentContent()) {
		t.Fatalf("reader stream %d %q", status, data)
	}

	for _, suffix := range []string{"/credentials/key", "/check"} {
		method := "GET"
		if suffix == "/check" {
			method = "POST"
		}
		status, data = request(method, base(a)+suffix, nil, tb, "")
		if status != 403 {
			t.Fatalf("reader can manage credential/check %d %s", status, data)
		}
	}
	must(coreDB.Exec("UPDATE access_grants SET revoked_at=? WHERE id=?", time.Now().UTC(), grantID).Error)

	status, data = request("GET", base(a), nil, tb, "")
	if status != 403 {
		t.Fatalf("revoked read %d %s", status, data)
	}
	status, data = request("GET", base(a)+"/folders", nil, tb, "")
	if status != 403 {
		t.Fatalf("revoked folders %d %s", status, data)
	}

	status, data = request("POST", base(a)+"/messages/list", messageQuery, tb, "")
	if status != 403 {
		t.Fatalf("revoked messages %d %s", status, data)
	}

	status, data = request("POST", base(a)+"/messages/structure", structureQuery, tb, "")
	if status != 403 {
		t.Fatalf("revoked structure %d %s", status, data)
	}

	status, data = request("POST", base(a)+"/messages/content", downloadQuery, tb, "")
	if status != 403 {
		t.Fatalf("revoked stream %d %s", status, data)
	}

	update := v1.Update{Scope: a, AccountInput: accountA.AccountInput, Revision: 2}
	update.Name = "Renamed"
	status, data = request("PUT", base(a), update, ta, "")
	if status != 200 {
		t.Fatalf("rename %d %s", status, data)
	}
	for _, state := range []struct {
		name     string
		revision int64
	}{{"paused", 3}, {"enabled", 4}, {"disconnected", 5}} {
		status, data = request("POST", base(a)+"/state", v1.SetState{Scope: a, Revision: state.revision, State: state.name}, ta, "")
		if status != 200 {
			t.Fatalf("state %d %s", status, data)
		}
		if state.name == "paused" {
			status, data = request("POST", base(a)+"/check", nil, ta, "")
			var out v1.CheckResult
			must(json.Unmarshal(data, &out))
			if status != 200 || out.Status != "paused" {
				t.Fatal("paused check", status)
			}
		}
	}
	status, data = request("PUT", base(a)+"/credentials", original, ta, "credential-"+a.RootID)
	if status != 200 {
		t.Fatalf("historical replay %d %s", status, data)
	}
	status, data = request("GET", base(a), nil, ta, "")
	var disconnected v1.Account
	must(json.Unmarshal(data, &disconnected))
	if status != 200 || disconnected.CredentialReady || disconnected.State != "disconnected" {
		t.Fatal("replay reconnected account")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int64
		must(mailDB.Table("outbox").Where("published_at IS NULL").Count(&n).Error)
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Mail outbox undelivered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	info, e := js.StreamInfo("MAIL")
	must(e)
	if info.State.Msgs != 7 {
		t.Fatal("wrong event count", info.State.Msgs)
	}
	for _, table := range []string{"accounts", "audit", "outbox", "command_results"} {
		var rows []map[string]any
		must(mailDB.Table(table).Find(&rows).Error)
		raw, e := json.Marshal(rows)
		must(e)
		for _, secret := range []string{passwordA, passwordB, passwordC} {
			if bytes.Contains(raw, []byte(secret)) || bytes.Contains(logs.Bytes(), []byte(secret)) {
				t.Fatal("plaintext credential leaked")
			}
		}
	}
	t.Log("PASS: signed Gate/Core/Access/TLS+NKey NATS/JetStream Mail, two users and multiple personal accounts, sealed credentials, real TLS IMAP/folders/message UID windows/MIME structure/private mTLS decoded streams, read-only/revoke, lifecycle/replay and ciphertext-only state")
}

func liveDomainAccess(t *testing.T, ctx context.Context, gateClient, domain identity.Client, session identity.UserSession, ws, source, op string) context.Context {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	audience := strings.Split(source, ".")[0] + "/v1"
	cred, err := gateClient.Credentials("identity.exchange_user")
	must(err)
	incoming, err := identity.Call[identity.UserExchange, identity.TokenResult](ctx, gateClient, "identity.v1.invocations.exchange_user", identity.UserExchange{Assertion: cred.Token, Session: session, Target: identity.Target{Audience: audience, Operation: source, WorkspaceID: ws}})
	must(err)
	outgoing, err := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, domain, "identity.v1.invocations.exchange_service", identity.ServiceExchange{IncomingToken: incoming.Token, IncomingOperation: source, Target: identity.Target{Audience: "access/v1", Operation: "access.v1." + op, WorkspaceID: ws}})
	must(err)
	parts := strings.Split(outgoing.Token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(err)
	var claims security.Claims
	must(json.Unmarshal(raw, &claims))
	return rpc.WithCredentials(ctx, rpc.Credentials{Token: outgoing.Token, IdempotencyKey: uid(), Proof: func(subject string, raw []byte) (security.Proof, error) {
		return security.SignProof(domain.PrivateKey, subject, raw, claims.JTI, security.Proof{Kid: domain.Kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: uid()})
	}})
}

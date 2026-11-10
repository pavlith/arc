package runtime_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/internal/testdb"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	nodeService "github.com/pavlith/arc/services/agent"
	"github.com/pavlith/arc/services/agent/journal"
	"github.com/pavlith/arc/services/core"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func rpcNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// The client reads only its own issued JWT's JTI to construct proof; the server
// independently verifies the complete token, caller key, policy and request.
func invocationCredentials(token, kid string, key ed25519.PrivateKey, nonce string) (rpc.Credentials, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return rpc.Credentials{}, security.ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return rpc.Credentials{}, err
	}
	var claims security.Claims
	if json.Unmarshal(raw, &claims) != nil {
		return rpc.Credentials{}, security.ErrUnauthenticated
	}
	return rpc.Credentials{Token: token, Proof: func(subject string, raw []byte) (security.Proof, error) {
		fresh := nonce
		if fresh == "" {
			fresh = rpcNonce()
		}
		return security.SignProof(key, subject, raw, claims.JTI, security.Proof{Kid: kid, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nonce: fresh})
	}}, nil
}
func signedRules(t *testing.T, key ed25519.PrivateKey, rules []access.Rule) access.Approved {
	t.Helper()
	raw, err := json.Marshal(access.Approval{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return access.Approved{Payload: raw, Signature: ed25519.Sign(key, raw)}
}

func TestRuntimeNodeRPC(t *testing.T) {
	url := os.Getenv("ARC_RUNTIME_NATS_URL")
	if url == "" {
		t.Skip("run python3 scripts/test-runtime.py with nats-server in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	secrets := os.Getenv("ARC_RUNTIME_NATS_SECRETS")
	config := func(seed, name string) sdk.Config {
		cfg := sdk.Config{URL: url, Name: name, NKeySeedFile: filepath.Join(secrets, seed), TLSCAFile: filepath.Join(secrets, "ca.crt")}
		if seed == "nats-smoke-client.seed" {
			cfg.InboxPrefix = "_INBOX.runtime.node-one"
		}
		if seed == "nats-jetstream-admin.seed" {
			cfg.InboxPrefix = "_INBOX.runtime.node-two"
		}
		return cfg
	}
	db, _ := testdb.Open(t, "core")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	newKey := func() ed25519.PrivateKey { _, key, err := ed25519.GenerateKey(rand.Reader); must(err); return key }
	identityKey, approvalKey, snapshotKey := newKey(), newKey(), newKey()
	accounts := []string{"00000000-0000-4000-8000-000000000101", "00000000-0000-4000-8000-000000000102"}
	keys := []ed25519.PrivateKey{newKey(), newKey()}
	kids := []string{"node-key-one", "node-key-two"}
	now := time.Now().UTC()
	must(db.Exec(`INSERT INTO identity_users(id,email) VALUES('admin','admin@example.test')`).Error)
	var rules []access.Rule
	for i, account := range accounts {
		must(db.Exec(`INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES(?,'arc-agent',?)`, account, []string{"one", "two"}[i]).Error)
		must(db.Exec(`INSERT INTO identity_service_credentials(kid,service_account_id,public_key,secret_reference,not_before,expires_at) VALUES(?,?,?,'fixture:node-key',?,?)`, kids[i], account, []byte(keys[i].Public().(ed25519.PublicKey)), now.Add(-time.Minute), now.Add(time.Hour)).Error)
		rules = append(rules, access.Rule{Caller: account, Audience: "identity/v1", Operation: "identity.v1.invocations.exchange_service", ActorKinds: []string{"bootstrap"}})
		for _, op := range []string{agent.OperationInventory, agent.OperationPull, agent.OperationReport} {
			rules = append(rules, access.Rule{Caller: account, Audience: agent.NodeAudience, Operation: op, ActorKinds: []string{"service"}})
		}
	}
	approved := signedRules(t, approvalKey, rules)
	service, err := core.New(core.Config{GormDB: db, NATS: config("nats-echo-service.seed", "runtime-core"), Version: "0.1.0", IdentitySigningKid: "core-test", IdentitySigningKey: identityKey, InstallationApprovalKey: approvalKey.Public().(ed25519.PublicKey), ContractBootstrap: []access.Approved{approved}, SnapshotKid: "core-test", SnapshotSigningKey: identityKey, RouteTrustKey: identityKey, RuntimeAuthorize: func(context.Context, string, string) error { return security.ErrDenied }, RuntimeControlPolicy: &controlPolicy{actor: "user:admin", caller: "forged-local-policy-caller"}, RuntimeSnapshotSigningKey: snapshotKey, RuntimeNodeRPC: true})
	must(err)
	t.Cleanup(func() { _ = service.Stop() })
	must(service.Identity.PublishSigningKey(ctx, now.Add(time.Hour)))
	control := service.Runtime.Control
	for i, node := range []string{"node-one", "node-two"} {
		must(control.RegisterNode(ctx, runtime.NodeRegistration{ID: node, ServiceAccountID: accounts[i], Capabilities: []agent.Kind{agent.Docker}}))
	}
	template := agent.Template{ID: "task", Revision: 1, Kind: agent.Docker, Target: "registry/arc/task@sha256:" + strings.Repeat("a", 64), MaxReplicas: 3}
	must(control.ApproveTemplate(ctx, "node-one", template))
	receipt, err := control.Apply(ctx, change("network-create", 0))
	must(err)
	must(service.Start(ctx))
	connections := make([]*nats.Conn, 2)
	clients := make([]*rpc.Client, 2)
	issuers := make([]identity.Client, 2)
	for i, seed := range []string{"nats-smoke-client.seed", "nats-jetstream-admin.seed"} {
		connections[i], err = sdk.Connect(ctx, config(seed, "runtime-node"))
		must(err)
		t.Cleanup(connections[i].Close)
		clients[i], err = rpc.NewClient(connections[i])
		must(err)
		issuers[i] = identity.Client{RPC: clients[i], ServiceID: accounts[i], Kid: kids[i], PrivateKey: keys[i]}
	}
	issue := func(i int, op string) (rpc.Credentials, error) {
		token, err := identity.Call[identity.ServiceExchange, identity.TokenResult](ctx, issuers[i], "identity.v1.invocations.exchange_service", identity.ServiceExchange{Target: identity.Target{Audience: agent.NodeAudience, Operation: op}})
		if err != nil {
			return rpc.Credentials{}, err
		}
		return invocationCredentials(token.Token, kids[i], keys[i], "")
	}
	client, err := agent.NewNodeClient(clients[0], "node-one", func(_ context.Context, op string) (rpc.Credentials, error) { return issue(0, op) })
	must(err)
	inventory, err := client.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one"})
	must(err)
	if len(inventory.ResourceIDs) != 1 || inventory.ResourceIDs[0] != "task-prod" {
		t.Fatalf("inventory: %+v", inventory)
	}
	pull := agent.PullRequest{NodeID: "node-one", ResourceID: "task-prod", RequestID: "network-request-" + rpcNonce()}
	signed, err := client.Pull(ctx, pull)
	must(err)
	raw, err := json.Marshal(signed)
	must(err)
	store, err := journal.Open(filepath.Join(t.TempDir(), "journal"))
	must(err)
	defer store.Close()
	host := &fakeHost{}
	executor := &agent.Executor{NodeID: "node-one", CoreKey: snapshotKey.Public().(ed25519.PublicKey), Templates: map[string]agent.Template{"task": template}, Drivers: map[agent.Kind]agent.Driver{agent.Docker: host}, Journal: store}
	observed, err := executor.Reconcile(ctx, raw, pull.RequestID)
	must(err)
	report := agent.Report{EventID: "event-network", OperationID: receipt.OperationID, SpecDigest: agent.SpecDigest(receipt.Desired), Status: agent.Succeeded, Observation: observed}
	must(client.Report(ctx, report))
	must(client.Report(ctx, report))
	if host.calls != 1 || countRows(t, db, "runtime_reports") != 1 {
		t.Fatal("network replay duplicated host or receipt")
	}
	op, err := control.Operation(ctx, receipt.OperationID)
	must(err)
	if op.Status != agent.Succeeded {
		t.Fatalf("operation status: %s", op.Status)
	}
	subject, _ := agent.NodeSubject("node-one", agent.OperationInventory)
	call := func(credentials rpc.Credentials, r agent.InventoryRequest) error {
		_, err := rpc.Call[agent.InventoryRequest, agent.InventoryPage](rpc.WithCredentials(ctx, credentials), clients[0], agent.OperationInventory, subject, r)
		return err
	}
	valid, err := issue(0, agent.OperationInventory)
	must(err)
	t.Run("scope_and_proof", func(t *testing.T) {
		_, err := rpc.Call[agent.InventoryRequest, agent.InventoryPage](ctx, clients[0], agent.OperationInventory, subject, agent.InventoryRequest{NodeID: "node-one"})
		if rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("unsigned request accepted: %v", err)
		}
		if err := call(valid, agent.InventoryRequest{NodeID: "node-two"}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("subject/payload mismatch: %v", err)
		}
		replayed, err := invocationCredentials(valid.Token, kids[0], keys[0], rpcNonce())
		must(err)
		must(call(replayed, agent.InventoryRequest{NodeID: "node-one"}))
		if err := call(replayed, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("nonce replay: %v", err)
		}
		wrong, err := invocationCredentials(valid.Token, kids[0], keys[1], "")
		must(err)
		if err := call(wrong, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("wrong proof key: %v", err)
		}
		wrongSubject := valid
		proof := valid.Proof
		wrongSubject.Proof = func(_ string, raw []byte) (security.Proof, error) {
			return proof("ctl.runtime.v1.node.node-two.inventory", raw)
		}
		if err := call(wrongSubject, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("proof subject not bound: %v", err)
		}
		pullCredentials, err := issue(0, agent.OperationPull)
		must(err)
		if err := call(pullCredentials, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("wrong operation token: %v", err)
		}
		// Even a valid caller/key on a transport permitted for node two cannot read it.
		otherSubject, _ := agent.NodeSubject("node-two", agent.OperationInventory)
		_, err = rpc.Call[agent.InventoryRequest, agent.InventoryPage](rpc.WithCredentials(ctx, valid), clients[1], agent.OperationInventory, otherSubject, agent.InventoryRequest{NodeID: "node-two"})
		if rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("foreign node binding: %v", err)
		}
		forged := []byte(`{"request_id":"header-forgery","operation":"runtime.v1.node.inventory","schema_version":1,"deadline_at":"` + time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano) + `","payload":{"node_id":"node-one"}}`)
		msg, err := connections[0].RequestMsgWithContext(ctx, &nats.Msg{Subject: subject, Header: nats.Header{"Arc-Caller": []string{accounts[0]}, "Arc-Actor": []string{"service:" + accounts[0]}}, Data: forged})
		must(err)
		var response struct {
			Error *rpc.Error `json:"error"`
		}
		must(json.Unmarshal(msg.Data, &response))
		if response.Error == nil || response.Error.Code != rpc.CodeUnauthenticated {
			t.Fatal("unverified headers accepted")
		}
	})
	t.Run("service_identity_only", func(t *testing.T) {
		parts := strings.Split(valid.Token, ".")
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		must(err)
		var baseline security.Claims
		must(json.Unmarshal(raw, &baseline))
		for name, mutate := range map[string]func(*security.Claims){
			"different subject":   func(cl *security.Claims) { cl.Subject = "service:" + accounts[1] },
			"workspace scope":     func(cl *security.Claims) { cl.WorkspaceID = "workspace" },
			"upstream invocation": func(cl *security.Claims) { cl.SourceAudience = "task/v1"; cl.SourceOperation = "task.read" },
			"session scope":       func(cl *security.Claims) { cl.SessionID = "unrelated-session" },
			"wrong audience":      func(cl *security.Claims) { cl.Audience = "identity/v1" },
		} {
			t.Run(name, func(t *testing.T) {
				cl := baseline
				mutate(&cl)
				cl.JTI = rpcNonce()
				token, err := security.Sign(identityKey, "core-test", cl)
				must(err)
				creds, err := invocationCredentials(token, kids[0], keys[0], "")
				must(err)
				if err := call(creds, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
					t.Fatalf("non-node invocation accepted: %v", err)
				}
			})
		}
	})
	t.Run("report_and_revocation", func(t *testing.T) {
		conflict := report
		conflict.Status = agent.InProgress
		if err := client.Report(ctx, conflict); rpc.ErrorCode(err) != rpc.CodeConflict {
			t.Fatalf("report payload replay conflict: %v", err)
		}
		creds, err := issue(0, agent.OperationReport)
		must(err)
		creds.IdempotencyKey = "different-event"
		reportSubject, _ := agent.NodeSubject("node-one", agent.OperationReport)
		_, err = rpc.Call[agent.Report, struct{}](rpc.WithCredentials(ctx, creds), clients[0], agent.OperationReport, reportSubject, report)
		if rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatalf("report key not bound to event: %v", err)
		}
		service.Fabric.Bootstrap = []access.Approved{signedRules(t, approvalKey, nil)}
		if err := call(valid, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("live policy revoke: %v", err)
		}
		service.Fabric.Bootstrap = []access.Approved{approved}
		must(db.Exec(`UPDATE identity_service_credentials SET revoked_at=? WHERE service_account_id=?`, time.Now(), accounts[0]).Error)
		if err := call(valid, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("live caller key revoke: %v", err)
		}
		must(db.Exec(`UPDATE identity_service_credentials SET revoked_at=NULL WHERE service_account_id=?`, accounts[0]).Error)
		must(control.DisableNode(ctx, "node-one"))
		if err := call(valid, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("live runtime node disable: %v", err)
		}
	})
	t.Run("nats_subject_permission", func(t *testing.T) {
		permission := make(chan error, 1)
		connections[0].SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case permission <- err:
			default:
			}
		})
		denied, _ := agent.NodeSubject("node-two", agent.OperationInventory)
		must(connections[0].Publish(denied, []byte("{}")))
		must(connections[0].FlushTimeout(time.Second))
		select {
		case err := <-permission:
			if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("foreign publish was not rejected by NATS")
		}
		subscription, err := connections[0].SubscribeSync("_INBOX.runtime.node-two.>")
		if err == nil {
			if subscription != nil {
				defer subscription.Unsubscribe()
			}
			must(connections[0].FlushTimeout(time.Second))
		}
		if err == nil {
			select {
			case err = <-permission:
			case <-time.After(2 * time.Second):
				t.Fatal("foreign reply inbox subscription accepted")
			}
		}
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("foreign reply inbox error: %v", err)
		}

	})
	t.Run("standalone_agent", func(t *testing.T) {
		binary := os.Getenv("ARC_RUNTIME_AGENT_BINARY")
		if binary == "" {
			t.Skip("runtime harness builds cmd/arc-agent")
		}
		directory := t.TempDir()
		keyFile := filepath.Join(directory, "service.seed")
		must(os.WriteFile(keyFile, keys[1].Seed(), 0600))
		rootFile := filepath.Join(directory, "core-public.json")
		public, err := json.Marshal(snapshotKey.Public().(ed25519.PublicKey))
		must(err)
		must(os.WriteFile(rootFile, public, 0600))
		brokerKey := filepath.Join(directory, "nats.seed")
		seed, err := os.ReadFile(filepath.Join(secrets, "nats-jetstream-admin.seed"))
		must(err)
		must(os.WriteFile(brokerKey, seed, 0600))
		cfg := nodeService.FileConfig{NodeID: "node-two", ServiceID: accounts[1], Kid: kids[1], KeyFile: keyFile, CoreSnapshotKeyFile: rootFile, StateDirectory: filepath.Join(directory, "state"), NATS: config("nats-jetstream-admin.seed", "standalone-agent"), PollSeconds: 1}
		cfg.NATS.NKeySeedFile = brokerKey
		configFile := filepath.Join(directory, "agent.json")
		encoded, err := json.Marshal(cfg)
		must(err)
		must(os.WriteFile(configFile, encoded, 0600))
		namespace := "proof:" + accounts[1] + ":" + kids[1]
		nonces := func() int64 {
			var count int64
			must(db.Table("identity_assertion_nonces").Where("namespace=?", namespace).Count(&count).Error)
			return count
		}
		before := nonces()
		command := exec.Command(binary, "-config", configFile)
		var output bytes.Buffer
		command.Stderr = &output
		must(command.Start())
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		defer func() { _ = command.Process.Kill() }()
		timeout := time.After(5 * time.Second)
		connected := false
		for !connected {
			select {
			case err := <-done:
				t.Fatalf("Agent exited before online inventory: %v %s", err, output.String())
			case <-timeout:
				t.Fatal("Agent did not authenticate inventory")
			case <-time.After(10 * time.Millisecond):
				connected = nonces() >= before+2
			}
		}
		must(command.Process.Signal(syscall.SIGTERM))
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Agent SIGTERM/interrupt shutdown: %v %s", err, output.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Agent did not stop")
		}
		reopened, err := journal.Open(cfg.StateDirectory)
		must(err)
		must(reopened.Close())
	})
	t.Run("core_unavailable", func(t *testing.T) {
		must(service.Stop())
		if err := call(valid, agent.InventoryRequest{NodeID: "node-one"}); rpc.ErrorCode(err) != rpc.CodeUnavailable {
			t.Fatalf("Core stop not fail-closed: %v", err)
		}
	})
}

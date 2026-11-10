package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/transport"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
)

func TestCoreProcess(t *testing.T) {
	brokerURL := os.Getenv("ARC_CORE_NATS_URL")
	if brokerURL == "" {
		t.Skip("run make core-smoke with the pinned nats-server in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, operator := bootstrapFixture(t)
	secrets := os.Getenv("ARC_CORE_NATS_SECRETS")
	cfg.NATS.URL = brokerURL
	cfg.NATS.TLSCAFile = filepath.Join(secrets, "ca.crt")
	seed, err := os.ReadFile(filepath.Join(secrets, "nats-echo-service.seed"))
	bootstrapMust(t, err)
	bootstrapMust(t, os.WriteFile(cfg.NATS.NKeySeedFile, seed, 0600))
	clear(seed)
	configFile := filepath.Join(t.TempDir(), "core.json")
	bootstrapJSON(t, configFile, cfg)
	binary := os.Getenv("ARC_CORE_BINARY")

	// The command must refuse an unprovisioned database without creating one.
	command := exec.CommandContext(ctx, binary, "-config", configFile)
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), ErrInvalid.Error()) {
		t.Fatalf("unmigrated startup: %v %s", err, output)
	}
	if _, err := os.Stat(cfg.SQLitePath); !os.IsNotExist(err) {
		t.Fatal("startup created database", err)
	}
	for range 2 {
		output, err := exec.CommandContext(ctx, os.Getenv("ARC_CORE_MIGRATOR"), "-service", "core", "-db", cfg.SQLitePath).CombinedOutput()
		if err != nil {
			t.Fatalf("external migration/replay: %v %s", err, output)
		}
	}
	// Operator fixture provisioning is independent of the running Core process.
	db, err := database.Open(ctx, cfg.SQLitePath)
	bootstrapMust(t, err)
	id := &identity.Core{GormDB: db}
	user, _, err := id.BootstrapUser(ctx, "core-smoke@example.test", "standalone fixture password")
	bootstrapMust(t, err)
	const account = "00000000-0000-4000-8000-000000000001"
	const kid = "standalone-client"
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	bootstrapMust(t, err)
	bootstrapMust(t, db.Exec("INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES(?,'gate','standalone-fixture')", account).Error)
	bootstrapMust(t, db.Exec("INSERT INTO identity_service_credentials(kid,service_account_id,public_key,secret_reference,not_before,expires_at) VALUES(?,?,?,'fixture:gate',?,?)", kid, account, []byte(clientKey.Public().(ed25519.PublicKey)), time.Now().Add(-time.Minute), time.Now().Add(time.Hour)).Error)
	bootstrapMust(t, database.Close(db))
	bootstrapPolicy(t, cfg.ContractBootstrapFiles[0], operator, access.Approval{Rules: []access.Rule{
		{Caller: account, Audience: "identity/v1", Operation: "identity.v1.sessions.login", ActorKinds: []string{"bootstrap"}},
		{Caller: account, Audience: "identity/v1", Operation: "identity.v1.sessions.validate", ActorKinds: []string{"bootstrap"}},
	}})
	observerCfg := sdk.Config{URL: brokerURL, Name: "core-observer", NKeySeedFile: filepath.Join(secrets, "nats-smoke-client.seed"), TLSCAFile: cfg.NATS.TLSCAFile}
	nc, err := sdk.Connect(ctx, observerCfg)
	bootstrapMust(t, err)
	defer nc.Close()
	client, err := rpc.NewClient(nc)
	bootstrapMust(t, err)
	caller := identity.Client{RPC: client, ServiceID: account, Kid: kid, PrivateKey: clientKey}
	readiness := func() bool {
		msg, err := nc.Request("$SRV.INFO.arc-core", nil, 100*time.Millisecond)
		if err != nil {
			return false
		}
		var info transport.Info
		bootstrapMust(t, json.Unmarshal(msg.Data, &info))
		if info.Name != "arc-core" {
			t.Fatal("wrong service identity")
		}
		seen := map[string]bool{}
		for _, endpoint := range info.Endpoints {
			seen[endpoint.Subject] = true
			if strings.Contains(endpoint.Subject, "runtime") || strings.Contains(endpoint.Subject, "bootstrap") {
				t.Fatal("unexpected administrative endpoint", endpoint.Subject)
			}
		}
		return seen["rpc.identity.v1.sessions.login"] && seen["rpc.access.v1.check"] && seen["ctl.arc.fabric.routes"]
	}
	assertStopped := func() {
		t.Helper()
		for _, subject := range []string{"$SRV.INFO.arc-core", "rpc.identity.v1.sessions.login", "rpc.access.v1.check", "ctl.arc.fabric.register"} {
			if _, err := nc.Request(subject, nil, 200*time.Millisecond); !errors.Is(err, nats.ErrNoResponders) {
				t.Fatalf("Core subscription survived shutdown (%s): %v", subject, err)
			}
		}
		if _, err := os.Stat(cfg.SQLitePath + "-wal"); !os.IsNotExist(err) {
			t.Fatal("Core did not close the last SQLite handle", err)
		}
	}
	for pass := range 2 {
		command := exec.CommandContext(ctx, binary, "-config", configFile)
		output, err := os.CreateTemp(t.TempDir(), "core-log")
		bootstrapMust(t, err)
		defer output.Close()
		command.Stdout, command.Stderr = output, output
		bootstrapMust(t, command.Start())
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		t.Cleanup(func() { _ = command.Process.Kill() })
		deadline := time.Now().Add(5 * time.Second)
		for !readiness() {
			select {
			case err := <-done:
				data, _ := os.ReadFile(output.Name())
				t.Fatalf("Core exited before readiness: %v %s", err, data)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("Core readiness timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
		login, err := identity.Call[identity.LoginRequest, identity.LoginResult](ctx, caller, "identity.v1.sessions.login", identity.LoginRequest{Email: "core-smoke@example.test", Password: "standalone fixture password"})
		bootstrapMust(t, err)
		if login.Session.UserID != user || login.AccessToken == "" {
			t.Fatal("real Identity login did not produce the expected session")
		}
		_, err = rpc.Call[identity.Empty, identity.Empty](ctx, client, "access.v1.check", "rpc.access.v1.check", identity.Empty{})
		if rpc.ErrorCode(err) != rpc.CodeUnauthenticated {
			t.Fatalf("unsigned Access request: %v", err)
		}
		_, err = identity.Call[identity.Empty, identity.Empty](ctx, caller, "identity.v1.sessions.logout", identity.Empty{})
		if rpc.ErrorCode(err) != rpc.CodePermissionDenied {
			t.Fatalf("operation outside signed approval: %v", err)
		}
		if _, err := nc.Request("ctl.runtime.v1.node.unapproved.inventory", nil, 200*time.Millisecond); !errors.Is(err, nats.ErrNoResponders) {
			t.Fatal("Runtime node protocol enabled without a live policy", err)
		}
		bootstrapMust(t, command.Process.Signal(syscall.SIGTERM))
		select {
		case err := <-done:
			bootstrapMust(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("Core SIGTERM timeout")
		}
		assertStopped()
		t.Logf("standalone Core start/login/denials/SIGTERM pass %d succeeded", pass+1)
	}
	// A valid broker identity without Core subscriptions must not leave a partial
	// service behind after module/monitoring binding fails.
	broken := cfg
	broken.NATS.NKeySeedFile = filepath.Join(t.TempDir(), "restricted-nats.seed")
	seed, err = os.ReadFile(observerCfg.NKeySeedFile)
	bootstrapMust(t, err)
	bootstrapMust(t, os.WriteFile(broken.NATS.NKeySeedFile, seed, 0600))
	clear(seed)
	brokenConfig := filepath.Join(t.TempDir(), "restricted-core.json")
	bootstrapJSON(t, brokenConfig, broken)
	output, err := exec.CommandContext(ctx, binary, "-config", brokenConfig).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "core: private NATS startup failed") {
		t.Fatalf("broker permission failure: %v %s", err, output)
	}
	assertStopped()
	// An in-process cancellation checks explicit cleanup independently of OS exit.
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Run(runCtx, configFile) }()
	deadline := time.Now().Add(5 * time.Second)
	for !readiness() {
		select {
		case err := <-done:
			t.Fatal("in-process startup failed", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("in-process readiness timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	select {
	case err := <-done:
		bootstrapMust(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("in-process Core did not stop")
	}
	assertStopped()
	db, err = database.Open(ctx, cfg.SQLitePath)
	bootstrapMust(t, err)
	defer database.Close(db)
	var count int64
	bootstrapMust(t, db.Table("identity_audit").Where("operation=?", "signing_keys.publish").Count(&count).Error)
	if count != 1 {
		t.Fatal("restart changed signing metadata", count)
	}
}

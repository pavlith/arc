package core_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	"github.com/pavlith/arc/internal/testdb"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func TestCoreWiringAndFailClosedConfiguration(t *testing.T) {
	if _, err := core.New(core.Config{}); !errors.Is(err, core.ErrInvalid) {
		t.Fatal("missing trust inputs accepted", err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := testdb.Open(t, "core")
	cfg := core.Config{
		GormDB: db, Version: "0.1.0", IdentitySigningKid: "identity-test",
		IdentitySigningKey: key, InstallationApprovalKey: pub,
		SnapshotKid: "snapshot-test", SnapshotSigningKey: key,
		RouteTrustKey:    key,
		RuntimeAuthorize: func(context.Context, string, string) error { return security.ErrDenied },
	}
	s, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Modules(), []string{"identity", "access", "fabric", "runtime"}) {
		t.Fatal("Core modules", s.Modules())
	}
	if s.Identity.Policy != s.Access || s.Access.ContractSource != s.Fabric || s.Fabric.Identity != s.Identity {
		t.Fatal("Core direct interface wiring is incorrect")
	}
	if s.Runtime.Control != nil || s.Runtime.NodeVerifier != nil {
		t.Fatal("Runtime control enabled without explicit policy")
	}
	cfg.RuntimeNodeRPC = true
	if _, err := core.New(cfg); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("node RPC enabled without Control trust: %v", err)
	}
	cfg.RuntimeNodeRPC = false
	cfg.RuntimeSnapshotSigningKey = key
	if _, err := core.New(cfg); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("partial Runtime trust configuration accepted: %v", err)
	}
	cfg.RuntimeControlPolicy = denyControlPolicy{}
	enabled, err := core.New(cfg)
	if err != nil || enabled.Runtime.Control == nil {
		t.Fatalf("explicit Runtime configuration failed: %v", err)
	}
	if _, err := enabled.Runtime.Control.Nodes(context.Background(), ""); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("Runtime policy bypassed: %v", err)
	}
	cfg.RuntimeNodeRPC = true
	network, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if network.Runtime.NodeVerifier == nil || network.Runtime.NodeVerifier.Keys != network.Identity || network.Runtime.NodeVerifier.State != network.Identity || network.Runtime.NodeVerifier.Nonces != network.Identity {
		t.Fatal("node RPC is not wired to actual Core Identity")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
}

var _ runtime.ControlPolicy = denyControlPolicy{}

type denyControlPolicy struct{}

func (denyControlPolicy) Manager(context.Context) (string, error) { return "", security.ErrDenied }
func (denyControlPolicy) Node(context.Context) (string, error)    { return "", security.ErrDenied }

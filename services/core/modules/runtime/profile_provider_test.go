package runtime_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func TestCoreProfilePullRequiresApprovedNodeAndCurrentHost(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	profile := managedNodeProfile()
	if err := f.control.ApproveNodeProfile(ctx, "node-one", profile); err != nil {
		t.Fatal(err)
	}
	request := agent.ProfilePlanRequest{
		NodeID: "node-one", ProfileID: profile.ID, Revision: profile.Revision,
		RequestID: "pull-profile-1234567890",
	}
	if _, err := f.control.PullProfile(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("profile returned without verified host facts: %v", err)
	}
	facts := agent.HostFacts{
		OS: "ubuntu", Version: "24.04", Architecture: "amd64",
		Kernel: "6.8.0-generic", CPUThreads: 2,
		MemoryBytes: 4 << 30, RootTotal: 10 << 30,
		RootAvailable: 5 << 30, APT: true,
	}
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", Host: &facts}); err != nil {
		t.Fatal(err)
	}
	signed, err := f.control.PullProfile(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	got, err := agent.VerifyProfilePlan(raw, f.pub, "node-one", request.RequestID, f.now)
	if err != nil || agent.NodeProfileDigest(got.Profile) != agent.NodeProfileDigest(profile) {
		t.Fatalf("invalid signed approved profile: %+v %v", got, err)
	}
	f.policy.caller = "other-sa"
	if _, err := f.control.PullProfile(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("other node obtained profile: %v", err)
	}
	f.policy.caller = "node-sa"
	facts.Version = "22.04"
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", Host: &facts}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.PullProfile(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("unsupported host release obtained a plan: %v", err)
	}
	facts.Version = "24.04"
	if _, err := f.control.Inventory(ctx, agent.InventoryRequest{NodeID: "node-one", Host: &facts}); err != nil {
		t.Fatal(err)
	}
	if err := f.control.RevokeNodeProfile(ctx, "node-one", profile.ID, profile.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := f.control.PullProfile(ctx, request); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("revoked version obtained a plan: %v", err)
	}
	invalid := request
	invalid.Revision = 0
	if _, err := f.control.PullProfile(ctx, invalid); !errors.Is(err, runtime.ErrInvalid) {
		t.Fatalf("bad revision accepted: %v", err)
	}
}

package apt

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/pavlith/arc/sdk/agent"
)

func TestPinnedUbuntuProfilePlansWithoutEffects(t *testing.T) {
	var calls int
	manager := &Manager{run: func(_ context.Context, binary string, args ...string) ([]byte, error) {
		calls++
		if binary != "/usr/bin/apt-get" || !slices.Contains(args, "-s") || !slices.Contains(args, "--") ||
			!slices.Contains(args, "curl=8.5.0-2ubuntu10.6") ||
			!slices.Contains(args, "git=1:2.43.0-1ubuntu7.3") {
			t.Fatalf("unexpected package planner argv: %s %v", binary, args)
		}
		return []byte("Inst git [old] (1:2.43.0-1ubuntu7.3 Ubuntu:24.04)\n"), nil
	}}
	profile := agent.NodeProfile{
		ID: "standard", Revision: 1, Ubuntu: []string{"24.04", "26.04"},
		Packages: []agent.PackagePin{
			{Name: "curl", Version: "8.5.0-2ubuntu10.6"},
			{Name: "git", Version: "1:2.43.0-1ubuntu7.3"},
		},
		Updates: agent.UpdatePolicy{Security: "manual", Packages: "manual", Reboot: "manual"},
	}
	host := agent.HostFacts{
		OS: "ubuntu", Version: "24.04", Architecture: "amd64",
		Kernel: "6.8.0-57-generic", CPUThreads: 4, MemoryBytes: 4 << 30,
		RootTotal: 10 << 30, RootAvailable: 5 << 30, APT: true,
	}
	plan, err := manager.PlanProfilePackages(context.Background(), profile, host)
	if err != nil || plan.ProfileDigest != agent.NodeProfileDigest(profile) ||
		len(plan.Plan.Install) != 1 || plan.Plan.Install[0] != "git" || calls != 1 {
		t.Fatalf("profile plan failed: %+v, %v, calls=%d", plan, err, calls)
	}
	unsupported := host
	unsupported.Version = "22.04"
	if _, err := manager.PlanProfilePackages(context.Background(), profile, unsupported); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported Ubuntu accepted: %v", err)
	}
	unsupported = host
	unsupported.APT = false
	if _, err := manager.PlanProfilePackages(context.Background(), profile, unsupported); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing APT accepted: %v", err)
	}
	invalid := profile
	invalid.Revision = 0
	if _, err := manager.PlanProfilePackages(context.Background(), invalid, host); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid profile accepted: %v", err)
	}
	if calls != 1 {
		t.Fatal("invalid profiles invoked apt-get")
	}
}

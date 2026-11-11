package apt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

type previewIssuer struct {
	key ed25519.PrivateKey
	profile agent.NodeProfile
	wrongNode bool
	issued int
}

func (p *previewIssuer) PullProfile(_ context.Context, req agent.ProfilePlanRequest) (agent.SignedProfilePlan, error) {
	p.issued++
	if len(req.RequestID) < 16 || req.ProfileID != p.profile.ID || req.Revision != p.profile.Revision {
		return agent.SignedProfilePlan{}, agent.ErrInvalid
	}
	node := req.NodeID
	if p.wrongNode {
		node = "node-two"
	}
	now := time.Now().Unix()
	return agent.SignProfilePlan(agent.ProfilePlanSnapshot{
		Version: 1, NodeID: node, RequestID: req.RequestID,
		IssuedAt: now, ExpiresAt: now + 30, Profile: p.profile,
	}, p.key)
}

func TestPreviewApprovedProfileEnforcesCoreTrustAndOnlySimulates(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &previewIssuer{
		key: private,
		profile: agent.NodeProfile{
			ID: "standard", Revision: 1, Ubuntu: []string{"24.04"},
			Packages: []agent.PackagePin{{Name: "curl", Version: "8.5.0-2ubuntu10.6"}},
			Updates: agent.UpdatePolicy{Security: "manual", Packages: "manual", Reboot: "manual"},
		},
	}
	facts := agent.HostFacts{
		OS: "ubuntu", Version: "24.04", Architecture: "amd64",
		Kernel: "6.8.0-generic", CPUThreads: 2,
		MemoryBytes: 4 << 30, RootTotal: 10 << 30,
		RootAvailable: 5 << 30, APT: true,
	}
	var simulations int
	m := &Manager{run: func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
		simulations++
		if cmd != "/usr/bin/apt-get" || !slices.Contains(args, "-s") ||
			!slices.Contains(args, "curl=8.5.0-2ubuntu10.6") {
			t.Fatalf("unapproved APT command: %s %v", cmd, args)
		}
		return []byte("Inst curl [old] (8.5.0-2ubuntu10.6 Ubuntu:24.04)\n"), nil
	}}
	plan, err := m.PreviewApprovedProfile(context.Background(), p, public, "node-one", "standard", 1, facts)
	if err != nil || plan.ProfileDigest != agent.NodeProfileDigest(p.profile) ||
		len(plan.Plan.Install) != 1 || simulations != 1 {
		t.Fatalf("valid profile preview failed: %+v err=%v simulations=%d", plan, err, simulations)
	}
	p.wrongNode = true
	if _, err := m.PreviewApprovedProfile(context.Background(), p, public, "node-one", "standard", 1, facts); !errors.Is(err, agent.ErrInvalid) {
		t.Fatalf("cross-node preview accepted: %v", err)
	}
	p.wrongNode = false
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.PreviewApprovedProfile(context.Background(), p, other, "node-one", "standard", 1, facts); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("unknown signer accepted: %v", err)
	}
	facts.Version = "22.04"
	if _, err := m.PreviewApprovedProfile(context.Background(), p, public, "node-one", "standard", 1, facts); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported Ubuntu preview accepted: %v", err)
	}
	if simulations != 1 {
		t.Fatal("denied previews still executed APT")
	}
}

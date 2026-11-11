package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
)

func TestSignedProfilePlanBoundToNodeRequestAndTime(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	request := "profile-pull-1234567890"
	profile := agent.NodeProfile{
		ID: "standard", Revision: 1, Ubuntu: []string{"24.04"},
		Packages: []agent.PackagePin{{Name: "curl", Version: "8.5.0-2ubuntu10.6"}},
		Updates:  agent.UpdatePolicy{Security: "manual", Packages: "manual", Reboot: "manual"},
	}
	snapshot := agent.ProfilePlanSnapshot{
		Version: 1, NodeID: "node-one", RequestID: request,
		IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 30, Profile: profile,
	}
	signed, err := agent.SignProfilePlan(snapshot, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(signed)
	got, err := agent.VerifyProfilePlan(raw, public, "node-one", request, now)
	if err != nil || agent.NodeProfileDigest(got.Profile) != agent.NodeProfileDigest(profile) {
		t.Fatalf("signed plan rejected: %+v %v", got, err)
	}
	for _, tc := range []struct {
		name, node, request string
		now                 time.Time
	}{
		{"cross-node", "node-two", request, now},
		{"replay-request", "node-one", "different-pull-1234567", now},
		{"expired", "node-one", request, now.Add(30 * time.Second)},
		{"not-yet-issued", "node-one", request, now.Add(-time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := agent.VerifyProfilePlan(raw, public, tc.node, tc.request, tc.now); !errors.Is(err, agent.ErrInvalid) {
				t.Fatalf("invalid plan accepted: %v", err)
			}
		})
	}
	modified := signed
	modified.Signature = "invalid"
	forged, _ := json.Marshal(modified)
	if _, err := agent.VerifyProfilePlan(forged, public, "node-one", request, now); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("forged signature accepted: %v", err)
	}
	tampered := signed
	tampered.Payload = json.RawMessage(`{"version":1,"node_id":"node-two"}`)
	forged, _ = json.Marshal(tampered)
	if _, err := agent.VerifyProfilePlan(forged, public, "node-one", request, now); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatalf("tampered profile accepted: %v", err)
	}
	tooLong := snapshot
	tooLong.ExpiresAt++
	if _, err := agent.SignProfilePlan(tooLong, key); !errors.Is(err, agent.ErrInvalid) {
		t.Fatalf("long-lived plan signed: %v", err)
	}
	invalid := snapshot
	invalid.Profile.Revision = 0
	if _, err := agent.SignProfilePlan(invalid, key); !errors.Is(err, agent.ErrInvalid) {
		t.Fatalf("invalid profile signed: %v", err)
	}
}

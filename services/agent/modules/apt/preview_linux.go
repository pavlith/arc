package apt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/agent"
)

// PreviewApprovedProfile requests an immutable, administrator-approved profile
// from Core over the node's authenticated connection. Signature, expiry and
// request binding are verified before any local APT simulation can begin.
// There are no mutating package operations on this path.
func (m *Manager) PreviewApprovedProfile(
	ctx context.Context, provider agent.ProfilePlanProvider, coreKey ed25519.PublicKey,
	node, profileID string, revision int64, host agent.HostFacts,
) (ProfilePackagePlan, error) {
	if ctx == nil || m == nil || provider == nil || len(coreKey) != ed25519.PublicKeySize ||
		!agent.ValidID(node) || !agent.ValidID(profileID) ||
		revision < 1 || revision > 1<<53-1 || host.Validate() != nil {
		return ProfilePackagePlan{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ProfilePackagePlan{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ProfilePackagePlan{}, ErrUnavailable
	}
	request := agent.ProfilePlanRequest{
		NodeID: node, ProfileID: profileID, Revision: revision,
		RequestID: "profile-" + hex.EncodeToString(nonce[:]),
	}
	signed, err := provider.PullProfile(ctx, request)
	if err != nil {
		return ProfilePackagePlan{}, err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return ProfilePackagePlan{}, ErrUnavailable
	}
	snapshot, err := agent.VerifyProfilePlan(raw, coreKey, node, request.RequestID, time.Now())
	if err != nil {
		return ProfilePackagePlan{}, err
	}
	if snapshot.Profile.ID != profileID || snapshot.Profile.Revision != revision {
		return ProfilePackagePlan{}, ErrInvalid
	}
	return m.PlanProfilePackages(ctx, snapshot.Profile, host)
}

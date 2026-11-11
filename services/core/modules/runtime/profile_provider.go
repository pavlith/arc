package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
)

// PullProfile returns an administrator-approved, signed read-only plan input
// to the authenticated node. It cannot issue permission for package changes.
func (c *Control) PullProfile(ctx context.Context, request agent.ProfilePlanRequest) (agent.SignedProfilePlan, error) {
	var out agent.SignedProfilePlan
	if !agent.ValidID(request.NodeID) || !agent.ValidID(request.ProfileID) ||
		request.Revision < 1 || request.Revision > 1<<53-1 ||
		len(request.RequestID) < 16 || len(request.RequestID) > 128 {
		return out, ErrInvalid
	}
	caller, err := c.nodeCaller(ctx)
	if err != nil {
		return out, err
	}
	err = c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		node, err := activeNode(tx, request.NodeID, caller)
		if err != nil {
			return err
		}
		if node.HostInventory == nil {
			return security.ErrDenied
		}
		var facts agent.HostFacts
		if json.Unmarshal([]byte(*node.HostInventory), &facts) != nil || facts.Validate() != nil {
			return security.ErrUnavailable
		}
		var row models.RuntimeNodeProfile
		if err := tx.Where("node_id=? AND id=? AND revision=? AND revoked=0",
			request.NodeID, request.ProfileID, request.Revision).Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return security.ErrDenied
			}
			return err
		}
		var profile agent.NodeProfile
		if json.Unmarshal([]byte(row.Spec), &profile) != nil || profile.Validate() != nil ||
			profile.ID != row.ID || profile.Revision != row.Revision ||
			agent.NodeProfileDigest(profile) != row.Digest {
			return security.ErrUnavailable
		}
		if facts.OS != "ubuntu" || !slices.Contains(profile.Ubuntu, facts.Version) || !facts.APT {
			return security.ErrDenied
		}
		now := c.now().Unix()
		out, err = agent.SignProfilePlan(agent.ProfilePlanSnapshot{
			Version: 1, NodeID: request.NodeID, RequestID: request.RequestID,
			IssuedAt: now, ExpiresAt: now + 30, Profile: profile,
		}, c.signingKey)
		return err
	})
	return out, mapped(err)
}

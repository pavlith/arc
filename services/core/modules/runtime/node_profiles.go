package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
)

// StoredNodeProfile is an administrator-approved declaration, never an
// execution authorization. Host agents cannot fetch it through node RPC.
type StoredNodeProfile struct {
	NodeID    string            `json:"node_id"`
	Profile   agent.NodeProfile `json:"profile"`
	Digest    string            `json:"digest"`
	Revoked   bool              `json:"revoked"`
	CreatedAt time.Time         `json:"created_at"`
}

// ApproveNodeProfile creates immutable, strictly consecutive versions. An
// identical retry is a no-op; changed or revoked versions never reactivate.
func (c *Control) ApproveNodeProfile(ctx context.Context, node string, profile agent.NodeProfile) error {
	if !agent.ValidID(node) || profile.Validate() != nil {
		return ErrInvalid
	}
	raw, err := canonical(profile)
	if err != nil {
		return err
	}
	checksum := agent.NodeProfileDigest(profile)
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		if _, err := activeNode(tx, node, ""); err != nil {
			return err
		}
		var latest int64
		if err := tx.Raw("SELECT COALESCE(MAX(revision),0) FROM runtime_node_profiles WHERE node_id=? AND id=?", node, profile.ID).Scan(&latest).Error; err != nil {
			return err
		}
		if profile.Revision <= latest {
			var stored models.RuntimeNodeProfile
			err := tx.Where("node_id=? AND id=? AND revision=?", node, profile.ID, profile.Revision).Take(&stored).Error
			if err != nil || stored.Spec != raw || stored.Digest != checksum || stored.Revoked {
				return ErrConflict
			}
			return nil
		}
		if profile.Revision != latest+1 {
			return ErrConflict
		}
		row := models.RuntimeNodeProfile{
			NodeID: node, ID: profile.ID, Revision: profile.Revision,
			Spec: raw, Digest: checksum, ApprovedBy: actor,
			CreatedAt: c.now().UTC(),
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return audit(tx, actor, "node.profile.approve", node+"/"+profile.ID, "", c.now().UTC())
	})
}

// RevokeNodeProfile is irreversible for a particular revision, including
// when later versions exist. It does not retroactively undo host operations.
func (c *Control) RevokeNodeProfile(ctx context.Context, node, id string, revision int64) error {
	if !agent.ValidID(node) || !agent.ValidID(id) || revision < 1 || revision > 1<<53-1 {
		return ErrInvalid
	}
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var row models.RuntimeNodeProfile
		if err := tx.Where("node_id=? AND id=? AND revision=?", node, id, revision).Take(&row).Error; err != nil {
			return err
		}
		if row.Revoked {
			return nil
		}
		if err := tx.Model(&row).Update("revoked", true).Error; err != nil {
			return err
		}
		return audit(tx, actor, "node.profile.revoke", node+"/"+id, "", c.now().UTC())
	})
}

// NodeProfile reads approved history for an authenticated infrastructure
// manager, including revocation status. It does not expose an apply endpoint.
func (c *Control) NodeProfile(ctx context.Context, node, id string, revision int64) (StoredNodeProfile, error) {
	if !agent.ValidID(node) || !agent.ValidID(id) || revision < 1 || revision > 1<<53-1 {
		return StoredNodeProfile{}, ErrInvalid
	}
	db, err := c.readable(ctx)
	if err != nil {
		return StoredNodeProfile{}, err
	}
	var row models.RuntimeNodeProfile
	if err := db.Where("node_id=? AND id=? AND revision=?", node, id, revision).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return StoredNodeProfile{}, sql.ErrNoRows
		}
		return StoredNodeProfile{}, security.ErrUnavailable
	}
	var profile agent.NodeProfile
	if json.Unmarshal([]byte(row.Spec), &profile) != nil || profile.Validate() != nil ||
		profile.ID != id || profile.Revision != revision || agent.NodeProfileDigest(profile) != row.Digest {
		return StoredNodeProfile{}, security.ErrUnavailable
	}
	return StoredNodeProfile{NodeID: node, Profile: profile, Digest: row.Digest, Revoked: row.Revoked, CreatedAt: row.CreatedAt}, nil
}

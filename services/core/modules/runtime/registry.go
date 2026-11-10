package runtime

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type NodeRegistration struct {
	ID               string       `json:"id"`
	ServiceAccountID string       `json:"service_account_id"`
	Capabilities     []agent.Kind `json:"capabilities"`
}

type Node struct {
	ID               string       `json:"id"`
	ServiceAccountID string       `json:"service_account_id"`
	Capabilities     []agent.Kind `json:"capabilities"`
	Active           bool         `json:"active"`
	LastSeenAt       *time.Time   `json:"last_seen_at,omitempty"`
	Host             *agent.HostFacts `json:"host,omitempty"`
}

// RegisterNode binds one service account to one node permanently. Identical
// registrations are idempotent; a disabled node is never silently reactivated.
func (c *Control) RegisterNode(ctx context.Context, node NodeRegistration) error {
	if !agent.ValidID(node.ID) || node.ServiceAccountID == "" || len(node.ServiceAccountID) > 128 || len(node.Capabilities) == 0 || len(node.Capabilities) > 3 {
		return ErrInvalid
	}
	caps := append([]agent.Kind(nil), node.Capabilities...)
	sort.Slice(caps, func(i, j int) bool { return caps[i] < caps[j] })
	for i, kind := range caps {
		if kind != agent.Docker && kind != agent.LXD && kind != agent.Systemd {
			return ErrInvalid
		}
		if i > 0 && kind == caps[i-1] {
			return ErrInvalid
		}
	}
	raw, _ := canonical(caps)
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var count int64
		if err := tx.Table("identity_service_accounts").Where("id=? AND disabled_at IS NULL AND service_definition='arc-agent'", node.ServiceAccountID).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return security.ErrDenied
		}
		row := models.RuntimeNode{ID: node.ID, ServiceAccountID: node.ServiceAccountID, Capabilities: raw, Active: true, CreatedAt: c.now().UTC()}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			var stored models.RuntimeNode
			if err := tx.Where("id=?", node.ID).Take(&stored).Error; err != nil {
				return ErrConflict
			}
			if stored.ServiceAccountID != row.ServiceAccountID || stored.Capabilities != raw || !stored.Active {
				return ErrConflict
			}
			return nil
		}
		return audit(tx, actor, "node.register", node.ID, "", c.now().UTC())
	})
}
func (c *Control) DisableNode(ctx context.Context, id string) error {
	if !agent.ValidID(id) {
		return ErrInvalid
	}
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var row models.RuntimeNode
		if err := tx.Where("id=?", id).Take(&row).Error; err != nil {
			return err
		}
		if !row.Active {
			return nil
		}
		if err := tx.Model(&row).Update("active", false).Error; err != nil {
			return err
		}
		return audit(tx, actor, "node.disable", id, "", c.now().UTC())
	})
}
func (c *Control) ApproveTemplate(ctx context.Context, node string, t agent.Template) error {
	if !agent.ValidID(node) || t.Validate() != nil {
		return ErrInvalid
	}
	raw, _ := canonical(t)
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		n, err := activeNode(tx, node, "")
		if err != nil {
			return err
		}
		var caps []agent.Kind
		if json.Unmarshal([]byte(n.Capabilities), &caps) != nil {
			return security.ErrUnavailable
		}
		supported := false
		for _, kind := range caps {
			if t.Kind == kind {
				supported = true
			}
		}
		if !supported {
			return security.ErrDenied
		}
		row := models.RuntimeTemplate{NodeID: node, ID: t.ID, Revision: t.Revision, Spec: raw, CreatedAt: c.now().UTC()}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			var stored models.RuntimeTemplate
			if err := tx.Where("node_id=? AND id=? AND revision=?", node, t.ID, t.Revision).Take(&stored).Error; err != nil {
				return err
			}
			if stored.Spec != raw || stored.Revoked {
				return ErrConflict
			}
			return nil
		}
		return audit(tx, actor, "template.approve", node+"/"+t.ID, "", c.now().UTC())
	})
}
func (c *Control) RevokeTemplate(ctx context.Context, node, id string, revision int64) error {
	if !agent.ValidID(node) || !agent.ValidID(id) || revision < 1 || revision > 1<<53-1 {
		return ErrInvalid
	}
	return c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var row models.RuntimeTemplate
		if err := tx.Where("node_id=? AND id=? AND revision=?", node, id, revision).Take(&row).Error; err != nil {
			return err
		}
		if row.Revoked {
			return nil
		}
		if err := tx.Model(&row).Update("revoked", true).Error; err != nil {
			return err
		}
		return audit(tx, actor, "template.revoke", node+"/"+id, "", c.now().UTC())
	})
}

// Nodes returns a bounded page ordered by stable ID; after is an exclusive cursor.
func (c *Control) Nodes(ctx context.Context, after string) ([]Node, error) {
	if after != "" && !agent.ValidID(after) {
		return nil, ErrInvalid
	}
	db, err := c.readable(ctx)
	if err != nil {
		return nil, err
	}
	var rows []models.RuntimeNode
	if err = db.Where("id>?", after).Order("id").Limit(100).Find(&rows).Error; err != nil {
		return nil, mapped(err)
	}
	out := make([]Node, 0, len(rows))
	for _, row := range rows {
		var caps []agent.Kind
		if json.Unmarshal([]byte(row.Capabilities), &caps) != nil {
			return nil, security.ErrUnavailable
		}
		node := Node{ID: row.ID, ServiceAccountID: row.ServiceAccountID, Capabilities: caps, Active: row.Active, LastSeenAt: row.LastSeenAt}
		if row.HostInventory != nil {
			var facts agent.HostFacts
			if json.Unmarshal([]byte(*row.HostInventory), &facts) != nil || facts.Validate() != nil {
				return nil, security.ErrUnavailable
			}
			node.Host = &facts
		}
		out = append(out, node)
	}
	return out, nil
}

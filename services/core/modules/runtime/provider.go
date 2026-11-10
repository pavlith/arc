package runtime

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
)

var _ agent.RuntimeProvider = (*Control)(nil)

func (c *Control) nodeCaller(ctx context.Context) (string, error) {
	if c == nil || c.db == nil || c.policy == nil {
		return "", security.ErrUnavailable
	}
	caller, err := c.policy.Node(ctx)
	if err != nil {
		return "", err
	}
	if caller == "" {
		return "", security.ErrUnauthenticated
	}
	return caller, nil
}
func (c *Control) Inventory(ctx context.Context, request agent.InventoryRequest) (agent.InventoryPage, error) {
	out := agent.InventoryPage{ResourceIDs: []string{}}
	if !agent.ValidID(request.NodeID) || (request.AfterID != "" && !agent.ValidID(request.AfterID)) {
		return out, ErrInvalid
	}
	caller, err := c.nodeCaller(ctx)
	if err != nil {
		return out, err
	}
	err = database.RetryBusy(ctx, func() error {
		return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := activeNode(tx, request.NodeID, caller); err != nil {
			return err
		}
		var ids []string
		if err := tx.Model(&models.RuntimeResource{}).Where("node_id=? AND id>?", request.NodeID, request.AfterID).Order("id").Limit(101).Pluck("id", &ids).Error; err != nil {
			return err
		}
		if len(ids) > 100 {
			ids = ids[:100]
			out.NextID = ids[99]
		}
		out.ResourceIDs = append(out.ResourceIDs, ids...)
		// Inventory authenticates the node on every round. Refresh node liveness
		// at most once per minute, without one audit/receipt per resource.
		now := c.now().UTC()
		if err := tx.Model(&models.RuntimeNode{}).
			Where("id=? AND active=1 AND (last_seen_at IS NULL OR last_seen_at<?)", request.NodeID, now.Add(-time.Minute)).
			Update("last_seen_at", now).Error; err != nil {
			return err
		}
		return nil
		})
	})
	if err != nil {
		return agent.InventoryPage{}, mapped(err)
	}
	return out, nil
}

func (c *Control) Pull(ctx context.Context, request agent.PullRequest) (agent.SignedSnapshot, error) {
	var out agent.SignedSnapshot
	if !agent.ValidID(request.NodeID) || !agent.ValidID(request.ResourceID) || len(request.RequestID) < 16 || len(request.RequestID) > 128 {
		return out, ErrInvalid
	}
	caller, err := c.nodeCaller(ctx)
	if err != nil {
		return out, err
	}
	err = c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := activeNode(tx, request.NodeID, caller); err != nil {
			return err
		}
		var row models.RuntimeResource
		if err := tx.Where("id=? AND node_id=?", request.ResourceID, request.NodeID).Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return security.ErrDenied
			}
			return err
		}
		template, err := approvedTemplate(tx, row.NodeID, row.TemplateID, row.TemplateRevision)
		if err != nil {
			return err
		}
		view, err := resourceSpec(row)
		if err != nil || view.Validate(template, row.NodeID) != nil {
			return security.ErrUnavailable
		}
		var operation models.RuntimeOperation
		if err := tx.Where("id=?", row.OperationID).Take(&operation).Error; err != nil {
			return err
		}
		if operation.Status == string(agent.Failed) || operation.Status == string(agent.Cancelled) {
			return ErrConflict
		}
		now := c.now().Unix()
		out, err = agent.Sign(agent.Snapshot{Version: 1, RequestID: request.RequestID, OperationID: row.OperationID, IssuedAt: now, ExpiresAt: now + 30, Spec: view}, c.signingKey)
		return err
	})
	return out, mapped(err)
}

func (c *Control) Report(ctx context.Context, report agent.Report) error {
	obs := report.Observation
	if !agent.ValidID(report.EventID) || !agent.ValidID(report.OperationID) || !agent.ValidID(obs.NodeID) || !agent.ValidID(obs.ResourceID) || obs.Revision < 1 || obs.Revision > 1<<53-1 || obs.Running < 0 || obs.Running > 100 {
		return ErrInvalid
	}
	switch report.Status {
	case agent.InProgress, agent.Succeeded:
		if report.ErrorCode != "" {
			return ErrInvalid
		}
	case agent.Failed:
		switch report.ErrorCode {
		case "DRIVER_UNAVAILABLE", "DRIVER_FAILED", "POLICY_DENIED", "NOT_READY":
		default:
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	caller, err := c.nodeCaller(ctx)
	if err != nil {
		return err
	}
	raw, err := canonical(report)
	if err != nil {
		return err
	}
	hash := digest(raw)
	return mapped(database.RetryBusy(ctx, func() error {
		return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if _, err := activeNode(tx, obs.NodeID, caller); err != nil {
				return err
			}
			var receipt struct{ Digest string }
			err := tx.Table("runtime_reports").Where("node_id=? AND event_id=?", obs.NodeID, report.EventID).Take(&receipt).Error
			if err == nil {
				if receipt.Digest != hash {
					return ErrConflict
				}
				return nil
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			var row models.RuntimeResource
			if err := tx.Where("id=? AND node_id=?", obs.ResourceID, obs.NodeID).Take(&row).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return security.ErrDenied
				}
				return err
			}
			if row.Revision != obs.Revision || row.OperationID != report.OperationID {
				return ErrConflict
			}
			// Revocation blocks new observations as well as new execution snapshots.
			template, err := approvedTemplate(tx, row.NodeID, row.TemplateID, row.TemplateRevision)
			if err != nil {
				return err
			}
			spec, err := resourceSpec(row)
			if err != nil || spec.Validate(template, row.NodeID) != nil {
				return security.ErrUnavailable
			}
			if report.SpecDigest != agent.SpecDigest(spec) || obs.State != spec.State || obs.Running > spec.Replicas {
				return ErrInvalid
			}
			if report.Status == agent.Succeeded && obs.Running != spec.Replicas {
				return ErrInvalid
			}
			var operation models.RuntimeOperation
			if err := tx.Where("id=?", row.OperationID).Take(&operation).Error; err != nil {
				return err
			}
			if operation.Status != string(agent.Pending) && operation.Status != string(agent.InProgress) {
				if operation.Status != string(report.Status) || operation.ErrorCode != report.ErrorCode {
					return ErrConflict
				}
			}
			now := c.now().UTC()
			if err := tx.Exec(`INSERT INTO runtime_reports(node_id,event_id,operation_id,digest,payload,received_at) VALUES(?,?,?,?,?,?)`, obs.NodeID, report.EventID, report.OperationID, hash, raw, now).Error; err != nil {
				return err
			}
			if err := tx.Exec(`INSERT INTO runtime_observations(resource_id,node_id,operation_id,revision,payload,received_at) VALUES(?,?,?,?,?,?)
   ON CONFLICT(resource_id) DO UPDATE SET node_id=excluded.node_id,operation_id=excluded.operation_id,revision=excluded.revision,payload=excluded.payload,received_at=excluded.received_at`, obs.ResourceID, obs.NodeID, report.OperationID, obs.Revision, raw, now).Error; err != nil {
				return err
			}
			if err := tx.Model(&operation).Updates(map[string]any{"status": string(report.Status), "error_code": report.ErrorCode, "updated_at": now}).Error; err != nil {
				return err
			}
			if err := tx.Model(&models.RuntimeNode{}).Where("id=?", obs.NodeID).Update("last_seen_at", now).Error; err != nil {
				return err
			}
			return audit(tx, "service:"+caller, "node.report", obs.ResourceID, report.OperationID, now)
		})
	}))
}

func resourceSpec(row models.RuntimeResource) (agent.Spec, error) {
	var spec agent.Spec
	if json.Unmarshal([]byte(row.Spec), &spec) != nil {
		return spec, security.ErrUnavailable
	}
	return spec, nil
}

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Change struct {
	// Revision must be zero: Core assigns expected_revision+1.
	Spec             agent.Spec `json:"spec"`
	ExpectedRevision int64      `json:"expected_revision"`
	IdempotencyKey   string     `json:"idempotency_key"`
}

// Receipt is immutable even when an operation later completes or is superseded.
type Receipt struct {
	OperationID string     `json:"operation_id"`
	Desired     agent.Spec `json:"desired"`
}
type Observed struct {
	Report     agent.Report `json:"report"`
	ReceivedAt time.Time    `json:"received_at"`
}
type Resource struct {
	Desired     agent.Spec `json:"desired"`
	OperationID string     `json:"operation_id"`
	Observed    *Observed  `json:"observed,omitempty"`
}
type Operation struct {
	ID                string                `json:"id"`
	ResourceID        string                `json:"resource_id"`
	RequestedRevision int64                 `json:"requested_revision"`
	Actor             string                `json:"actor"`
	Status            agent.OperationStatus `json:"status"`
	ErrorCode         string                `json:"error_code,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

// Apply commits desired state, immutable revision, operation, audit and hint
// outbox together. It never calls a host driver or reinterprets legacy JSON specs.
func (c *Control) Apply(ctx context.Context, change Change) (Receipt, error) {
	var out Receipt
	if change.Spec.Revision != 0 || change.Spec.TemplateDigest != "" || change.ExpectedRevision < 0 || change.ExpectedRevision >= 1<<53-1 || len(change.IdempotencyKey) == 0 || len(change.IdempotencyKey) > 128 {
		return out, ErrInvalid
	}
	raw, err := canonical(change)
	if err != nil {
		return out, err
	}
	requestHash := digest(raw)
	err = c.managed(ctx, func(tx *gorm.DB, actor string) error {
		var replay models.RuntimeOperation
		err := tx.Where("actor=? AND idempotency_key=?", actor, change.IdempotencyKey).Take(&replay).Error
		if err == nil {
			if replay.RequestHash != requestHash {
				return ErrConflict
			}
			if json.Unmarshal([]byte(replay.Result), &out) != nil {
				return security.ErrUnavailable
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		want := change.Spec
		want.Revision = change.ExpectedRevision + 1
		if !agent.ValidID(want.NodeID) || !agent.ValidID(want.ID) || agent.Bootstrap(want.ID) {
			return ErrInvalid
		}
		if _, err := activeNode(tx, want.NodeID, ""); err != nil {
			return err
		}
		template, err := approvedTemplate(tx, want.NodeID, want.TemplateID, want.TemplateRevision)
		if err != nil {
			return err
		}
		want.TemplateDigest = agent.TemplateDigest(template)
		if want.Validate(template, want.NodeID) != nil {
			return ErrInvalid
		}
		spec, err := canonical(want)
		if err != nil {
			return err
		}
		var previous models.RuntimeResource
		err = tx.Where("id=?", want.ID).Take(&previous).Error
		exists := err == nil
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if exists {
			if previous.Revision != change.ExpectedRevision || previous.NodeID != want.NodeID || previous.Kind != string(want.Kind) || previous.State == string(agent.Deleted) {
				return ErrConflict
			}
		} else if change.ExpectedRevision != 0 {
			return ErrConflict
		}
		id, err := operationID()
		if err != nil {
			return err
		}
		now := c.now().UTC()
		row := models.RuntimeResource{ID: want.ID, NodeID: want.NodeID, TemplateID: want.TemplateID, TemplateRevision: want.TemplateRevision, Kind: string(want.Kind), Revision: want.Revision, State: string(want.State), Replicas: want.Replicas, Spec: spec, OperationID: id, UpdatedAt: now}
		if !exists {
			result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrConflict
			}
		} else {
			result := tx.Model(&models.RuntimeResource{}).Where("id=? AND revision=?", want.ID, change.ExpectedRevision).Updates(map[string]any{"template_id": row.TemplateID, "template_revision": row.TemplateRevision, "revision": row.Revision, "state": row.State, "replicas": row.Replicas, "spec": row.Spec, "operation_id": id, "updated_at": now})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrConflict
			}
			if err := tx.Model(&models.RuntimeOperation{}).Where("id=? AND status IN ('pending','running')", previous.OperationID).Updates(map[string]any{"status": string(agent.Cancelled), "updated_at": now}).Error; err != nil {
				return err
			}
		}
		out = Receipt{OperationID: id, Desired: want}
		result, err := canonical(out)
		if err != nil {
			return err
		}
		operation := models.RuntimeOperation{ID: id, ResourceID: want.ID, RequestedRevision: want.Revision, Actor: actor, IdempotencyKey: change.IdempotencyKey, RequestHash: requestHash, Status: string(agent.Pending), Result: result, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&operation).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO runtime_revisions(resource_id,revision,spec,digest,operation_id,created_at) VALUES(?,?,?,?,?,?)`, want.ID, want.Revision, spec, agent.SpecDigest(want), id, now).Error; err != nil {
			return err
		}
		if err := audit(tx, actor, "resource.apply", want.ID, id, now); err != nil {
			return err
		}
		// A hint contains identity/revision only, never executable desired state.
		hint, _ := canonical(struct {
			ResourceID  string `json:"resource_id"`
			NodeID      string `json:"node_id"`
			Revision    int64  `json:"revision"`
			OperationID string `json:"operation_id"`
		}{want.ID, want.NodeID, want.Revision, id})
		return tx.Exec(`INSERT INTO runtime_outbox(event_id,subject,payload,created_at) VALUES(?,?,?,?)`, id, "ctl.runtime.v1.node."+want.NodeID+".changed", hint, now).Error
	})
	if err != nil {
		return Receipt{}, err
	}
	return out, nil
}

func resourceView(db *gorm.DB, row models.RuntimeResource) (Resource, error) {
	var out Resource
	out.OperationID = row.OperationID
	if json.Unmarshal([]byte(row.Spec), &out.Desired) != nil {
		return out, security.ErrUnavailable
	}
	var observed struct {
		Payload    string
		ReceivedAt time.Time
	}
	err := db.Table("runtime_observations").Where("resource_id=?", row.ID).Take(&observed).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Observed = &Observed{ReceivedAt: observed.ReceivedAt}
	if json.Unmarshal([]byte(observed.Payload), &out.Observed.Report) != nil {
		return Resource{}, security.ErrUnavailable
	}
	return out, nil
}
func (c *Control) Resource(ctx context.Context, id string) (Resource, error) {
	if !agent.ValidID(id) {
		return Resource{}, ErrInvalid
	}
	db, err := c.readable(ctx)
	if err != nil {
		return Resource{}, err
	}
	var out Resource
	// Desired and observed must come from one SQLite read snapshot.
	err = db.Transaction(func(tx *gorm.DB) error {
		var row models.RuntimeResource
		if err := tx.Where("id=?", id).Take(&row).Error; err != nil {
			return err
		}
		var err error
		out, err = resourceView(tx, row)
		return err
	})
	return out, mapped(err)
}
func (c *Control) Resources(ctx context.Context, after string) ([]Resource, error) {
	if after != "" && !agent.ValidID(after) {
		return nil, ErrInvalid
	}
	db, err := c.readable(ctx)
	if err != nil {
		return nil, err
	}
	out := []Resource{}
	err = db.Transaction(func(tx *gorm.DB) error {
		var rows []models.RuntimeResource
		if err := tx.Where("id>?", after).Order("id").Limit(100).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			view, err := resourceView(tx, row)
			if err != nil {
				return err
			}
			out = append(out, view)
		}
		return nil
	})
	if err != nil {
		return nil, mapped(err)
	}
	return out, nil
}
func (c *Control) Operation(ctx context.Context, id string) (Operation, error) {
	if !agent.ValidID(id) {
		return Operation{}, ErrInvalid
	}
	db, err := c.readable(ctx)
	if err != nil {
		return Operation{}, err
	}
	var row models.RuntimeOperation
	if err := db.Where("id=?", id).Take(&row).Error; err != nil {
		return Operation{}, mapped(err)
	}
	return Operation{ID: row.ID, ResourceID: row.ResourceID, RequestedRevision: row.RequestedRevision, Actor: row.Actor, Status: agent.OperationStatus(row.Status), ErrorCode: row.ErrorCode, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

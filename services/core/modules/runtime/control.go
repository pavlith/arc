package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/agent"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/models"
	"gorm.io/gorm"
)

// ControlPolicy is a trusted in-process adapter, never request-supplied data.
// Manager must require live arc.runtime.manage for an authenticated Arc admin,
// excluding workspace-only admins and delegated agent/workflow identities.
// Node returns the verified service account ID, not a header or payload field.
// A future RPC adapter must verify invocation/proof before entering Control.
type ControlPolicy interface {
	Manager(context.Context) (string, error)
	Node(context.Context) (string, error)
}

type ControlConfig struct {
	DB         *gorm.DB
	Policy     ControlPolicy
	SigningKey ed25519.PrivateKey
	Now        func() time.Time
}

type Control struct {
	db         *gorm.DB
	policy     ControlPolicy
	signingKey ed25519.PrivateKey
	now        func() time.Time
}

func NewControl(cfg ControlConfig) (*Control, error) {
	if cfg.DB == nil || cfg.Policy == nil || len(cfg.SigningKey) != ed25519.PrivateKeySize {
		return nil, security.ErrUnavailable
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Control{db: cfg.DB, policy: cfg.Policy, signingKey: append(ed25519.PrivateKey(nil), cfg.SigningKey...), now: now}, nil
}

func (c *Control) manager(ctx context.Context) (string, error) {
	if c == nil || c.db == nil || c.policy == nil {
		return "", security.ErrUnavailable
	}
	actor, err := c.policy.Manager(ctx)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(actor, "user:") || len(actor) <= 5 || len(actor) > 133 {
		return "", security.ErrDenied
	}
	return actor, nil
}
func activeManager(tx *gorm.DB, actor string) error {
	var count int64
	if err := tx.Table("identity_users").Where("id=? AND status='active'", strings.TrimPrefix(actor, "user:")).Count(&count).Error; err != nil {
		return security.ErrUnavailable
	}
	if count != 1 {
		return security.ErrDenied
	}
	return nil
}
func (c *Control) managed(ctx context.Context, fn func(*gorm.DB, string) error) error {
	return mapped(database.RetryBusy(ctx, func() error {
		actor, err := c.manager(ctx)
		if err != nil {
			return err
		}
		return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := activeManager(tx, actor); err != nil {
				return err
			}
			return fn(tx, actor)
		})
	}))
}
func (c *Control) readable(ctx context.Context) (*gorm.DB, error) {
	actor, err := c.manager(ctx)
	if err != nil {
		return nil, err
	}
	db := c.db.WithContext(ctx)
	if err = activeManager(db, actor); err != nil {
		return nil, err
	}
	return db, nil
}
func mapped(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrInvalid, ErrConflict, security.ErrDenied, security.ErrUnauthenticated, security.ErrUnavailable, sql.ErrNoRows, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return sql.ErrNoRows
	}
	return security.ErrUnavailable
}
func canonical(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", ErrInvalid
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		return "", ErrInvalid
	}
	return string(raw), nil
}
func digest(raw string) string { sum := sha256.Sum256([]byte(raw)); return hex.EncodeToString(sum[:]) }
func operationID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", security.ErrUnavailable
	}
	return "op-" + hex.EncodeToString(random[:]), nil
}
func audit(tx *gorm.DB, actor, action, target, op string, now time.Time) error {
	return tx.Exec(`INSERT INTO runtime_audit(actor,action,target_id,operation_id,occurred_at) VALUES(?,?,?,?,?)`, actor, action, target, op, now).Error
}

func activeNode(tx *gorm.DB, id, caller string) (models.RuntimeNode, error) {
	var node models.RuntimeNode
	err := tx.Model(&models.RuntimeNode{}).Joins("JOIN identity_service_accounts s ON s.id=runtime_nodes.service_account_id").
		Where("runtime_nodes.id=? AND runtime_nodes.active=1 AND s.disabled_at IS NULL AND s.service_definition='arc-agent'", id).Take(&node).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return node, security.ErrDenied
	}
	if err != nil {
		return node, err
	}
	if caller != "" && node.ServiceAccountID != caller {
		return node, security.ErrDenied
	}
	return node, nil
}
func approvedTemplate(tx *gorm.DB, node string, id string, revision int64) (agent.Template, error) {
	var row models.RuntimeTemplate
	if err := tx.Where("node_id=? AND id=? AND revision=? AND revoked=0", node, id, revision).Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return agent.Template{}, security.ErrDenied
		}
		return agent.Template{}, err
	}
	var t agent.Template
	if json.Unmarshal([]byte(row.Spec), &t) != nil || t.Validate() != nil {
		return t, security.ErrUnavailable
	}
	return t, nil
}

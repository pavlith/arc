package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

// mutationGORM serializes each ACL mutation and its idempotent replay on
// access_policy_state. Results, policy revisions and the audit append are committed
// atomically. SQLite uniquely constrains (actor,caller,operation,idempotency_key).
func (c *Core) mutationGORM(ctx context.Context, op string, payload any,
	apply func(*gorm.DB, security.Claims, int64) (MutationResult, error)) (MutationResult, error) {
	var out MutationResult
	cl, err := c.claims(ctx, op)
	if err != nil {
		return out, err
	}
	meta, ok := rpc.Metadata(ctx)
	if !ok || len(meta.IdempotencyKey) == 0 || len(meta.IdempotencyKey) > 128 {
		return out, ErrValidation
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return out, ErrValidation
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		return out, ErrValidation
	}
	hash := sha256.Sum256(raw)
	err = database.RetryBusy(ctx, func() error {
		out = MutationResult{}
		return c.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// Acquiring the SQLite write lock BEFORE dedup/live checks avoids
			// concurrent first-writer snapshots and double effects.
			if err := tx.Exec("UPDATE access_policy_state SET revision=revision WHERE singleton=1").Error; err != nil {
				return err
			}
			var rev int64
			if err := tx.Raw("SELECT revision FROM access_policy_state WHERE singleton=1").Row().Scan(&rev); err != nil {
				return err
			}
			if err := c.liveGORM(tx, cl); err != nil {
				return err
			}
			var savedHash, savedResult []byte
			err := tx.Raw(`SELECT request_hash,result FROM access_operations
				WHERE actor=? AND caller=? AND operation=? AND idempotency_key=?`,
				cl.Subject, cl.Caller, op, meta.IdempotencyKey).
				Row().Scan(&savedHash, &savedResult)
			if err == nil {
				if !bytes.Equal(savedHash, hash[:]) {
					return ErrConflict
				}
				if len(savedResult) == 0 || json.Unmarshal(savedResult, &out) != nil {
					return ErrUnavailable
				}
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			out, err = apply(tx, cl, rev+1)
			if err != nil {
				return err
			}
			out.Revision = rev+1
			serialized, err := json.Marshal(out)
			if err != nil {
				return err
			}
			if err := tx.Exec(
				"UPDATE access_policy_state SET revision=? WHERE singleton=1", out.Revision,
			).Error; err != nil {
				return err
			}
			var resourceID any
			if out.ResourceID != "" {
				resourceID = out.ResourceID
			}
			if err := tx.Exec(`INSERT INTO access_operations(
				actor,caller,operation,idempotency_key,request_hash,resource_id,state,result)
				VALUES(?,?,?,?,?,?, 'completed',?)`,
				cl.Subject, cl.Caller, op, meta.IdempotencyKey, hash[:],
				resourceID, serialized).Error; err != nil {
				return err
			}
			change := op
			if grant, ok := payload.(GrantRequest); ok {
				self := grant.PrincipalKind+":"+grant.PrincipalID == cl.Subject ||
					grant.PrincipalKind == "user" && grant.PrincipalID == cl.OnBehalfOf
				if !self && grant.PrincipalKind == "role" &&
					(grant.PrincipalID == "owner" || grant.PrincipalID == "admin") {
					user := actorUser(cl)
					var role string
					if user != "" {
						err := tx.Raw(`SELECT role FROM identity_memberships
							WHERE workspace_id=(SELECT workspace_id FROM access_resources WHERE id=?)
							AND user_id=? AND revoked_at IS NULL`,
							grant.ResourceID, user).Row().Scan(&role)
						self = err == nil && role == grant.PrincipalID
					}
				}
				if !self && grant.PrincipalKind == "group" {
					user := actorUser(cl)
					if user != "" {
						if err := tx.Raw(`SELECT EXISTS(SELECT 1 FROM identity_group_members
							WHERE group_id=? AND user_id=?)`,
							grant.PrincipalID, user).Row().Scan(&self); err != nil {
							return err
						}
					}
				}
				if self {
					change = "self_grant"
				}
			}
			details := map[string]any{"state": out.State}
			switch q := payload.(type) {
			case GrantRequest:
				details["grant"] = q
			case RegisterRequest:
				details["type"] = q.Type
				details["contract_digest"] = q.ContractDigest
			}
			encoded, err := json.Marshal(details)
			if err != nil {
				return err
			}
			var onBehalf, grantID any
			if cl.OnBehalfOf != "" {
				onBehalf = cl.OnBehalfOf
			}
			if out.GrantID != "" {
				grantID = out.GrantID
			}
			if err := tx.Exec(`INSERT INTO access_policy_audit
				(actor,caller,on_behalf_of,operation,resource_id,policy_revision,change_kind,grant_id,change)
				VALUES(?,?,?,?,?,?,?,?,?)`,
				cl.Subject, cl.Caller, onBehalf, op, resourceID,
				out.Revision, change, grantID, string(encoded)).Error; err != nil {
				return err
			}
			return nil
		})
	})
	if err != nil {
		return MutationResult{}, normalize(err)
	}
	return out, nil
}

func (c *Core) registerTypeGORM(ctx context.Context, q RegisterRequest) (MutationResult, error) {
	return c.mutationGORM(ctx, "resource_types.register", q,
		func(tx *gorm.DB, cl security.Claims, _ int64) (MutationResult, error) {
			spec, err := c.Contracts.Type(q.Type, cl.Caller, q.ContractDigest)
			if err != nil {
				return MutationResult{}, err
			}
			var old string
			err = tx.Raw("SELECT contract_digest FROM access_resource_types WHERE type=?", q.Type).
				Row().Scan(&old)
			if err == nil {
				if old != q.ContractDigest {
					return MutationResult{}, ErrConflict
				}
				return MutationResult{State: "registered"}, nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return MutationResult{}, err
			}
			actions, err := json.Marshal(spec.Actions)
			if err != nil {
				return MutationResult{}, err
			}
			err = tx.Exec(`INSERT INTO access_resource_types(
				type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance)
				VALUES(?,?,?,?,?,?,?,?)`,
				spec.Type, spec.Provider, q.ContractDigest, string(actions),
				spec.ShareAction, spec.CreateAction, spec.DeleteAction, spec.AllowInheritance).Error
			return MutationResult{State: "registered"}, err
		})
}

func (c *Core) reserveGORM(ctx context.Context, q ReserveRequest) (MutationResult, error) {
	return c.mutationGORM(ctx, "resources.reserve", q,
		func(tx *gorm.DB, cl security.Claims, rev int64) (MutationResult, error) {
			if !validUUID(q.OwnerID) ||
				q.ParentID != "" && !validUUID(q.ParentID) ||
				q.WorkspaceID != "" && !validUUID(q.WorkspaceID) {
				return MutationResult{}, ErrValidation
			}
			spec, err := c.readTypeGORM(tx, q.Type)
			if errors.Is(err, sql.ErrNoRows) {
				return MutationResult{}, ErrDenied
			}
			if err != nil {
				return MutationResult{}, err
			}
			if spec.Provider != cl.Caller ||
				q.InheritACL && !spec.AllowInheritance ||
				!c.Contracts.action(cl, spec.CreateAction) ||
				cl.WorkspaceID != "" && cl.WorkspaceID != q.WorkspaceID {
				return MutationResult{}, ErrDenied
			}
			user := actorUser(cl)
			if user == "" {
				return MutationResult{}, ErrDenied
			}
			switch q.OwnerKind {
			case "user":
				if q.OwnerID != user || q.WorkspaceID != "" {
					return MutationResult{}, ErrDenied
				}
			case "workspace":
				if q.WorkspaceID != q.OwnerID {
					return MutationResult{}, ErrDenied
				}
				var role string
				err := tx.Raw(`SELECT role FROM identity_memberships
					WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL`,
					q.WorkspaceID, user).Row().Scan(&role)
				if errors.Is(err, sql.ErrNoRows) {
					return MutationResult{}, ErrDenied
				}
				if err != nil {
					return MutationResult{}, err
				}
				if q.ParentID == "" && role != "owner" && role != "admin" {
					return MutationResult{}, ErrDenied
				}
			default:
				return MutationResult{}, ErrDenied
			}
			if q.ParentID != "" {
				parent, err := readResourceGORM(tx, q.ParentID)
				if errors.Is(err, sql.ErrNoRows) {
					return MutationResult{}, ErrDenied
				}
				if err != nil {
					return MutationResult{}, err
				}
				if parent.State != "active" || parent.OwnerKind != q.OwnerKind ||
					parent.OwnerID != q.OwnerID || parent.WorkspaceID != q.WorkspaceID {
					return MutationResult{}, ErrDenied
				}
				allowed, err := c.evaluateGORM(tx, cl, CheckRequest{ResourceID: q.ParentID, Action: spec.CreateAction})
				if err != nil {
					return MutationResult{}, err
				}
				if !allowed {
					return MutationResult{}, ErrDenied
				}
			} else if cl.DelegationID != "" {
				return MutationResult{}, ErrDenied
			}
			id, err := uuid()
			if err != nil {
				return MutationResult{}, err
			}
			var ownerUserID, workspaceID, parentID any
			if q.OwnerKind == "user" {
				ownerUserID = q.OwnerID
			}
			if q.WorkspaceID != "" {
				workspaceID = q.WorkspaceID
			}
			if q.ParentID != "" {
				parentID = q.ParentID
			}
			err = tx.Exec(`INSERT INTO access_resources(
				id,type,provider_service,owner_kind,owner_id,owner_user_id,
				workspace_id,acl_parent_id,inherit_acl,state,policy_revision,created_at,updated_at)
				VALUES(?,?,?,?,?,?,?,?,?,'reserved',?,?,?)`,
				id, q.Type, cl.Caller, q.OwnerKind, q.OwnerID, ownerUserID,
				workspaceID, parentID, q.InheritACL, rev, c.now(), c.now()).Error
			return MutationResult{ResourceID: id, State: "reserved"}, err
		})
}

func (c *Core) transitionGORM(ctx context.Context, op string, q LifecycleRequest) (MutationResult, error) {
	return c.mutationGORM(ctx, "resources."+op, q,
		func(tx *gorm.DB, cl security.Claims, rev int64) (MutationResult, error) {
			if !validUUID(q.ResourceID) {
				return MutationResult{}, ErrValidation
			}
			resource, err := readResourceGORM(tx, q.ResourceID)
			if errors.Is(err, sql.ErrNoRows) {
				return MutationResult{}, ErrDenied
			}
			if err != nil {
				return MutationResult{}, err
			}
			if resource.Provider != cl.Caller ||
				cl.WorkspaceID != "" && cl.WorkspaceID != resource.WorkspaceID {
				return MutationResult{}, ErrDenied
			}
			var expected, next string
			switch op {
			case "activate":
				expected, next = "reserved", "active"
			case "abort":
				expected, next = "reserved", "aborted"
			case "begin_delete":
				expected, next = "active", "deleting"
			case "finalize_delete":
				expected, next = "deleting", "deleted"
			default:
				return MutationResult{}, ErrValidation
			}
			if resource.State == next || op == "begin_delete" && resource.State == "deleted" {
				return MutationResult{ResourceID: resource.ID, State: resource.State}, nil
			}
			if resource.State != expected {
				return MutationResult{}, ErrConflict
			}
			if op == "begin_delete" {
				spec, err := c.readTypeGORM(tx, resource.Type)
				if err != nil {
					return MutationResult{}, err
				}
				allowed, err := c.evaluateGORM(tx, cl,
					CheckRequest{ResourceID: resource.ID, Action: spec.DeleteAction})
				if err != nil {
					return MutationResult{}, err
				}
				if !allowed {
					return MutationResult{}, ErrDenied
				}
			} else {
				if c.Domain == nil {
					return MutationResult{}, ErrUnavailable
				}
				if err := c.Domain.Confirm(ctx, resource.Provider, resource.ID, op, q.Receipt); err != nil {
					return MutationResult{}, err
				}
			}
			err = tx.Exec(`UPDATE access_resources SET state=?,policy_revision=?,updated_at=?
				WHERE id=?`, next, rev, c.now(), resource.ID).Error
			return MutationResult{ResourceID: resource.ID, State: next}, err
		})
}

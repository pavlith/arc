package access

import (
	"context"
	"database/sql"

	"github.com/pavlith/arc/pkgs/security"
)

func (c *Core) RegisterType(ctx context.Context, q RegisterRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.RegisterType(ctx, q)
	}
	return c.mutation(ctx, "resource_types.register", q, func(t *sql.Tx, cl security.Claims, rev int64) (MutationResult, error) {
		spec, e := c.Contracts.Type(q.Type, cl.Caller, q.ContractDigest)
		if e != nil {
			return MutationResult{}, e
		}
		var old string
		e = t.QueryRowContext(ctx, `SELECT contract_digest FROM access.resource_types WHERE type=$1`, q.Type).Scan(&old)
		if e == nil {
			if old != q.ContractDigest {
				return MutationResult{}, ErrConflict
			}
			return MutationResult{State: "registered"}, nil
		}
		if e != sql.ErrNoRows {
			return MutationResult{}, e
		}
		_, e = t.ExecContext(ctx, `INSERT INTO access.resource_types(type,provider_service,contract_digest,actions,share_action,create_action,delete_action,allow_inheritance) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, spec.Type, spec.Provider, q.ContractDigest, spec.Actions, spec.ShareAction, spec.CreateAction, spec.DeleteAction, spec.AllowInheritance)
		return MutationResult{State: "registered"}, e
	})
}
func (c *Core) Reserve(ctx context.Context, q ReserveRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.Reserve(ctx, q)
	}
	return c.mutation(ctx, "resources.reserve", q, func(t *sql.Tx, cl security.Claims, rev int64) (MutationResult, error) {
		if !validUUID(q.OwnerID) || q.ParentID != "" && !validUUID(q.ParentID) || q.WorkspaceID != "" && !validUUID(q.WorkspaceID) {
			return MutationResult{}, ErrValidation
		}
		spec, e := c.readType(ctx, t, q.Type)
		if e == sql.ErrNoRows {
			return MutationResult{}, ErrDenied
		}
		if e != nil {
			return MutationResult{}, e
		}
		if spec.Provider != cl.Caller || q.InheritACL && !spec.AllowInheritance || !c.Contracts.action(cl, spec.CreateAction) {
			return MutationResult{}, ErrDenied
		}
		if cl.WorkspaceID != "" && cl.WorkspaceID != q.WorkspaceID {
			return MutationResult{}, ErrDenied
		}
		user := actorUser(cl)
		if user == "" {
			return MutationResult{}, ErrDenied
		}
		if q.OwnerKind == "user" {
			if q.OwnerID != user || q.WorkspaceID != "" {
				return MutationResult{}, ErrDenied
			}
		} else if q.OwnerKind == "workspace" {
			if q.WorkspaceID != q.OwnerID {
				return MutationResult{}, ErrDenied
			}
			var role string
			e = t.QueryRowContext(ctx, `SELECT role FROM identity.memberships WHERE workspace_id::text=$1 AND user_id::text=$2 AND revoked_at IS NULL`, q.WorkspaceID, user).Scan(&role)
			if e == sql.ErrNoRows {
				return MutationResult{}, ErrDenied
			}
			if e != nil {
				return MutationResult{}, e
			}
			if q.ParentID == "" && role != "owner" && role != "admin" {
				return MutationResult{}, ErrDenied
			}
		} else {
			return MutationResult{}, ErrDenied
		}
		if q.ParentID != "" {
			p, e := readResource(ctx, t, q.ParentID)
			if e == sql.ErrNoRows {
				return MutationResult{}, ErrDenied
			}
			if e != nil {
				return MutationResult{}, e
			}
			if p.State != "active" || p.OwnerKind != q.OwnerKind || p.OwnerID != q.OwnerID || p.WorkspaceID != q.WorkspaceID {
				return MutationResult{}, ErrDenied
			}
			allowed, e := c.evaluate(ctx, t, cl, CheckRequest{q.ParentID, spec.CreateAction})
			if e != nil {
				return MutationResult{}, e
			}
			if !allowed {
				return MutationResult{}, ErrDenied
			}
		} else if cl.DelegationID != "" {
			return MutationResult{}, ErrDenied
		}
		id, e := uuid()
		if e != nil {
			return MutationResult{}, e
		}
		_, e = t.ExecContext(ctx, `INSERT INTO access.resources(id,type,provider_service,owner_kind,owner_id,owner_user_id,workspace_id,acl_parent_id,inherit_acl,state,policy_revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,CASE WHEN $4='user' THEN $5::uuid END,NULLIF($6,'')::uuid,NULLIF($7,'')::uuid,$8,'reserved',$9,$10,$10)`, id, q.Type, cl.Caller, q.OwnerKind, q.OwnerID, q.WorkspaceID, q.ParentID, q.InheritACL, rev, c.now())
		return MutationResult{ResourceID: id, State: "reserved"}, e
	})
}
func (c *Core) Activate(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.Activate(ctx, q)
	}
	return c.transition(ctx, "activate", q)
}
func (c *Core) Abort(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.Abort(ctx, q)
	}
	return c.transition(ctx, "abort", q)
}
func (c *Core) BeginDelete(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.BeginDelete(ctx, q)
	}
	return c.transition(ctx, "begin_delete", q)
}
func (c *Core) FinalizeDelete(ctx context.Context, q LifecycleRequest) (MutationResult, error) {
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.FinalizeDelete(ctx, q)
	}
	return c.transition(ctx, "finalize_delete", q)
}
func (c *Core) transition(ctx context.Context, op string, q LifecycleRequest) (MutationResult, error) {
	return c.mutation(ctx, "resources."+op, q, func(t *sql.Tx, cl security.Claims, rev int64) (MutationResult, error) {
		if !validUUID(q.ResourceID) {
			return MutationResult{}, ErrValidation
		}
		r, e := readResource(ctx, t, q.ResourceID)
		if e == sql.ErrNoRows {
			return MutationResult{}, ErrDenied
		}
		if e != nil {
			return MutationResult{}, e
		}
		if r.Provider != cl.Caller || cl.WorkspaceID != "" && cl.WorkspaceID != r.WorkspaceID {
			return MutationResult{}, ErrDenied
		}
		expected, next := "", ""
		switch op {
		case "activate":
			expected, next = "reserved", "active"
		case "abort":
			expected, next = "reserved", "aborted"
		case "begin_delete":
			expected, next = "active", "deleting"
		case "finalize_delete":
			expected, next = "deleting", "deleted"
		}
		if r.State == next || op == "begin_delete" && r.State == "deleted" {
			return MutationResult{ResourceID: r.ID, State: r.State}, nil
		}
		if r.State != expected {
			return MutationResult{}, ErrConflict
		}
		if op == "begin_delete" {
			spec, e := c.readType(ctx, t, r.Type)
			if e != nil {
				return MutationResult{}, e
			}
			allowed, e := c.evaluate(ctx, t, cl, CheckRequest{r.ID, spec.DeleteAction})
			if e != nil {
				return MutationResult{}, e
			}
			if !allowed {
				return MutationResult{}, ErrDenied
			}
		} else {
			if c.Domain == nil {
				return MutationResult{}, ErrUnavailable
			}
			if e = c.Domain.Confirm(ctx, r.Provider, r.ID, op, q.Receipt); e != nil {
				return MutationResult{}, e
			}
		}
		_, e = t.ExecContext(ctx, `UPDATE access.resources SET state=$2,policy_revision=$3,updated_at=$4 WHERE id=$1`, r.ID, next, rev, c.now())
		return MutationResult{ResourceID: r.ID, State: next}, e
	})
}

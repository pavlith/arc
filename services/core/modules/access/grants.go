package access

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

func (c *Core) principal(ctx context.Context, t *sql.Tx, r Resource, kind, id string) error {
	if kind != "role" && !validUUID(id) {
		return ErrValidation
	}
	var ok bool
	var e error
	switch kind {
	case "user":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users u WHERE u.id::text=$1 AND u.status='active' AND ($2='' OR EXISTS(SELECT 1 FROM identity.memberships m WHERE m.user_id=u.id AND m.workspace_id::text=$2 AND m.revoked_at IS NULL)))`, id, r.WorkspaceID).Scan(&ok)
	case "role":
		ok = r.WorkspaceID != "" && (id == "owner" || id == "admin" || id == "member" || id == "guest")
	case "group":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.groups WHERE id::text=$1 AND workspace_id::text=$2)`, id, r.WorkspaceID).Scan(&ok)
	case "service":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.service_accounts WHERE id::text=$1 AND disabled_at IS NULL)`, id).Scan(&ok)
	case "agent":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.agent_identities WHERE id::text=$1 AND disabled_at IS NULL AND ((workspace_id IS NULL AND $2='' AND owner_user_id::text=$3) OR (workspace_id::text=$2 AND $2<>'')))`, id, r.WorkspaceID, r.OwnerID).Scan(&ok)
	default:
		return ErrValidation
	}
	if e != nil {
		return e
	}
	if !ok {
		return ErrDenied
	}
	return nil
}
func (c *Core) grantAuthority(ctx context.Context, t *sql.Tx, cl security.Claims, r Resource, action string) (bool, error) {
	spec, e := c.readType(ctx, t, r.Type)
	if e != nil {
		return false, e
	}
	if !contains(spec.Actions, action) || !c.Contracts.action(cl, action) {
		return false, ErrDenied
	}
	manage, e := c.evaluate(ctx, t, cl, CheckRequest{r.ID, "access.grants.manage"})
	if e != nil {
		return false, e
	}
	if manage {
		return true, nil
	}
	if action == "access.grants.manage" || action == spec.ShareAction {
		return false, ErrDenied
	}
	share, e := c.evaluate(ctx, t, cl, CheckRequest{r.ID, spec.ShareAction})
	if e != nil {
		return false, e
	}
	own, e := c.evaluate(ctx, t, cl, CheckRequest{r.ID, action})
	if e != nil {
		return false, e
	}
	if !share || !own {
		return false, ErrDenied
	}
	return false, nil
}

// share cannot turn an expiring permission or consent into a lasting grant.
func (c *Core) grantExpiry(ctx context.Context, t *sql.Tx, cl security.Claims, r Resource, action string, expires *time.Time, manage bool) error {
	if cl.DelegationID != "" {
		var until time.Time
		if e := t.QueryRowContext(ctx, `SELECT expires_at FROM identity.delegations WHERE id=$1 AND revoked_at IS NULL`, cl.DelegationID).Scan(&until); e != nil {
			return e
		}
		if expires == nil || expires.After(until) {
			return ErrDenied
		}
	}
	if manage {
		return nil
	}
	spec, e := c.readType(ctx, t, r.Type)
	if e != nil {
		return e
	}
	parents, valid, e := chain(ctx, t, r)
	if e != nil {
		return e
	}
	if !valid {
		return ErrDenied
	}
	ids := make([]string, 0, len(parents))
	for _, p := range parents {
		ids = append(ids, p.ID)
	}
	user := actorUser(cl)
	kind, principal, _ := strings.Cut(cl.Subject, ":")
	if user != "" {
		kind, principal = "user", user
	}
	rows, e := t.QueryContext(ctx, `SELECT g.action,bool_or(g.expires_at IS NULL),max(g.expires_at)
 FROM access.grants g WHERE g.resource_id=ANY($1::uuid[]) AND g.action=ANY($2::text[])
 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$3) AND (
 (g.principal_kind=$4 AND g.principal_id=$5) OR ($6<>'' AND (
 (g.principal_kind='role' AND EXISTS(SELECT 1 FROM identity.memberships m WHERE m.user_id::text=$6 AND m.workspace_id::text=$7 AND m.revoked_at IS NULL AND m.role=g.principal_id)) OR
 (g.principal_kind='group' AND EXISTS(SELECT 1 FROM identity.group_members gm JOIN identity.groups gr ON gr.id=gm.group_id WHERE gm.user_id::text=$6 AND gm.group_id::text=g.principal_id AND gr.workspace_id::text=$7)))))
 GROUP BY g.action`, ids, []string{spec.ShareAction, action}, c.now(), kind, principal, user, r.WorkspaceID)
	if e != nil {
		return e
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var act string
		var unlimited bool
		var until sql.NullTime
		if e = rows.Scan(&act, &unlimited, &until); e != nil {
			return e
		}
		if !unlimited && (!until.Valid || expires == nil || expires.After(until.Time)) {
			return ErrDenied
		}
		seen[act] = true
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if !seen[spec.ShareAction] || !seen[action] {
		return ErrDenied
	}
	return nil
}
func (c *Core) AddGrant(ctx context.Context, q GrantRequest) (MutationResult, error) {
	if c != nil && c.GormDB != nil {
		if c.ContractSource != nil {
			next, e := c.resolveContracts(ctx)
			if e != nil {
				return MutationResult{}, e
			}
			return next.AddGrant(ctx, q)
		}
		return c.addGrantGORM(ctx, q)
	}

	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.AddGrant(ctx, q)
	}
	return c.mutation(ctx, "grants.add", q, func(t *sql.Tx, cl security.Claims, rev int64) (MutationResult, error) {
		if !validUUID(q.ResourceID) || !namespaced(q.Action) || q.ExpiresAt != nil && !q.ExpiresAt.After(c.now()) {
			return MutationResult{}, ErrValidation
		}
		r, e := readResource(ctx, t, q.ResourceID)
		if e == sql.ErrNoRows {
			return MutationResult{}, ErrDenied
		}
		if e != nil {
			return MutationResult{}, e
		}
		if r.State != "active" {
			return MutationResult{}, ErrDenied
		}
		manage, e := c.grantAuthority(ctx, t, cl, r, q.Action)
		if e != nil {
			return MutationResult{}, e
		}
		if e = c.grantExpiry(ctx, t, cl, r, q.Action, q.ExpiresAt, manage); e != nil {
			return MutationResult{}, e
		}
		if e = c.principal(ctx, t, r, q.PrincipalKind, q.PrincipalID); e != nil {
			return MutationResult{}, e
		}
		id, e := uuid()
		if e != nil {
			return MutationResult{}, e
		}
		_, e = t.ExecContext(ctx, `INSERT INTO access.grants(id,resource_id,principal_kind,principal_id,action,expires_at,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, r.ID, q.PrincipalKind, q.PrincipalID, q.Action, q.ExpiresAt, cl.Subject, c.now())
		if e != nil {
			return MutationResult{}, e
		}
		_, e = t.ExecContext(ctx, `UPDATE access.resources SET policy_revision=$2,updated_at=$3 WHERE id=$1`, r.ID, rev, c.now())
		return MutationResult{ResourceID: r.ID, GrantID: id, State: "granted"}, e
	})
}
func (c *Core) RevokeGrant(ctx context.Context, q RevokeRequest) (MutationResult, error) {
	if c != nil && c.GormDB != nil {
		if c.ContractSource != nil {
			next, e := c.resolveContracts(ctx)
			if e != nil {
				return MutationResult{}, e
			}
			return next.RevokeGrant(ctx, q)
		}
		return c.revokeGrantGORM(ctx, q)
	}

	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return MutationResult{}, e
		}
		return next.RevokeGrant(ctx, q)
	}
	return c.mutation(ctx, "grants.revoke", q, func(t *sql.Tx, cl security.Claims, rev int64) (MutationResult, error) {
		if !validUUID(q.GrantID) {
			return MutationResult{}, ErrValidation
		}
		var resource, action, creator string
		var revoked sql.NullTime
		e := t.QueryRowContext(ctx, `SELECT resource_id,action,created_by,revoked_at FROM access.grants WHERE id::text=$1`, q.GrantID).Scan(&resource, &action, &creator, &revoked)
		if e == sql.ErrNoRows {
			return MutationResult{}, ErrDenied
		}
		if e != nil {
			return MutationResult{}, e
		}
		r, e := readResource(ctx, t, resource)
		if e != nil {
			return MutationResult{}, e
		}
		manage, e := c.grantAuthority(ctx, t, cl, r, action)
		if e != nil {
			return MutationResult{}, e
		}
		if !manage && creator != cl.Subject {
			return MutationResult{}, ErrDenied
		}
		if !revoked.Valid {
			if _, e = t.ExecContext(ctx, `UPDATE access.grants SET revoked_at=$2 WHERE id=$1`, q.GrantID, c.now()); e != nil {
				return MutationResult{}, e
			}
			if _, e = t.ExecContext(ctx, `UPDATE access.resources SET policy_revision=$2,updated_at=$3 WHERE id=$1`, resource, rev, c.now()); e != nil {
				return MutationResult{}, e
			}
		}
		return MutationResult{ResourceID: resource, GrantID: q.GrantID, State: "revoked"}, nil
	})
}

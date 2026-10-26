package access

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

func (c *Core) principalGORM(tx *gorm.DB, resource Resource, kind, id string) error {
	if kind != "role" && !validUUID(id) {
		return ErrValidation
	}
	var allowed bool
	var err error
	switch kind {
	case "user":
		err = tx.Raw(`SELECT EXISTS(SELECT 1 FROM identity_users u WHERE u.id=?
			AND u.status='active' AND (?='' OR EXISTS(
				SELECT 1 FROM identity_memberships m
				WHERE m.user_id=u.id AND m.workspace_id=? AND m.revoked_at IS NULL)))`,
			id, resource.WorkspaceID, resource.WorkspaceID).Row().Scan(&allowed)
	case "role":
		allowed = resource.WorkspaceID != "" &&
			(id == "owner" || id == "admin" || id == "member" || id == "guest")
	case "group":
		err = tx.Raw("SELECT EXISTS(SELECT 1 FROM identity_groups WHERE id=? AND workspace_id=?)",
			id, resource.WorkspaceID).Row().Scan(&allowed)
	case "service":
		err = tx.Raw("SELECT EXISTS(SELECT 1 FROM identity_service_accounts WHERE id=? AND disabled_at IS NULL)",
			id).Row().Scan(&allowed)
	case "agent":
		err = tx.Raw(`SELECT EXISTS(SELECT 1 FROM identity_agent_identities
			WHERE id=? AND disabled_at IS NULL AND (
				(workspace_id IS NULL AND ?='' AND owner_user_id=?)
				OR (workspace_id=? AND ?<>'')))`,
			id, resource.WorkspaceID, resource.OwnerID,
			resource.WorkspaceID, resource.WorkspaceID).Row().Scan(&allowed)
	default:
		return ErrValidation
	}
	if err != nil {
		return err
	}
	if !allowed {
		return ErrDenied
	}
	return nil
}

func (c *Core) grantAuthorityGORM(tx *gorm.DB, cl security.Claims, resource Resource, action string) (bool, error) {
	spec, err := c.readTypeGORM(tx, resource.Type)
	if err != nil {
		return false, err
	}
	if !contains(spec.Actions, action) || !c.Contracts.action(cl, action) {
		return false, ErrDenied
	}
	manage, err := c.evaluateGORM(tx, cl,
		CheckRequest{ResourceID: resource.ID, Action: "access.grants.manage"})
	if err != nil {
		return false, err
	}
	if manage {
		return true, nil
	}
	if action == "access.grants.manage" || action == spec.ShareAction {
		return false, ErrDenied
	}
	share, err := c.evaluateGORM(tx, cl, CheckRequest{ResourceID: resource.ID, Action: spec.ShareAction})
	if err != nil {
		return false, err
	}
	own, err := c.evaluateGORM(tx, cl, CheckRequest{ResourceID: resource.ID, Action: action})
	if err != nil {
		return false, err
	}
	if !share || !own {
		return false, ErrDenied
	}
	return false, nil
}

// grantExpiryGORM enforces that delegated/shared grants cannot outlive their
// caller's permissions. Grant expiry is checked using a
// time-bound check of each matched SQLite grant.
func (c *Core) grantExpiryGORM(tx *gorm.DB, cl security.Claims, resource Resource,
	action string, expiry *time.Time, manage bool) error {
	if cl.DelegationID != "" {
		var until time.Time
		if err := tx.Raw(`SELECT expires_at FROM identity_delegations
			WHERE id=? AND revoked_at IS NULL`, cl.DelegationID).Row().Scan(&until); err != nil {
			return err
		}
		if expiry == nil || expiry.After(until) {
			return ErrDenied
		}
	}
	if manage {
		return nil
	}
	spec, err := c.readTypeGORM(tx, resource.Type)
	if err != nil {
		return err
	}
	parents, valid, err := chainGORM(tx, resource)
	if err != nil {
		return err
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
	rows, err := tx.Raw(`SELECT g.action,g.expires_at
		FROM access_grants g WHERE g.resource_id IN ?
		AND g.action IN ? AND g.revoked_at IS NULL
		AND (g.expires_at IS NULL OR g.expires_at>?)
		AND (
			(g.principal_kind=? AND g.principal_id=?)
			OR (?<>'' AND (
				(g.principal_kind='role' AND EXISTS(
					SELECT 1 FROM identity_memberships m WHERE m.user_id=?
					AND m.workspace_id=? AND m.revoked_at IS NULL AND m.role=g.principal_id))
				OR (g.principal_kind='group' AND EXISTS(
					SELECT 1 FROM identity_group_members gm
					JOIN identity_groups gr ON gr.id=gm.group_id
					WHERE gm.user_id=? AND gm.group_id=g.principal_id AND gr.workspace_id=?))
			))
		)`, ids, []string{spec.ShareAction, action}, c.now(),
		kind, principal, user, user, resource.WorkspaceID, user, resource.WorkspaceID).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	// A principal may have multiple grants for one action. Any unexpired
	// authority that covers the proposed expiry is sufficient.
	covered := map[string]bool{}
	for rows.Next() {
		var grantedAction string
		var until sql.NullTime
		if err := rows.Scan(&grantedAction, &until); err != nil {
			return err
		}
		if !until.Valid || expiry != nil && !expiry.After(until.Time) {
			covered[grantedAction] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !covered[spec.ShareAction] || !covered[action] {
		return ErrDenied
	}
	return nil
}

func (c *Core) addGrantGORM(ctx context.Context, q GrantRequest) (MutationResult, error) {
	return c.mutationGORM(ctx, "grants.add", q,
		func(tx *gorm.DB, cl security.Claims, revision int64) (MutationResult, error) {
			if !validUUID(q.ResourceID) || !namespaced(q.Action) ||
				q.ExpiresAt != nil && !q.ExpiresAt.After(c.now()) {
				return MutationResult{}, ErrValidation
			}
			resource, err := readResourceGORM(tx, q.ResourceID)
			if errors.Is(err, sql.ErrNoRows) {
				return MutationResult{}, ErrDenied
			}
			if err != nil {
				return MutationResult{}, err
			}
			if resource.State != "active" {
				return MutationResult{}, ErrDenied
			}
			manage, err := c.grantAuthorityGORM(tx, cl, resource, q.Action)
			if err != nil {
				return MutationResult{}, err
			}
			if err := c.grantExpiryGORM(tx, cl, resource, q.Action, q.ExpiresAt, manage); err != nil {
				return MutationResult{}, err
			}
			if err := c.principalGORM(tx, resource, q.PrincipalKind, q.PrincipalID); err != nil {
				return MutationResult{}, err
			}
			id, err := uuid()
			if err != nil {
				return MutationResult{}, err
			}
			if err := tx.Exec(`INSERT INTO access_grants(
				id,resource_id,principal_kind,principal_id,action,expires_at,created_by,created_at)
				VALUES(?,?,?,?,?,?,?,?)`,
				id, resource.ID, q.PrincipalKind, q.PrincipalID,
				q.Action, q.ExpiresAt, cl.Subject, c.now()).Error; err != nil {
				return MutationResult{}, err
			}
			err = tx.Exec(`UPDATE access_resources SET policy_revision=?,updated_at=? WHERE id=?`,
				revision, c.now(), resource.ID).Error
			return MutationResult{ResourceID: resource.ID, GrantID: id, State: "granted"}, err
		})
}

func (c *Core) revokeGrantGORM(ctx context.Context, q RevokeRequest) (MutationResult, error) {
	return c.mutationGORM(ctx, "grants.revoke", q,
		func(tx *gorm.DB, cl security.Claims, revision int64) (MutationResult, error) {
			if !validUUID(q.GrantID) {
				return MutationResult{}, ErrValidation
			}
			var resourceID, action, creator string
			var revoked sql.NullTime
			err := tx.Raw(`SELECT resource_id,action,created_by,revoked_at
				FROM access_grants WHERE id=?`, q.GrantID).
				Row().Scan(&resourceID, &action, &creator, &revoked)
			if errors.Is(err, sql.ErrNoRows) {
				return MutationResult{}, ErrDenied
			}
			if err != nil {
				return MutationResult{}, err
			}
			resource, err := readResourceGORM(tx, resourceID)
			if err != nil {
				return MutationResult{}, err
			}
			manage, err := c.grantAuthorityGORM(tx, cl, resource, action)
			if err != nil {
				return MutationResult{}, err
			}
			if !manage && creator != cl.Subject {
				return MutationResult{}, ErrDenied
			}
			if !revoked.Valid {
				if err := tx.Exec("UPDATE access_grants SET revoked_at=? WHERE id=?",
					c.now(), q.GrantID).Error; err != nil {
					return MutationResult{}, err
				}
				if err := tx.Exec(
					"UPDATE access_resources SET policy_revision=?,updated_at=? WHERE id=?",
					revision, c.now(), resourceID).Error; err != nil {
					return MutationResult{}, err
				}
			}
			return MutationResult{ResourceID: resourceID, GrantID: q.GrantID, State: "revoked"}, nil
		})
}

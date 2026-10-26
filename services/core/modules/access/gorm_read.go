package access

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

// snapshotGORM reads the policy revision and every live ACL dependency from
// the same SQLite snapshot. Readers never observe half a Fabric approval.
func (c *Core) snapshotGORM(ctx context.Context, fn func(*gorm.DB, int64) error) error {
	if err := c.ready(); err != nil {
		return err
	}
	err := c.GormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var revision int64
		if err := tx.Raw("SELECT revision FROM access_policy_state WHERE singleton=1").Row().Scan(&revision); err != nil {
			return err
		}
		return fn(tx, revision)
	})
	return normalize(err)
}

func readResourceGORM(tx *gorm.DB, id string) (Resource, error) {
	var resource Resource
	err := tx.Raw(`SELECT id,type,provider_service,owner_kind,owner_id,
		COALESCE(workspace_id,''),COALESCE(acl_parent_id,''),
		inherit_acl,state,policy_revision FROM access_resources WHERE id=?`, id).
		Row().Scan(&resource.ID, &resource.Type, &resource.Provider, &resource.OwnerKind,
		&resource.OwnerID, &resource.WorkspaceID, &resource.ParentID,
		&resource.InheritACL, &resource.State, &resource.Revision)
	return resource, err
}

func (c *Core) readTypeGORM(tx *gorm.DB, name string) (TypeSpec, error) {
	var provider, digest string
	if err := tx.Raw("SELECT provider_service,contract_digest FROM access_resource_types WHERE type=?", name).
		Row().Scan(&provider, &digest); err != nil {
		return TypeSpec{}, err
	}
	return c.Contracts.Type(name, provider, digest)
}

// liveGORM is deliberately separate from the Identity access-token verifier.
// A stale caller key, revoked session or delegation cannot authorize an ACL read.
func (c *Core) liveGORM(tx *gorm.DB, cl security.Claims) error {
	var ok bool
	err := tx.Raw(`SELECT EXISTS(
		SELECT 1 FROM identity_service_accounts s
		JOIN identity_service_credentials k ON k.service_account_id=s.id
		WHERE s.id=? AND k.kid=? AND s.disabled_at IS NULL
		AND k.revoked_at IS NULL AND k.not_before<=? AND k.expires_at>?)`,
		cl.Caller, cl.Confirmation.Kid, c.now(), c.now()).Row().Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return security.ErrUnauthenticated
	}
	kind, id, found := strings.Cut(cl.Subject, ":")
	if !found || !validUUID(id) {
		return security.ErrUnauthenticated
	}
	switch kind {
	case "user":
		err = tx.Raw(`SELECT EXISTS(
			SELECT 1 FROM identity_users u JOIN identity_sessions s ON s.user_id=u.id
			WHERE u.id=? AND s.id=? AND u.status='active'
			AND s.revoked_at IS NULL AND s.expires_at>?)`,
			id, cl.SessionID, c.now()).Row().Scan(&ok)
	case "service":
		err = tx.Raw("SELECT EXISTS(SELECT 1 FROM identity_service_accounts WHERE id=? AND disabled_at IS NULL)", id).Row().Scan(&ok)
	case "agent":
		err = tx.Raw("SELECT EXISTS(SELECT 1 FROM identity_agent_identities WHERE id=? AND disabled_at IS NULL)", id).Row().Scan(&ok)
	default:
		return security.ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	if !ok {
		return security.ErrUnauthenticated
	}
	if (cl.OnBehalfOf != "") != (cl.DelegationID != "") {
		return security.ErrUnauthenticated
	}
	if cl.DelegationID != "" {
		var grantor, granteeKind, grantee string
		err = tx.Raw(`SELECT d.grantor_user_id,d.grantee_kind,d.grantee_id
			FROM identity_delegations d JOIN identity_users u ON u.id=d.grantor_user_id
			WHERE d.id=? AND d.revoked_at IS NULL AND d.expires_at>? AND u.status='active'`,
			cl.DelegationID, c.now()).Row().Scan(&grantor, &granteeKind, &grantee)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
		if err != nil {
			return err
		}
		if grantor != cl.OnBehalfOf || granteeKind+":"+grantee != cl.Subject {
			return ErrDenied
		}
	}
	return nil
}

func chainGORM(tx *gorm.DB, resource Resource) ([]Resource, bool, error) {
	parents := []Resource{resource}
	seen := map[string]bool{resource.ID: true}
	inherit := resource.InheritACL
	next := resource.ParentID
	for next != "" {
		if seen[next] || len(seen) >= 64 {
			return nil, false, nil
		}
		seen[next] = true
		parent, err := readResourceGORM(tx, next)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if parent.State != "active" || parent.OwnerKind != resource.OwnerKind ||
			parent.OwnerID != resource.OwnerID || parent.WorkspaceID != resource.WorkspaceID {
			return nil, false, nil
		}
		if inherit {
			parents = append(parents, parent)
			inherit = parent.InheritACL
		}
		next = parent.ParentID
	}
	return parents, true, nil
}

func (c *Core) userPermissionGORM(tx *gorm.DB, user string, r Resource, parents []Resource, action string) (bool, error) {
	var active bool
	err := tx.Raw("SELECT EXISTS(SELECT 1 FROM identity_users WHERE id=? AND status='active')", user).
		Row().Scan(&active)
	if err != nil || !active {
		return false, err
	}
	role := ""
	if r.WorkspaceID != "" {
		err = tx.Raw(`SELECT role FROM identity_memberships
			WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL`,
			r.WorkspaceID, user).Row().Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	if r.OwnerKind == "user" && r.OwnerID == user {
		return true, nil
	}
	if action == "access.grants.manage" && (role == "owner" || role == "admin") {
		return true, nil
	}
	ids := make([]string, 0, len(parents))
	for _, parent := range parents {
		ids = append(ids, parent.ID)
	}
	var allowed bool
	err = tx.Raw(`SELECT EXISTS(
		SELECT 1 FROM access_grants g WHERE g.resource_id IN ? AND g.action=?
		AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>?)
		AND (
			(g.principal_kind='user' AND g.principal_id=?)
			OR (g.principal_kind='role' AND ?<>'' AND g.principal_id=?)
			OR (g.principal_kind='group' AND EXISTS(
				SELECT 1 FROM identity_group_members gm JOIN identity_groups gr ON gr.id=gm.group_id
				WHERE gm.user_id=? AND gm.group_id=g.principal_id AND gr.workspace_id=?))
		))`, ids, action, c.now(), user, role, role, user, r.WorkspaceID).Row().Scan(&allowed)
	return allowed, err
}

func (c *Core) evaluateGORM(tx *gorm.DB, cl security.Claims, q CheckRequest) (bool, error) {
	if !validUUID(q.ResourceID) || !namespaced(q.Action) {
		return false, ErrValidation
	}
	if !c.Contracts.action(cl, q.Action) {
		return false, nil
	}
	resource, err := readResourceGORM(tx, q.ResourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if resource.State != "active" || cl.WorkspaceID != "" && cl.WorkspaceID != resource.WorkspaceID {
		return false, nil
	}
	spec, err := c.readTypeGORM(tx, resource.Type)
	if err != nil {
		return false, err
	}
	if !contains(spec.Actions, q.Action) {
		return false, nil
	}
	parents, valid, err := chainGORM(tx, resource)
	if err != nil || !valid {
		return false, err
	}
	if strings.HasPrefix(cl.Subject, "user:") {
		return c.userPermissionGORM(tx, strings.TrimPrefix(cl.Subject, "user:"), resource, parents, q.Action)
	}
	if strings.HasPrefix(cl.Subject, "agent:") {
		var scope, workspace string
		err = tx.Raw(`SELECT execution_scope,COALESCE(workspace_id,'') FROM identity_agent_identities
			WHERE id=? AND disabled_at IS NULL`, strings.TrimPrefix(cl.Subject, "agent:")).
			Row().Scan(&scope, &workspace)
		if err != nil {
			return false, err
		}
		if workspace != "" && workspace != resource.WorkspaceID ||
			!contains(c.Contracts.agentScopes[scope], q.Action) {
			return false, nil
		}
	}
	if cl.DelegationID != "" {
		var resourcesJSON, actionsJSON []byte
		var expires time.Time
		err = tx.Raw(`SELECT resource_ids,actions,expires_at
			FROM identity_delegations WHERE id=? AND revoked_at IS NULL`,
			cl.DelegationID).Row().Scan(&resourcesJSON, &actionsJSON, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		var resources, actions []string
		if json.Unmarshal(resourcesJSON, &resources) != nil ||
			json.Unmarshal(actionsJSON, &actions) != nil {
			return false, ErrUnavailable
		}
		if !expires.After(c.now()) || !contains(resources, resource.ID) || !contains(actions, q.Action) {
			return false, nil
		}
		return c.userPermissionGORM(tx, cl.OnBehalfOf, resource, parents, q.Action)
	}
	kind, id, ok := strings.Cut(cl.Subject, ":")
	if !ok {
		return false, security.ErrUnauthenticated
	}
	ids := make([]string, 0, len(parents))
	for _, parent := range parents {
		ids = append(ids, parent.ID)
	}
	var allowed bool
	err = tx.Raw(`SELECT EXISTS(SELECT 1 FROM access_grants
		WHERE resource_id IN ? AND principal_kind=? AND principal_id=? AND action=?
		AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?))`,
		ids, kind, id, q.Action, c.now()).Row().Scan(&allowed)
	return allowed, err
}

func (c *Core) checkGORM(ctx context.Context, q CheckRequest) (Decision, error) {
	cl, err := c.claims(ctx, "check")
	if err != nil {
		return Decision{}, err
	}
	var decision Decision
	err = c.snapshotGORM(ctx, func(tx *gorm.DB, revision int64) error {
		if err := c.liveGORM(tx, cl); err != nil {
			return err
		}
		decision.Revision = revision
		var err error
		decision.Allowed, err = c.evaluateGORM(tx, cl, q)
		return err
	})
	return decision, err
}

func (c *Core) checkManyGORM(ctx context.Context, q CheckManyRequest) (CheckManyResult, error) {
	cl, err := c.claims(ctx, "check_many")
	if err != nil {
		return CheckManyResult{}, err
	}
	if len(q.Checks) == 0 || len(q.Checks) > 100 {
		return CheckManyResult{}, ErrValidation
	}
	fixed := *c
	at := c.now()
	fixed.Now = func() time.Time { return at }
	result := CheckManyResult{Decisions: []Decision{}}
	err = fixed.snapshotGORM(ctx, func(tx *gorm.DB, revision int64) error {
		if err := fixed.liveGORM(tx, cl); err != nil {
			return err
		}
		result.Revision = revision
		for _, check := range q.Checks {
			allowed, err := fixed.evaluateGORM(tx, cl, check)
			if err != nil {
				return err
			}
			result.Decisions = append(result.Decisions, Decision{Allowed: allowed, Revision: revision})
		}
		return nil
	})
	if err != nil {
		return CheckManyResult{}, err
	}
	return result, nil
}

func (c *Core) listGORM(ctx context.Context, q ListRequest) (ListResult, error) {
	cl, err := c.claims(ctx, "list_accessible_roots")
	if err != nil {
		return ListResult{}, err
	}
	if q.Limit < 1 || q.Limit > 100 || !namespaced(q.Action) ||
		q.Type != "" && !namespaced(q.Type) || q.Cursor != "" && !validUUID(q.Cursor) ||
		q.OwnerID != "" && !validUUID(q.OwnerID) || q.WorkspaceID != "" && !validUUID(q.WorkspaceID) ||
		q.OwnerKind != "" && q.OwnerKind != "user" && q.OwnerKind != "workspace" {
		return ListResult{}, ErrValidation
	}
	fixed := *c
	at := c.now()
	fixed.Now = func() time.Time { return at }
	result := ListResult{Resources: []Resource{}}
	err = fixed.snapshotGORM(ctx, func(tx *gorm.DB, revision int64) error {
		if err := fixed.liveGORM(tx, cl); err != nil {
			return err
		}
		result.Revision = revision
		after := q.Cursor
		for len(result.Resources) < q.Limit+1 {
			rows, err := tx.Raw(`SELECT id FROM access_resources
				WHERE state='active' AND acl_parent_id IS NULL
				AND (?='' OR owner_kind=?) AND (?='' OR owner_id=?)
				AND (?='' OR COALESCE(workspace_id,'')=?)
				AND (?='' OR type=?) AND id>? ORDER BY id LIMIT 128`,
				q.OwnerKind, q.OwnerKind, q.OwnerID, q.OwnerID,
				q.WorkspaceID, q.WorkspaceID, q.Type, q.Type, after).Rows()
			if err != nil {
				return err
			}
			ids := make([]string, 0, 128)
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, id)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				break
			}
			for _, id := range ids {
				after = id
				allowed, err := fixed.evaluateGORM(tx, cl, CheckRequest{ResourceID: id, Action: q.Action})
				if err != nil {
					return err
				}
				if !allowed {
					continue
				}
				resource, err := readResourceGORM(tx, id)
				if err != nil {
					return err
				}
				result.Resources = append(result.Resources, resource)
				if len(result.Resources) > q.Limit {
					result.Resources = result.Resources[:q.Limit]
					result.NextCursor = result.Resources[len(result.Resources)-1].ID
					return nil
				}
			}
		}
		return nil
	})
	if err != nil {
		return ListResult{}, err
	}
	return result, nil
}

func (c *Core) userScopeGORM(ctx context.Context, user string, resources, actions []string) error {
	if !validUUID(user) {
		return ErrDenied
	}
	return c.snapshotGORM(ctx, func(tx *gorm.DB, _ int64) error {
		for _, id := range resources {
			if !validUUID(id) {
				return ErrDenied
			}
			resource, err := readResourceGORM(tx, id)
			if errors.Is(err, sql.ErrNoRows) || resource.State != "active" {
				return ErrDenied
			}
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
			spec, err := c.readTypeGORM(tx, resource.Type)
			if err != nil {
				return err
			}
			for _, action := range actions {
				if !contains(spec.Actions, action) {
					return ErrDenied
				}
				allowed, err := c.userPermissionGORM(tx, user, resource, parents, action)
				if err != nil {
					return err
				}
				if !allowed {
					return ErrDenied
				}
			}
		}
		return nil
	})
}

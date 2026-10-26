package access

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

func (c *Core) live(ctx context.Context, t *sql.Tx, cl security.Claims) error {
	var ok bool
	e := t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.service_accounts s JOIN identity.service_credentials k ON k.service_account_id=s.id WHERE s.id::text=$1 AND k.kid=$2 AND s.disabled_at IS NULL AND k.revoked_at IS NULL AND k.not_before<=$3 AND k.expires_at>$3)`, cl.Caller, cl.Confirmation.Kid, c.now()).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return security.ErrUnauthenticated
	}
	parts := strings.Split(cl.Subject, ":")
	if len(parts) != 2 {
		return security.ErrUnauthenticated
	}
	switch parts[0] {
	case "user":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users u JOIN identity.sessions s ON s.user_id=u.id WHERE u.id::text=$1 AND s.id::text=$2 AND u.status='active' AND s.revoked_at IS NULL AND s.expires_at>$3)`, parts[1], cl.SessionID, c.now()).Scan(&ok)
	case "service":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.service_accounts WHERE id::text=$1 AND disabled_at IS NULL)`, parts[1]).Scan(&ok)
	case "agent":
		e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.agent_identities WHERE id::text=$1 AND disabled_at IS NULL)`, parts[1]).Scan(&ok)
	default:
		return security.ErrUnauthenticated
	}
	if e != nil {
		return e
	}
	if !ok {
		return security.ErrUnauthenticated
	}
	if (cl.OnBehalfOf != "") != (cl.DelegationID != "") {
		return security.ErrUnauthenticated
	}
	if cl.DelegationID != "" {
		var grantor, kind, grantee string
		e = t.QueryRowContext(ctx, `SELECT d.grantor_user_id,d.grantee_kind,d.grantee_id FROM identity.delegations d JOIN identity.users u ON u.id=d.grantor_user_id WHERE d.id::text=$1 AND d.revoked_at IS NULL AND d.expires_at>$2 AND u.status='active'`, cl.DelegationID, c.now()).Scan(&grantor, &kind, &grantee)
		if e == sql.ErrNoRows {
			return ErrDenied
		}
		if e != nil {
			return e
		}
		if grantor != cl.OnBehalfOf || kind+":"+grantee != cl.Subject {
			return ErrDenied
		}
	}
	return nil
}
func chain(ctx context.Context, t *sql.Tx, r Resource) ([]Resource, bool, error) {
	result := []Resource{r}
	seen := map[string]bool{r.ID: true}
	inherit := r.InheritACL
	next := r.ParentID
	for next != "" {
		if seen[next] || len(seen) >= 64 {
			return nil, false, nil
		}
		seen[next] = true
		p, e := readResource(ctx, t, next)
		if e == sql.ErrNoRows {
			return nil, false, nil
		}
		if e != nil {
			return nil, false, e
		}
		if p.State != "active" || p.OwnerKind != r.OwnerKind || p.OwnerID != r.OwnerID || p.WorkspaceID != r.WorkspaceID {
			return nil, false, nil
		}
		if inherit {
			result = append(result, p)
			inherit = p.InheritACL
		}
		next = p.ParentID
	}
	return result, true, nil
}
func (c *Core) userPermission(ctx context.Context, t *sql.Tx, user string, r Resource, parents []Resource, action string) (bool, error) {
	var active bool
	if e := t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE id::text=$1 AND status='active')`, user).Scan(&active); e != nil {
		return false, e
	}
	if !active {
		return false, nil
	}
	role := ""
	if r.WorkspaceID != "" {
		e := t.QueryRowContext(ctx, `SELECT role FROM identity.memberships WHERE workspace_id::text=$1 AND user_id::text=$2 AND revoked_at IS NULL`, r.WorkspaceID, user).Scan(&role)
		if e == sql.ErrNoRows {
			return false, nil
		}
		if e != nil {
			return false, e
		}
	}
	if r.OwnerKind == "user" && r.OwnerID == user {
		return true, nil
	}
	if action == "access.grants.manage" && (role == "owner" || role == "admin") {
		return true, nil
	}
	ids := []string{}
	for _, p := range parents {
		ids = append(ids, p.ID)
	}
	var allowed bool
	e := t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM access.grants g WHERE g.resource_id=ANY($1::uuid[]) AND g.action=$2 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>$3) AND ((g.principal_kind='user' AND g.principal_id=$4) OR (g.principal_kind='role' AND $5<>'' AND g.principal_id=$5) OR (g.principal_kind='group' AND EXISTS(SELECT 1 FROM identity.group_members gm JOIN identity.groups gr ON gr.id=gm.group_id WHERE gm.user_id::text=$4 AND gm.group_id::text=g.principal_id AND gr.workspace_id::text=$6))))`, ids, action, c.now(), user, role, r.WorkspaceID).Scan(&allowed)
	return allowed, e
}
func (c *Core) evaluate(ctx context.Context, t *sql.Tx, cl security.Claims, q CheckRequest) (bool, error) {
	if !validUUID(q.ResourceID) || !namespaced(q.Action) {
		return false, ErrValidation
	}
	if !c.Contracts.action(cl, q.Action) {
		return false, nil
	}
	r, e := readResource(ctx, t, q.ResourceID)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if r.State != "active" || cl.WorkspaceID != "" && cl.WorkspaceID != r.WorkspaceID {
		return false, nil
	}
	spec, e := c.readType(ctx, t, r.Type)
	if e != nil {
		return false, e
	}
	if !contains(spec.Actions, q.Action) {
		return false, nil
	}
	parents, valid, e := chain(ctx, t, r)
	if e != nil || !valid {
		return false, e
	}
	if strings.HasPrefix(cl.Subject, "user:") {
		return c.userPermission(ctx, t, strings.TrimPrefix(cl.Subject, "user:"), r, parents, q.Action)
	}
	if strings.HasPrefix(cl.Subject, "agent:") {
		var scope, workspace string
		e = t.QueryRowContext(ctx, `SELECT execution_scope,COALESCE(workspace_id::text,'') FROM identity.agent_identities WHERE id::text=$1 AND disabled_at IS NULL`, strings.TrimPrefix(cl.Subject, "agent:")).Scan(&scope, &workspace)
		if e != nil {
			return false, e
		}
		if workspace != "" && workspace != r.WorkspaceID || !contains(c.Contracts.agentScopes[scope], q.Action) {
			return false, nil
		}
	}
	if cl.DelegationID != "" {
		var resources, actions []byte
		var expiry time.Time
		e = t.QueryRowContext(ctx, `SELECT array_to_json(resource_ids),array_to_json(actions),expires_at FROM identity.delegations WHERE id::text=$1 AND revoked_at IS NULL`, cl.DelegationID).Scan(&resources, &actions, &expiry)
		if e == sql.ErrNoRows {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		var rs, as []string
		if json.Unmarshal(resources, &rs) != nil || json.Unmarshal(actions, &as) != nil {
			return false, ErrUnavailable
		}
		if !expiry.After(c.now()) || !contains(rs, r.ID) || !contains(as, q.Action) {
			return false, nil
		}
		return c.userPermission(ctx, t, cl.OnBehalfOf, r, parents, q.Action)
	}
	parts := strings.Split(cl.Subject, ":")
	ids := []string{}
	for _, p := range parents {
		ids = append(ids, p.ID)
	}
	var allowed bool
	e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM access.grants WHERE resource_id=ANY($1::uuid[]) AND principal_kind=$2 AND principal_id=$3 AND action=$4 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>$5))`, ids, parts[0], parts[1], q.Action, c.now()).Scan(&allowed)
	return allowed, e
}
func (c *Core) Check(ctx context.Context, q CheckRequest) (Decision, error) {
 if c != nil && c.GormDB != nil {
 if c.ContractSource != nil { next,e := c.resolveContracts(ctx); if e != nil { return Decision{}, e }; return next.Check(ctx,q) }
 return c.checkGORM(ctx,q)
 }
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return Decision{}, e
		}
		return next.Check(ctx, q)
	}
	cl, e := c.claims(ctx, "check")
	if e != nil {
		return Decision{}, e
	}
	var out Decision
	e = c.snapshot(ctx, func(t *sql.Tx, rev int64) error {
		if e := c.live(ctx, t, cl); e != nil {
			return e
		}
		out.Revision = rev
		var e error
		out.Allowed, e = c.evaluate(ctx, t, cl, q)
		return e
	})
	return out, e
}
func (c *Core) CheckMany(ctx context.Context, q CheckManyRequest) (CheckManyResult, error) {
 if c != nil && c.GormDB != nil {
 if c.ContractSource != nil { next,e := c.resolveContracts(ctx); if e != nil { return CheckManyResult{}, e }; return next.CheckMany(ctx,q) }
 return c.checkManyGORM(ctx,q)
 }
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return CheckManyResult{}, e
		}
		return next.CheckMany(ctx, q)
	}
	cl, e := c.claims(ctx, "check_many")
	if e != nil {
		return CheckManyResult{}, e
	}
	if len(q.Checks) == 0 || len(q.Checks) > 100 {
		return CheckManyResult{}, ErrValidation
	}
	requestCore := *c
	at := c.now()
	requestCore.Now = func() time.Time { return at }
	c = &requestCore
	out := CheckManyResult{Decisions: []Decision{}}
	e = c.snapshot(ctx, func(t *sql.Tx, rev int64) error {
		if e := c.live(ctx, t, cl); e != nil {
			return e
		}
		out.Revision = rev
		for _, check := range q.Checks {
			allowed, e := c.evaluate(ctx, t, cl, check)
			if e != nil {
				return e
			}
			out.Decisions = append(out.Decisions, Decision{allowed, rev})
		}
		return nil
	})
	if e != nil {
		return CheckManyResult{}, e
	}
	return out, nil
}
func (c *Core) ListAccessibleRoots(ctx context.Context, q ListRequest) (ListResult, error) {
 if c != nil && c.GormDB != nil {
 if c.ContractSource != nil { next,e := c.resolveContracts(ctx); if e != nil { return ListResult{}, e }; return next.ListAccessibleRoots(ctx,q) }
 return c.listGORM(ctx,q)
 }
	if c != nil && c.ContractSource != nil {
		next, e := c.resolveContracts(ctx)
		if e != nil {
			return ListResult{}, e
		}
		return next.ListAccessibleRoots(ctx, q)
	}
	cl, e := c.claims(ctx, "list_accessible_roots")
	if e != nil {
		return ListResult{}, e
	}
	if q.Limit < 1 || q.Limit > 100 || !namespaced(q.Action) || q.Type != "" && !namespaced(q.Type) || q.Cursor != "" && !validUUID(q.Cursor) || q.OwnerID != "" && !validUUID(q.OwnerID) || q.WorkspaceID != "" && !validUUID(q.WorkspaceID) || q.OwnerKind != "" && q.OwnerKind != "user" && q.OwnerKind != "workspace" {
		return ListResult{}, ErrValidation
	}
	requestCore := *c
	at := c.now()
	requestCore.Now = func() time.Time { return at }
	c = &requestCore
	out := ListResult{Resources: []Resource{}}
	e = c.snapshot(ctx, func(t *sql.Tx, rev int64) error {
		if e := c.live(ctx, t, cl); e != nil {
			return e
		}
		out.Revision = rev
		after := q.Cursor
		for len(out.Resources) < q.Limit+1 {
			rows, e := t.QueryContext(ctx, `SELECT id FROM access.resources WHERE state='active' AND acl_parent_id IS NULL AND ($1='' OR owner_kind=$1) AND ($2='' OR owner_id::text=$2) AND ($3='' OR workspace_id::text=$3) AND ($4='' OR type=$4) AND id::text>$5 ORDER BY id LIMIT 128`, q.OwnerKind, q.OwnerID, q.WorkspaceID, q.Type, after)
			if e != nil {
				return e
			}
			ids := make([]string, 0, 128)
			for rows.Next() {
				var id string
				if e = rows.Scan(&id); e != nil {
					rows.Close()
					return e
				}
				ids = append(ids, id)
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if len(ids) == 0 {
				break
			}
			for _, id := range ids {
				after = id
				allowed, e := c.evaluate(ctx, t, cl, CheckRequest{id, q.Action})
				if e != nil {
					return e
				}
				if !allowed {
					continue
				}
				r, e := readResource(ctx, t, id)
				if e != nil {
					return e
				}
				out.Resources = append(out.Resources, r)
				if len(out.Resources) > q.Limit {
					out.Resources = out.Resources[:q.Limit]
					out.NextCursor = out.Resources[len(out.Resources)-1].ID
					return nil
				}
			}
		}
		return nil
	})
	if e != nil {
		return ListResult{}, e
	}
	return out, nil
}
func (c *Core) userScope(ctx context.Context, user string, resources, actions []string) error {
 if c != nil && c.GormDB != nil { return c.userScopeGORM(ctx,user,resources,actions) }
	if !validUUID(user) {
		return ErrDenied
	}
	return c.snapshot(ctx, func(t *sql.Tx, _ int64) error {
		for _, id := range resources {
			if !validUUID(id) {
				return ErrDenied
			}
			r, e := readResource(ctx, t, id)
			if e == sql.ErrNoRows {
				return ErrDenied
			}
			if e != nil {
				return e
			}
			if r.State != "active" {
				return ErrDenied
			}
			parents, ok, e := chain(ctx, t, r)
			if e != nil {
				return e
			}
			if !ok {
				return ErrDenied
			}
			spec, e := c.readType(ctx, t, r.Type)
			if e != nil {
				return e
			}
			for _, a := range actions {
				if !contains(spec.Actions, a) {
					return ErrDenied
				}
				allowed, e := c.userPermission(ctx, t, user, r, parents, a)
				if e != nil {
					return e
				}
				if !allowed {
					return ErrDenied
				}
			}
		}
		return nil
	})
}

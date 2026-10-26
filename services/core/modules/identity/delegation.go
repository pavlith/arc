package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

type Delegation struct {
	ID            string     `json:"id"`
	Grantor       string     `json:"grantor_user_id"`
	GranteeKind   string     `json:"grantee_kind"`
	GranteeID     string     `json:"grantee_id"`
	Resources     []string   `json:"resource_ids"`
	Actions       []string   `json:"actions"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	ConsentMethod string     `json:"consent_method"`
}

func (c *Core) CreateDelegation(ctx context.Context, auth UserSession, d Delegation) (Delegation, error) {
	s, e := c.user(ctx, auth)
	if e != nil {
		return Delegation{}, e
	}
	if d.Grantor != "" && d.Grantor != s.UserID {
		return Delegation{}, ErrDenied
	}
	d.Grantor = s.UserID
	if d.GranteeID == s.UserID || (d.GranteeKind != "agent" && d.GranteeKind != "service") || len(d.Resources) == 0 || len(d.Actions) == 0 {
		return Delegation{}, ErrDenied
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = c.now().Add(24 * time.Hour)
	}
	if !d.ExpiresAt.After(c.now()) || d.ExpiresAt.After(c.now().Add(24*time.Hour)) {
		return Delegation{}, ErrDenied
	}
	for _, a := range d.Actions {
		if a == "" || strings.ContainsAny(a, "*>") {
			return Delegation{}, ErrDenied
		}
	}
	for _, r := range d.Resources {
		if r == "" || strings.ContainsAny(r, "*>") {
			return Delegation{}, ErrDenied
		}
	}
	if e = c.allow(ctx, Authorization{Actor: "user:" + s.UserID, Operation: "identity.v1.delegations.create", ExpiresAt: d.ExpiresAt, Resources: d.Resources, Actions: d.Actions}); e != nil {
		return Delegation{}, e
	}
	d.ID, e = uuid()
	if e != nil {
		return Delegation{}, e
	}
	d.ConsentMethod = "interactive_session"
	d.RevokedAt = nil
	e = c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		table := "identity.service_accounts"
		status := "disabled_at IS NULL"
		if d.GranteeKind == "agent" {
			table = "identity.agent_identities"
			status += " AND owner_user_id::text=$2"
		}
		var id string
		args := []any{d.GranteeID}
		if d.GranteeKind == "agent" {
			args = append(args, s.UserID)
		}
		if e := t.QueryRowContext(ctx, `SELECT id FROM `+table+` WHERE id::text=$1 AND `+status+` FOR SHARE`, args...).Scan(&id); e != nil {
			return keyError(e)
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.delegations(id,grantor_user_id,grantee_kind,grantee_id,resource_ids,actions,expires_at,created_by,consent_method,created_at,grantee_service_id,grantee_agent_id) VALUES($1,$2,$3,$4,$5,$6,$7,$2,$8,$9,CASE WHEN $3='service' THEN $4::uuid END,CASE WHEN $3='agent' THEN $4::uuid END)`, d.ID, s.UserID, d.GranteeKind, d.GranteeID, d.Resources, d.Actions, d.ExpiresAt, d.ConsentMethod, c.now()); e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "delegations.create", d.ID, "ok")
	})
	return d, e
}
func (c *Core) delegation(ctx context.Context, id string) (Delegation, error) {
	if c != nil && c.GormDB != nil {
		return c.delegationGORM(ctx, id)
	}
	var d Delegation
	if e := c.ready(); e != nil {
		return d, e
	}
	var resources, actions []byte
	var revoked sql.NullTime
	e := c.DB.QueryRowContext(ctx, `SELECT id,grantor_user_id,grantee_kind,grantee_id,array_to_json(resource_ids),array_to_json(actions),expires_at,revoked_at,consent_method FROM identity.delegations WHERE id::text=$1`, id).Scan(&d.ID, &d.Grantor, &d.GranteeKind, &d.GranteeID, &resources, &actions, &d.ExpiresAt, &revoked, &d.ConsentMethod)
	if e != nil {
		return d, keyError(e)
	}
	if e = json.Unmarshal(resources, &d.Resources); e != nil {
		return d, e
	}
	if e = json.Unmarshal(actions, &d.Actions); e != nil {
		return d, e
	}
	if revoked.Valid {
		d.RevokedAt = &revoked.Time
	}
	return d, nil
}
func (c *Core) GetDelegation(ctx context.Context, auth UserSession, id string) (Delegation, error) {
	s, e := c.user(ctx, auth)
	if e != nil {
		return Delegation{}, e
	}
	d, e := c.delegation(ctx, id)
	if e != nil {
		return d, e
	}
	if d.Grantor != s.UserID {
		return Delegation{}, ErrDenied
	}
	return d, nil
}
func (c *Core) RevokeDelegation(ctx context.Context, auth UserSession, id string) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		r, e := t.ExecContext(ctx, `UPDATE identity.delegations SET revoked_at=$3 WHERE id::text=$1 AND grantor_user_id::text=$2`, id, s.UserID, c.now())
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrDenied
		}
		return audit(ctx, t, "user:"+s.UserID, "delegations.revoke", id, "ok")
	})
}
func (c *Core) checkDelegation(ctx context.Context, cl security.Claims) error {
	if c != nil && c.GormDB != nil {
		return c.checkDelegationGORM(ctx, cl)
	}
	d, e := c.delegation(ctx, cl.DelegationID)
	if e != nil {
		return e
	}
	if d.RevokedAt != nil || !d.ExpiresAt.After(c.now()) || cl.Subject != d.GranteeKind+":"+d.GranteeID || cl.OnBehalfOf != d.Grantor {
		return ErrDenied
	}
	var active bool
	e = c.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE id::text=$1 AND status='active')`, d.Grantor).Scan(&active)
	if e != nil {
		return ErrUnavailable
	}
	if !active {
		return ErrDenied
	}
	return c.allow(ctx, Authorization{Caller: cl.Caller, Actor: "user:" + d.Grantor, Operation: cl.Operation, Audience: cl.Audience, WorkspaceID: cl.WorkspaceID, DelegationID: d.ID, Resources: d.Resources, Actions: d.Actions})
}

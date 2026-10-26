package identity

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
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
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		table := "identity_service_accounts"
		status := "disabled_at IS NULL"
		if d.GranteeKind == "agent" {
			table = "identity_agent_identities"
			status += " AND owner_user_id=?"
		}
		var id string
		args := []any{d.GranteeID}
		if d.GranteeKind == "agent" {
			args = append(args, s.UserID)
		}
		if e := t.WithContext(ctx).Raw(`SELECT id FROM `+table+` WHERE id=? AND `+status+``, args...).Row().Scan(&id); e != nil {
			return keyError(e)
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_delegations(id,grantor_user_id,grantee_kind,grantee_id,resource_ids,actions,expires_at,created_by,consent_method,created_at,grantee_service_id,grantee_agent_id) VALUES( ?,?,?,?,?,?,?,?,?,?,CASE WHEN ?='service' THEN ? END,CASE WHEN ?='agent' THEN ? END)`, d.ID, s.UserID, d.GranteeKind, d.GranteeID, encodeStrings(d.Resources), encodeStrings(d.Actions), d.ExpiresAt, s.UserID, d.ConsentMethod, c.now(), d.GranteeKind, d.GranteeID, d.GranteeKind, d.GranteeID).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "delegations.create", d.ID, "ok")
	})
	return d, e
}
func (c *Core) delegation(ctx context.Context, id string) (Delegation, error) {
	return c.delegationGORM(ctx, id)
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
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		r := t.WithContext(ctx).Exec(`UPDATE identity_delegations SET revoked_at=? WHERE id=? AND grantor_user_id=?`, c.now(), id, s.UserID)
		if r.Error != nil {
			return r.Error
		}
		n := r.RowsAffected
		if n != 1 {
			return ErrDenied
		}
		return audit(ctx, t, "user:"+s.UserID, "delegations.revoke", id, "ok")
	})
}
func (c *Core) checkDelegation(ctx context.Context, cl security.Claims) error {
	return c.checkDelegationGORM(ctx, cl)
}

func encodeStrings(values []string) string { raw, _ := json.Marshal(values); return string(raw) }

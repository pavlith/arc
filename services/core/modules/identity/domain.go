package identity

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

func (c *Core) lockSession(ctx context.Context, t *gorm.DB, s Session) error {
	var ok bool
	e := t.WithContext(ctx).Raw(`SELECT true FROM identity_sessions s JOIN identity_users u ON u.id=s.user_id WHERE s.id=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active'`, s.ID, c.now()).Row().Scan(&ok)
	return keyError(e)
}
func (c *Core) CreateWorkspace(ctx context.Context, auth UserSession, name string) (string, error) {
	s, e := c.user(ctx, auth)
	if e != nil {
		return "", e
	}
	if strings.TrimSpace(name) == "" {
		return "", ErrDenied
	}
	id, e := uuid()
	if e != nil {
		return "", e
	}
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_workspaces(id,name) VALUES( ?,?)`, id, name).Error; e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_memberships(workspace_id,user_id,role) VALUES( ?,?,'owner')`, id, s.UserID).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "workspaces.create", id, "ok")
	})
	return id, e
}
func workspaceRole(ctx context.Context, t *gorm.DB, workspace, user string) (string, error) {
	var revision int64
	if e := t.WithContext(ctx).Raw(`SELECT revision FROM identity_workspaces WHERE id=?`, workspace).Row().Scan(&revision); e != nil {
		return "", keyError(e)
	}
	var role string
	e := t.WithContext(ctx).Raw(`SELECT role FROM identity_memberships WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL`, workspace, user).Row().Scan(&role)
	return role, keyError(e)
}
func (c *Core) SetMembership(ctx context.Context, auth UserSession, workspace, user, role string, revoke bool) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	if role != "owner" && role != "admin" && role != "member" && role != "guest" {
		return ErrDenied
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		own, e := workspaceRole(ctx, t, workspace, s.UserID)
		if e != nil {
			return e
		}
		if own != "owner" && own != "admin" {
			return ErrDenied
		}
		var previous string
		e = t.WithContext(ctx).Raw(`SELECT role FROM identity_memberships WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL`, workspace, user).Row().Scan(&previous)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		if own != "owner" && (role == "owner" || previous == "owner" || role == "admin" || previous == "admin") {
			return ErrDenied
		}
		if previous == "owner" && (revoke || role != "owner") {
			var owners int
			if e = t.WithContext(ctx).Raw(`SELECT count(*) FROM identity_memberships WHERE workspace_id=? AND role='owner' AND revoked_at IS NULL`, workspace).Row().Scan(&owners); e != nil {
				return e
			}
			if owners <= 1 {
				return ErrDenied
			}
		}
		if revoke {
			if e = t.WithContext(ctx).Exec(`UPDATE identity_memberships SET revoked_at=? WHERE workspace_id=? AND user_id=?`, c.now(), workspace, user).Error; e != nil {
				return e
			}
			if e = t.WithContext(ctx).Exec(`DELETE FROM identity_group_members WHERE workspace_id=? AND user_id=?`, workspace, user).Error; e != nil {
				return e
			}
		} else {
			if e = t.WithContext(ctx).Exec(`INSERT INTO identity_memberships(workspace_id,user_id,role) VALUES( ?,?,?) ON CONFLICT(workspace_id,user_id) DO UPDATE SET role=?,revoked_at=NULL`, workspace, user, role, role).Error; e != nil {
				return e
			}
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_workspaces SET revision=revision+1 WHERE id=?`, workspace).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "memberships.change", workspace+":"+user, "ok")
	})
}
func (c *Core) CreateGroup(ctx context.Context, auth UserSession, workspace, name string) (string, error) {
	s, e := c.user(ctx, auth)
	if e != nil {
		return "", e
	}
	id, e := uuid()
	if e != nil {
		return "", e
	}
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		role, e := workspaceRole(ctx, t, workspace, s.UserID)
		if e != nil {
			return e
		}
		if role != "owner" && role != "admin" {
			return ErrDenied
		}
		if strings.TrimSpace(name) == "" {
			return ErrDenied
		}
		if e = t.WithContext(ctx).Exec(`INSERT INTO identity_groups(id,workspace_id,name) VALUES( ?,?,?)`, id, workspace, name).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "groups.create", id, "ok")
	})
	return id, e
}
func (c *Core) SetGroupMember(ctx context.Context, auth UserSession, workspace, group, user string, remove bool) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		role, e := workspaceRole(ctx, t, workspace, s.UserID)
		if e != nil {
			return e
		}
		if role != "owner" && role != "admin" {
			return ErrDenied
		}
		if remove {
			e = t.WithContext(ctx).Exec(`DELETE FROM identity_group_members WHERE workspace_id=? AND group_id=? AND user_id=?`, workspace, group, user).Error
		} else {
			var ok bool
			e = t.WithContext(ctx).Raw(`SELECT EXISTS(SELECT 1 FROM identity_memberships WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL)`, workspace, user).Row().Scan(&ok)
			if e != nil {
				return e
			}
			if !ok {
				return ErrDenied
			}
			e = t.WithContext(ctx).Exec(`INSERT INTO identity_group_members(workspace_id,group_id,user_id) VALUES( ?,?,?) ON CONFLICT DO NOTHING`, workspace, group, user).Error
		}
		if e != nil {
			return e
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_workspaces SET revision=revision+1 WHERE id=?`, workspace).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "groups.members.change", group+":"+user, "ok")
	})
}
func (c *Core) admin(ctx context.Context, auth UserSession, op string) (Session, error) {
	s, e := c.user(ctx, auth)
	if e != nil {
		return s, e
	}
	e = c.allow(ctx, Authorization{Actor: "user:" + s.UserID, Audience: "identity/v1", Operation: op})
	return s, e
}
func (c *Core) RegisterService(ctx context.Context, auth UserSession, definition, deployment string) (string, error) {
	s, e := c.admin(ctx, auth, "identity.v1.service_accounts.register")
	if e != nil {
		return "", e
	}
	if definition == "" || deployment == "" {
		return "", ErrDenied
	}
	if e = c.allow(ctx, Authorization{Actor: "user:" + s.UserID, Audience: definition, Operation: "deployment.approved", Resources: []string{deployment}}); e != nil {
		return "", e
	}
	id, e := uuid()
	if e != nil {
		return "", e
	}
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_service_accounts(id,service_definition,deployment) VALUES( ?,?,?)`, id, definition, deployment).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "service_accounts.register", id, "ok")
	})
	return id, e
}
func (c *Core) AddServiceKey(ctx context.Context, auth UserSession, service, kid string, public ed25519.PublicKey, reference string, expires time.Time) error {
	s, e := c.admin(ctx, auth, "identity.v1.service_keys.rotate")
	if e != nil {
		return e
	}
	if len(public) != 32 || kid == "" || reference == "" || !expires.After(c.now()) {
		return ErrDenied
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		var disabled sql.NullTime
		if e := t.WithContext(ctx).Raw(`SELECT disabled_at FROM identity_service_accounts WHERE id=?`, service).Row().Scan(&disabled); e != nil {
			return keyError(e)
		}
		if disabled.Valid {
			return ErrDenied
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_service_credentials(kid,service_account_id,public_key,secret_reference,not_before,expires_at) VALUES( ?,?,?,?,?,?)`, kid, service, []byte(public), reference, c.now(), expires).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "service_keys.rotate", kid, "ok")
	})
}
func (c *Core) DisableService(ctx context.Context, auth UserSession, id string) error {
	s, e := c.admin(ctx, auth, "identity.v1.service_accounts.disable")
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`UPDATE identity_service_accounts SET disabled_at=? WHERE id=?`, c.now(), id).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "service_accounts.disable", id, "ok")
	})
}
func (c *Core) RevokeKey(ctx context.Context, auth UserSession, kid string, signing bool) error {
	s, e := c.admin(ctx, auth, "identity.v1.keys.revoke")
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		table := "identity_service_credentials"
		if signing {
			table = "identity_signing_key_metadata"
		}
		if e := t.WithContext(ctx).Exec(`UPDATE `+table+` SET revoked_at=? WHERE kid=?`, c.now(), kid).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "keys.revoke", kid, "ok")
	})
}
func (c *Core) SetUserDisabled(ctx context.Context, auth UserSession, id string, disabled bool) error {
	s, e := c.admin(ctx, auth, "identity.v1.users.status")
	if e != nil {
		return e
	}
	status := "active"
	if disabled {
		status = "disabled"
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if e := t.WithContext(ctx).Exec(`UPDATE identity_users SET status=? WHERE id=?`, status, id).Error; e != nil {
			return e
		}
		if disabled {
			if e := t.WithContext(ctx).Exec(`UPDATE identity_sessions SET revoked_at=? WHERE user_id=?`, c.now(), id).Error; e != nil {
				return e
			}
		}
		return audit(ctx, t, "user:"+s.UserID, "users.status", id, "ok")
	})
}
func (c *Core) RegisterAgent(ctx context.Context, auth UserSession, workspace, scope string) (string, error) {
	s, e := c.user(ctx, auth)
	if e != nil {
		return "", e
	}
	if scope == "" {
		return "", ErrDenied
	}
	if e = c.allow(ctx, Authorization{Actor: "user:" + s.UserID, WorkspaceID: workspace, Operation: "identity.v1.agents.register", Resources: []string{scope}}); e != nil {
		return "", e
	}
	id, e := uuid()
	if e != nil {
		return "", e
	}
	e = c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if workspace != "" {
			if _, e := workspaceRole(ctx, t, workspace, s.UserID); e != nil {
				return e
			}
		}
		if e := t.WithContext(ctx).Exec(`INSERT INTO identity_agent_identities(id,owner_user_id,workspace_id,execution_scope) VALUES( ?,?,NULLIF(?,''),?)`, id, s.UserID, workspace, scope).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "agents.register", id, "ok")
	})
	return id, e
}

// Compile-time boundary assertions.
var _ security.Keys = (*Core)(nil)
var _ security.LiveState = (*Core)(nil)
var _ security.Nonces = (*Core)(nil)

func (c *Core) LeaveWorkspace(ctx context.Context, auth UserSession, workspace string) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		role, e := workspaceRole(ctx, t, workspace, s.UserID)
		if e != nil {
			return e
		}
		if role == "owner" {
			var owners int
			if e = t.WithContext(ctx).Raw(`SELECT count(*) FROM identity_memberships WHERE workspace_id=? AND role='owner' AND revoked_at IS NULL`, workspace).Row().Scan(&owners); e != nil {
				return e
			}
			if owners <= 1 {
				return ErrDenied
			}
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_memberships SET revoked_at=? WHERE workspace_id=? AND user_id=?`, c.now(), workspace, s.UserID).Error; e != nil {
			return e
		}
		if e = t.WithContext(ctx).Exec(`DELETE FROM identity_group_members WHERE workspace_id=? AND user_id=?`, workspace, s.UserID).Error; e != nil {
			return e
		}
		if e = t.WithContext(ctx).Exec(`UPDATE identity_workspaces SET revision=revision+1 WHERE id=?`, workspace).Error; e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "memberships.leave", workspace, "ok")
	})
}
func (c *Core) DisableAgent(ctx context.Context, auth UserSession, id string) error {
	s, e := c.user(ctx, auth)
	if e != nil {
		return e
	}
	return c.tx(ctx, func(t *gorm.DB) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		r := t.WithContext(ctx).Exec(`UPDATE identity_agent_identities SET disabled_at=? WHERE id=? AND owner_user_id=?`, c.now(), id, s.UserID)
		if r.Error != nil {
			return r.Error
		}
		n := r.RowsAffected
		if n != 1 {
			return ErrDenied
		}
		return audit(ctx, t, "user:"+s.UserID, "agents.disable", id, "ok")
	})
}

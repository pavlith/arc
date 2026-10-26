package identity

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"strings"
	"time"

	"github.com/pavlith/arc/pkgs/security"
)

func (c *Core) lockSession(ctx context.Context, t *sql.Tx, s Session) error {
	var ok bool
	e := t.QueryRowContext(ctx, `SELECT true FROM identity.sessions s JOIN identity.users u ON u.id=s.user_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND u.status='active' FOR SHARE OF s,u`, s.ID, c.now()).Scan(&ok)
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
	e = c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.workspaces(id,name) VALUES($1,$2)`, id, name); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.memberships(workspace_id,user_id,role) VALUES($1,$2,'owner')`, id, s.UserID); e != nil {
			return e
		}
		return audit(ctx, t, "user:"+s.UserID, "workspaces.create", id, "ok")
	})
	return id, e
}
func workspaceRole(ctx context.Context, t *sql.Tx, workspace, user string) (string, error) {
	var revision int64
	if e := t.QueryRowContext(ctx, `SELECT revision FROM identity.workspaces WHERE id::text=$1 FOR UPDATE`, workspace).Scan(&revision); e != nil {
		return "", keyError(e)
	}
	var role string
	e := t.QueryRowContext(ctx, `SELECT role FROM identity.memberships WHERE workspace_id::text=$1 AND user_id::text=$2 AND revoked_at IS NULL`, workspace, user).Scan(&role)
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
	return c.tx(ctx, func(t *sql.Tx) error {
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
		e = t.QueryRowContext(ctx, `SELECT role FROM identity.memberships WHERE workspace_id::text=$1 AND user_id::text=$2 AND revoked_at IS NULL`, workspace, user).Scan(&previous)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		if own != "owner" && (role == "owner" || previous == "owner" || role == "admin" || previous == "admin") {
			return ErrDenied
		}
		if previous == "owner" && (revoke || role != "owner") {
			var owners int
			if e = t.QueryRowContext(ctx, `SELECT count(*) FROM identity.memberships WHERE workspace_id::text=$1 AND role='owner' AND revoked_at IS NULL`, workspace).Scan(&owners); e != nil {
				return e
			}
			if owners <= 1 {
				return ErrDenied
			}
		}
		if revoke {
			if _, e = t.ExecContext(ctx, `UPDATE identity.memberships SET revoked_at=$3 WHERE workspace_id::text=$1 AND user_id::text=$2`, workspace, user, c.now()); e != nil {
				return e
			}
			if _, e = t.ExecContext(ctx, `DELETE FROM identity.group_members WHERE workspace_id::text=$1 AND user_id::text=$2`, workspace, user); e != nil {
				return e
			}
		} else {
			if _, e = t.ExecContext(ctx, `INSERT INTO identity.memberships(workspace_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(workspace_id,user_id) DO UPDATE SET role=$3,revoked_at=NULL`, workspace, user, role); e != nil {
				return e
			}
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.workspaces SET revision=revision+1 WHERE id::text=$1`, workspace); e != nil {
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
	e = c.tx(ctx, func(t *sql.Tx) error {
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
		if _, e = t.ExecContext(ctx, `INSERT INTO identity.groups(id,workspace_id,name) VALUES($1,$2,$3)`, id, workspace, name); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
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
			_, e = t.ExecContext(ctx, `DELETE FROM identity.group_members WHERE workspace_id::text=$1 AND group_id::text=$2 AND user_id::text=$3`, workspace, group, user)
		} else {
			var ok bool
			e = t.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity.memberships WHERE workspace_id::text=$1 AND user_id::text=$2 AND revoked_at IS NULL)`, workspace, user).Scan(&ok)
			if e != nil {
				return e
			}
			if !ok {
				return ErrDenied
			}
			_, e = t.ExecContext(ctx, `INSERT INTO identity.group_members(workspace_id,group_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, workspace, group, user)
		}
		if e != nil {
			return e
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.workspaces SET revision=revision+1 WHERE id::text=$1`, workspace); e != nil {
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
	e = c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.service_accounts(id,service_definition,deployment) VALUES($1,$2,$3)`, id, definition, deployment); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		var disabled sql.NullTime
		if e := t.QueryRowContext(ctx, `SELECT disabled_at FROM identity.service_accounts WHERE id::text=$1 FOR UPDATE`, service).Scan(&disabled); e != nil {
			return keyError(e)
		}
		if disabled.Valid {
			return ErrDenied
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.service_credentials(kid,service_account_id,public_key,secret_reference,not_before,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, kid, service, []byte(public), reference, c.now(), expires); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `UPDATE identity.service_accounts SET disabled_at=$2 WHERE id::text=$1`, id, c.now()); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		table := "identity.service_credentials"
		if signing {
			table = "identity.signing_key_metadata"
		}
		if _, e := t.ExecContext(ctx, `UPDATE `+table+` SET revoked_at=$2 WHERE kid=$1`, kid, c.now()); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if _, e := t.ExecContext(ctx, `UPDATE identity.users SET status=$2 WHERE id::text=$1`, id, status); e != nil {
			return e
		}
		if disabled {
			if _, e := t.ExecContext(ctx, `UPDATE identity.sessions SET revoked_at=$2 WHERE user_id::text=$1`, id, c.now()); e != nil {
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
	e = c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		if workspace != "" {
			if _, e := workspaceRole(ctx, t, workspace, s.UserID); e != nil {
				return e
			}
		}
		if _, e := t.ExecContext(ctx, `INSERT INTO identity.agent_identities(id,owner_user_id,workspace_id,execution_scope) VALUES($1,$2,NULLIF($3,'')::uuid,$4)`, id, s.UserID, workspace, scope); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		role, e := workspaceRole(ctx, t, workspace, s.UserID)
		if e != nil {
			return e
		}
		if role == "owner" {
			var owners int
			if e = t.QueryRowContext(ctx, `SELECT count(*) FROM identity.memberships WHERE workspace_id::text=$1 AND role='owner' AND revoked_at IS NULL`, workspace).Scan(&owners); e != nil {
				return e
			}
			if owners <= 1 {
				return ErrDenied
			}
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.memberships SET revoked_at=$3 WHERE workspace_id::text=$1 AND user_id=$2`, workspace, s.UserID, c.now()); e != nil {
			return e
		}
		if _, e = t.ExecContext(ctx, `DELETE FROM identity.group_members WHERE workspace_id::text=$1 AND user_id=$2`, workspace, s.UserID); e != nil {
			return e
		}
		if _, e = t.ExecContext(ctx, `UPDATE identity.workspaces SET revision=revision+1 WHERE id::text=$1`, workspace); e != nil {
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
	return c.tx(ctx, func(t *sql.Tx) error {
		if e := c.lockSession(ctx, t, s); e != nil {
			return e
		}
		r, e := t.ExecContext(ctx, `UPDATE identity.agent_identities SET disabled_at=$3 WHERE id::text=$1 AND owner_user_id=$2`, id, s.UserID, c.now())
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrDenied
		}
		return audit(ctx, t, "user:"+s.UserID, "agents.disable", id, "ok")
	})
}

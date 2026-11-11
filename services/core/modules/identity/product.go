package identity

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"gorm.io/gorm"
)

// ProductRequest carries the browser credential separately from user input.
// Gate authenticates as a service and the Core resolves the user online.
type ProductRequest[T any] struct {
	Session UserSession `json:"session"`
	Input   T           `json:"input"`
}

type Profile struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type Workspace struct {
	ID       string `json:"id"`
	RootID   string `json:"acl_root_id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Revision int64  `json:"revision"`
}

type Member struct {
	Profile
	Role string `json:"role"`
}

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type TaskRoot struct {
	ID       string `json:"id"`
	CanWrite bool   `json:"can_write"`
}

type Page struct {
	After string `json:"after,omitempty"`
}

type WorkspaceInput struct {
	WorkspaceID string `json:"workspace_id"`
}

type WorkspaceCreate struct {
	Name string `json:"name"`
}

type WorkspacePage struct {
	WorkspaceInput
	Page
}

type WorkspaceUpdate struct {
	WorkspaceInput
	Name     string `json:"name"`
	Revision int64  `json:"revision"`
}

type MembershipChange struct {
	WorkspaceInput
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

type GroupChange struct {
	WorkspaceInput
	GroupID string `json:"group_id,omitempty"`
	Name    string `json:"name,omitempty"`
}

type GroupMemberChange struct {
	WorkspaceInput
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

type GroupPage struct {
	WorkspaceInput
	Page
	GroupID string `json:"group_id"`
}

type ProvisionUser struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var productID = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

func productInvalid() error {
	return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Identity input"}
}
func productNotFound() error { return &rpc.Error{Code: rpc.CodeNotFound, Message: "not found"} }

func productName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return "", productInvalid()
	}
	return name, nil
}

func (c *Core) productRole(ctx context.Context, workspace, user string, manager bool) (string, error) {
	if !productID.MatchString(workspace) {
		return "", productInvalid()
	}
	var role string
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT m.role FROM identity_memberships m
		JOIN identity_workspaces w ON w.id=m.workspace_id AND w.archived_at IS NULL
		WHERE m.workspace_id=? AND m.user_id=? AND m.revoked_at IS NULL`, workspace, user).Row().Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", productNotFound()
	}
	if err != nil {
		return "", ErrUnavailable
	}
	if manager && role != "owner" && role != "admin" {
		return "", ErrDenied
	}
	return role, nil
}

func (c *Core) profile(ctx context.Context, user string) (Profile, error) {
	var out Profile
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT id,email FROM identity_users WHERE id=? AND status='active'`, user).
		Row().Scan(&out.ID, &out.Email)
	return out, keyError(err)
}

func (c *Core) workspaces(ctx context.Context, user string, q Page) ([]Workspace, error) {
	out := []Workspace{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT w.id,COALESCE(w.acl_root_id,'') AS root_id,w.name,w.revision,m.role
		FROM identity_workspaces w JOIN identity_memberships m ON m.workspace_id=w.id
		WHERE m.user_id=? AND m.revoked_at IS NULL AND w.archived_at IS NULL AND w.id>? ORDER BY w.id LIMIT 100`, user, q.After).Scan(&out).Error
	return out, err
}

func (c *Core) workspace(ctx context.Context, user string, q WorkspaceInput) (Workspace, error) {
	role, err := c.productRole(ctx, q.WorkspaceID, user, false)
	if err != nil {
		return Workspace{}, err
	}
	out := Workspace{ID: q.WorkspaceID, Role: role}
	err = c.db(ctx).WithContext(ctx).Raw(`SELECT name,revision,COALESCE(acl_root_id,'') FROM identity_workspaces WHERE id=?`, q.WorkspaceID).
		Row().Scan(&out.Name, &out.Revision, &out.RootID)
	return out, err
}

func (c *Core) updateWorkspace(ctx context.Context, user string, q WorkspaceUpdate) (Workspace, error) {
	name, err := productName(q.Name)
	if err != nil || q.Revision < 1 {
		return Workspace{}, productInvalid()
	}
	db := c.db(ctx).WithContext(ctx)
	updated := db.Exec(`UPDATE identity_workspaces SET name=?,revision=revision+1 WHERE id=? AND revision=?`, name, q.WorkspaceID, q.Revision)
	if updated.Error != nil {
		return Workspace{}, updated.Error
	}
	if updated.RowsAffected != 1 {
		return Workspace{}, ErrConflict
	}
	if err := audit(ctx, db, "user:"+user, "workspaces.update", q.WorkspaceID, "ok"); err != nil {
		return Workspace{}, err
	}
	return c.workspace(ctx, user, q.WorkspaceInput)
}

func (c *Core) members(ctx context.Context, user string, q WorkspacePage) ([]Member, error) {
	if _, err := c.productRole(ctx, q.WorkspaceID, user, false); err != nil {
		return nil, err
	}
	out := []Member{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT u.id,u.email,m.role FROM identity_memberships m
		JOIN identity_users u ON u.id=m.user_id WHERE m.workspace_id=? AND m.revoked_at IS NULL
		AND u.status='active' AND u.id>? ORDER BY u.id LIMIT 100`, q.WorkspaceID, q.After).Scan(&out).Error
	return out, err
}

func (c *Core) groups(ctx context.Context, user string, q WorkspacePage) ([]Group, error) {
	if _, err := c.productRole(ctx, q.WorkspaceID, user, false); err != nil {
		return nil, err
	}
	out := []Group{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT id,name FROM identity_groups
		WHERE workspace_id=? AND id>? ORDER BY id LIMIT 100`, q.WorkspaceID, q.After).Scan(&out).Error
	return out, err
}

func (c *Core) taskRoots(ctx context.Context, user string, q WorkspacePage) ([]TaskRoot, error) {
	if _, err := c.productRole(ctx, q.WorkspaceID, user, false); err != nil {
		return nil, err
	}
	if c.TaskRoots == nil {
		return nil, ErrUnavailable
	}
	return c.TaskRoots(ctx, user, q.WorkspaceID, q.After)
}

func (c *Core) groupMembers(ctx context.Context, user string, q GroupPage) ([]Profile, error) {
	if _, err := c.productRole(ctx, q.WorkspaceID, user, false); err != nil {
		return nil, err
	}
	if err := c.checkProductGroup(ctx, q.WorkspaceID, q.GroupID); err != nil {
		return nil, err
	}
	out := []Profile{}
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT u.id,u.email FROM identity_group_members g
		JOIN identity_memberships m ON m.workspace_id=g.workspace_id AND m.user_id=g.user_id
		JOIN identity_users u ON u.id=g.user_id WHERE g.workspace_id=? AND g.group_id=?
		AND m.revoked_at IS NULL AND u.status='active' AND u.id>? ORDER BY u.id LIMIT 100`, q.WorkspaceID, q.GroupID, q.After).Scan(&out).Error
	return out, err
}

func (c *Core) checkProductGroup(ctx context.Context, workspace, group string) error {
	if !productID.MatchString(group) {
		return productInvalid()
	}
	var exists bool
	if err := c.db(ctx).WithContext(ctx).Raw(`SELECT EXISTS(SELECT 1 FROM identity_groups WHERE workspace_id=? AND id=?)`, workspace, group).Row().Scan(&exists); err != nil {
		return ErrUnavailable
	}
	if !exists {
		return productNotFound()
	}
	return nil
}

func (c *Core) changeGroup(ctx context.Context, user string, q GroupChange, remove bool) (Group, error) {
	if err := c.checkProductGroup(ctx, q.WorkspaceID, q.GroupID); err != nil {
		return Group{}, err
	}
	db := c.db(ctx).WithContext(ctx)
	out := Group{ID: q.GroupID}
	op := "groups.update"
	if remove {
		op = "groups.delete"
		if err := db.Exec(`DELETE FROM identity_group_members WHERE workspace_id=? AND group_id=?`, q.WorkspaceID, q.GroupID).Error; err != nil {
			return Group{}, err
		}
		if err := db.Exec(`DELETE FROM identity_groups WHERE workspace_id=? AND id=?`, q.WorkspaceID, q.GroupID).Error; err != nil {
			return Group{}, err
		}
	} else {
		name, err := productName(q.Name)
		if err != nil {
			return Group{}, err
		}
		if err := db.Exec(`UPDATE identity_groups SET name=? WHERE workspace_id=? AND id=?`, name, q.WorkspaceID, q.GroupID).Error; err != nil {
			return Group{}, err
		}
		out.Name = name
	}
	if err := db.Exec(`UPDATE identity_workspaces SET revision=revision+1 WHERE id=?`, q.WorkspaceID).Error; err != nil {
		return Group{}, err
	}
	return out, audit(ctx, db, "user:"+user, op, q.WorkspaceID+":"+q.GroupID, "ok")
}

func bindProductRead[Q, R any](s *sdk.Service, c *Core, name string, read func(context.Context, string, Q) (R, error)) error {
	return bindOperation(s, c, "product."+name, false, func(ctx context.Context, req ProductRequest[Q]) (R, error) {
		var out R
		err := c.db(ctx).WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			ctx := database.TransactionContext(ctx, c.GormDB, tx)
			user, err := c.user(ctx, req.Session)
			if err != nil {
				return err
			}
			out, err = read(ctx, user.UserID, req.Input)
			return err
		})
		return out, err
	})
}

func (q WorkspaceInput) workspaceID() string { return q.WorkspaceID }

func bindProductWrite[Q interface{ workspaceID() string }, R any](s *sdk.Service, c *Core, name string, manager bool, write func(context.Context, Session, ProductRequest[Q]) (R, error)) error {
	name = "product." + name
	return bindOperation(s, c, name, true, func(ctx context.Context, req ProductRequest[Q]) (R, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			var zero R
			return zero, err
		}
		return runCommand(ctx, c, user, "identity.v1."+name, func(ctx context.Context) error {
			_, err := c.productRole(ctx, req.Input.workspaceID(), user.UserID, manager)
			return err
		}, func(ctx context.Context) (R, error) { return write(ctx, user, req) })
	})
}

func (c *Core) bindProduct(s *sdk.Service) error {
	registrations := []func() error{
		func() error { return c.bindAccount(s) },
		func() error { return c.bindProductWorkspaceCreate(s) },
		func() error { return c.bindProductWorkspaceArchive(s) },
		func() error { return bindProductWrite(s, c, "invitations.create", true, c.createInvitation) },
		func() error { return bindProductWrite(s, c, "invitations.revoke", true, c.revokeInvitation) },
		func() error { return bindProductRead(s, c, "invitations.list", c.invitations) },
		func() error { return c.bindInvitationAccept(s) },
		func() error { return c.bindProductProvision(s) },
		func() error {
			return bindProductRead(s, c, "profile", func(ctx context.Context, user string, _ Empty) (Profile, error) { return c.profile(ctx, user) })
		},
		func() error { return bindProductRead(s, c, "workspaces.list", c.workspaces) },
		func() error { return bindProductRead(s, c, "workspaces.get", c.workspace) },
		func() error { return bindProductRead(s, c, "members.list", c.members) },
		func() error { return bindProductRead(s, c, "groups.list", c.groups) },
		func() error { return bindProductRead(s, c, "task_roots.list", c.taskRoots) },
		func() error { return bindProductRead(s, c, "groups.members.list", c.groupMembers) },
		func() error {
			return bindProductWrite(s, c, "workspaces.update", true, func(ctx context.Context, user Session, req ProductRequest[WorkspaceUpdate]) (Workspace, error) {
				return c.updateWorkspace(ctx, user.UserID, req.Input)
			})
		},
		func() error {
			return bindProductWrite(s, c, "workspaces.leave", false, func(ctx context.Context, _ Session, req ProductRequest[WorkspaceInput]) (Empty, error) {
				return Empty{}, c.LeaveWorkspace(ctx, req.Session, req.Input.WorkspaceID)
			})
		},
		func() error { return c.bindProductMembership(s, false) },
		func() error { return c.bindProductMembership(s, true) },
		func() error {
			return bindProductWrite(s, c, "groups.create", true, func(ctx context.Context, _ Session, req ProductRequest[GroupChange]) (Group, error) {
				name, err := productName(req.Input.Name)
				if err != nil || req.Input.GroupID != "" {
					return Group{}, productInvalid()
				}
				id, err := c.CreateGroup(ctx, req.Session, req.Input.WorkspaceID, name)
				return Group{ID: id, Name: name}, err
			})
		},
		func() error { return c.bindProductGroup(s, false) },
		func() error { return c.bindProductGroup(s, true) },
		func() error { return c.bindProductGroupMember(s, false) },
		func() error { return c.bindProductGroupMember(s, true) },
	}
	for _, register := range registrations {
		if err := register(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Core) bindProductWorkspaceCreate(s *sdk.Service) error {
	const name = "product.workspaces.create"
	return bindOperation(s, c, name, true, func(ctx context.Context, req ProductRequest[WorkspaceCreate]) (Workspace, error) {
		if c.CreateWorkspaceRoot == nil {
			return Workspace{}, ErrUnavailable
		}
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Workspace{}, err
		}
		nameInput, err := productName(req.Input.Name)
		if err != nil {
			return Workspace{}, err
		}
		id, err := runCommand(ctx, c, user, "identity.v1."+name, nil, func(ctx context.Context) (string, error) {
			return c.CreateWorkspace(ctx, req.Session, nameInput)
		})
		if err != nil {
			return Workspace{}, err
		}
		return c.workspace(ctx, user.UserID, WorkspaceInput{WorkspaceID: id})
	})
}

func (c *Core) bindProductProvision(s *sdk.Service) error {
	const name = "product.users.provision"
	const op = "identity.v1." + name
	return bindOperation(s, c, name, true, func(ctx context.Context, req ProductRequest[ProvisionUser]) (Profile, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Profile{}, err
		}
		return runCommand(ctx, c, user, op, func(ctx context.Context) error {
			return c.allow(ctx, Authorization{Actor: "user:" + user.UserID, Audience: "identity/v1", Operation: op})
		}, func(ctx context.Context) (Profile, error) {
			email := strings.ToLower(strings.TrimSpace(req.Input.Email))
			var exists bool
			if err := c.db(ctx).WithContext(ctx).Raw(`SELECT EXISTS(SELECT 1 FROM identity_users WHERE email=?)`, email).Row().Scan(&exists); err != nil {
				return Profile{}, ErrUnavailable
			}
			if exists {
				return Profile{}, ErrConflict
			}
			id, _, err := c.provisionUser(ctx, email, req.Input.Password, "user:"+user.UserID)
			return Profile{ID: id, Email: email}, err
		})
	})
}

func (c *Core) bindProductMembership(s *sdk.Service, remove bool) error {
	name := "members.set"
	if remove {
		name = "members.remove"
	}
	return bindProductWrite(s, c, name, true, func(ctx context.Context, _ Session, req ProductRequest[MembershipChange]) (Empty, error) {
		q := req.Input
		if !productID.MatchString(q.UserID) {
			return Empty{}, productInvalid()
		}
		if remove {
			q.Role = "member" // SetMembership authorizes the previous role on revocation.
		}
		return Empty{}, c.SetMembership(ctx, req.Session, q.WorkspaceID, q.UserID, q.Role, remove)
	})
}

func (c *Core) bindProductGroup(s *sdk.Service, remove bool) error {
	name := "groups.update"
	if remove {
		name = "groups.delete"
	}
	return bindProductWrite(s, c, name, true, func(ctx context.Context, user Session, req ProductRequest[GroupChange]) (Group, error) {
		return c.changeGroup(ctx, user.UserID, req.Input, remove)
	})
}

func (c *Core) bindProductGroupMember(s *sdk.Service, remove bool) error {
	name := "groups.members.add"
	if remove {
		name = "groups.members.remove"
	}
	return bindProductWrite(s, c, name, true, func(ctx context.Context, user Session, req ProductRequest[GroupMemberChange]) (Empty, error) {
		q := req.Input
		if !productID.MatchString(q.UserID) {
			return Empty{}, productInvalid()
		}
		if err := c.checkProductGroup(ctx, q.WorkspaceID, q.GroupID); err != nil {
			return Empty{}, err
		}
		if !remove && q.UserID == user.UserID {
			return Empty{}, ErrDenied
		}
		return Empty{}, c.SetGroupMember(ctx, req.Session, q.WorkspaceID, q.GroupID, q.UserID, remove)
	})
}

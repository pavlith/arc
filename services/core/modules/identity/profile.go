package identity

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/mattn/go-sqlite3"
	"github.com/pavlith/arc/sdk"
)

type ProfileUpdate struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Revision    int64  `json:"revision"`
}
type WorkspaceSlugInput struct {
	Slug string `json:"slug"`
}

var workspaceSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func validWorkspaceSlug(slug, id string) bool {
	if slug == id && productID.MatchString(id) {
		return true
	}
	if !workspaceSlugPattern.MatchString(slug) || productID.MatchString(slug) {
		return false
	}
	switch slug {
	case "api", "login", "logout", "invite", "share", "forgot-password", "reset-password", "workspace-setup", "assets", "healthz", "readyz":
		return false
	}
	return true
}
func identityWriteError(err error) error {
	var sqlErr sqlite3.Error
	if errors.As(err, &sqlErr) && (sqlErr.ExtendedCode == sqlite3.ErrConstraintUnique || sqlErr.ExtendedCode == sqlite3.ErrConstraintPrimaryKey) {
		return ErrConflict
	}
	return err
}
func (c *Core) selfProfile(ctx context.Context, user string, _ Empty) (SelfProfile, error) {
	p, err := c.profile(ctx, user)
	if err != nil {
		return SelfProfile{}, err
	}
	out := SelfProfile{Profile: p}
	err = c.allow(ctx, Authorization{Actor: "user:" + user, Audience: "identity/v1", Operation: "identity.v1.product.users.list"})
	if err == nil {
		out.IsSysadmin = true
	} else if !errors.Is(err, ErrDenied) {
		return SelfProfile{}, err
	}
	return out, nil
}
func (c *Core) workspaceBySlug(ctx context.Context, user string, q WorkspaceSlugInput) (Workspace, error) {
	if !workspaceSlugPattern.MatchString(q.Slug) {
		return Workspace{}, productInvalid()
	}
	var id string
	err := c.db(ctx).WithContext(ctx).Raw(`SELECT id FROM identity_workspaces WHERE COALESCE(slug,id)=? AND archived_at IS NULL`, q.Slug).Row().Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, productNotFound()
	}
	if err != nil {
		return Workspace{}, ErrUnavailable
	}
	return c.workspace(ctx, user, WorkspaceInput{WorkspaceID: id})
}
func (c *Core) bindProfileSettings(s *sdk.Service) error {
	return bindOperation(s, c, "product.account.profile.update", true, func(ctx context.Context, req ProductRequest[ProfileUpdate]) (Profile, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Profile{}, err
		}
		q := req.Input
		q.Name = strings.TrimSpace(q.Name)
		q.DisplayName = strings.TrimSpace(q.DisplayName)
		if q.Name == "" || q.DisplayName == "" || len(q.Name) > 128 || len(q.DisplayName) > 128 || q.Revision < 1 {
			return Profile{}, productInvalid()
		}
		return runCommand(ctx, c, user, "identity.v1.product.account.profile.update", nil, func(ctx context.Context) (Profile, error) {
			db := c.db(ctx).WithContext(ctx)
			result := db.Exec(`UPDATE identity_users SET name=?,display_name=?,profile_revision=profile_revision+1 WHERE id=? AND status='active' AND profile_revision=?`, q.Name, q.DisplayName, user.UserID, q.Revision)
			if result.Error != nil {
				return Profile{}, ErrUnavailable
			}
			if result.RowsAffected != 1 {
				return Profile{}, ErrConflict
			}
			if err := audit(ctx, db, "user:"+user.UserID, "users.profile", user.UserID, "ok"); err != nil {
				return Profile{}, ErrUnavailable
			}
			return c.profile(ctx, user.UserID)
		})
	})
}

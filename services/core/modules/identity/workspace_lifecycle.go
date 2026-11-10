package identity

import (
	"context"

	"github.com/pavlith/arc/sdk"
)

func (c *Core) bindProductWorkspaceArchive(s *sdk.Service) error {
	const name = "product.workspaces.archive"
	return bindOperation(s, c, name, true, func(ctx context.Context, req ProductRequest[WorkspaceInput]) (Empty, error) {
		user, err := c.user(ctx, req.Session)
		if err != nil {
			return Empty{}, err
		}
		// Replay only acknowledges the completed archive to its original actor.
		return runCommand(ctx, c, user, "identity.v1."+name, nil, func(ctx context.Context) (Empty, error) {
			return Empty{}, c.archiveWorkspace(ctx, user.UserID, req.Input.WorkspaceID)
		})
	})
}

func (c *Core) archiveWorkspace(ctx context.Context, user, workspace string) error {
	role, err := c.productRole(ctx, workspace, user, true)
	if err != nil {
		return err
	}
	if role != "owner" {
		return ErrDenied
	}
	if c.ArchiveWorkspaceRoot == nil {
		return ErrUnavailable
	}
	if err := c.ArchiveWorkspaceRoot(ctx, workspace, user); err != nil {
		return err
	}
	db := c.db(ctx).WithContext(ctx)
	now := c.now()
	if err := db.Exec(`UPDATE identity_workspaces SET archived_at=?,revision=revision+1 WHERE id=?`, now, workspace).Error; err != nil {
		return ErrUnavailable
	}
	if err := db.Exec(`UPDATE identity_memberships SET revoked_at=? WHERE workspace_id=? AND revoked_at IS NULL`, now, workspace).Error; err != nil {
		return ErrUnavailable
	}
	if err := db.Exec(`DELETE FROM identity_group_members WHERE workspace_id=?`, workspace).Error; err != nil {
		return ErrUnavailable
	}
	if err := db.Exec(`UPDATE identity_workspace_invitations SET revoked_at=?
		WHERE workspace_id=? AND consumed_at IS NULL AND revoked_at IS NULL`, now, workspace).Error; err != nil {
		return ErrUnavailable
	}
	return audit(ctx, db, "user:"+user, "workspaces.archive", workspace, "ok")
}

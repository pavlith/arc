package access

import (
	"context"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
)

const (
	workspaceRootType     = "arc.workspace"
	workspaceRootAccount  = "00000000-0000-4000-8000-00000000a001"
	workspaceRootDigest   = "0000000000000000000000000000000000000000000000000000000000000000"
	workspaceManageAction = "arc.workspace.manage"
)

// CreateWorkspaceRoot joins Identity's owner transaction after the workspace and
// its owner membership have been inserted. Core registers this type locally.
func (c *Core) CreateWorkspaceRoot(ctx context.Context, workspace, owner string) error {
	if c == nil || c.GormDB == nil || !validUUID(workspace) || !validUUID(owner) {
		return ErrUnavailable
	}
	tx := database.FromContext(ctx, c.GormDB)
	if tx == c.GormDB {
		return ErrUnavailable
	}
	tx = tx.WithContext(ctx)
	var activeOwner bool
	if err := tx.Raw(`SELECT EXISTS(SELECT 1 FROM identity_memberships m JOIN identity_users u ON u.id=m.user_id
		WHERE m.workspace_id=? AND m.user_id=? AND m.role='owner' AND m.revoked_at IS NULL AND u.status='active')`, workspace, owner).
		Row().Scan(&activeOwner); err != nil {
		return ErrUnavailable
	}
	if !activeOwner {
		return ErrDenied
	}
	caller := workspaceRootAccount
	if claims, ok := rpc.VerifiedClaims(ctx); ok {
		if !validUUID(claims.Caller) {
			return ErrDenied
		}
		caller = claims.Caller
	}
	var revision int64
	if err := tx.Raw(`UPDATE access_policy_state SET revision=revision+1 WHERE singleton=1 RETURNING revision`).Row().Scan(&revision); err != nil {
		return ErrUnavailable
	}
	if err := tx.Exec(`INSERT INTO access_resources(id,type,provider_service,owner_kind,owner_id,workspace_id,inherit_acl,state,policy_revision)
		VALUES(?,?,?,'workspace',?,?,0,'active',?)`, workspace, workspaceRootType, workspaceRootAccount, workspace, workspace, revision).Error; err != nil {
		return ErrUnavailable
	}
	if err := tx.Exec(`INSERT INTO access_policy_audit(actor,caller,operation,resource_id,policy_revision,change_kind)
		VALUES(?,?,'workspaces.create_root',?,?,'workspace_root_created')`, "user:"+owner, caller, workspace, revision).Error; err != nil {
		return ErrUnavailable
	}
	return nil
}

// ArchiveWorkspaceRoot changes only the Core-owned root inside Identity's
// archive transaction. Domain and personal content is retained.
func (c *Core) ArchiveWorkspaceRoot(ctx context.Context, workspace, owner string) error {
	if c == nil || c.GormDB == nil || !validUUID(workspace) || !validUUID(owner) {
		return ErrUnavailable
	}
	tx := database.FromContext(ctx, c.GormDB)
	claims, ok := rpc.VerifiedClaims(ctx)
	if tx == c.GormDB || !ok || !validUUID(claims.Caller) {
		return ErrDenied
	}
	tx = tx.WithContext(ctx)
	var revision int64
	if err := tx.Raw(`UPDATE access_policy_state SET revision=revision+1 WHERE singleton=1 RETURNING revision`).Row().Scan(&revision); err != nil {
		return ErrUnavailable
	}
	now := c.now()
	res := tx.Exec(`UPDATE access_resources SET state='deleting',policy_revision=?,updated_at=?
		WHERE id=? AND workspace_id=? AND type=? AND provider_service=? AND state='active'
		AND EXISTS(SELECT 1 FROM identity_memberships WHERE workspace_id=? AND user_id=? AND role='owner' AND revoked_at IS NULL)`,
		revision, now, workspace, workspace, workspaceRootType, workspaceRootAccount, workspace, owner)
	if res.Error != nil {
		return ErrUnavailable
	}
	if res.RowsAffected != 1 {
		return ErrDenied
	}
	if err := tx.Exec(`UPDATE access_resources SET state='deleted' WHERE id=?`, workspace).Error; err != nil {
		return ErrUnavailable
	}
	if err := tx.Exec(`INSERT INTO access_policy_audit(actor,caller,operation,resource_id,policy_revision,change_kind)
		VALUES(?,?,'workspaces.archive_root',?,?,'workspace_root_archived')`, "user:"+owner, claims.Caller, workspace, revision).Error; err != nil {
		return ErrUnavailable
	}
	return nil
}

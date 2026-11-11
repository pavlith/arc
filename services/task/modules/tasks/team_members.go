package tasks

import (
	"context"
	"time"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/models"
	"gorm.io/gorm"
)

func (s *Service) changeTeamMember(ctx context.Context, tx *gorm.DB, q taskv1.TeamMemberChange, remove bool) (taskv1.CatalogMutationResult, error) {
	team, err := catalogTeam(ctx, tx, q.TeamScope)
	if err != nil {
		return taskv1.CatalogMutationResult{}, err
	}
	if q.Revision < 1 {
		return taskv1.CatalogMutationResult{}, invalidCatalog()
	}
	if team.Revision != q.Revision {
		return taskv1.CatalogMutationResult{}, catalogConflict()
	}
	if !remove {
		checkCtx, err := InvocationContext(ctx, s.Identity, identity.Target{Audience: "access/v1", Operation: "access.v1.principals.validate_users"})
		if err != nil {
			return taskv1.CatalogMutationResult{}, err
		}
		res, err := (&access.Client{RPC: s.Identity.RPC}).ValidateUsers(checkCtx, access.ValidateUsersRequest{ResourceID: q.RootID, ActorAction: "access.grants.manage", UserAction: "task.read", UserIDs: []string{q.UserID}})
		if err != nil {
			return taskv1.CatalogMutationResult{}, err
		}
		if !res.Valid {
			return taskv1.CatalogMutationResult{}, security.ErrDenied
		}
		if err := tx.WithContext(ctx).Create(&models.TeamMember{TeamID: q.TeamID, WorkspaceID: q.WorkspaceID, RootID: q.RootID, UserID: q.UserID, CreatedAt: time.Now().UTC()}).Error; err != nil {
			return taskv1.CatalogMutationResult{}, catalogError(err)
		}
	} else {
		res := tx.WithContext(ctx).Where("team_id=? AND user_id=? AND workspace_id=? AND acl_root_id=?", q.TeamID, q.UserID, q.WorkspaceID, q.RootID).Delete(&models.TeamMember{})
		if res.Error != nil {
			return taskv1.CatalogMutationResult{}, catalogError(res.Error)
		}
		if res.RowsAffected != 1 {
			return taskv1.CatalogMutationResult{}, catalogConflict()
		}
	}
	team.Revision++
	team.UpdatedAt = time.Now().UTC()
	if err := tx.WithContext(ctx).Save(&team).Error; err != nil {
		return taskv1.CatalogMutationResult{}, catalogError(err)
	}
	return taskv1.CatalogMutationResult{Scope: q.Scope, ID: team.ID, Revision: team.Revision, UpdatedAt: team.UpdatedAt}, s.catalogChanged(ctx, tx, q.Scope, "team", team.ID, team.Revision)
}
func (s *Service) addTeamMember(ctx context.Context, tx *gorm.DB, q taskv1.TeamMemberChange) (taskv1.CatalogMutationResult, error) {
	return s.changeTeamMember(ctx, tx, q, false)
}
func (s *Service) removeTeamMember(ctx context.Context, tx *gorm.DB, q taskv1.TeamMemberChange) (taskv1.CatalogMutationResult, error) {
	return s.changeTeamMember(ctx, tx, q, true)
}
func (s *Service) listTeamMembers(ctx context.Context, q taskv1.TeamMemberPage) (taskv1.TeamMembersResult, error) {
	out := taskv1.TeamMembersResult{Members: []taskv1.TeamMember{}}
	if q.Limit < 1 || q.Limit > 100 {
		return out, invalidCatalog()
	}
	if _, err := catalogTeam(ctx, s.GormDB, q.TeamScope); err != nil {
		return out, err
	}
	var rows []models.TeamMember
	if err := s.GormDB.WithContext(ctx).Where("team_id=? AND workspace_id=? AND acl_root_id=? AND user_id>?", q.TeamID, q.WorkspaceID, q.RootID, q.Cursor).Order("user_id").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return out, catalogError(err)
	}
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
		out.NextCursor = rows[len(rows)-1].UserID
	}
	for _, row := range rows {
		out.Members = append(out.Members, taskv1.TeamMember{UserID: row.UserID, CreatedAt: row.CreatedAt})
	}
	return out, nil
}

package tasks

import (
	"context"

	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

// Triage is an explicit one-way decision from the Team backlog. Reusing the
// normal update ensures revision checks, reference/assignee validation, audit,
// idempotent replay and metadata-only outbox invalidation stay identical.
func (s *Service) triageWork(ctx context.Context, tx *gorm.DB, q taskv1.WorkTriageRequest) (taskv1.WorkItem, error) {
	if q.Revision < 1 || q.ExpectedUpdatedAt.IsZero() || q.StatusID == "" {
		return taskv1.WorkItem{}, invalidWork()
	}
	current, err := workItem(ctx, tx, q.GetRequest)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	if current.TeamID == "" || current.Status != "backlog" ||
		current.Revision != q.Revision || !current.UpdatedAt.Equal(q.ExpectedUpdatedAt) {
		return taskv1.WorkItem{}, catalogConflict()
	}
	destination, err := catalogStatus(ctx, tx, taskv1.TeamScope{Scope: q.Scope, TeamID: current.TeamID}, q.StatusID)
	if err != nil {
		return taskv1.WorkItem{}, err
	}
	if destination.Category != "todo" && destination.Category != "cancelled" {
		return taskv1.WorkItem{}, invalidWork()
	}
	in := taskv1.WorkInput{
		Title: current.Title, TeamID: current.TeamID, StatusID: destination.ID,
		Description: current.Description, Priority: current.Priority, DueDate: current.DueDate,
		SortOrder: current.SortOrder, ProjectID: current.ProjectID,
		LabelIDs: current.LabelIDs, AssigneeIDs: current.AssigneeIDs,
	}
	return s.updateWork(ctx, tx, taskv1.WorkUpdateRequest{
		GetRequest: q.GetRequest, WorkInput: in,
		Revision: q.Revision, ExpectedUpdatedAt: q.ExpectedUpdatedAt,
	})
}

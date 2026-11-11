package tasks

import (
	"context"
	"encoding/json"

	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

// All items use the operation's one verified root; no item can override its scope.
// The shared command store owns the complete transaction and replay record.
func (s *Service) bulkUpdateWork(ctx context.Context, tx *gorm.DB, q taskv1.BulkUpdateRequest) (taskv1.BulkUpdateResult, error) {
	empty := taskv1.BulkUpdateResult{}
	if len(q.Items) < 1 || len(q.Items) > 20 {
		return empty, invalidWork()
	}
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > 180000 {
		return empty, invalidWork()
	}
	seen := map[string]bool{}
	for _, item := range q.Items {
		if item.TaskID == "" || seen[item.TaskID] || item.Revision < 1 || item.ExpectedUpdatedAt.IsZero() {
			return empty, invalidWork()
		}
		seen[item.TaskID] = true
		if err := validateWork(item.WorkInput); err != nil {
			return empty, err
		}
	}
	out := taskv1.BulkUpdateResult{Items: []taskv1.WorkVersion{}}
	for _, item := range q.Items {
		updated, err := s.updateWork(ctx, tx, taskv1.WorkUpdateRequest{GetRequest: taskv1.GetRequest{Scope: q.Scope, TaskID: item.TaskID}, WorkInput: item.WorkInput, Revision: item.Revision, ExpectedUpdatedAt: item.ExpectedUpdatedAt})
		if err != nil {
			return empty, err
		}
		out.Items = append(out.Items, taskv1.WorkVersion{TaskID: item.TaskID, Revision: updated.Revision, UpdatedAt: updated.UpdatedAt})
	}
	return out, nil
}

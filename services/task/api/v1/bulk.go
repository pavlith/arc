package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type BulkWorkItem struct {
	WorkInput
	TaskID            string    `json:"task_id"`
	Revision          int64     `json:"revision"`
	ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
}
type BulkUpdateRequest struct {
	Scope
	Items []BulkWorkItem `json:"items"`
}
type WorkVersion struct {
	TaskID    string    `json:"task_id"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}
type BulkUpdateResult struct {
	Items []WorkVersion `json:"items"`
}

var WorkBulkUpdate = module.Command[BulkUpdateRequest, BulkUpdateResult]{ID: "task.work.bulk_update"}

package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type WorkItem struct {
	ParentID string `json:"parent_id,omitempty"`
	Task
	TeamID      string     `json:"team_id,omitempty"`
	StatusID    string     `json:"status_id,omitempty"`
	Identifier  string     `json:"identifier"`
	ProjectID   string     `json:"project_id,omitempty"`
	LabelIDs    []string   `json:"label_ids"`
	Description string     `json:"description"`
	Priority    int        `json:"priority"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	SortOrder   int64      `json:"sort_order"`
	AssigneeIDs []string   `json:"assignee_ids"`
	Revision    int64      `json:"revision"`
	Archived    bool       `json:"archived"`
}
type WorkInput struct {
	ProjectID   string     `json:"project_id,omitempty"`
	LabelIDs    []string   `json:"label_ids,omitempty"`
	Title       string     `json:"title"`
	TeamID      string     `json:"team_id"`
	StatusID    string     `json:"status_id,omitempty"`
	Description string     `json:"description"`
	Priority    int        `json:"priority"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	SortOrder   int64      `json:"sort_order"`
	AssigneeIDs []string   `json:"assignee_ids,omitempty"`
}
type WorkCreateRequest struct {
	Scope
	WorkInput
}
type WorkUpdateRequest struct {
	GetRequest
	WorkInput
	Revision          int64     `json:"revision"`
	ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
}
type WorkArchiveRequest struct {
	GetRequest
	Revision          int64     `json:"revision"`
	ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
}
type ArchivedItem struct {
	Scope
	ID        string    `json:"id"`
	TeamID    string    `json:"team_id,omitempty"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	UpdatedAt time.Time `json:"updated_at"`
}
type WorkListRequest struct {
	ParentID  string `json:"parent_id,omitempty"`
	TopLevel  bool   `json:"top_level,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	LabelID   string `json:"label_id,omitempty"`
	CatalogPage
	TeamID     string `json:"team_id,omitempty"`
	StatusID   string `json:"status_id,omitempty"`
	AssigneeID string `json:"assignee_id,omitempty"`
	Priority   *int   `json:"priority,omitempty"`
	Search     string `json:"search,omitempty"`
}
type WorkListResult struct {
	Tasks      []WorkItem `json:"tasks"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

var (
	WorkCreate  = module.Command[WorkCreateRequest, WorkItem]{ID: "task.work.create"}
	WorkUpdate  = module.Command[WorkUpdateRequest, WorkItem]{ID: "task.work.update"}
	WorkArchive = module.Command[WorkArchiveRequest, ArchivedItem]{ID: "task.work.archive"}
	WorkGet     = module.Query[GetRequest, WorkItem]{ID: "task.work.get"}
	WorkList    = module.Query[WorkListRequest, WorkListResult]{ID: "task.work.list"}
)

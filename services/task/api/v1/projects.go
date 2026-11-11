package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type ProjectInput struct {
	TeamID      string     `json:"team_id,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Color       string     `json:"color"`
	Status      string     `json:"status,omitempty"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
}
type Project struct {
	Scope
	ProjectInput
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type ProjectCreateRequest struct {
	Scope
	ProjectInput
}
type ProjectScope struct {
	Scope
	ProjectID string `json:"project_id"`
}
type ProjectUpdateRequest struct {
	ProjectScope
	ProjectInput
	Revision int64 `json:"revision"`
}
type ProjectArchiveRequest struct {
	ProjectScope
	Revision int64 `json:"revision"`
}
type ProjectsResult struct {
	Projects   []Project `json:"projects"`
	NextCursor string    `json:"next_cursor,omitempty"`
}
type ProjectListRequest struct {
	CatalogPage
	TeamID string `json:"team_id,omitempty"`
}
type LabelInput struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}
type Label struct {
	Scope
	LabelInput
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type LabelCreateRequest struct {
	Scope
	LabelInput
}
type LabelScope struct {
	Scope
	LabelID string `json:"label_id"`
}
type LabelUpdateRequest struct {
	LabelScope
	LabelInput
	Revision int64 `json:"revision"`
}
type LabelArchiveRequest struct {
	LabelScope
	Revision int64 `json:"revision"`
}
type LabelsResult struct {
	Labels     []Label `json:"labels"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

var (
	ProjectCreate  = module.Command[ProjectCreateRequest, Project]{ID: "task.projects.create"}
	ProjectUpdate  = module.Command[ProjectUpdateRequest, Project]{ID: "task.projects.update"}
	ProjectArchive = module.Command[ProjectArchiveRequest, ArchivedItem]{ID: "task.projects.archive"}
	ProjectGet     = module.Query[ProjectScope, Project]{ID: "task.projects.get"}
	ProjectList    = module.Query[ProjectListRequest, ProjectsResult]{ID: "task.projects.list"}
	LabelCreate    = module.Command[LabelCreateRequest, Label]{ID: "task.labels.create"}
	LabelUpdate    = module.Command[LabelUpdateRequest, Label]{ID: "task.labels.update"}
	LabelArchive   = module.Command[LabelArchiveRequest, ArchivedItem]{ID: "task.labels.archive"}
	LabelGet       = module.Query[LabelScope, Label]{ID: "task.labels.get"}
	LabelList      = module.Query[CatalogPage, LabelsResult]{ID: "task.labels.list"}
)

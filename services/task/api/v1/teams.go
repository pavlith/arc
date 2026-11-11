package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type Team struct {
	Scope
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Key         string    `json:"key"`
	Description string    `json:"description"`
	Color       string    `json:"color"`
	Revision    int64     `json:"revision"`
	Archived    bool      `json:"archived"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type TeamCreateRequest struct {
	Scope
	Name        string `json:"name"`
	Key         string `json:"key"`
	Description string `json:"description"`
	Color       string `json:"color"`
}
type TeamScope struct {
	Scope
	TeamID string `json:"team_id"`
}
type TeamUpdateRequest struct {
	TeamScope
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Revision    int64  `json:"revision"`
}
type TeamArchiveRequest struct {
	TeamScope
	Revision int64 `json:"revision"`
}
type CatalogPage struct {
	Scope
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}
type TeamsResult struct {
	Teams      []Team `json:"teams"`
	NextCursor string `json:"next_cursor,omitempty"`
}
type WorkflowStatus struct {
	TeamScope
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"`
	Color     string    `json:"color"`
	Position  int       `json:"position"`
	IsDefault bool      `json:"is_default"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type StatusCreateRequest struct {
	TeamScope
	Name      string `json:"name"`
	Category  string `json:"category"`
	Color     string `json:"color"`
	Position  int    `json:"position"`
	IsDefault bool   `json:"is_default"`
}
type StatusUpdateRequest struct {
	StatusCreateRequest
	StatusID string `json:"status_id"`
	Revision int64  `json:"revision"`
}
type StatusDeleteRequest struct {
	TeamScope
	StatusID string `json:"status_id"`
	Revision int64  `json:"revision"`
}
type StatusesResult struct {
	Statuses []WorkflowStatus `json:"statuses"`
}
type CatalogChanged struct {
	Scope
	EntityKind string `json:"entity_kind"`
	EntityID   string `json:"entity_id"`
	Revision   int64  `json:"revision"`
}

const CatalogChangedSubject = "evt.task.catalog.changed.v1"
const CatalogChangedName = "task.catalog.changed"

var (
	TeamCreate   = module.Command[TeamCreateRequest, Team]{ID: "task.teams.create"}
	TeamUpdate   = module.Command[TeamUpdateRequest, Team]{ID: "task.teams.update"}
	TeamArchive  = module.Command[TeamArchiveRequest, ArchivedItem]{ID: "task.teams.archive"}
	TeamGet      = module.Query[TeamScope, Team]{ID: "task.teams.get"}
	TeamList     = module.Query[CatalogPage, TeamsResult]{ID: "task.teams.list"}
	StatusCreate = module.Command[StatusCreateRequest, WorkflowStatus]{ID: "task.statuses.create"}
	StatusUpdate = module.Command[StatusUpdateRequest, WorkflowStatus]{ID: "task.statuses.update"}
	StatusDelete = module.Command[StatusDeleteRequest, ArchivedItem]{ID: "task.statuses.delete"}
	StatusList   = module.Query[TeamScope, StatusesResult]{ID: "task.statuses.list"}
)

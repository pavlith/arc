package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

type Comment struct {
	GetRequest
	ID        string    `json:"id"`
	ParentID  string    `json:"parent_id,omitempty"`
	AuthorID  string    `json:"author_id"`
	Body      string    `json:"body"`
	Resolved  bool      `json:"resolved"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type CommentCreateRequest struct {
	GetRequest
	Body     string `json:"body"`
	ParentID string `json:"parent_id,omitempty"`
}
type CommentScope struct {
	GetRequest
	CommentID string `json:"comment_id"`
}
type CommentUpdateRequest struct {
	CommentScope
	Body     string `json:"body"`
	Revision int64  `json:"revision"`
}
type CommentResolveRequest struct {
	CommentScope
	Resolved bool  `json:"resolved"`
	Revision int64 `json:"revision"`
}
type CommentArchiveRequest struct {
	CommentScope
	Revision int64 `json:"revision"`
}
type CommentPage struct {
	GetRequest
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}
type CommentsResult struct {
	Comments   []Comment `json:"comments"`
	NextCursor string    `json:"next_cursor,omitempty"`
}
type HistoryRequest struct {
	GetRequest
	Cursor int64 `json:"cursor,omitempty"`
	Limit  int   `json:"limit"`
}
type HistoryEntry struct {
	ID            int64     `json:"id"`
	Actor         string    `json:"actor"`
	Operation     string    `json:"operation"`
	EntityID      string    `json:"entity_id"`
	Revision      int64     `json:"revision"`
	FieldsChanged []string  `json:"fields_changed"`
	CreatedAt     time.Time `json:"created_at"`
}
type HistoryResult struct {
	History    []HistoryEntry `json:"history"`
	NextCursor int64          `json:"next_cursor,omitempty"`
}
type ViewFilters struct {
	TeamID     string `json:"team_id,omitempty"`
	StatusID   string `json:"status_id,omitempty"`
	AssigneeID string `json:"assignee_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	LabelID    string `json:"label_id,omitempty"`
	Priority   *int   `json:"priority,omitempty"`
	Search     string `json:"search,omitempty"`
	Layout     string `json:"layout,omitempty"`
	GroupBy    string `json:"group_by,omitempty"`
	Sort       string `json:"sort,omitempty"`
}
type ViewInput struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Filters     ViewFilters `json:"filters"`
	IsShared    bool        `json:"is_shared"`
}
type SavedView struct {
	Scope
	ViewInput
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type ViewScope struct {
	Scope
	ViewID string `json:"view_id"`
}
type ViewCreateRequest struct {
	Scope
	ViewInput
}
type ViewUpdateRequest struct {
	ViewScope
	ViewInput
	Revision int64 `json:"revision"`
}
type ViewArchiveRequest struct {
	ViewScope
	Revision int64 `json:"revision"`
}
type ViewsResult struct {
	Views      []SavedView `json:"views"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

var (
	CommentCreate  = module.Command[CommentCreateRequest, Comment]{ID: "task.comments.create"}
	CommentUpdate  = module.Command[CommentUpdateRequest, Comment]{ID: "task.comments.update"}
	CommentResolve = module.Command[CommentResolveRequest, CatalogMutationResult]{ID: "task.comments.resolve"}
	CommentArchive = module.Command[CommentArchiveRequest, ArchivedItem]{ID: "task.comments.archive"}
	CommentList    = module.Query[CommentPage, CommentsResult]{ID: "task.comments.list"}
	WorkHistory    = module.Query[HistoryRequest, HistoryResult]{ID: "task.work.history"}
	ViewCreate     = module.Command[ViewCreateRequest, SavedView]{ID: "task.views.create"}
	ViewUpdate     = module.Command[ViewUpdateRequest, SavedView]{ID: "task.views.update"}
	ViewArchive    = module.Command[ViewArchiveRequest, ArchivedItem]{ID: "task.views.archive"}
	ViewGet        = module.Query[ViewScope, SavedView]{ID: "task.views.get"}
	ViewList       = module.Query[CatalogPage, ViewsResult]{ID: "task.views.list"}
)

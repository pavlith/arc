package v1

import (
	"time"

	"github.com/pavlith/arc/sdk/module"
)

// Templates are shared inside a Task ACL root; Team is a business classification,
// not a second authorization boundary.
type TemplateInput struct {
	Name string `json:"name"`
	WorkInput
}
type WorkTemplate struct {
	Scope
	TemplateInput
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type TemplateCreateRequest struct {
	Scope
	TemplateInput
}
type TemplateScope struct {
	Scope
	TemplateID string `json:"template_id"`
}
type TemplateUpdateRequest struct {
	TemplateScope
	TemplateInput
	Revision int64 `json:"revision"`
}
type TemplateArchiveRequest struct {
	TemplateScope
	Revision int64 `json:"revision"`
}
type TemplateUseRequest struct {
	TemplateScope
	Title string `json:"title,omitempty"`
}
type TemplatesResult struct {
	Templates  []WorkTemplate `json:"templates"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

var (
	TemplateCreate  = module.Command[TemplateCreateRequest, WorkTemplate]{ID: "task.templates.create"}
	TemplateUpdate  = module.Command[TemplateUpdateRequest, WorkTemplate]{ID: "task.templates.update"}
	TemplateArchive = module.Command[TemplateArchiveRequest, ArchivedItem]{ID: "task.templates.archive"}
	TemplateGet     = module.Query[TemplateScope, WorkTemplate]{ID: "task.templates.get"}
	TemplateList    = module.Query[CatalogPage, TemplatesResult]{ID: "task.templates.list"}
	TemplateUse     = module.Command[TemplateUseRequest, WorkItem]{ID: "task.templates.use"}
)

package v1

import (
	"encoding/json"
	"time"

	"github.com/pavlith/arc/sdk/resource"
)

type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}
type PageRef struct {
	Scope
	PageID string `json:"page_id"`
}
type Metadata struct {
	Scope
	ID        string    `json:"id"`
	ParentID  string    `json:"parent_id,omitempty"`
	Title     string    `json:"title"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Page struct {
	Metadata
	Document json.RawMessage `json:"document"`
}
type Input struct {
	Title    string          `json:"title"`
	Document json.RawMessage `json:"document"`
}
type Create struct {
	Scope
	Input
	ParentID   string `json:"parent_id,omitempty"`
	TemplateID string `json:"template_id,omitempty"`
}
type Update struct {
	PageRef
	Input
	Revision int64 `json:"revision"`
}
type Move struct {
	PageRef
	ParentID string `json:"parent_id,omitempty"`
	Revision int64  `json:"revision"`
}
type Archive struct {
	PageRef
	Revision int64 `json:"revision"`
}
type List struct {
	Scope
	ParentID string `json:"parent_id,omitempty"`
	Query    string `json:"query,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit"`
}
type PageList struct {
	Pages      []Metadata `json:"pages"`
	NextCursor string     `json:"next_cursor,omitempty"`
}
type VersionRef struct {
	PageRef
	Version int64 `json:"version"`
}
type VersionList struct {
	PageRef
	Before int64 `json:"before,omitempty"`
	Limit  int   `json:"limit"`
}
type Version struct {
	Revision  int64     `json:"revision"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
}
type Versions struct {
	Versions   []Version `json:"versions"`
	NextBefore int64     `json:"next_before,omitempty"`
}
type Restore struct {
	VersionRef
	Revision int64 `json:"revision"`
}
type Preview struct {
	PageRef
	Target resource.Ref `json:"target"`
}
type Template struct {
	Scope
	ID string `json:"id"`
	Input
	Revision int64 `json:"revision"`
	Archived bool  `json:"archived"`
}
type TemplateRef struct {
	Scope
	TemplateID string `json:"template_id"`
}
type TemplateCreate struct {
	Scope
	Input
}
type TemplateUpdate struct {
	TemplateRef
	Input
	Revision int64 `json:"revision"`
}
type TemplateArchive struct {
	TemplateRef
	Revision int64 `json:"revision"`
}
type TemplateList struct {
	Templates  []TemplateSummary `json:"templates"`
	NextCursor string            `json:"next_cursor,omitempty"`
}
type Grant struct {
	Scope
	PrincipalID string `json:"principal_id,omitempty"`
	Action      string `json:"action,omitempty"`
	GrantID     string `json:"grant_id,omitempty"`
}
type GrantResult struct {
	ResourceID string `json:"resource_id,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	State      string `json:"state,omitempty"`
	Revision   int64  `json:"policy_revision"`
}
type Changed struct {
	Scope
	EntityID string `json:"entity_id"`
	Revision int64  `json:"revision"`
	Action   string `json:"action"`
}

const ChangedSubject = "evt.pages.catalog.changed.v1"
const ChangedName = "pages.catalog.changed"

type Mutation struct {
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	Archived  bool      `json:"archived"`
	UpdatedAt time.Time `json:"updated_at"`
}
type TemplateSummary struct {
	Scope
	ID       string `json:"id"`
	Title    string `json:"title"`
	Revision int64  `json:"revision"`
}

type TemplateUse struct {
	Scope
	TemplateID string `json:"template_id"`
	ParentID   string `json:"parent_id,omitempty"`
}

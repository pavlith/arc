// Package v1 owns the Tasks v1 DTOs, contract schemas and typed operations.
// The Fabric service identity is still "tasks", not the Go directory name "task".
package v1

import "time"

type Task struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	RootID      string    `json:"acl_root_id"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}
type CreateRequest struct {
	Scope
	Title string `json:"title"`
}
type GetRequest struct {
	Scope
	TaskID string `json:"task_id"`
}
type ListRequest struct {
	Scope
	Limit int `json:"limit"`
}
type ListResponse struct {
	Tasks []Task `json:"tasks"`
}
type CreatedEvent struct {
	Scope
	TaskID string `json:"task_id"`
}

type GrantCommand struct {
	Scope
	Action        string `json:"action"`
	PrincipalKind string `json:"principal_kind"`
	PrincipalID   string `json:"principal_id"`
	GrantID       string `json:"grant_id,omitempty"`
}

type GrantResult struct {
	ResourceID string `json:"resource_id,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	State      string `json:"state,omitempty"`
	Revision   int64  `json:"policy_revision"`
}

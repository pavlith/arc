package tasks

import taskv1 "github.com/pavlith/arc/services/task/api/v1"

type Task = taskv1.Task
type Scope = taskv1.Scope
type CreateRequest = taskv1.CreateRequest
type GetRequest = taskv1.GetRequest
type ListRequest = taskv1.ListRequest
type ListResponse = taskv1.ListResponse
type CreatedEvent = taskv1.CreatedEvent
type GrantCommand = taskv1.GrantCommand

const (
	Create  = taskv1.CreateID
	Admin   = taskv1.AdminID
	Get     = taskv1.GetID
	List    = taskv1.ListID
	Created = taskv1.CreatedSubject
)

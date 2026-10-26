package tasks

import tasksv1 "github.com/pavlith/arc/services/task/api/v1"

type Task = tasksv1.Task
type Scope = tasksv1.Scope
type CreateRequest = tasksv1.CreateRequest
type GetRequest = tasksv1.GetRequest
type ListRequest = tasksv1.ListRequest
type ListResponse = tasksv1.ListResponse
type CreatedEvent = tasksv1.CreatedEvent
type GrantCommand = tasksv1.GrantCommand

const (
	Create  = tasksv1.CreateID
	Admin   = tasksv1.AdminID
	Get     = tasksv1.GetID
	List    = tasksv1.ListID
	Created = tasksv1.CreatedSubject
)

package tasks

import taskv1 "github.com/pavlith/arc/services/task/api/v1"

type Task = taskv1.Task
type Scope = taskv1.Scope
type CreateRequest = taskv1.BaseCreate
type GetRequest = taskv1.GetRequest
type CreatedEvent = taskv1.CreatedEvent
type GrantCommand = taskv1.GrantCommand

const (
	Admin   = taskv1.AdminID
	Created = taskv1.CreatedSubject
)

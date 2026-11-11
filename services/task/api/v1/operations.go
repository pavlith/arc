package v1

import "github.com/pavlith/arc/sdk/module"

const (
	CreateID       = "task.task.create"
	GetID          = "task.tasks.get"
	EditID         = "task.tasks.edit"
	ListID         = "task.tasks.list"
	AdminID        = "task.roots.grants"
	ListGrantsID   = "task.roots.grants.list"
	CreatedSubject = "evt.task.task.created.v1"
	CreatedName    = "task.task.created"
)

var (
	Create     = module.Command[CreateRequest, Task]{ID: CreateID}
	Get        = module.Query[GetRequest, Task]{ID: GetID}
	Edit       = module.Command[EditRequest, Task]{ID: EditID}
	List       = module.Query[ListRequest, ListResponse]{ID: ListID}
	Admin      = module.Command[GrantCommand, GrantResult]{ID: AdminID}
	ListGrants = module.Query[GrantsRequest, GrantsResult]{ID: ListGrantsID}
	Created    = module.Event[CreatedEvent]{Name: CreatedName, Subject: CreatedSubject}
)

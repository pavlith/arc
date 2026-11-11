package v1

import "github.com/pavlith/arc/sdk/module"

const (
	AdminID        = "task.roots.grants"
	ListGrantsID   = "task.roots.grants.list"
	CreatedSubject = "evt.task.task.created.v1"
	CreatedName    = "task.task.created"
)

var (
	Admin      = module.Command[GrantCommand, GrantResult]{ID: AdminID}
	ListGrants = module.Query[GrantsRequest, GrantsResult]{ID: ListGrantsID}
	Created    = module.Event[CreatedEvent]{Name: CreatedName, Subject: CreatedSubject}
)

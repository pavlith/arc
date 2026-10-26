package v1

import "github.com/pavlith/arc/pkgs/module"

const (
    CreateID = "tasks.tasks.create"
    GetID = "tasks.tasks.get"
    ListID = "tasks.tasks.list"
    AdminID = "tasks.roots.grants"
    CreatedSubject = "evt.tasks.task.created.v1"
    CreatedName = "tasks.task.created"
)
var (
    Create = module.Command[CreateRequest, Task]{ID: CreateID}
    Get = module.Query[GetRequest, Task]{ID: GetID}
    List = module.Query[ListRequest, ListResponse]{ID: ListID}
    Admin = module.Command[GrantCommand, GrantResult]{ID: AdminID}
    Created = module.Event[CreatedEvent]{Name:CreatedName,Subject:CreatedSubject}
)

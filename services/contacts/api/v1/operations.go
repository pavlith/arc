package v1

import "github.com/pavlith/arc/sdk/module"

var (
	GetBook               = module.Query[Scope, Book]{ID: "contacts.books.get"}
	UpdateBook            = module.Command[BookUpdate, Book]{ID: "contacts.books.update"}
	CreateContact         = module.Command[Create, Contact]{ID: "contacts.contacts.create"}
	GetContact            = module.Query[ContactRef, Contact]{ID: "contacts.contacts.get"}
	UpdateContact         = module.Command[Update, Contact]{ID: "contacts.contacts.update"}
	DeleteContact         = module.Command[Delete, Mutation]{ID: "contacts.contacts.delete"}
	ListContacts          = module.Query[List, ContactList]{ID: "contacts.contacts.list"}
	RootGrants            = module.Command[Grant, GrantResult]{ID: "contacts.roots.grants"}
	PersonalGetBook       = module.Query[Scope, Book]{ID: "contacts.personal.books.get"}
	PersonalUpdateBook    = module.Command[BookUpdate, Book]{ID: "contacts.personal.books.update"}
	PersonalCreateContact = module.Command[Create, Contact]{ID: "contacts.personal.contacts.create"}
	PersonalGetContact    = module.Query[ContactRef, Contact]{ID: "contacts.personal.contacts.get"}
	PersonalUpdateContact = module.Command[Update, Contact]{ID: "contacts.personal.contacts.update"}
	PersonalDeleteContact = module.Command[Delete, Mutation]{ID: "contacts.personal.contacts.delete"}
	PersonalListContacts  = module.Query[List, ContactList]{ID: "contacts.personal.contacts.list"}
	PersonalRootGrants    = module.Command[Grant, GrantResult]{ID: "contacts.personal.roots.grants"}
	GetObject             = module.Query[ContactRef, VCardObject]{ID: "contacts.objects.get"}
	CreateObject          = module.Command[ObjectCreate, VCardObject]{ID: "contacts.objects.create"}
	UpdateObject          = module.Command[ObjectUpdate, VCardObject]{ID: "contacts.objects.update"}
	DeleteObject          = module.Command[ObjectDelete, Mutation]{ID: "contacts.objects.delete"}
	PersonalGetObject     = module.Query[ContactRef, VCardObject]{ID: "contacts.personal.objects.get"}
	PersonalCreateObject  = module.Command[ObjectCreate, VCardObject]{ID: "contacts.personal.objects.create"}
	PersonalUpdateObject  = module.Command[ObjectUpdate, VCardObject]{ID: "contacts.personal.objects.update"}
	PersonalDeleteObject  = module.Command[ObjectDelete, Mutation]{ID: "contacts.personal.objects.delete"}
)

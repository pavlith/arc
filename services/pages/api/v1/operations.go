package v1

import (
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/resource"
)

var (
	CreatePage               = module.Command[Create, Page]{ID: "pages.pages.create"}
	GetPage                  = module.Query[PageRef, Page]{ID: "pages.pages.get"}
	UpdatePage               = module.Command[Update, Page]{ID: "pages.pages.update"}
	MovePage                 = module.Command[Move, Mutation]{ID: "pages.pages.move"}
	ArchivePage              = module.Command[Archive, Mutation]{ID: "pages.pages.archive"}
	ListPages                = module.Query[List, PageList]{ID: "pages.pages.list"}
	ListVersions             = module.Query[VersionList, Versions]{ID: "pages.pages.versions"}
	RestorePage              = module.Command[Restore, Page]{ID: "pages.pages.restore"}
	PreviewReference         = module.Query[Preview, resource.Summary]{ID: "pages.pages.preview"}
	CreateTemplate           = module.Command[TemplateCreate, Template]{ID: "pages.templates.create"}
	UpdateTemplate           = module.Command[TemplateUpdate, Template]{ID: "pages.templates.update"}
	GetTemplate              = module.Query[TemplateRef, Template]{ID: "pages.templates.get"}
	ListTemplates            = module.Query[List, TemplateList]{ID: "pages.templates.list"}
	ArchiveTemplate          = module.Command[TemplateArchive, Mutation]{ID: "pages.templates.archive"}
	UseTemplate              = module.Command[TemplateUse, Page]{ID: "pages.templates.use"}
	RootGrants               = module.Command[Grant, GrantResult]{ID: "pages.roots.grants"}
	PersonalCreatePage       = module.Command[Create, Page]{ID: "pages.personal.pages.create"}
	PersonalGetPage          = module.Query[PageRef, Page]{ID: "pages.personal.pages.get"}
	PersonalUpdatePage       = module.Command[Update, Page]{ID: "pages.personal.pages.update"}
	PersonalMovePage         = module.Command[Move, Mutation]{ID: "pages.personal.pages.move"}
	PersonalArchivePage      = module.Command[Archive, Mutation]{ID: "pages.personal.pages.archive"}
	PersonalListPages        = module.Query[List, PageList]{ID: "pages.personal.pages.list"}
	PersonalListVersions     = module.Query[VersionList, Versions]{ID: "pages.personal.pages.versions"}
	PersonalRestorePage      = module.Command[Restore, Page]{ID: "pages.personal.pages.restore"}
	PersonalPreviewReference = module.Query[Preview, resource.Summary]{ID: "pages.personal.pages.preview"}
	PersonalCreateTemplate   = module.Command[TemplateCreate, Template]{ID: "pages.personal.templates.create"}
	PersonalUpdateTemplate   = module.Command[TemplateUpdate, Template]{ID: "pages.personal.templates.update"}
	PersonalGetTemplate      = module.Query[TemplateRef, Template]{ID: "pages.personal.templates.get"}
	PersonalListTemplates    = module.Query[List, TemplateList]{ID: "pages.personal.templates.list"}
	PersonalArchiveTemplate  = module.Command[TemplateArchive, Mutation]{ID: "pages.personal.templates.archive"}
	PersonalUseTemplate      = module.Command[TemplateUse, Page]{ID: "pages.personal.templates.use"}
	PersonalRootGrants       = module.Command[Grant, GrantResult]{ID: "pages.personal.roots.grants"}
)

package v1

import "github.com/pavlith/arc/sdk/module"

var (
	MultigetObjects         = module.Query[ObjectBatchQuery, ObjectBatchResult]{ID: "calendar.objects.multiget"}
	PersonalMultigetObjects = module.Query[ObjectBatchQuery, ObjectBatchResult]{ID: "calendar.personal.objects.multiget"}
	SyncCollection          = module.Query[SyncQuery, SyncResult]{ID: "calendar.objects.sync"}
	PersonalSyncCollection  = module.Query[SyncQuery, SyncResult]{ID: "calendar.personal.objects.sync"}
	GetObject               = module.Query[EventRef, ICalObject]{ID: "calendar.objects.get"}
	CreateObject            = module.Command[ObjectCreate, ICalObject]{ID: "calendar.objects.create"}
	UpdateObject            = module.Command[ObjectUpdate, ICalObject]{ID: "calendar.objects.update"}
	DeleteObject            = module.Command[ObjectDelete, Mutation]{ID: "calendar.objects.delete"}
	PersonalGetObject       = module.Query[EventRef, ICalObject]{ID: "calendar.personal.objects.get"}
	PersonalCreateObject    = module.Command[ObjectCreate, ICalObject]{ID: "calendar.personal.objects.create"}
	PersonalUpdateObject    = module.Command[ObjectUpdate, ICalObject]{ID: "calendar.personal.objects.update"}
	PersonalDeleteObject    = module.Command[ObjectDelete, Mutation]{ID: "calendar.personal.objects.delete"}

	ListOccurrences         = module.Query[OccurrenceQuery, OccurrenceList]{ID: "calendar.events.occurrences"}
	PersonalListOccurrences = module.Query[OccurrenceQuery, OccurrenceList]{ID: "calendar.personal.events.occurrences"}
	GetCalendar             = module.Query[Scope, Calendar]{ID: "calendar.calendars.get"}
	UpdateCalendar          = module.Command[CalendarUpdate, Calendar]{ID: "calendar.calendars.update"}
	CreateEvent             = module.Command[Create, Event]{ID: "calendar.events.create"}
	GetEvent                = module.Query[EventRef, Event]{ID: "calendar.events.get"}
	UpdateEvent             = module.Command[Update, Event]{ID: "calendar.events.update"}
	DeleteEvent             = module.Command[Delete, Mutation]{ID: "calendar.events.delete"}
	ListEvents              = module.Query[List, EventList]{ID: "calendar.events.list"}
	FreeBusy                = module.Query[Range, BusyResult]{ID: "calendar.free_busy"}
	RootGrants              = module.Command[Grant, GrantResult]{ID: "calendar.roots.grants"}
	PersonalGetCalendar     = module.Query[Scope, Calendar]{ID: "calendar.personal.calendars.get"}
	PersonalUpdateCalendar  = module.Command[CalendarUpdate, Calendar]{ID: "calendar.personal.calendars.update"}
	PersonalCreateEvent     = module.Command[Create, Event]{ID: "calendar.personal.events.create"}
	PersonalGetEvent        = module.Query[EventRef, Event]{ID: "calendar.personal.events.get"}
	PersonalUpdateEvent     = module.Command[Update, Event]{ID: "calendar.personal.events.update"}
	PersonalDeleteEvent     = module.Command[Delete, Mutation]{ID: "calendar.personal.events.delete"}
	PersonalListEvents      = module.Query[List, EventList]{ID: "calendar.personal.events.list"}
	PersonalFreeBusy        = module.Query[Range, BusyResult]{ID: "calendar.personal.free_busy"}
	PersonalRootGrants      = module.Command[Grant, GrantResult]{ID: "calendar.personal.roots.grants"}
)

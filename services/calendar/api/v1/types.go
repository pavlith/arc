package v1

import "time"

type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}
type CalendarInput struct {
	Name     string `json:"name"`
	Timezone string `json:"timezone"`
}
type Calendar struct {
	Scope
	CalendarInput
	Revision int64 `json:"revision"`
}
type CalendarUpdate struct {
	Scope
	CalendarInput
	Revision int64 `json:"revision"`
}
type EventRef struct {
	Scope
	EventID string `json:"event_id"`
}

// Timed events use RFC3339 instants. All-day events use exclusive local dates.
type Input struct {
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Timezone    string      `json:"timezone"`
	AllDay      bool        `json:"all_day"`
	Start       string      `json:"start"`
	End         string      `json:"end"`
	Busy        bool        `json:"busy"`
	RRule       string      `json:"rrule,omitempty"`
	Exceptions  []Exception `json:"exceptions,omitempty"`
}
type Create struct {
	Scope
	Input
}
type Update struct {
	EventRef
	Input
	Revision int64 `json:"revision"`
}
type Delete struct {
	EventRef
	Revision int64 `json:"revision"`
}
type Event struct {
	UID string `json:"uid"`
	Scope
	ID string `json:"id"`
	Input
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Range struct {
	Scope
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
}
type List struct {
	Range
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}
type EventList struct {
	Events     []EventSummary `json:"events"`
	NextCursor string         `json:"next_cursor,omitempty"`
}
type Interval struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type BusyResult struct {
	Intervals []Interval `json:"intervals"`
}
type Mutation struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Deleted  bool   `json:"deleted"`
}
type Grant struct {
	Scope
	PrincipalKind string `json:"principal_kind,omitempty"`
	PrincipalID   string `json:"principal_id,omitempty"`
	Action        string `json:"action,omitempty"`
	GrantID       string `json:"grant_id,omitempty"`
}
type GrantResult struct {
	ResourceID string `json:"resource_id,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	State      string `json:"state,omitempty"`
	Revision   int64  `json:"policy_revision"`
}
type Changed struct {
	Scope
	EntityID string `json:"entity_id"`
	Revision int64  `json:"revision"`
	Action   string `json:"action"`
}

const ChangedSubject = "evt.calendar.catalog.changed.v1"
const ChangedName = "calendar.catalog.changed"

// EventSummary bounds list responses independently of description size.
type EventSummary struct {
	Scope
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Timezone  string    `json:"timezone"`
	AllDay    bool      `json:"all_day"`
	Start     string    `json:"start"`
	End       string    `json:"end"`
	Busy      bool      `json:"busy"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Exception identifies an original occurrence, even when it is moved.
// A cancellation has no replacement dates; a move supplies both start and end.
type Exception struct {
	RecurrenceID string `json:"recurrence_id"`
	Cancelled    bool   `json:"cancelled"`
	Start        string `json:"start,omitempty"`
	End          string `json:"end,omitempty"`
}
type Occurrence struct {
	Scope
	EventID      string `json:"event_id"`
	RecurrenceID string `json:"recurrence_id"`
	Title        string `json:"title"`
	Timezone     string `json:"timezone"`
	AllDay       bool   `json:"all_day"`
	Start        string `json:"start"`
	End          string `json:"end"`
	Busy         bool   `json:"busy"`
	Revision     int64  `json:"revision"`
}
type OccurrenceQuery struct {
	Range
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}
type OccurrenceList struct {
	Occurrences []Occurrence `json:"occurrences"`
	NextCursor  string       `json:"next_cursor,omitempty"`
}

// Object bodies stay inside the owner RPC; a later DAV adapter can reuse these.
type ICalObject struct {
	Scope
	EventID  string `json:"event_id"`
	UID      string `json:"uid"`
	ETag     string `json:"etag"`
	Revision int64  `json:"revision"`
	Data     string `json:"data"`
}
type ObjectCreate struct {
	EventRef
	IfNoneMatch bool   `json:"if_none_match"`
	Data        string `json:"data"`
}
type ObjectUpdate struct {
	EventRef
	IfMatch string `json:"if_match"`
	Data    string `json:"data"`
}
type ObjectDelete struct {
	EventRef
	IfMatch string `json:"if_match"`
}

// SyncItem snapshots object metadata only; object GET returns current content.
type SyncItem struct {
	EventID  string `json:"event_id"`
	UID      string `json:"uid"`
	Revision int64  `json:"revision"`
	State    string `json:"state"`
	ETag     string `json:"etag,omitempty"`
}
type SyncQuery struct {
	Scope
	Token  string `json:"token,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}
type SyncResult struct {
	Scope
	Items    []SyncItem `json:"items"`
	Complete bool       `json:"complete"`
	Token    string     `json:"token,omitempty"`
	Cursor   string     `json:"cursor,omitempty"`
}

// KnownETag is a cache hint, never authorization or a write precondition.
type ObjectBatchTarget struct {
	EventID   string `json:"event_id"`
	KnownETag string `json:"known_etag,omitempty"`
}
type ObjectBatchQuery struct {
	Scope
	Objects []ObjectBatchTarget `json:"objects"`
	Offset  int                 `json:"offset,omitempty"`
}
type ObjectBatchItem struct {
	EventID  string `json:"event_id"`
	Status   string `json:"status"`
	UID      string `json:"uid,omitempty"`
	Revision int64  `json:"revision,omitempty"`
	ETag     string `json:"etag,omitempty"`
	Data     string `json:"data,omitempty"`
}
type ObjectBatchResult struct {
	Scope
	Items     []ObjectBatchItem `json:"items"`
	Complete  bool              `json:"complete"`
	NextIndex int               `json:"next_index,omitempty"`
}

package v1

import "time"

type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}
type BookInput struct {
	Name string `json:"name"`
}
type Book struct {
	Scope
	BookInput
	Revision int64 `json:"revision"`
}
type BookUpdate struct {
	Scope
	BookInput
	Revision int64 `json:"revision"`
}
type ContactRef struct {
	Scope
	ContactID string `json:"contact_id"`
}
type LabelledValue struct {
	Label string `json:"label,omitempty"`
	Value string `json:"value"`
}
type Address struct {
	Label      string `json:"label,omitempty"`
	Street     string `json:"street,omitempty"`
	Locality   string `json:"locality,omitempty"`
	Region     string `json:"region,omitempty"`
	PostalCode string `json:"postal_code,omitempty"`
	Country    string `json:"country,omitempty"`
}
type Input struct {
	DisplayName    string            `json:"display_name"`
	GivenName      string            `json:"given_name,omitempty"`
	FamilyName     string            `json:"family_name,omitempty"`
	AdditionalName string            `json:"additional_name,omitempty"`
	Prefix         string            `json:"prefix,omitempty"`
	Suffix         string            `json:"suffix,omitempty"`
	Organization   string            `json:"organization,omitempty"`
	Role           string            `json:"role,omitempty"`
	Phones         []LabelledValue   `json:"phones,omitempty"`
	Emails         []LabelledValue   `json:"emails,omitempty"`
	Addresses      []Address         `json:"addresses,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	CustomFields   map[string]string `json:"custom_fields,omitempty"`
}
type Create struct {
	Scope
	Input
}
type Update struct {
	ContactRef
	Input
	Revision int64 `json:"revision"`
}
type Delete struct {
	ContactRef
	Revision int64 `json:"revision"`
}
type Contact struct {
	Scope
	ID  string `json:"id"`
	UID string `json:"uid"`
	Input
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type List struct {
	Scope
	Query  string `json:"query,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}
type Summary struct {
	Scope
	ID           string    `json:"id"`
	UID          string    `json:"uid"`
	DisplayName  string    `json:"display_name"`
	Organization string    `json:"organization"`
	Role         string    `json:"role"`
	Revision     int64     `json:"revision"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type ContactList struct {
	Contacts   []Summary `json:"contacts"`
	NextCursor string    `json:"next_cursor,omitempty"`
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

const ChangedSubject = "evt.contacts.catalog.changed.v1"
const ChangedName = "contacts.catalog.changed"

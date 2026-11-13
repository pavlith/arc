package v1

import (
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
	"time"
)

type Scope struct {
	WorkspaceID string `json:"workspace_id"`
	RootID      string `json:"acl_root_id"`
}
type AccountInput struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Login string `json:"login"`
	Email string `json:"email"`
}
type Account struct {
	Scope
	AccountInput
	OwnerID           string `json:"owner_id"`
	Revision          int64  `json:"revision"`
	Generation        int64  `json:"generation"`
	CredentialVersion int64  `json:"credential_version"`
	CredentialReady   bool   `json:"credential_ready"`
	State             string `json:"state"`
}
type Update struct {
	Scope
	AccountInput
	Revision int64 `json:"revision"`
}
type SetCredential struct {
	Scope
	Revision int64  `json:"revision"`
	KeyID    string `json:"key_id"`
	Sealed   string `json:"sealed"`
}
type SetState struct {
	Scope
	Revision int64  `json:"revision"`
	State    string `json:"state"`
}
type KeyInfo struct {
	Scope
	credentials.PublicInfo
}
type CheckResult struct {
	Scope
	Revision     int64    `json:"revision"`
	Generation   int64    `json:"generation"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
}
type Changed struct {
	Scope
	Revision   int64  `json:"revision"`
	Generation int64  `json:"generation"`
	Action     string `json:"action"`
}

const ChangedSubject = "evt.mail.accounts.changed.v1"
const ChangedName = "mail.accounts.changed"

type FolderList struct {
	Scope
	Revision   int64               `json:"revision"`
	Generation int64               `json:"generation"`
	Status     string              `json:"status"`
	Folders    []imapclient.Folder `json:"folders"`
}

type MessageListQuery struct {
	Scope
	Generation int64 `json:"generation"`
	imapclient.MessageQuery
}
type MessageList struct {
	Scope
	Revision   int64  `json:"revision"`
	Generation int64  `json:"generation"`
	WireName   string `json:"wire_name"`
	Status     string `json:"status"`
	imapclient.MessagePage
}

// StructureQuery requires an exact remote namespace; it cannot follow a UID reset.
type StructureQuery struct {
	Scope
	Generation int64 `json:"generation"`
	imapclient.StructureQuery
}
type Structure struct {
	Scope
	Revision   int64  `json:"revision"`
	Generation int64  `json:"generation"`
	WireName   string `json:"wire_name"`
	Status     string `json:"status"`
	imapclient.MessageStructure
}

// DownloadRequest is signed in full for the private HTTPS byte transport.
type DownloadRequest struct {
	Scope
	Generation int64 `json:"generation"`
	imapclient.DownloadQuery
}

type CreateAccount struct {
	WorkspaceID string `json:"workspace_id"`
	AccountInput
}
type AccountListQuery struct {
	WorkspaceID string `json:"workspace_id"`
	Limit       int    `json:"limit"`
	Cursor      string `json:"cursor,omitempty"`
}
type AccountList struct {
	WorkspaceID    string    `json:"workspace_id"`
	Accounts       []Account `json:"accounts"`
	NextCursor     string    `json:"next_cursor,omitempty"`
	PolicyRevision int64     `json:"policy_revision"`
}

type RefreshMessages struct{ MessageListQuery }
type CachedFolder struct {
	ID            string    `json:"id"`
	WireName      string    `json:"wire_name"`
	Revision      int64     `json:"revision"`
	UIDValidity   uint32    `json:"uid_validity"`
	UIDNext       uint32    `json:"uid_next"`
	RemoteCount   uint32    `json:"remote_count"`
	NextBeforeUID uint32    `json:"next_before_uid,omitempty"`
	LowUID        uint32    `json:"low_uid"`
	HighUID       uint32    `json:"high_uid"`
	Status        string    `json:"status"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type RefreshResult struct {
	Scope
	Generation int64         `json:"generation"`
	Status     string        `json:"status"`
	Folder     *CachedFolder `json:"folder"`
	Upserted   int           `json:"upserted"`
	Removed    int           `json:"removed"`
}
type CachedMessage struct {
	ID          string `json:"id"`
	FolderID    string `json:"folder_id"`
	UIDValidity uint32 `json:"uid_validity"`
	imapclient.Message
}
type CachedListQuery struct {
	Scope
	Generation  int64  `json:"generation"`
	WireName    string `json:"wire_name"`
	Limit       int    `json:"limit"`
	UIDValidity uint32 `json:"uid_validity,omitempty"`
	BeforeUID   uint32 `json:"before_uid,omitempty"`
}
type CachedList struct {
	Scope
	Generation    int64           `json:"generation"`
	Folder        CachedFolder    `json:"folder"`
	Messages      []CachedMessage `json:"messages"`
	NextBeforeUID uint32          `json:"next_before_uid,omitempty"`
}
type CachedGetQuery struct {
	Scope
	Generation int64  `json:"generation"`
	MessageID  string `json:"message_id"`
}
type CachedGet struct {
	Scope
	Generation int64  `json:"generation"`
	WireName   string `json:"wire_name"`
	CachedMessage
}
type MessagesChanged struct {
	Scope
	Generation  int64  `json:"generation"`
	FolderID    string `json:"folder_id"`
	Revision    int64  `json:"revision"`
	UIDValidity uint32 `json:"uid_validity"`
}

const MessagesChangedSubject = "evt.mail.messages.changed.v1"
const MessagesChangedName = "mail.messages.changed"

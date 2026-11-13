// Package mail owns personal connection configuration and user-requested checks.
package mail

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/identity"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
	"github.com/pavlith/arc/services/mail/models"
	"gorm.io/gorm"
)

type Module struct {
	DB       *gorm.DB
	Contract *contract.Compiled
	Identity identity.Client
	Vault    *credentials.Vault
	Probe    *imapclient.Client
	Check    func(context.Context, string, string) error
}

func (*Module) ID() string { return "mail" }
func (s *Module) db(ctx context.Context) *gorm.DB {
	return database.FromContext(ctx, s.DB).WithContext(ctx)
}
func invalid() error  { return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Mail input"} }
func conflict() error { return &rpc.Error{Code: rpc.CodeConflict, Message: "Mail revision conflict"} }
func dbError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &rpc.Error{Code: rpc.CodeNotFound, Message: "mail account unavailable"}
	}
	return security.ErrUnavailable
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func validScope(q v1.Scope) bool { return q.WorkspaceID == "" && idPattern.MatchString(q.RootID) }
func (s *Module) root(ctx context.Context, q v1.Scope) (models.Account, error) {
	return account(ctx, s.db(ctx), q)
}
func account(ctx context.Context, db *gorm.DB, q v1.Scope) (models.Account, error) {
	var row models.Account
	err := db.WithContext(ctx).Where("acl_root_id=? AND workspace_id='' AND lifecycle='active'", q.RootID).Take(&row).Error
	return row, dbError(err)
}

func (s *Module) Authorize(ctx context.Context, root, action string) error {
	cl, ok := rpc.VerifiedClaims(ctx)
	meta, has := rpc.Metadata(ctx)
	if !ok || !has || cl.SessionID == "" || !strings.HasPrefix(cl.Subject, "user:") {
		return security.ErrUnauthenticated
	}
	var scope v1.Scope
	if json.Unmarshal(meta.Payload, &scope) != nil || !validScope(scope) || scope.RootID != root || cl.WorkspaceID != "" || !strings.HasPrefix(cl.Operation, "mail.personal.") {
		return security.ErrDenied
	}
	if _, err := s.root(ctx, scope); err != nil {
		return err
	}
	if s.Check == nil {
		return security.ErrUnavailable
	}
	if err := s.Check(ctx, root, action); err != nil {
		return err
	}
	if cl.Operation == v1.GetCacheStatus.ID || cl.Operation == v1.PruneCache.ID {
		_, err := s.ownerCacheAccount(ctx, s.db(ctx), scope)
		return err
	}
	if cl.Operation == v1.RefreshMessageIndex.ID {
		return s.stageRefresh(ctx)
	}
	return nil
}
func text(s string, max int) (string, error) {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return "", invalid()
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", invalid()
		}
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", invalid()
	}
	return s, nil
}
func validate(in v1.AccountInput) (v1.AccountInput, error) {
	for _, f := range []struct {
		p *string
		n int
	}{{&in.Name, 256}, {&in.Login, 320}, {&in.Email, 254}} {
		v, err := text(*f.p, f.n)
		if err != nil {
			return in, err
		}
		*f.p = v
	}
	host, err := imapclient.Host(in.Host)
	if err != nil || in.Port < 1 || in.Port > 65535 {
		return in, invalid()
	}
	in.Host = host
	a, err := mail.ParseAddress(in.Email)
	if err != nil || a.Name != "" || a.Address != in.Email {
		return in, invalid()
	}
	return in, nil
}
func input(row models.Account) v1.AccountInput {
	return v1.AccountInput{Name: row.Name, Host: row.Host, Port: row.Port, Login: row.Login, Email: row.Email}
}
func dto(row models.Account) v1.Account {
	return v1.Account{Scope: v1.Scope{RootID: row.RootID}, AccountInput: input(row), OwnerID: row.OwnerID, Revision: row.Revision, Generation: row.Generation, CredentialVersion: row.CredentialVersion, CredentialReady: len(row.Ciphertext) > 0, State: row.State}
}
func binding(row models.Account) credentials.Binding {
	return credentials.Binding{AccountID: row.RootID, OwnerID: row.OwnerID, Generation: row.Generation, Revision: row.Revision}
}

// PrepareRoot is a trusted operator hook after exact Access reservation. It is
// not an unauthenticated/public account provisioning or credential API.
func (s *Module) PrepareRoot(ctx context.Context, q v1.Scope, owner string, in v1.AccountInput, key ed25519.PrivateKey, kid, provider string) (string, error) {
	return s.prepareRoot(ctx, s.db(ctx), q, owner, in, key, kid, provider)
}
func (s *Module) prepareRoot(ctx context.Context, db *gorm.DB, q v1.Scope, owner string, in v1.AccountInput, key ed25519.PrivateKey, kid, provider string) (string, error) {
	if !validScope(q) || !idPattern.MatchString(owner) {
		return "", invalid()
	}
	in, err := validate(in)
	if err != nil {
		return "", err
	}
	receipt, err := access.SignDomainReceipt(key, access.DomainReceipt{Provider: provider, Root: q.RootID, Operation: "activate", Kid: kid, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		return "", err
	}
	err = db.WithContext(ctx).Exec("INSERT INTO accounts(acl_root_id,workspace_id,owner_id,lifecycle,name,host,port,login,email,state,revision,generation) VALUES(?,'',?,'prepared',?,?,?,?,?,'enabled',1,1) ON CONFLICT DO NOTHING", q.RootID, owner, in.Name, in.Host, in.Port, in.Login, in.Email).Error
	if err != nil {
		return "", dbError(err)
	}
	var old models.Account
	if err = db.WithContext(ctx).Where("acl_root_id=?", q.RootID).Take(&old).Error; err != nil {
		return "", dbError(err)
	}
	if old.WorkspaceID != "" || old.OwnerID != owner || old.Lifecycle == "prepared" && input(old) != in {
		return "", conflict()
	}
	return receipt, nil
}
func (s *Module) ActivateRoot(ctx context.Context, q v1.Scope) error {
	if !validScope(q) {
		return invalid()
	}
	res := s.DB.WithContext(ctx).Exec("UPDATE accounts SET lifecycle='active' WHERE acl_root_id=? AND workspace_id=''", q.RootID)
	if res.Error != nil {
		return dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return dbError(gorm.ErrRecordNotFound)
	}
	return nil
}
func (s *Module) get(ctx context.Context, q v1.Scope) (v1.Account, error) {
	row, err := s.root(ctx, q)
	return dto(row), err
}
func (s *Module) update(ctx context.Context, tx *gorm.DB, q v1.Update) (v1.Account, error) {
	in, err := validate(q.AccountInput)
	if err != nil {
		return v1.Account{}, err
	}
	row, err := account(ctx, tx, q.Scope)
	if err != nil {
		return v1.Account{}, err
	}
	if q.Revision < 1 || q.Revision != row.Revision {
		return v1.Account{}, conflict()
	}
	old := input(row)
	old.Name = in.Name
	if old != in {
		row.Generation++
		row.CredentialVersion++
		row.Ciphertext = nil
		row.KeyID = ""
	}
	row.Name = in.Name
	row.Host = in.Host
	row.Port = in.Port
	row.Login = in.Login
	row.Email = in.Email
	return s.save(ctx, tx, row, q.Revision, "account.updated")
}
func (s *Module) key(ctx context.Context, q v1.Scope) (v1.KeyInfo, error) {
	row, err := s.root(ctx, q)
	if err != nil {
		return v1.KeyInfo{}, err
	}
	if row.State == "disconnected" {
		return v1.KeyInfo{}, conflict()
	}
	return v1.KeyInfo{Scope: q, PublicInfo: s.Vault.Public(binding(row))}, nil
}
func (s *Module) setCredentials(ctx context.Context, tx *gorm.DB, q v1.SetCredential) (v1.Account, error) {
	row, err := account(ctx, tx, q.Scope)
	if err != nil {
		return v1.Account{}, err
	}
	if q.Revision < 1 || row.Revision != q.Revision || row.State == "disconnected" {
		return v1.Account{}, conflict()
	}
	password, err := s.Vault.Unseal(q.KeyID, q.Sealed, binding(row))
	if err != nil {
		return v1.Account{}, invalid()
	}
	defer clear(password)
	row.CredentialVersion++
	row.KeyID, row.Ciphertext, err = s.Vault.Encrypt(binding(row), row.CredentialVersion, password)
	if err != nil {
		return v1.Account{}, security.ErrUnavailable
	}
	return s.save(ctx, tx, row, q.Revision, "credentials.set")
}
func (s *Module) state(ctx context.Context, tx *gorm.DB, q v1.SetState) (v1.Account, error) {
	if q.State != "enabled" && q.State != "paused" && q.State != "disconnected" {
		return v1.Account{}, invalid()
	}
	row, err := account(ctx, tx, q.Scope)
	if err != nil {
		return v1.Account{}, err
	}
	if q.Revision < 1 || row.Revision != q.Revision {
		return v1.Account{}, conflict()
	}
	row.State = q.State
	if q.State == "disconnected" {
		row.Generation++
		row.CredentialVersion++
		row.Ciphertext = nil
		row.KeyID = ""
	}
	return s.save(ctx, tx, row, q.Revision, "account.state")
}
func (s *Module) save(ctx context.Context, tx *gorm.DB, row models.Account, revision int64, action string) (v1.Account, error) {
	row.Revision = revision + 1
	res := tx.Model(&models.Account{}).Where("acl_root_id=? AND workspace_id='' AND lifecycle='active' AND revision=?", row.RootID, revision).Updates(map[string]any{"name": row.Name, "host": row.Host, "port": row.Port, "login": row.Login, "email": row.Email, "state": row.State, "revision": row.Revision, "generation": row.Generation, "credential_version": row.CredentialVersion, "ciphertext": row.Ciphertext, "key_id": row.KeyID})
	if res.Error != nil {
		return v1.Account{}, dbError(res.Error)
	}
	if res.RowsAffected != 1 {
		return v1.Account{}, conflict()
	}
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok {
		return v1.Account{}, security.ErrUnauthenticated
	}
	if err := tx.Exec("INSERT INTO audit(acl_root_id,actor,operation,revision,generation) VALUES(?,?,?,?,?)", row.RootID, cl.Subject, cl.Operation, row.Revision, row.Generation).Error; err != nil {
		return v1.Account{}, dbError(err)
	}
	payload, err := json.Marshal(v1.Changed{Scope: v1.Scope{RootID: row.RootID}, Revision: row.Revision, Generation: row.Generation, Action: action})
	if err != nil {
		return v1.Account{}, invalid()
	}
	err = (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, v1.ChangedSubject, events.Envelope{ID: newID(), Type: v1.ChangedName, Version: 1, AggregateID: row.RootID, OccurredAt: time.Now().UTC(), Payload: payload})
	return dto(row), err
}
func (s *Module) checkConnection(ctx context.Context, q v1.Scope) (v1.CheckResult, error) {
	row, result, err := s.remoteRead(ctx, q, "mail.connection.manage", 0, s.Probe.Check)
	return v1.CheckResult{Scope: q, Revision: row.Revision, Generation: row.Generation, Status: result.Status, Capabilities: result.Capabilities}, err
}
func (s *Module) folders(ctx context.Context, q v1.Scope) (v1.FolderList, error) {
	row, result, err := s.remoteRead(ctx, q, "mail.read", 0, s.Probe.Folders)
	if result.Folders == nil {
		result.Folders = []imapclient.Folder{}
	}
	return v1.FolderList{Scope: q, Revision: row.Revision, Generation: row.Generation, Status: result.Status, Folders: result.Folders}, err
}
func (s *Module) remoteRead(ctx context.Context, q v1.Scope, action string, expectedGeneration int64, read func(context.Context, imapclient.Settings, []byte) imapclient.Result) (models.Account, imapclient.Result, error) {
	row, err := s.root(ctx, q)
	result := imapclient.Result{Capabilities: []string{}}
	if err != nil {
		return row, result, err
	}
	if expectedGeneration > 0 && row.Generation != expectedGeneration {
		return row, result, conflict()
	}

	if row.State != "enabled" {
		result.Status = row.State
		return row, result, nil
	}
	if len(row.Ciphertext) == 0 {
		result.Status = "credentials_missing"
		return row, result, nil
	}
	password, err := s.Vault.Decrypt(binding(row), row.CredentialVersion, row.KeyID, row.Ciphertext)
	if err != nil {
		return row, result, security.ErrUnavailable
	}
	defer clear(password)
	result = read(ctx, imapclient.Settings{Host: row.Host, Port: row.Port, Login: row.Login}, password)
	if err = s.Check(ctx, q.RootID, action); err != nil {
		return row, result, err
	}
	latest, err := s.root(ctx, q)
	if err != nil {
		return row, result, err
	}
	if latest.Revision != row.Revision || latest.Generation != row.Generation || latest.CredentialVersion != row.CredentialVersion || latest.State != "enabled" {
		return row, result, conflict()
	}
	return row, result, nil
}

func (s *Module) messages(ctx context.Context, q v1.MessageListQuery) (v1.MessageList, error) {
	if q.Generation < 1 || !q.MessageQuery.Valid() {
		return v1.MessageList{}, invalid()
	}
	row, result, err := s.remoteRead(ctx, q.Scope, "mail.read", q.Generation, func(ctx context.Context, settings imapclient.Settings, password []byte) imapclient.Result {
		return s.Probe.Messages(ctx, settings, password, q.MessageQuery)
	})
	if result.Page.Messages == nil {
		result.Page.Messages = []imapclient.Message{}
	}
	return v1.MessageList{Scope: q.Scope, Revision: row.Revision, Generation: row.Generation, WireName: q.WireName, Status: result.Status, MessagePage: result.Page}, err
}

func (s *Module) structure(ctx context.Context, q v1.StructureQuery) (v1.Structure, error) {
	if q.Generation < 1 || !q.StructureQuery.Valid() {
		return v1.Structure{}, invalid()
	}
	row, result, err := s.remoteRead(ctx, q.Scope, "mail.read", q.Generation, func(ctx context.Context, settings imapclient.Settings, password []byte) imapclient.Result {
		return s.Probe.Structure(ctx, settings, password, q.StructureQuery)
	})
	structure := imapclient.EmptyStructure(q.StructureQuery)
	if result.Structure != nil {
		structure = *result.Structure
	}
	return v1.Structure{Scope: q.Scope, Revision: row.Revision, Generation: row.Generation, WireName: q.WireName, Status: result.Status, MessageStructure: structure}, err
}

func (s *Module) Register(r *module.Registry) error {
	if s.DB == nil || s.Contract == nil || s.Vault == nil || s.Probe == nil || s.Check == nil {
		return security.ErrUnavailable
	}
	collection := module.Policy{Trusted: s.AuthorizeCollection}
	if err := module.BindQuery(r, v1.ListUnifiedMessages, collection, s.listUnified); err != nil {
		return err
	}
	if err := module.BindCommand(r, v1.CreatePersonalAccount, collection, events.Store{DB: s.DB}, s.createAccount); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.ListAccounts, collection, s.listAccounts); err != nil {
		return err
	}
	policy := module.Policy{Resource: s.Authorize}
	if err := module.BindQuery(r, v1.GetCacheStatus, policy, s.cacheStatus); err != nil {
		return err
	}
	if err := module.BindCommand(r, v1.PruneCache, policy, events.Store{DB: s.DB}, s.pruneCache); err != nil {
		return err
	}
	if err := module.BindCommand(r, v1.RefreshMessageIndex, policy, events.Store{DB: s.DB}, s.refreshIndex); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.ListCachedMessages, policy, s.listCached); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.GetCachedMessage, policy, s.getCached); err != nil {
		return err
	}

	if err := module.BindQuery(r, v1.PrivateDownload, policy, func(context.Context, v1.DownloadRequest) (struct{}, error) {
		return struct{}{}, &rpc.Error{Code: rpc.CodePermissionDenied, Message: "Mail content requires private HTTPS transport"}
	}); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.GetStructure, policy, s.structure); err != nil {
		return err
	}
	store := events.Store{DB: s.DB}
	if err := module.BindQuery(r, v1.GetAccount, policy, s.get); err != nil {
		return err
	}
	if err := module.BindCommand(r, v1.UpdateAccount, policy, store, s.update); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.GetCredentialKey, policy, s.key); err != nil {
		return err
	}
	if err := module.BindCommand(r, v1.SetCredentials, policy, store, s.setCredentials); err != nil {
		return err
	}
	if err := module.BindCommand(r, v1.SetAccountState, policy, store, s.state); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.ListFolders, policy, s.folders); err != nil {
		return err
	}
	if err := module.BindQuery(r, v1.ListMessages, policy, s.messages); err != nil {
		return err
	}
	return module.BindQuery(r, v1.CheckConnection, policy, s.checkConnection)
}

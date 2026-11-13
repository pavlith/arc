package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/models"
	"github.com/pavlith/arc/services/resources"
	"gorm.io/gorm"
)

func collectionUser(ctx context.Context) (string, error) {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || cl.SessionID == "" || cl.WorkspaceID != "" || cl.DelegationID != "" || cl.OnBehalfOf != "" || !strings.HasPrefix(cl.Subject, "user:") {
		return "", security.ErrDenied
	}
	user := strings.TrimPrefix(cl.Subject, "user:")
	if !idPattern.MatchString(user) {
		return "", security.ErrDenied
	}
	return user, nil
}

// AuthorizeCollection runs before command replay and before the SDK opens a SQL
// transaction. Provisioning's network calls never hold an owner database lock.
func (s *Module) AuthorizeCollection(ctx context.Context, operation string) error {
	cl, ok := rpc.VerifiedClaims(ctx)
	if !ok || cl.Operation != operation {
		return security.ErrDenied
	}
	user, err := collectionUser(ctx)
	if err != nil {
		return err
	}
	switch operation {
	case v1.ListAccounts.ID, v1.ListUnifiedMessages.ID:
		return nil // Collection handlers enforce live Core ACL.
	case v1.CreatePersonalAccount.ID:
		meta, ok := rpc.Metadata(ctx)
		var q v1.CreateAccount
		if !ok || meta.IdempotencyKey == "" || len(meta.IdempotencyKey) > 128 || json.Unmarshal(meta.Payload, &q) != nil || q.WorkspaceID != "" {
			return invalid()
		}
		in, err := validate(q.AccountInput)
		if err != nil {
			return err
		}
		hash, err := provisionHash(ctx)
		if err != nil {
			return err
		}
		return s.prepareAccount(ctx, user, meta.IdempotencyKey, hash, in)
	default:
		return security.ErrDenied
	}
}
func provisionHash(ctx context.Context) ([]byte, error) {
	meta, ok := rpc.Metadata(ctx)
	if !ok {
		return nil, security.ErrDenied
	}
	canonical, err := security.CanonicalJSON(meta.Payload)
	if err != nil {
		return nil, invalid()
	}
	hash := sha256.Sum256(canonical)
	return hash[:], nil
}

type accountProvision struct {
	Actor          string
	IdempotencyKey string
	RequestHash    []byte
	RootID         string `gorm:"column:acl_root_id"`
}

func readProvision(ctx context.Context, db *gorm.DB, user, key string) (accountProvision, error) {
	var p accountProvision
	err := db.WithContext(ctx).Table("account_provisions").Where("actor=? AND idempotency_key=?", "user:"+user, key).Take(&p).Error
	return p, err
}
func (s *Module) provisionContext(ctx context.Context, operation, key string) (context.Context, error) {
	client := s.Identity
	client.IdempotencyKey = key
	return resources.Invocation(ctx, client, "access/v1", operation)
}
func (s *Module) prepareAccount(ctx context.Context, user, key string, hash []byte, in v1.AccountInput) error {
	intent, err := readProvision(ctx, s.db(ctx), user, key)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return dbError(err)
	}
	if err == nil {
		if !bytes.Equal(intent.RequestHash, hash) {
			return conflict()
		}
		var row models.Account
		if err := s.db(ctx).Where("acl_root_id=? AND owner_id=? AND workspace_id=''", intent.RootID, user).Take(&row).Error; err != nil {
			return dbError(err)
		}
		if row.Lifecycle == "active" {
			return s.Check(ctx, row.RootID, "mail.connection.manage")
		}
	}
	ac := &access.Client{RPC: s.Identity.RPC}
	if intent.RootID == "" {
		binding, _ := json.Marshal([]string{"user:" + user, v1.CreatePersonalAccount.ID, key})
		sum := sha256.Sum256(binding)
		next, err := s.provisionContext(ctx, "access.v1.resources.reserve", "mail-create:"+hex.EncodeToString(sum[:]))
		if err != nil {
			return err
		}
		reserved, err := ac.Reserve(next, access.ReserveRequest{Type: "mail.personal", OwnerKind: "user", OwnerID: user})
		if err != nil {
			return err
		}
		if !idPattern.MatchString(reserved.ResourceID) || reserved.State != "reserved" {
			return security.ErrUnavailable
		}
		intent = accountProvision{Actor: "user:" + user, IdempotencyKey: key, RequestHash: hash, RootID: reserved.ResourceID}
	}
	scope := v1.Scope{RootID: intent.RootID}
	var receipt string
	// The prepared account and request binding become durable together. The
	// signed receipt is used only after this transaction has committed.
	err = database.RetryBusy(ctx, func() error {
		return s.db(ctx).Transaction(func(tx *gorm.DB) error {
			var prepareErr error
			receipt, prepareErr = s.prepareRoot(ctx, tx, scope, user, in, s.Identity.PrivateKey, s.Identity.Kid, s.Identity.ServiceID)
			if prepareErr != nil {
				return prepareErr
			}
			res := tx.Table("account_provisions").Exec("INSERT INTO account_provisions(actor,idempotency_key,request_hash,acl_root_id) VALUES(?,?,?,?) ON CONFLICT(actor,idempotency_key) DO NOTHING", intent.Actor, key, hash, scope.RootID)
			if res.Error != nil {
				return res.Error
			}
			saved, err := readProvision(ctx, tx, user, key)
			if err != nil {
				return err
			}
			if saved.RootID != scope.RootID || !bytes.Equal(saved.RequestHash, hash) {
				return conflict()
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	// A new receipt has a fresh expiry. Bind activation idempotency to that exact
	// receipt; Core's lifecycle transition itself tolerates an already active root.
	receiptHash := sha256.Sum256([]byte(receipt))
	next, err := s.provisionContext(ctx, "access.v1.resources.activate", "mail-activate:"+hex.EncodeToString(receiptHash[:]))
	if err != nil {
		return err
	}
	activated, err := ac.Activate(next, access.LifecycleRequest{ResourceID: scope.RootID, Receipt: receipt})
	if err != nil {
		return err
	}
	if activated.ResourceID != scope.RootID || activated.State != "active" {
		return security.ErrUnavailable
	}
	return s.Check(ctx, scope.RootID, "mail.connection.manage")
}
func (s *Module) createAccount(ctx context.Context, tx *gorm.DB, q v1.CreateAccount) (v1.Account, error) {
	user, err := collectionUser(ctx)
	if err != nil {
		return v1.Account{}, err
	}
	meta, ok := rpc.Metadata(ctx)
	if !ok || q.WorkspaceID != "" {
		return v1.Account{}, invalid()
	}
	hash, err := provisionHash(ctx)
	if err != nil {
		return v1.Account{}, err
	}
	intent, err := readProvision(ctx, tx, user, meta.IdempotencyKey)
	if err != nil {
		return v1.Account{}, dbError(err)
	}
	if !bytes.Equal(intent.RequestHash, hash) {
		return v1.Account{}, conflict()
	}
	in, err := validate(q.AccountInput)
	if err != nil {
		return v1.Account{}, err
	}
	var row models.Account
	if err = tx.Where("acl_root_id=? AND owner_id=? AND workspace_id='' AND lifecycle='prepared'", intent.RootID, user).Take(&row).Error; err != nil {
		return v1.Account{}, dbError(err)
	}
	if input(row) != in || row.Revision != 1 || row.Generation != 1 || row.CredentialVersion != 0 || len(row.Ciphertext) != 0 {
		return v1.Account{}, conflict()
	}
	result := tx.Model(&models.Account{}).Where("acl_root_id=? AND lifecycle='prepared'", row.RootID).Update("lifecycle", "active")
	if result.Error != nil {
		return v1.Account{}, dbError(result.Error)
	}
	if result.RowsAffected != 1 {
		return v1.Account{}, conflict()
	}
	cl, _ := rpc.VerifiedClaims(ctx)
	if err = tx.Exec("INSERT INTO audit(acl_root_id,actor,operation,revision,generation) VALUES(?,?,?,?,?)", row.RootID, cl.Subject, cl.Operation, row.Revision, row.Generation).Error; err != nil {
		return v1.Account{}, dbError(err)
	}
	payload, err := json.Marshal(v1.Changed{Scope: v1.Scope{RootID: row.RootID}, Revision: row.Revision, Generation: row.Generation, Action: "account.created"})
	if err != nil {
		return v1.Account{}, err
	}
	err = (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, v1.ChangedSubject, events.Envelope{ID: newID(), Type: v1.ChangedName, Version: 1, AggregateID: row.RootID, OccurredAt: time.Now().UTC(), Payload: payload})
	return dto(row), err
}
func (s *Module) listAccounts(ctx context.Context, q v1.AccountListQuery) (v1.AccountList, error) {
	empty := v1.AccountList{Accounts: []v1.Account{}}
	if _, err := collectionUser(ctx); err != nil {
		return empty, err
	}
	if q.WorkspaceID != "" || q.Limit < 1 || q.Limit > 20 || q.Cursor != "" && !idPattern.MatchString(q.Cursor) {
		return empty, invalid()
	}
	next, err := s.provisionContext(ctx, "access.v1.list_accessible_roots", "")
	if err != nil {
		return empty, err
	}
	ac := &access.Client{RPC: s.Identity.RPC}
	roots, err := ac.ListAccessibleRoots(next, access.ListRequest{OwnerKind: "user", Type: "mail.personal", Action: "mail.read", Limit: q.Limit, Cursor: q.Cursor})
	if err != nil {
		return empty, err
	}
	if len(roots.Resources) > q.Limit || roots.Revision < 1 || roots.NextCursor != "" && !idPattern.MatchString(roots.NextCursor) {
		return empty, security.ErrUnavailable
	}
	ids := []string{}
	byID := map[string]access.Resource{}
	after := q.Cursor
	for _, root := range roots.Resources {
		if !idPattern.MatchString(root.ID) || root.ID <= after || root.Type != "mail.personal" || root.Provider != s.Identity.ServiceID || root.OwnerKind != "user" || !idPattern.MatchString(root.OwnerID) || root.WorkspaceID != "" || root.ParentID != "" || root.State != "active" {
			return empty, security.ErrUnavailable
		}
		ids = append(ids, root.ID)
		byID[root.ID] = root
		after = root.ID
	}
	if roots.NextCursor != "" && (len(ids) == 0 || roots.NextCursor != after) {
		return empty, security.ErrUnavailable
	}
	result := v1.AccountList{Accounts: []v1.Account{}, NextCursor: roots.NextCursor, PolicyRevision: roots.Revision}
	if len(ids) == 0 {
		return result, nil
	}
	var rows []models.Account
	if err = s.db(ctx).Where("acl_root_id IN ? AND workspace_id='' AND lifecycle='active'", ids).Order("acl_root_id").Find(&rows).Error; err != nil {
		return empty, dbError(err)
	}
	checks := []access.CheckRequest{}
	for _, row := range rows {
		if row.OwnerID != byID[row.RootID].OwnerID {
			return empty, security.ErrUnavailable
		}
		result.Accounts = append(result.Accounts, dto(row))
		checks = append(checks, access.CheckRequest{ResourceID: row.RootID, Action: "mail.read"})
	}
	if len(checks) > 0 {
		next, err = s.provisionContext(ctx, "access.v1.check_many", "")
		if err != nil {
			return empty, err
		}
		decisions, err := ac.CheckMany(next, access.CheckManyRequest{Checks: checks})
		if err != nil {
			return empty, err
		}
		if len(decisions.Decisions) != len(checks) || decisions.Revision < 1 {
			return empty, security.ErrUnavailable
		}
		for _, decision := range decisions.Decisions {
			if !decision.Allowed {
				return empty, security.ErrDenied
			}
		}
		result.PolicyRevision = decisions.Revision
	}
	return result, nil
}

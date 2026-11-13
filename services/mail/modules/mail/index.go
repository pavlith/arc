package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/imapclient"
	"gorm.io/gorm"
)

type indexFolder struct {
	ID            string
	RootID        string `gorm:"column:acl_root_id"`
	Generation    int64
	WireName      string
	Revision      int64
	UIDValidity   uint32 `gorm:"column:uid_validity"`
	UIDNext       uint32 `gorm:"column:uid_next"`
	RemoteCount   uint32
	NextBeforeUID uint32 `gorm:"column:next_before_uid"`
	LowUID        uint32 `gorm:"column:low_uid"`
	HighUID       uint32 `gorm:"column:high_uid"`
	Status        string
	UpdatedAt     time.Time
}

func (indexFolder) TableName() string { return "mail_folders" }

type indexMessage struct {
	ID           string
	FolderID     string
	UIDValidity  uint32 `gorm:"column:uid_validity"`
	UID          uint32 `gorm:"column:uid"`
	Present      bool
	Summary      []byte
	InternalUnix int64
}

func (indexMessage) TableName() string { return "mail_messages" }

type refreshSnapshot struct {
	AccountRevision   int64
	CredentialVersion int64
	State             string
	FolderID          string
	FolderRevision    int64
	Status            string
	Page              imapclient.MessagePage
}
type refreshStage struct {
	Actor          string
	IdempotencyKey string
	RequestHash    []byte
	RootID         string `gorm:"column:acl_root_id"`
	Snapshot       []byte
	CreatedUnix    int64
}

func (refreshStage) TableName() string { return "mail_refresh_staging" }
func folderDTO(f indexFolder) v1.CachedFolder {
	return v1.CachedFolder{ID: f.ID, WireName: f.WireName, Revision: f.Revision, UIDValidity: f.UIDValidity, UIDNext: f.UIDNext, RemoteCount: f.RemoteCount, NextBeforeUID: f.NextBeforeUID, LowUID: f.LowUID, HighUID: f.HighUID, Status: f.Status, UpdatedAt: f.UpdatedAt}
}
func readIndexFolder(ctx context.Context, db *gorm.DB, root string, generation int64, wire string) (indexFolder, error) {
	var f indexFolder
	err := db.WithContext(ctx).Where("acl_root_id=? AND generation=? AND wire_name=?", root, generation, wire).Take(&f).Error
	return f, err
}
func refreshIdentity(ctx context.Context) (string, string, []byte, error) {
	claims, ok := rpc.VerifiedClaims(ctx)
	meta, has := rpc.Metadata(ctx)
	if !ok || !has || claims.Operation != v1.RefreshMessageIndex.ID || meta.IdempotencyKey == "" || len(meta.IdempotencyKey) > 128 {
		return "", "", nil, security.ErrDenied
	}
	hash, err := provisionHash(ctx)
	return claims.Subject, meta.IdempotencyKey, hash, err
}
func completedRefresh(ctx context.Context, db *gorm.DB, actor, key string, hash []byte) (bool, error) {
	var saved struct{ RequestHash []byte }
	err := db.WithContext(ctx).Table("command_results").Select("request_hash").Where("actor=? AND operation=? AND idempotency_key=?", actor, v1.RefreshMessageIndex.ID, key).Take(&saved).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, dbError(err)
	}
	if !bytes.Equal(saved.RequestHash, hash) {
		return false, conflict()
	}
	return true, nil
}

// stageRefresh runs only from the resource policy, before command replay/SQL.
// Neither credentials nor invocation/session tokens enter the staging record.
func (s *Module) stageRefresh(ctx context.Context) error {
	meta, _ := rpc.Metadata(ctx)
	var q v1.RefreshMessages
	if json.Unmarshal(meta.Payload, &q) != nil || q.Generation < 1 || !q.MessageQuery.Valid() {
		return invalid()
	}
	actor, key, hash, err := refreshIdentity(ctx)
	if err != nil {
		return err
	}
	if done, err := completedRefresh(ctx, s.db(ctx), actor, key, hash); done || err != nil {
		return err
	}
	var pending refreshStage
	err = s.db(ctx).Where("actor=? AND idempotency_key=?", actor, key).Take(&pending).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return dbError(err)
	}
	if err == nil && !bytes.Equal(pending.RequestHash, hash) {
		return conflict()
	}
	baseline, err := readIndexFolder(ctx, s.db(ctx), q.RootID, q.Generation, q.WireName)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return dbError(err)
	}
	row, remote, err := s.remoteRead(ctx, q.Scope, "mail.read", q.Generation, func(ctx context.Context, settings imapclient.Settings, password []byte) imapclient.Result {
		return s.Probe.Messages(ctx, settings, password, q.MessageQuery)
	})
	if err != nil {
		return err
	}
	// A known namespace reset is committed as invalidation before accepting a
	// rescan, even when the caller omitted UIDVALIDITY. Quotas cannot keep an
	// observed old namespace usable by rolling back a too-large new snapshot.
	if baseline.ID != "" && remote.Status == "ok" && remote.Page.UIDValidity != baseline.UIDValidity {
		remote.Status = "uidvalidity_changed"
		remote.Page.Messages = []imapclient.Message{}
		remote.Page.NextBeforeUID = 0
	}
	snapshot := refreshSnapshot{AccountRevision: row.Revision, CredentialVersion: row.CredentialVersion, State: row.State, FolderID: baseline.ID, FolderRevision: baseline.Revision, Status: remote.Status, Page: remote.Page}
	raw, err := json.Marshal(snapshot)
	if err != nil || len(raw) > indexStageBytes {
		return indexCapacity()
	}
	return database.RetryBusy(ctx, func() error {
		return s.db(ctx).Transaction(func(tx *gorm.DB) error {
			// A competing identical request may have committed while IMAP was running.
			if done, err := completedRefresh(ctx, tx, actor, key, hash); done || err != nil {
				return err
			}
			current, err := account(ctx, tx, q.Scope)
			if err != nil {
				return err
			}
			if current.Revision != row.Revision || current.Generation != q.Generation || current.CredentialVersion != row.CredentialVersion || current.State != row.State {
				return conflict()
			}
			now := time.Now().Unix()
			if err := tx.Exec("DELETE FROM mail_refresh_staging WHERE acl_root_id=? AND created_unix<?", q.RootID, now-indexPendingSeconds).Error; err != nil {
				return dbError(err)
			}
			var old refreshStage
			found := tx.Where("actor=? AND idempotency_key=?", actor, key).Take(&old).Error
			if found == nil && !bytes.Equal(old.RequestHash, hash) {
				return conflict()
			}
			if found != nil && !errors.Is(found, gorm.ErrRecordNotFound) {
				return dbError(found)
			}
			if errors.Is(found, gorm.ErrRecordNotFound) {
				var count int64
				if err := tx.Model(&refreshStage{}).Where("acl_root_id=?", q.RootID).Count(&count).Error; err != nil {
					return dbError(err)
				}
				if count >= indexPendingBatches {
					return indexCapacity()
				}
			}
			return dbError(tx.Exec(`INSERT INTO mail_refresh_staging(actor,idempotency_key,request_hash,acl_root_id,snapshot,created_unix) VALUES(?,?,?,?,?,?) ON CONFLICT(actor,idempotency_key) DO UPDATE SET snapshot=excluded.snapshot,created_unix=excluded.created_unix`, actor, key, hash, q.RootID, raw, now).Error)
		})
	})
}
func indexCapacity() error {
	return &rpc.Error{Code: rpc.CodeConflict, Message: "Mail index capacity exceeded"}
}
func (s *Module) refreshIndex(ctx context.Context, tx *gorm.DB, q v1.RefreshMessages) (v1.RefreshResult, error) {
	empty := v1.RefreshResult{}
	actor, key, hash, err := refreshIdentity(ctx)
	if err != nil {
		return empty, err
	}
	var staged refreshStage
	if err = tx.Where("actor=? AND idempotency_key=?", actor, key).Take(&staged).Error; err != nil {
		return empty, dbError(err)
	}
	if staged.RootID != q.RootID || !bytes.Equal(staged.RequestHash, hash) {
		return empty, conflict()
	}
	var snapshot refreshSnapshot
	if json.Unmarshal(staged.Snapshot, &snapshot) != nil {
		return empty, security.ErrUnavailable
	}
	row, err := account(ctx, tx, q.Scope)
	if err != nil {
		return empty, err
	}
	if row.Generation != q.Generation || row.Revision != snapshot.AccountRevision || row.CredentialVersion != snapshot.CredentialVersion || row.State != snapshot.State {
		return empty, conflict()
	}
	result := v1.RefreshResult{Scope: q.Scope, Generation: q.Generation, Status: snapshot.Status}
	if snapshot.Status == "ok" || snapshot.Status == "uidvalidity_changed" {
		f, err := readIndexFolder(ctx, tx, q.RootID, q.Generation, q.WireName)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return empty, dbError(err)
		}
		if f.ID != snapshot.FolderID || f.Revision != snapshot.FolderRevision {
			return empty, conflict()
		}
		if snapshot.Page.UIDValidity == 0 || snapshot.Page.UIDNext == 0 {
			return empty, security.ErrUnavailable
		}
		if f.ID == "" {
			var count int64
			if err := tx.Model(&indexFolder{}).Where("acl_root_id=?", q.RootID).Count(&count).Error; err != nil {
				return empty, dbError(err)
			}
			if count >= indexFolders {
				return empty, indexCapacity()
			}
			f = indexFolder{ID: newID(), RootID: q.RootID, Generation: q.Generation, WireName: q.WireName}
		}
		if f.UIDValidity != snapshot.Page.UIDValidity {
			removed := tx.Model(&indexMessage{}).Where("folder_id=? AND present=1", f.ID).Update("present", false)
			if removed.Error != nil {
				return empty, dbError(removed.Error)
			}
			result.Removed += int(removed.RowsAffected)
		}
		f.UIDValidity = snapshot.Page.UIDValidity
		f.UIDNext = snapshot.Page.UIDNext
		f.RemoteCount = snapshot.Page.Exists
		f.NextBeforeUID = snapshot.Page.NextBeforeUID
		f.Status = snapshot.Status
		f.UpdatedAt = time.Now().UTC()
		f.Revision++
		f.LowUID, f.HighUID = 0, 0
		if snapshot.Status == "ok" && snapshot.Page.Exists > 0 {
			before := q.BeforeUID
			if before == 0 {
				before = snapshot.Page.UIDNext
			}
			if before > 1 {
				f.HighUID = before - 1
				f.LowUID = 1
				if f.HighUID >= q.UIDWindow {
					f.LowUID = f.HighUID - q.UIDWindow + 1
				}
			}
		}
		if err := tx.Save(&f).Error; err != nil {
			return empty, dbError(err)
		}
		if snapshot.Status == "ok" {
			uids := []uint32{}
			seen := map[uint32]bool{}
			for _, message := range snapshot.Page.Messages {
				if message.UID < f.LowUID || message.UID > f.HighUID || seen[message.UID] {
					return empty, security.ErrUnavailable
				}
				seen[message.UID] = true
				raw, err := json.Marshal(message)
				if err != nil || len(raw) > indexMessageBytes {
					return empty, indexCapacity()
				}
				if err := tx.Exec(`INSERT INTO mail_messages(id,folder_id,uid_validity,uid,present,summary,internal_unix) VALUES(?,?,?,?,1,?,?) ON CONFLICT(folder_id,uid_validity,uid) DO UPDATE SET present=1,summary=excluded.summary,internal_unix=excluded.internal_unix`, newID(), f.ID, f.UIDValidity, message.UID, raw, message.InternalDate.UnixMicro()).Error; err != nil {
					return empty, dbError(err)
				}
				uids = append(uids, message.UID)
			}
			absent := tx.Model(&indexMessage{}).Where("folder_id=? AND uid_validity=? AND present=1", f.ID, f.UIDValidity)
			if snapshot.Page.Exists > 0 {
				absent = absent.Where("uid BETWEEN ? AND ?", f.LowUID, f.HighUID)
			}
			if len(uids) > 0 {
				absent = absent.Where("uid NOT IN ?", uids)
			}
			removed := absent.Update("present", false)
			if removed.Error != nil {
				return empty, dbError(removed.Error)
			}
			result.Upserted = len(uids)
			result.Removed += int(removed.RowsAffected)
		}
		var quota struct {
			Count int64
			Size  int64
		}
		if err := tx.Raw("SELECT count(*) AS count,COALESCE(sum(length(m.summary)),0) AS size FROM mail_messages m JOIN mail_folders f ON f.id=m.folder_id WHERE f.acl_root_id=?", q.RootID).Scan(&quota).Error; err != nil {
			return empty, dbError(err)
		}
		if quota.Count > indexMessages || quota.Size > indexTotalBytes {
			return empty, indexCapacity()
		}
		if err := tx.Exec("INSERT INTO audit(acl_root_id,actor,operation,revision,generation) VALUES(?,?,?,?,?)", q.RootID, actor, v1.RefreshMessageIndex.ID, row.Revision, row.Generation).Error; err != nil {
			return empty, dbError(err)
		}
		payload, err := json.Marshal(v1.MessagesChanged{Scope: q.Scope, Generation: q.Generation, FolderID: f.ID, Revision: f.Revision, UIDValidity: f.UIDValidity})
		if err != nil {
			return empty, err
		}
		if err = (events.Store{DB: s.DB}).Enqueue(ctx, tx, s.Contract, v1.MessagesChangedSubject, events.Envelope{ID: newID(), Type: v1.MessagesChangedName, Version: 1, AggregateID: f.ID, OccurredAt: f.UpdatedAt, Payload: payload}); err != nil {
			return empty, err
		}
		dto := folderDTO(f)
		result.Folder = &dto
	}
	if err := tx.Where("actor=? AND idempotency_key=?", actor, key).Delete(&refreshStage{}).Error; err != nil {
		return empty, dbError(err)
	}
	return result, nil
}
func cachedMessageDTO(m indexMessage) (v1.CachedMessage, error) {
	var summary imapclient.Message
	if json.Unmarshal(m.Summary, &summary) != nil || summary.UID != m.UID {
		return v1.CachedMessage{}, security.ErrUnavailable
	}
	return v1.CachedMessage{ID: m.ID, FolderID: m.FolderID, UIDValidity: m.UIDValidity, Message: summary}, nil
}
func (s *Module) checkIndexRead(ctx context.Context, scope v1.Scope, generation int64, f indexFolder) error {
	if err := s.Check(ctx, scope.RootID, "mail.read"); err != nil {
		return err
	}
	row, err := s.root(ctx, scope)
	if err != nil {
		return err
	}
	if row.Generation != generation {
		return conflict()
	}
	latest, err := readIndexFolder(ctx, s.db(ctx), scope.RootID, generation, f.WireName)
	if err != nil {
		return dbError(err)
	}
	if latest.ID != f.ID || latest.Revision != f.Revision || latest.UIDValidity != f.UIDValidity {
		return conflict()
	}
	return nil
}
func (s *Module) listCached(ctx context.Context, q v1.CachedListQuery) (v1.CachedList, error) {
	empty := v1.CachedList{}
	selector := imapclient.MessageQuery{WireName: q.WireName, UIDWindow: 1, UIDValidity: q.UIDValidity, BeforeUID: q.BeforeUID}
	if q.Generation < 1 || q.Limit < 1 || q.Limit > 20 || !selector.Valid() {
		return empty, invalid()
	}
	row, err := s.root(ctx, q.Scope)
	if err != nil {
		return empty, err
	}
	if row.Generation != q.Generation {
		return empty, conflict()
	}
	f, err := readIndexFolder(ctx, s.db(ctx), q.RootID, q.Generation, q.WireName)
	if err != nil {
		return empty, dbError(err)
	}
	if q.UIDValidity != 0 && q.UIDValidity != f.UIDValidity {
		return empty, conflict()
	}
	query := s.db(ctx).Where("folder_id=? AND uid_validity=? AND present=1", f.ID, f.UIDValidity)
	if q.BeforeUID > 0 {
		query = query.Where("uid<?", q.BeforeUID)
	}
	var rows []indexMessage
	if err = query.Order("uid DESC").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
		return empty, dbError(err)
	}
	result := v1.CachedList{Scope: q.Scope, Generation: q.Generation, Folder: folderDTO(f), Messages: []v1.CachedMessage{}}
	for i, message := range rows {
		if i >= q.Limit {
			result.NextBeforeUID = rows[i-1].UID
			break
		}
		dto, err := cachedMessageDTO(message)
		if err != nil {
			return empty, err
		}
		result.Messages = append(result.Messages, dto)
		raw, err := json.Marshal(result)
		if err != nil {
			return empty, err
		}
		if len(raw) > (128<<10)-64 {
			result.Messages = result.Messages[:len(result.Messages)-1]
			if len(result.Messages) == 0 {
				return empty, indexCapacity()
			}
			result.NextBeforeUID = result.Messages[len(result.Messages)-1].UID
			break
		}
	}
	if err := s.checkIndexRead(ctx, q.Scope, q.Generation, f); err != nil {
		return empty, err
	}
	return result, nil
}
func (s *Module) getCached(ctx context.Context, q v1.CachedGetQuery) (v1.CachedGet, error) {
	empty := v1.CachedGet{}
	if q.Generation < 1 || !idPattern.MatchString(q.MessageID) {
		return empty, invalid()
	}
	row, err := s.root(ctx, q.Scope)
	if err != nil {
		return empty, err
	}
	if row.Generation != q.Generation {
		return empty, conflict()
	}
	var message indexMessage
	err = s.db(ctx).Table("mail_messages AS m").Select("m.*").Joins("JOIN mail_folders f ON f.id=m.folder_id").Where("m.id=? AND f.acl_root_id=? AND f.generation=? AND m.present=1 AND m.uid_validity=f.uid_validity", q.MessageID, q.RootID, q.Generation).Take(&message).Error
	if err != nil {
		return empty, dbError(err)
	}
	var f indexFolder
	if err = s.db(ctx).Where("id=? AND acl_root_id=? AND generation=?", message.FolderID, q.RootID, q.Generation).Take(&f).Error; err != nil {
		return empty, dbError(err)
	}
	if f.UIDValidity != message.UIDValidity {
		return empty, dbError(gorm.ErrRecordNotFound)
	}
	dto, err := cachedMessageDTO(message)
	if err != nil {
		return empty, err
	}
	if err = s.checkIndexRead(ctx, q.Scope, q.Generation, f); err != nil {
		return empty, err
	}
	return v1.CachedGet{Scope: q.Scope, Generation: q.Generation, WireName: f.WireName, CachedMessage: dto}, nil
}

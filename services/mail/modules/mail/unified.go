package mail

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/access"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/imapclient"
	"gorm.io/gorm"
)

// This cursor is a position selector, never a permission or authorization token.
type unifiedCursor struct {
	Version      int    `json:"version"`
	Sources      string `json:"sources"`
	InternalUnix int64  `json:"internal_unix"`
	ID           string `json:"id"`
}

func normalizedSources(sources []v1.UnifiedSource) ([]v1.UnifiedSource, []string, error) {
	if len(sources) < 1 || len(sources) > 20 {
		return nil, nil, invalid()
	}
	out := append([]v1.UnifiedSource{}, sources...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].RootID != out[j].RootID {
			return out[i].RootID < out[j].RootID
		}
		return out[i].WireName < out[j].WireName
	})
	roots := []string{}
	generations := map[string]int64{}
	for i, source := range out {
		if !idPattern.MatchString(source.RootID) || source.Generation < 1 || !(imapclient.MessageQuery{WireName: source.WireName, UIDWindow: 1}).Valid() {
			return nil, nil, invalid()
		}
		generation, seen := generations[source.RootID]
		if seen && generation != source.Generation || i > 0 && out[i-1].RootID == source.RootID && out[i-1].WireName == source.WireName {
			return nil, nil, invalid()
		}
		if !seen {
			roots = append(roots, source.RootID)
			generations[source.RootID] = source.Generation
		}
	}
	return out, roots, nil
}
func sourceDigest(states []v1.UnifiedSourceState) string {
	raw, _ := json.Marshal(states)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func parseUnifiedCursor(value, digest string) (unifiedCursor, error) {
	if len(value) > 512 {
		return unifiedCursor{}, invalid()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	var cursor unifiedCursor
	if err != nil || contract.Strict(raw, &cursor) != nil || cursor.Version != 1 || !idPattern.MatchString(cursor.ID) {
		return cursor, invalid()
	}
	if cursor.Sources != digest {
		return cursor, conflict()
	}
	return cursor, nil
}
func makeUnifiedCursor(digest string, message v1.CachedGet) string {
	raw, _ := json.Marshal(unifiedCursor{Version: 1, Sources: digest, InternalUnix: message.InternalDate.UnixMicro(), ID: message.ID})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func (s *Module) checkUnifiedAccess(ctx context.Context, roots []string) (int64, error) {
	next, err := s.provisionContext(ctx, "access.v1.check_many", "")
	if err != nil {
		return 0, err
	}
	checks := make([]access.CheckRequest, 0, len(roots))
	for _, root := range roots {
		checks = append(checks, access.CheckRequest{ResourceID: root, Action: "mail.read"})
	}
	decisions, err := (&access.Client{RPC: s.Identity.RPC}).CheckMany(next, access.CheckManyRequest{Checks: checks})
	if err != nil {
		return 0, err
	}
	if len(decisions.Decisions) != len(checks) || decisions.Revision < 1 {
		return 0, rpc.SecurityError(security.ErrUnavailable)
	}
	for _, decision := range decisions.Decisions {
		if !decision.Allowed {
			return 0, rpc.SecurityError(security.ErrDenied)
		}
	}
	return decisions.Revision, nil
}
func (s *Module) unifiedSources(ctx context.Context, sources []v1.UnifiedSource) ([]v1.UnifiedSourceState, map[string]v1.UnifiedSourceState, error) {
	states := make([]v1.UnifiedSourceState, 0, len(sources))
	folders := map[string]v1.UnifiedSourceState{}
	checked := map[string]bool{}
	for _, source := range sources {
		if !checked[source.RootID] {
			account, err := s.root(ctx, v1.Scope{RootID: source.RootID})
			if err != nil {
				return nil, nil, err
			}
			if account.Generation != source.Generation {
				return nil, nil, conflict()
			}
			checked[source.RootID] = true
		}
		state := v1.UnifiedSourceState{UnifiedSource: source}
		folder, err := readIndexFolder(ctx, s.db(ctx), source.RootID, source.Generation, source.WireName)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, dbError(err)
		}
		if err == nil {
			if !idPattern.MatchString(folder.ID) || folder.UIDValidity == 0 {
				return nil, nil, rpc.SecurityError(security.ErrUnavailable)
			}
			if _, duplicate := folders[folder.ID]; duplicate {
				return nil, nil, rpc.SecurityError(security.ErrUnavailable)
			}
			state.Indexed = true
			state.FolderID = folder.ID
			state.UIDValidity = folder.UIDValidity
			folders[folder.ID] = state
		}
		states = append(states, state)
	}
	return states, folders, nil
}
func (s *Module) listUnified(ctx context.Context, q v1.UnifiedQuery) (v1.UnifiedList, error) {
	empty := v1.UnifiedList{}
	if _, err := collectionUser(ctx); err != nil {
		return empty, rpc.SecurityError(err)
	}
	if q.WorkspaceID != "" || q.Limit < 1 || q.Limit > 20 || len(q.Cursor) > 512 {
		return empty, invalid()
	}
	sources, roots, err := normalizedSources(q.Sources)
	if err != nil {
		return empty, err
	}
	revision, err := s.checkUnifiedAccess(ctx, roots)
	if err != nil {
		return empty, err
	}
	states, folders, err := s.unifiedSources(ctx, sources)
	if err != nil {
		return empty, err
	}
	digest := sourceDigest(states)
	var cursor unifiedCursor
	if q.Cursor != "" {
		cursor, err = parseUnifiedCursor(q.Cursor, digest)
		if err != nil {
			return empty, err
		}
	}
	result := v1.UnifiedList{Sources: states, Messages: []v1.CachedGet{}, PolicyRevision: revision}
	if len(folders) > 0 {
		ids := make([]string, 0, len(folders))
		for id := range folders {
			ids = append(ids, id)
		}
		query := s.db(ctx).Table("mail_messages AS m").Select("m.*").Joins("JOIN mail_folders f ON f.id=m.folder_id").Where("m.folder_id IN ? AND m.present=1 AND m.uid_validity=f.uid_validity", ids)
		if q.Cursor != "" {
			query = query.Where("(m.internal_unix<? OR (m.internal_unix=? AND m.id<?))", cursor.InternalUnix, cursor.InternalUnix, cursor.ID)
		}
		var rows []indexMessage
		if err = query.Order("m.internal_unix DESC,m.id DESC").Limit(q.Limit + 1).Find(&rows).Error; err != nil {
			return empty, dbError(err)
		}
		for i, message := range rows {
			if i >= q.Limit {
				break
			}
			source, ok := folders[message.FolderID]
			if !ok || source.UIDValidity != message.UIDValidity {
				return empty, conflict()
			}
			dto, err := cachedMessageDTO(message)
			if err != nil {
				return empty, err
			}
			if message.InternalUnix != dto.InternalDate.UnixMicro() {
				return empty, rpc.SecurityError(security.ErrUnavailable)
			}
			result.Messages = append(result.Messages, v1.CachedGet{Scope: v1.Scope{RootID: source.RootID}, Generation: source.Generation, WireName: source.WireName, CachedMessage: dto})
			raw, err := json.Marshal(result)
			if err != nil {
				return empty, err
			}
			// Reserve space for the bounded continuation and a final policy revision.
			if len(raw) > (128<<10)-512 {
				result.Messages = result.Messages[:len(result.Messages)-1]
				if len(result.Messages) == 0 {
					return empty, indexCapacity()
				}
				break
			}
		}
		if len(result.Messages) < len(rows) {
			result.NextCursor = makeUnifiedCursor(digest, result.Messages[len(result.Messages)-1])
		}
	}
	// Include every selected root in the final check, even if its folder has no
	// local messages. Neither a partial page nor source metadata escapes denial.
	result.PolicyRevision, err = s.checkUnifiedAccess(ctx, roots)
	if err != nil {
		return empty, err
	}
	latest, _, err := s.unifiedSources(ctx, sources)
	if err != nil {
		return empty, err
	}
	if sourceDigest(latest) != digest {
		return empty, conflict()
	}
	return result, nil
}

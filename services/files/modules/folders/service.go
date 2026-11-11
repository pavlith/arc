// Package folders owns scoped folder mutations and live Access enforcement.
package folders

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"gorm.io/gorm"
)

type Service struct {
	GormDB   *gorm.DB
	Identity identity.Client
	Contract *contract.Compiled
	Check func(context.Context, string, string) error
}

// NewID is a cryptographically random RFC 4122 v4 UUID.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func (*Service) ID() string { return "folders" }

func (s *Service) Register(r *module.Registry) error {
	if s == nil || s.GormDB == nil || s.Contract == nil || s.Check == nil {
		return security.ErrUnavailable
	}
	policy := module.Policy{Resource: s.Authorize}
	store := events.Store{DB: s.GormDB}
	if err := module.BindCommand(r, filesv1.FolderCreate, policy, store, s.create); err != nil {
		return err
	}
	if err := module.BindQuery(r, filesv1.FolderGet, policy, s.get); err != nil {
		return err
	}
	if err := module.BindQuery(r, filesv1.FolderList, policy, s.list); err != nil {
		return err
	}
	if err := module.BindCommand(r, filesv1.FolderRename, policy, store, s.rename); err != nil {
		return err
	}
	if err := module.BindCommand(r, filesv1.FolderMove, policy, store, s.move); err != nil {
		return err
	}
	return module.BindCommand(r, filesv1.FolderArchive, policy, store, s.archive)
}

// Authorize rejects forged root/workspace bindings BEFORE the online Access
// check. This policy runs even for replayed idempotency keys.
func (s *Service) Authorize(ctx context.Context, root, action string) error {
	meta, ok := rpc.Metadata(ctx)
	cl, verified := rpc.VerifiedClaims(ctx)
	if !ok || !verified || !strings.HasPrefix(cl.Subject, "user:") {
		return security.ErrUnauthenticated
	}
	var scope filesv1.Scope
	if json.Unmarshal(meta.Payload, &scope) != nil || root == "" ||
		root != scope.RootID || cl.WorkspaceID != scope.WorkspaceID || scope.WorkspaceID == "" {
		return security.ErrDenied
	}
	var exists bool
	if err := s.GormDB.WithContext(ctx).Raw(
		"SELECT EXISTS(SELECT 1 FROM roots WHERE acl_root_id=? AND workspace_id=? AND state='active')",
		root, scope.WorkspaceID).Row().Scan(&exists); err != nil {
		return security.ErrUnavailable
	}
	if !exists {
		return security.ErrDenied
	}
	return s.Check(ctx, root, action)
}

func invalid() error {
	return &rpc.Error{Code: rpc.CodeValidation, Message: "invalid Files folder input"}
}
func conflict() error {
	return &rpc.Error{Code: rpc.CodeConflict, Message: "Files folder revision or sibling conflict"}
}
func notFound() error {
	return &rpc.Error{Code: rpc.CodeNotFound, Message: "Files folder not found"}
}
func unavailable(err error) error {
	if err == nil {
		return nil
	}
	var e *rpc.Error
	if errors.As(err, &e) {
		return err
	}
	return rpc.SecurityError(security.ErrUnavailable)
}

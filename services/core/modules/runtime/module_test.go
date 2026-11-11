package runtime_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/runtime"
	"gorm.io/gorm"
)

func TestRuntimeModuleHasNoUnapprovedDesiredStateEndpoint(t *testing.T) {
	m := &runtime.Module{GormDB: &gorm.DB{}}
	if _, err := m.Bind(nil); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("missing operator policy accepted: %v", err)
	}
	m.Authorize = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err := m.Bind(nil); err != nil {
		t.Fatalf("in-process module bootstrap refused: %v", err)
	}
}

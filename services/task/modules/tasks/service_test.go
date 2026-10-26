package tasks_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/task/modules/tasks"
	"gorm.io/gorm"
)

func TestNoVerifiedInvocationNoACL(t *testing.T) {
	svc := &tasks.Service{GormDB: &gorm.DB{}, Check: func(context.Context, string, string) error {
		t.Fatal("ACL called with unverified actor")
		return nil
	}}
	if err := svc.Authorize(context.Background(), "root", "task.read"); !errors.Is(err, security.ErrUnauthenticated) {
		t.Fatal("unverified invocation accepted", err)
	}
}

package runtime_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

func TestRuntimeRefusesUnapprovedDesiredState(t *testing.T) {
	m := &runtime.Module{DB: &sql.DB{}}
	if _, err := m.Put(context.Background(), runtime.Desired{ID: "instance", ServiceName: "task",
		Replicas: 1, Spec: json.RawMessage(`{"image":"tasks:v1"}`)}, 0); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("missing online auth allowed desired state: %v", err)
	}
	if _, err := m.Get(context.Background(), "instance"); !errors.Is(err, security.ErrUnavailable) {
		t.Fatalf("missing online auth allowed read: %v", err)
	}
	m.Authorize = func(context.Context, string, string) error { return security.ErrDenied }
	if _, err := m.Put(context.Background(), runtime.Desired{ID: "instance", ServiceName: "task",
		Replicas: 1, Spec: json.RawMessage(`{"image":"tasks:v1"}`)}, 0); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("denied operator could set desired state: %v", err)
	}
	if _, err := m.Get(context.Background(), "instance"); !errors.Is(err, security.ErrDenied) {
		t.Fatalf("denied operator could read desired state: %v", err)
	}
	if _, err := m.Bind(nil); err != nil {
		t.Fatalf("module failed in-process bootstrap binding: %v", err)
	}
}

func TestRuntimeRejectsInvalidDeploymentBeforeDatabase(t *testing.T) {
	m := &runtime.Module{DB: &sql.DB{}, Authorize: func(context.Context, string, string) error {
		t.Fatal("invalid request reached authorization")
		return nil
	}}
	for _, want := range []runtime.Desired{
		{ServiceName: "task", Replicas: 1, Spec: json.RawMessage("{}")},
		{ID: "d", Replicas: 1, Spec: json.RawMessage("{}")},
		{ID: "d", ServiceName: "task", Replicas: -1, Spec: json.RawMessage("{}")},
		{ID: "d", ServiceName: "task", Replicas: 1, Spec: json.RawMessage("{")},
	} {
		if _, err := m.Put(context.Background(), want, 0); !errors.Is(err, runtime.ErrInvalid) {
			t.Fatalf("invalid desired state passed: %+v, %v", want, err)
		}
	}
}

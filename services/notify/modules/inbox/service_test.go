package inbox_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/pavlith/arc/pkgs/events"
	"github.com/pavlith/arc/pkgs/security"
	"github.com/pavlith/arc/services/notify/modules/inbox"
)

func TestRecipientNotTakenFromInvalidEvent(t *testing.T) {
	s := &inbox.Service{DB: &sql.DB{}}
	if err := s.Effect(context.Background(), nil, events.Envelope{
		AggregateID: "task-id", Payload: []byte(`{"task_id":"spoofed","recipient":"attacker"}`),
	}); !errors.Is(err, security.ErrDenied) {
		t.Fatal("invalid producer payload accepted", err)
	}
}

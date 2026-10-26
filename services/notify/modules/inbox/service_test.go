package inbox_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/notify/modules/inbox"
	"gorm.io/gorm"
)

func TestRecipientNotTakenFromInvalidEvent(t *testing.T) {
	s := &inbox.Service{GormDB: &gorm.DB{}}
	if err := s.Effect(context.Background(), nil, events.Envelope{
		AggregateID: "task-id", Payload: []byte(`{"task_id":"spoofed","recipient":"attacker"}`),
	}); !errors.Is(err, security.ErrDenied) {
		t.Fatal("invalid producer payload accepted", err)
	}
}

package module_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/events"
	"github.com/pavlith/arc/pkgs/internal/testcontract"
	"github.com/pavlith/arc/pkgs/module"
	"github.com/pavlith/arc/pkgs/security"
)

func TestTypedEventRequiresDomainTransaction(t *testing.T) {
	artifact, err := contract.Compile(testcontract.Artifact(1))
	if err != nil {
		t.Fatal(err)
	}
	def := module.Event[struct {
		Value string `json:"value"`
	}]{
		Name: "books.item.created", Subject: "evt.books.item.created.v1",
	}
	event := events.Envelope{ID: "f164acdc-56fd-4dcf-8c57-5ef345b30db4", Version: 1,
		AggregateID: "root", OccurredAt: time.Now().UTC()}
	if err := module.EnqueueEvent(context.Background(), events.Store{},
		nil, artifact, def, event, struct {
			Value string `json:"value"`
		}{Value: "ok"}); !errors.Is(err, security.ErrUnavailable) {
		t.Fatal("uncommitted outbox event accepted", err)
	}
	if err := module.EnqueueEvent(context.Background(), events.Store{},
		nil, artifact, module.Event[struct {
			Value string `json:"value"`
		}]{Name: "foreign", Subject: def.Subject},
		event, struct {
			Value string `json:"value"`
		}{Value: "ok"}); err == nil {
		t.Fatal("foreign event unexpectedly accepted")
	}
}

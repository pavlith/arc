package services_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/notify"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	"github.com/pavlith/arc/services/task"
	tasksv1 "github.com/pavlith/arc/services/task/api/v1"
)

type closedRegistry struct{ calls int }

func (r *closedRegistry) Register(context.Context, *nats.Conn, sdk.Registration) error {
	r.calls++
	return security.ErrDenied
}
func (r *closedRegistry) Ready(context.Context, sdk.Registration, sdk.ReadyEvidence) error {
	r.calls++
	return security.ErrDenied
}
func (r *closedRegistry) Check(context.Context, sdk.Registration) error {
	r.calls++
	return security.ErrDenied
}
func (r *closedRegistry) EventPermit(context.Context, sdk.Registration, fabric.EventSubscription) error {
	r.calls++
	return security.ErrDenied
}

func TestTaskNotifyComposeNoNetworkAndExactSubscription(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := &closedRegistry{}
	id := identity.Client{RPC: &rpc.Client{}, ServiceID: "instance-uuid", Kid: "instance-key", PrivateKey: private}
	tasks, err := task.New(task.Config{
		DB: &sql.DB{}, Runtime: sdk.AppConfig{Registry: reg, Instance: "tasks-instance"},
		Identity: id, CoreTrust: pub,
	})
	if err != nil {
		t.Fatalf("task composition: %v", err)
	}
	t.Cleanup(func() { _ = tasks.Stop() })
	if tasks.App.Connection() != nil || tasks.Tasks.ID() != "tasks" || tasks.Publisher.ID() != "outbox" {
		t.Fatal("task composition unexpectedly opened a connection")
	}
	source, err := contract.Compile(tasksv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	cfg := notify.Config{
		DB: &sql.DB{}, Runtime: sdk.AppConfig{Instance: "notify-instance"},
		Identity: id, CoreTrust: pub, Registry: reg,
		Subscription: fabric.EventSubscription{
			Provider: "publisher-uuid", Digest: source.Digest,
			Subject: tasksv1.CreatedSubject, Durable: "notifications-task-created-v1",
		},
		Provider: &delivery.FakeProvider{},
	}
	notifications, err := notify.New(cfg)
	if err != nil {
		t.Fatalf("notify composition: %v", err)
	}
	t.Cleanup(func() { _ = notifications.Stop() })
	if notifications.App.Connection() != nil || notifications.Inbox.ID() != "inbox" ||
		notifications.Delivery.ID() != "delivery" {
		t.Fatal("notify composition unexpectedly opened a connection")
	}
	if reg.calls != 0 {
		t.Fatal("composition contacted Fabric before Start")
	}
	for _, mutate := range []func(*notify.Config){
		func(c *notify.Config) { c.Subscription.Subject = "evt.rogue" },
		func(c *notify.Config) { c.Subscription.Digest = "incorrect" },
		func(c *notify.Config) { c.Subscription.Durable = "wrong-durable" },
		func(c *notify.Config) { c.Subscription.Provider = "" },
		func(c *notify.Config) { c.Provider = nil },
	} {
		bad := cfg
		mutate(&bad)
		if _, err := notify.New(bad); !errors.Is(err, notify.ErrInvalid) {
			t.Fatalf("unapproved subscription/provider accepted: %v", err)
		}
	}
}

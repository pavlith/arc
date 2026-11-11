package gate

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

func TestRealtimeEventValidationAndRecipientIsolation(t *testing.T) {
	task, err := contract.Compile(taskv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	notify, err := contract.Compile(notifyv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	h := &realtimeHub{task: task, notify: notify}
	const (
		workspace = "00000000-0000-4000-8000-000000000001"
		root      = "00000000-0000-4000-8000-000000000002"
		user      = "00000000-0000-4000-8000-000000000003"
		other     = "00000000-0000-4000-8000-000000000004"
		entity    = "00000000-0000-4000-8000-000000000005"
		eventID   = "00000000-0000-4000-8000-000000000006"
	)
	encode := func(kind, aggregate string, v any) []byte {
		t.Helper()
		payload, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(events.Envelope{
			ID: eventID, Type: kind, Version: 1, AggregateID: aggregate,
			OccurredAt: time.Now().UTC(), Payload: payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := encode(taskv1.CatalogChangedName, entity, taskv1.CatalogChanged{
		Scope:      taskv1.Scope{WorkspaceID: workspace, RootID: root},
		EntityKind: "work", EntityID: entity, Revision: 2,
	})
	item, ok := h.parse(taskv1.CatalogChangedSubject, raw)
	if !ok || item.workspace != workspace || item.root != root || item.kind != "work" || item.revision != 2 {
		t.Fatal("valid Task invalidation was rejected")
	}
	if _, ok := h.parse(notifyv1.InboxChangedSubject, raw); ok {
		t.Fatal("Task event accepted on Notify subject")
	}
	if _, ok := h.parse(taskv1.CatalogChangedSubject, encode(taskv1.CatalogChangedName, entity,
		taskv1.CatalogChanged{Scope: taskv1.Scope{WorkspaceID: workspace}, EntityKind: "work", EntityID: entity, Revision: 2})); ok {
		t.Fatal("unbound Task root accepted")
	}
	if _, ok := h.parse(taskv1.CatalogChangedSubject, encode(taskv1.CatalogChangedName, entity,
		taskv1.CatalogChanged{Scope: taskv1.Scope{WorkspaceID: workspace, RootID: root}, EntityKind: "work", EntityID: entity, Revision: 0})); ok {
		t.Fatal("zero-revision Task invalidation accepted")
	}
	raw = encode(notifyv1.InboxChangedName, entity, notifyv1.InboxChanged{
		RecipientID: user, NotificationID: entity, Revision: 1,
	})
	item, ok = h.parse(notifyv1.InboxChangedSubject, raw)
	if !ok || item.recipient != user || item.kind != "inbox" {
		t.Fatal("valid Inbox event was rejected")
	}
	if _, ok := h.parse(notifyv1.InboxChangedSubject, encode(notifyv1.InboxChangedName, other,
		notifyv1.InboxChanged{RecipientID: user, NotificationID: entity, Revision: 1})); ok {
		t.Fatal("mismatched aggregate accepted")
	}
	if _, ok := h.parse(notifyv1.InboxChangedSubject, encode(notifyv1.InboxChangedName, entity,
		notifyv1.InboxChanged{RecipientID: "", NotificationID: entity, Revision: 1})); ok {
		t.Fatal("unbound Inbox recipient accepted")
	}
	if _, ok := h.parse(notifyv1.InboxChangedSubject, encode(notifyv1.InboxChangedName, entity,
		notifyv1.InboxChanged{RecipientID: user, NotificationID: entity, Revision: -1})); ok {
		t.Fatal("negative Inbox revision accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &realtimeClient{
		ctx: ctx, cancel: cancel, userID: user,
		subs:  map[string]liveSubscription{"only": {channel: "inbox"}},
		queue: make(chan queuedInvalidation, 32),
	}
	c.enqueue(invalidation{channel: "inbox", recipient: other, kind: "inbox", id: entity})
	if len(c.queue) != 0 {
		t.Fatal("cross-recipient event queued")
	}
	c.enqueue(item)
	if len(c.queue) != 1 {
		t.Fatal("own Inbox invalidation not queued")
	}
	c.mu.Lock()
	c.subs = map[string]liveSubscription{"task": {channel: "task", workspace: workspace, root: root}}
	c.mu.Unlock()
	c.enqueue(invalidation{channel: "task", workspace: workspace, root: other, id: entity})
	if len(c.queue) != 1 {
		t.Fatal("cross-root event queued")
	}
	c.enqueue(invalidation{channel: "task", workspace: workspace, root: root, id: entity})
	if len(c.queue) != 2 {
		t.Fatal("same-root event not queued")
	}
}

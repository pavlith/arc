package gate

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
)

type invalidation struct {
	channel   string
	workspace string
	root      string
	recipient string
	kind      string
	id        string
	revision  int64
}

type queuedInvalidation struct {
	subscriptionID string
	event          invalidation
}

type realtimeHub struct {
	nc            *nats.Conn
	task          *contract.Compiled
	notify        *contract.Compiled
	ready         atomic.Bool
	mu            sync.Mutex
	clients       map[*realtimeClient]struct{}
	subscriptions []*nats.Subscription
}

func newRealtimeHub(nc *nats.Conn) (*realtimeHub, error) {
	if nc == nil {
		return nil, errors.New("gate realtime: no broker connection")
	}
	task, err := contract.Compile(taskv1.Artifact())
	if err != nil {
		return nil, err
	}
	notify, err := contract.Compile(notifyv1.Artifact())
	if err != nil {
		return nil, err
	}
	return &realtimeHub{nc: nc, task: task, notify: notify, clients: map[*realtimeClient]struct{}{}}, nil
}

func (h *realtimeHub) start() error {
	if h.ready.Load() || !h.nc.IsConnected() {
		return errors.New("gate realtime: broker unavailable")
	}
	for _, subject := range []string{taskv1.CatalogChangedSubject, taskv1.CreatedSubject, notifyv1.InboxChangedSubject} {
		sub, err := h.nc.Subscribe(subject, func(msg *nats.Msg) {
			event, ok := h.parse(msg.Subject, msg.Data)
			if ok {
				h.broadcast(event)
			}
		})
		if err != nil {
			h.stop()
			return err
		}
		h.subscriptions = append(h.subscriptions, sub)
	}
	if err := h.nc.FlushTimeout(3 * time.Second); err != nil {
		h.stop()
		return err
	}
	if err := h.nc.LastError(); err != nil {
		h.stop()
		return err
	}
	h.ready.Store(true)
	return nil
}

func (h *realtimeHub) stop() {
	h.ready.Store(false)
	h.mu.Lock()
	clients := make([]*realtimeClient, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		c.stop()
	}
	for _, sub := range h.subscriptions {
		_ = sub.Unsubscribe()
	}
	h.subscriptions = nil
}

func (h *realtimeHub) parse(subject string, raw []byte) (invalidation, bool) {
	var envelope events.Envelope
	if len(raw) > 256<<10 || contract.Strict(raw, &envelope) != nil {
		return invalidation{}, false
	}
	compiled := h.task
	if subject == notifyv1.InboxChangedSubject {
		compiled = h.notify
	} else if subject != taskv1.CatalogChangedSubject && subject != taskv1.CreatedSubject {
		return invalidation{}, false
	}
	if events.Validate(compiled, subject, envelope) != nil {
		return invalidation{}, false
	}
	switch subject {
	case taskv1.CatalogChangedSubject:
		var change taskv1.CatalogChanged
		if json.Unmarshal(envelope.Payload, &change) != nil ||
			!realtimeUUID.MatchString(change.WorkspaceID) ||
			!realtimeUUID.MatchString(change.RootID) ||
			!realtimeUUID.MatchString(change.EntityID) ||
			change.Revision < 1 || change.EntityID != envelope.AggregateID {
			return invalidation{}, false
		}
		return invalidation{channel: "task", workspace: change.WorkspaceID, root: change.RootID,
			kind: change.EntityKind, id: change.EntityID, revision: change.Revision}, true
	case taskv1.CreatedSubject:
		var created taskv1.CreatedEvent
		if json.Unmarshal(envelope.Payload, &created) != nil ||
			!realtimeUUID.MatchString(created.WorkspaceID) ||
			!realtimeUUID.MatchString(created.RootID) ||
			!realtimeUUID.MatchString(created.TaskID) ||
			created.TaskID != envelope.AggregateID {
			return invalidation{}, false
		}
		return invalidation{channel: "task", workspace: created.WorkspaceID, root: created.RootID,
			kind: "work", id: created.TaskID, revision: 1}, true
	case notifyv1.InboxChangedSubject:
		var changed notifyv1.InboxChanged
		if json.Unmarshal(envelope.Payload, &changed) != nil {
			return invalidation{}, false
		}
		target := changed.NotificationID
		if target == "" {
			target = changed.RecipientID
		}
		if envelope.AggregateID != target ||
			!realtimeUUID.MatchString(changed.RecipientID) ||
			(changed.NotificationID != "" && !realtimeUUID.MatchString(changed.NotificationID)) ||
			changed.Revision < 0 {
			return invalidation{}, false
		}
		return invalidation{channel: "inbox", recipient: changed.RecipientID,
			kind: "inbox", id: changed.NotificationID, revision: changed.Revision}, true
	}
	return invalidation{}, false
}

func (h *realtimeHub) add(c *realtimeClient) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.ready.Load() || len(h.clients) >= 1024 {
		return false
	}
	h.clients[c] = struct{}{}
	return true
}

func (h *realtimeHub) remove(c *realtimeClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (h *realtimeHub) broadcast(event invalidation) {
	if !h.ready.Load() {
		return
	}
	h.mu.Lock()
	clients := make([]*realtimeClient, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		c.enqueue(event)
	}
}

// Disconnect idle or unresponsive sockets after broker interruption; clients
// refetch on reconnect rather than pretending invalidations were durable.
func (h *realtimeHub) connected(ctx context.Context) bool {
	return ctx.Err() == nil && h.ready.Load() && h.nc.IsConnected() && h.nc.LastError() == nil
}

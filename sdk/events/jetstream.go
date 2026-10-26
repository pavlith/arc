package events

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
)

type Delivery struct {
	Store    Store
	Contract *contract.Compiled
	// Permit checks the currently approved provider/consumer before each batch.
	Permit func(context.Context) error
}

func (d Delivery) permitted(ctx context.Context) error {
	if d.Contract == nil || d.Permit == nil {
		return security.ErrUnavailable
	}
	return d.Permit(ctx)
}

// PublishBatch runs after the domain commit. A crash after publish is retried with
// the same JetStream message ID; consumers still deduplicate beyond its window.
func (d Delivery) PublishBatch(ctx context.Context, js nats.JetStreamContext, limit int) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e := d.permitted(ctx); e != nil {
		return 0, e
	}
	if limit < 1 || limit > 100 {
		return 0, contract.ErrInvalid
	}
	table, e := d.Store.table("outbox")
	if e != nil {
		return 0, e
	}
	t, e := d.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer t.Rollback()
	rows, e := t.QueryContext(ctx, `SELECT event_id,subject,envelope FROM `+table+` WHERE published_at IS NULL ORDER BY created_at,event_id LIMIT $1 FOR UPDATE SKIP LOCKED`, limit)
	if e != nil {
		return 0, e
	}
	type item struct {
		id, subject string
		raw         []byte
	}
	batch := []item{}
	for rows.Next() {
		var v item
		if e = rows.Scan(&v.id, &v.subject, &v.raw); e != nil {
			rows.Close()
			return 0, e
		}
		batch = append(batch, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	for _, v := range batch {
		var ev Envelope
		if contract.Strict(v.raw, &ev) != nil || Validate(d.Contract, v.subject, ev) != nil {
			return 0, contract.ErrInvalid
		}
		if _, e = js.Publish(v.subject, v.raw, nats.MsgId(v.id), nats.Context(ctx)); e != nil {
			return 0, e
		}
		if _, e = t.ExecContext(ctx, `UPDATE `+table+` SET published_at=now() WHERE event_id=$1`, v.id); e != nil {
			return 0, e
		}
	}
	if e = t.Commit(); e != nil {
		return 0, e
	}
	return len(batch), nil
}

// Pull consumes one bounded batch from an approved event subject. DLQ subjects
// derive from that exact subject and durable name; configuration is not a route.
func (d Delivery) Pull(ctx context.Context, js nats.JetStreamContext, subject, durable string, h func(context.Context, *sql.Tx, Envelope) error) error {
	if e := d.permitted(ctx); e != nil {
		return e
	}
	if durable == "" || strings.ContainsAny(durable, ".*> /\\") || h == nil {
		return contract.ErrInvalid
	}
	approved := false
	for _, ev := range d.Contract.Manifest.Events {
		if ev.Subject == subject {
			approved = true
		}
	}
	if !approved {
		return security.ErrDenied
	}
	stream, e := js.StreamNameBySubject(subject, nats.Context(ctx))
	if e != nil {
		return e
	}
	info, e := js.ConsumerInfo(stream, durable, nats.Context(ctx))
	if errors.Is(e, nats.ErrConsumerNotFound) {
		info, e = js.AddConsumer(stream, &nats.ConsumerConfig{Durable: durable, FilterSubject: subject, AckPolicy: nats.AckExplicitPolicy, AckWait: 30 * time.Second, MaxAckPending: 100}, nats.Context(ctx))
	}
	if e != nil {
		return e
	}
	if info.Config.FilterSubject != subject || info.Config.AckPolicy != nats.AckExplicitPolicy || info.Config.DeliverSubject != "" {
		return contract.ErrInvalid
	}
	// Bind to a durable created explicitly above. Unsubscribe must not delete it
	// or reset its delivery cursor after each bounded worker batch.
	sub, e := js.PullSubscribe(subject, durable, nats.Bind(stream, durable), nats.ManualAck())
	if e != nil {
		return e
	}
	defer sub.Unsubscribe()
	// Reserve processing/ACK budget even when a sparse batch waits for fetch expiry.
	fetchCtx, cancelFetch := context.WithTimeout(ctx, 250*time.Millisecond)
	msgs, e := sub.Fetch(10, nats.Context(fetchCtx))
	cancelFetch()
	if e != nil {
		return e
	}
	for _, msg := range msgs {
		if e = d.permitted(ctx); e != nil {
			_ = msg.Nak()
			return e
		}
		e = d.Store.Consume(ctx, durable, subject, d.Contract, msg.Data, h)
		if e == nil {
			if e = msg.AckSync(nats.Context(ctx)); e != nil {
				return e
			}
			continue
		}
		meta, me := msg.Metadata()
		if me != nil {
			return me
		}
		if meta.NumDelivered >= 5 {
			dlq := "dlq." + subject + "." + durable
			if _, pe := js.Publish(dlq, msg.Data, nats.MsgId(durable+":"+meta.Stream+":"+stringID(meta.Sequence.Stream)), nats.Context(ctx)); pe != nil {
				_ = msg.NakWithDelay(time.Second)
				return pe
			}
			if e = msg.Term(); e != nil {
				return e
			}
		} else {
			delay := time.Duration(1<<min(meta.NumDelivered, 6)) * 100 * time.Millisecond
			if ne := msg.NakWithDelay(delay); ne != nil {
				return ne
			}
		}
	}
	return nil
}
func stringID(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

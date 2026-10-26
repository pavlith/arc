package events

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/security"
	"gorm.io/gorm"
)

// Delivery verifies live event permissions and uses the owner SQLite inbox/outbox.
type Delivery struct {
	Store    Store
	Contract *contract.Compiled
	Permit   func(context.Context) error
}

func (d Delivery) permit(ctx context.Context) error {
	if d.Contract == nil || d.Permit == nil || d.Store.DB == nil {
		return security.ErrUnavailable
	}
	return d.Permit(ctx)
}

func (d Delivery) PublishBatch(ctx context.Context, js nats.JetStreamContext, limit int) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.permit(ctx); err != nil {
		return 0, err
	}
	if limit < 1 || limit > 100 {
		return 0, contract.ErrInvalid
	}
	n := 0
	err := database.RetryBusy(ctx, func() error {
		return d.Store.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			// A write statement first obtains SQLite's reserved writer lock.
			// Without it, a read-then-update transaction can fail with
			// SQLITE_BUSY_SNAPSHOT under a concurrent publisher.
			locked := tx.Exec(`UPDATE outbox SET published_at=published_at
				WHERE event_id=(SELECT event_id FROM outbox WHERE published_at IS NULL
				ORDER BY created_at,event_id LIMIT 1)`)
			if locked.Error != nil {
				return locked.Error
			}
			rows, err := tx.Raw(`SELECT event_id,subject,envelope FROM outbox
				WHERE published_at IS NULL ORDER BY created_at,event_id LIMIT ?`, limit).Rows()
			if err != nil {
				return err
			}
			type item struct {
				id, subject string
				raw         []byte
			}
			batch := []item{}
			for rows.Next() {
				var v item
				if err := rows.Scan(&v.id, &v.subject, &v.raw); err != nil {
					rows.Close()
					return err
				}
				batch = append(batch, v)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, v := range batch {
				var ev Envelope
				if contract.Strict(v.raw, &ev) != nil || Validate(d.Contract, v.subject, ev) != nil {
					return contract.ErrInvalid
				}
				if _, err := js.Publish(v.subject, v.raw, nats.MsgId(v.id), nats.Context(ctx)); err != nil {
					return err
				}
				if err := tx.Exec(`UPDATE outbox SET published_at=? WHERE event_id=?`,
					time.Now().UTC(), v.id).Error; err != nil {
					return err
				}
			}
			n = len(batch)
			return nil
		})
	})
	return n, err
}

func (d Delivery) Pull(ctx context.Context, js nats.JetStreamContext, subject, durable string,
	handler func(context.Context, *gorm.DB, Envelope) error) error {
	if err := d.permit(ctx); err != nil {
		return err
	}
	if durable == "" || strings.ContainsAny(durable, ".*> /\\") || handler == nil {
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
	stream, err := js.StreamNameBySubject(subject, nats.Context(ctx))
	if err != nil {
		return err
	}
	info, err := js.ConsumerInfo(stream, durable, nats.Context(ctx))
	if errors.Is(err, nats.ErrConsumerNotFound) {
		info, err = js.AddConsumer(stream, &nats.ConsumerConfig{
			Durable: durable, FilterSubject: subject, AckPolicy: nats.AckExplicitPolicy,
			AckWait: 30 * time.Second, MaxAckPending: 100,
		}, nats.Context(ctx))
	}
	if err != nil {
		return err
	}
	if info.Config.FilterSubject != subject || info.Config.AckPolicy != nats.AckExplicitPolicy || info.Config.DeliverSubject != "" {
		return contract.ErrInvalid
	}
	sub, err := js.PullSubscribe(subject, durable, nats.Bind(stream, durable), nats.ManualAck())
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	fetchCtx, cancelFetch := context.WithTimeout(ctx, 250*time.Millisecond)
	msgs, err := sub.Fetch(10, nats.Context(fetchCtx))
	cancelFetch()
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if err = d.permit(ctx); err != nil {
			_ = msg.Nak()
			return err
		}
		err = d.Store.Consume(ctx, durable, subject, d.Contract, msg.Data, handler)
		if err == nil {
			if err = msg.AckSync(nats.Context(ctx)); err != nil {
				return err
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
			if err = msg.Term(); err != nil {
				return err
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

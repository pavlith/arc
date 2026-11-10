package events

import (
	"context"
	"log/slog"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
)

type deliveryObservation struct {
	kind, id, traceparent string
	duration, lag         time.Duration
	code                  rpc.Code
}

func deliveryResult(ctx context.Context, kind string, ev Envelope, start time.Time, err error) deliveryObservation {
	trace := rpc.Correlation(rpc.WithOutgoing(ctx, rpc.Outgoing{Traceparent: ev.Traceparent})).Traceparent
	return deliveryObservation{kind: kind, id: ev.ID, traceparent: trace,
		duration: time.Since(start), lag: max(0, time.Since(ev.OccurredAt)), code: rpc.DiagnosticCode(err)}
}

func (o deliveryObservation) log(ctx context.Context) {
	slog.InfoContext(ctx, "arc event", "kind", o.kind, "event_id", o.id,
		"traceparent", o.traceparent, "duration_ms", float64(o.duration)/float64(time.Millisecond),
		"delivery_lag_ms", float64(o.lag)/float64(time.Millisecond), "error_code", o.code)
}

// Package telemetry defines optional, non-authoritative execution observations.
package telemetry

import (
	"context"
	"log/slog"
	"time"

	"github.com/pavlith/arc/pkgs/rpc"
)

// Observation contains no request/response payloads or credentials.
type Observation struct {
	Service   string
	Module    string
	Operation string
	Kind      string
	Duration  time.Duration
	ErrorCode rpc.Code
}

// Observer is an optional diagnostics hook; it never grants access.
type Observer interface {
	Observe(context.Context, Observation)
}

type ObserverFunc func(context.Context, Observation)

func (f ObserverFunc) Observe(ctx context.Context, v Observation) {
	if f != nil {
		f(ctx, v)
	}
}

type Slog struct{ Logger *slog.Logger }

func (s Slog) Observe(ctx context.Context, v Observation) {
	if s.Logger == nil {
		return
	}
	s.Logger.InfoContext(ctx, "arc operation", "service", v.Service,
		"module", v.Module, "operation", v.Operation, "kind", v.Kind,
		"duration", v.Duration, "error_code", v.ErrorCode)
}

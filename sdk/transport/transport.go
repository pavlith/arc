// Package transport exposes the low-level NATS Micro runtime without coupling
// module implementations to service composition.
package transport

import (
	"context"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
)

type Config = sdk.Config
type Micro = sdk.Service
type MicroConfig = sdk.ServiceConfig

func Connect(ctx context.Context, cfg Config) (*nats.Conn, error) {
	return sdk.Connect(ctx, cfg)
}

func NewMicro(ctx context.Context, cfg MicroConfig) (*Micro, error) {
	return sdk.NewService(ctx, cfg)
}

// Package transport exposes the low-level NATS Micro runtime without coupling
// module implementations to service composition.
package transport

import (
    "context"

    "github.com/nats-io/nats.go"
    "github.com/pavlith/arc/pkgs"
)

type Config = pkgs.Config
type Micro = pkgs.Service
type MicroConfig = pkgs.ServiceConfig

func Connect(ctx context.Context, cfg Config) (*nats.Conn, error) {
    return pkgs.Connect(ctx, cfg)
}

func NewMicro(ctx context.Context, cfg MicroConfig) (*Micro, error) {
    return pkgs.NewService(ctx, cfg)
}

package sdk

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk/transport"
)

type ServiceConfig struct {
	Connection  Config
	Name        string
	Version     string
	Description string
}

// Service owns one NATS connection and an official nats.go/micro service.
type Service struct {
	connection *nats.Conn
	micro      *transport.Service
}

// newServiceOnConnection creates one service identity on an already-approved
// NATS connection. App must register with Fabric before calling this.
func newServiceOnConnection(nc *nats.Conn, cfg ServiceConfig, metadata map[string]string) (*Service, error) {
	if nc == nil || cfg.Name == "" || cfg.Version == "" {
		return nil, errors.New("sdk: service name, version and NATS connection are required")
	}
	runtime, err := transport.New(nc, transport.Config{
		Name: cfg.Name, Version: cfg.Version,
		Description: cfg.Description, Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("sdk: register native NATS transport: %w", err)
	}
	return &Service{connection: nc, micro: runtime}, nil
}

func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Name == "" || cfg.Version == "" {
		return nil, errors.New("sdk: service name and version are required")
	}
	ncCfg := cfg.Connection
	if ncCfg.Name == "" {
		ncCfg.Name = cfg.Name
	}
	nc, err := Connect(ctx, ncCfg)
	if err != nil {
		return nil, err
	}
	svc, err := newServiceOnConnection(nc, cfg, nil)
	if err != nil {
		nc.Close()
		return nil, err
	}
	return svc, nil
}

func (s *Service) AddEndpoint(name string, handler transport.Handler, opts ...transport.EndpointOpt) error {
	if s == nil || s.micro == nil {
		return errors.New("sdk: service is not initialized")
	}
	if err := s.micro.AddEndpoint(name, handler, opts...); err != nil {
		return fmt.Errorf("sdk: add endpoint: %w", err)
	}
	return nil
}

func (s *Service) Connection() *nats.Conn {
	if s == nil {
		return nil
	}
	return s.connection
}

func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	var stopErr error
	if s.micro != nil {
		stopErr = s.micro.Stop()
	}
	if s.connection != nil {
		// micro.Stop queues UNSUB asynchronously. Wait for the server to process it
		// before closing, so subsequent RPCs observe no responders immediately.
		if !s.connection.IsClosed() {
			if err := s.connection.FlushTimeout(5 * time.Second); err != nil {
				stopErr = errors.Join(stopErr, err)
			}
		}
		s.connection.Close()
	}
	return stopErr
}

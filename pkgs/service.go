package pkgs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
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
	micro      micro.Service
}

func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Name == "" || cfg.Version == "" {
		return nil, errors.New("pkgs: service name and version are required")
	}
	connectionCfg := cfg.Connection
	if connectionCfg.Name == "" {
		connectionCfg.Name = cfg.Name
	}
	nc, err := Connect(ctx, connectionCfg)
	if err != nil {
		return nil, err
	}
	service, err := micro.AddService(nc, micro.Config{
		Name:        cfg.Name,
		Version:     cfg.Version,
		Description: cfg.Description,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("pkgs: add micro service: %w", err)
	}
	return &Service{connection: nc, micro: service}, nil
}

func (s *Service) AddEndpoint(name string, handler micro.Handler, opts ...micro.EndpointOpt) error {
	if s == nil || s.micro == nil {
		return errors.New("pkgs: service is not initialized")
	}
	if err := s.micro.AddEndpoint(name, handler, opts...); err != nil {
		return fmt.Errorf("pkgs: add endpoint: %w", err)
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

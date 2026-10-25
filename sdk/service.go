package sdk

import (
	"context"
	"errors"
	"fmt"

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
		return nil, errors.New("sdk: service name and version are required")
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
		return nil, fmt.Errorf("sdk: add micro service: %w", err)
	}
	return &Service{connection: nc, micro: service}, nil
}

func (s *Service) AddEndpoint(name string, handler micro.Handler, opts ...micro.EndpointOpt) error {
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
		s.connection.Close()
	}
	return stopErr
}

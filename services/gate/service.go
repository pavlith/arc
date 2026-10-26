// Package gate composes the authenticated HTTP edge, discovery and listener.
// Gate does not own domain data or approve dynamic API routes.
package gate

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/services/gate/modules/discovery"
	edge "github.com/pavlith/arc/services/gate/modules/http"
	"github.com/pavlith/arc/services/gate/modules/listener"
)

var ErrInvalid = errors.New("gate: invalid service configuration")

type Config struct {
	HTTP        edge.Config
	Listen      string
	TLSCertFile string
	TLSKeyFile  string
	// Shared private connection, owned by bootstrap. No database access.
	NATS *nats.Conn
}

type Service struct {
	HTTP      *edge.Gate
	Discovery *discovery.Module
	Listener  *listener.Module
	mu        sync.Mutex
	started   bool
	stopped   bool
}

func New(cfg Config) (*Service, error) {
	g, err := edge.New(cfg.HTTP)
	if err != nil {
		return nil, err
	}
	discover, err := discovery.New(g, cfg.NATS)
	if err != nil {
		return nil, err
	}
	listenerModule, err := listener.New(listener.Config{
		Listen: cfg.Listen, TLSCertFile: cfg.TLSCertFile, TLSKeyFile: cfg.TLSKeyFile,
		BehindTrustedProxy: len(cfg.HTTP.TrustedProxies) > 0,
	}, g)
	if err != nil {
		return nil, err
	}
	return &Service{HTTP: g, Discovery: discover, Listener: listenerModule}, nil
}
func (s *Service) Modules() []string { return []string{"http", "discovery", "listener"} }
func (s *Service) Handler() http.Handler {
	if s == nil {
		return nil
	}
	return s.HTTP
}
func (s *Service) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return ErrInvalid
	}
	if err := s.Discovery.Start(ctx); err != nil {
		return err
	}
	if err := s.Listener.Start(ctx); err != nil {
		s.Discovery.Stop()
		return err
	}
	s.started = true
	return nil
}
func (s *Service) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	s.stopped = true
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	err := s.Listener.Stop(ctx)
	s.Discovery.Stop()
	return err
}

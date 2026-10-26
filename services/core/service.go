// Package core composes Arc's trusted Core process from four in-process modules.
// Core bootstrap is explicitly separated from approved domain-service deployment:
// it uses the low-level pkgs Micro service without weakening pkgs/service.Compose.
package core

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/pkgs/security"
	"github.com/pavlith/arc/services/core/modules/access"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/core/modules/runtime"
)

var ErrInvalid = errors.New("core: invalid bootstrap configuration")

// Module binds approved private/bootstrap endpoints to a shared Core process.
// No internal Core->Core NATS request is needed: all four modules share Go objects.
type Module interface {
	ID() string
	Bind(*pkgs.Service) (func(), error)
}

type Config struct {
	DB                      *sql.DB
	NATS                    pkgs.Config
	Version                 string
	IdentitySigningKid      string
	IdentitySigningKey      ed25519.PrivateKey
	InstallationApprovalKey ed25519.PublicKey
	ContractBootstrap       []access.Approved
	SnapshotKid             string
	SnapshotSigningKey      ed25519.PrivateKey
	RouteTrustKey           ed25519.PrivateKey
	RuntimeAuthorize        runtime.Authorize
	Now                     func() time.Time
}

type Service struct {
	Identity *identity.Core
	Access   *access.Core
	Fabric   *fabric.Core
	Runtime  *runtime.Module

	connection pkgs.Config
	version    string
	modules    []Module
	mu         sync.Mutex
	transport  *pkgs.Service
	closes     []func()
	stopped    bool
	started    bool
}

// New wires the Identity->Access->Fabric policy graph without network access.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Version == "" || cfg.IdentitySigningKid == "" ||
		cfg.SnapshotKid == "" ||
		len(cfg.IdentitySigningKey) != ed25519.PrivateKeySize ||
		len(cfg.InstallationApprovalKey) != ed25519.PublicKeySize ||
		len(cfg.SnapshotSigningKey) != ed25519.PrivateKeySize ||
		len(cfg.RouteTrustKey) != ed25519.PrivateKeySize ||
		cfg.RuntimeAuthorize == nil {
		return nil, ErrInvalid
	}
	id := &identity.Core{DB: cfg.DB, PrivateKey: cfg.IdentitySigningKey,
		SigningKid: cfg.IdentitySigningKid, Now: cfg.Now}
	ac := &access.Core{DB: cfg.DB, Identity: id, Now: cfg.Now}
	fb := &fabric.Core{DB: cfg.DB, Identity: id,
		ApprovalKey: cfg.InstallationApprovalKey, Bootstrap: cfg.ContractBootstrap,
		SnapshotKid: cfg.SnapshotKid, SnapshotKey: cfg.SnapshotSigningKey,
		RouteTrustKey: cfg.RouteTrustKey}
	ac.ContractSource = fb
	id.Policy = ac
	rt := &runtime.Module{DB: cfg.DB, Authorize: cfg.RuntimeAuthorize}
	return &Service{
		Identity: id, Access: ac, Fabric: fb, Runtime: rt,
		connection: cfg.NATS, version: cfg.Version,
		modules: []Module{id, ac, fb, rt},
	}, nil
}

// Modules reports the real installed modules in deterministic binding order.
func (s *Service) Modules() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.modules))
	for _, m := range s.modules {
		names = append(names, m.ID())
	}
	return names
}

// Start binds every internal endpoint, validates the NATS subscriptions, and
// exposes one official NATS Micro service for the privileged Core process.
func (s *Service) Start(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return ErrInvalid
	}
	if err := s.Identity.DB.PingContext(ctx); err != nil {
		return security.ErrUnavailable
	}
	transport, err := pkgs.NewService(ctx, pkgs.ServiceConfig{
		Connection: s.connection, Name: "arc-core", Version: s.version,
		Description: "Identity, Access, Fabric and Runtime Control",
	})
	if err != nil {
		return err
	}
	cleanups := []func(){}
	abort := func(e error) error {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
		_ = transport.Stop()
		return e
	}
	for _, m := range s.modules {
		cleanup, e := m.Bind(transport)
		if e != nil {
			return abort(fmt.Errorf("core module %s: %w", m.ID(), e))
		}
		if cleanup != nil {
			cleanups = append(cleanups, cleanup)
		}
	}
	if err := transport.Connection().FlushWithContext(ctx); err != nil {
		return abort(err)
	}
	if err := transport.Connection().LastError(); err != nil {
		return abort(err)
	}
	s.closes = cleanups
	s.transport = transport
	s.started = true
	return nil
}

// Stop is idempotent, and shuts down control subscriptions before Micro.
func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	s.stopped = true
	for i := len(s.closes) - 1; i >= 0; i-- {
		s.closes[i]()
	}
	if s.transport != nil {
		return s.transport.Stop()
	}
	return nil
}

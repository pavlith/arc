// Package task composes the approved "task" Fabric service from typed modules.
// The Go package name intentionally does not change its public API identity.
package task

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/service"
	"github.com/pavlith/arc/services/core/modules/identity"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"github.com/pavlith/arc/services/task/modules/outbox"
	"github.com/pavlith/arc/services/task/modules/tasks"
)

var ErrInvalid = errors.New("task: invalid service dependencies")

type Config struct {
	DB        *sql.DB
	Runtime   sdk.AppConfig
	Identity  identity.Client
	CoreTrust ed25519.PublicKey
}

type Service struct {
	App       *service.App
	Tasks     *tasks.Service
	Publisher *outbox.Module
}

// New does not connect to NATS or open a database: all bindings and permits are
// validated before Start. Runtime Artifact and incoming authorizer are pinned here.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Identity.RPC == nil ||
		cfg.Identity.ServiceID == "" || cfg.Identity.Kid == "" ||
		len(cfg.Identity.PrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CoreTrust) != ed25519.PublicKeySize ||
		cfg.Runtime.Registry == nil || cfg.Runtime.Authorize != nil ||
		cfg.Runtime.Resource != nil || cfg.Runtime.Trusted != nil ||
		cfg.Runtime.SelfCheck != nil {
		return nil, ErrInvalid
	}

	artifact := taskv1.Artifact()
	compiled, err := contract.Compile(artifact)
	if err != nil {
		return nil, err
	}
	if len(cfg.Runtime.Artifact.Manifest) != 0 {
		supplied, err := contract.Compile(cfg.Runtime.Artifact)
		if err != nil || supplied.Digest != compiled.Digest {
			return nil, ErrInvalid
		}
	}
	cfg.Runtime.Artifact = artifact
	cfg.Runtime.Authorize = identity.RemoteAuthorizer(cfg.Identity, cfg.CoreTrust, "task/v1")
	cfg.Runtime.SelfCheck = cfg.DB.PingContext

	s := &Service{}
	tasksModule := &tasks.Service{
		DB: cfg.DB, Identity: cfg.Identity, Contract: compiled,
		Check: tasks.OnlineCheck(cfg.Identity),
	}
	registration := sdk.Registration{
		Service: "task", Instance: cfg.Runtime.Instance,
		Build: compiled.Manifest.Service.BuildVersion, Digest: compiled.Digest,
	}
	publisher := &outbox.Module{
		DB: cfg.DB, Contract: compiled, Registry: cfg.Runtime.Registry,
		Registration: registration,
		Connection: func() *nats.Conn {
			if s.App == nil {
				return nil
			}
			return s.App.Connection()
		},
	}
	app, err := service.Compose(service.Config{
		Definition: service.Definition{Name: "task", APIMajor: 1,
			Kind: service.Domain, Modules: []module.Module{tasksModule, publisher}},
		Runtime: cfg.Runtime,
	})
	if err != nil {
		return nil, err
	}
	s.App = app
	s.Tasks = tasksModule
	s.Publisher = publisher
	return s, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s == nil || s.App == nil {
		return ErrInvalid
	}
	return s.App.Start(ctx)
}
func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	if s.App == nil {
		return nil
	}
	return s.App.Stop()
}

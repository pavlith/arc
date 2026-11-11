// Package files composes Files' independently deployed signed service.
package files

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/service"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/modules/folders"
	"github.com/pavlith/arc/services/files/modules/outbox"
	"gorm.io/gorm"
)

var ErrInvalid = errors.New("files: invalid service dependencies")

type Config struct {
	GormDB    *gorm.DB
	Runtime   sdk.AppConfig
	Identity  identity.Client
	CoreTrust ed25519.PublicKey
}

type Service struct {
	App       *service.App
	Folders   *folders.Service
	Publisher *outbox.Module
}

func New(cfg Config) (*Service, error) {
	if cfg.GormDB == nil || cfg.Identity.RPC == nil ||
		cfg.Identity.ServiceID == "" || cfg.Identity.Kid == "" ||
		len(cfg.Identity.PrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CoreTrust) != ed25519.PublicKeySize ||
		cfg.Runtime.Registry == nil || cfg.Runtime.Authorize != nil ||
		cfg.Runtime.Resource != nil || cfg.Runtime.Trusted != nil ||
		cfg.Runtime.SelfCheck != nil {
		return nil, ErrInvalid
	}
	artifact := filesv1.Artifact()
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
	cfg.Runtime.Authorize = identity.RemoteAuthorizer(cfg.Identity, cfg.CoreTrust, "files/v1")
	owner, err := cfg.GormDB.DB()
	if err != nil {
		return nil, ErrInvalid
	}
	cfg.Runtime.SelfCheck = owner.PingContext
	s := &Service{}
	foldersModule := &folders.Service{GormDB: cfg.GormDB, Identity: cfg.Identity, Contract: compiled, Check: folders.OnlineCheck(cfg.Identity)}
	registration := sdk.Registration{
		Service: "files", Instance: cfg.Runtime.Instance,
		Build: compiled.Manifest.Service.BuildVersion, Digest: compiled.Digest,
	}
	publisher := &outbox.Module{
		GormDB: cfg.GormDB, Contract: compiled, Registry: cfg.Runtime.Registry,
		Registration: registration, Connection: func() *nats.Conn {
			if s.App == nil {
				return nil
			}
			return s.App.Connection()
		},
	}
	app, err := service.Compose(service.Config{
		Definition: service.Definition{Name: "files", APIMajor: 1,
			Kind: service.Domain, Modules: []module.Module{foldersModule, publisher}},
		Runtime: cfg.Runtime,
	})
	if err != nil {
		return nil, err
	}
	s.App, s.Folders, s.Publisher = app, foldersModule, publisher
	return s, nil
}
func (s *Service) Start(ctx context.Context) error {
	if s == nil || s.App == nil {
		return ErrInvalid
	}
	return s.App.Start(ctx)
}
func (s *Service) Stop() error {
	if s == nil || s.App == nil {
		return nil
	}
	return s.App.Stop()
}

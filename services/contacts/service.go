// Package contacts composes the signed Contacts service with independent persistence.
package contacts

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/service"
	contactsv1 "github.com/pavlith/arc/services/contacts/api/v1"
	contacts "github.com/pavlith/arc/services/contacts/modules/contacts"
	"github.com/pavlith/arc/services/contacts/modules/outbox"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/resources"
	"gorm.io/gorm"
)

var ErrInvalid = errors.New("contacts: invalid service dependencies")

type Config struct {
	GormDB    *gorm.DB
	Runtime   sdk.AppConfig
	Identity  identity.Client
	CoreTrust ed25519.PublicKey
}

type Service struct {
	App       *service.App
	Contacts  *contacts.Module
	Publisher *outbox.Module
}

// New does not connect to NATS or open a database: all bindings and permits are
// validated before Start. Runtime Artifact and incoming authorizer are pinned here.
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

	artifact := contactsv1.Artifact()
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
	cfg.Runtime.Authorize = identity.RemoteAuthorizer(cfg.Identity, cfg.CoreTrust, "contacts/v1")

	owner, err := cfg.GormDB.DB()
	if err != nil {
		return nil, ErrInvalid
	}
	cfg.Runtime.SelfCheck = owner.PingContext

	s := &Service{}
	contactsModule := &contacts.Module{DB: cfg.GormDB, Identity: cfg.Identity, Contract: compiled,
		Check: resources.OnlineCheck(cfg.Identity),
	}
	registration := sdk.Registration{
		Service: "contacts", Instance: cfg.Runtime.Instance,
		Build: compiled.Manifest.Service.BuildVersion, Digest: compiled.Digest,
	}
	publisher := &outbox.Module{
		GormDB: cfg.GormDB, Contract: compiled, Registry: cfg.Runtime.Registry,
		Registration: registration,
		Connection: func() *nats.Conn {
			if s.App == nil {
				return nil
			}
			return s.App.Connection()
		},
	}
	app, err := service.Compose(service.Config{
		Definition: service.Definition{Name: "contacts", APIMajor: 1,
			Kind: service.Domain, Modules: []module.Module{contactsModule, publisher}},
		Runtime: cfg.Runtime,
	})
	if err != nil {
		return nil, err
	}
	s.App = app
	s.Contacts = contactsModule
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

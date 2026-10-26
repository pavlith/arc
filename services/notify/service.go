// Package notify composes the "notifications" Fabric service with independent
// inbox, delivery and authenticated health modules.
package notify

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/pkgs"
	"github.com/pavlith/arc/pkgs/contract"
	"github.com/pavlith/arc/pkgs/module"
	"github.com/pavlith/arc/pkgs/service"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	"github.com/pavlith/arc/services/notify/modules/health"
	"github.com/pavlith/arc/services/notify/modules/inbox"
	tasksv1 "github.com/pavlith/arc/services/task/api/v1"
)

var ErrInvalid = errors.New("notify: invalid service dependencies")

// EventRegistry checks the exact signed source, artifact digest, subject, durable
// and consumer identity with live Fabric approval.
type EventRegistry interface {
	pkgs.Registry
	EventPermit(context.Context, pkgs.Registration, fabric.EventSubscription) error
}

type Config struct {
	DB           *sql.DB
	Runtime      pkgs.AppConfig
	Identity     identity.Client
	CoreTrust    ed25519.PublicKey
	Registry     EventRegistry
	Subscription fabric.EventSubscription
	Provider     delivery.Provider
}

type Service struct {
	App      *service.App
	Inbox    *inbox.Module
	Delivery *delivery.Module
}

func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Identity.RPC == nil ||
		cfg.Identity.ServiceID == "" || cfg.Identity.Kid == "" ||
		len(cfg.Identity.PrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CoreTrust) != ed25519.PublicKeySize ||
		cfg.Registry == nil || cfg.Provider == nil ||
		cfg.Runtime.Authorize != nil || cfg.Runtime.Resource != nil ||
		cfg.Runtime.Trusted != nil || cfg.Runtime.SelfCheck != nil {
		return nil, ErrInvalid
	}

	artifact := notifyv1.Artifact()
	own, err := contract.Compile(artifact)
	if err != nil {
		return nil, err
	}
	if len(cfg.Runtime.Artifact.Manifest) != 0 {
		supplied, err := contract.Compile(cfg.Runtime.Artifact)
		if err != nil || supplied.Digest != own.Digest {
			return nil, ErrInvalid
		}
	}
	source, err := contract.Compile(tasksv1.Artifact())
	if err != nil {
		return nil, err
	}
	if cfg.Subscription.Provider == "" ||
		cfg.Subscription.Digest != source.Digest ||
		cfg.Subscription.Subject != tasksv1.CreatedSubject ||
		cfg.Subscription.Durable != inbox.Durable {
		return nil, ErrInvalid
	}

	cfg.Runtime.Artifact = artifact
	cfg.Runtime.Registry = cfg.Registry
	cfg.Runtime.Authorize = identity.RemoteAuthorizer(cfg.Identity, cfg.CoreTrust, "notifications/v1")
	cfg.Runtime.SelfCheck = cfg.DB.PingContext

	registration := pkgs.Registration{
		Service: "notifications", Instance: cfg.Runtime.Instance,
		Build: own.Manifest.Service.BuildVersion, Digest: own.Digest,
	}
	permit := func(ctx context.Context) error {
		return cfg.Registry.EventPermit(ctx, registration, cfg.Subscription)
	}
	s := &Service{}
	receiver := &inbox.Module{
		DB: cfg.DB, Contract: source, Permit: permit,
		Connection: func() *nats.Conn {
			if s.App == nil {
				return nil
			}
			return s.App.Connection()
		},
	}
	sender := &delivery.Module{DB: cfg.DB, Provider: cfg.Provider, Permit: permit}
	app, err := service.Compose(service.Config{
		Definition: service.Definition{
			Name: "notifications", APIMajor: 1, Kind: service.Domain,
			Modules: []module.Module{
				&health.Module{ServiceID: cfg.Identity.ServiceID}, receiver, sender,
			},
		},
		Runtime: cfg.Runtime,
	})
	if err != nil {
		return nil, err
	}
	s.App = app
	s.Inbox = receiver
	s.Delivery = sender
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

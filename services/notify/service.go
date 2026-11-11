// Package notify composes the "notify" Fabric service with independent
// inbox, delivery and authenticated health modules.
package notify

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/module"
	"github.com/pavlith/arc/sdk/service"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	notifyv1 "github.com/pavlith/arc/services/notify/api/v1"
	"github.com/pavlith/arc/services/notify/modules/delivery"
	"github.com/pavlith/arc/services/notify/modules/health"
	"github.com/pavlith/arc/services/notify/modules/inbox"
	inboxoutbox "github.com/pavlith/arc/services/notify/modules/outbox"
	"github.com/pavlith/arc/services/notify/modules/userinbox"
	pagesv1 "github.com/pavlith/arc/services/pages/api/v1"
	taskv1 "github.com/pavlith/arc/services/task/api/v1"
	"gorm.io/gorm"
)

var ErrInvalid = errors.New("notify: invalid service dependencies")

// EventRegistry checks the exact signed source, artifact digest, subject, durable
// and consumer identity with live Fabric approval.
type EventRegistry interface {
	sdk.Registry
	EventPermit(context.Context, sdk.Registration, fabric.EventSubscription) error
}

type Config struct {
	GormDB        *gorm.DB
	Runtime       sdk.AppConfig
	Identity      identity.Client
	CoreTrust     ed25519.PublicKey
	Registry      EventRegistry
	Subscription  fabric.EventSubscription
	Subscriptions []fabric.EventSubscription
	Provider      delivery.Provider
}

type Service struct {
	App       *service.App
	Inbox     *inbox.Module
	Delivery  *delivery.Module
	Publisher *inboxoutbox.Module
}

func New(cfg Config) (*Service, error) {
	if cfg.GormDB == nil || cfg.Identity.RPC == nil ||
		cfg.Identity.ServiceID == "" || cfg.Identity.Kid == "" ||
		len(cfg.Identity.PrivateKey) != ed25519.PrivateKeySize ||
		len(cfg.CoreTrust) != ed25519.PublicKeySize ||
		cfg.Registry == nil ||
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
	if cfg.Provider == nil {
		cfg.Provider = delivery.DisabledProvider{}
	}
	subscriptions := cfg.Subscriptions
	if len(subscriptions) == 0 {
		subscriptions = []fabric.EventSubscription{cfg.Subscription}
	}
	sources := make([]*contract.Compiled, len(subscriptions))
	seen := map[string]bool{}
	for i, sub := range subscriptions {
		var artifact contract.Artifact
		durable := ""
		switch sub.Subject {
		case taskv1.CreatedSubject:
			artifact = taskv1.Artifact()
			durable = inbox.Durable
		case pagesv1.ChangedSubject:
			artifact = pagesv1.Artifact()
			durable = "notify-pages-changed-v1"
		case filesv1.CatalogChangedSubject:
			artifact = filesv1.Artifact()
			durable = "notify-files-changed-v1"
		default:
			return nil, ErrInvalid
		}
		source, e := contract.Compile(artifact)
		if e != nil {
			return nil, e
		}
		if sub.Provider == "" || sub.Digest != source.Digest || sub.Durable != durable || seen[sub.Subject] {
			return nil, ErrInvalid
		}
		seen[sub.Subject] = true
		sources[i] = source
	}

	cfg.Runtime.Artifact = artifact
	cfg.Runtime.Registry = cfg.Registry
	cfg.Runtime.Authorize = identity.RemoteAuthorizer(cfg.Identity, cfg.CoreTrust, "notify/v1")

	owner, err := cfg.GormDB.DB()
	if err != nil {
		return nil, ErrInvalid
	}
	cfg.Runtime.SelfCheck = owner.PingContext

	registration := sdk.Registration{
		Service: "notify", Instance: cfg.Runtime.Instance,
		Build: own.Manifest.Service.BuildVersion, Digest: own.Digest,
	}
	permits := make([]func(context.Context) error, len(subscriptions))
	for i, sub := range subscriptions {
		permits[i] = func(ctx context.Context) error { return cfg.Registry.EventPermit(ctx, registration, sub) }
	}
	permit := func(ctx context.Context) error {
		for _, p := range permits {
			if e := p(ctx); e != nil {
				return e
			}
		}
		return nil
	}
	s := &Service{}
	modules := []module.Module{&health.Module{ServiceID: cfg.Identity.ServiceID}}
	var receiver *inbox.Module
	for i, sub := range subscriptions {
		r := &inbox.Module{GormDB: cfg.GormDB, Contract: sources[i], Permit: permits[i], Subject: sub.Subject, Durable: sub.Durable, Channel: delivery.Channel(cfg.Provider), Connection: func() *nats.Conn {
			if s.App == nil {
				return nil
			}
			return s.App.Connection()
		}}
		if receiver == nil {
			receiver = r
		}
		modules = append(modules, r)
	}
	sender := &delivery.Module{GormDB: cfg.GormDB, Provider: cfg.Provider, Permit: permit}
	publisher := &inboxoutbox.Module{
		GormDB: cfg.GormDB, Contract: own, Registry: cfg.Registry,
		Registration: registration,
		Connection: func() *nats.Conn {
			if s.App == nil {
				return nil
			}
			return s.App.Connection()
		},
	}
	app, err := service.Compose(service.Config{
		Definition: service.Definition{
			Name: "notify", APIMajor: 1, Kind: service.Domain,
			Modules: append(modules, sender, &userinbox.Module{GormDB: cfg.GormDB, Identity: cfg.Identity}, publisher),
		},
		Runtime: cfg.Runtime,
	})
	if err != nil {
		return nil, err
	}
	s.App = app
	s.Inbox = receiver
	s.Delivery = sender
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
	if s == nil || s.App == nil {
		return nil
	}
	return s.App.Stop()
}

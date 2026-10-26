// Package domainrun wires standalone M0 domain processes to the existing SDK.
package domainrun

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/nats-io/nats.go"
	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/events"
	"github.com/pavlith/arc/sdk/fabric"
	"github.com/pavlith/arc/sdk/identity"
	"github.com/pavlith/arc/sdk/notifications"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/sdk/tasks"
	"log"
	"os"
	"time"
)

type Config struct {
	NATS         sdk.Config               `json:"nats"`
	DSNFile      string                   `json:"dsn_file"`
	ServiceID    string                   `json:"service_id"`
	Kid          string                   `json:"kid"`
	KeyFile      string                   `json:"key_file"`
	CoreKeyFile  string                   `json:"core_key_file"`
	Instance     string                   `json:"instance"`
	Subscription fabric.EventSubscription `json:"subscription"`
}

// Start accepts separate connections/roles per process; Core DB is never opened.
func Start(ctx context.Context, kind string, cfg Config) (*sdk.App, func(context.Context) error, error) {
	key, e := identity.LoadSigningKey(cfg.KeyFile)
	if e != nil {
		return nil, nil, errors.New("domain: service key unavailable")
	}
	b, e := os.ReadFile(cfg.CoreKeyFile)
	if e != nil {
		return nil, nil, e
	}
	var core ed25519.PublicKey
	if json.Unmarshal(b, &core) != nil || len(core) != 32 {
		return nil, nil, errors.New("domain: invalid Core public key")
	}
	b, e = os.ReadFile(cfg.DSNFile)
	if e != nil {
		return nil, nil, errors.New("domain: DSN unavailable")
	}
	db, e := sql.Open("pgx", string(b))
	if e != nil {
		return nil, nil, errors.New("domain: DB unavailable")
	}
	db.SetMaxOpenConns(12)
	var a contract.Artifact
	switch kind {
	case "tasks":
		a = tasks.Artifact()
	case "notifications":
		a = notifications.Artifact()
	default:
		db.Close()
		return nil, nil, errors.New("unknown domain")
	}
	m, e := contract.Compile(a)
	if e != nil {
		db.Close()
		return nil, nil, e
	}
	registry := &fabric.Client{Account: cfg.ServiceID, Kid: cfg.Kid, Key: key, CoreKey: core}
	// Identity RPC uses a separate connection from the SDK subscription lifecycle.
	nc, e := sdk.Connect(ctx, cfg.NATS)
	if e != nil {
		db.Close()
		return nil, nil, e
	}
	rc, e := rpc.NewClient(nc)
	if e != nil {
		nc.Close()
		db.Close()
		return nil, nil, e
	}
	client := identity.Client{RPC: rc, ServiceID: cfg.ServiceID, Kid: cfg.Kid, PrivateKey: key}
	domain := &tasks.Service{DB: db, Identity: client, Contract: m, Check: tasks.OnlineCheck(client)}
	app, e := sdk.NewApp(sdk.AppConfig{Connection: cfg.NATS, Artifact: a, Instance: cfg.Instance, Registry: registry, Authorize: identity.RemoteAuthorizer(client, core, kind+"/v1"), Resource: domain.Authorize, Trusted: func(ctx context.Context, op string) error {
		cl, ok := rpc.VerifiedClaims(ctx)
		if !ok || cl.Operation != op || cl.Subject != "service:"+cfg.ServiceID {
			return security.ErrDenied
		}
		return nil
	}, SelfCheck: db.PingContext})
	if e == nil {
		if kind == "tasks" {
			e = domain.Bind(app)
		} else {
			e = sdk.Handle(app, notifications.Health, func(context.Context, identity.Empty) (identity.Empty, error) { return identity.Empty{}, nil })
		}
	}
	if e == nil {
		e = app.Start(ctx)
	}
	if e != nil {
		nc.Close()
		db.Close()
		return nil, nil, e
	}
	reg := sdk.Registration{Service: kind, Instance: cfg.Instance, Build: m.Manifest.Service.BuildVersion, Digest: m.Digest}
	js, e := app.Connection().JetStream()
	if e != nil {
		app.Stop()
		nc.Close()
		db.Close()
		return nil, nil, e
	}
	cleanup := func() { app.Stop(); nc.Close(); db.Close() }
	worker := func(ctx context.Context) error {
		defer cleanup()
		permit := func(ctx context.Context) error { return registry.Check(ctx, reg) }
		eventContract := m
		if kind == "notifications" {
			eventContract, e = contract.Compile(tasks.Artifact())
			if e != nil {
				return e
			}
			if cfg.Subscription.Digest != eventContract.Digest || cfg.Subscription.Subject != tasks.Created || cfg.Subscription.Durable != notifications.Durable {
				return security.ErrDenied
			}
			permit = func(ctx context.Context) error { return registry.EventPermit(ctx, reg, cfg.Subscription) }
		}
		delivery := events.Delivery{Store: events.Store{DB: db, Schema: kind}, Contract: eventContract, Permit: permit}
		notify := &notifications.Service{DB: db}
		fake := &notifications.FakeProvider{}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				work, cancel := context.WithTimeout(ctx, 5*time.Second)
				if kind == "tasks" {
					_, e = delivery.PublishBatch(work, js, 100)
				} else {
					e = delivery.Pull(work, js, tasks.Created, notifications.Durable, notify.Effect)
					// External intents have their own budget, independent of an empty pull.
					if e == nil || errors.Is(e, context.DeadlineExceeded) || errors.Is(e, nats.ErrTimeout) {
						cancel()
						work, cancel = context.WithTimeout(ctx, 5*time.Second)
						if pe := permit(work); pe == nil {
							_, e = notify.Deliver(work, fake)
						} else {
							e = pe
						}
					}
				}
				cancel()
				if e != nil && ctx.Err() == nil {
					var api *nats.APIError
					if errors.As(e, &api) {
						log.Printf("%s: JetStream batch deferred: code=%d reason=%s", kind, api.Code, api.Description)
					} else {
						log.Printf("%s: batch deferred: %T code=%s", kind, e, rpc.ErrorCode(e))
					}
				}
			}
		}
	}
	return app, worker, nil
}
func Run(ctx context.Context, kind, file string) error {
	b, e := os.ReadFile(file)
	if e != nil {
		return e
	}
	var cfg Config
	if contract.Strict(b, &cfg) != nil {
		return errors.New("domain: invalid configuration")
	}
	_, work, e := Start(ctx, kind, cfg)
	if e != nil {
		return e
	}
	return work(ctx)
}

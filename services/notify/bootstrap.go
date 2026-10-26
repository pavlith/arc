package notify

import (
	"context"
	"errors"

	"github.com/pavlith/arc/sdk/bootstrap"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/notify/modules/delivery"
)

// BootstrapConfig contains only the notification-specific event permission in
// addition to the common SDK bootstrap config.
type BootstrapConfig struct {
	bootstrap.Config
	Subscription fabric.EventSubscription `json:"subscription"`
}

func Run(ctx context.Context, path string) error {
	var cfg BootstrapConfig
	if err := bootstrap.ReadConfig(path, &cfg); err != nil {
		return err
	}
	deps, err := bootstrap.Open(ctx, cfg.Config)
	if err != nil {
		return err
	}
	defer deps.Close()

	registry := &fabric.Client{
		Account: cfg.ServiceID, Kid: cfg.Kid, Key: deps.Key, CoreKey: deps.CoreTrust,
	}
	app, err := New(Config{
		DB: deps.DB, GormDB: deps.GormDB, Runtime: deps.RuntimeConfig(cfg.Config, registry),
		Identity: identity.Client{
			RPC: deps.RPC, ServiceID: cfg.ServiceID, Kid: cfg.Kid, PrivateKey: deps.Key,
		},
		CoreTrust: deps.CoreTrust,
		Registry:  registry, Subscription: cfg.Subscription,
		Provider: &delivery.FakeProvider{}, // M0 proof adapter; replace for production
	})
	if err != nil {
		return err
	}
	if err = app.Start(ctx); err != nil {
		_ = app.Stop()
		return err
	}
	defer app.Stop()
	err = app.App.Wait(ctx)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

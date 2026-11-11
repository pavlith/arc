package files

import (
	"context"
	"errors"

	"github.com/pavlith/arc/sdk/bootstrap"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/files/storage"
)

type BootstrapConfig struct {
	bootstrap.Config
	StoragePath string `json:"storage_path"`
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
	store, err := storage.OpenLocal(cfg.StoragePath)
	if err != nil {
		return err
	}
	defer store.Close()
	registry := &fabric.Client{
		Account: cfg.ServiceID, Kid: cfg.Kid, Key: deps.Key, CoreKey: deps.CoreTrust,
	}
	app, err := New(Config{
		GormDB: deps.GormDB, Runtime: deps.RuntimeConfig(cfg.Config, registry),
		Identity: identity.Client{
			RPC: deps.RPC, ServiceID: cfg.ServiceID,
			Kid: cfg.Kid, PrivateKey: deps.Key,
		},
		CoreTrust: deps.CoreTrust,
		Storage:   store,
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

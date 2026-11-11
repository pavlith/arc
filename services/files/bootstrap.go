package files

import (
	"context"
	"errors"

	"github.com/pavlith/arc/sdk/bootstrap"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/storage"
	"github.com/pavlith/arc/services/files/stream"
)

type BootstrapConfig struct {
	bootstrap.Config
	StoragePath        string `json:"storage_path"`
	StreamListen       string `json:"stream_listen,omitempty"`
	StreamTLSCertFile  string `json:"stream_tls_cert_file,omitempty"`
	StreamTLSKeyFile   string `json:"stream_tls_key_file,omitempty"`
	StreamClientCAFile string `json:"stream_client_ca_file,omitempty"`
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
	// The byte listener is explicitly opt-in and cannot run without mTLS,
	// Core invocation verification and a complete approved Files artifact.
	var private *stream.Server
	streamRequested := cfg.StreamListen != "" || cfg.StreamTLSCertFile != "" ||
		cfg.StreamTLSKeyFile != "" || cfg.StreamClientCAFile != ""
	if streamRequested {
		compiled, e := contract.Compile(filesv1.Artifact())
		if e != nil {
			return e
		}
		private, err = stream.New(stream.Config{
			Listen: cfg.StreamListen, TLSCertFile: cfg.StreamTLSCertFile,
			TLSKeyFile: cfg.StreamTLSKeyFile, ClientCAFile: cfg.StreamClientCAFile,
			Verify:  identity.RemoteAuthorizer(app.Folders.Identity, deps.CoreTrust, "files/v1"),
			Objects: app.Objects, Contract: compiled,
		})
		if err != nil {
			return err
		}
	}
	if err = app.Start(ctx); err != nil {
		_ = app.Stop()
		return err
	}
	defer app.Stop()
	if private != nil {
		if err = private.Start(); err != nil {
			return err
		}
		defer private.Stop(context.Background())
	}
	err = app.App.Wait(ctx)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

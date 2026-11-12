package mail

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"

	"github.com/pavlith/arc/sdk/bootstrap"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
)

// BootstrapConfig is the configuration of the standalone arc-mail process.
// Other services never import it to start Mail.
type BootstrapConfig struct {
	bootstrap.Config
	MasterKeyFile string            `json:"master_key_file"`
	IMAP          imapclient.Config `json:"imap"`
	IMAPCAFile    string            `json:"imap_ca_file,omitempty"`
}

func Run(ctx context.Context, path string) error {
	var cfg BootstrapConfig
	if err := bootstrap.ReadConfig(path, &cfg); err != nil {
		return err
	}
	vault, err := credentials.Load(cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	if cfg.IMAPCAFile != "" {
		f, err := os.Open(cfg.IMAPCAFile)
		if err != nil {
			return imapclient.ErrInvalid
		}
		raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		f.Close()
		if err != nil || len(raw) > 1<<20 {
			return imapclient.ErrInvalid
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return imapclient.ErrInvalid
		}
		cfg.IMAP.RootCAs = pool
	}
	probe, err := imapclient.New(cfg.IMAP)
	if err != nil {
		return err
	}

	deps, err := bootstrap.Open(ctx, cfg.Config)
	if err != nil {
		return err
	}
	defer deps.Close()

	// Each deployed service has its own ServiceAccount, owner DB, connections
	// and approved Fabric registry. No shared process-level service switch.
	registry := &fabric.Client{
		Account: cfg.ServiceID, Kid: cfg.Kid, Key: deps.Key, CoreKey: deps.CoreTrust,
	}
	app, err := New(Config{
		Vault: vault, Probe: probe, GormDB: deps.GormDB, Runtime: deps.RuntimeConfig(cfg.Config, registry),
		Identity: identity.Client{
			RPC: deps.RPC, ServiceID: cfg.ServiceID, Kid: cfg.Kid, PrivateKey: deps.Key,
		},
		CoreTrust: deps.CoreTrust,
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

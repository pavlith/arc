package mail

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"time"

	"github.com/pavlith/arc/sdk/bootstrap"
	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
	"github.com/pavlith/arc/services/mail/imapclient"
	"github.com/pavlith/arc/services/mail/stream"
)

// BootstrapConfig is the configuration of the standalone arc-mail process.
// Other services never import it to start Mail.
type BootstrapConfig struct {
	StreamListen       string `json:"stream_listen,omitempty"`
	StreamTLSCertFile  string `json:"stream_tls_cert_file,omitempty"`
	StreamTLSKeyFile   string `json:"stream_tls_key_file,omitempty"`
	StreamClientCAFile string `json:"stream_client_ca_file,omitempty"`
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
	var private *stream.Server
	if cfg.StreamListen != "" || cfg.StreamTLSCertFile != "" || cfg.StreamTLSKeyFile != "" || cfg.StreamClientCAFile != "" {
		compiled, e := contract.Compile(v1.Artifact())
		if e != nil {
			return e
		}
		private, err = stream.New(stream.Config{Listen: cfg.StreamListen, TLSCertFile: cfg.StreamTLSCertFile, TLSKeyFile: cfg.StreamTLSKeyFile, ClientCAFile: cfg.StreamClientCAFile, Contract: compiled, Accounts: app.Accounts, Verify: identity.RemoteAuthorizer(app.Accounts.Identity, deps.CoreTrust, "mail/v1")})
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
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = private.Stop(shutdown)
		}()
	}
	err = app.App.Wait(ctx)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

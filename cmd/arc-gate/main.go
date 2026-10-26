package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pavlith/arc/sdk"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
	gate "github.com/pavlith/arc/services/gate"
	edge "github.com/pavlith/arc/services/gate/modules/http"
)

type config struct {
	Listen           string     `json:"listen"`
	PublicOrigin     string     `json:"public_origin"`
	AllowedOrigins   []string   `json:"allowed_origins"`
	TrustedProxies   []string   `json:"trusted_proxies"`
	NATS             sdk.Config `json:"nats"`
	ServiceID        string     `json:"service_id"`
	Kid              string     `json:"kid"`
	KeyFile          string     `json:"key_file"`
	CoreTrustKeyFile string     `json:"core_trust_key_file"`
	TLSCertFile      string     `json:"tls_cert_file"`
	TLSKeyFile       string     `json:"tls_key_file"`
}

func main() {
	file := flag.String("config", "", "path to Gate JSON configuration")
	flag.Parse()
	if e := run(*file); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run(file string) error {
	f, e := os.Open(file)
	if e != nil {
		return errors.New("gate: cannot open configuration")
	}
	defer f.Close()
	var cfg config
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil {
		return errors.New("gate: invalid configuration")
	}
	if cfg.ServiceID == "" || cfg.Kid == "" {
		return errors.New("gate: service identity is required")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	key, e := identity.LoadSigningKey(cfg.KeyFile)
	if e != nil {
		return errors.New("gate: cannot load service credential")
	}
	raw, e := os.ReadFile(cfg.CoreTrustKeyFile)
	if e != nil {
		return errors.New("gate: cannot load Core trust root")
	}
	var root ed25519.PublicKey
	if json.Unmarshal(raw, &root) != nil {
		root, e = base64.StdEncoding.DecodeString(string(raw))
		if e != nil {
			return errors.New("gate: invalid Core trust root")
		}
	}
	if len(root) != 32 {
		return errors.New("gate: invalid Core trust root")
	}
	proxies := []netip.Prefix{}
	for _, s := range cfg.TrustedProxies {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return errors.New("gate: invalid trusted proxy CIDR")
		}
		proxies = append(proxies, p)
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") || cfg.TLSCertFile == "" && len(proxies) == 0 {
		return errors.New("gate: HTTPS certificate or explicit trusted proxy required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	nc, e := sdk.Connect(ctx, cfg.NATS)
	if e != nil {
		return errors.New("gate: private NATS connection failed")
	}
	defer nc.Close()
	client, e := rpc.NewClient(nc)
	if e != nil {
		return e
	}

	remote := &edge.Remote{Client: identity.Client{
		RPC: client, ServiceID: cfg.ServiceID, Kid: cfg.Kid, PrivateKey: key,
	}, TrustRoot: root}
	g, err := gate.New(gate.Config{
		HTTP: edge.Config{
			Backend:        remote,
			PublicOrigin:   cfg.PublicOrigin,
			AllowedOrigins: cfg.AllowedOrigins,
			TrustedProxies: proxies,
		},
		Listen:      cfg.Listen,
		TLSCertFile: cfg.TLSCertFile,
		TLSKeyFile:  cfg.TLSKeyFile,
		NATS:        nc,
	})
	if err != nil {
		return err
	}
	if err = g.Start(ctx); err != nil {
		return err
	}
	log.Printf("Arc Gate listening on %s", cfg.Listen)
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return g.Stop(shutdown)
}

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nkeys"
)

type nkeyIdentity struct {
	file string
	name string
}

var identities = []nkeyIdentity{
	{file: "nats-echo-service.seed", name: "echo service"},
	{file: "nats-smoke-client.seed", name: "smoke client"},
	{file: "nats-jetstream-admin.seed", name: "JetStream bootstrap"},
}

var passwordFiles = []string{
	"postgres-admin-password",
	"postgres-migrator-password",
	"postgres-core-password",
}

func main() {
	output := flag.String("out", "../.secrets/dev", "output directory")
	runtimeDirectory := flag.String("runtime-dir", "/run/secrets", "NATS runtime secret directory")
	storeDirectory := flag.String("store-dir", "/data/jetstream", "NATS JetStream store directory")
	flag.Parse()
	if err := runWithRuntime(*output, *runtimeDirectory, *storeDirectory); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap failed:", err)
		os.Exit(1)
	}
	fmt.Println("development credentials are ready in", *output)
}

func run(output string) error {
	return runWithRuntime(output, "/run/secrets", "/data/jetstream")
}

func runWithRuntime(output, runtimeDirectory, storeDirectory string) error {
	if output == "" {
		return errors.New("output directory is required")
	}
	if runtimeDirectory == "" || storeDirectory == "" {
		return errors.New("runtime and store directories are required")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.Chmod(output, 0o700); err != nil {
		return fmt.Errorf("protect output directory: %w", err)
	}

	publicKeys, err := ensureNKeys(output)
	if err != nil {
		return err
	}
	if err := ensureTLS(output); err != nil {
		return err
	}
	if err := ensurePasswords(output); err != nil {
		return err
	}
	return writeNATSConfig(output, runtimeDirectory, storeDirectory, publicKeys)
}

func ensureNKeys(output string) (map[string]string, error) {
	paths := make([]string, 0, len(identities))
	for _, identity := range identities {
		paths = append(paths, filepath.Join(output, identity.file))
	}
	exists, err := setState(paths)
	if err != nil {
		return nil, err
	}
	if !exists {
		for _, identity := range identities {
			pair, err := nkeys.CreateUser()
			if err != nil {
				return nil, fmt.Errorf("create %s NKey: %w", identity.name, err)
			}
			seed, err := pair.Seed()
			if err != nil {
				pair.Wipe()
				return nil, fmt.Errorf("encode %s NKey: %w", identity.name, err)
			}
			seed = append(seed, '\n')
			if err := writeExclusive(filepath.Join(output, identity.file), seed, 0o600); err != nil {
				pair.Wipe()
				return nil, err
			}
			pair.Wipe()
			for index := range seed {
				seed[index] = 0
			}
		}
	}

	publicKeys := make(map[string]string, len(identities))
	for _, identity := range identities {
		path := filepath.Join(output, identity.file)
		if err := requirePrivateMode(path); err != nil {
			return nil, err
		}
		seed, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s NKey: %w", identity.name, err)
		}
		pair, err := nkeys.FromSeed(bytes.TrimSpace(seed))
		for index := range seed {
			seed[index] = 0
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s NKey: %w", identity.name, err)
		}
		publicKey, err := pair.PublicKey()
		if err != nil {
			pair.Wipe()
			return nil, fmt.Errorf("derive %s public NKey: %w", identity.name, err)
		}
		pair.Wipe()
		publicKeys[identity.file] = publicKey
	}
	return publicKeys, nil
}

func ensureTLS(output string) error {
	paths := []string{
		filepath.Join(output, "ca.crt"),
		filepath.Join(output, "nats-server.crt"),
		filepath.Join(output, "nats-server.key"),
	}
	exists, err := setState(paths)
	if err != nil || exists {
		if exists {
			return requirePrivateMode(paths[2])
		}
		return err
	}

	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Arc development CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}
	serverSerial, err := randomSerial()
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "nats"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"nats", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create server certificate: %w", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("encode server key: %w", err)
	}

	if err := writeExclusive(paths[0], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return err
	}
	if err := writeExclusive(paths[1], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o644); err != nil {
		return err
	}
	return writeExclusive(paths[2], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}), 0o600)
}

func ensurePasswords(output string) error {
	paths := make([]string, 0, len(passwordFiles))
	for _, name := range passwordFiles {
		paths = append(paths, filepath.Join(output, name))
	}
	exists, err := setState(paths)
	if err != nil || exists {
		if exists {
			for _, path := range paths {
				if err := requirePrivateMode(path); err != nil {
					return err
				}
			}
		}
		return err
	}
	for _, path := range paths {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("generate database password: %w", err)
		}
		password := []byte(base64.RawURLEncoding.EncodeToString(raw) + "\n")
		for index := range raw {
			raw[index] = 0
		}
		if err := writeExclusive(path, password, 0o600); err != nil {
			return err
		}
		for index := range password {
			password[index] = 0
		}
	}
	return nil
}

func writeNATSConfig(output, runtimeDirectory, storeDirectory string, publicKeys map[string]string) error {
	serverCert := filepath.Join(runtimeDirectory, "nats_server_cert")
	serverKey := filepath.Join(runtimeDirectory, "nats_server_key")
	caCert := filepath.Join(runtimeDirectory, "nats_ca_cert")
	if runtimeDirectory != "/run/secrets" {
		serverCert = filepath.Join(runtimeDirectory, "nats-server.crt")
		serverKey = filepath.Join(runtimeDirectory, "nats-server.key")
		caCert = filepath.Join(runtimeDirectory, "ca.crt")
	}
	config := fmt.Sprintf(`server_name: arc-dev
port: 4222
http: 8222

jetstream {
  store_dir: %q
  max_memory_store: 256MB
  max_file_store: 1GB
}

tls {
  cert_file: %q
  key_file: %q
  ca_file: %q
  timeout: 2
}

authorization {
  users: [
    {
      nkey: %q
      permissions: {
        publish: { allow: ["_INBOX.>"] }
        subscribe: { allow: [
          "rpc.bootstrap.v1.echo",
          "$SRV.PING", "$SRV.PING.arc-bootstrap", "$SRV.PING.arc-bootstrap.>",
          "$SRV.INFO", "$SRV.INFO.arc-bootstrap", "$SRV.INFO.arc-bootstrap.>",
          "$SRV.STATS", "$SRV.STATS.arc-bootstrap", "$SRV.STATS.arc-bootstrap.>"
        ] }
      }
    },
    {
      nkey: %q
      permissions: {
        publish: { allow: ["rpc.bootstrap.v1.echo"] }
        subscribe: { allow: ["_INBOX.>"] }
      }
    },
    {
      nkey: %q
      permissions: {
        publish: { allow: ["$JS.API.>", "evt.>"] }
        subscribe: { allow: ["_INBOX.>"] }
      }
    }
  ]
}
`,
		storeDirectory,
		serverCert,
		serverKey,
		caCert,
		publicKeys["nats-echo-service.seed"],
		publicKeys["nats-smoke-client.seed"],
		publicKeys["nats-jetstream-admin.seed"],
	)
	return writeAtomic(filepath.Join(output, "nats-server.conf"), []byte(config), 0o600)
}

func setState(paths []string) (bool, error) {
	found := 0
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return false, fmt.Errorf("credential path is not a regular file: %s", path)
			}
			found++
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("inspect credential path: %w", err)
		}
	}
	if found != 0 && found != len(paths) {
		return false, errors.New("partial credential set exists; remove the development secret directory and regenerate")
	}
	return found == len(paths), nil
}

func requirePrivateMode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private file must be regular and mode 0600: %s", path)
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".arc-config-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install NATS config: %w", err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

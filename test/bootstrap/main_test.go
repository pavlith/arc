package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCreatesStablePrivateCredentialsWithoutEmbeddingSecrets(t *testing.T) {
	output := t.TempDir()
	if err := run(output); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("secret directory mode = %o", directory.Mode().Perm())
	}

	secretFiles := []string{}
	for _, identity := range identities {
		secretFiles = append(secretFiles, identity.file)
	}
	secretFiles = append(secretFiles, "nats-server.key", "nats-server.conf")

	before := make(map[string]string, len(secretFiles))
	config, err := os.ReadFile(filepath.Join(output, "nats-server.conf"))
	if err != nil {
		t.Fatal(err)
	}
	configText := string(config)
	for _, expected := range []string{
		`publish: { allow: ["rpc.bootstrap.v1.echo"] }`,
		`"rpc.bootstrap.v1.echo",`,
		`publish: { allow: ["$JS.API.>", "evt.>"] }`,
	} {
		if !strings.Contains(configText, expected) {
			t.Fatalf("NATS config is missing scoped permission %q", expected)
		}
	}
	if strings.Contains(configText, `"$SRV.>"`) {
		t.Fatal("service received broad NATS Micro monitoring permission")
	}
	for _, name := range secretFiles {
		path := filepath.Join(output, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %o", name, info.Mode().Perm())
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(contents)
		if name != "nats-server.conf" && strings.Contains(string(config), strings.TrimSpace(string(contents))) {
			t.Fatalf("%s leaked into NATS config", name)
		}
	}

	if err := run(output); err != nil {
		t.Fatal(err)
	}
	for name, want := range before {
		contents, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(contents) != want {
			t.Fatalf("%s changed on repeated bootstrap", name)
		}
	}
}

func TestRunRejectsPartialCredentialSet(t *testing.T) {
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(output, identities[0].file), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(output); err == nil {
		t.Fatal("partial credential set was accepted")
	}
}

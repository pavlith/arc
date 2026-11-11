package agent

import (
	"crypto/ed25519"
	"testing"
)

func TestNodeConnectionCloseClearsPrivateSigningKey(t *testing.T) {
	key := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	connection := &nodeConnection{key: key}
	connection.Close()
	connection.Close()
	for _, b := range key {
		if b != 0 {
			t.Fatal("private signing key not cleared")
		}
	}
	var absent *nodeConnection
	absent.Close()
}

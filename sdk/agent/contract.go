// Package agent defines the typed Core-to-node boundary. It contains no host API.
package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

var ErrInvalid = errors.New("agent: invalid contract")
var ErrStale = errors.New("agent: stale or conflicting revision")

// RFC8785 numbers must survive an IEEE-754 JSON round trip exactly.
const maxRevision int64 = 1<<53 - 1

// Kinds are separate resources, not Docker-compatible deployment emulations.
type Kind string

const (
	Docker  Kind = "docker.container"
	LXD     Kind = "lxd.instance"
	Systemd Kind = "systemd.service"
)

type State string

const (
	Running State = "running"
	Stopped State = "stopped"
	Deleted State = "deleted"
)

// Spec accepts references to operator-approved configuration, never shell,
// environment values, mounts, capabilities or host ports from API callers.
type Spec struct {
	ID               string `json:"id"`
	NodeID           string `json:"node_id"`
	Kind             Kind   `json:"kind"`
	TemplateID       string `json:"template_id"`
	TemplateRevision int64  `json:"template_revision"`
	TemplateDigest   string `json:"template_digest"`
	Revision         int64  `json:"revision"`
	State            State  `json:"state"`
	Replicas         int    `json:"replicas"`
}

// Template is installed by the node operator, independently of desired state.
// A driver must reject unsupported security settings rather than ignore them.
type Template struct {
	ID          string `json:"id"`
	Revision    int64  `json:"revision"`
	Kind        Kind   `json:"kind"`
	Target      string `json:"target"`
	MaxReplicas int    `json:"max_replicas"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var imageDigest = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$`)
var unitName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,120}\.service$`)

func ValidID(id string) bool { return identifier.MatchString(id) }
func Bootstrap(id string) bool {
	switch id {
	case "core", "arc-core", "gate", "arc-gate", "nats", "agent", "arc-agent", "docker", "containerd", "lxd", "ssh", "sshd":
		return true
	}
	return false
}
func (t Template) Validate() error {
	if !ValidID(t.ID) || t.Revision < 1 || t.Revision > maxRevision || t.MaxReplicas < 1 || t.MaxReplicas > 100 || Bootstrap(t.ID) {
		return ErrInvalid
	}
	switch t.Kind {
	case Docker:
		if !imageDigest.MatchString(t.Target) {
			return ErrInvalid
		}
	case LXD:
		// A local immutable image fingerprint, not a remote alias or mutable name.
		if len(t.Target) != 64 {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(t.Target); err != nil {
			return ErrInvalid
		}
		if t.MaxReplicas != 1 {
			return ErrInvalid
		}
	case Systemd:
		if !unitName.MatchString(t.Target) || Bootstrap(t.Target[:len(t.Target)-8]) || t.MaxReplicas != 1 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (s Spec) Validate(t Template, node string) error {
	if t.Validate() != nil || !ValidID(node) || s.NodeID != node || !ValidID(s.ID) || Bootstrap(s.ID) ||
		s.TemplateID != t.ID || s.TemplateRevision != t.Revision || s.TemplateDigest != TemplateDigest(t) || s.Kind != t.Kind || s.Revision < 1 || s.Revision > maxRevision || s.Replicas < 0 || s.Replicas > t.MaxReplicas {
		return ErrInvalid
	}
	switch s.State {
	case Running:
		if s.Replicas < 1 {
			return ErrInvalid
		}
	case Stopped, Deleted:
		if s.Replicas != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Snapshot is a short-lived answer to one fresh pull request. An event is only
// a hint to pull; it is never an execution instruction.
type Snapshot struct {
	Version     int    `json:"version"`
	RequestID   string `json:"request_id"`
	OperationID string `json:"operation_id"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	Spec        Spec   `json:"spec"`
}
type SignedSnapshot struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

func strict(raw []byte, dst any) error {
	if len(raw) > 65536 {
		return ErrInvalid
	}
	canonical, err := security.CanonicalJSON(raw)
	if err != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func snapshotBytes(s Snapshot) ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return security.CanonicalJSON(raw)
}
func Sign(s Snapshot, key ed25519.PrivateKey) (SignedSnapshot, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedSnapshot{}, ErrInvalid
	}
	raw, err := snapshotBytes(s)
	if err != nil {
		return SignedSnapshot{}, err
	}
	return SignedSnapshot{raw, base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte("arc.runtime.snapshot.v1\n"), raw...)))}, nil
}
func Verify(raw []byte, key ed25519.PublicKey, node, request string, now time.Time, templates map[string]Template) (Snapshot, error) {
	var signed SignedSnapshot
	var s Snapshot
	if len(key) != ed25519.PublicKeySize || strict(raw, &signed) != nil {
		return s, security.ErrUnauthenticated
	}
	canonical, err := security.CanonicalJSON(signed.Payload)
	if err != nil {
		return s, security.ErrUnauthenticated
	}
	sig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte("arc.runtime.snapshot.v1\n"), canonical...), sig) {
		return s, security.ErrUnauthenticated
	}
	if strict(canonical, &s) != nil || s.Version != 1 || len(request) < 16 || len(request) > 128 || s.RequestID != request || !ValidID(s.OperationID) || s.IssuedAt > now.Unix() || s.ExpiresAt <= now.Unix() || s.ExpiresAt <= s.IssuedAt || s.ExpiresAt-s.IssuedAt > 30 {
		return Snapshot{}, ErrInvalid
	}
	t, ok := templates[s.Spec.TemplateID]
	if !ok || s.Spec.Validate(t, node) != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}

// SpecDigest excludes request freshness: repeated pulls of the same revision
// must be identical even though their request IDs and expiration differ.
func SpecDigest(s Spec) string { return objectDigest(s) }

// TemplateDigest binds a template reference to its complete approved contents.
func TemplateDigest(t Template) string { return objectDigest(t) }

func objectDigest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	raw, err = security.CanonicalJSON(raw)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

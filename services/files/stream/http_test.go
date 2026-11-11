package stream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/migrations"
	"github.com/pavlith/arc/services/files/models"
	"github.com/pavlith/arc/services/files/modules/objects"
	"github.com/pavlith/arc/services/files/storage"
)

const (
	streamWorkspace = "00000000-0000-4000-8000-000000000101"
	streamRoot      = "00000000-0000-4000-8000-000000000102"
	streamUpload    = "00000000-0000-4000-8000-000000000103"
	streamFile      = "00000000-0000-4000-8000-000000000104"
)

func TestMTLSPrivateByteReceiverScopesAndStreaming(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "files.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close(db)
	if err := database.Migrate(ctx, db, migrations.SQLite()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO roots(acl_root_id,workspace_id,state) VALUES(?,?,'active')", streamRoot, streamWorkspace).Error; err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenLocal(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Prepare(ctx, streamUpload); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.Create(&models.Upload{
		ID: streamUpload, WorkspaceID: streamWorkspace, RootID: streamRoot,
		ActorID: "user:alice", SessionID: "session-a", Filename: "private.bin",
		DeclaredMIME: "application/octet-stream", ExpectedSize: 3, TempKey: streamUpload,
		State: "pending", IdempotencyKey: "init-1",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	compiled, err := contract.Compile(filesv1.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	allowed := true
	checks := 0
	mod := &objects.Module{DB: db, Contract: compiled, Storage: store,
		Authorize: func(_ context.Context, root, action string) error {
			checks++
			if !allowed || root != streamRoot || (action != "files.create" && action != "files.read") {
				return security.ErrDenied
			}
			return nil
		}}
	// Fixture identity authority only. Production uses
	// identity.RemoteAuthorizer and Core's Ed25519 proof verifier.
	verified := rpc.RemoteInvocationAuthorizer(func(_ context.Context, subject string, raw []byte) (security.Claims, error) {
		var env struct {
			Auth      string         `json:"auth"`
			Operation string         `json:"operation"`
			Proof     security.Proof `json:"proof"`
		}
		if json.Unmarshal(raw, &env) != nil || env.Auth != "fixture-token" ||
			env.Proof.Signature != "fixture-signed" ||
			subject != "rpc.files.v1."+strings.TrimPrefix(env.Operation, "files.") {
			return security.Claims{}, security.ErrUnauthenticated
		}
		return security.Claims{Subject: "user:alice", SessionID: "session-a",
			WorkspaceID: streamWorkspace, Operation: env.Operation}, nil
	})
	s, err := New(Config{
		Listen: "127.0.0.1:0", TLSCertFile: "unused", TLSKeyFile: "unused", ClientCAFile: "unused",
		Verify: verified, Objects: mod, Contract: compiled,
	})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(operation string, payload any) string {
		q, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{
			"request_id": "fixture-1", "operation": operation, "schema_version": 1,
			"deadline_at": time.Now().Add(20 * time.Second), "auth": "fixture-token",
			"proof":           security.Proof{Kid: "fixture", Signature: "fixture-signed", Nonce: "nonce-1234567890123456", Timestamp: now.Format(time.RFC3339Nano)},
			"idempotency_key": "chunk-key-1", "payload": json.RawMessage(q),
		})
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	req := func(method, path string, body io.Reader, op string, payload any) *http.Request {
		r := httptest.NewRequest(method, "https://files.internal"+path, body)
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{new(x509.Certificate)}}}
		r.Header.Set(InvocationHeader, encode(op, payload))
		return r
	}
	ref := filesv1.UploadRef{
		Scope:    filesv1.Scope{WorkspaceID: streamWorkspace, RootID: streamRoot},
		UploadID: streamUpload,
	}
	chunk := filesv1.PrivateChunkRequest{UploadRef: ref, Offset: 0, Length: 3}
	r := req(http.MethodPatch, ChunkPath, strings.NewReader("abc"), filesv1.PrivateChunk.ID, chunk)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || checks < 2 {
		t.Fatalf("signed chunk failed: status=%d checks=%d body=%s", w.Code, checks, w.Body.String())
	}
	var updated filesv1.Upload
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil || updated.Offset != 3 {
		t.Fatalf("stored chunk metadata: %+v %v", updated, err)
	}
	r = req(http.MethodPatch, ChunkPath, strings.NewReader("abc"), filesv1.PrivateChunk.ID, chunk)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("stale offset replay accepted: %d", w.Code)
	}
	// The exact private invocation cannot be sent without an mTLS client.
	r = req(http.MethodPatch, ChunkPath, strings.NewReader("abc"), filesv1.PrivateChunk.ID, chunk)
	r.TLS = nil
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing mTLS accepted: %d", w.Code)
	}
	r = req(http.MethodPatch, ChunkPath, strings.NewReader("abc"), filesv1.PrivateChunk.ID, chunk)
	r.Header.Del(InvocationHeader)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("missing signed envelope accepted: %d", w.Code)
	}
	digest := sha256.Sum256([]byte("abc"))
	if _, err := store.Promote(ctx, streamUpload, streamFile, 3, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.File{
		ID: streamFile, WorkspaceID: streamWorkspace, RootID: streamRoot,
		Filename: "private.bin", MIME: "application/octet-stream", Size: 3, SHA256: hex.EncodeToString(digest[:]),
		BlobKey: streamFile, Revision: 1, State: "ready", CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatal(err)
	}
	file := filesv1.FileRef{Scope: ref.Scope, FileID: streamFile}
	r = req(http.MethodGet, DownloadPath, nil, filesv1.PrivateDownload.ID, file)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "abc" || w.Header().Get("Content-Length") != "3" {
		t.Fatalf("private ready file download: status=%d body=%q len=%q", w.Code, w.Body.String(), w.Header().Get("Content-Length"))
	}
	allowed = false
	r = req(http.MethodGet, DownloadPath, nil, filesv1.PrivateDownload.ID, file)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 || w.Body.String() == "abc" {
		t.Fatalf("revoked ACL disclosed file: %d %q", w.Code, w.Body.String())
	}
	allowed = true
	r = req(http.MethodGet, DownloadPath, nil, filesv1.PrivateDownload.ID, filesv1.FileRef{
		Scope:  filesv1.Scope{WorkspaceID: streamWorkspace, RootID: "00000000-0000-4000-8000-000000000105"},
		FileID: streamFile})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-root file disclosed: %d", w.Code)
	}
	// A browser-supplied cookie cannot pass the private receiver boundary.
	r = req(http.MethodGet, DownloadPath, nil, filesv1.PrivateDownload.ID, file)
	r.Header.Set("Cookie", "__Host-arc_session=forged")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("browser cookie accepted: %d", w.Code)
	}
	// Missing decoded body is never treated as a success response.
	r = req(http.MethodGet, DownloadPath, nil, filesv1.PrivateDownload.ID, file)
	r.URL.RawQuery = "force=1"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("query smuggling accepted: %d", w.Code)
	}
	if offset, err := store.Open(ctx, streamFile); err != nil {
		t.Fatalf("bad requests removed ready blob: %v", err)
	} else {
		_ = offset.Close()
	}
	if checks < 4 {
		t.Fatalf("live ACL never checked: %d", checks)
	}
	_ = bytes.MinRead
}

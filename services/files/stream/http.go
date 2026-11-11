// Package stream implements Files' private, mTLS-only byte endpoint.
// It accepts signed invocation metadata, never browser identity headers.
package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/modules/objects"
	"github.com/pavlith/arc/services/files/storage"
)

const (
	ChunkPath = "/private/v1/files/chunk"
	DownloadPath = "/private/v1/files/download"
	InvocationHeader = "X-Arc-Invocation"
)

var requestID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type Verify func(context.Context, string, []byte) (context.Context, error)

type Config struct {
	Listen string
	TLSCertFile string
	TLSKeyFile string
	ClientCAFile string
	Verify Verify
	Objects *objects.Module
	Contract *contract.Compiled
}

type Server struct {
	cfg Config
	handler http.Handler
	server *http.Server
	listener net.Listener
	ended chan error
	mu sync.Mutex
}

// New validates the immutable signed artifact and the private byte paths.
func New(cfg Config) (*Server, error) {
	if cfg.Listen == "" || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" ||
		cfg.ClientCAFile == "" || cfg.Verify == nil || cfg.Objects == nil ||
		cfg.Contract == nil {
		return nil, security.ErrUnavailable
	}
	for _, entry := range []struct{ID,Action string}{
		{filesv1.PrivateChunk.ID,"files.create"},
		{filesv1.PrivateDownload.ID,"files.read"},
	} {
		op, err := cfg.Contract.Operation(entry.ID)
		if err != nil || op.HTTP.Expose || op.Auth.Mode != "resource" ||
			op.Auth.Action != entry.Action || op.Auth.ResourceFrom != "payload.acl_root_id" ||
			op.Auth.WorkspaceFrom != "payload.workspace_id" {
			return nil, security.ErrUnavailable
		}
	}
	s := &Server{cfg:cfg}
	s.handler = http.HandlerFunc(s.serve)
	return s,nil
}

func (s *Server) Handler() http.Handler {
	if s == nil {return nil}
	return s.handler
}

type invocation struct {
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	SchemaVersion int `json:"schema_version"`
	DeadlineAt time.Time `json:"deadline_at"`
	Auth string `json:"auth"`
	Proof security.Proof `json:"proof"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Traceparent string `json:"traceparent,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

func sendError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (s *Server) serve(w http.ResponseWriter,r *http.Request) {
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("X-Content-Type-Options","nosniff")
	w.Header().Set("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'")
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
		r.URL.RawQuery != "" || r.URL.RawPath != "" ||
		r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" ||
		r.Header.Get("Authorization") != "" {
		sendError(w,http.StatusForbidden)
		return
	}
	var operation string
	switch {
	case r.Method == http.MethodPatch && r.URL.Path == ChunkPath:
		operation = filesv1.PrivateChunk.ID
	case r.Method == http.MethodGet && r.URL.Path == DownloadPath:
		operation = filesv1.PrivateDownload.ID
	default:
		sendError(w,http.StatusNotFound)
		return
	}
	header := r.Header.Values(InvocationHeader)
	if len(header) != 1 || len(header[0]) < 8 || len(header[0]) > 32768 {
		sendError(w,http.StatusUnauthorized)
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(header[0])
	if err != nil || len(raw) > 24576 {
		sendError(w,http.StatusUnauthorized)
		return
	}
	var env invocation
	if contract.Strict(raw,&env) != nil || env.Operation != operation ||
		env.SchemaVersion != 1 || !requestID.MatchString(env.RequestID) ||
		env.Auth == "" || env.Proof.Signature == "" ||
		!env.DeadlineAt.After(time.Now()) ||
		env.DeadlineAt.After(time.Now().Add(60*time.Second)) {
		sendError(w,http.StatusUnauthorized)
		return
	}
	op, err := s.cfg.Contract.Operation(operation)
	if err != nil || op.HTTP.Expose || s.cfg.Contract.Validate(op.RequestSchema,env.Payload) != nil {
		sendError(w,http.StatusForbidden)
		return
	}
	if operation == filesv1.PrivateChunk.ID && (env.IdempotencyKey == "" || len(env.IdempotencyKey) > 128) {
		sendError(w,http.StatusBadRequest)
		return
	}
	// Core verifies Ed25519 proof, token/session, target service and nonce.
	// The proof covers the exact scope, object ID, offset and byte count.
	ctx, cancel := context.WithDeadline(r.Context(),env.DeadlineAt)
	defer cancel()
	ctx,err = s.cfg.Verify(ctx,op.Subject,raw)
	if err != nil || ctx == nil {
		sendError(w,http.StatusForbidden)
		return
	}
	if operation == filesv1.PrivateChunk.ID {
		var q filesv1.PrivateChunkRequest
		if json.Unmarshal(env.Payload,&q) != nil || r.ContentLength != q.Length ||
			r.ContentLength < 1 || r.ContentLength > storage.MaxChunkSize ||
			len(r.TransferEncoding) > 0 {
			sendError(w,http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w,r.Body,storage.MaxChunkSize)
		result,err := s.cfg.Objects.AppendChunk(ctx,q.UploadRef,q.Offset,q.Length,r.Body)
		if err != nil {
			sendError(w,http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type","application/json")
		_ = json.NewEncoder(w).Encode(result)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		sendError(w,http.StatusBadRequest)
		return
	}
	var ref filesv1.FileRef
	if json.Unmarshal(env.Payload,&ref) != nil {
		sendError(w,http.StatusBadRequest)
		return
	}
	// All response headers are set ONLY after an authorized metadata lookup.
	file,err := s.cfg.Objects.PrepareDownload(ctx,ref)
	if err != nil {
		sendError(w,http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type","application/octet-stream")
	w.Header().Set("Content-Disposition",`attachment; filename="download.bin"`)
	w.Header().Set("ETag",file.ETag)
	w.Header().Set("Content-Length",strconv.FormatInt(file.Size,10))
	// A failed/revoked stream after a 200 terminates early. Its declared size
	// makes this a truncated response, never a complete successful download.
	if _,err := s.cfg.Objects.StreamDownload(ctx,ref,w); err != nil {
		return
	}
}

// Start is strictly opt-in and requires client certificate verification.
func (s *Server) Start() error {
	if s == nil {return security.ErrUnavailable}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {return security.ErrUnavailable}
	cert,err := tls.LoadX509KeyPair(s.cfg.TLSCertFile,s.cfg.TLSKeyFile)
	if err != nil {return security.ErrUnavailable}
	pem,err := os.ReadFile(s.cfg.ClientCAFile)
	if err != nil {return security.ErrUnavailable}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {return security.ErrUnavailable}
	l,err := net.Listen("tcp",s.cfg.Listen)
	if err != nil {return err}
	tlsListener := tls.NewListener(l,&tls.Config{
		MinVersion:tls.VersionTLS13,
		Certificates:[]tls.Certificate{cert},
		ClientCAs:pool,ClientAuth:tls.RequireAndVerifyClientCert,
		NextProtos:[]string{"http/1.1"},
	})
	server := &http.Server{
		Handler:s.handler,
		ReadHeaderTimeout:5*time.Second,
		ReadTimeout:90*time.Second,
		IdleTimeout:60*time.Second,
		MaxHeaderBytes:48<<10,
	}
	s.server,s.listener,s.ended=server,tlsListener,make(chan error,1)
	go func() {
		err := server.Serve(tlsListener)
		if errors.Is(err,http.ErrServerClosed) {err=nil}
		s.ended<-err
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s == nil {return nil}
	s.mu.Lock()
	srv,done:=s.server,s.ended
	s.server=nil
	s.ended=nil
	s.mu.Unlock()
	if srv==nil{return nil}
	if ctx==nil {ctx=context.Background()}
	err:=srv.Shutdown(ctx)
	if err != nil {_=srv.Close()}
	if done!=nil {
		if stop:=<-done;stop!=nil {err=errors.Join(err,stop)}
	}
	return err
}

var _ io.Writer = http.ResponseWriter(nil)

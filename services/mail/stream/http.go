// Package stream serves Mail bytes only over private mTLS with Core-verified proofs.
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
	"sync"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/imapclient"
	mail "github.com/pavlith/arc/services/mail/modules/mail"
)

const DownloadPath = "/private/v1/mail/download"
const InvocationHeader = "X-Arc-Invocation"

var requestID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type Config struct {
	Listen, TLSCertFile, TLSKeyFile, ClientCAFile string
	Verify                                        func(context.Context, string, []byte) (context.Context, error)
	Accounts                                      *mail.Module
	Contract                                      *contract.Compiled
}
type Server struct {
	cfg      Config
	handler  http.Handler
	server   *http.Server
	listener net.Listener
	ended    chan error
	mu       sync.Mutex
}

func New(cfg Config) (*Server, error) {
	if cfg.Listen == "" || cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" || cfg.ClientCAFile == "" || cfg.Verify == nil || cfg.Accounts == nil || cfg.Contract == nil {
		return nil, security.ErrUnavailable
	}
	op, err := cfg.Contract.Operation(v1.PrivateDownload.ID)
	if err != nil || op.HTTP.Expose || op.Auth.Mode != "resource" || op.Auth.ResourceType != "mail.personal" || op.Auth.Action != "mail.read" || op.Auth.ResourceFrom != "payload.acl_root_id" || op.Auth.WorkspaceFrom != "" {
		return nil, security.ErrUnavailable
	}
	s := &Server{cfg: cfg}
	s.handler = http.HandlerFunc(s.serve)
	return s, nil
}
func (s *Server) Handler() http.Handler { return s.handler }

type invocation struct {
	RequestID      string          `json:"request_id"`
	Operation      string          `json:"operation"`
	SchemaVersion  int             `json:"schema_version"`
	DeadlineAt     time.Time       `json:"deadline_at"`
	Auth           string          `json:"auth"`
	Proof          security.Proof  `json:"proof"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	Traceparent    string          `json:"traceparent,omitempty"`
	Payload        json.RawMessage `json:"payload"`
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox; frame-ancestors 'none'")
	fail := func(code int) { http.Error(w, http.StatusText(code), code) }
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
		fail(403)
		return
	}
	if r.Method != "GET" || r.URL.Path != DownloadPath {
		fail(404)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Range") != "" {
		fail(400)
		return
	}
	header := r.Header.Values(InvocationHeader)
	if len(header) != 1 || len(header[0]) < 8 || len(header[0]) > 32768 {
		fail(401)
		return
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(header[0])
	if err != nil || len(raw) > 24576 {
		fail(401)
		return
	}
	var env invocation
	if contract.Strict(raw, &env) != nil || env.Operation != v1.PrivateDownload.ID || env.SchemaVersion != 1 || !requestID.MatchString(env.RequestID) || env.Auth == "" || env.Proof.Signature == "" || env.IdempotencyKey != "" || !env.DeadlineAt.After(time.Now()) || env.DeadlineAt.After(time.Now().Add(60*time.Second)) {
		fail(401)
		return
	}
	op, err := s.cfg.Contract.Operation(env.Operation)
	if err != nil || s.cfg.Contract.Validate(op.RequestSchema, env.Payload) != nil {
		fail(403)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), env.DeadlineAt)
	defer cancel()
	ctx, err = s.cfg.Verify(ctx, op.Subject, raw)
	if err != nil || ctx == nil {
		fail(403)
		return
	}
	var q v1.DownloadRequest
	if json.Unmarshal(env.Payload, &q) != nil {
		fail(400)
		return
	}
	started := false
	err = s.cfg.Accounts.StreamDownload(ctx, q, func(source io.Reader) error {
		// Validate the first block before exposing any success headers.
		buffer := make([]byte, imapclient.DownloadBlockSize)
		n, err := source.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="message.eml"`)
		if q.Section != "" {
			w.Header().Set("Content-Disposition", `attachment; filename="attachment.bin"`)
		}
		w.Header().Set("X-Arc-Mail-Stream", "v1")
		w.WriteHeader(200)
		started = true
		if n > 0 {
			written, e := w.Write(buffer[:n])
			if e != nil {
				return e
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return nil
		}
		_, err = io.CopyBuffer(struct{ io.Writer }{w}, source, buffer)
		return err
	})
	if err != nil {
		if started {
			panic(http.ErrAbortHandler)
		}
		fail(403)
	}
}

// Start is strictly opt-in and requires client certificate verification.
func (s *Server) Start() error {
	if s == nil {
		return security.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return security.ErrUnavailable
	}
	privateKey, err := os.Stat(s.cfg.TLSKeyFile)
	if err != nil || !privateKey.Mode().IsRegular() || privateKey.Mode().Perm()&0077 != 0 {
		return security.ErrUnavailable
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	if err != nil {
		return security.ErrUnavailable
	}
	pem, err := os.ReadFile(s.cfg.ClientCAFile)
	if err != nil {
		return security.ErrUnavailable
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return security.ErrUnavailable
	}
	l, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(l, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool, ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"http/1.1"},
	})
	server := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       90 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    48 << 10,
	}
	s.server, s.listener, s.ended = server, tlsListener, make(chan error, 1)
	// Capture the completion channel: Stop clears the owner field before
	// waiting. Sending through s.ended after that would deadlock on nil.
	done := s.ended
	go func() {
		err := server.Serve(tlsListener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	srv, done := s.server, s.ended
	s.server = nil
	s.ended = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := srv.Shutdown(ctx)
	if err != nil {
		_ = srv.Close()
	}
	if done != nil {
		if stop := <-done; stop != nil {
			err = errors.Join(err, stop)
		}
	}
	return err
}

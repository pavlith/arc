// Package transport implements Arc's deliberately narrow NATS service transport.
//
// The wire-level $SRV.PING/INFO/STATS responses are compatible with the NATS
// micro v1 monitoring protocol. This is an Arc-specific implementation of
// those protocol shapes, not a vendored copy of nats.go/micro. The NATS client,
// request/reply, queue subscriptions and reconnect handling remain nats.go's.
//
// An Arc logical service owns its NATS connection and Fabric identity.
// This transport has no authorization bypass: requests are authenticated and
// schema-checked by sdk/rpc and sdk/app, never by the transport itself.
package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"
)

var (
	ErrInvalid     = errors.New("transport: invalid service or endpoint")
	ErrStopped     = errors.New("transport: service already stopped")
	serviceName    = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	serviceVersion = regexp.MustCompile("^[0-9]+[.][0-9]+[.][0-9]+([-+][A-Za-z0-9.-]+)?$")
)

// Config defines one NATS Micro-compatible monitoring identity.
type Config struct {
	Name, Version, Description string
	Metadata                   map[string]string
}
type Identity struct {
	Name     string            `json:"name"`
	ID       string            `json:"id"`
	Version  string            `json:"version"`
	Metadata map[string]string `json:"metadata"`
}
type EndpointInfo struct {
	Name       string            `json:"name"`
	Subject    string            `json:"subject"`
	QueueGroup string            `json:"queue_group"`
	Metadata   map[string]string `json:"metadata"`
}
type Info struct {
	Identity
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Endpoints   []EndpointInfo `json:"endpoints"`
}
type EndpointStats struct {
	Name                  string        `json:"name"`
	Subject               string        `json:"subject"`
	QueueGroup            string        `json:"queue_group"`
	NumRequests           int           `json:"num_requests"`
	NumErrors             int           `json:"num_errors"`
	LastError             string        `json:"last_error"`
	ProcessingTime        time.Duration `json:"processing_time"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
}
type Stats struct {
	Identity
	Type      string           `json:"type"`
	Started   time.Time        `json:"started"`
	Endpoints []*EndpointStats `json:"endpoints"`
}

// Request is just what Arc RPC needs. Authentication and response envelopes
// are handled by sdk/rpc, rather than duplicated in micro's request API.
type Request interface {
	Data() []byte
	Respond([]byte) error
}
type Handler func(Request)

type request struct{ msg *nats.Msg }

func (r request) Data() []byte { return r.msg.Data }
func (r request) Respond(data []byte) error {
	if r.msg.Reply == "" {
		return ErrInvalid
	}
	return r.msg.Respond(data)
}

type EndpointOptions struct{ Subject, QueueGroup string }
type EndpointOpt func(*EndpointOptions)

func WithEndpointSubject(subject string) EndpointOpt {
	return func(o *EndpointOptions) { o.Subject = subject }
}
func WithEndpointQueueGroup(group string) EndpointOpt {
	return func(o *EndpointOptions) { o.QueueGroup = group }
}

type endpoint struct {
	info         EndpointInfo
	subscription *nats.Subscription
	stats        EndpointStats
}

// Service is one independently registered NATS process. Stop does not close
// the connection: the SDK's service owner is responsible for that.
type Service struct {
	nc        *nats.Conn
	cfg       Config
	identity  Identity
	started   time.Time
	mu        sync.RWMutex
	stopped   bool
	controls  []*nats.Subscription
	endpoints map[string]*endpoint
	subjects  map[string]struct{}
}

func New(nc *nats.Conn, cfg Config) (*Service, error) {
	if nc == nil || nc.IsClosed() || !serviceName.MatchString(cfg.Name) ||
		!serviceVersion.MatchString(cfg.Version) {
		return nil, ErrInvalid
	}
	metadata := make(map[string]string, len(cfg.Metadata))
	for k, v := range cfg.Metadata {
		metadata[k] = v
	}
	s := &Service{
		nc: nc, cfg: cfg, identity: Identity{
			Name: cfg.Name, ID: nuid.Next(), Version: cfg.Version, Metadata: metadata,
		}, started: time.Now().UTC(),
		endpoints: make(map[string]*endpoint), subjects: make(map[string]struct{}),
	}
	for _, v := range []string{"PING", "INFO", "STATS"} {
		for _, subject := range []string{
			"$SRV." + v, "$SRV." + v + "." + cfg.Name, "$SRV." + v + "." + cfg.Name + "." + s.identity.ID,
		} {
			verb := v
			sub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
				if msg.Reply == "" {
					return
				}
				var payload any
				switch verb {
				case "PING":
					payload = struct {
						Identity
						Type string `json:"type"`
					}{Identity: s.identitySnapshot(), Type: "io.nats.micro.v1.ping_response"}
				case "INFO":
					payload = s.Info()
				case "STATS":
					payload = s.Stats()
				}
				data, err := json.Marshal(payload)
				if err == nil {
					_ = msg.Respond(data)
				}
			})
			if err != nil {
				_ = s.Stop()
				return nil, fmt.Errorf("transport: subscribe monitor %s: %w", subject, err)
			}
			s.mu.Lock()
			s.controls = append(s.controls, sub)
			s.mu.Unlock()
		}
	}
	return s, nil
}
func (s *Service) identitySnapshot() Identity {
	out := s.identity
	out.Metadata = make(map[string]string, len(s.identity.Metadata))
	for k, v := range s.identity.Metadata {
		out.Metadata[k] = v
	}
	return out
}

func validSubject(subject string) bool {
	if subject == "" ||
		strings.ContainsAny(subject, " *>") ||
		strings.ContainsAny(subject, string([]byte{9, 10, 13})) ||
		strings.HasPrefix(subject, ".") || strings.HasSuffix(subject, ".") ||
		strings.Contains(subject, "..") {
		return false
	}
	return true
}
func (s *Service) AddEndpoint(name string, handler Handler, opts ...EndpointOpt) error {
	if s == nil || !serviceName.MatchString(name) || handler == nil {
		return ErrInvalid
	}
	options := EndpointOptions{Subject: name, QueueGroup: "q"}
	for _, opt := range opts {
		if opt == nil {
			return ErrInvalid
		}
		opt(&options)
	}
	if !validSubject(options.Subject) || !validSubject(options.QueueGroup) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.nc.IsClosed() {
		return ErrStopped
	}
	if _, ok := s.endpoints[name]; ok {
		return ErrInvalid
	}
	if _, ok := s.subjects[options.Subject]; ok {
		return ErrInvalid
	}
	e := &endpoint{info: EndpointInfo{Name: name, Subject: options.Subject, QueueGroup: options.QueueGroup, Metadata: map[string]string{}}}
	e.stats = EndpointStats{Name: name, Subject: options.Subject, QueueGroup: options.QueueGroup}
	subscription, err := s.nc.QueueSubscribe(options.Subject, options.QueueGroup, func(msg *nats.Msg) {
		started := time.Now()
		req := request{msg: msg}
		// A panic must not kill the subscription's NATS callback goroutine.
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			handler(req)
		}()
		duration := time.Since(started)
		s.mu.Lock()
		e.stats.NumRequests++
		e.stats.ProcessingTime += duration
		e.stats.AverageProcessingTime = e.stats.ProcessingTime / time.Duration(e.stats.NumRequests)
		if panicked {
			e.stats.NumErrors++
			e.stats.LastError = "handler panic"
		}
		s.mu.Unlock()
	})
	if err != nil {
		return fmt.Errorf("transport: endpoint subscribe %s: %w", name, err)
	}
	e.subscription = subscription
	s.endpoints[name] = e
	s.subjects[options.Subject] = struct{}{}
	return nil
}

func (s *Service) Info() Info {
	if s == nil {
		return Info{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Info{
		Identity: s.identitySnapshot(), Type: "io.nats.micro.v1.info_response",
		Description: s.cfg.Description, Endpoints: make([]EndpointInfo, 0, len(s.endpoints)),
	}
	for _, e := range s.endpoints {
		info := e.info
		info.Metadata = map[string]string{}
		out.Endpoints = append(out.Endpoints, info)
	}
	return out
}
func (s *Service) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Stats{Identity: s.identitySnapshot(), Type: "io.nats.micro.v1.stats_response",
		Started: s.started, Endpoints: make([]*EndpointStats, 0, len(s.endpoints))}
	for _, e := range s.endpoints {
		st := e.stats
		out.Endpoints = append(out.Endpoints, &st)
	}
	return out
}

// Stop is idempotent and never leaves a monitoring subscription behind.
// The owner flushes UNSUB to NATS before closing the connection.
func (s *Service) Stop() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	subs := append([]*nats.Subscription{}, s.controls...)
	for _, e := range s.endpoints {
		subs = append(subs, e.subscription)
	}
	s.controls = nil
	s.mu.Unlock()
	var result error
	for _, sub := range subs {
		if sub == nil {
			continue
		}
		if err := sub.Unsubscribe(); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
			result = errors.Join(result, err)
		}
	}
	return result
}

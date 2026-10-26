// Package listener owns Gate's bounded HTTPS listener and graceful shutdown.
package listener

import (
    "context"
    "crypto/tls"
    "errors"
    "net"
    "net/http"
    "sync"
    "time"
)

var ErrInvalid=errors.New("gate listener: TLS or explicitly trusted reverse proxy is required")

type Config struct {
    Listen string
    TLSCertFile string
    TLSKeyFile string
    BehindTrustedProxy bool
}

type Module struct {
    Config Config
    Handler http.Handler
    mu sync.Mutex
    server *http.Server
    done chan error
    started bool
}

func New(cfg Config, handler http.Handler) (*Module,error) {
    if handler==nil || (cfg.TLSCertFile=="")!=(cfg.TLSKeyFile=="") ||
        (cfg.TLSCertFile=="" && !cfg.BehindTrustedProxy) {
        return nil,ErrInvalid
    }
    if cfg.Listen=="" {cfg.Listen=":8443"}
    return &Module{Config:cfg,Handler:handler},nil
}

func (m *Module) ID() string {return "listener"}

func (m *Module) Start(ctx context.Context) error {
    if m==nil || ctx==nil {return ErrInvalid}
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.started {return ErrInvalid}
    l,err:=net.Listen("tcp",m.Config.Listen)
    if err!=nil {return err}
    s:=&http.Server{
        Handler:m.Handler,
        ReadHeaderTimeout:5*time.Second,
        ReadTimeout:15*time.Second,
        WriteTimeout:20*time.Second,
        IdleTimeout:60*time.Second,
        MaxHeaderBytes:16<<10,
        TLSConfig:&tls.Config{MinVersion:tls.VersionTLS13},
    }
    m.server=s
    m.done=make(chan error,1)
    m.started=true
    go func(){
        var e error
        if m.Config.TLSCertFile!="" {
            e=s.ServeTLS(l,m.Config.TLSCertFile,m.Config.TLSKeyFile)
        } else {e=s.Serve(l)}
        if errors.Is(e,http.ErrServerClosed) {e=nil}
        m.done<-e
    }()
    return nil
}

func (m *Module) Stop(ctx context.Context) error {
    if m==nil{return nil}
    m.mu.Lock()
    s,done:=m.server,m.done
    m.server=nil
    m.done=nil
    m.mu.Unlock()
    if s==nil{return nil}
    if ctx==nil {ctx=context.Background()}
    e:=s.Shutdown(ctx)
    if e!=nil {_=s.Close()}
    if done!=nil {if serveErr:=<-done;serveErr!=nil {e=errors.Join(e,serveErr)}}
    return e
}

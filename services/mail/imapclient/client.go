// Package imapclient implements bounded, user-requested implicit-TLS checks.
// It deliberately exposes no mailbox or message mutation primitive.
package imapclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("mail: invalid IMAP policy")

type Endpoint struct {
	Host  string   `json:"host"`
	Port  int      `json:"port"`
	CIDRs []string `json:"cidrs"`
}
type Config struct {
	Endpoints []Endpoint     `json:"endpoints"`
	TimeoutMS int            `json:"timeout_ms"`
	RootCAs   *x509.CertPool `json:"-"`
}
type Settings struct {
	Host  string
	Port  int
	Login string
}
type Result struct {
	Status       string
	Capabilities []string
}
type Client struct {
	allow   map[string][]netip.Prefix
	timeout time.Duration
	roots   *x509.CertPool
}

func Host(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return "", ErrInvalid
		}
		return a.Unmap().String(), nil
	}
	if len(s) == 0 || len(s) > 253 {
		return "", ErrInvalid
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalid
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", ErrInvalid
			}
		}
	}
	return s, nil
}
func New(cfg Config) (*Client, error) {
	if len(cfg.Endpoints) > 128 {
		return nil, ErrInvalid
	}
	ms := cfg.TimeoutMS
	if ms == 0 {
		ms = 2000
	}
	if ms < 100 || ms > 3000 {
		return nil, ErrInvalid
	}
	if cfg.RootCAs != nil {
		cfg.RootCAs = cfg.RootCAs.Clone()
	}
	c := &Client{allow: map[string][]netip.Prefix{}, timeout: time.Duration(ms) * time.Millisecond, roots: cfg.RootCAs}
	for _, e := range cfg.Endpoints {
		host, err := Host(e.Host)
		if err != nil || e.Port < 1 || e.Port > 65535 || len(e.CIDRs) == 0 || len(e.CIDRs) > 32 {
			return nil, ErrInvalid
		}
		key := net.JoinHostPort(host, strconv.Itoa(e.Port))
		if _, ok := c.allow[key]; ok {
			return nil, ErrInvalid
		}
		for _, s := range e.CIDRs {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().Is4In6() {
				return nil, ErrInvalid
			}
			c.allow[key] = append(c.allow[key], p.Masked())
		}
	}
	return c, nil
}
func (c *Client) Check(ctx context.Context, s Settings, password []byte) Result {
	fail := func(status string) Result { return Result{Status: status, Capabilities: []string{}} }
	host, err := Host(s.Host)
	if err != nil || s.Port < 1 || s.Port > 65535 {
		return fail("destination_denied")
	}
	prefixes, ok := c.allow[net.JoinHostPort(host, strconv.Itoa(s.Port))]
	if !ok {
		return fail("destination_denied")
	}
	if len(password) == 0 || len(password) > 4096 || !utf8.Valid(password) || s.Login == "" || len(s.Login) > 1280 || !utf8.ValidString(s.Login) {
		return fail("authentication_failed")
	}
	for _, v := range []string{s.Login, string(password)} {
		for _, r := range v {
			if unicode.IsControl(r) {
				return fail("authentication_failed")
			}
		}
	}
	work, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(work, "ip", host)
	if err != nil || len(ips) == 0 || len(ips) > 32 {
		return fail("unavailable")
	}
	for _, ip := range ips {
		allowed := false
		for _, p := range prefixes {
			allowed = allowed || p.Contains(ip.Unmap())
		}
		if !allowed {
			return fail("destination_denied")
		}
	}
	// Validate all answers, then dial only those exact addresses. No second lookup
	// can redirect a credential-bearing connection after destination validation.
	var raw net.Conn
	for _, ip := range ips {
		raw, err = (&net.Dialer{}).DialContext(work, "tcp", net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(s.Port)))
		if err == nil {
			break
		}
	}
	if err != nil {
		return fail("unavailable")
	}
	defer raw.Close()
	stop := context.AfterFunc(work, func() { raw.Close() })
	defer stop()
	deadline, _ := work.Deadline()
	if raw.SetDeadline(deadline) != nil {
		return fail("unavailable")
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: c.roots, MinVersion: tls.VersionTLS12})
	if conn.HandshakeContext(work) != nil {
		return fail("tls_failed")
	}
	// LimitReader also bounds a malicious server that keeps sending unterminated
	// lines. Reader.ReadSlice avoids an unbounded allocation before that cap.
	p := &protocol{reader: bufio.NewReaderSize(io.LimitReader(conn, 64<<10), 4096), writer: conn}
	greeting, err := p.read()
	if err != nil || !strings.HasPrefix(strings.ToUpper(greeting), "* OK ") {
		return fail("protocol_error")
	}
	caps, err := p.capabilities("M1")
	if err != nil {
		return fail("protocol_error")
	}
	if !caps["IMAP4REV1"] && !caps["IMAP4REV2"] {
		return fail("protocol_error")
	}
	var accepted bool
	if caps["AUTH=PLAIN"] {
		plain := append([]byte{0}, []byte(s.Login)...)
		plain = append(plain, 0)
		plain = append(plain, password...)
		encoded := base64.StdEncoding.EncodeToString(plain)
		clear(plain)
		if caps["SASL-IR"] {
			if p.write("M2 AUTHENTICATE PLAIN "+encoded) != nil {
				return fail("unavailable")
			}
		} else {
			if p.write("M2 AUTHENTICATE PLAIN") != nil {
				return fail("unavailable")
			}
			challenge, e := p.read()
			if e != nil {
				return fail("protocol_error")
			}
			if strings.TrimSpace(challenge) != "+" {
				if strings.HasPrefix(strings.ToUpper(challenge), "M2 NO ") {
					return fail("authentication_failed")
				}
				return fail("protocol_error")
			}
			if p.write(encoded) != nil {
				return fail("unavailable")
			}
		}
		accepted, err = p.completion("M2", nil)
	} else {
		if caps["LOGINDISABLED"] {
			return fail("authentication_failed")
		}
		quote := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		if p.write("M2 LOGIN "+quote(s.Login)+" "+quote(string(password))) != nil {
			return fail("unavailable")
		}
		accepted, err = p.completion("M2", nil)
	}
	if err != nil {
		return fail("protocol_error")
	}
	if !accepted {
		return fail("authentication_failed")
	}
	caps, err = p.capabilities("M3")
	if err != nil {
		return fail("protocol_error")
	}
	if !caps["IMAP4REV1"] && !caps["IMAP4REV2"] {
		return fail("protocol_error")
	}
	result := Result{Status: "ok", Capabilities: []string{}}
	for _, name := range []string{"IMAP4REV1", "IMAP4REV2", "AUTH=PLAIN", "SASL-IR", "LOGINDISABLED", "IDLE", "CONDSTORE", "QRESYNC"} {
		if caps[name] {
			result.Capabilities = append(result.Capabilities, name)
		}
	}
	_ = p.write("M4 LOGOUT")
	return result
}

type protocol struct {
	reader *bufio.Reader
	writer io.Writer
	lines  int
}

func (p *protocol) read() (string, error) {
	p.lines++
	if p.lines > 128 {
		return "", ErrInvalid
	}
	raw, err := p.reader.ReadSlice('\n')
	if err != nil || len(raw) > 4096 || len(raw) < 2 || raw[len(raw)-2] != '\r' {
		return "", ErrInvalid
	}
	for _, b := range raw[:len(raw)-2] {
		if b < 32 && b != '\t' || b == 127 {
			return "", ErrInvalid
		}
	}
	return string(raw[:len(raw)-2]), nil
}
func (p *protocol) write(command string) error {
	_, err := io.WriteString(p.writer, command+"\r\n")
	return err
}
func (p *protocol) completion(tag string, caps map[string]bool) (bool, error) {
	for i := 0; i < 32; i++ {
		line, err := p.read()
		if err != nil {
			return false, err
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return false, ErrInvalid
		}
		if parts[0] == tag {
			switch strings.ToUpper(parts[1]) {
			case "OK":
				return true, nil
			case "NO":
				return false, nil
			default:
				return false, ErrInvalid
			}
		}
		if parts[0] != "*" || strings.EqualFold(parts[1], "BYE") {
			return false, ErrInvalid
		}
		if caps != nil && strings.EqualFold(parts[1], "CAPABILITY") {
			if len(parts) > 66 {
				return false, ErrInvalid
			}
			for _, v := range parts[2:] {
				if len(v) > 128 {
					return false, ErrInvalid
				}
				caps[strings.ToUpper(v)] = true
			}
		}
	}
	return false, ErrInvalid
}
func (p *protocol) capabilities(tag string) (map[string]bool, error) {
	if p.write(fmt.Sprintf("%s CAPABILITY", tag)) != nil {
		return nil, ErrInvalid
	}
	caps := map[string]bool{}
	ok, err := p.completion(tag, caps)
	if err != nil || !ok {
		return nil, ErrInvalid
	}
	return caps, nil
}

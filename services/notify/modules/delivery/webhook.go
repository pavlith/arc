package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var ErrWebhook = errors.New("notify: webhook unavailable")

type WebhookConfig struct {
	CAFile    string `json:"ca_file,omitempty"`
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	KeyFile   string `json:"key_file"`
	TimeoutMS int    `json:"timeout_ms"`
}

type Webhook struct {
	url    string
	key    []byte
	client *http.Client
}

func (c WebhookConfig) Open() (Provider, error) {
	if !c.Enabled {
		return DisabledProvider{}, nil
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || !filepath.IsAbs(c.KeyFile) {
		return nil, ErrWebhook
	}
	st, err := os.Lstat(c.KeyFile)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() < 32 || st.Size() > 4096 {
		return nil, ErrWebhook
	}
	key, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return nil, ErrWebhook
	}
	ms := c.TimeoutMS
	if ms == 0 {
		ms = 3000
	}
	if ms < 100 || ms > 5000 {
		return nil, ErrWebhook
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		b, e := os.ReadFile(c.CAFile)
		if e != nil {
			return nil, ErrWebhook
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, ErrWebhook
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &Webhook{url: c.URL, key: key, client: &http.Client{Transport: transport, Timeout: time.Duration(ms) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (*Webhook) Channel() string { return "webhook" }
func (p *Webhook) Send(ctx context.Context, recipient, key string) error {
	body, _ := json.Marshal(struct {
		Version   int    `json:"version"`
		Type      string `json:"type"`
		Recipient string `json:"recipient_user_id"`
		Key       string `json:"delivery_key"`
	}{1, "arc.inbox.changed", recipient, key})
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, p.key)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return ErrWebhook
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("X-Arc-Timestamp", timestamp)
	req.Header.Set("X-Arc-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := p.client.Do(req)
	if err != nil {
		return ErrWebhook
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrWebhook
	}
	return nil
}

type DisabledProvider struct{}

func (DisabledProvider) Channel() string                            { return "" }
func (DisabledProvider) Send(context.Context, string, string) error { return ErrWebhook }

// Channel preserves explicit fixture providers implementing the original interface.
func Channel(p Provider) string {
	if p == nil {
		return ""
	}
	if v, ok := p.(interface{ Channel() string }); ok {
		return v.Channel()
	}
	return "fake"
}

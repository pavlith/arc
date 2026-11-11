package delivery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/database"
	"github.com/pavlith/arc/services/notify/migrations"
	"gorm.io/gorm"
)

func deliveryDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, e := database.Open(context.Background(), filepath.Join(t.TempDir(), "notify.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { database.Close(db) })
	for range 2 {
		if e = database.Migrate(context.Background(), db, migrations.SQLite()); e != nil {
			t.Fatal(e)
		}
	}
	if e = db.Exec(`INSERT INTO notifications(id,recipient_user_id,event_id,kind) VALUES('n','u','e','task.created')`).Error; e != nil {
		t.Fatal(e)
	}
	return db
}
func intent(t *testing.T, db *gorm.DB, channel string) {
	t.Helper()
	if e := db.Exec(`INSERT INTO delivery_intents(notification_id,recipient_user_id,channel,dedup_key)VALUES('n','u',?,?)`, channel, DedupKey("n", "u", channel)).Error; e != nil {
		t.Fatal(e)
	}
}
func TestWebhookLocalTLSRetrySignatureAndDisabled(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	key := DedupKey("n", "u", "webhook")
	var calls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(r.Header.Get("X-Arc-Timestamp") + "."))
		m.Write(b)
		if r.Header.Get("X-Arc-Signature") != "v1="+hex.EncodeToString(m.Sum(nil)) || r.Header.Get("Idempotency-Key") != key {
			t.Error("invalid signature/key")
		}
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		if len(payload) != 4 || payload["type"] != "arc.inbox.changed" || payload["recipient_user_id"] != "u" || payload["delivery_key"] != key {
			t.Errorf("unexpected content: %s", b)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer receiver.Close()
	p := &Webhook{url: receiver.URL, key: secret, client: receiver.Client()}
	p.client.Timeout = time.Second
	db := deliveryDB(t)
	intent(t, db, "webhook")
	now := time.Now().UTC()
	s := &Service{GormDB: db, Now: func() time.Time { return now }}
	if _, e := s.Deliver(context.Background(), p); e == nil {
		t.Fatal("503 accepted")
	}
	if n, e := s.Deliver(context.Background(), p); e != nil || n != 0 || calls.Load() != 1 {
		t.Fatal("backoff ignored", n, e)
	}
	now = now.Add(time.Second)
	if n, e := s.Deliver(context.Background(), p); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if n, e := s.Deliver(context.Background(), p); e != nil || n != 0 || calls.Load() != 2 {
		t.Fatal("delivered again", n, e)
	}
	if n, e := s.Deliver(context.Background(), DisabledProvider{}); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	cfg := WebhookConfig{Enabled: true, URL: receiver.URL, KeyFile: filepath.Join(t.TempDir(), "secret")}
	os.WriteFile(cfg.KeyFile, secret, 0600)
	if _, e := cfg.Open(); e != nil {
		t.Fatal(e)
	}
	os.Chmod(cfg.KeyFile, 0644)
	if _, e := cfg.Open(); e == nil {
		t.Fatal("public secret accepted")
	}
	for _, u := range []string{"http://example.test", "https://user:password@example.test", "https://example.test/#fragment"} {
		cfg.URL = u
		if _, e := cfg.Open(); e == nil {
			t.Fatal("invalid URL accepted")
		}
	}
	if p, e := (WebhookConfig{}).Open(); e != nil || Channel(p) != "" {
		t.Fatal("default delivery enabled")
	}
}

type blockingProvider struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingProvider) Send(ctx context.Context, _, _ string) error {
	p.once.Do(func() { close(p.started) })
	select {
	case <-p.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestLeaseFencingNoWriterLockAcrossNetworkAndExhaustion(t *testing.T) {
	db := deliveryDB(t)
	intent(t, db, "fake")
	p := &blockingProvider{started: make(chan struct{}), release: make(chan struct{})}
	s := &Service{GormDB: db}
	done := make(chan int, 1)
	go func() { n, _ := s.Deliver(context.Background(), p); done <- n }()
	<-p.started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := db.WithContext(ctx).Exec(`UPDATE notifications SET revision=revision+1`).Error; e != nil {
		t.Fatal("network holds SQL transaction", e)
	}
	if n, e := s.Deliver(ctx, &FakeProvider{}); e != nil || n != 0 {
		t.Fatal("active lease claimed twice", n, e)
	}
	if e := db.Exec(`UPDATE delivery_intents SET lease_until=?`, time.Now().UTC().Add(-time.Minute)).Error; e != nil {
		t.Fatal(e)
	}
	if n, e := s.Deliver(ctx, &FakeProvider{}); e != nil || n != 1 {
		t.Fatal("expired lease not recovered", n, e)
	}
	close(p.release)
	if n := <-done; n != 0 {
		t.Fatal("stale completion overwrote newer claim")
	}
	db.Exec(`UPDATE delivery_intents SET delivered_at=NULL,attempts=9,next_attempt_at=NULL`)
	if _, e := s.Deliver(ctx, &FakeProvider{Fail: true}); e == nil {
		t.Fatal("failure not reported")
	}
	var failed bool
	db.Raw(`SELECT failed_at IS NOT NULL FROM delivery_intents`).Row().Scan(&failed)
	if !failed {
		t.Fatal("retry not exhausted")
	}
	if n, e := s.Deliver(ctx, &FakeProvider{}); e != nil || n != 0 {
		t.Fatal("exhausted retry sent", n, e)
	}
}
func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	r := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
	}))
	defer r.Close()
	c := r.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p := &Webhook{url: r.URL, key: []byte(strings.Repeat("s", 32)), client: c}
	if p.Send(context.Background(), "u", "k") == nil || leaked.Load() != 0 {
		t.Fatal("redirect accepted")
	}
}

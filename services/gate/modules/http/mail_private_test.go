package gate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
)

func approveMailBytes(t *testing.T, g *Gate) {
	t.Helper()
	artifact := v1.Artifact()
	compiled, err := contract.Compile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	op, err := compiled.Operation(v1.GetStructure.ID)
	if err != nil {
		t.Fatal(err)
	}
	snap := fabric.RouteSnapshot{Revision: 1, IssuedAt: time.Now(), Artifacts: map[string]contract.Artifact{compiled.Digest: artifact}, Routes: []fabric.Route{{Method: op.HTTP.Method, Path: op.HTTP.Path, Service: "mail", Operation: op.ID, Subject: op.Subject, Digest: compiled.Digest, APIMajor: 1, SuccessStatus: op.HTTP.SuccessStatus, Bindings: op.HTTP.Bindings}}}
	key := testKey(213)
	now := time.Now()
	jwks := security.PublicJWKS([]security.Key{{Kid: "mail-test", Public: key.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}}, now)
	signed, err := fabric.SignSnapshot(snap, "mail-test", key)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.routes.apply(signed, jwks); err != nil {
		t.Fatal(err)
	}
	g.available.Store(true)
}

type failedMailReader struct{}

func (failedMailReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestMailGateApprovalSelectorsAndTruncatedStream(t *testing.T) {
	calls := 0
	truncate := false
	backend := &filesBoundaryBackend{}
	g, err := New(Config{Backend: backend, PublicOrigin: "https://arc.test", PrivateMail: &PrivateMailConfig{URL: "https://mail.internal", Client: &http.Client{Transport: filesTransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Path != "/private/v1/mail/download" || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" || req.Header.Get("X-Arc-Invocation") == "" {
			t.Fatal("private boundary", req.URL)
		}
		var body io.Reader = strings.NewReader("mail bytes")
		if truncate {
			body = io.MultiReader(body, failedMailReader{})
		}
		h := make(http.Header)
		h.Set("Content-Type", "application/octet-stream")
		h.Set("X-Arc-Mail-Stream", "v1")
		return &http.Response{StatusCode: 200, Header: h, ContentLength: -1, Body: io.NopCloser(body)}, nil
	})}, Sign: func(_ context.Context, op, token string, payload json.RawMessage, idem string) ([]byte, error) {
		var q v1.DownloadRequest
		if json.Unmarshal(payload, &q) != nil || op != v1.PrivateDownload.ID || q.RootID != filesRoot || q.UID != 102 || q.Section != "2" || idem != "" {
			t.Fatal("unsigned selector", string(payload))
		}
		return []byte("signed-private-fixture"), nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(body string) *http.Request {
		r := httptest.NewRequest("POST", "https://arc.test/api/v1/mail/personal/accounts/"+filesRoot+"/messages/content", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer fixture")
		return r
	}
	body := `{"generation":1,"wire_name":"SU5CT1g","uid_validity":77,"uid":102,"section":"2"}`
	w := httptest.NewRecorder()
	g.ServeHTTP(w, request(body))
	if w.Code != 503 || calls != 0 {
		t.Fatal("unapproved private transport enabled", w.Code)
	}
	approveMailBytes(t, g)
	w = httptest.NewRecorder()
	g.ServeHTTP(w, request(body))
	if w.Code != 200 || w.Body.String() != "mail bytes" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, bad := range []string{strings.Replace(body, `"section":"2"`, `"section":"1] BAD"`, 1), strings.Replace(body, `"uid_validity":77,`, "", 1), strings.Replace(body, `"generation":1`, `"acl_root_id":"`+filesRoot+`","generation":1`, 1)} {
		w = httptest.NewRecorder()
		g.ServeHTTP(w, request(bad))
		if w.Code != 400 {
			t.Fatal("invalid selector accepted", w.Code, bad)
		}
	}
	truncate = true
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("truncation did not abort HTTP: %v", got)
		}
	}()
	g.ServeHTTP(httptest.NewRecorder(), request(body))
}
func TestMailPrivateProofBindsUIDAndSection(t *testing.T) {
	key := testKey(211)
	remote := &Remote{Client: identity.Client{PrivateKey: key, Kid: "gate-test"}}
	payload := json.RawMessage(`{"acl_root_id":"` + filesRoot + `","generation":1,"wire_name":"SU5CT1g","uid_validity":77,"uid":102,"section":"2"}`)
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"private-jti"}`)) + ".signature"
	raw, err := remote.SignPrivate(context.Background(), v1.PrivateDownload.ID, token, payload, "")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Proof security.Proof `json:"proof"`
	}
	if json.Unmarshal(raw, &env) != nil {
		t.Fatal("proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Proof.Signature)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		raw   []byte
		valid bool
	}{{raw, true}, {[]byte(strings.Replace(string(raw), `"uid":102`, `"uid":101`, 1)), false}, {[]byte(strings.Replace(string(raw), `"section":"2"`, `"section":"1"`, 1)), false}} {
		message, err := security.ProofMessage("rpc.mail.v1.personal.messages.download", tc.raw, "private-jti", env.Proof)
		if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), message, sig) != tc.valid {
			t.Fatal("proof did not bind private selectors", tc.valid, err)
		}
	}
}

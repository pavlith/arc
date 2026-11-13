package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
	mailv1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/imapclient"
)

type PrivateMailConfig struct {
	URL    string
	Client *http.Client
	Sign   func(context.Context, string, string, json.RawMessage, string) ([]byte, error)
}

func validatePrivateMail(cfg *PrivateMailConfig) error {
	if cfg == nil || cfg.Client == nil || cfg.Sign == nil {
		return errors.New("gate: missing private Mail TLS client")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("gate: private Mail requires exact HTTPS origin")
	}
	return nil
}

var mailBytesPath = regexp.MustCompile(`^/api/v1/mail/personal/accounts/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/messages/content$`)

func isMailBytePath(value string) bool {
	return strings.HasPrefix(value, "/api/v1/mail/personal/accounts/") && strings.HasSuffix(value, "/messages/content")
}
func (g *Gate) signedMailOp() (contract.Operation, *contract.Compiled, error) {
	table := g.routes.current.Load()
	if table == nil || !g.available.Load() {
		return contract.Operation{}, nil, errors.New("routes unavailable")
	}
	for _, entry := range table.entries {
		if entry.route.Service != "mail" || entry.route.Operation != mailv1.GetStructure.ID {
			continue
		}
		op, err := entry.compiled.Operation(mailv1.PrivateDownload.ID)
		if err == nil && op.Kind == "query" && !op.HTTP.Expose && op.Auth.Mode == "resource" && op.Auth.ResourceType == "mail.personal" && op.Auth.Action == "mail.read" && op.Auth.ResourceFrom == "payload.acl_root_id" && op.Auth.WorkspaceFrom == "" {
			return op, entry.compiled, nil
		}
	}
	return contract.Operation{}, nil, errors.New("private Mail not approved")
}
func (g *Gate) mailBytes(w http.ResponseWriter, r *http.Request, requestID string) {
	reject := func(code rpc.Code) { writeError(w, requestID, fault(code)) }
	if g.cfg.PrivateMail == nil {
		reject(rpc.CodeUnavailable)
		return
	}
	match := mailBytesPath.FindStringSubmatch(r.URL.Path)
	if match == nil || r.Method != "POST" {
		reject(rpc.CodeNotFound)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Header.Get("Range") != "" || r.Header.Get("Content-Encoding") != "" {
		reject(rpc.CodeValidation)
		return
	}
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		reject(rpc.CodeValidation)
		return
	}
	op, artifact, err := g.signedMailOp()
	if err != nil {
		reject(rpc.CodeUnavailable)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		reject(rpc.CodeValidation)
		return
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		reject(rpc.CodeValidation)
		return
	}
	if _, present := object["acl_root_id"]; present {
		reject(rpc.CodeValidation)
		return
	}
	object["acl_root_id"], _ = json.Marshal(match[1])
	payload, err := json.Marshal(object)
	if err != nil || artifact.Validate(op.RequestSchema, payload) != nil {
		reject(rpc.CodeValidation)
		return
	}
	auth, err := g.external(r, false)
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	if _, err = g.cfg.Backend.Authenticate(ctx, auth); err != nil {
		writeError(w, requestID, err)
		return
	}
	token, err := g.cfg.Backend.Exchange(ctx, identity.UserExchange{Session: auth.Session, AccessToken: auth.AccessToken, Target: identity.Target{Audience: "mail/v1", Operation: op.ID}})
	if err != nil {
		writeError(w, requestID, err)
		return
	}
	signed, err := g.cfg.PrivateMail.Sign(ctx, op.ID, token.Token, payload, "")
	if err != nil || len(signed) > 24576 {
		reject(rpc.CodeUnavailable)
		return
	}
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(g.cfg.PrivateMail.URL, "/")+"/private/v1/mail/download", http.NoBody)
	if err != nil {
		reject(rpc.CodeUnavailable)
		return
	}
	req.Header.Set("X-Arc-Invocation", base64.RawURLEncoding.EncodeToString(signed))
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := g.cfg.PrivateMail.Client.Do(req)
	if err != nil {
		reject(rpc.CodeUnavailable)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		reject(rpc.CodePermissionDenied)
		return
	}
	if resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("X-Arc-Mail-Stream") != "v1" || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength > imapclient.MaxDownloadSize {
		reject(rpc.CodeUnavailable)
		return
	}
	var q mailv1.DownloadRequest
	if json.Unmarshal(payload, &q) != nil {
		reject(rpc.CodeUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="message.eml"`)
	if q.Section != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="attachment.bin"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox; frame-ancestors 'none'")
	// Chunked HTTP must end successfully only after Mail's final authorization and
	// IMAP completion. Abort prevents a truncated/revoked stream looking complete.
	w.WriteHeader(200)
	count, err := io.CopyBuffer(w, io.LimitReader(resp.Body, imapclient.MaxDownloadSize+1), make([]byte, 64<<10))
	if err != nil || count > imapclient.MaxDownloadSize {
		panic(http.ErrAbortHandler)
	}
}

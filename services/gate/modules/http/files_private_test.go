package gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/fabric"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
)

const (
	filesWorkspace = "00000000-0000-4000-8000-000000000010"
	filesRoot = "00000000-0000-4000-8000-000000000011"
	filesUpload = "00000000-0000-4000-8000-000000000012"
	filesObject = "00000000-0000-4000-8000-000000000013"
)

type filesBoundaryBackend struct {
	closedBackend
	authenticated int
	exchanged int
	target identity.Target
	deny bool
}

func (b *filesBoundaryBackend) Authenticate(context.Context, identity.Authentication) (identity.Session,error) {
	b.authenticated++
	if b.deny {return identity.Session{},security.ErrDenied}
	return identity.Session{ID:"session-a",UserID:"alice",ExpiresAt:time.Now().Add(time.Hour)},nil
}
func (b *filesBoundaryBackend) Exchange(_ context.Context,q identity.UserExchange) (identity.TokenResult,error) {
	b.exchanged++
	b.target=q.Target
	return identity.TokenResult{Token:"signed-fixture"},nil
}
type filesTransportFunc func(*http.Request)(*http.Response,error)
func (f filesTransportFunc) RoundTrip(q *http.Request)(*http.Response,error) {return f(q)}

func signedFilesRoutes(t *testing.T,g *Gate) {
	t.Helper()
	artifact:=filesv1.Artifact()
	compiled,err:=contract.Compile(artifact)
	if err!=nil {t.Fatal(err)}
	snap:=fabric.RouteSnapshot{Revision:1,IssuedAt:time.Now(),
		Artifacts:map[string]contract.Artifact{compiled.Digest:artifact}}
	for _,op:=range compiled.Manifest.Operations {
		if op.ID!="files.uploads.get" && op.ID!="files.files.get" {continue}
		snap.Routes=append(snap.Routes,fabric.Route{
			Method:op.HTTP.Method,Path:op.HTTP.Path,Service:"files",
			Operation:op.ID,Subject:op.Subject,Digest:compiled.Digest,
			APIMajor:1,SuccessStatus:op.HTTP.SuccessStatus,Bindings:op.HTTP.Bindings,
		})
	}
	key:=testKey(214)
	now:=time.Now()
	jwks:=security.PublicJWKS([]security.Key{{
		Kid:"files-snapshot-test",Public:key.Public().(ed25519.PublicKey),
		NotBefore:now.Add(-time.Hour),ExpiresAt:now.Add(time.Hour),
	}},now)
	signed,err:=fabric.SignSnapshot(snap,"files-snapshot-test",key)
	if err!=nil {t.Fatal(err)}
	if err:=g.routes.apply(signed,jwks);err!=nil {t.Fatal(err)}
	g.available.Store(true)
}

func TestPrivateFilesGateSignedScopeAndBrowserBoundary(t *testing.T) {
	backend:=&filesBoundaryBackend{}
	var signedOperation string
	var sentPrivate int
	client:=&http.Client{Transport:filesTransportFunc(func(req *http.Request)(*http.Response,error){
		sentPrivate++
		if req.Header.Get("Authorization")!="" || req.Header.Get("Cookie")!="" ||
			req.Header.Get("X-Arc-Invocation")=="" {t.Fatal("untrusted browser credential forwarded")}
		raw,err:=base64.RawURLEncoding.DecodeString(req.Header.Get("X-Arc-Invocation"))
		if err!=nil || string(raw)!="signed-fixture" {t.Fatal("missing private proof")}
		if req.Method==http.MethodPatch {
			if req.URL.Path!="/private/v1/files/chunk" || req.ContentLength!=3 {
				t.Fatalf("unexpected private chunk: %s %d",req.URL.Path,req.ContentLength)
			}
			b,err:=io.ReadAll(req.Body)
			if err!=nil || string(b)!="abc" {t.Fatalf("chunk corrupted: %q %v",b,err)}
			out,_:=json.Marshal(filesv1.Upload{
				Scope:filesv1.Scope{WorkspaceID:filesWorkspace,RootID:filesRoot},
				ID:filesUpload,Filename:"x.bin",MIME:"application/octet-stream",
				ExpectedSize:3,Offset:3,ExpiresAt:time.Now().Add(time.Hour),State:"pending",
			})
			return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewReader(out)),
				Header:make(http.Header),Request:req},nil
		}
		if req.URL.Path!="/private/v1/files/download" {t.Fatalf("unexpected private path: %s",req.URL.Path)}
		h:=http.Header{}
		h.Set("Content-Type","application/octet-stream")
		h.Set("Content-Length","5")
		return &http.Response{StatusCode:200,Body:io.NopCloser(bytes.NewBufferString("hello")),
			Header:h,Request:req},nil
	})}
	g,err:=New(Config{
		Backend:backend,PublicOrigin:"https://arc.example.test",
		PrivateFiles:&PrivateFilesConfig{URL:"https://files.internal:9482",Client:client,
			Sign:func(_ context.Context,op,token string,payload json.RawMessage,idem string)([]byte,error){
				signedOperation=op
				if token!="signed-fixture" || len(payload)==0 {t.Fatalf("bad signing input: %s",op)}
				return []byte("signed-fixture"),nil
			}},
	})
	if err!=nil {t.Fatal(err)}
	url:="https://arc.example.test/api/v1/files/workspaces/"+filesWorkspace+"/roots/"+filesRoot
	uploadURL:=url+"/uploads/"+filesUpload+"/bytes"
	fileURL:=url+"/files/"+filesObject+"/content"
	request:=func(method,url string,body io.Reader)*http.Request{
		req:=httptest.NewRequest(method,url,body)
		req.TLS=&tls.ConnectionState{}
		req.Header.Set("Authorization","Bearer browser-token")
		return req
	}
	req:=request(http.MethodPatch,uploadURL,bytes.NewBufferString("abc"))
	req.Header.Set("Upload-Offset","0")
	req.Header.Set("Idempotency-Key","chunk-1")
	req.Header.Set("Content-Type","application/octet-stream")
	w:=httptest.NewRecorder()
	g.ServeHTTP(w,req)
	if w.Code!=503 || sentPrivate!=0 || backend.authenticated!=0 {
		t.Fatalf("unsigned Fabric route accepted: status=%d private=%d auth=%d",w.Code,sentPrivate,backend.authenticated)
	}
	signedFilesRoutes(t,g)
	req=request(http.MethodPatch,uploadURL,bytes.NewBufferString("abc"))
	req.Header.Set("Upload-Offset","0")
	req.Header.Set("Idempotency-Key","chunk-1")
	req.Header.Set("Content-Type","application/octet-stream")
	w=httptest.NewRecorder()
	g.ServeHTTP(w,req)
	if w.Code!=200 || signedOperation!=filesv1.PrivateChunk.ID ||
		backend.target.WorkspaceID!=filesWorkspace || backend.target.Operation!=filesv1.PrivateChunk.ID || sentPrivate!=1 {
		t.Fatalf("private signed upload failed: status=%d op=%s target=%+v count=%d body=%s",
			w.Code,signedOperation,backend.target,sentPrivate,w.Body.String())
	}
	req=request(http.MethodGet,fileURL,nil)
	w=httptest.NewRecorder()
	g.ServeHTTP(w,req)
	if w.Code!=200 || w.Body.String()!="hello" ||
		signedOperation!=filesv1.PrivateDownload.ID || sentPrivate!=2 {
		t.Fatalf("private signed download failed: status=%d body=%q count=%d",w.Code,w.Body.String(),sentPrivate)
	}
	req=request(http.MethodPatch,uploadURL,bytes.NewBufferString("abc"))
	req.Header.Set("Upload-Offset","0")
	req.Header.Set("Idempotency-Key","chunk-1")
	// Browser must declare the binary MIME type, never active content.
	w=httptest.NewRecorder()
	g.ServeHTTP(w,req)
	if w.Code!=400 || sentPrivate!=2 {t.Fatalf("invalid upload MIME accepted: %d",w.Code)}
	req=request(http.MethodPatch,uploadURL,bytes.NewBufferString("abc"))
	req.Header.Set("Upload-Offset","3")
	req.Header.Set("Content-Type","application/octet-stream")
	req.Header.Set("Idempotency-Key","chunk-2")
	backend.deny=true
	w=httptest.NewRecorder()
	g.ServeHTTP(w,req)
	if w.Code!=403 || sentPrivate!=2 {t.Fatalf("denied authentication crossed private boundary: %d",w.Code)}
	backend.deny=false
	g.available.Store(false)
	req=request(http.MethodGet,fileURL,nil)
	w=httptest.NewRecorder()
	g.ServeHTTP(w,req)
	if w.Code!=503 || sentPrivate!=2 {t.Fatalf("unavailable snapshot used: status=%d",w.Code)}
}

func TestFilesByteBrowserCORSPreflight(t *testing.T) {
	g,err:=New(Config{Backend:closedBackend{},PublicOrigin:"https://arc.example.test"})
	if err!=nil {t.Fatal(err)}
	r:=httptest.NewRequest(http.MethodOptions,"https://arc.example.test/api/v1/files/workspaces/x/roots/y/uploads/z/bytes",nil)
	r.TLS=&tls.ConnectionState{}
	r.Header.Set("Origin","https://arc.example.test")
	r.Header.Set("Access-Control-Request-Method","PATCH")
	r.Header.Set("Access-Control-Request-Headers","upload-offset,content-type,x-csrf-token,idempotency-key")
	w:=httptest.NewRecorder()
	g.ServeHTTP(w,r)
	if w.Code!=204 || w.Header().Get("Access-Control-Allow-Origin")!="https://arc.example.test" {
		t.Fatalf("upload preflight denied: %d %s",w.Code,w.Body.String())
	}
}

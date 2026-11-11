package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/storage"
)

type PrivateFilesConfig struct {
	URL string
	Client *http.Client
	Sign func(context.Context,string,string,json.RawMessage,string) ([]byte,error)
}

func validatePrivateFiles(cfg *PrivateFilesConfig) error {
	if cfg == nil || cfg.Client == nil || cfg.Sign == nil {
		return errors.New("gate: missing private Files TLS client")
	}
	u,err:=url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return errors.New("gate: private Files requires exact HTTPS origin")
	}
	return nil
}

var fileBytesPath = regexp.MustCompile(`^/api/v1/files/workspaces/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/roots/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/(uploads|files)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/(bytes|content)$`)

func isFilesBytePath(value string) bool {
	return strings.HasPrefix(value,"/api/v1/files/workspaces/") &&
		(strings.HasSuffix(value,"/bytes") || strings.HasSuffix(value,"/content"))
}

// signedFilesOp permits private bytes only when the currently approved,
// signed Fabric snapshot advertises the matching Files metadata operation and
// its exact hidden private contract operation within the SAME artifact.
func (g *Gate) signedFilesOp(opID string) (contract.Operation,*contract.Compiled,error) {
	table:=g.routes.current.Load()
	if table == nil || !g.available.Load() {return contract.Operation{},nil,errors.New("routes unavailable")}
	approved:="files.uploads.get"
	action:="files.create"
	if opID==filesv1.PrivateDownload.ID {
		approved="files.files.get"
		action="files.read"
	}
	for _,en:=range table.entries {
		if en.route.Service!="files" || en.route.Operation!=approved {continue}
		private,err:=en.compiled.Operation(opID)
		if err==nil && !private.HTTP.Expose && private.Auth.Mode=="resource" &&
			private.Auth.ResourceType=="files.workspace" &&
			private.Auth.Action==action &&
			private.Auth.ResourceFrom=="payload.acl_root_id" &&
			private.Auth.WorkspaceFrom=="payload.workspace_id" {
			return private,en.compiled,nil
		}
	}
	return contract.Operation{},nil,errors.New("private Files not approved")
}

func (g *Gate) filesBytes(w http.ResponseWriter,r *http.Request, requestID string) {
	if g.cfg.PrivateFiles==nil || r.URL.RawQuery!="" || r.URL.RawPath!="" ||
		path.Clean(r.URL.Path)!=r.URL.Path || strings.ContainsAny(r.URL.Path,"\\%") {
		writeError(w,requestID,fault(rpc.CodeUnavailable))
		return
	}
	match:=fileBytesPath.FindStringSubmatch(r.URL.Path)
	if match==nil {writeError(w,requestID,fault(rpc.CodeNotFound));return}
	chunk:=match[3]=="uploads" && match[5]=="bytes" && r.Method==http.MethodPatch
	download:=match[3]=="files" && match[5]=="content" && r.Method==http.MethodGet
	if !chunk && !download {writeError(w,requestID,fault(rpc.CodeNotFound));return}
	opID:=filesv1.PrivateChunk.ID
	privatePath:="/private/v1/files/chunk"
	var q any
	if chunk {
		offset,err:=strconv.ParseInt(r.Header.Get("Upload-Offset"),10,64)
		if err!=nil || offset<0 || offset>storage.MaxObjectSize ||
			r.ContentLength<1 || r.ContentLength>storage.MaxChunkSize ||
			r.ContentLength>storage.MaxObjectSize-offset || len(r.TransferEncoding)>0 {
			writeError(w,requestID,fault(rpc.CodeValidation))
			return
		}
		q=filesv1.PrivateChunkRequest{
			UploadRef:filesv1.UploadRef{
				Scope:filesv1.Scope{WorkspaceID:match[1],RootID:match[2]},
				UploadID:match[4]},
			Offset:offset,Length:r.ContentLength,
		}
	} else {
		opID=filesv1.PrivateDownload.ID
		privatePath="/private/v1/files/download"
		if len(r.TransferEncoding)>0 || r.ContentLength>0 ||
			r.Header.Get("Range")!="" {
			writeError(w,requestID,fault(rpc.CodeValidation))
			return
		}
		q=filesv1.FileRef{Scope:filesv1.Scope{WorkspaceID:match[1],RootID:match[2]},FileID:match[4]}
	}
	op,artifact,err:=g.signedFilesOp(opID)
	if err!=nil {writeError(w,requestID,fault(rpc.CodeUnavailable));return}
	payload,err:=json.Marshal(q)
	if err!=nil || artifact.Validate(op.RequestSchema,payload)!=nil {
		writeError(w,requestID,fault(rpc.CodeValidation))
		return
	}
	auth,err:=g.external(r,chunk)
	if err!=nil {writeError(w,requestID,err);return}
	ctx,cancel:=context.WithTimeout(r.Context(),55*time.Second)
	defer cancel()
	if _,err=g.cfg.Backend.Authenticate(ctx,auth);err!=nil {
		writeError(w,requestID,err);return
	}
	token,err:=g.cfg.Backend.Exchange(ctx,identity.UserExchange{
		Session:auth.Session,AccessToken:auth.AccessToken,
		Target:identity.Target{Audience:"files/v1",Operation:opID,WorkspaceID:match[1]},
	})
	if err!=nil {writeError(w,requestID,err);return}
	idem:=r.Header.Get("Idempotency-Key")
	if chunk && (idem==""||len(idem)>128) {
		writeError(w,requestID,fault(rpc.CodeValidation));return
	}
	signed,err:=g.cfg.PrivateFiles.Sign(ctx,opID,token.Token,payload,idem)
	if err!=nil {writeError(w,requestID,fault(rpc.CodeUnavailable));return}
	if len(signed)>24576 {writeError(w,requestID,fault(rpc.CodeValidation));return}
	body:=io.Reader(http.NoBody)
	method:=http.MethodGet
	if chunk {
		method=http.MethodPatch
		r.Body=http.MaxBytesReader(w,r.Body,storage.MaxChunkSize)
		body=r.Body
	}
	req,err:=http.NewRequestWithContext(ctx,method,
		strings.TrimSuffix(g.cfg.PrivateFiles.URL,"/")+privatePath,body)
	if err!=nil {writeError(w,requestID,fault(rpc.CodeUnavailable));return}
	req.Header.Set("X-Arc-Invocation",base64.RawURLEncoding.EncodeToString(signed))
	req.Header.Set("Accept","application/octet-stream")
	if chunk {
		req.ContentLength=r.ContentLength
		req.Header.Set("Content-Type","application/octet-stream")
	}
	resp,err:=g.cfg.PrivateFiles.Client.Do(req)
	if err!=nil {writeError(w,requestID,fault(rpc.CodeUnavailable));return}
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK {
		// File server errors are intentionally generic at the public boundary.
		writeError(w,requestID,fault(rpc.CodePermissionDenied))
		return
	}
	if chunk {
		limited,err:=io.ReadAll(io.LimitReader(resp.Body,32769))
		if err!=nil || len(limited)>32768 || artifact.Validate(op.ResponseSchema,limited)!=nil {
			writeError(w,requestID,fault(rpc.CodeUnavailable));return
		}
		writeJSON(w,200,json.RawMessage(limited))
		return
	}
	var size int64
	size,err=strconv.ParseInt(resp.Header.Get("Content-Length"),10,64)
	if err!=nil||size<0||size>storage.MaxObjectSize ||
		resp.Header.Get("Content-Type")!="application/octet-stream" {
		writeError(w,requestID,fault(rpc.CodeUnavailable))
		return
	}
	// Headers are generated by Files, never browser-controlled. A fixed
	// attachment name avoids reflecting untrusted filenames into HTTP.
	w.Header().Set("Content-Type","application/octet-stream")
	w.Header().Set("Content-Disposition",`attachment; filename="download.bin"`)
	w.Header().Set("Content-Length",strconv.FormatInt(size,10))
	w.Header().Set("X-Content-Type-Options","nosniff")
	if etag:=resp.Header.Get("ETag");regexp.MustCompile(`^"[0-9a-f]{64}"$`).MatchString(etag) {
		w.Header().Set("ETag",etag)
	}
	w.WriteHeader(http.StatusOK)
	_,_=io.CopyBuffer(w,resp.Body,make([]byte,64<<10))
}

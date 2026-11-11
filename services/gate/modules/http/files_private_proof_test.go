package gate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/pavlith/arc/sdk/security"
	"github.com/pavlith/arc/services/core/modules/identity"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
)

func TestFilesPrivateProofBindsScopeOffsetAndOperation(t *testing.T) {
	key := testKey(219)
	remote := &Remote{Client: identity.Client{PrivateKey:key, Kid:"fixture-key"}}
	request := filesv1.PrivateChunkRequest{
		UploadRef:filesv1.UploadRef{
			Scope:filesv1.Scope{WorkspaceID:filesWorkspace,RootID:filesRoot},
			UploadID:filesUpload,
		},
		Offset:0,Length:3,
	}
	payload,err:=json.Marshal(request)
	if err!=nil{t.Fatal(err)}
	token:="header."+base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"fixture-jti"}`))+".signature"
	raw,err:=remote.SignPrivate(context.Background(),filesv1.PrivateChunk.ID,token,payload,"chunk-key")
	if err!=nil{t.Fatal(err)}
	var envelope struct {
		Operation string `json:"operation"`
		Auth string `json:"auth"`
		Proof security.Proof `json:"proof"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(raw,&envelope)!=nil || envelope.Operation!=filesv1.PrivateChunk.ID ||
		envelope.Auth!=token {
		t.Fatal("signed invocation envelope corrupt")
	}
	message,err:=security.ProofMessage("rpc.files.v1.uploads.chunk",raw,"fixture-jti",envelope.Proof)
	if err!=nil{t.Fatal(err)}
	sig,err:=base64.RawURLEncoding.DecodeString(envelope.Proof.Signature)
	if err!=nil||!ed25519.Verify(key.Public().(ed25519.PublicKey),message,sig){
		t.Fatal("signature cannot be verified")
	}
	var value map[string]any
	if err:=json.Unmarshal(raw,&value);err!=nil{t.Fatal(err)}
	scope:=value["payload"].(map[string]any)
	scope["offset"]=float64(1)
	modified,err:=json.Marshal(value)
	if err!=nil{t.Fatal(err)}
	message,err=security.ProofMessage("rpc.files.v1.uploads.chunk",modified,"fixture-jti",envelope.Proof)
	if err!=nil{t.Fatal(err)}
	if ed25519.Verify(key.Public().(ed25519.PublicKey),message,sig){
		t.Fatal("altered upload offset retained valid proof")
	}
	if _,err:=remote.SignPrivate(context.Background(),"files.folders.list",token,payload,"chunk-key");err==nil{
		t.Fatal("unapproved operation signed as a private byte transport")
	}
}

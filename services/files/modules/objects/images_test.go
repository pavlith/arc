package objects

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/resource"
	"github.com/pavlith/arc/sdk/rpc"
	"github.com/pavlith/arc/sdk/security"
	v1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/models"
)

func TestRasterCompletionAndOwnedAvatar(t *testing.T) {
	s := quotaFixture(t, Quota{})
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.Signer.ServiceID = "files-provider"
	s.Signer.Kid = "files-key"
	s.Signer.PrivateKey = key
	const rootID = "20000000-0000-4000-8000-000000000001"
	if err := s.DB.Create(&models.Root{RootID: rootID, OwnerID: "alice", State: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	scope := v1.Scope{RootID: rootID}
	complete := func(name string, body []byte) (v1.File, error) {
		q := v1.UploadInitiateRequest{Scope: scope, Filename: name, MIME: "image/png", ExpectedSize: int64(len(body))}
		u, err := quotaCommand(t, s, "alice", "", v1.PersonalUploadInitiate.ID, name, q, s.initiate)
		if err != nil {
			return v1.File{}, err
		}
		if _, err := s.Storage.Append(context.Background(), u.ID, 0, int64(len(body)), bytes.NewReader(body)); err != nil {
			return v1.File{}, err
		}
		if err := s.DB.Model(&models.Upload{}).Where("id=?", u.ID).Update("offset", len(body)).Error; err != nil {
			return v1.File{}, err
		}
		return quotaCommand(t, s, "alice", "", v1.PersonalUploadComplete.ID, "complete-"+name, v1.UploadRef{Scope: scope, UploadID: u.ID}, s.complete)
	}
	file, err := complete("valid.png", encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{[]byte("<svg onload='evil()'/>"), []byte("not a PNG")} {
		if _, err := complete(string(body[:3])+".png", body); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatalf("active/corrupt image accepted: %v", err)
		}
	}
	var huge bytes.Buffer
	png.Encode(&huge, image.NewRGBA(image.Rect(0, 0, 1025, 1)))
	if _, err := complete("huge.png", huge.Bytes()); rpc.ErrorCode(err) != rpc.CodeValidation {
		t.Fatalf("dimension bound: %v", err)
	}
	ref := v1.FileRef{Scope: scope, FileID: file.ID}
	call := func(user string) (v1.AvatarResult, error) {
		auth := rpc.RemoteInvocationAuthorizer(func(context.Context, string, []byte) (security.Claims, error) {
			return security.Claims{Subject: "user:" + user, SessionID: "session-a", Operation: v1.AvatarPrepare.ID}, nil
		})
		raw, _ := json.Marshal(map[string]any{"operation": v1.AvatarPrepare.ID, "proof": security.Proof{}, "auth": "fixture", "payload": ref})
		ctx, err := auth(context.Background(), "fixture", raw)
		if err != nil {
			t.Fatal(err)
		}
		return s.prepareAvatar(ctx, ref)
	}
	result, err := call("alice")
	if err != nil {
		t.Fatal(err)
	}
	env, err := resource.ParseAvatar(result.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := resource.VerifyAvatar(pub, env, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := call("bob"); err == nil {
		t.Fatal("grantee prepared another owner's avatar")
	}
}

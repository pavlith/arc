package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	uploadID = "00000000-0000-4000-8000-000000000001"
	objectID = "00000000-0000-4000-8000-000000000002"
	otherID = "00000000-0000-4000-8000-000000000003"
)

func TestLocalLifecycleAndIntegrity(t *testing.T) {
	ctx := context.Background()
	s, err := OpenLocal(filepath.Join(t.TempDir(), "private"))
	if err != nil { t.Fatal(err) }
	defer s.Close()
	if err := s.Prepare(ctx, uploadID); err != nil { t.Fatal(err) }
	if err := s.Prepare(ctx, uploadID); !errors.Is(err,ErrConflict) { t.Fatalf("duplicate prepare: %v",err) }
	if next,err := s.Append(ctx,uploadID,0,3,strings.NewReader("abc")); err != nil || next != 3 {
		t.Fatalf("first chunk %d %v",next,err)
	}
	if next,err := s.Append(ctx,uploadID,0,3,strings.NewReader("abc")); !errors.Is(err,ErrConflict) || next != 3 {
		t.Fatalf("wrong offset replay: %d %v",next,err)
	}
	if next,err := s.Append(ctx,uploadID,3,4,strings.NewReader("def")); !errors.Is(err,io.ErrUnexpectedEOF) || next != 3 {
		t.Fatalf("short body rollback: %d %v",next,err)
	}
	if next,err := s.Append(ctx,uploadID,3,1,strings.NewReader("xy")); !errors.Is(err,ErrInvalid) || next != 3 {
		t.Fatalf("extra body rollback: %d %v",next,err)
	}
	if next,err := s.Append(ctx,uploadID,3,3,strings.NewReader("def")); err != nil || next != 6 {
		t.Fatalf("final chunk: %d %v",next,err)
	}
	if offset,err := s.Offset(ctx,uploadID); err != nil || offset != 6 {
		t.Fatalf("offset: %d %v",offset,err)
	}
	if _,err := s.Promote(ctx,uploadID,objectID,7,""); !errors.Is(err,ErrConflict) {
		t.Fatalf("length mismatch: %v",err)
	}
	if _,err := s.Promote(ctx,uploadID,objectID,6,strings.Repeat("0",64)); !errors.Is(err,ErrConflict) {
		t.Fatalf("hash mismatch: %v",err)
	}
	sum := sha256.Sum256([]byte("abcdef"))
	digest := hex.EncodeToString(sum[:])
	object,err := s.Promote(ctx,uploadID,objectID,6,digest)
	if err != nil || object.Size != 6 || object.SHA256 != digest { t.Fatalf("promotion: %+v %v",object,err) }
	f,err := s.Open(ctx,objectID)
	if err != nil { t.Fatal(err) }
	body,err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || !bytes.Equal(body,[]byte("abcdef")) { t.Fatalf("read: %s %v",body,err) }
	if _,err := s.Offset(ctx,uploadID); !errors.Is(err,ErrMissing) { t.Fatalf("promoted temp present: %v",err) }
	if err := s.Prepare(ctx,otherID); err != nil { t.Fatal(err) }
	if _,err := s.Append(ctx,otherID,0,3,strings.NewReader("XYZ")); err != nil { t.Fatal(err) }
	if _,err := s.Promote(ctx,otherID,objectID,3,""); !errors.Is(err,ErrConflict) {
		t.Fatalf("existing object overwritten: %v",err)
	}
	if err := s.Abort(ctx,otherID); err != nil { t.Fatal(err) }
	if err := s.Abort(ctx,otherID); err != nil { t.Fatalf("abort replay: %v",err) }
	if _,err := s.Open(ctx,objectID); err != nil { t.Fatalf("abort deleted ready file: %v",err) }
}

func TestLocalRejectsKeysAndUnsafeStorage(t *testing.T) {
	ctx := context.Background()
	s,err := OpenLocal(filepath.Join(t.TempDir(),"private"))
	if err != nil { t.Fatal(err) }
	defer s.Close()
	for _, key := range []string{"../outside","/tmp/evil","ABCDEF","a/b",strings.Repeat("x",64),""} {
		if err := s.Prepare(ctx,key); !errors.Is(err,ErrInvalid) { t.Fatalf("accepted %q: %v",key,err) }
		if _,err := s.Open(ctx,key); !errors.Is(err,ErrInvalid) { t.Fatalf("open accepted %q: %v",key,err) }
	}
	if _,err := s.Append(ctx,uploadID,0,MaxChunkSize+1,strings.NewReader("x")); !errors.Is(err,ErrInvalid) {
		t.Fatalf("oversized chunk: %v",err)
	}
	if _,err := s.Append(ctx,uploadID,MaxObjectSize,1,strings.NewReader("x")); !errors.Is(err,ErrInvalid) {
		t.Fatalf("object overflow: %v",err)
	}
	stopped,cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Prepare(stopped,uploadID); !errors.Is(err,context.Canceled) { t.Fatalf("cancel: %v",err) }
	p := filepath.Join(t.TempDir(),"shared")
	if err := os.Mkdir(p,0755); err != nil { t.Fatal(err) }
	if _,err := OpenLocal(p); !errors.Is(err,ErrInvalid) { t.Fatalf("shared directory accepted: %v",err) }
	parent := t.TempDir()
	link := filepath.Join(parent,"alias")
	if err := os.Symlink(p,link); err != nil { t.Fatal(err) }
	if _,err := OpenLocal(link); !errors.Is(err,ErrInvalid) { t.Fatalf("symlink root accepted: %v",err) }
}

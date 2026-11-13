package mail

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/rpc"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/imapclient"
)

func TestUnifiedSourceValidationAndCursorFences(t *testing.T) {
	a := v1.UnifiedSource{RootID: root, Generation: 1, WireName: "SU5CT1g"}
	b := v1.UnifiedSource{RootID: owner, Generation: 1, WireName: "SU5CT1g"}
	forward, roots, err := normalizedSources([]v1.UnifiedSource{a, b})
	if err != nil || len(roots) != 2 {
		t.Fatal(err)
	}
	reverse, _, err := normalizedSources([]v1.UnifiedSource{b, a})
	if err != nil || forward[0] != reverse[0] || forward[1] != reverse[1] {
		t.Fatal("source order changed selection")
	}
	changedGeneration := a
	changedGeneration.Generation = 2
	changedGeneration.WireName = base64.RawURLEncoding.EncodeToString([]byte("Archive"))
	injected := a
	injected.WireName = base64.RawURLEncoding.EncodeToString([]byte("INBOX\r\nBAD"))
	for _, bad := range [][]v1.UnifiedSource{nil, {a, a}, {a, changedGeneration}, {injected}, make([]v1.UnifiedSource, 21)} {
		if _, _, err := normalizedSources(bad); err == nil {
			t.Fatal("invalid source set accepted", bad)
		}
	}
	states := []v1.UnifiedSourceState{{UnifiedSource: a, Indexed: true, FolderID: owner, UIDValidity: 77}}
	date := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	message := v1.CachedGet{CachedMessage: v1.CachedMessage{ID: owner, Message: imapclient.Message{InternalDate: date}}}
	digest := sourceDigest(states)
	value := makeUnifiedCursor(digest, message)
	cursor, err := parseUnifiedCursor(value, digest)
	if err != nil || cursor.ID != owner || cursor.InternalUnix != date.UnixMicro() {
		t.Fatal(cursor, err)
	}
	states[0].UIDValidity = 78
	if _, err := parseUnifiedCursor(value, sourceDigest(states)); rpc.ErrorCode(err) != rpc.CodeConflict {
		t.Fatal("cursor crossed observed namespace", err)
	}
	for _, bad := range []string{"!", base64.RawURLEncoding.EncodeToString([]byte(`{"version":2,"sources":"x","id":"` + owner + `"}`)), base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"id":"` + owner + `","extra":true}`))} {
		if _, err := parseUnifiedCursor(bad, digest); rpc.ErrorCode(err) != rpc.CodeValidation {
			t.Fatal("malformed cursor accepted", err)
		}
	}
	if _, err := (&Module{}).listUnified(context.Background(), v1.UnifiedQuery{}); rpc.ErrorCode(err) != rpc.CodePermissionDenied {
		t.Fatal("unverified unified read accepted", err)
	}
}

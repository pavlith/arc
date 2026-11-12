package fabric

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
)

// strictSnapshotJSON is only for bounded, expanded route snapshots. Ordinary
// manifests, artifacts and RPC envelopes retain contract.Strict's 256 KiB cap.
func strictSnapshotJSON(raw []byte, value any) error {
	if len(raw) > maxExpandedSnapshot {
		return contract.ErrInvalid
	}
	if _, err := security.CanonicalJSON(raw); err != nil {
		return contract.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return contract.ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return contract.ErrInvalid
	}
	return nil
}

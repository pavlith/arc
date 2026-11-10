// Package testlog captures structured diagnostics without racing background RPCs.
package testlog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
)

type Recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Capture installs a JSON logger for a nonparallel test and restores it at cleanup.
func Capture(t *testing.T) *Recorder {
	t.Helper()
	r := &Recorder{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(r, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return r
}

func (r *Recorder) Write(raw []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(raw)
}

func (r *Recorder) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

func (r *Recorder) Entries() []map[string]any { return Parse(r.Bytes()) }

// Parse ignores library text and incomplete trailing lines in live process logs.
func Parse(raw []byte) []map[string]any {
	var entries []map[string]any
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		var entry map[string]any
		if json.Unmarshal(line, &entry) == nil && entry != nil {
			entries = append(entries, entry)
		}
	}
	return entries
}

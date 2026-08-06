package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type RecordedEvent struct {
	Ts    string `json:"ts"`
	Event Event  `json:"event"`
}

type FileTelemetry struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

func NewFileTelemetry(path string) (*FileTelemetry, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("telemetry: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("telemetry: open %s: %w", path, err)
	}
	return &FileTelemetry{f: f, now: time.Now}, nil
}

func (t *FileTelemetry) Record(_ context.Context, e Event) error {
	rec := RecordedEvent{Ts: t.clock().UTC().Format(time.RFC3339Nano), Event: e}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("telemetry: marshal: %w", err)
	}
	line = append(line, '\n')

	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.f.Write(line); err != nil {
		return fmt.Errorf("telemetry: write: %w", err)
	}
	// fsync per record: the signal must survive a crash
	if err := t.f.Sync(); err != nil {
		return fmt.Errorf("telemetry: sync: %w", err)
	}
	return nil
}

func (t *FileTelemetry) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *FileTelemetry) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	err := t.f.Close()
	t.f = nil
	return err
}

func ReadTelemetry(path string) ([]RecordedEvent, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []RecordedEvent
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec RecordedEvent
		if json.Unmarshal(line, &rec) != nil {
			continue // tolerate a torn final line
		}
		out = append(out, rec)
	}
	return out, nil
}

var _ TelemetrySink = (*FileTelemetry)(nil)

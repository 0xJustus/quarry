package channels

import (
	"context"
	"sync"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type OutboxItem struct {
	Hash          string
	BehavioralKey string
	Placement     string
	Wire          []byte
}

type Outbox interface {
	Enqueue(ctx context.Context, item OutboxItem) error
}

// carries every placement; the sync worker applies tier policy
type LocalOutboxSink struct{ Out Outbox }

func (s LocalOutboxSink) MaxPlacement() artifact.Placement { return artifact.Private }

func (s LocalOutboxSink) Emit(ctx context.Context, e *artifact.Envelope) error {
	wire, err := e.Marshal()
	if err != nil {
		return err
	}
	return s.Out.Enqueue(ctx, OutboxItem{
		Hash:          e.Artifact.ID,
		BehavioralKey: e.Artifact.BehavioralKey(),
		Placement:     string(e.Placement),
		Wire:          wire,
	})
}

type MemorySink struct {
	Cap     artifact.Placement
	mu      sync.Mutex
	Emitted []*artifact.Envelope
}

func NewMemorySink(cap artifact.Placement) *MemorySink { return &MemorySink{Cap: cap} }

func (m *MemorySink) MaxPlacement() artifact.Placement { return m.Cap }

func (m *MemorySink) Emit(_ context.Context, e *artifact.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Emitted = append(m.Emitted, e)
	return nil
}

type MemoryTelemetry struct {
	mu     sync.Mutex
	Events []Event
}

func (t *MemoryTelemetry) Record(_ context.Context, e Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Events = append(t.Events, e)
	return nil
}

type NoopUpdateFeed struct{}

func (NoopUpdateFeed) Pull(context.Context, string) (Update, bool, error) {
	return Update{}, false, nil
}

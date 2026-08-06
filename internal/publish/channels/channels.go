// Package channels defines the outbound artifact seams and the emit gate.
package channels

import (
	"context"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type ArtifactSink interface {
	Emit(ctx context.Context, e *artifact.Envelope) error
	MaxPlacement() artifact.Placement
}

// PriorArt is a candidate match, never authority: the caller re-grounds it.
type PriorArt struct {
	ArtifactID string
	Source     string // "local" | "commons"
	BugClass   string
	Abstract   string
	Sites      []string // crash-stack function symbols
}

type PatternSource interface {
	Lookup(ctx context.Context, keys []string) ([]PriorArt, error)
}

// Event carries de-identified values only; nothing here may re-identify.
type Event struct {
	Kind   string
	RunID  string
	Fields map[string]string
}

type TelemetrySink interface {
	Record(ctx context.Context, e Event) error
}

type Update struct {
	Version  string
	Catalog  []byte
	Corpora  []byte
	ModelRef string
}

type UpdateFeed interface {
	Pull(ctx context.Context, sinceVersion string) (Update, bool, error)
}

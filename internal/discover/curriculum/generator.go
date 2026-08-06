package curriculum

import (
	"context"
	"errors"
)

var ErrGeneratorUnconfigured = errors.New("curriculum: generator not configured")

type GenSpec struct {
	Seed     *Target // nil ⇒ generate from scratch
	BugClass string
	Count    int
}

// a real generator MUST verify each target holds a reachable bug before yielding it
type Generator interface {
	Generate(ctx context.Context, spec GenSpec) ([]Target, error)
}

// the honest default: never fabricates a target
type UnconfiguredGenerator struct{}

func (UnconfiguredGenerator) Generate(context.Context, GenSpec) ([]Target, error) {
	return nil, ErrGeneratorUnconfigured
}

type GeneratedSource struct {
	inner *SliceSource
}

func NewGeneratedSource(ctx context.Context, g Generator, spec GenSpec) (*GeneratedSource, error) {
	targets, err := g.Generate(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &GeneratedSource{inner: NewSliceSource(targets)}, nil
}

func (s *GeneratedSource) Next(ctx context.Context) (*Target, error) { return s.inner.Next(ctx) }

var _ Generator = UnconfiguredGenerator{}

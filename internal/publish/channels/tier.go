package channels

import (
	"context"
	"fmt"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

// admission control only: it narrows what may be placed, never soundness.
type PlacementPolicy interface {
	Admit(ctx context.Context, e *artifact.Envelope, cap artifact.Placement) error
}

type AllowAllPolicy struct{}

func (AllowAllPolicy) Admit(context.Context, *artifact.Envelope, artifact.Placement) error {
	return nil
}

type TrustedTierPolicy struct {
	Held       string // the grant this emitter presents
	Authorized map[string]bool
}

func NewTrustedTierPolicy(held string, authorized ...string) TrustedTierPolicy {
	m := make(map[string]bool, len(authorized))
	for _, a := range authorized {
		m[a] = true
	}
	return TrustedTierPolicy{Held: held, Authorized: m}
}

func (p TrustedTierPolicy) Admit(_ context.Context, e *artifact.Envelope, _ artifact.Placement) error {
	if e.Placement != artifact.Trusted {
		return nil
	}
	if p.Held == "" || !p.Authorized[p.Held] {
		return fmt.Errorf("trusted-tier policy: grant %q is not authorized to place at the trusted tier", p.Held)
	}
	return nil
}

func NewTrustedSink() *MemorySink { return NewMemorySink(artifact.Trusted) }

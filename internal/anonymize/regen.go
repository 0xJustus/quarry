package anonymize

import (
	"bytes"
	"context"
)

type NormalizedTarget struct {
	Specimen []byte
	Verifier Verifier
}

type RegenResult struct {
	PoV         []byte
	Reproduces  bool
	Regenerated bool
	Notes       string
}

// reports reproduction only; never asserts the bug is real
type PoVRegenerator interface {
	Regenerate(ctx context.Context, target NormalizedTarget, oldPoV []byte) (RegenResult, error)
}

type ReproFunc func(ctx context.Context, target NormalizedTarget, pov []byte) (bool, error)

type MinimizeFunc func(ctx context.Context, target NormalizedTarget, pov []byte) ([]byte, error)

type DefaultRegenerator struct {
	Repro    ReproFunc // absent: no reproduction claim may be made
	Minimize MinimizeFunc
}

func (d *DefaultRegenerator) Regenerate(ctx context.Context, target NormalizedTarget, oldPoV []byte) (RegenResult, error) {
	pov := append([]byte(nil), oldPoV...)

	if d.Repro == nil {
		return RegenResult{PoV: pov, Reproduces: false, Notes: "no repro predicate wired; cannot re-verify PoV against normalized target"}, nil
	}

	ok, err := d.Repro(ctx, target, pov)
	if err != nil {
		return RegenResult{PoV: pov}, err
	}
	if !ok {
		return RegenResult{PoV: pov, Reproduces: false, Notes: "old PoV no longer reproduces after normalization; hold for human"}, nil
	}

	if d.Minimize == nil {
		return RegenResult{PoV: pov, Reproduces: true}, nil
	}

	min, err := d.Minimize(ctx, target, pov)
	if err != nil {
		// minimize is a nicety, not a correctness gate: never fail the pipeline on it
		return RegenResult{PoV: pov, Reproduces: true, Notes: "re-minimize failed; kept unminimized reproducing PoV: " + err.Error()}, nil
	}
	// re-check: a minimizer that drifted off the bug is worse than no minimizer
	ok, err = d.Repro(ctx, target, min)
	if err != nil {
		return RegenResult{PoV: pov, Reproduces: true, Notes: "re-check of minimized PoV errored; kept unminimized: " + err.Error()}, nil
	}
	if !ok {
		return RegenResult{PoV: pov, Reproduces: true, Notes: "minimized PoV did not reproduce; kept unminimized"}, nil
	}
	return RegenResult{PoV: min, Reproduces: true, Regenerated: !bytes.Equal(min, oldPoV)}, nil
}

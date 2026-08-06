package channels

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"reflect"

	"github.com/0xjustus/quarry/internal/publish/artifact"
)

type ReIDResult struct {
	Score   float64
	Cleared bool
	Notes   string
}

type ReIDBattery interface {
	Score(ctx context.Context, e *artifact.Envelope, minForTier float64) ReIDResult
}

// Anonymizer normalizes an envelope without changing its behavior.
type Anonymizer interface {
	Anonymize(ctx context.Context, e *artifact.Envelope) (*artifact.Envelope, error)
}

func placementRank(p artifact.Placement) int {
	switch p {
	case artifact.Public:
		return 0
	case artifact.Trusted:
		return 1
	case artifact.Private:
		return 2
	}
	return 99 // unknown: maximally restricted
}

func minReIDForPlacement(p artifact.Placement) float64 {
	switch p {
	case artifact.Public:
		return 0.9
	case artifact.Trusted:
		return 0.5
	default:
		return 0.0
	}
}

type Gate struct {
	Anon    Anonymizer
	Battery ReIDBattery
	Signer  ed25519.PrivateKey
	Policy  PlacementPolicy // nil: no extra restriction
}

func NewGate(anon Anonymizer, battery ReIDBattery) *Gate {
	if anon == nil {
		anon = NewRealAnonymizer()
	}
	if battery == nil {
		battery = NewLeakScanBattery()
	}
	return &Gate{Anon: anon, Battery: battery}
}

func (g *Gate) WithSigner(priv ed25519.PrivateKey) *Gate { g.Signer = priv; return g }

func (g *Gate) WithPolicy(p PlacementPolicy) *Gate { g.Policy = p; return g }

func (g *Gate) Emit(ctx context.Context, sink ArtifactSink, e *artifact.Envelope) (*artifact.Envelope, error) {
	if e == nil {
		return nil, fmt.Errorf("emit gate: nil envelope")
	}
	cap := sink.MaxPlacement()
	if !cap.Valid() {
		return nil, fmt.Errorf("emit gate: sink capacity %q is not a valid placement; refusing to emit", cap)
	}

	out, err := g.Anon.Anonymize(ctx, e)
	if err != nil {
		return nil, fmt.Errorf("emit gate: anonymize: %w", err)
	}
	if err := out.Artifact.ComputeID(); err != nil {
		return nil, fmt.Errorf("emit gate: compute id: %w", err)
	}
	if !out.Placement.Valid() {
		return nil, fmt.Errorf("emit gate: placement %q is not a valid tier", out.Placement)
	}

	if placementRank(out.Placement) > placementRank(cap) {
		return nil, fmt.Errorf("emit gate: placement %q exceeds sink capacity %q", out.Placement, cap)
	}

	if g.Policy != nil {
		if err := g.Policy.Admit(ctx, out, cap); err != nil {
			return nil, fmt.Errorf("emit gate: placement policy: %w", err)
		}
	}

	// never ship an attestation that does not cover the emitted bytes
	switch {
	case out.Signature != nil && signedFieldsChanged(e, out):
		if g.Signer == nil {
			return nil, fmt.Errorf("emit gate: anonymization rewrote signed fields, voiding the inherited signature, and no signer is configured; refusing to emit")
		}
		out.Signature = nil
		if err := out.Sign(g.Signer); err != nil {
			return nil, fmt.Errorf("emit gate: re-sign after anonymize: %w", err)
		}
	case !out.Artifact.SelfReproducing() && out.Signature == nil && g.Signer != nil:
		if err := out.Sign(g.Signer); err != nil {
			return nil, fmt.Errorf("emit gate: sign: %w", err)
		}
	}

	res := g.Battery.Score(ctx, out, minReIDForPlacement(out.Placement))
	if !res.Cleared {
		return nil, fmt.Errorf("emit gate: re-id clearance failed for %q (score %.2f): %s", out.Placement, res.Score, res.Notes)
	}

	// anti-poisoning: never emit what we cannot verify ourselves
	if err := out.Verify(); err != nil {
		return nil, fmt.Errorf("emit gate: self-verify: %w", err)
	}

	if err := sink.Emit(ctx, out); err != nil {
		return nil, fmt.Errorf("emit gate: sink: %w", err)
	}
	return out, nil
}

// keep in step with Envelope.sigPreimage
func signedFieldsChanged(in, out *artifact.Envelope) bool {
	return in.Artifact.ID != out.Artifact.ID ||
		in.Placement != out.Placement ||
		in.Abstract != out.Abstract ||
		!reflect.DeepEqual(in.Provenance, out.Provenance)
}

type StubBattery struct{}

func (StubBattery) Score(_ context.Context, e *artifact.Envelope, minForTier float64) ReIDResult {
	if minForTier <= 0 {
		return ReIDResult{Score: 1, Cleared: true, Notes: "local tier: no clearance required"}
	}
	if e.Artifact.Content.Specimen == nil && e.Artifact.Reproducer == nil {
		return ReIDResult{Score: 1, Cleared: true, Notes: "abstract artifact: no runnable material"}
	}
	return ReIDResult{Score: 0, Cleared: false, Notes: "M1 stub battery refuses specimen/reproducer-bearing artifacts above local tier"}
}

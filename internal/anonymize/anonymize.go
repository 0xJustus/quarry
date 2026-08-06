// Package anonymize: redact → normalize → PoV-regen for emitted specimens.
package anonymize

import "context"

type Result struct {
	Specimen []byte
	// non-empty: a human must clear the artifact before public placement
	Leaks       []LoadBearingLeak
	Normalized  bool
	Regenerated bool
	PoV         []byte
	Notes       []string
}

// any field may be nil: a nil stage is skipped, never corrupts the specimen
type Pipeline struct {
	Redactor    *TaintRedactor
	Normalizer  Normalizer
	Verifier    Verifier
	Regenerator PoVRegenerator
}

func (p *Pipeline) Run(ctx context.Context, specimen, oldPoV []byte, keep KeepSet) (Result, error) {
	res := Result{Specimen: append([]byte(nil), specimen...), PoV: append([]byte(nil), oldPoV...)}

	if p.Redactor != nil {
		red, leaks := p.Redactor.Redact(string(res.Specimen), keep)
		res.Specimen = []byte(red)
		res.Leaks = leaks
	}

	if p.Normalizer != nil {
		nr, err := NormalizeAndVerify(p.Normalizer, p.Verifier, res.Specimen)
		if err != nil {
			return res, err
		}
		if nr.Verified {
			res.Specimen = nr.Normalized
			res.Normalized = nr.Changed
		} else {
			res.Notes = append(res.Notes, "normalization discarded: normalized specimen failed re-verify")
		}
	}

	if p.Regenerator != nil {
		rr, err := p.Regenerator.Regenerate(ctx, NormalizedTarget{Specimen: res.Specimen, Verifier: p.Verifier}, res.PoV)
		if err != nil {
			return res, err
		}
		res.PoV = rr.PoV
		res.Regenerated = rr.Regenerated
		if !rr.Reproduces {
			res.Notes = append(res.Notes, "regeneration: PoV does not reproduce against normalized target")
		}
		if rr.Notes != "" {
			res.Notes = append(res.Notes, rr.Notes)
		}
	}

	return res, nil
}

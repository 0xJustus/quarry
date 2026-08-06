// Package minimize is the oracle-driven byte-level PoV reducer: deletion ddmin, deterministic, key-preserving.
package minimize

import (
	"context"

	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
)

// constant so baseline and every candidate key on identical footing
const pathSig = "minimize"

const defaultMaxRuns = 5000

type Options struct {
	MaxRuns int             // 0 → defaultMaxRuns
	Fixed   *runner.RunSpec // REQUIRED for a differential Spec, else no candidate can pass
}

type Result struct {
	Minimized     []byte
	BehavioralKey string
	OriginalSize  int
	ReducedSize   int
	Runs          int  // a differential spec spends 2 per candidate
	FrameLess     bool // baseline resolved no frames, so NOT reduced (key can't discriminate)
}

type minimizer struct {
	runner  runner.Runner
	spec    oracle.Spec
	base    runner.RunSpec
	fixed   *runner.RunSpec
	key     string
	runs    int
	maxRuns int
}

// Minimize shrinks pov by deletion ddmin, keeping a candidate only on a passing verdict AND the same key.
func Minimize(ctx context.Context, r runner.Runner, spec oracle.Spec, base runner.RunSpec, pov []byte, opts Options) (Result, error) {
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	// NoPoV bakes the input into argv: every candidate runs identically, so refuse rather than fabricate a reduction (vault: Corpus and Grading)
	if base.NoPoV || (opts.Fixed != nil && opts.Fixed.NoPoV) {
		return Result{}, errNoPoVSpec
	}
	// a staged sequence needs one run per stage; a byte reducer drives a single run
	if len(spec.Sequence) > 0 {
		return Result{}, errSequenceSpec
	}
	// a differential Spec is judged on the pair; without the reference the verdict can never pass
	if spec.Differential != nil && opts.Fixed == nil {
		return Result{}, errNoReference
	}
	if base.Sanitizer == "" {
		base.Sanitizer = sanitizerFromSpec(spec)
	}
	m := &minimizer{runner: r, spec: spec, base: base, fixed: opts.Fixed, maxRuns: opts.MaxRuns}
	if m.maxRuns <= 0 {
		m.maxRuns = defaultMaxRuns
	}

	// baseline: the original must reproduce, or there's nothing to minimize
	ok, crash, err := m.evaluate(ctx, pov)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, errNoRepro
	}
	m.key = artifact.ComputeBehavioralKey(crash)

	// frame-less verdict has no discriminating key: a smaller input could reach a DIFFERENT root cause — refuse to reduce
	if !artifact.FramesResolved(crash) {
		return Result{
			Minimized:     append([]byte(nil), pov...),
			BehavioralKey: m.key,
			OriginalSize:  len(pov),
			ReducedSize:   len(pov),
			Runs:          m.runs,
			FrameLess:     true,
		}, nil
	}

	cur := append([]byte(nil), pov...)
	n := 2
	for len(cur) >= 2 && m.runs < m.maxRuns {
		reduced := false
		for i := 0; i < n; i++ {
			if m.runs >= m.maxRuns {
				break
			}
			cand := removeChunk(cur, n, i)
			if len(cand) == 0 {
				continue // never test the empty input
			}
			if m.reproduces(ctx, cand) {
				cur = cand
				n-- // retreat but stay >= 2
				if n < 2 {
					n = 2
				}
				reduced = true
				break
			}
		}
		if reduced {
			continue
		}
		if n >= len(cur) {
			break // byte granularity exhausted → 1-minimal
		}
		if n *= 2; n > len(cur) {
			n = len(cur)
		}
	}

	return Result{
		Minimized:     cur,
		BehavioralKey: m.key,
		OriginalSize:  len(pov),
		ReducedSize:   len(cur),
		Runs:          m.runs,
	}, nil
}

// evaluate runs a candidate (and the reference, for a differential Spec) and reports pass + the parsed crash.
func (m *minimizer) evaluate(ctx context.Context, cand []byte) (bool, artifact.Crash, error) {
	spec := m.base
	spec.PoV = cand
	m.runs++
	res, err := m.runner.Run(ctx, spec)
	if err != nil {
		return false, artifact.Crash{}, err
	}
	var fixed *oracle.RunResult
	if m.fixed != nil {
		fspec := *m.fixed
		fspec.PoV = cand
		m.runs++
		fres, ferr := m.runner.Run(ctx, fspec)
		if ferr != nil {
			return false, artifact.Crash{}, ferr
		}
		fixed = &fres
	}
	if !m.spec.Evaluate(res, fixed).Pass {
		return false, artifact.Crash{}, nil
	}
	// CrashFromPoV is the shared constructor, so a refused reduction's key matches what federation/triage publish.
	return true, artifact.CrashFromPoV(res, pathSig, cand), nil
}

// search predicate: same passing verdict AND same key; a run error counts as did-not-reproduce
func (m *minimizer) reproduces(ctx context.Context, cand []byte) bool {
	ok, crash, err := m.evaluate(ctx, cand)
	return err == nil && ok && artifact.ComputeBehavioralKey(crash) == m.key
}

func removeChunk(data []byte, n, i int) []byte {
	start := i * len(data) / n
	end := (i + 1) * len(data) / n
	out := make([]byte, 0, len(data)-(end-start))
	out = append(out, data[:start]...)
	return append(out, data[end:]...)
}

// infer sanitizer from the spec (mirrors verify)
func sanitizerFromSpec(s oracle.Spec) string {
	for _, c := range s.Conditions {
		if c.Type == oracle.CondSanitizer && c.Tool != "" {
			return c.Tool
		}
	}
	return ""
}

type minErr string

func (e minErr) Error() string { return string(e) }

const errNoRepro = minErr("minimize: the PoV does not reproduce (verdict fail); nothing to minimize")
const errNoPoVSpec = minErr("minimize: run.no_pov is set — the reproducer's input is baked into argv and the runners ignore the PoV, so there is no PoV to reduce")
const errSequenceSpec = minErr("minimize: the oracle declares a staged sequence; it needs one run per stage and cannot be judged from a single run")
const errNoReference = minErr("minimize: the oracle is differential; pass Options.Fixed (the reference build's RunSpec) so each candidate can be judged against the reference run")

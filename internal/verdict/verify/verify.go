// Package verify wires the runner to the pure oracle and records each judgment as an experiment.
package verify

import (
	"context"
	"fmt"
	"time"

	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
)

// re-run budget multiplier and count when a verdict rests on a bare wall-clock kill
const hangConfirmFactor = 3
const hangReruns = 2

const defaultTimeout = 30 * time.Second

type Verifier struct {
	Runner runner.Runner
	Store  *store.Store
}

type Request struct {
	RunID        string
	HypothesisID string
	Model        string
	ToolHashes   []string

	Spec oracle.Spec

	// authoritative (vulnerable) target template; the PoV is injected before running
	Base  runner.RunSpec
	Fixed *runner.RunSpec

	// re-execute a non-passing PoV N more times and confirm on any crash
	Reruns int

	PoV []byte

	// ordered pre-judgment chain; the verdict is the FINAL stage's observation (vault: Verdict Core)
	Stages []runner.RunSpec
}

type Result struct {
	Verdict      oracle.Verdict
	Primary      oracle.RunResult
	Fixed        *oracle.RunResult
	ExperimentID string
}

// Verify runs the PoV (plus the fixed image, in differential mode) and records the experiment.
func (v *Verifier) Verify(ctx context.Context, req Request) (Result, error) {
	if err := req.Spec.Validate(); err != nil {
		return Result{}, err
	}

	if len(req.Stages) > 0 {
		return v.verifyStaged(ctx, req)
	}

	// fail closed: a chain judged by one run would confirm stages that never ran
	if len(req.Spec.Sequence) > 0 {
		return Result{}, fmt.Errorf("verify: oracle declares a staged sequence of %d stages but no Stages run templates were supplied; a chain cannot be judged by a single run", len(req.Spec.Sequence))
	}

	base := req.Base
	base.PoV = req.PoV
	if base.Sanitizer == "" {
		base.Sanitizer = sanitizerFromSpec(req.Spec)
	}
	primary, err := v.Runner.Run(ctx, base)
	if err != nil {
		return Result{}, fmt.Errorf("verify: primary run: %w", err)
	}

	var fixedPtr *oracle.RunResult
	if req.Spec.Differential != nil {
		// fail loudly rather than silently as "no bug"
		if req.Fixed == nil {
			return Result{}, fmt.Errorf("verify: oracle declares a differential but no fixed build was provided (add a `fixed:` ingest block)")
		}
		fx := *req.Fixed
		fx.PoV = req.PoV
		if fx.Sanitizer == "" {
			fx.Sanitizer = base.Sanitizer
		}
		fixedRes, err := v.Runner.Run(ctx, fx)
		if err != nil {
			return Result{}, fmt.Errorf("verify: fixed run: %w", err)
		}
		fixedPtr = &fixedRes
	}

	verdict := judge(req.Spec, primary, fixedPtr)

	// best-of-N: a bug that reproduces only some runs must not be lost to one clean run
	if !verdict.Pass && req.Spec.Differential == nil && req.Reruns > 0 {
		for i := 0; i < req.Reruns; i++ {
			r, rerr := v.Runner.Run(ctx, base)
			if rerr != nil {
				continue
			}
			if vd := judge(req.Spec, r, nil); vd.Pass {
				primary, verdict = r, vd
				break
			}
		}
	}

	// a bare wall-clock kill is a weak DoS signal: re-run at k× budget before publishing it
	if passRestsOnTimeout(req.Spec, verdict) || divergeRestsOnTargetHang(req.Spec, verdict, primary) {
		esc := base
		esc.Timeout = effectiveTimeout(base.Timeout) * hangConfirmFactor
		// demote only if EVERY re-run completes; all re-runs erroring keeps the observed verdict
		killedAgain, completed := false, 0
		var lastCompleted oracle.RunResult
		for i := 0; i < hangReruns; i++ {
			escRes, escErr := v.Runner.Run(ctx, esc)
			if escErr != nil {
				continue
			}
			// only a COMPLETED re-run may stand in as the new primary observation
			if bad, _ := oracle.Incomplete(escRes); bad {
				killedAgain = true
				break
			}
			completed++
			lastCompleted = escRes
		}
		if !killedAgain && completed == hangReruns {
			primary = lastCompleted
			verdict = judge(req.Spec, lastCompleted, fixedPtr)
		}
	}

	// content-address the PoV so the experiment is reproducible (re-run, don't recall)
	var pocHash string
	if v.Store != nil {
		if h, err := v.Store.PutBlob(ctx, req.PoV, "application/octet-stream"); err == nil {
			pocHash = h
		}
	}

	res := Result{Verdict: verdict, Primary: primary, Fixed: fixedPtr}
	if v.Store != nil {
		expID, err := v.Store.RecordExperiment(ctx, store.ExperimentInput{
			RunID:        req.RunID,
			HypothesisID: req.HypothesisID,
			Kind:         "oracle",
			Model:        req.Model,
			ToolHashes:   req.ToolHashes,
			PoCBlob:      pocHash,
			Spec:         req.Spec,
			Primary:      primary,
			Fixed:        fixedPtr,
			Verdict:      verdict,
		})
		if err != nil {
			return res, fmt.Errorf("verify: record experiment: %w", err)
		}
		res.ExperimentID = expID
	}
	return res, nil
}

// no differential and no re-run passes here: re-running a stateful chain is not idempotent
func (v *Verifier) verifyStaged(ctx context.Context, req Request) (Result, error) {
	if req.Spec.Differential != nil {
		return Result{}, fmt.Errorf("verify: staged Sequence is not supported with a differential oracle")
	}
	// 1:1 or trailing observations go unjudged and stages match the wrong runs
	if n := len(req.Spec.Sequence); n > 0 && n != len(req.Stages) {
		return Result{}, fmt.Errorf("verify: oracle declares %d sequence stages but %d run templates were supplied; the chain must map 1:1", n, len(req.Stages))
	}
	baseSan := req.Base.Sanitizer
	if baseSan == "" {
		baseSan = sanitizerFromSpec(req.Spec)
	}

	results := make([]oracle.RunResult, 0, len(req.Stages))
	var triggerPoV []byte
	for i, st := range req.Stages {
		if len(st.PoV) == 0 {
			st.PoV = req.PoV
		}
		if st.Sanitizer == "" {
			st.Sanitizer = baseSan
		}
		r, err := v.Runner.Run(ctx, st)
		if err != nil {
			return Result{}, fmt.Errorf("verify: staged run %d/%d: %w", i+1, len(req.Stages), err)
		}
		results = append(results, r)
		triggerPoV = st.PoV
	}

	// a Sequence is judged per stage; otherwise only the terminal observation is judged
	primary := results[len(results)-1]
	var verdict oracle.Verdict
	if len(req.Spec.Sequence) > 0 {
		verdict = req.Spec.EvaluateSequence(results)
	} else {
		verdict = judge(req.Spec, primary, nil)
	}

	var pocHash string
	if v.Store != nil {
		if h, err := v.Store.PutBlob(ctx, triggerPoV, "application/octet-stream"); err == nil {
			pocHash = h
		}
	}

	res := Result{Verdict: verdict, Primary: primary}
	if v.Store != nil {
		expID, err := v.Store.RecordExperiment(ctx, store.ExperimentInput{
			RunID:        req.RunID,
			HypothesisID: req.HypothesisID,
			Kind:         "oracle-staged",
			Model:        req.Model,
			ToolHashes:   req.ToolHashes,
			PoCBlob:      pocHash,
			Spec:         req.Spec,
			Primary:      primary,
			Verdict:      verdict,
		})
		if err != nil {
			return res, fmt.Errorf("verify: record staged experiment: %w", err)
		}
		res.ExperimentID = expID
	}
	return res, nil
}

// supervisor-side guard: an incomplete fixed build must never carry a confirmation
func judge(spec oracle.Spec, primary oracle.RunResult, fixed *oracle.RunResult) oracle.Verdict {
	verdict := spec.Evaluate(primary, fixed)
	if spec.Differential == nil || fixed == nil || !verdict.Pass {
		return verdict
	}
	bad, why := oracle.Incomplete(*fixed)
	if !bad {
		return verdict
	}
	reason := "fixed build " + why + "; differential inconclusive"
	verdict.Pass = false
	verdict.PartialCredit = append(verdict.PartialCredit, reason)
	if verdict.Differential != nil {
		// the printed DiffResult must not claim a confirmation the verdict withdrew
		verdict.Differential.Satisfied = false
		if verdict.Differential.Detail == "" {
			verdict.Differential.Detail = reason
		} else {
			verdict.Differential.Detail += "; " + reason
		}
	}
	return verdict
}

// require:all ⇒ a matched timeout is load-bearing; require:any ⇒ only if nothing else matched
func passRestsOnTimeout(s oracle.Spec, v oracle.Verdict) bool {
	if !v.Pass {
		return false
	}
	sawTimeout := false
	for _, c := range v.Conditions {
		if !c.Matched {
			continue
		}
		if c.Type == oracle.CondTimeout {
			sawTimeout = true
			continue
		}
		if s.Require != "all" {
			return false
		}
	}
	return sawTimeout
}

// the target's failure to complete is a bare wall-clock kill: same k× re-confirmation
func divergeRestsOnTargetHang(s oracle.Spec, v oracle.Verdict, primary oracle.RunResult) bool {
	if !v.Pass || s.Differential == nil || s.Differential.Rule != oracle.DivergeOnOutput {
		return false
	}
	bad, _ := oracle.Incomplete(primary)
	return bad
}

func effectiveTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultTimeout
	}
	return d
}

func sanitizerFromSpec(s oracle.Spec) string {
	for _, c := range s.Conditions {
		if c.Type == oracle.CondSanitizer && c.Tool != "" {
			return c.Tool
		}
	}
	return ""
}

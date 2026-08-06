package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xjustus/quarry/internal/discover/fuzz"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type differentialFuzzTool struct{ s *Session }

func (differentialFuzzTool) Name() string { return "differential_fuzz" }

func (differentialFuzzTool) Description() string {
	return "After propose_reference has installed a reference, FIND the diverging input by coverage-guided " +
		"fuzzing instead of guessing by hand — 0 reasoning tokens spent searching. Compiles the target and your " +
		"reference into one abort-on-divergence harness (a divergence becomes a crash the fuzzer hunts), runs a " +
		"bounded campaign, and CONFIRMS any hit on the real oracle. Call it once after propose_reference; if it " +
		"returns no divergence, either the target is correct or the input is deep — refine the reference or use " +
		"run_generator. Optional budget_seconds (default 45, max 180)."
}

func (differentialFuzzTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` +
		`"budget_seconds":{"type":"integer","description":"fuzzing wall-clock budget (default 45, max 180)"}},` +
		`"required":[]}`)
}

func (t *differentialFuzzTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	if t.s.Fixed == nil || t.s.Oracle.Differential == nil || t.s.Oracle.Differential.Rule != oracle.DivergeOnOutput {
		return "differential_fuzz needs an installed reference — call propose_reference first, then differential_fuzz.", nil
	}
	if t.s.ReferenceSource == "" || t.s.TargetSource == "" {
		return "differential_fuzz is unavailable (missing target or reference source) — search manually with run_generator / run_pov.", nil
	}
	var a struct {
		BudgetSeconds int `json:"budget_seconds"`
	}
	_ = json.Unmarshal(args, &a)
	budget := 45 * time.Second
	if a.BudgetSeconds > 0 {
		if a.BudgetSeconds > 180 {
			a.BudgetSeconds = 180
		}
		budget = time.Duration(a.BudgetSeconds) * time.Second
	}
	docker := t.s.DockerBin
	if docker == "" {
		docker = "docker"
	}

	img, compileErr, err := fuzz.BuildDifferentialImage(ctx, docker, t.s.TargetSource, t.s.ReferenceSource)
	if err != nil {
		return "", fmt.Errorf("differential_fuzz: build harness: %w", err)
	}
	if compileErr != "" {
		return "differential_fuzz: the abort-on-divergence harness did not COMPILE (a program that exit()s instead of " +
			"returning, or a non-standard I/O contract, breaks the combine). Falling back — search with run_generator / " +
			"run_pov. Build error:\n" + compileErr, nil
	}

	seedDir, err := os.MkdirTemp("", "difffuzz-seed-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(seedDir)
	// a generic cold-start seed, NOT a known diverging input
	_ = os.WriteFile(filepath.Join(seedDir, "seed"), []byte{0x01, 0, 0, 0, 0, 0, 0, 0x08}, 0o644)
	outDir, err := os.MkdirTemp("", "difffuzz-out-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(outDir)

	res, ferr := fuzz.Campaign{
		Image: img, SeedDir: seedDir, OutDir: outDir,
		HarnessArgv: []string{"/harness", "@@"}, Duration: budget, StopOnCrash: true, DockerBin: docker,
	}.Run(ctx)
	if ferr != nil {
		return "differential_fuzz: campaign error (" + ferr.Error() + ") — fall back to run_generator / run_pov.", nil
	}
	if len(res.Crashes) == 0 {
		return fmt.Sprintf("differential_fuzz: no divergence found by coverage-guided search in %s. The target may correctly "+
			"implement the spec (no diverging input exists), or the input is deep — re-check your reference against the spec, "+
			"or target the suspect field with run_generator.", budget), nil
	}

	// the harness's own abort is not the verdict: the real oracle disposes
	pov := res.Crashes[0].Bytes
	if t.s.CandidateSink != nil {
		t.s.CandidateSink(pov)
	}
	vr, verr := t.s.Verifier.Verify(ctx, verify.Request{
		RunID: t.s.RunID, HypothesisID: t.s.HypothesisID, Model: t.s.Model,
		Spec: t.s.Oracle, Base: t.s.Base, Fixed: t.s.Fixed, PoV: pov,
	})
	if verr != nil {
		return "", fmt.Errorf("differential_fuzz: confirm: %w", verr)
	}
	t.s.LastResult, t.s.LastVerdict, t.s.LastPoV = &vr, &vr.Verdict, pov
	if !vr.Verdict.Pass {
		return "differential_fuzz: the fuzzer found an abort in the differential harness, but the oracle did NOT confirm a " +
			"divergence on the real builds (possible harness artifact). Inconclusive — verify with run_pov.", nil
	}
	t.s.Confirmed = true
	t.s.ConfirmedPoV = pov
	snap := vr
	t.s.ConfirmedResult = &snap
	return fmt.Sprintf("differential_fuzz: FOUND a diverging input by coverage-guided search and CONFIRMED it on the oracle "+
		"(target and reference disagree on executed output) — the logic bug is oracle-confirmed, with 0 reasoning tokens spent "+
		"searching. %d-byte PoV.", len(pov)), nil
}

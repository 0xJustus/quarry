package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/discover/diff"
	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type DiffRequest struct {
	Caller      Caller `json:"caller,omitempty"`
	Diff        []byte `json:"diff"`
	VulnTarget  string `json:"vuln_target,omitempty"`
	FixedTarget string `json:"fixed_target,omitempty"`
	PoV         []byte `json:"pov,omitempty"`
}

type DiffFileFocus struct {
	Path    string   `json:"path"`
	Added   int      `json:"added"`
	Removed int      `json:"removed"`
	Symbols []string `json:"symbols,omitempty"`
}

type DiffFocus struct {
	Files   []DiffFileFocus `json:"files"`
	Symbols []string        `json:"symbols"`
}

type DiffResult struct {
	Focus     DiffFocus `json:"focus"`
	Mode      string    `json:"mode"`
	Confirmed bool      `json:"confirmed"`
	Verdict   string    `json:"verdict,omitempty"`
	BugClass  string    `json:"bug_class,omitempty"`
	CrashSite string    `json:"crash_site,omitempty"`
	Frames    []string  `json:"frames,omitempty"`
	InDiff    bool      `json:"crash_in_diff"`
	Matched   string    `json:"matched_symbol,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

func (e *Engine) Diff(ctx context.Context, req DiffRequest) (DiffResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	differential := req.VulnTarget != "" || req.FixedTarget != ""
	kind := audit.KindAccess
	if differential {
		kind = audit.KindCall
	}
	sp := log.Start("core.Diff", kind, fmt.Sprintf("diff:%s vuln:%s fixed:%s", digest(req.Diff), req.VulnTarget, req.FixedTarget))
	res, err := e.diff(ctx, log, req)
	sp.End(diffSummary(res, err), err)
	return res, err
}

func (e *Engine) diff(ctx context.Context, log audit.Recorder, req DiffRequest) (DiffResult, error) {
	if len(req.Diff) == 0 {
		return DiffResult{}, fmt.Errorf("diff: diff is required")
	}
	d, err := diff.Parse(req.Diff)
	if err != nil {
		return DiffResult{}, fmt.Errorf("diff: parse: %w", err)
	}
	focus := buildDiffFocus(d)

	if req.VulnTarget == "" && req.FixedTarget == "" {
		return DiffResult{Focus: focus, Mode: "focus-only",
			Detail: "changed-code focus only: no PoV was judged (pass vuln_target/fixed_target/pov to run the differential)"}, nil
	}
	if req.VulnTarget == "" || req.FixedTarget == "" {
		return DiffResult{}, fmt.Errorf("diff: differential verify needs both vuln_target and fixed_target descriptors")
	}
	if len(req.PoV) == 0 {
		return DiffResult{}, fmt.Errorf("diff: pov is required to run the differential (vuln-crashes / fixed-doesn't)")
	}

	dv, dvBase, err := target.Load(req.VulnTarget)
	if err != nil {
		return DiffResult{}, fmt.Errorf("diff: load vuln target: %w", err)
	}
	preparedV, err := target.Prepare(ctx, dv, dvBase, e.cfg.DockerBin)
	if err != nil {
		return DiffResult{}, fmt.Errorf("diff: prepare vuln: %w", err)
	}
	df, dfBase, err := target.Load(req.FixedTarget)
	if err != nil {
		return DiffResult{}, fmt.Errorf("diff: load fixed target: %w", err)
	}
	preparedF, err := target.Prepare(ctx, df, dfBase, e.cfg.DockerBin)
	if err != nil {
		return DiffResult{}, fmt.Errorf("diff: prepare fixed: %w", err)
	}

	if fmt.Sprintf("%T", preparedV.Runner) != fmt.Sprintf("%T", preparedF.Runner) {
		return DiffResult{}, fmt.Errorf("diff: vuln and fixed must be the same target kind (got %T vs %T)", preparedV.Runner, preparedF.Runner)
	}

	spec := preparedV.Oracle
	spec.Differential = &oracle.Differential{FixedImage: preparedF.Ref, Rule: oracle.PassOnVulnFailOnFixed}

	v := &verify.Verifier{Runner: auditedRunner{inner: preparedV.Runner, log: log}}
	r, err := v.Verify(ctx, verify.Request{
		Model: "diff", Spec: spec,
		Base: preparedV.Base, Fixed: &preparedF.Base, PoV: req.PoV,
	})
	if err != nil {
		return DiffResult{}, fmt.Errorf("diff: differential run: %w", err)
	}

	out := DiffResult{Focus: focus, Mode: "differential", Confirmed: r.Verdict.Pass}
	out.BugClass = r.Primary.Sanitizer.BugClass
	out.CrashSite = r.Primary.Sanitizer.CrashSite
	out.Frames = r.Primary.Sanitizer.Frames
	if r.Verdict.Pass {
		out.Verdict = "vuln-crashes-fixed-clean"
		out.Matched = diffScopeCrash(d, r)
		out.InDiff = out.Matched != ""
		out.Detail = "differential confirmed: the PoV crashes the vulnerable build and not the fixed build"
	} else {
		out.Verdict = "unconfirmed"
		out.Detail = diffDifferentialDetail(r)
	}
	return out, nil
}

func buildDiffFocus(d *diff.Diff) DiffFocus {
	f := DiffFocus{Symbols: d.Symbols()}
	for _, file := range d.Files {
		add, rem := file.Stat()
		f.Files = append(f.Files, DiffFileFocus{Path: file.Path(), Added: add, Removed: rem, Symbols: file.Symbols})
	}
	return f
}

func diffScopeCrash(d *diff.Diff, res verify.Result) string {
	cands := append([]string{res.Primary.Sanitizer.CrashSite}, res.Primary.Sanitizer.Frames...)
	for _, c := range cands {
		if m := d.MatchSymbol(c); m != "" {
			return m
		}
	}
	return ""
}

func diffDifferentialDetail(res verify.Result) string {
	dr := res.Verdict.Differential
	switch {
	case dr == nil:
		return "no crash reproduced on the vulnerable build"
	case !dr.MatchedOnVuln:
		return "the PoV did not crash the vulnerable build — not reproduced"
	case dr.MatchedOnFixed:
		return "the PoV also crashes the fixed build — not attributable to this change"
	default:
		if len(res.Verdict.PartialCredit) > 0 {
			return "differential inconclusive: " + strings.Join(res.Verdict.PartialCredit, ", ")
		}
		return "differential not satisfied"
	}
}

func diffSummary(res DiffResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.Mode == "focus-only" {
		return fmt.Sprintf("focus-only files:%d symbols:%d", len(res.Focus.Files), len(res.Focus.Symbols))
	}
	if res.Confirmed {
		return "CONFIRMED " + res.Verdict
	}
	return "unconfirmed"
}

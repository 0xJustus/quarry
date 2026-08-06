package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/federation"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type CommonsIngestRequest struct {
	Caller     Caller `json:"caller,omitempty"`
	TargetFile string `json:"target_file"`
	PoV        []byte `json:"pov"`
	Source     string `json:"source"`
	OutDir     string `json:"out_dir,omitempty"`
	CommitDir  string `json:"commit_dir,omitempty"`
	Reruns     int    `json:"reruns,omitempty"`

	GradeBin   []byte `json:"grade_bin,omitempty"`
	GradeApp   string `json:"grade_app,omitempty"`
	GradeImage string `json:"grade_image,omitempty"`
}

type CommonsIngestResult struct {
	Admitted   bool   `json:"admitted"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Source     string `json:"source,omitempty"`
	AcquiredBy string `json:"acquired_by,omitempty"`

	Private *artifact.Envelope `json:"private,omitempty"`
	Public  *artifact.Envelope `json:"public,omitempty"`

	PrivatePath string `json:"private_path,omitempty"`
	PublicPath  string `json:"public_path,omitempty"`

	Committed       bool     `json:"committed,omitempty"`
	CommitArtifacts int      `json:"commit_artifacts,omitempty"`
	CommitKeys      int      `json:"commit_keys,omitempty"`
	CommitTreeBytes int      `json:"commit_tree_bytes,omitempty"`
	GateOK          bool     `json:"gate_ok,omitempty"`
	GateArtifacts   int      `json:"gate_artifacts,omitempty"`
	GateKeys        int      `json:"gate_keys,omitempty"`
	GateFailures    []string `json:"gate_failures,omitempty"`

	CrashGrade      string `json:"crash_grade,omitempty"`
	CrashGradeError string `json:"crash_grade_error,omitempty"`
}

func (e *Engine) CommonsIngest(ctx context.Context, req CommonsIngestRequest) (CommonsIngestResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CommonsIngest", audit.KindCall, fmt.Sprintf("target:%s pov:%s source:%s", req.TargetFile, digest(req.PoV), req.Source))
	res, err := e.commonsIngest(ctx, log, req)
	sp.End(commonsIngestSummary(res, err), err)
	return res, err
}

func (e *Engine) commonsIngest(ctx context.Context, log audit.Recorder, req CommonsIngestRequest) (CommonsIngestResult, error) {
	if req.TargetFile == "" || len(req.PoV) == 0 || req.Source == "" {
		return CommonsIngestResult{}, fmt.Errorf("commons ingest: target_file, pov, and source are required")
	}
	desc, baseDir, err := target.Load(req.TargetFile)
	if err != nil {
		return CommonsIngestResult{}, fmt.Errorf("commons ingest: load target: %w", err)
	}
	prepared, err := target.Prepare(ctx, desc, baseDir, e.cfg.DockerBin)
	if err != nil {
		return CommonsIngestResult{}, fmt.Errorf("commons ingest: prepare: %w", err)
	}

	prepared.Base.IsolateNetwork = true
	if prepared.Fixed != nil {
		prepared.Fixed.IsolateNetwork = true
	}
	reruns := req.Reruns
	if reruns == 0 {
		reruns = 1
	}

	v := &verify.Verifier{Runner: auditedRunner{inner: prepared.Runner, log: log}}
	vr, err := v.Verify(ctx, verify.Request{
		Model: federation.AcquiredBy, Spec: prepared.Oracle, Base: prepared.Base, Fixed: prepared.Fixed,
		PoV: req.PoV, Reruns: reruns,
	})
	if err != nil {
		return CommonsIngestResult{}, fmt.Errorf("commons ingest: grounding run: %w", err)
	}

	createdAt := time.Now().UTC().Format(time.RFC3339)

	env, admitted := federation.Admit(vr.Verdict, federation.Finding{Source: req.Source, PoV: req.PoV, Spec: prepared.Oracle}, vr.Primary, commonsPathSig(prepared.Base), createdAt)
	if !admitted {

		return CommonsIngestResult{
			Admitted: false,
			Source:   req.Source,
			Evidence: "REJECTED — the claim did not reproduce on quarry's oracle (ungrounded)",
		}, nil
	}

	kind, evDetail := commonsClassifyKind(vr)

	crashGrade, crashGradeErr := "", ""
	if len(req.GradeBin) > 0 && (vr.Primary.Sanitizer.Fired || vr.Primary.TermSignal != 0) && os.Getenv("FLY_API_TOKEN") != "" {
		a, gerr := e.gradeCrashOnFly(ctx, log, req.GradeBin, req.PoV, req.GradeApp, req.GradeImage)
		if gerr != nil {
			crashGradeErr = gerr.Error()
		} else {
			crashGrade = a.Grade.String()
		}
	}

	abstract := "federated-ingest: " + kind + " from " + req.Source
	if crashGrade != "" {
		abstract += " [crash-primitive:" + crashGrade + "]"
	}
	pub := env.PublicAbstract(abstract, createdAt)
	_ = pub.Artifact.ComputeID()

	out := CommonsIngestResult{
		Admitted:        true,
		ArtifactID:      env.Artifact.ID,
		Kind:            kind,
		Evidence:        evDetail,
		Source:          req.Source,
		AcquiredBy:      env.Provenance.AcquiredBy,
		Private:         env,
		Public:          pub,
		CrashGrade:      crashGrade,
		CrashGradeError: crashGradeErr,
	}

	if req.OutDir != "" {
		if err := os.MkdirAll(req.OutDir, 0o755); err != nil {
			return out, fmt.Errorf("commons ingest: out dir: %w", err)
		}
		out.PrivatePath = filepath.Join(req.OutDir, "envelope-private.json")
		out.PublicPath = filepath.Join(req.OutDir, "envelope-public.json")
		if err := writeEnvelopeJSON(out.PrivatePath, env); err != nil {
			return out, err
		}
		if err := writeEnvelopeJSON(out.PublicPath, pub); err != nil {
			return out, err
		}
	}

	if req.CommitDir != "" {
		st, err := gitcommons.Add(req.CommitDir, []*artifact.Envelope{pub})
		if err != nil {
			return out, fmt.Errorf("commons ingest: commit to commons tree %q: %w", req.CommitDir, err)
		}
		out.Committed = true
		out.CommitArtifacts = st.Artifacts
		out.CommitKeys = st.Keys
		out.CommitTreeBytes = st.TreeBytes

		rep, verr := gitcommons.Verify(req.CommitDir)
		out.GateOK = verr == nil && rep.OK()
		out.GateArtifacts = rep.Artifacts
		out.GateKeys = rep.Keys
		out.GateFailures = rep.Failures
		if !out.GateOK {
			return out, fmt.Errorf("commons ingest: anti-poisoning gate FAILED after commit: err=%v failures=%v", verr, rep.Failures)
		}
	}
	return out, nil
}

func commonsIngestSummary(res CommonsIngestResult, err error) string {
	if err != nil {
		return "error"
	}
	if !res.Admitted {
		return "REJECTED"
	}
	s := "ADMITTED " + res.Kind
	if res.Committed {
		s += " committed"
	}
	return s
}

type CommonsVerifyRequest struct {
	Caller Caller `json:"caller,omitempty"`
	Dir    string `json:"dir,omitempty"`
}

type CommonsVerifyResult struct {
	OK        bool     `json:"ok"`
	Artifacts int      `json:"artifacts"`
	Keys      int      `json:"keys"`
	Signers   int      `json:"signers"`
	Failures  []string `json:"failures,omitempty"`
}

func (e *Engine) CommonsVerify(ctx context.Context, req CommonsVerifyRequest) (CommonsVerifyResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	dir := req.Dir
	if dir == "" {
		dir = "."
	}
	sp := log.Start("core.CommonsVerify", audit.KindAccess, "dir:"+dir)
	rep, err := gitcommons.Verify(dir)
	if err != nil {
		sp.End("error", err)
		return CommonsVerifyResult{}, fmt.Errorf("commons verify: %w", err)
	}
	out := CommonsVerifyResult{
		OK:        rep.OK(),
		Artifacts: rep.Artifacts,
		Keys:      rep.Keys,
		Signers:   rep.Signers,
		Failures:  rep.Failures,
	}
	sp.End(fmt.Sprintf("ok:%v artifacts:%d keys:%d failures:%d", out.OK, out.Artifacts, out.Keys, len(out.Failures)), nil)
	return out, nil
}

func commonsPathSig(base runner.RunSpec) string {
	switch {
	case base.NoPoV:
		return "testcase"
	case base.StdinPoV:
		return "stdin"
	default:
		return "argv"
	}
}

func commonsClassifyKind(res verify.Result) (kind, detail string) {
	dr := res.Verdict.Differential
	conds := commonsConfirmedConditions(res.Verdict)
	switch {
	case dr != nil && dr.Rule == oracle.DivergeOnOutput:
		return "spec-divergence", "oracle-confirmed behavioral divergence from the reference: " + dr.Detail
	case commonsMatchedCondDetail(conds, oracle.CondMetamorphic) != "":
		return "spec-divergence (metamorphic)", "oracle-confirmed metamorphic-relation violation (spec divergence, no crash): " + commonsMatchedCondDetail(conds, oracle.CondMetamorphic)
	case commonsMatchedCondDetail(conds, oracle.CondDivergence) != "":
		return "spec-divergence", "oracle-confirmed divergence from the declared baseline (spec violation, no crash): " + commonsMatchedCondDetail(conds, oracle.CondDivergence)
	case res.Primary.TimedOut:
		return "hang / DoS", "confirmed a hang / DoS (timed out)"
	case res.Primary.OOMKilled:
		return "resource-exhaustion DoS", "confirmed a memory-exhaustion DoS (kernel OOM-killed); not a memory-safety crash"
	case res.Primary.Sanitizer.Fired || oracle.IsCrashSignal(res.Primary.TermSignal):
		return "real-crash", "oracle-confirmed real crash"
	default:
		return "non-crash spec violation", "oracle-confirmed non-crash condition (" + commonsMatchedCondTypes(conds) + "): no crash evidence — no corroborated sanitizer report and no fault signal"
	}
}

func commonsConfirmedConditions(v oracle.Verdict) []oracle.ConditionResult {
	out := append([]oracle.ConditionResult(nil), v.Conditions...)
	for _, st := range v.Stages {
		out = append(out, st.Conditions...)
	}
	return out
}

func commonsMatchedCondDetail(conds []oracle.ConditionResult, t oracle.ConditionType) string {
	for _, c := range conds {
		if c.Type == t && c.Matched {
			if c.Detail == "" {
				return string(t)
			}
			return c.Detail
		}
	}
	return ""
}

func commonsMatchedCondTypes(conds []oracle.ConditionResult) string {
	var ts []string
	for _, c := range conds {
		if c.Matched {
			ts = append(ts, string(c.Type))
		}
	}
	if len(ts) == 0 {
		return "none"
	}
	return strings.Join(ts, ", ")
}

func writeEnvelopeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

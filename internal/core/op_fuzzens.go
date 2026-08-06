package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/discover/cpg"
	"github.com/0xjustus/quarry/internal/discover/fuzz"
	"github.com/0xjustus/quarry/internal/discover/loop"
	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/platform/toolctl"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/channels"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

func (e *Engine) fuzzEnsModelRouter(lowBudgetTokens int) (model.Model, router.Router) {
	cfg := e.cfg
	cheap := model.New(cfg.ResolvedProvider(), cfg.ModelBaseURL(), cfg.APIKey)
	if cfg.StrongModel == "" {
		return cheap, router.NewStaticRouter(cfg.Model)
	}
	strong := cheap
	if cfg.StrongTransportDiffers() {
		strong = model.New(cfg.StrongResolvedProvider(), cfg.StrongModelBaseURL(), cfg.StrongAPIKey())
	}
	mdl := model.NewMultiModel(cheap).Register(cfg.Model, cheap).Register(cfg.StrongModel, strong)
	tr := router.NewTieredRouter(cfg.Model, cfg.StrongModel)
	tr.LowBudgetTokens = lowBudgetTokens
	return mdl, tr
}

func fuzzEnsResolveIncludes(root string, includes []string) []string {
	if len(includes) == 0 {
		return nil
	}
	out := make([]string, 0, len(includes))
	for _, inc := range includes {
		if inc == "" {
			continue
		}
		if filepath.IsAbs(inc) {
			out = append(out, inc)
			continue
		}
		if abs, err := filepath.Abs(filepath.Join(root, inc)); err == nil {
			out = append(out, abs)
		} else {
			out = append(out, filepath.Join(root, inc))
		}
	}
	return out
}

func fuzzEnsSplitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fuzzAttachToolProvisioner(prepared *target.Prepared, storeRoot string, extraAllow []string) error {
	if prepared == nil || prepared.Base.Toolset.Empty() {
		return nil
	}
	allow, err := toolctl.Allowlist(storeRoot)
	if err != nil {
		return fmt.Errorf("tool provisioning: %w", err)
	}
	for _, h := range extraAllow {
		if h = strings.TrimSpace(h); h != "" {
			allow = append(allow, h)
		}
	}
	st := broker.NewLocalStore(storeRoot, allow)
	prepared.SetProvisioner(broker.NewProvisioner(st))
	return nil
}

func fuzzBehavioralKey(r verify.Result) string {
	if !artifact.FramesResolved(artifact.CrashFrom(r.Primary, "")) {
		return ""
	}
	return artifact.ComputeBehavioralKey(artifact.CrashFrom(r.Primary, ""))
}

func fuzzDedupKey(r verify.Result, input []byte) string {
	return artifact.ComputeBehavioralKey(artifact.CrashFromPoV(r.Primary, "", input))
}

type FuzzRequest struct {
	Caller     Caller `json:"caller,omitempty"`
	TargetFile string `json:"target_file"`
	Image      string `json:"image"`
	Seeds      string `json:"seeds"`

	Dict        string `json:"dict,omitempty"`
	Cmplog      string `json:"cmplog,omitempty"`
	Harness     string `json:"harness,omitempty"`
	ForSeconds  int    `json:"for_seconds,omitempty"`
	StopOnCrash bool   `json:"stop_on_crash,omitempty"`

	UseAnalyst bool   `json:"analyst,omitempty"`
	SeedSource string `json:"seed_source,omitempty"`
	Objective  string `json:"objective,omitempty"`

	ToolStore     string `json:"tool_store,omitempty"`
	ToolAllowlist string `json:"tool_allowlist,omitempty"`
}

type FuzzFinding struct {
	BehavioralKey string   `json:"behavioral_key"`
	BugClass      string   `json:"bug_class,omitempty"`
	CrashSite     string   `json:"crash_site,omitempty"`
	Frames        []string `json:"frames,omitempty"`
	CrashInput    []byte   `json:"crash_input"`
}

type FuzzResult struct {
	Execs        int64         `json:"execs"`
	Coverage     string        `json:"coverage,omitempty"`
	Crashes      int           `json:"crashes_found"`
	Confirmed    []FuzzFinding `json:"confirmed"`
	Inconclusive int           `json:"inconclusive,omitempty"`
	OracleErrors []string      `json:"oracle_errors,omitempty"`
}

func (r *FuzzResult) recordUnjudged(name string, err error) {
	r.Inconclusive++
	if len(r.OracleErrors) < 3 {
		r.OracleErrors = append(r.OracleErrors, name+": "+err.Error())
	}
}

func (e *Engine) Fuzz(ctx context.Context, req FuzzRequest) (FuzzResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Fuzz", audit.KindCall, fmt.Sprintf("target:%s image:%s analyst:%v", req.TargetFile, req.Image, req.UseAnalyst))
	res, err := e.fuzz(ctx, log, req)
	sp.End(fuzzSummary(res, err), err)
	return res, err
}

func (e *Engine) fuzz(ctx context.Context, log audit.Recorder, req FuzzRequest) (FuzzResult, error) {
	if req.TargetFile == "" || req.Image == "" || req.Seeds == "" {
		return FuzzResult{}, fmt.Errorf("fuzz: target_file, image, and seeds are all required")
	}
	desc, baseDir, err := target.Load(req.TargetFile)
	if err != nil {
		return FuzzResult{}, err
	}
	prepared, err := target.Prepare(ctx, desc, baseDir, e.cfg.DockerBin)
	if err != nil {
		return FuzzResult{}, err
	}
	toolStore := req.ToolStore
	if toolStore == "" {
		toolStore = "toolchain/store"
	}
	if err := fuzzAttachToolProvisioner(prepared, toolStore, fuzzEnsSplitCSV(req.ToolAllowlist)); err != nil {
		return FuzzResult{}, err
	}

	v := &verify.Verifier{Runner: auditedRunner{inner: prepared.Runner, log: log}}

	out, err := os.MkdirTemp("", "quarry-fuzz-*")
	if err != nil {
		return FuzzResult{}, err
	}
	defer os.RemoveAll(out)

	dur := time.Duration(req.ForSeconds) * time.Second
	if dur <= 0 {
		dur = 60 * time.Second
	}
	camp := fuzz.Campaign{
		Image: req.Image, SeedDir: req.Seeds, OutDir: out, DictPath: req.Dict, CmplogBin: req.Cmplog,
		Duration: dur, StopOnCrash: req.StopOnCrash, DockerBin: e.cfg.DockerBin,
	}
	if req.Harness != "" {
		camp.HarnessArgv = strings.Fields(req.Harness)
	}

	if req.UseAnalyst {
		mdl, rt := e.fuzzEnsModelRouter(0)
		srcs := append([]string(nil), prepared.Sources...)
		srcs = append(srcs, fuzzEnsSplitCSV(req.SeedSource)...)
		objective := req.Objective
		if objective == "" {
			objective = "find a memory-safety vulnerability reachable from untrusted input"
		}
		am := auditedModel{inner: mdl, log: log}
		d, derr := loop.AnalystFuzzDictionary(ctx, am, rt, loop.PlanRequest{Objective: objective, TargetDesc: prepared.Desc, SeedFiles: srcs})
		if derr == nil && strings.TrimSpace(d) != "" {
			df := filepath.Join(out, "analyst-dict.txt")
			if werr := os.WriteFile(df, []byte(d), 0o644); werr == nil {
				camp.DictHostFile = df
			}
		}
	}

	campRes, err := camp.Run(ctx)
	if err != nil {
		return FuzzResult{}, fmt.Errorf("fuzz: campaign failed: %w", err)
	}

	summary := FuzzResult{Execs: campRes.Execs, Coverage: campRes.Coverage, Crashes: len(campRes.Crashes)}
	seen := map[string]bool{}
	for _, cr := range campRes.Crashes {
		vr, verr := v.Verify(ctx, verify.Request{Model: "fuzz", Spec: prepared.Oracle, Base: prepared.Base, Fixed: prepared.Fixed, PoV: cr.Bytes})
		if verr != nil {
			summary.recordUnjudged(cr.Name, verr)
			continue
		}
		if !vr.Verdict.Pass {
			continue
		}
		key := fuzzDedupKey(vr, cr.Bytes)
		if seen[key] {
			continue
		}
		seen[key] = true
		summary.Confirmed = append(summary.Confirmed, FuzzFinding{
			BehavioralKey: fuzzBehavioralKey(vr),
			BugClass:      vr.Primary.Sanitizer.BugClass,
			CrashSite:     vr.Primary.Sanitizer.CrashSite,
			Frames:        vr.Primary.Sanitizer.Frames,
			CrashInput:    cr.Bytes,
		})
	}

	if summary.Inconclusive > 0 {
		return summary, fmt.Errorf("fuzz: INCONCLUSIVE — the oracle could not judge %d of %d fuzzer crash(es) (%s)",
			summary.Inconclusive, len(campRes.Crashes), strings.Join(summary.OracleErrors, "; "))
	}
	return summary, nil
}

func fuzzSummary(res FuzzResult, err error) string {
	if err != nil && len(res.Confirmed) == 0 && res.Inconclusive == 0 {
		return "error"
	}
	return fmt.Sprintf("confirmed:%d crashes:%d inconclusive:%d execs:%d", len(res.Confirmed), res.Crashes, res.Inconclusive, res.Execs)
}

type EnsembleRequest struct {
	Caller     Caller `json:"caller,omitempty"`
	TargetFile string `json:"target_file"`
	Image      string `json:"image"`
	Seeds      string `json:"seeds"`

	Dict     string `json:"dict,omitempty"`
	Cmplog   string `json:"cmplog,omitempty"`
	Harness  string `json:"harness,omitempty"`
	Engine   string `json:"engine,omitempty"`
	AflBin   string `json:"afl_bin,omitempty"`
	OutMount string `json:"out_mount,omitempty"`

	Objective   string `json:"objective,omitempty"`
	SeedSource  string `json:"seed_source,omitempty"`
	CommonsTree string `json:"commons_tree,omitempty"`
	CPGPath     string `json:"cpg,omitempty"`

	FuzzForSeconds int    `json:"fuzz_for_seconds,omitempty"`
	MaxIters       int    `json:"max_iters,omitempty"`
	MaxHypotheses  int    `json:"max_hypotheses,omitempty"`
	TokenBudget    int    `json:"token_budget,omitempty"`
	AgentImage     string `json:"agent_image,omitempty"`
}

type EnsembleFinding struct {
	Novel         bool   `json:"novel"`
	Statement     string `json:"statement"`
	BehavioralKey string `json:"behavioral_key,omitempty"`
}

type EnsembleResult struct {
	Confirmed      bool              `json:"confirmed"`
	Findings       []EnsembleFinding `json:"findings"`
	PoVSubmissions int               `json:"pov_submissions"`
	Hypotheses     int               `json:"hypotheses"`
}

func (e *Engine) Ensemble(ctx context.Context, req EnsembleRequest) (EnsembleResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Ensemble", audit.KindCall, fmt.Sprintf("target:%s image:%s", req.TargetFile, req.Image))
	res, err := e.ensemble(ctx, log, req)
	sp.End(ensembleSummary(res, err), err)
	return res, err
}

func (e *Engine) ensemble(ctx context.Context, log audit.Recorder, req EnsembleRequest) (EnsembleResult, error) {
	if req.TargetFile == "" || req.Image == "" || req.Seeds == "" {
		return EnsembleResult{}, fmt.Errorf("ensemble: target_file, image, and seeds are all required")
	}
	harness := req.Harness
	if harness == "" {
		harness = "/harness @@"
	}
	harnessArgv := strings.Fields(harness)
	if len(harnessArgv) == 0 {
		return EnsembleResult{}, fmt.Errorf("ensemble: harness must name the fuzzer leg's in-container argv (e.g. '/out/fuzzer @@')")
	}
	var legEngine loop.FuzzEngine
	switch strings.ToLower(strings.TrimSpace(req.Engine)) {
	case "", "auto":
		legEngine = loop.EngineAuto
	case "afl":
		legEngine = loop.EngineAFL
	case "libfuzzer":
		legEngine = loop.EngineLibFuzzer
	default:
		return EnsembleResult{}, fmt.Errorf("ensemble: engine must be auto, afl or libfuzzer (got %q)", req.Engine)
	}

	desc, baseDir, err := target.Load(req.TargetFile)
	if err != nil {
		return EnsembleResult{}, err
	}
	prepared, err := target.Prepare(ctx, desc, baseDir, e.cfg.DockerBin)
	if err != nil {
		return EnsembleResult{}, err
	}
	if err := e.cfg.EnsureDataDir(); err != nil {
		return EnsembleResult{}, err
	}
	st, err := store.Open(e.cfg.StoreDir())
	if err != nil {
		return EnsembleResult{}, err
	}
	defer st.Close()

	mdl, rt := e.fuzzEnsModelRouter(req.TokenBudget / 5)
	am := auditedModel{inner: mdl, log: log}

	agentImage := req.AgentImage
	if agentImage == "" {
		agentImage = e.cfg.AgentImage
	}

	l := &loop.Loop{
		Store: st, Model: am, Router: rt, Runner: auditedRunner{inner: prepared.Runner, log: log},
		Gate: channels.NewGate(nil, nil), Sink: channels.LocalOutboxSink{Out: st},
		WorkspaceRoot: e.cfg.WorkspaceDir(), AgentImage: agentImage, DockerBin: e.cfg.DockerBin,
	}

	sources := loop.Federated{loop.LocalSource{Store: st}}
	if req.CommonsTree != "" {
		gs, gerr := gitcommons.Open(req.CommonsTree)
		if gerr != nil {
			return EnsembleResult{}, fmt.Errorf("open git-native commons %s: %w", req.CommonsTree, gerr)
		}
		sources = append(sources, gs)
		l.Primer = loop.CommonsPrimer{Dir: req.CommonsTree}
	}
	if len(sources) == 1 {
		l.Source = sources[0]
	} else {
		l.Source = sources
	}
	l.Critic = loop.ModelCritic{Model: am, Router: rt}

	srcs := append([]string(nil), prepared.Sources...)
	srcs = append(srcs, fuzzEnsSplitCSV(req.SeedSource)...)

	resolvedCPG, cpgCleanup := e.resolveEnsembleCPG(ctx, req.CPGPath, prepared.CPG, srcs)
	defer cpgCleanup()

	fuzzFor := time.Duration(req.FuzzForSeconds) * time.Second
	if fuzzFor <= 0 {
		fuzzFor = 5 * time.Minute
	}
	maxIters := req.MaxIters
	if maxIters <= 0 {
		maxIters = 24
	}
	maxHyp := req.MaxHypotheses
	if maxHyp <= 0 {
		maxHyp = 5
	}
	objective := req.Objective
	if objective == "" {
		objective = "find a memory-safety vulnerability reachable from untrusted input"
	}

	rep, err := l.RunEnsemble(ctx, loop.Request{
		Objective:     objective,
		Mode:          "discover",
		TargetRef:     prepared.Ref,
		TargetDesc:    prepared.Desc,
		Oracle:        prepared.Oracle,
		Base:          prepared.Base,
		Fixed:         prepared.Fixed,
		SeedFiles:     srcs,
		CPGPath:       resolvedCPG,
		Analyst:       true,
		MaxIters:      maxIters,
		MaxHypotheses: maxHyp,
		TokenBudget:   req.TokenBudget,
	}, loop.FuzzLeg{
		Image: req.Image, SeedDir: req.Seeds, DictPath: req.Dict, CmplogBin: req.Cmplog, Budget: fuzzFor,
		HarnessArgv: harnessArgv, Engine: legEngine, AflBin: req.AflBin, OutMount: req.OutMount,
	})
	if err != nil {
		return EnsembleResult{}, fmt.Errorf("ensemble: %w", err)
	}

	out := EnsembleResult{Confirmed: rep.Confirmed, PoVSubmissions: rep.PoVSubmissions, Hypotheses: rep.Hypotheses}
	for _, f := range rep.Findings {
		bk := ""
		if f.Private != nil {
			bk = f.Private.Artifact.BehavioralKey()
		}
		out.Findings = append(out.Findings, EnsembleFinding{Novel: f.Novel, Statement: f.Statement, BehavioralKey: bk})
	}
	return out, nil
}

func (e *Engine) resolveEnsembleCPG(ctx context.Context, explicit string, cc *target.CPGConfig, srcs []string) (string, func()) {
	noop := func() {}
	if explicit != "" || cc == nil || len(srcs) == 0 {
		return explicit, noop
	}
	if !cpg.JoernAvailable() {
		return "", noop
	}
	dir, derr := os.MkdirTemp("", "quarry-cpg-*")
	if derr != nil {
		return "", noop
	}
	cleanup := func() { os.RemoveAll(dir) }
	srcRoot, _ := filepath.Abs(srcs[0])
	gr, gerr := cpg.Generate(ctx, cpg.GenSpec{
		Src:      srcRoot,
		Out:      filepath.Join(dir, "cpg.bin"),
		Defines:  cc.Defines,
		Includes: fuzzEnsResolveIncludes(srcRoot, cc.Includes),
	})
	if gerr != nil {
		return "", cleanup
	}
	return gr.CpgPath, cleanup
}

func ensembleSummary(res EnsembleResult, err error) string {
	if err != nil {
		return "error"
	}
	verdict := "not-confirmed"
	if res.Confirmed {
		verdict = "CONFIRMED"
	}
	return fmt.Sprintf("%s findings:%d povs:%d hyps:%d", verdict, len(res.Findings), res.PoVSubmissions, res.Hypotheses)
}

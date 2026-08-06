package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/discover/loop"
	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/platform/toolcat"
	"github.com/0xjustus/quarry/internal/platform/toolctl"
	"github.com/0xjustus/quarry/internal/publish/channels"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

type InvestigateRequest struct {
	Caller Caller `json:"caller,omitempty"`

	Objective string `json:"objective,omitempty"`
	Mode      string `json:"mode,omitempty"`

	TargetFile string `json:"target_file,omitempty"`
	Bin        string `json:"bin,omitempty"`
	Image      string `json:"image,omitempty"`
	Argv       string `json:"argv,omitempty"`
	Sanitizer  string `json:"sanitizer,omitempty"`
	OracleSpec string `json:"oracle_spec,omitempty"`
	OracleFile string `json:"oracle_file,omitempty"`

	CommonsTree string `json:"commons_tree,omitempty"`
	SeedSource  string `json:"seed_source,omitempty"`
	CPGPath     string `json:"cpg_path,omitempty"`

	ToolCatalog   string   `json:"tool_catalog,omitempty"`
	ToolStore     string   `json:"tool_store,omitempty"`
	ToolAllowlist []string `json:"tool_allowlist,omitempty"`

	AgentImage     string `json:"agent_image,omitempty"`
	SandboxNetwork string `json:"sandbox_network,omitempty"`

	MaxIters      int    `json:"max_iters,omitempty"`
	MaxHypotheses int    `json:"max_hypotheses,omitempty"`
	MaxDepth      int    `json:"max_depth,omitempty"`
	TokenBudget   int    `json:"token_budget,omitempty"`
	StallLimit    int    `json:"stall_limit,omitempty"`
	ContextBudget int    `json:"context_budget,omitempty"`
	KeepRecent    int    `json:"keep_recent,omitempty"`
	Compactor     string `json:"compactor,omitempty"`

	Analyst bool `json:"analyst,omitempty"`
	Critic  bool `json:"critic,omitempty"`
	NoSign  bool `json:"no_sign,omitempty"`

	FuzzImage  string        `json:"fuzz_image,omitempty"`
	FuzzSeeds  string        `json:"fuzz_seeds,omitempty"`
	FuzzDict   string        `json:"fuzz_dict,omitempty"`
	FuzzCmplog string        `json:"fuzz_cmplog,omitempty"`
	FuzzFor    time.Duration `json:"fuzz_for,omitempty"`
}

type InvestigateFinding struct {
	Statement     string `json:"statement"`
	PrivateID     string `json:"private_id,omitempty"`
	PublicID      string `json:"public_id,omitempty"`
	BugClass      string `json:"bug_class,omitempty"`
	IntegrityTier string `json:"integrity_tier,omitempty"`
	Placement     string `json:"placement,omitempty"`
	BehavioralKey string `json:"behavioral_key,omitempty"`
	Novel         bool   `json:"novel"`
}

type InvestigateResult struct {
	RunID          string               `json:"run_id"`
	Confirmed      bool                 `json:"confirmed"`
	StopReason     string               `json:"stop_reason,omitempty"`
	Hypotheses     int                  `json:"hypotheses"`
	Iterations     int                  `json:"iterations"`
	PoVSubmissions int                  `json:"pov_submissions"`
	Findings       []InvestigateFinding `json:"findings,omitempty"`
	RuledOut       string               `json:"ruled_out,omitempty"`

	TotalTokens      int     `json:"total_tokens"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	CostUSD          float64 `json:"cost_usd,omitempty"`

	ElapsedMS         int64   `json:"elapsed_ms"`
	Novel             int     `json:"novel"`
	Rediscoveries     int     `json:"rediscoveries"`
	TokensPerFinding  int     `json:"tokens_per_finding,omitempty"`
	SecondsPerFinding float64 `json:"seconds_per_finding,omitempty"`
	PriorArtHitRate   float64 `json:"prior_art_hit_rate,omitempty"`
}

func (e *Engine) Investigate(ctx context.Context, req InvestigateRequest) (InvestigateResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Investigate", audit.KindCall, investigateArgs(req))
	res, err := e.investigate(ctx, log, req)
	sp.End(investigateSummary(res, err), err)
	return res, err
}

func (e *Engine) investigate(ctx context.Context, log audit.Recorder, req InvestigateRequest) (InvestigateResult, error) {
	mode := req.Mode
	if mode == "" {
		mode = "copilot"
	}
	objective := req.Objective
	if objective == "" {
		objective = defaultInvestigateObjective(mode)
	}

	desc, baseDir, err := e.resolveInvestigateTarget(req)
	if err != nil {
		return InvestigateResult{}, err
	}
	prepared, err := target.Prepare(ctx, desc, baseDir, e.cfg.DockerBin)
	if err != nil {
		return InvestigateResult{}, fmt.Errorf("investigate: prepare: %w", err)
	}
	if err := attachInvestigateToolProvisioner(prepared, req.ToolStore, req.ToolAllowlist); err != nil {
		return InvestigateResult{}, err
	}

	if err := e.cfg.EnsureDataDir(); err != nil {
		return InvestigateResult{}, err
	}
	st, err := store.Open(e.cfg.StoreDir())
	if err != nil {
		return InvestigateResult{}, fmt.Errorf("investigate: open store: %w", err)
	}
	defer st.Close()

	mdl, rt := e.buildInvestigateModelRouter(req.TokenBudget / 5)
	am := auditedModel{inner: mdl, log: log}

	agentImage := req.AgentImage
	if agentImage == "" {
		agentImage = e.cfg.AgentImage
	}

	l := &loop.Loop{
		Store:          st,
		Model:          am,
		Router:         rt,
		Runner:         auditedRunner{inner: prepared.Runner, log: log},
		Gate:           channels.NewGate(nil, nil),
		Sink:           channels.LocalOutboxSink{Out: st},
		WorkspaceRoot:  e.cfg.WorkspaceDir(),
		AgentImage:     agentImage,
		DockerBin:      e.cfg.DockerBin,
		SandboxNetwork: req.SandboxNetwork,
	}
	if req.ToolCatalog != "" {
		cat, err := toolcat.Load(req.ToolCatalog)
		if err != nil {
			return InvestigateResult{}, fmt.Errorf("investigate: tool catalog: %w", err)
		}
		l.Catalog = cat
	}
	if !req.NoSign {
		key, err := e.cfg.LoadOrCreateSigningKey()
		if err != nil {
			return InvestigateResult{}, err
		}
		l.Signer = key
	}

	sources := loop.Federated{loop.LocalSource{Store: st}}
	if req.CommonsTree != "" {
		gs, gerr := gitcommons.Open(req.CommonsTree)
		if gerr != nil {
			return InvestigateResult{}, fmt.Errorf("investigate: open git-native commons %s: %w", req.CommonsTree, gerr)
		}
		sources = append(sources, gs)
		l.Primer = loop.CommonsPrimer{Dir: req.CommonsTree}
	}
	if len(sources) == 1 {
		l.Source = sources[0]
	} else {
		l.Source = sources
	}

	seeds := append([]string(nil), prepared.Sources...)
	seeds = append(seeds, splitInvestigateCSV(req.SeedSource)...)
	var targetBinary string
	if len(seeds) == 0 && prepared.Base.Binary != "" {
		targetBinary = prepared.Base.Binary
	}

	useAnalyst := req.Analyst || (mode == "discover" && len(seeds) > 0)
	if req.Critic || useAnalyst {
		l.Critic = loop.ModelCritic{Model: am, Router: rt}
	}

	request := loop.Request{
		Objective:     objective,
		Mode:          mode,
		TargetRef:     prepared.Ref,
		TargetDesc:    prepared.Desc,
		Oracle:        prepared.Oracle,
		Base:          prepared.Base,
		Fixed:         prepared.Fixed,
		SeedFiles:     seeds,
		TargetBinary:  targetBinary,
		CPGPath:       req.CPGPath,
		Analyst:       useAnalyst,
		MaxIters:      req.MaxIters,
		MaxHypotheses: req.MaxHypotheses,
		MaxDepth:      req.MaxDepth,
		TokenBudget:   req.TokenBudget,
		StallLimit:    req.StallLimit,
		ContextBudget: req.ContextBudget,
		KeepRecent:    req.KeepRecent,
		Compactor:     req.Compactor,
	}

	var rep loop.Report
	if req.FuzzImage != "" && mode == "discover" {
		if req.FuzzSeeds == "" {
			return InvestigateResult{}, errors.New("investigate: fuzz_image requires fuzz_seeds (an initial seed corpus dir)")
		}
		rep, err = l.RunEnsemble(ctx, request, loop.FuzzLeg{
			Image: req.FuzzImage, SeedDir: req.FuzzSeeds, DictPath: req.FuzzDict,
			CmplogBin: req.FuzzCmplog, Budget: req.FuzzFor,
		})
	} else {
		rep, err = l.Run(ctx, request)
	}
	return investigateResultFrom(rep), err
}

func (e *Engine) resolveInvestigateTarget(req InvestigateRequest) (*target.Descriptor, string, error) {
	if req.TargetFile != "" {
		return target.Load(req.TargetFile)
	}
	spec, err := loadInvestigateOracle(req)
	if err != nil {
		return nil, "", err
	}
	argv := splitInvestigateArgv(req.Argv)
	d := &target.Descriptor{Name: "inline", Run: target.RunConfig{Argv: argv, Sanitizer: req.Sanitizer}, Oracle: spec}
	switch {
	case req.Bin != "":
		d.Ingest = target.Ingest{Kind: target.KindBinary, Binary: req.Bin}
		if len(argv) == 0 {
			d.Run.Argv = []string{req.Bin, "{poc}"}
		}
	case req.Image != "":
		d.Ingest = target.Ingest{Kind: target.KindImage, Image: req.Image}
		if len(argv) == 0 {
			return nil, "", errors.New("investigate: image requires argv (the in-container command, with {poc})")
		}
	default:
		return nil, "", errors.New("investigate: no target: pass target_file, or bin/image with an oracle")
	}
	return d, ".", nil
}

func loadInvestigateOracle(req InvestigateRequest) (oracle.Spec, error) {
	switch {
	case req.OracleFile != "":
		return oracle.Load(req.OracleFile)
	case req.OracleSpec != "":
		return oracle.ParseShortcut(req.OracleSpec)
	default:
		return oracle.Spec{}, errors.New("investigate: an oracle is required: pass oracle_spec or oracle_file (or a target_file with an oracle)")
	}
}

func (e *Engine) buildInvestigateModelRouter(lowBudgetTokens int) (model.Model, router.Router) {
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

func attachInvestigateToolProvisioner(prepared *target.Prepared, storeRoot string, extraAllow []string) error {
	if prepared == nil || prepared.Base.Toolset.Empty() {
		return nil
	}
	allow, err := toolctl.Allowlist(storeRoot)
	if err != nil {
		return fmt.Errorf("investigate: tool provisioning: %w", err)
	}
	for _, h := range extraAllow {
		if h = strings.TrimSpace(h); h != "" {
			allow = append(allow, h)
		}
	}
	ls := broker.NewLocalStore(storeRoot, allow)
	prepared.SetProvisioner(broker.NewProvisioner(ls))
	return nil
}

func defaultInvestigateObjective(mode string) string {
	if mode == "discover" {
		return "Find a memory-safety vulnerability reachable from untrusted input, and prove it with a PoV that satisfies the oracle."
	}
	return "Develop a proof-of-vulnerability for this target that satisfies the oracle."
}

func splitInvestigateArgv(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func splitInvestigateCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func investigateResultFrom(rep loop.Report) InvestigateResult {
	m := rep.Metrics()
	res := InvestigateResult{
		RunID:             rep.RunID,
		Confirmed:         rep.Confirmed,
		StopReason:        rep.StopReason,
		Hypotheses:        rep.Hypotheses,
		Iterations:        rep.Iterations,
		PoVSubmissions:    rep.PoVSubmissions,
		RuledOut:          rep.RuledOut,
		TotalTokens:       rep.Usage.TotalTokens,
		PromptTokens:      rep.Usage.PromptTokens,
		CompletionTokens:  rep.Usage.CompletionTokens,
		CostUSD:           rep.Usage.CostUSD,
		ElapsedMS:         m.Elapsed.Milliseconds(),
		Novel:             m.Novel,
		Rediscoveries:     m.Rediscoveries,
		TokensPerFinding:  m.TokensPerFinding,
		SecondsPerFinding: m.SecondsPerFinding,
		PriorArtHitRate:   m.PriorArtHitRate,
	}
	for _, f := range rep.Findings {
		fd := InvestigateFinding{Statement: f.Statement, Novel: f.Novel}
		if f.Private != nil {
			fd.PrivateID = f.Private.Artifact.ID
			fd.BugClass = f.Private.Artifact.Content.Crash.BugClass
			fd.IntegrityTier = string(f.Private.IntegrityTier())
			fd.Placement = string(f.Private.Placement)
			fd.BehavioralKey = f.Private.Artifact.BehavioralKey()
		}
		if f.Public != nil {
			fd.PublicID = f.Public.Artifact.ID
		}
		res.Findings = append(res.Findings, fd)
	}
	return res
}

func investigateArgs(req InvestigateRequest) string {
	tgt := req.TargetFile
	if tgt == "" {
		switch {
		case req.Bin != "":
			tgt = "bin:" + req.Bin
		case req.Image != "":
			tgt = "image:" + req.Image
		}
	}
	mode := req.Mode
	if mode == "" {
		mode = "copilot"
	}
	return fmt.Sprintf("mode:%s target:%s", mode, tgt)
}

func investigateSummary(res InvestigateResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.Confirmed {
		return fmt.Sprintf("CONFIRMED findings:%d", len(res.Findings))
	}
	if res.StopReason != "" {
		return "not-confirmed:" + res.StopReason
	}
	return "not-confirmed"
}

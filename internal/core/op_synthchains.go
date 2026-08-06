package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xjustus/quarry/internal/discover/loop"
	"github.com/0xjustus/quarry/internal/discover/synth"
	"github.com/0xjustus/quarry/internal/intake/chain"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
)

type SynthRequest struct {
	Caller          Caller   `json:"caller,omitempty"`
	SeedSources     []string `json:"seed_sources"`
	Objective       string   `json:"objective,omitempty"`
	TargetDesc      string   `json:"target_desc,omitempty"`
	EntryHint       string   `json:"entry_hint,omitempty"`
	BuildSystem     string   `json:"build_system,omitempty"`
	BaseImage       string   `json:"base_image,omitempty"`
	IncludeDirs     []string `json:"include_dirs,omitempty"`
	WithCmplog      bool     `json:"with_cmplog,omitempty"`
	OutDir          string   `json:"out_dir,omitempty"`
	StaticLibFuzz   string   `json:"static_lib_fuzz,omitempty"`
	StaticLibOracle string   `json:"static_lib_oracle,omitempty"`
	Validate        bool     `json:"validate,omitempty"`
	ImageTag        string   `json:"image_tag,omitempty"`
	MinEdges        int      `json:"min_edges,omitempty"`
}

type SynthValidation struct {
	Built        bool   `json:"built"`
	SmokePass    bool   `json:"smoke_pass"`
	Edges        int    `json:"edges"`
	CoveragePass bool   `json:"coverage_pass"`
	OK           bool   `json:"ok"`
	Reason       string `json:"reason,omitempty"`
}

type SynthResult struct {
	Entry       string           `json:"entry"`
	Model       string           `json:"model,omitempty"`
	HarnessC    string           `json:"harness_c"`
	Dockerfile  string           `json:"dockerfile"`
	Includes    []string         `json:"includes,omitempty"`
	HarnessPath string           `json:"harness_path,omitempty"`
	DockerPath  string           `json:"dockerfile_path,omitempty"`
	Validated   *SynthValidation `json:"validated,omitempty"`
}

func (e *Engine) Synth(ctx context.Context, req SynthRequest) (SynthResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Synth", audit.KindCall, fmt.Sprintf("seeds:%s validate:%v", strings.Join(req.SeedSources, ","), req.Validate))
	res, err := e.synth(ctx, log, req)
	sp.End(synthSummary(res, err), err)
	return res, err
}

func (e *Engine) synth(ctx context.Context, log audit.Recorder, req SynthRequest) (SynthResult, error) {
	if len(req.SeedSources) == 0 {
		return SynthResult{}, fmt.Errorf("synth: seed_sources is required (target source dir[s])")
	}
	if req.Validate && (req.StaticLibFuzz == "" || req.StaticLibOracle == "") {
		return SynthResult{}, fmt.Errorf("synth: validate requires static_lib_fuzz and static_lib_oracle to build")
	}

	mdl, rt := e.modelRouterForSynth()
	planner := synth.Planner{Model: auditedModel{inner: mdl, log: log}, Router: rt}

	inventory := loop.SourceInventory(req.SeedSources)
	pres, err := planner.Plan(ctx, synth.Request{
		Objective:       req.Objective,
		TargetDesc:      req.TargetDesc,
		SourceInventory: inventory,
		EntryHint:       req.EntryHint,
		BuildSystem:     req.BuildSystem,
	})
	if err != nil {
		return SynthResult{}, fmt.Errorf("synth: harness synthesis failed: %w", err)
	}

	dockerfile := synth.RenderDockerfile(synth.BuildSpec{
		BaseImage:       req.BaseImage,
		BuildSystem:     req.BuildSystem,
		Spec:            pres.Spec,
		IncludeDirs:     req.IncludeDirs,
		StaticLibFuzz:   req.StaticLibFuzz,
		StaticLibOracle: req.StaticLibOracle,
		WithCmplog:      req.WithCmplog,
	})

	out := SynthResult{
		Entry: pres.Spec.Entry, Model: pres.Model,
		HarnessC: pres.HarnessC, Dockerfile: dockerfile, Includes: pres.Spec.Includes,
	}

	outDir := req.OutDir
	if outDir == "" {
		outDir = req.SeedSources[0]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return SynthResult{}, err
	}
	harnessPath := filepath.Join(outDir, "harness.c")
	dockerPath := filepath.Join(outDir, "Dockerfile.quarry")
	if err := os.WriteFile(harnessPath, []byte(pres.HarnessC), 0o644); err != nil {
		return SynthResult{}, err
	}
	if err := os.WriteFile(dockerPath, []byte(dockerfile), 0o644); err != nil {
		return SynthResult{}, err
	}
	out.HarnessPath, out.DockerPath = harnessPath, dockerPath

	if req.Validate {
		imageTag := req.ImageTag
		if imageTag == "" {
			imageTag = "quarry-synth:latest"
		}
		vr, verr := synth.Validate(ctx, synth.ValidateSpec{
			ContextDir: req.SeedSources[0], Dockerfile: dockerfile, HarnessC: pres.HarnessC,
			ImageTag: imageTag, DockerBin: e.cfg.DockerBin, MinEdges: req.MinEdges,
		})
		if verr != nil {
			return SynthResult{}, fmt.Errorf("synth: validate: %w", verr)
		}
		out.Validated = &SynthValidation{
			Built: vr.Built, SmokePass: vr.SmokePass, Edges: vr.Edges,
			CoveragePass: vr.CoveragePass, OK: vr.OK(), Reason: vr.Reason,
		}
	}
	return out, nil
}

func (e *Engine) modelRouterForSynth() (model.Model, router.Router) {
	cheap := model.New(e.cfg.ResolvedProvider(), e.cfg.ModelBaseURL(), e.cfg.APIKey)
	if e.cfg.StrongModel == "" {
		return cheap, router.NewStaticRouter(e.cfg.Model)
	}
	strong := cheap
	if e.cfg.StrongTransportDiffers() {
		strong = model.New(e.cfg.StrongResolvedProvider(), e.cfg.StrongModelBaseURL(), e.cfg.StrongAPIKey())
	}
	mdl := model.NewMultiModel(cheap).Register(e.cfg.Model, cheap).Register(e.cfg.StrongModel, strong)
	return mdl, router.NewTieredRouter(e.cfg.Model, e.cfg.StrongModel)
}

func synthSummary(res SynthResult, err error) string {
	if err != nil {
		return "error"
	}
	s := "entry:" + res.Entry
	if res.Validated != nil {
		if res.Validated.OK {
			s += " validated:ACCEPTED"
		} else {
			s += " validated:REJECTED"
		}
	}
	return s
}

type ChainsRequest struct {
	Caller Caller `json:"caller,omitempty"`
	Tree   string `json:"tree"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

type ChainTransition struct {
	Index      int    `json:"index"`
	Pre        string `json:"pre"`
	Post       string `json:"post"`
	Technique  string `json:"technique"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Grounding  string `json:"grounding"`
}

type ChainsResult struct {
	Artifacts   int               `json:"artifacts"`
	Primitives  map[string]int    `json:"primitives,omitempty"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Found       bool              `json:"found"`
	ChainID     string            `json:"chain_id,omitempty"`
	Transitions []ChainTransition `json:"transitions,omitempty"`
}

func (e *Engine) Chains(ctx context.Context, req ChainsRequest) (ChainsResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	from, to := req.From, req.To
	if from == "" {
		from = chain.CapInputReachable
	}
	if to == "" {
		to = chain.CapCodeExecution
	}
	sp := log.Start("core.Chains", audit.KindAccess, fmt.Sprintf("tree:%s %s->%s", req.Tree, from, to))
	res, err := e.chains(req.Tree, from, to)
	sp.End(chainsSummary(res, err), err)
	return res, err
}

func (e *Engine) chains(tree, from, to string) (ChainsResult, error) {
	if tree == "" {
		return ChainsResult{}, fmt.Errorf("chains: tree is required (a pulled quarry-commons tree)")
	}
	envs, err := gitcommons.LoadEnvelopes(tree)
	if err != nil {
		return ChainsResult{}, err
	}
	if len(envs) == 0 {
		return ChainsResult{}, fmt.Errorf("chains: no artifacts/ in %s (is it a quarry-commons tree?)", tree)
	}
	facts := make([]chain.ArtifactFact, 0, len(envs))
	classes := map[string]int{}
	for _, en := range envs {
		f := chain.FactFromEnvelope(en)
		facts = append(facts, f)
		classes[chain.PrimitiveForBugClass(f.BugClass).Class]++
	}
	g := chain.BuildGraph(facts)

	res := ChainsResult{Artifacts: len(facts), Primitives: classes, From: from, To: to}
	syn, ok := g.Synthesize(chain.Cap(from), chain.Cap(to))
	if !ok {
		return res, nil
	}
	res.Found = true
	res.ChainID = syn.ID()
	for i, t := range syn.Transitions {
		grounding := "modeled"
		if t.Verified != "" {
			grounding = t.Verified
		}
		res.Transitions = append(res.Transitions, ChainTransition{
			Index: i + 1, Pre: t.Pre.Class, Post: t.Post.Class,
			Technique: t.Technique.Name, ArtifactID: t.Technique.ArtifactID, Grounding: grounding,
		})
	}
	return res, nil
}

func chainsSummary(res ChainsResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.Found {
		return fmt.Sprintf("PATH:%d-edges", len(res.Transitions))
	}
	return "no-path"
}

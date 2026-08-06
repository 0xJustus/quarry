package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/discover/binfuzz"
	"github.com/0xjustus/quarry/internal/discover/binnav"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/fly"
)

func resolveFly(app, token string) (fly.Client, error) {
	if app == "" {
		app = os.Getenv("FLY_APP")
	}
	if app == "" {
		app = "quarry-vetd"
	}
	if token == "" {
		token = os.Getenv("FLY_API_TOKEN")
	}
	if token == "" {
		return fly.Client{}, fmt.Errorf("fly token is required (binary-mode QEMU fuzzing runs on a native x86-64 Fly Machine; set FLY_API_TOKEN or pass fly_token)")
	}
	return fly.Client{App: app, Token: token}, nil
}

func readSeedDir(dir string) (map[string][]byte, error) {
	if dir == "" {
		return nil, fmt.Errorf("seeds_dir is required")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read seeds_dir: %w", err)
	}
	seeds := map[string][]byte{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return nil, rerr
		}
		seeds[e.Name()] = b
	}
	if len(seeds) == 0 {
		return nil, fmt.Errorf("seeds_dir %q has no seed files", dir)
	}
	return seeds, nil
}

func binfuzzDispatch(ctx context.Context, log audit.Recorder, cl fly.Client, image string, guest fly.Guest, spec binfuzz.Spec, wait time.Duration) (int, fly.Machine, error) {

	if err := cl.EnsureEgressDenyPolicy(ctx); err != nil {
		return binfuzz.ExitError, fly.Machine{}, fmt.Errorf("contain the fuzz target: %w", err)
	}
	sp := log.Start("fly.RunOneshot", audit.KindSideEffect, fmt.Sprintf("app:%s image:%s cpus:%d mem:%d", cl.App, image, guest.CPUs, guest.MemoryMB))
	code, m, err := binfuzz.RunOnFly(ctx, cl, image, guest, spec, wait)
	sp.End(fmt.Sprintf("exit:%d machine:%s", code, m.ID), err)
	return code, m, err
}

func (e *Engine) binnavAnalyze(ctx context.Context, log audit.Recorder, binPath, image string) (*binnav.Nav, error) {
	abs, err := filepath.Abs(binPath)
	if err != nil {
		return nil, err
	}
	sp := log.Start("binnav.analyze", audit.KindSideEffect, "bin:"+abs+" image:"+image)
	nav, err := binnav.Run(ctx, abs, e.cfg.DockerBin, image)
	if err != nil {
		sp.End("error", err)
		return nil, err
	}
	sp.End(fmt.Sprintf("funcs:%d sinks:%d inputs:%d", len(nav.Funcs), len(nav.Sinks), len(nav.Inputs)), nil)
	return nav, nil
}

func navResult(nav *binnav.Nav, top int) BinnavResult {
	if top <= 0 {
		top = 12
	}
	dirs := nav.Directors()
	res := BinnavResult{
		Funcs: len(nav.Funcs), SinkFns: len(nav.Sinks), InputFns: len(nav.Inputs),
		Warnings: nav.Warnings(),
	}
	shown := dirs
	if len(shown) > top {
		shown = shown[:top]
	}
	for _, t := range shown {
		res.Directors = append(res.Directors, BinnavTarget{
			Addr: t.Func.Addr, Name: t.Func.Name, Score: t.Score,
			SinksCalled: t.SinksCalled, HandlesInput: t.HandlesInput, ReachableFromIn: t.ReachableFromIn,
		})
	}
	return res
}

type BinfuzzRequest struct {
	Caller         Caller   `json:"caller,omitempty"`
	SourceC        []byte   `json:"source_c,omitempty"`
	Binary         []byte   `json:"binary,omitempty"`
	SeedsDir       string   `json:"seeds_dir"`
	Dict           []byte   `json:"dict,omitempty"`
	Argv           []string `json:"argv,omitempty"`
	QASan          bool     `json:"qasan,omitempty"`
	Cmplog         bool     `json:"cmplog,omitempty"`
	PersistentAddr string   `json:"persistent_addr,omitempty"`
	BudgetS        int      `json:"budget_s,omitempty"`
	FlyApp         string   `json:"fly_app,omitempty"`
	FlyToken       string   `json:"fly_token,omitempty"`
	Image          string   `json:"image,omitempty"`
	MemoryMB       int      `json:"memory_mb,omitempty"`
	CPUs           int      `json:"cpus,omitempty"`
}

type BinfuzzResult struct {
	Confirmed bool   `json:"confirmed"`
	ExitCode  int    `json:"exit_code"`
	Verdict   string `json:"verdict"`
	MachineID string `json:"machine_id,omitempty"`
}

func (e *Engine) Binfuzz(ctx context.Context, req BinfuzzRequest) (BinfuzzResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	tgt := "bin:" + digest(req.Binary)
	if len(req.SourceC) > 0 {
		tgt = "source-c:" + digest(req.SourceC)
	}
	sp := log.Start("core.Binfuzz", audit.KindCall, fmt.Sprintf("%s seeds:%s budget:%ds", tgt, req.SeedsDir, req.BudgetS))
	res, err := e.binfuzz(ctx, log, req)
	sp.End(fmt.Sprintf("exit:%d confirmed:%v", res.ExitCode, res.Confirmed), err)
	return res, err
}

func (e *Engine) binfuzz(ctx context.Context, log audit.Recorder, req BinfuzzRequest) (BinfuzzResult, error) {
	if (len(req.SourceC) == 0) == (len(req.Binary) == 0) {
		return BinfuzzResult{}, fmt.Errorf("binfuzz: pass exactly one of source_c or binary")
	}
	budget := req.BudgetS
	if budget <= 0 {
		budget = 120
	}
	spec := binfuzz.Spec{
		Argv: req.Argv, BudgetS: budget, QASan: req.QASan, Cmplog: req.Cmplog,
		PersistentAddr: req.PersistentAddr,
	}
	if len(req.SourceC) > 0 {
		spec.SourceC = string(req.SourceC)
	} else {
		spec.BinaryB64 = binfuzz.GzB64(req.Binary)
	}
	seeds, err := readSeedDir(req.SeedsDir)
	if err != nil {
		return BinfuzzResult{}, fmt.Errorf("binfuzz: %w", err)
	}
	spec.Seeds = seeds
	for _, line := range strings.Split(strings.TrimRight(string(req.Dict), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			spec.Dict = append(spec.Dict, line)
		}
	}

	cl, err := resolveFly(req.FlyApp, req.FlyToken)
	if err != nil {
		return BinfuzzResult{}, fmt.Errorf("binfuzz: %w", err)
	}
	mem, cpus := req.MemoryMB, req.CPUs
	if mem <= 0 {
		mem = 4096
	}
	if cpus <= 0 {
		cpus = 4
	}
	guest := fly.Guest{CPUKind: "shared", CPUs: cpus, MemoryMB: mem}
	image := req.Image
	wait := time.Duration(budget)*time.Second + 6*time.Minute

	code, m, err := binfuzzDispatch(ctx, log, cl, image, guest, spec, wait)
	if err != nil {
		return BinfuzzResult{ExitCode: code, MachineID: m.ID}, fmt.Errorf("binfuzz: %w (machine %s)", err, m.ID)
	}
	return BinfuzzResult{
		Confirmed: code == binfuzz.ExitConfirmed, ExitCode: code,
		Verdict: binfuzz.VerdictString(code), MachineID: m.ID,
	}, nil
}

type BinnavRequest struct {
	Caller  Caller `json:"caller,omitempty"`
	BinPath string `json:"bin_path"`
	Image   string `json:"image,omitempty"`
	Top     int    `json:"top,omitempty"`
}

type BinnavTarget struct {
	Addr            uint64   `json:"addr"`
	Name            string   `json:"name"`
	Score           int      `json:"score"`
	SinksCalled     []string `json:"sinks_called"`
	HandlesInput    bool     `json:"handles_input"`
	ReachableFromIn bool     `json:"reachable_from_input"`
}

type BinnavResult struct {
	Funcs     int            `json:"funcs"`
	SinkFns   int            `json:"sink_funcs"`
	InputFns  int            `json:"input_funcs"`
	Directors []BinnavTarget `json:"directors"`
	Warnings  []string       `json:"warnings,omitempty"`
}

func (e *Engine) Binnav(ctx context.Context, req BinnavRequest) (BinnavResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Binnav", audit.KindAccess, "bin:"+req.BinPath)
	res, err := e.binnav(ctx, log, req)
	sp.End(fmt.Sprintf("funcs:%d directors:%d", res.Funcs, len(res.Directors)), err)
	return res, err
}

func (e *Engine) binnav(ctx context.Context, log audit.Recorder, req BinnavRequest) (BinnavResult, error) {
	if req.BinPath == "" {
		return BinnavResult{}, fmt.Errorf("binnav: bin_path is required")
	}
	nav, err := e.binnavAnalyze(ctx, log, req.BinPath, req.Image)
	if err != nil {
		return BinnavResult{}, fmt.Errorf("binnav: %w", err)
	}
	return navResult(nav, req.Top), nil
}

type BindiscoRequest struct {
	Caller   Caller   `json:"caller,omitempty"`
	BinPath  string   `json:"bin_path"`
	SeedsDir string   `json:"seeds_dir"`
	Argv     []string `json:"argv,omitempty"`
	BudgetS  int      `json:"budget_s,omitempty"`
	QASan    bool     `json:"qasan,omitempty"`
	Cmplog   bool     `json:"cmplog,omitempty"`
	NavImage string   `json:"nav_image,omitempty"`
	Image    string   `json:"image,omitempty"`
	FlyApp   string   `json:"fly_app,omitempty"`
	FlyToken string   `json:"fly_token,omitempty"`
	MemoryMB int      `json:"memory_mb,omitempty"`
	CPUs     int      `json:"cpus,omitempty"`
}

type BindiscoResult struct {
	Nav         BinnavResult `json:"nav"`
	Confirmed   bool         `json:"confirmed"`
	ExitCode    int          `json:"exit_code"`
	Verdict     string       `json:"verdict"`
	MachineID   string       `json:"machine_id,omitempty"`
	Attribution string       `json:"attribution,omitempty"`
}

func (e *Engine) Bindisco(ctx context.Context, req BindiscoRequest) (BindiscoResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Bindisco", audit.KindCall, fmt.Sprintf("bin:%s seeds:%s budget:%ds", req.BinPath, req.SeedsDir, req.BudgetS))
	res, err := e.bindisco(ctx, log, req)
	sp.End(fmt.Sprintf("exit:%d confirmed:%v", res.ExitCode, res.Confirmed), err)
	return res, err
}

func (e *Engine) bindisco(ctx context.Context, log audit.Recorder, req BindiscoRequest) (BindiscoResult, error) {
	if req.BinPath == "" || req.SeedsDir == "" {
		return BindiscoResult{}, fmt.Errorf("bindisco: bin_path and seeds_dir are required")
	}
	absBin, err := filepath.Abs(req.BinPath)
	if err != nil {
		return BindiscoResult{}, err
	}
	cl, err := resolveFly(req.FlyApp, req.FlyToken)
	if err != nil {
		return BindiscoResult{}, fmt.Errorf("bindisco: %w", err)
	}

	nav, err := e.binnavAnalyze(ctx, log, absBin, req.NavImage)
	if err != nil {
		return BindiscoResult{}, fmt.Errorf("bindisco: nav: %w", err)
	}
	dirs := nav.Directors()
	out := BindiscoResult{Nav: navResult(nav, 0)}

	b, err := os.ReadFile(absBin)
	if err != nil {
		return out, err
	}
	seeds, err := readSeedDir(req.SeedsDir)
	if err != nil {
		return out, fmt.Errorf("bindisco: %w", err)
	}
	budget := req.BudgetS
	if budget <= 0 {
		budget = 180
	}
	spec := binfuzz.Spec{
		BinaryB64: binfuzz.GzB64(b), Argv: req.Argv,
		BudgetS: budget, QASan: req.QASan, Cmplog: req.Cmplog, Seeds: seeds,
	}
	mem, cpus := req.MemoryMB, req.CPUs
	if mem <= 0 {
		mem = 4096
	}
	if cpus <= 0 {
		cpus = 4
	}
	guest := fly.Guest{CPUKind: "shared", CPUs: cpus, MemoryMB: mem}

	code, m, err := binfuzzDispatch(ctx, log, cl, req.Image, guest, spec, time.Duration(budget)*time.Second+6*time.Minute)
	if err != nil {
		out.ExitCode, out.MachineID = code, m.ID
		return out, fmt.Errorf("bindisco: fuzz: %w (machine %s)", err, m.ID)
	}
	out.ExitCode, out.MachineID = code, m.ID
	out.Confirmed = code == binfuzz.ExitConfirmed
	out.Verdict = binfuzz.VerdictString(code)
	if out.Confirmed && len(dirs) > 0 {
		out.Attribution = fmt.Sprintf("the crash is in the binary the director flagged; the top sink-reaching function 0x%x (%s, sinks=[%s]) is the prime suspect for the fault site",
			dirs[0].Func.Addr, dirs[0].Func.Name, strings.Join(dirs[0].SinksCalled, ","))
	}
	return out, nil
}

package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/verdict/minimize"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

type MinimizeRequest struct {
	Caller     Caller `json:"caller,omitempty"`
	TargetFile string `json:"target_file,omitempty"`
	Bin        string `json:"bin,omitempty"`
	Image      string `json:"image,omitempty"`
	Argv       string `json:"argv,omitempty"`
	Sanitizer  string `json:"sanitizer,omitempty"`
	PoV        []byte `json:"pov"`
	TimeoutS   int    `json:"timeout_s,omitempty"`
	MaxRuns    int    `json:"max_runs,omitempty"`
}

type MinimizeResult struct {
	OriginalSize  int    `json:"original_size"`
	ReducedSize   int    `json:"reduced_size"`
	Removed       int    `json:"removed_bytes"`
	Runs          int    `json:"runs"`
	BehavioralKey string `json:"behavioral_key"`
	FrameLess     bool   `json:"frame_less,omitempty"`
	Minimized     []byte `json:"minimized,omitempty"`
}

func (e *Engine) Minimize(ctx context.Context, req MinimizeRequest) (MinimizeResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Minimize", audit.KindCall, minimizeArgs(req))
	res, err := e.minimize(ctx, log, req)
	sp.End(minimizeSummary(res, err), err)
	return res, err
}

func (e *Engine) minimize(ctx context.Context, log audit.Recorder, req MinimizeRequest) (MinimizeResult, error) {
	if len(req.PoV) == 0 {
		return MinimizeResult{}, fmt.Errorf("minimize: pov is required")
	}
	if req.TargetFile == "" && req.Bin == "" && req.Image == "" {
		return MinimizeResult{}, fmt.Errorf("minimize: pass target_file (quarry.yaml), or bin/image (with argv for image)")
	}
	desc, baseDir, err := minimizeResolveTarget(req)
	if err != nil {
		return MinimizeResult{}, err
	}
	prepared, err := target.Prepare(ctx, desc, baseDir, e.cfg.DockerBin)
	if err != nil {
		return MinimizeResult{}, err
	}
	res, err := minimize.Minimize(ctx, auditedRunner{inner: prepared.Runner, log: log}, prepared.Oracle, prepared.Base, req.PoV, minimize.Options{MaxRuns: req.MaxRuns, Fixed: prepared.Fixed})
	if err != nil {
		return MinimizeResult{}, fmt.Errorf("minimize: %w", err)
	}
	return MinimizeResult{
		OriginalSize:  res.OriginalSize,
		ReducedSize:   res.ReducedSize,
		Removed:       res.OriginalSize - res.ReducedSize,
		Runs:          res.Runs,
		BehavioralKey: res.BehavioralKey,
		FrameLess:     res.FrameLess,
		Minimized:     res.Minimized,
	}, nil
}

func minimizeResolveTarget(req MinimizeRequest) (*target.Descriptor, string, error) {
	if req.TargetFile != "" {
		return target.Load(req.TargetFile)
	}
	san := req.Sanitizer
	if san == "" {
		san = "asan"
	}
	timeoutS := req.TimeoutS
	if timeoutS <= 0 {
		timeoutS = 20
	}
	av := minimizeSplitArgv(req.Argv)
	desc := &target.Descriptor{
		Name:   "minimize",
		Run:    target.RunConfig{Argv: av, Sanitizer: san, TimeoutS: timeoutS},
		Oracle: minimizeAnyCrashOracle(),
	}
	switch {
	case req.Bin != "":
		desc.Ingest = target.Ingest{Kind: target.KindBinary, Binary: req.Bin}
		if len(av) == 0 {
			desc.Run.Argv = []string{req.Bin, "{poc}"}
		}
	case req.Image != "":
		desc.Ingest = target.Ingest{Kind: target.KindImage, Image: req.Image}
		if len(av) == 0 {
			return nil, "", fmt.Errorf("minimize: image needs argv (the in-container command, with {poc})")
		}
	}
	return desc, ".", nil
}

func minimizeAnyCrashOracle() oracle.Spec {
	return oracle.Spec{Require: "any", Conditions: []oracle.Condition{
		{Type: oracle.CondSanitizer, Tool: "asan"},
		{Type: oracle.CondSignal, Signals: []string{"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL"}},
		{Type: oracle.CondTimeout},
	}}
}

func minimizeSplitArgv(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func minimizeArgs(req MinimizeRequest) string {
	tgt := "target:" + req.TargetFile
	if req.TargetFile == "" {
		switch {
		case req.Bin != "":
			tgt = "bin:" + req.Bin
		case req.Image != "":
			tgt = "image:" + req.Image
		}
	}
	return tgt + " pov:" + digest(req.PoV)
}

func minimizeSummary(res MinimizeResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.FrameLess {
		return "frame-less (not reduced)"
	}
	return fmt.Sprintf("%d->%d bytes in %d runs", res.OriginalSize, res.ReducedSize, res.Runs)
}

package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/fly"
	"github.com/0xjustus/quarry/internal/publish/autovet"
	"github.com/0xjustus/quarry/internal/verdict/exploit"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

func (e *Engine) gradeCrashOnFly(ctx context.Context, log audit.Recorder, bin, pov []byte, app, image string) (exploit.Assessment, error) {
	if app == "" {
		app = "quarry-vetd"
	}
	if image == "" {
		image = "aflplusplus/aflplusplus:latest"
	}
	token := os.Getenv("FLY_API_TOKEN")
	if token == "" {
		return exploit.Assessment{}, fmt.Errorf("crash-grade: FLY_API_TOKEN is required (gdb marker-injection runs on a native x86-64 Fly Machine)")
	}
	cl := fly.Client{App: app, Token: token}
	guest := fly.Guest{CPUKind: "shared", CPUs: 1, MemoryMB: 1024}
	esp := log.Start("fly.grade", audit.KindSideEffect, fmt.Sprintf("app:%s image:%s bin:%s pov:%s", app, image, digest(bin), digest(pov)))
	a, err := exploit.FlyGrade(ctx, cl, image, guest, bin, pov, 6*time.Minute)
	esp.End("grade:"+a.Grade.String(), err)
	return a, err
}

type DispatchRequest struct {
	Caller        Caller   `json:"caller,omitempty"`
	TargetFile    string   `json:"target_file,omitempty"`
	Bin           []byte   `json:"bin,omitempty"`
	InImageBinary string   `json:"in_image_binary,omitempty"`
	Argv          []string `json:"argv,omitempty"`
	Sanitizer     string   `json:"sanitizer,omitempty"`
	NoPoV         bool     `json:"nopov,omitempty"`
	PoV           []byte   `json:"pov,omitempty"`
	FlyApp        string   `json:"fly_app,omitempty"`
	FlyImage      string   `json:"fly_image,omitempty"`
	MemoryMB      int      `json:"memory_mb,omitempty"`
	TimeoutS      int      `json:"timeout_s,omitempty"`
}

type DispatchResult struct {
	Verdict   string `json:"verdict"`
	Admitted  bool   `json:"admitted"`
	MachineID string `json:"machine_id,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Detail    string `json:"detail,omitempty"`
}

func (e *Engine) Dispatch(ctx context.Context, req DispatchRequest) (DispatchResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sel := "target:" + req.TargetFile
	if req.Bin != nil {
		sel = "bin:" + digest(req.Bin)
	}
	if req.InImageBinary != "" {
		sel = "in-image:" + req.InImageBinary
	}
	sp := log.Start("core.Dispatch", audit.KindCall, fmt.Sprintf("%s pov:%s nopov:%v", sel, digest(req.PoV), req.NoPoV))
	res, err := e.dispatch(ctx, log, req)
	sp.End(dispatchSummary(res, err), err)
	return res, err
}

func (e *Engine) dispatch(ctx context.Context, log audit.Recorder, req DispatchRequest) (DispatchResult, error) {
	token := os.Getenv("FLY_API_TOKEN")
	if token == "" {
		return DispatchResult{}, fmt.Errorf("dispatch: FLY_API_TOKEN is required")
	}
	if len(req.PoV) == 0 && !req.NoPoV {
		return DispatchResult{}, fmt.Errorf("dispatch: pov is required (or set nopov for a self-contained reproducer)")
	}
	if req.TargetFile == "" && req.Bin == nil && req.InImageBinary == "" {
		return DispatchResult{}, fmt.Errorf("dispatch: pass target_file, bin, or in_image_binary")
	}

	san := req.Sanitizer
	if san == "" {
		san = "asan"
	}
	vetReq, err := buildDispatchVetRequest(req, san)
	if err != nil {
		return DispatchResult{}, err
	}

	app := req.FlyApp
	if app == "" {
		app = "quarry-vetd"
	}
	image := req.FlyImage
	if image == "" {
		image = "registry.fly.io/quarry-vetd:latest"
	}
	mem := req.MemoryMB
	if mem <= 0 {
		mem = 512
	}
	timeoutS := req.TimeoutS
	if timeoutS <= 0 {
		timeoutS = 120
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutS+60)*time.Second)
	defer cancel()

	cl := fly.Client{App: app, Token: token}
	if err := cl.EnsureEgressDenyPolicy(runCtx); err != nil {
		return DispatchResult{}, fmt.Errorf("dispatch: %w", err)
	}

	esp := log.Start("fly.dispatch", audit.KindSideEffect, fmt.Sprintf("app:%s image:%s mem:%d timeout:%ds", app, image, mem, timeoutS))
	code, m, err := dispatchOnce(runCtx, cl, image, mem, vetReq, time.Duration(timeoutS)*time.Second)
	esp.End(fmt.Sprintf("machine:%s exit:%d", m.ID, code), err)
	if err != nil {
		return DispatchResult{}, fmt.Errorf("dispatch: %w", err)
	}

	st, detail := dispatchOutcome(code)
	out := DispatchResult{ExitCode: code, MachineID: m.ID, Detail: detail}
	switch st {
	case autovet.StatusAdmitted:
		out.Verdict, out.Admitted = "admitted", true
	case autovet.StatusRejected:
		out.Verdict = "rejected"
	default:
		out.Verdict = "error"
	}
	return out, nil
}

func dispatchOutcome(code int) (autovet.Status, string) {
	switch code {
	case 0:
		return autovet.StatusAdmitted, "oracle-confirmed on an air-gapped Machine; auto-destroyed"
	case 3:
		return autovet.StatusRejected, "the candidate did not reproduce on re-execution"
	default:
		return autovet.StatusInconclusive, fmt.Sprintf("vetd exited %d (request/infra error, or the VM was killed): nothing was observed, so this is NOT a rejection", code)
	}
}

func buildDispatchVetRequest(req DispatchRequest, san string) ([]byte, error) {
	run := map[string]any{"sanitizer": san}
	var spec oracle.Spec

	switch {
	case req.InImageBinary != "":
		spec = anyCrashOracleSpec()
		run["binary"] = req.InImageBinary
		run["argv"] = req.Argv
	case req.TargetFile != "":
		d, baseDir, err := target.Load(req.TargetFile)
		if err != nil {
			return nil, err
		}
		if d.Ingest.Kind != target.KindBinary {
			return nil, fmt.Errorf("dispatch: target_file supports only binary targets here; use in_image_binary for image/ARVO targets")
		}
		if d.Oracle.Differential != nil {
			return nil, fmt.Errorf("dispatch: target %q declares a differential oracle; the vet job cannot carry the reference (fixed) build, so the substrate cannot judge it — verify it locally with core.Verify", d.Name)
		}
		spec = d.Oracle
		run["argv"] = d.Run.Argv
		if d.Run.Sanitizer != "" {
			run["sanitizer"] = d.Run.Sanitizer
		}
		if d.Run.StdinPoV {
			run["stdin_pov"] = true
		}
		if d.Run.NoPoV {
			run["nopov"] = true
		}
		if d.Run.TimeoutS > 0 {
			run["timeout_s"] = d.Run.TimeoutS
		}
		raw, err := os.ReadFile(filepath.Join(baseDir, d.Ingest.Binary))
		if err != nil {
			return nil, fmt.Errorf("dispatch: read target binary: %w", err)
		}
		run["target_b64"] = base64.StdEncoding.EncodeToString(raw)
	case req.Bin != nil:
		spec = anyCrashOracleSpec()
		argvTmpl := req.Argv
		if len(argvTmpl) == 0 {
			argvTmpl = []string{"target", "{poc}"}
		}
		run["argv"] = argvTmpl
		run["target_b64"] = base64.StdEncoding.EncodeToString(req.Bin)
	}
	if req.NoPoV {
		run["nopov"] = true
	}

	vr := map[string]any{
		"artifact_id": "dispatch",
		"oracle":      spec,
		"run":         run,
		"pov_b64":     base64.StdEncoding.EncodeToString(req.PoV),
	}
	b, err := json.Marshal(vr)
	if err != nil {
		return nil, err
	}
	if len(b) > 900_000 {
		return nil, fmt.Errorf("dispatch: vet job is %d bytes; too large to inline via env (use in_image_binary with a baked image)", len(b))
	}
	return b, nil
}

func anyCrashOracleSpec() oracle.Spec {
	return oracle.Spec{Require: "any", Conditions: []oracle.Condition{
		{Type: oracle.CondSanitizer, Tool: "asan"},
		{Type: oracle.CondSignal, Signals: []string{"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL"}},
		{Type: oracle.CondTimeout},
	}}
}

func dispatchOnce(ctx context.Context, cl fly.Client, flyImage string, memMB int, vetReq []byte, timeout time.Duration) (int, fly.Machine, error) {
	cfg := fly.MachineConfig{
		Image: flyImage,
		Env:   map[string]string{"QUARRY_VET_REQUEST_B64": base64.StdEncoding.EncodeToString(vetReq)},
		Guest: fly.Guest{CPUKind: "shared", CPUs: 1, MemoryMB: memMB},
	}
	return cl.RunOneshot(ctx, cfg, timeout)
}

func dispatchSummary(res DispatchResult, err error) string {
	if err != nil {
		return "error"
	}
	return res.Verdict
}

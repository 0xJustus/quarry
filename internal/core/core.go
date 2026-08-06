package core

import (
	"context"
	"fmt"

	"github.com/0xjustus/quarry/internal/intake/target"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/config"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type Engine struct {
	cfg   config.Config
	audit *audit.Log
}

func New(cfg config.Config, log *audit.Log) (*Engine, error) {
	if log == nil {
		return nil, fmt.Errorf("core: an audit log is required (pass audit.NewWriter(io.Discard) to opt out explicitly)")
	}
	return &Engine{cfg: cfg, audit: log}, nil
}

func (e *Engine) Audit() *audit.Log { return e.audit }

func (e *Engine) logFor(principal, session string) audit.Recorder {
	if principal == "" && session == "" {
		return e.audit
	}
	return e.audit.Sub(principal, session)
}

type Caller struct {
	Principal string `json:"principal,omitempty"`
	Session   string `json:"session,omitempty"`
}

type VerifyRequest struct {
	Caller         Caller `json:"caller,omitempty"`
	TargetFile     string `json:"target_file"`
	PoV            []byte `json:"pov"`
	Reruns         int    `json:"reruns,omitempty"`
	IsolateNetwork bool   `json:"isolate_network,omitempty"`
}

type VerifyResult struct {
	Confirmed bool           `json:"confirmed"`
	Verdict   oracle.Verdict `json:"verdict"`
}

func (e *Engine) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Verify", audit.KindCall, "target:"+req.TargetFile+" pov:"+digest(req.PoV))
	res, err := e.verify(ctx, log, req)
	sp.End(verifySummary(res, err), err)
	return res, err
}

func (e *Engine) verify(ctx context.Context, log audit.Recorder, req VerifyRequest) (VerifyResult, error) {
	if req.TargetFile == "" {
		return VerifyResult{}, fmt.Errorf("verify: target_file is required")
	}
	if len(req.PoV) == 0 {
		return VerifyResult{}, fmt.Errorf("verify: pov is required")
	}
	desc, baseDir, err := target.Load(req.TargetFile)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verify: load target: %w", err)
	}
	prepared, err := target.Prepare(ctx, desc, baseDir, e.cfg.DockerBin)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verify: prepare: %w", err)
	}
	if req.IsolateNetwork {
		prepared.Base.IsolateNetwork = true
		if prepared.Fixed != nil {
			prepared.Fixed.IsolateNetwork = true
		}
	}
	v := &verify.Verifier{Runner: auditedRunner{inner: prepared.Runner, log: log}}
	r, err := v.Verify(ctx, verify.Request{
		Model: "verify", Spec: prepared.Oracle, Base: prepared.Base, Fixed: prepared.Fixed,
		PoV: req.PoV, Reruns: req.Reruns,
	})
	if err != nil {
		return VerifyResult{}, fmt.Errorf("verify: run: %w", err)
	}
	return VerifyResult{Confirmed: r.Verdict.Pass, Verdict: r.Verdict}, nil
}

func verifySummary(res VerifyResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.Confirmed {
		return "CONFIRMED"
	}
	return "not-confirmed"
}

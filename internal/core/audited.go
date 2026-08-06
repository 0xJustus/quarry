package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
)

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:8])
}

type auditedRunner struct {
	inner runner.Runner
	log   audit.Recorder
}

func (a auditedRunner) Run(ctx context.Context, spec runner.RunSpec) (oracle.RunResult, error) {
	tgt := ""
	switch {
	case spec.Image != "":
		tgt = "image:" + spec.Image
	case spec.Binary != "":
		tgt = "bin:" + spec.Binary
	}
	args := fmt.Sprintf("%s argv:%v", tgt, spec.ArgvTmpl)
	if len(spec.PoV) > 0 {
		args += " pov:" + digest(spec.PoV)
	}
	sp := a.log.Start("runner.Run", audit.KindSideEffect, args)
	rr, err := a.inner.Run(ctx, spec)
	sp.End(runSummary(rr), err)
	return rr, err
}

func runSummary(rr oracle.RunResult) string {
	var state string
	switch {
	case rr.OOMKilled:
		state = "oom-killed"
	case rr.TimedOut:
		state = "timed-out"
	case rr.TermSignal != 0:
		state = fmt.Sprintf("signal:%d", rr.TermSignal)
	default:
		state = fmt.Sprintf("exit:%d", rr.ExitCode)
	}
	if rr.Sanitizer.Fired {
		state += " san:" + rr.Sanitizer.Tool + "/" + rr.Sanitizer.BugClass
	}
	return state
}

type auditedModel struct {
	inner model.Model
	log   audit.Recorder
}

func (a auditedModel) Chat(ctx context.Context, req model.ChatRequest) (model.ChatResponse, error) {
	args := fmt.Sprintf("model:%s msgs:%d maxtok:%d prompt:%s", req.Model, len(req.Messages), req.MaxTokens, promptDigest(req))
	sp := a.log.Start("model.Chat", audit.KindSideEffect, args)
	resp, err := a.inner.Chat(ctx, req)
	res := fmt.Sprintf("tokens:%d+%d finish:%s", resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.FinishReason)
	sp.End(res, err)
	return resp, err
}

func promptDigest(req model.ChatRequest) string {
	h := sha256.New()
	for _, m := range req.Messages {
		h.Write([]byte(m.Content))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)[:8])
}

var (
	_ runner.Runner = auditedRunner{}
	_ model.Model   = auditedModel{}
)

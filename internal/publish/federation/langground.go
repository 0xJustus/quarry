package federation

import (
	"context"

	"github.com/0xjustus/quarry/internal/intake/backend"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

// VerdictFromFault maps a backend Fault to a Verdict; never forges a signal.
func VerdictFromFault(f backend.Fault) oracle.Verdict {
	if !f.Faulted {
		return oracle.Verdict{Pass: false, Conditions: []oracle.ConditionResult{
			{Type: oracle.CondExit, Matched: false, Detail: "ran to completion, no fault"},
		}}
	}
	var ct oracle.ConditionType
	switch f.Class {
	case backend.FaultMemory:
		ct = oracle.CondSignal
	case backend.FaultTimeout:
		ct = oracle.CondTimeout
	default:
		ct = oracle.CondExit
	}
	detail := f.Signal
	if f.Site != "" {
		detail += " @ " + f.Site
	}
	return oracle.Verdict{Pass: true, Conditions: []oracle.ConditionResult{
		{Type: ct, Matched: true, Detail: detail},
	}}
}

func runResultFromFault(f backend.Fault) oracle.RunResult {
	rr := oracle.RunResult{Stderr: string(f.Output), ExitCode: 1}
	switch f.Class {
	case backend.FaultMemory:
		rr.ExitCode = 0 // signal-only crash: not an abnormal exit
	case backend.FaultTimeout:
		rr.TimedOut = true
	}
	rr.Sanitizer = oracle.SanitizerReport{BugClass: f.Signal, CrashSite: f.Site}
	return rr
}

func GroundLang(ctx context.Context, be backend.Verifier, image string, f Finding, pathSig, createdAt string) (*artifact.Envelope, bool, error) {
	fault, err := be.RunOnce(ctx, image, f.PoV)
	if err != nil {
		return nil, false, err
	}
	verdict := VerdictFromFault(fault)
	env, ok := Admit(verdict, f, runResultFromFault(fault), pathSig, createdAt)
	return env, ok, nil
}

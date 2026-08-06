package core

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/publish/sarif"
)

type ReportRequest struct {
	Caller   Caller `json:"caller,omitempty"`
	Verify   []byte `json:"verify"`
	SrcRoot  string `json:"src_root,omitempty"`
	Repo     string `json:"repo,omitempty"`
	Revision string `json:"revision,omitempty"`
}

type verifyJSON struct {
	Confirmed     bool     `json:"confirmed"`
	Verdict       string   `json:"verdict"`
	BugClass      string   `json:"bug_class,omitempty"`
	CrashSite     string   `json:"crash_site,omitempty"`
	BehavioralKey string   `json:"behavioral_key,omitempty"`
	Frames        []string `json:"frames,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type ReportResult struct {
	SARIF sarif.Report `json:"sarif"`
}

func (e *Engine) Report(ctx context.Context, req ReportRequest) (ReportResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Report", audit.KindAccess, "verify:"+digest(req.Verify))
	if len(req.Verify) == 0 {
		err := fmt.Errorf("report: verify result is required")
		sp.End("error", err)
		return ReportResult{}, err
	}
	var v verifyJSON
	if err := json.Unmarshal(req.Verify, &v); err != nil {
		sp.End("parse-error", err)
		return ReportResult{}, fmt.Errorf("report: parse verify json: %w", err)
	}
	rep := sarif.Build(sarif.Input{
		Confirmed:     v.Confirmed,
		Verdict:       v.Verdict,
		BugClass:      v.BugClass,
		CrashSite:     v.CrashSite,
		BehavioralKey: v.BehavioralKey,
		Frames:        v.Frames,
	}, sarif.Opts{SrcRoot: req.SrcRoot, Repo: req.Repo, Revision: req.Revision})
	sp.End(fmt.Sprintf("confirmed:%v verdict:%s", v.Confirmed, v.Verdict), nil)
	return ReportResult{SARIF: rep}, nil
}

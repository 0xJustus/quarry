package core

import (
	"context"
	"fmt"

	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/publish/sarif"
	"github.com/0xjustus/quarry/internal/verdict/impact"
)

type ImpactGradeRequest struct {
	Caller    Caller   `json:"caller,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Reference []byte   `json:"reference"`
	Divergent []byte   `json:"divergent"`
	Fields    []string `json:"fields,omitempty"`
}

type ImpactGradeResult struct {
	Rung         string `json:"rung"`
	Demonstrated bool   `json:"demonstrated"`
	Probe        string `json:"probe,omitempty"`
	RefDecision  string `json:"ref_decision,omitempty"`
	DivDecision  string `json:"div_decision,omitempty"`
	Rationale    string `json:"rationale"`
}

func (e *Engine) ImpactGrade(ctx context.Context, req ImpactGradeRequest) (ImpactGradeResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.ImpactGrade", audit.KindCall, fmt.Sprintf("kind:%s ref:%s div:%s", req.Kind, digest(req.Reference), digest(req.Divergent)))
	kind := req.Kind
	if kind == "" {
		kind = "diverge_on_output"
	}
	probes := impact.DefaultProbes()
	for _, f := range req.Fields {
		if f != "" {
			probes = append(probes, impact.FieldProbe(f))
		}
	}
	a := impact.Grade(impact.DivergenceFrom(kind, req.Reference, req.Divergent), probes)
	res := ImpactGradeResult{
		Rung: a.Rung.String(), Demonstrated: a.Demonstrated, Probe: a.ProbeName,
		RefDecision: a.RefDecision, DivDecision: a.DivDecision, Rationale: a.Rationale,
	}
	sp.End("rung:"+res.Rung, nil)
	return res, nil
}

type SarifIngestRequest struct {
	Caller    Caller   `json:"caller,omitempty"`
	Data      []byte   `json:"data"`
	KnownKeys []string `json:"known_keys,omitempty"`
	Measured  bool     `json:"measured,omitempty"`
}

type SarifDecision struct {
	Verdict    string `json:"verdict"`
	RuleID     string `json:"rule_id"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	MatchedKey string `json:"matched_key,omitempty"`
}

type SarifIngestResult struct {
	Total     int             `json:"total"`
	Novel     int             `json:"novel"`
	Decisions []SarifDecision `json:"decisions"`
}

func (e *Engine) SarifIngest(ctx context.Context, req SarifIngestRequest) (SarifIngestResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.SarifIngest", audit.KindAccess, fmt.Sprintf("data:%s known:%d measured:%v", digest(req.Data), len(req.KnownKeys), req.Measured))
	cands, err := sarif.Parse(req.Data)
	if err != nil {
		sp.End("parse-error", err)
		return SarifIngestResult{}, fmt.Errorf("sarif ingest: parse: %w", err)
	}
	src := sarif.FingerprintsAsserted
	if req.Measured {
		src = sarif.FingerprintsMeasured
	}
	decisions := sarif.Dedup(cands, req.KnownKeys, src)
	out := SarifIngestResult{Total: len(decisions), Novel: len(sarif.Novels(decisions))}
	for _, d := range decisions {
		out.Decisions = append(out.Decisions, SarifDecision{
			Verdict: string(d.Verdict), RuleID: d.Candidate.RuleID, File: d.Candidate.File,
			Line: d.Candidate.Line, MatchedKey: d.MatchedKey,
		})
	}
	sp.End(fmt.Sprintf("novel:%d/%d", out.Novel, out.Total), nil)
	return out, nil
}

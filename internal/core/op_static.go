package core

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/0xjustus/quarry/internal/discover/cpg"
	"github.com/0xjustus/quarry/internal/discover/loop"
	"github.com/0xjustus/quarry/internal/platform/audit"
)

const sinkpointEmptyScanNote = "note: 0 sinks is NOT evidence of a clean surface — static scanning needs a CGo/tree-sitter build; a pure-Go (CGO_ENABLED=0) quarry reports an empty sink map for ANY source tree"

type SinkpointsRequest struct {
	Caller Caller   `json:"caller,omitempty"`
	Paths  []string `json:"paths"`
	Max    int      `json:"max,omitempty"`
}

type Sinkpoint struct {
	File     string `json:"file"`
	Function string `json:"function,omitempty"`
	Line     int    `json:"line"`
	Kind     string `json:"kind"`
	Severity int    `json:"severity"`
	Snippet  string `json:"snippet,omitempty"`
}

type SinkpointsResult struct {
	Paths  int         `json:"paths"`
	Total  int         `json:"total"`
	High   int         `json:"high"`
	Medium int         `json:"medium"`
	Sinks  []Sinkpoint `json:"sinks"`
	Note   string      `json:"note,omitempty"`
}

func (e *Engine) Sinkpoints(ctx context.Context, req SinkpointsRequest) (SinkpointsResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Sinkpoints", audit.KindAccess, fmt.Sprintf("paths:%d max:%d", len(req.Paths), req.Max))
	if len(req.Paths) == 0 {
		err := fmt.Errorf("sinkpoints: paths is required (source files/dirs to scan)")
		sp.End("error", err)
		return SinkpointsResult{}, err
	}
	sinks := loop.StaticSinkpoints(req.Paths)
	out := SinkpointsResult{Paths: len(req.Paths), Total: len(sinks)}
	for _, s := range sinks {
		if s.Severity >= 3 {
			out.High++
		} else {
			out.Medium++
		}
	}
	sorted := slices.Clone(sinks)
	slices.SortStableFunc(sorted, func(a, b loop.Sink) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line))
	})
	if req.Max > 0 && len(sorted) > req.Max {
		sorted = sorted[:req.Max]
	}
	out.Sinks = make([]Sinkpoint, 0, len(sorted))
	for _, s := range sorted {
		out.Sinks = append(out.Sinks, Sinkpoint{
			File: s.File, Function: s.Function, Line: s.Line, Kind: s.Kind, Severity: s.Severity, Snippet: s.Snippet,
		})
	}
	if out.Total == 0 {
		out.Note = sinkpointEmptyScanNote
	}
	sp.End(fmt.Sprintf("sinks:%d (%dH/%dM)", out.Total, out.High, out.Medium), nil)
	return out, nil
}

type CallgraphRequest struct {
	Caller   Caller   `json:"caller,omitempty"`
	Paths    []string `json:"paths"`
	Function string   `json:"function,omitempty"`
	MaxNames int      `json:"max_names,omitempty"`
}

type CallgraphResult struct {
	Funcs       int      `json:"funcs"`
	WithCallers int      `json:"with_callers"`
	WithCallees int      `json:"with_callees"`
	TotalNames  int      `json:"total_names,omitempty"`
	Names       []string `json:"names,omitempty"`
	Callers     []string `json:"callers,omitempty"`
	Callees     []string `json:"callees,omitempty"`
	Source      string   `json:"source,omitempty"`
}

func (e *Engine) Callgraph(ctx context.Context, req CallgraphRequest) (CallgraphResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.Callgraph", audit.KindAccess, fmt.Sprintf("paths:%d fn:%s", len(req.Paths), req.Function))
	if len(req.Paths) == 0 {
		err := fmt.Errorf("callgraph: paths is required (source files/dirs to scan)")
		sp.End("error", err)
		return CallgraphResult{}, err
	}
	g := loop.BuildCallGraph(req.Paths)
	nf, nc, nce := g.Summary()
	out := CallgraphResult{Funcs: nf, WithCallers: nc, WithCallees: nce}
	if req.Function != "" {
		out.Callers = g.Callers(req.Function)
		out.Callees = g.Callees(req.Function)
		out.Source = g.Function(req.Function)
	} else {
		names := g.FuncNames()
		out.TotalNames = len(names)
		max := req.MaxNames
		if max <= 0 {
			max = 200
		}
		if len(names) > max {
			names = names[:max]
		}
		out.Names = names
	}
	sp.End(fmt.Sprintf("funcs:%d", nf), nil)
	return out, nil
}

type CPGGenerateRequest struct {
	Caller     Caller   `json:"caller,omitempty"`
	SeedSource string   `json:"seed_source"`
	Defines    []string `json:"defines,omitempty"`
	Includes   []string `json:"includes,omitempty"`
	Out        string   `json:"out,omitempty"`
}

type CPGGenerateResult struct {
	CpgPath  string `json:"cpg_path"`
	Methods  int    `json:"methods"`
	Calls    int    `json:"calls"`
	Cached   bool   `json:"cached"`
	CacheKey string `json:"cache_key,omitempty"`
}

func (e *Engine) CPGGenerate(ctx context.Context, req CPGGenerateRequest) (CPGGenerateResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGGenerate", audit.KindCall, fmt.Sprintf("src:%s defines:%d includes:%d", req.SeedSource, len(req.Defines), len(req.Includes)))
	if req.SeedSource == "" {
		err := fmt.Errorf("cpg generate: seed_source is required")
		sp.End("error", err)
		return CPGGenerateResult{}, err
	}
	out := req.Out
	if out == "" {
		out = filepath.Join(os.TempDir(), "quarry-cpg.bin")
	}
	gr, err := cpg.Generate(ctx, cpg.GenSpec{
		Src: req.SeedSource, Out: out, Defines: req.Defines, Includes: req.Includes,
	})
	if err != nil {
		sp.End("error", err)
		return CPGGenerateResult{}, err
	}
	res := CPGGenerateResult{CpgPath: gr.CpgPath, Methods: gr.Methods, Calls: gr.Calls, Cached: gr.Cached, CacheKey: gr.CacheKey}
	sp.End(fmt.Sprintf("methods:%d calls:%d cached:%v", res.Methods, res.Calls, res.Cached), nil)
	return res, nil
}

type CPGFuncRequest struct {
	Caller   Caller `json:"caller,omitempty"`
	CpgPath  string `json:"cpg_path"`
	Function string `json:"function"`
}

type NameListResult struct {
	Names []string `json:"names"`
}

func (e *Engine) CPGCallers(ctx context.Context, req CPGFuncRequest) (NameListResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGCallers", audit.KindAccess, fmt.Sprintf("cpg:%s fn:%s", req.CpgPath, req.Function))
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg callers: cpg_path is required")
		sp.End("error", err)
		return NameListResult{}, err
	}
	names, err := cpg.New(req.CpgPath).Callers(ctx, req.Function)
	sp.End(fmt.Sprintf("n:%d", len(names)), err)
	if err != nil {
		return NameListResult{}, err
	}
	return NameListResult{Names: names}, nil
}

func (e *Engine) CPGCallees(ctx context.Context, req CPGFuncRequest) (NameListResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGCallees", audit.KindAccess, fmt.Sprintf("cpg:%s fn:%s", req.CpgPath, req.Function))
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg callees: cpg_path is required")
		sp.End("error", err)
		return NameListResult{}, err
	}
	names, err := cpg.New(req.CpgPath).Callees(ctx, req.Function)
	sp.End(fmt.Sprintf("n:%d", len(names)), err)
	if err != nil {
		return NameListResult{}, err
	}
	return NameListResult{Names: names}, nil
}

func (e *Engine) CPGBounds(ctx context.Context, req CPGFuncRequest) (NameListResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGBounds", audit.KindAccess, fmt.Sprintf("cpg:%s fn:%s", req.CpgPath, req.Function))
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg bounds: cpg_path is required")
		sp.End("error", err)
		return NameListResult{}, err
	}
	checks, err := cpg.New(req.CpgPath).BoundsChecks(ctx, req.Function)
	sp.End(fmt.Sprintf("n:%d", len(checks)), err)
	if err != nil {
		return NameListResult{}, err
	}
	return NameListResult{Names: checks}, nil
}

type CPGSliceResult struct {
	Slice string `json:"slice"`
}

func (e *Engine) CPGSlice(ctx context.Context, req CPGFuncRequest) (CPGSliceResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGSlice", audit.KindAccess, fmt.Sprintf("cpg:%s fn:%s", req.CpgPath, req.Function))
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg slice: cpg_path is required")
		sp.End("error", err)
		return CPGSliceResult{}, err
	}
	sl, err := cpg.New(req.CpgPath).Slice(ctx, req.Function)
	sp.End(fmt.Sprintf("lines:%d", len(sl)), err)
	if err != nil {
		return CPGSliceResult{}, err
	}
	return CPGSliceResult{Slice: sl}, nil
}

type CPGReachesRequest struct {
	Caller  Caller `json:"caller,omitempty"`
	CpgPath string `json:"cpg_path"`
	From    string `json:"from"`
	To      string `json:"to"`
}

type CPGReachesResult struct {
	Reaches           bool `json:"reaches"`
	TransitiveCallers int  `json:"transitive_callers"`
}

func (e *Engine) CPGReaches(ctx context.Context, req CPGReachesRequest) (CPGReachesResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGReaches", audit.KindAccess, fmt.Sprintf("cpg:%s %s->%s", req.CpgPath, req.From, req.To))
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg reaches: cpg_path is required")
		sp.End("error", err)
		return CPGReachesResult{}, err
	}
	r, n, err := cpg.New(req.CpgPath).Reaches(ctx, req.From, req.To)
	sp.End(fmt.Sprintf("reaches:%v callers:%d", r, n), err)
	if err != nil {
		return CPGReachesResult{}, err
	}
	return CPGReachesResult{Reaches: r, TransitiveCallers: n}, nil
}

type CPGTaintRequest struct {
	Caller  Caller `json:"caller,omitempty"`
	CpgPath string `json:"cpg_path"`
	Source  string `json:"source"`
	Sink    string `json:"sink"`
}

type CPGTaintResult struct {
	Count int      `json:"count"`
	Paths []string `json:"paths,omitempty"`
}

func (e *Engine) CPGTaint(ctx context.Context, req CPGTaintRequest) (CPGTaintResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGTaint", audit.KindAccess, fmt.Sprintf("cpg:%s %s~>%s", req.CpgPath, req.Source, req.Sink))
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg taint: cpg_path is required")
		sp.End("error", err)
		return CPGTaintResult{}, err
	}
	n, paths, err := cpg.New(req.CpgPath).TaintFlows(ctx, req.Source, req.Sink)
	sp.End(fmt.Sprintf("flows:%d", n), err)
	if err != nil {
		return CPGTaintResult{}, err
	}
	return CPGTaintResult{Count: n, Paths: paths}, nil
}

type CPGSinksRequest struct {
	Caller  Caller `json:"caller,omitempty"`
	CpgPath string `json:"cpg_path"`
}

type CPGPriorArt struct {
	BugClass string `json:"bug_class"`
	Abstract string `json:"abstract,omitempty"`
}

type CPGSink struct {
	Callee string        `json:"callee"`
	Func   string        `json:"func,omitempty"`
	Line   int           `json:"line"`
	Prior  []CPGPriorArt `json:"prior,omitempty"`
}

type CPGSinksResult struct {
	Total int       `json:"total"`
	Sinks []CPGSink `json:"sinks"`
}

func (e *Engine) CPGSinks(ctx context.Context, req CPGSinksRequest) (CPGSinksResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.CPGSinks", audit.KindAccess, "cpg:"+req.CpgPath)
	if req.CpgPath == "" {
		err := fmt.Errorf("cpg sinks: cpg_path is required")
		sp.End("error", err)
		return CPGSinksResult{}, err
	}
	sites, err := cpg.New(req.CpgPath).Sinks(ctx)
	if err != nil {
		sp.End("error", err)
		return CPGSinksResult{}, err
	}
	out := CPGSinksResult{Total: len(sites), Sinks: make([]CPGSink, 0, len(sites))}
	for _, s := range sites {
		cs := CPGSink{Callee: s.Callee, Func: s.Func, Line: s.Line}
		for _, p := range s.Prior {
			cs.Prior = append(cs.Prior, CPGPriorArt{BugClass: p.BugClass, Abstract: p.Abstract})
		}
		out.Sinks = append(out.Sinks, cs)
	}
	sp.End(fmt.Sprintf("sinks:%d", out.Total), nil)
	return out, nil
}

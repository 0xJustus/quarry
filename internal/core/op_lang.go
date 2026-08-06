package core

import (
	"context"
	"fmt"
	"time"

	"github.com/0xjustus/quarry/internal/intake/backend"
	"github.com/0xjustus/quarry/internal/platform/audit"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/federation"
	"github.com/0xjustus/quarry/internal/publish/gitcommons"
)

type LangFault struct {
	Faulted bool   `json:"faulted"`
	Class   string `json:"class,omitempty"`
	Signal  string `json:"signal,omitempty"`
	Site    string `json:"site,omitempty"`
	Grader  string `json:"grader,omitempty"`
}

func langFaultFrom(f backend.Fault) LangFault {
	return LangFault{Faulted: f.Faulted, Class: string(f.Class), Signal: f.Signal, Site: f.Site, Grader: f.Grader()}
}

type LangCommitResult struct {
	Attempted        bool   `json:"attempted"`
	Committed        bool   `json:"committed"`
	AddedArtifacts   int    `json:"added_artifacts,omitempty"`
	GateOK           bool   `json:"gate_ok,omitempty"`
	CommonsArtifacts int    `json:"commons_artifacts,omitempty"`
	CommonsKeys      int    `json:"commons_keys,omitempty"`
	Error            string `json:"error,omitempty"`
}

func (e *Engine) langGroundAndCommit(ctx context.Context, log audit.Recorder, be backend.Verifier, image, source string, pov []byte, commitDir, grader string) LangCommitResult {
	if commitDir == "" {
		return LangCommitResult{}
	}
	res := LangCommitResult{Attempted: true}
	sp := log.Start("core.LangCommit", audit.KindSideEffect, fmt.Sprintf("commit:%s src:%s pov:%s", commitDir, source, digest(pov)))
	createdAt := time.Now().UTC().Format(time.RFC3339)
	env, ok, err := federation.GroundLang(ctx, be, image, federation.Finding{Source: source, PoV: pov}, "lang", createdAt)
	if err != nil {
		res.Error = "ground: " + err.Error()
		sp.End("ground-error", err)
		return res
	}
	if !ok {
		res.Error = "the finding did NOT re-ground on our runner — not admitted (anti-poisoning)"
		sp.End("not-admitted", nil)
		return res
	}
	abstract := "federated multi-language finding from " + source
	if grader != "" {
		abstract += " [grader=" + grader + "]"
	}
	pub := env.PublicAbstract(abstract, createdAt)
	_ = pub.Artifact.ComputeID()
	st, err := gitcommons.Add(commitDir, []*artifact.Envelope{pub})
	if err != nil {
		res.Error = "add to commons: " + err.Error()
		sp.End("add-error", err)
		return res
	}
	res.AddedArtifacts = st.Artifacts
	rep, err := gitcommons.Verify(commitDir)
	if err != nil || !rep.OK() {
		res.Error = fmt.Sprintf("anti-poisoning gate FAILED after commit: err=%v failures=%v", err, rep.Failures)
		sp.End("gate-failed", err)
		return res
	}
	res.Committed = true
	res.GateOK = true
	res.CommonsArtifacts = rep.Artifacts
	res.CommonsKeys = rep.Keys
	sp.End(fmt.Sprintf("committed +%d gate:%d/%d", st.Artifacts, rep.Artifacts, rep.Keys), nil)
	return res
}

func verifierForLang(name, mainClass, entry string) (backend.Verifier, error) {
	switch name {
	case "java":
		return backend.JavaBackend{MainClass: mainClass}, nil
	case "python":
		return backend.PythonBackend{Entry: entry}, nil
	case "go":
		return backend.Go{}, nil
	case "c":
		return backend.C{}, nil
	default:
		return nil, fmt.Errorf("no implemented verifier for %q", name)
	}
}

type LangDetectRequest struct {
	Caller Caller `json:"caller,omitempty"`
	Dir    string `json:"dir"`
}

type LangDetectResult struct {
	Recognized bool   `json:"recognized"`
	Backend    string `json:"backend,omitempty"`
	Capability string `json:"capability,omitempty"`
}

func (e *Engine) LangDetect(ctx context.Context, req LangDetectRequest) (LangDetectResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.LangDetect", audit.KindAccess, "dir:"+req.Dir)
	if req.Dir == "" {
		err := fmt.Errorf("lang detect: dir is required")
		sp.End("error", err)
		return LangDetectResult{}, err
	}
	b := backend.Detect(req.Dir)
	if b == nil {
		sp.End("unrecognized", nil)
		return LangDetectResult{Recognized: false}, nil
	}
	capab := "verify-only"
	if _, ok := any(b).(backend.Fuzzer); ok {
		capab = "fuzz+verify"
	}
	sp.End("detected:"+b.Name(), nil)
	return LangDetectResult{Recognized: true, Backend: b.Name(), Capability: capab}, nil
}

type LangGroundRequest struct {
	Caller    Caller `json:"caller,omitempty"`
	Dir       string `json:"dir"`
	PoV       []byte `json:"pov"`
	Backend   string `json:"backend,omitempty"`
	MainClass string `json:"main_class,omitempty"`
	Entry     string `json:"entry,omitempty"`
	CommitDir string `json:"commit_dir,omitempty"`
}

type LangGroundResult struct {
	Backend string           `json:"backend"`
	Image   string           `json:"image,omitempty"`
	Fault   LangFault        `json:"fault"`
	Commit  LangCommitResult `json:"commit"`
}

func (e *Engine) LangGround(ctx context.Context, req LangGroundRequest) (LangGroundResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.LangGround", audit.KindCall, fmt.Sprintf("dir:%s pov:%s be:%s", req.Dir, digest(req.PoV), req.Backend))
	res, err := e.langGround(ctx, log, req)
	sp.End(langGroundSummary(res, err), err)
	return res, err
}

func (e *Engine) langGround(ctx context.Context, log audit.Recorder, req LangGroundRequest) (LangGroundResult, error) {
	if req.Dir == "" {
		return LangGroundResult{}, fmt.Errorf("lang ground: dir is required")
	}
	if len(req.PoV) == 0 {
		return LangGroundResult{}, fmt.Errorf("lang ground: pov is required")
	}
	name := req.Backend
	if name == "" {
		b := backend.Detect(req.Dir)
		if b == nil {
			return LangGroundResult{}, fmt.Errorf("lang ground: no backend recognizes %s; set backend", req.Dir)
		}
		name = b.Name()
	}
	mainClass := req.MainClass
	if mainClass == "" {
		mainClass = "Target"
	}
	entry := req.Entry
	if entry == "" {
		entry = "target.py"
	}
	be, err := verifierForLang(name, mainClass, entry)
	if err != nil {
		return LangGroundResult{}, fmt.Errorf("lang ground: %w", err)
	}
	image, err := be.BuildImage(ctx, req.Dir)
	if err != nil {
		return LangGroundResult{Backend: name}, fmt.Errorf("lang ground: build (%s): %w", name, err)
	}
	fault, err := be.RunOnce(ctx, image, req.PoV)
	if err != nil {
		return LangGroundResult{Backend: name, Image: image}, fmt.Errorf("lang ground: run: %w", err)
	}
	out := LangGroundResult{Backend: name, Image: image, Fault: langFaultFrom(fault)}
	if fault.Faulted {
		out.Commit = e.langGroundAndCommit(ctx, log, be, image, "quarry-lang:"+name, req.PoV, req.CommitDir, fault.Grader())
	}
	return out, nil
}

func langGroundSummary(res LangGroundResult, err error) string {
	if err != nil {
		return "error"
	}
	if !res.Fault.Faulted {
		return "no-fault"
	}
	return "FAULT:" + res.Fault.Signal + " grader:" + res.Fault.Grader
}

type LangFuzzRequest struct {
	Caller    Caller `json:"caller,omitempty"`
	Dir       string `json:"dir"`
	Backend   string `json:"backend,omitempty"`
	Module    string `json:"module,omitempty"`
	Entry     string `json:"entry,omitempty"`
	ForSecs   int    `json:"for_secs,omitempty"`
	CommitDir string `json:"commit_dir,omitempty"`
}

type LangFuzzResult struct {
	Backend      string           `json:"backend"`
	Image        string           `json:"image,omitempty"`
	CrashesFound int              `json:"crashes_found"`
	Confirmed    bool             `json:"confirmed"`
	Fault        LangFault        `json:"fault"`
	ReproDigest  string           `json:"repro_digest,omitempty"`
	ReproBytes   int              `json:"repro_bytes,omitempty"`
	Commit       LangCommitResult `json:"commit"`
}

func (e *Engine) LangFuzz(ctx context.Context, req LangFuzzRequest) (LangFuzzResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	be := req.Backend
	if be == "" {
		be = "python"
	}
	sp := log.Start("core.LangFuzz", audit.KindCall, fmt.Sprintf("dir:%s be:%s for:%ds", req.Dir, be, req.ForSecs))
	res, err := e.langFuzz(ctx, log, req, be)
	sp.End(langFuzzSummary(res, err), err)
	return res, err
}

func (e *Engine) langFuzz(ctx context.Context, log audit.Recorder, req LangFuzzRequest, beName string) (LangFuzzResult, error) {
	if req.Dir == "" {
		return LangFuzzResult{}, fmt.Errorf("lang fuzz: dir is required")
	}
	var fz backend.Fuzzer
	switch beName {
	case "python":
		fz = backend.Python{Module: req.Module, Function: req.Entry}
	case "java":
		fz = backend.Java{Lib: req.Module, Function: req.Entry}
	case "rust":
		fz = backend.Rust{Crate: req.Module, Function: req.Entry}
	case "js":
		fz = backend.JS{Module: req.Module, Function: req.Entry}
	case "php":
		fz = backend.PHP{Lib: req.Module, Function: req.Entry}
	case "go":
		fz = backend.Go{FuzzFunc: req.Entry}
	default:
		return LangFuzzResult{}, fmt.Errorf("lang fuzz: backend %q is not a discovery backend", beName)
	}
	forS := req.ForSecs
	if forS <= 0 {
		forS = 90
	}
	image, err := fz.BuildImage(ctx, req.Dir)
	if err != nil {
		return LangFuzzResult{Backend: beName}, fmt.Errorf("lang fuzz: build: %w", err)
	}
	crashes, err := fz.Fuzz(ctx, image, "", forS)
	if err != nil {
		return LangFuzzResult{Backend: beName, Image: image}, fmt.Errorf("lang fuzz: %w", err)
	}
	out := LangFuzzResult{Backend: beName, Image: image, CrashesFound: len(crashes)}
	if len(crashes) == 0 {
		return out, nil
	}
	fault, err := fz.RunOnce(ctx, image, crashes[0])
	if err != nil {
		return out, fmt.Errorf("lang fuzz: confirm: %w", err)
	}
	out.Confirmed = fault.Faulted
	out.Fault = langFaultFrom(fault)
	out.ReproDigest = backend.PoVDigest(crashes[0])
	out.ReproBytes = len(crashes[0])
	out.Commit = e.langGroundAndCommit(ctx, log, fz, image, "quarry-lang:"+beName, crashes[0], req.CommitDir, fault.Grader())
	return out, nil
}

func langFuzzSummary(res LangFuzzResult, err error) string {
	if err != nil {
		return "error"
	}
	if res.CrashesFound == 0 {
		return "no-crashes"
	}
	return fmt.Sprintf("crashes:%d confirmed:%v", res.CrashesFound, res.Confirmed)
}

type LangDiscoverRequest struct {
	Caller    Caller `json:"caller,omitempty"`
	Dir       string `json:"dir"`
	Backend   string `json:"backend,omitempty"`
	Module    string `json:"module,omitempty"`
	Entry     string `json:"entry,omitempty"`
	ForSecs   int    `json:"for_secs,omitempty"`
	CommitDir string `json:"commit_dir,omitempty"`
}

type LangDiscoverFinding struct {
	Class     string           `json:"class"`
	Signal    string           `json:"signal"`
	Site      string           `json:"site"`
	Grader    string           `json:"grader"`
	PoVDigest string           `json:"pov_digest"`
	PoVBytes  int              `json:"pov_bytes"`
	Commit    LangCommitResult `json:"commit"`
}

type LangDiscoverResult struct {
	Backend    string                `json:"backend"`
	Image      string                `json:"image,omitempty"`
	RawCrashes int                   `json:"raw_crashes"`
	Confirmed  []LangDiscoverFinding `json:"confirmed"`
}

func (e *Engine) LangDiscover(ctx context.Context, req LangDiscoverRequest) (LangDiscoverResult, error) {
	log := e.logFor(req.Caller.Principal, req.Caller.Session)
	sp := log.Start("core.LangDiscover", audit.KindCall, fmt.Sprintf("dir:%s be:%s for:%ds", req.Dir, req.Backend, req.ForSecs))
	res, err := e.langDiscover(ctx, log, req)
	sp.End(langDiscoverSummary(res, err), err)
	return res, err
}

func (e *Engine) langDiscover(ctx context.Context, log audit.Recorder, req LangDiscoverRequest) (LangDiscoverResult, error) {
	if req.Dir == "" {
		return LangDiscoverResult{}, fmt.Errorf("lang discover: dir is required")
	}
	forS := req.ForSecs
	if forS <= 0 {
		forS = 90
	}
	rep, err := backend.Discover(ctx, req.Dir, backend.DiscoverOpts{
		Backend: req.Backend, Module: req.Module, Function: req.Entry, BudgetSecs: forS,
	})
	if err != nil {
		return LangDiscoverResult{}, fmt.Errorf("lang discover: %w", err)
	}
	out := LangDiscoverResult{Backend: rep.Backend, Image: rep.Image, RawCrashes: rep.RawCrashes}
	if len(rep.Confirmed) == 0 {
		return out, nil
	}
	fz, _ := backend.FuzzerFor(rep.Backend, req.Module, req.Entry)
	for _, d := range rep.Confirmed {
		f := LangDiscoverFinding{
			Class: string(d.Fault.Class), Signal: d.Fault.Signal, Site: d.Fault.Site,
			Grader: d.Grader, PoVDigest: backend.PoVDigest(d.PoV), PoVBytes: len(d.PoV),
		}
		if req.CommitDir != "" && fz != nil {
			f.Commit = e.langGroundAndCommit(ctx, log, fz, rep.Image, "quarry-lang:"+rep.Backend, d.PoV, req.CommitDir, d.Grader)
		}
		out.Confirmed = append(out.Confirmed, f)
	}
	return out, nil
}

func langDiscoverSummary(res LangDiscoverResult, err error) string {
	if err != nil {
		return "error"
	}
	return fmt.Sprintf("raw:%d confirmed:%d", res.RawCrashes, len(res.Confirmed))
}

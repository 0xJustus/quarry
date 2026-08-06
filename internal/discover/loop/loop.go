// Package loop drives one investigation end-to-end.
package loop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xjustus/quarry/internal/discover/agent"
	"github.com/0xjustus/quarry/internal/platform/mcp"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/platform/toolcat"
	"github.com/0xjustus/quarry/internal/publish/artifact"
	"github.com/0xjustus/quarry/internal/publish/channels"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
	"github.com/0xjustus/quarry/internal/verdict/runner"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

// Loop wires the client together for one investigation.
type Loop struct {
	Store  *store.Store
	Model  model.Model
	Router router.Router
	Runner runner.Runner

	Gate *channels.Gate
	Sink channels.ArtifactSink

	Signer ed25519.PrivateKey

	Source channels.PatternSource

	// records kinds + counts only, never target bytes or PoV content.
	Telemetry channels.TelemetrySink

	Updates channels.UpdateFeed

	Primer Primer

	Critic Critic

	Coverage CoverageFeed

	Planner     Planner
	MaxParallel int

	WorkspaceRoot string

	AgentImage     string
	DockerBin      string
	SandboxNetwork string

	Catalog   toolcat.Catalog
	AgentRole string

	Now func() time.Time
	Log func(string)

	harvestMu sync.Mutex // serializes the check-then-act harvest across parallel producers
	// within-run dedup set (behavioral key), guarded by harvestMu; reset at the start of each Run.
	harvested map[string]bool
}

// Request describes one investigation.
type Request struct {
	Objective  string
	Mode       string // "discover" | "copilot"
	TargetRef  string
	TargetDesc string

	Oracle oracle.Spec
	Base   runner.RunSpec
	Fixed  *runner.RunSpec

	MaxIters         int
	HypothesisBudget int

	MaxHypotheses int
	GlobalBudget  int

	TokenBudget int
	StallLimit  int

	ContextBudget int
	KeepRecent    int
	Compactor     string

	MaxDepth int

	SeedFiles []string

	TargetBinary string

	CPGPath string

	ConcolicELF string

	Analyst         bool
	UndirectedSlots int

	CorpusDir   string
	OnCandidate func([]byte)

	Escalate      bool
	EscalateMax   int
	EscalateIters int
	// SkipCorroboration disables the corroboration backstop; A/B only, never set in production.
	SkipCorroboration bool
}

// Finding is one oracle-confirmed result: private specimen + public sibling.
type Finding struct {
	HypothesisID string
	Statement    string
	Private      *artifact.Envelope
	Public       *artifact.Envelope

	PriorArt []channels.PriorArt
	Novel    bool
	// NoveltyUnknown: the prior-art lookup did not complete; count as NEITHER novel nor rediscovery.
	NoveltyUnknown bool
}

// Report is the terminal conclusion of a run.
type Report struct {
	RunID          string
	Confirmed      bool
	StopReason     string
	Iterations     int
	Usage          model.Usage
	Findings       []Finding
	Hypotheses     int
	RuledOut       string
	PoVSubmissions int

	Private *artifact.Envelope
	Public  *artifact.Envelope

	Elapsed time.Duration
}

// Metrics derives the empirical numbers a run produces. Zero-safe.
type Metrics struct {
	Confirmed         int
	Novel             int
	Rediscoveries     int
	NoveltyUndecided  int
	TotalTokens       int
	CostUSD           float64
	Elapsed           time.Duration
	Iterations        int
	TokensPerFinding  int
	SecondsPerFinding float64
	PriorArtHitRate   float64
}

func (r Report) Metrics() Metrics {
	m := Metrics{
		Confirmed:   len(r.Findings),
		TotalTokens: r.Usage.TotalTokens,
		CostUSD:     r.Usage.CostUSD,
		Elapsed:     r.Elapsed,
		Iterations:  r.Iterations,
	}
	for _, f := range r.Findings {
		switch {
		case f.NoveltyUnknown:
			m.NoveltyUndecided++
		case f.Novel:
			m.Novel++
		default:
			m.Rediscoveries++
		}
	}
	if m.Confirmed > 0 {
		m.TokensPerFinding = m.TotalTokens / m.Confirmed
		m.SecondsPerFinding = r.Elapsed.Seconds() / float64(m.Confirmed)
	}
	// rate over DECIDED findings only; undecided ones are excluded from the denominator.
	if decided := m.Novel + m.Rediscoveries; decided > 0 {
		m.PriorArtHitRate = float64(m.Rediscoveries) / float64(decided)
	}
	return m
}

func (l *Loop) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Loop) log(format string, a ...any) {
	if l.Log != nil {
		l.Log(fmt.Sprintf(format, a...))
	}
}

// Run plans the frontier, dispatches scientists, and aggregates findings.
func (l *Loop) Run(ctx context.Context, req Request) (Report, error) {
	if req.Mode == "" {
		req.Mode = "copilot"
	}
	if err := req.Oracle.Validate(); err != nil {
		return Report{}, err
	}
	l.harvestMu.Lock()
	l.harvested = map[string]bool{}
	l.harvestMu.Unlock()
	if l.Signer != nil && l.Gate != nil {
		l.Gate.Signer = l.Signer
	}

	start := l.now()
	run, err := l.Store.CreateRun(ctx, req.Objective, req.TargetRef, req.Mode)
	if err != nil {
		return Report{}, err
	}
	rep := Report{RunID: run.ID}
	_ = l.Store.AppendEvent(ctx, run.ID, "note", "supervisor", map[string]string{
		"objective": req.Objective, "target": req.TargetRef, "mode": req.Mode,
	})

	// open the CPG session after CreateRun (a failed run never spins up a Joern REPL); release once.
	cpgQ, closeCPG := l.openCPG(ctx, req)
	defer closeCPG()

	hyps, err := l.plan(ctx, req, cpgQ)
	if err != nil {
		l.log("planner failed (%v); falling back to single hypothesis", err)
		hyps = []Hypothesis{{Statement: req.Objective}}
	}
	rep.Hypotheses = len(hyps)

	budget := req.HypothesisBudget
	if budget <= 0 {
		budget = 100
	}
	perHypIters := req.MaxIters
	if perHypIters <= 0 {
		perHypIters = 24
	}
	globalBudget := req.GlobalBudget
	if globalBudget <= 0 {
		globalBudget = perHypIters * len(hyps)
	}

	type task struct {
		hyp   store.Hypothesis
		state Hypothesis
		// priorAttempt: the parent line's failed-attempt note, inherited by a child (self-correcting retry).
		priorAttempt string
	}
	var tasks []task
	for _, hy := range hyps {
		h, err := l.Store.AddHypothesis(ctx, run.ID, "", hy.Statement, budget)
		if err != nil {
			return rep, err
		}
		tasks = append(tasks, task{hyp: *h, state: hy})
	}

	parallel := l.MaxParallel
	if parallel <= 0 {
		parallel = 4
	}
	if req.Mode == "copilot" || len(tasks) == 1 {
		parallel = 1
	}

	maxDepth := req.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 2
	}

	escalateMax := req.EscalateMax
	if escalateMax <= 0 {
		escalateMax = 2
	}
	escalateIters := req.EscalateIters
	if escalateIters <= 0 {
		escalateIters = perHypIters
	}

	var (
		mu       sync.Mutex
		findings []Finding
		ruledOut []string
		// alsoConfirmed: lines the oracle CONFIRMED but that produced no separate Finding; never report as ruled out.
		alsoConfirmed []string
		totalIter     int
		usage         model.Usage
		povSubs       int
		spent         int32
		escalations   int32
	)

	var seedIndex map[string]string
	if len(req.SeedFiles) > 0 {
		seedIndex = buildSeedIndex(req.SeedFiles)
	}
	codeNav := buildCallGraphNav(req.SeedFiles)

	// wave-based frontier: spawned sub-hypotheses seed the next wave, down to maxDepth.
	wave := tasks
	for depth := 0; len(wave) > 0 && depth <= maxDepth; depth++ {
		var (
			childMu  sync.Mutex
			children []task
		)
		sem := make(chan struct{}, parallel)
		var wg sync.WaitGroup
		for _, t := range wave {
			if int(atomic.LoadInt32(&spent)) >= globalBudget {
				_ = l.Store.SetHypothesisState(ctx, t.hyp.ID, store.HypExhausted, "global budget exhausted before dispatch")
				mu.Lock()
				ruledOut = append(ruledOut, "• "+t.state.Statement+" — not investigated (global budget hit)")
				mu.Unlock()
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(t task, depth int) {
				defer wg.Done()
				defer func() { <-sem }()

				res := l.runScientist(ctx, run.ID, t.hyp, t.state.Scope, t.priorAttempt, seedIndex, codeNav, cpgQ, req, perHypIters, router.Checkable)
				atomic.AddInt32(&spent, int32(res.iterations))

				// asymmetric escalation: one strong-tier retry for a warm directed lead (gate on !res.confirmed).
				if req.Escalate && !res.confirmed && escalationWarm(res, depth, t.state.Statement) &&
					atomic.AddInt32(&escalations, 1) <= int32(escalateMax) {
					l.log("escalating stalled lead to strong tier (%s): %s", res.stopReason, t.state.Statement)
					esc := l.runScientist(ctx, run.ID, t.hyp, t.state.Scope, t.priorAttempt, seedIndex, codeNav, cpgQ, req, escalateIters, router.OpenReasoning)
					atomic.AddInt32(&spent, int32(esc.iterations))
					res = mergeEscalation(res, esc)
					if esc.confirmed {
						res.confirmed = true
					}
				}

				mu.Lock()
				totalIter += res.iterations
				addUsage(&usage, res.usage)
				povSubs += res.povSubmissions
				switch {
				case res.finding != nil:
					findings = append(findings, *res.finding)
				case res.confirmed:
					alsoConfirmed = append(alsoConfirmed, "• "+t.state.Statement+" — "+res.stopReason)
				default:
					ruledOut = append(ruledOut, "• "+t.state.Statement+" — "+res.stopReason)
				}
				mu.Unlock()

				// a confirmed line neither spawns a child wave nor goes to the critic.
				if res.finding == nil && !res.confirmed && depth < maxDepth {
					spawn := res.spawned
					if len(spawn) == 0 && depth == 0 && l.Critic != nil {
						v, cerr := l.Critic.Review(ctx, ReviewRequest{Objective: t.state.Statement, StopReason: res.stopReason, Summary: res.finalMessage})
						if cerr == nil && !v.Adequate && v.Suggestion != "" {
							spawn = []string{v.Suggestion}
							l.log("critic judged the line premature: %s", v.Reason)
						}
					}
					for _, stmt := range spawn {
						ch, err := l.Store.AddHypothesis(ctx, run.ID, t.hyp.ID, stmt, budget)
						if err != nil {
							continue
						}
						childMu.Lock()
						// children inherit the parent's sink slice AND its best failed attempt.
						children = append(children, task{hyp: *ch, state: Hypothesis{Statement: stmt, Scope: t.state.Scope}, priorAttempt: res.failureSummary})
						childMu.Unlock()
						l.log("dispatching child line (depth %d): %s", depth+1, stmt)
					}
				}
			}(t, depth)
		}
		wg.Wait()
		wave = children
	}

	rep.Findings = findings
	rep.Iterations = totalIter
	rep.Usage = usage
	rep.PoVSubmissions = povSubs
	rep.Elapsed = l.now().Sub(start)
	rep.Confirmed = len(findings) > 0
	if len(findings) > 0 {
		rep.Private, rep.Public = findings[0].Private, findings[0].Public
		rep.StopReason = "confirmed"
	} else {
		rep.StopReason = "exhausted"
	}
	rep.RuledOut = l.frontierReport(ctx, run.ID, findings, ruledOut, alsoConfirmed)

	// fail closed: an interrupted run is not an exhausted frontier — say so AND return the error (vault: Loop Core).
	if cerr := ctx.Err(); cerr != nil {
		rep.StopReason = "interrupted (" + cerr.Error() + ")"
		_ = l.Store.FinishRun(ctx, run.ID, "interrupted", map[string]any{
			"confirmed": rep.Confirmed, "findings": len(findings), "hypotheses": len(tasks), "iterations": totalIter,
			"error": cerr.Error(),
		})
		return rep, fmt.Errorf("run interrupted: %w", cerr)
	}

	_ = l.Store.FinishRun(ctx, run.ID, "done", map[string]any{
		"confirmed": rep.Confirmed, "findings": len(findings), "hypotheses": len(tasks), "iterations": totalIter,
	})
	return rep, nil
}

// plan picks a planner (explicit or by mode) and decomposes the objective.
func (l *Loop) plan(ctx context.Context, req Request, cpgQ agent.CPGQuerier) ([]Hypothesis, error) {
	p := l.Planner
	useAnalyst := req.Analyst || (p == nil && req.Mode == "discover" && len(req.SeedFiles) > 0)
	if p == nil {
		switch {
		case req.Mode == "copilot":
			p = SingleHypothesis{}
		case useAnalyst:
			p = OrchestratedAnalyst{Model: l.Model, Router: l.Router, Log: func(s string) { l.log("%s", s) }}
			l.log("planner: RoleAnalyst (orchestrated map-reduce → per-slice decomposed review → deterministic work items)")
		default:
			p = ModelPlanner{Model: l.Model, Router: l.Router}
		}
	}
	// Planner is stored by VALUE, so re-assign after setting the field — the type-switch copy would not stick.
	if cpgQ != nil {
		switch a := p.(type) {
		case DecomposedAnalyst:
			a.CPG = cpgQ
			p = a
		case OrchestratedAnalyst:
			a.CPG = cpgQ
			p = a
		}
	}
	max := req.MaxHypotheses
	if req.Mode == "copilot" {
		max = 1
	} else if max <= 0 {
		max = 6
	}
	undirected := 0
	if useAnalyst || isAnalyst(p) {
		undirected = req.UndirectedSlots
		if undirected <= 0 {
			undirected = 1
		}
		if max <= 1 {
			undirected = 0
		}
	}
	return p.Plan(ctx, PlanRequest{
		Objective:  req.Objective,
		TargetDesc: req.TargetDesc,
		Mode:       req.Mode,
		Max:        max,
		PriorArt:   l.primeHints(ctx, req),
		SeedFiles:  req.SeedFiles,
		Undirected: undirected,
	})
}

func isAnalyst(p Planner) bool {
	switch p.(type) {
	case ModelAnalyst, DecomposedAnalyst, OrchestratedAnalyst:
		return true
	}
	return false
}

const primeK = 5

const priorArtHintMax = 200

// primeHints queries the Primer for prior art and renders compact planner hints. nil when no Primer.
func (l *Loop) primeHints(ctx context.Context, req Request) []string {
	if l.Primer == nil {
		return nil
	}
	pa, err := l.Primer.Prime(ctx, PrimeQuery{Objective: req.Objective, TargetDesc: req.TargetDesc, K: primeK})
	if err != nil {
		l.log("prior-art priming: %v", err)
		return nil
	}
	l.record(ctx, "", "query", map[string]string{"source": "primer", "matches": strconv.Itoa(len(pa))})
	seen := map[string]bool{}
	var hints []string
	for _, a := range pa {
		if len(hints) >= primeK {
			break
		}
		if a.ArtifactID != "" {
			if seen[a.ArtifactID] {
				continue
			}
			seen[a.ArtifactID] = true
		}
		if h := priorArtHint(a); h != "" {
			hints = append(hints, h)
		}
	}
	if len(hints) > 0 {
		l.log("primed planning with %d prior-art hint(s)", len(hints))
	}
	return hints
}

func priorArtHint(a channels.PriorArt) string {
	class := strings.TrimSpace(a.BugClass)
	ab := strings.TrimSpace(a.Abstract)
	if len(ab) > priorArtHintMax {
		ab = strings.TrimSpace(ab[:priorArtHintMax]) + "…"
	}
	switch {
	case class == "" && ab == "":
		return ""
	case class == "":
		return "- " + ab
	case ab == "":
		return "- [" + class + "]"
	default:
		return "- [" + class + "] " + ab
	}
}

type scientistResult struct {
	finding        *Finding
	stopReason     string
	iterations     int
	usage          model.Usage
	povSubmissions int
	spawned        []string
	finalMessage   string
	failureSummary string

	// confirmed: the ORACLE confirmed this line even when no Finding came back; NOT a dead-end (a backstop-refuted line is not confirmed).
	confirmed bool
}

func (l *Loop) compactor(kind string) agent.Compactor {
	if kind == "model" {
		return agent.ModelCompactor{Model: l.Model, Router: l.Router}
	}
	return agent.TemplateCompactor{}
}

func (l *Loop) runScientist(ctx context.Context, runID string, hyp store.Hypothesis, scope []string, priorAttempt string, seedIndex map[string]string, codeNav agent.CodeNavigator, cpgQ agent.CPGQuerier, req Request, maxIters int, taskKind router.TaskKind) scientistResult {
	wsRoot := l.WorkspaceRoot
	if wsRoot == "" {
		wsRoot = filepath.Join(".", ".quarry-ws")
	}
	ws, err := agent.NewWorkspace(filepath.Join(wsRoot, runID, hyp.ID))
	if err != nil {
		_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypExhausted, "workspace error: "+err.Error())
		return scientistResult{stopReason: "workspace error"}
	}
	seeds := req.SeedFiles
	if req.CorpusDir != "" {
		seeds = append(append([]string(nil), seeds...), req.CorpusDir)
	}
	seedWorkspace(ws, seeds)
	if l.AgentImage != "" {
		sb, serr := agent.NewContainerSandbox(l.DockerBin, l.AgentImage, ws.Root, "quarry-agent-"+shortID(runID, hyp.ID))
		if serr != nil {
			_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypExhausted, "sandbox error: "+serr.Error())
			return scientistResult{stopReason: "sandbox error: " + serr.Error()}
		}
		sb.Network = l.SandboxNetwork
		ws.Sandbox = sb
		defer ws.Close()
	}
	sess := &agent.Session{
		Store:         l.Store,
		Verifier:      &verify.Verifier{Runner: l.Runner, Store: l.Store},
		RunID:         runID,
		HypothesisID:  hyp.ID,
		Workspace:     ws,
		Oracle:        req.Oracle,
		Base:          req.Base,
		Fixed:         req.Fixed,
		DockerBin:     l.DockerBin,
		TargetSource:  readSeedSource(req.SeedFiles),
		CandidateSink: req.OnCandidate,
		CodeNav:       codeNav,
		CPG:           cpgQ,
		BinaryPath:    req.TargetBinary,
	}
	ra := &agent.ReAct{Model: l.Model, Router: l.Router, Session: sess, Log: l.Log, Compactor: l.compactor(req.Compactor)}
	if tools := l.catalogTools(sess); len(tools) > 0 {
		ra.Tools = append(agent.Belt(sess), tools...)
	}
	// sink-centered slice scoping directs attention; it does not gate — the full tree is seeded too.
	targetDesc := req.TargetDesc
	if slice := sliceScope(seedIndex, scope, sliceScopeBudget); slice != "" {
		targetDesc = strings.TrimSpace(targetDesc + "\n\nFOCUSED SOURCE SLICE — the audited sink neighborhood for this lead; read this first, then widen into the full source seeded in your workspace if you need to:\n" + slice)
	}
	if pa := strings.TrimSpace(priorAttempt); pa != "" {
		targetDesc = strings.TrimSpace(targetDesc + "\n\n" + pa)
	}
	if ch := coverageHint(ctx, l.Coverage); ch != "" {
		targetDesc = strings.TrimSpace(targetDesc + "\n\n" + ch)
	}
	out, err := ra.Run(ctx, agent.Config{
		Role:          router.RoleExploitDev,
		TaskKind:      taskKind,
		Objective:     hyp.Statement,
		TargetDesc:    targetDesc,
		MaxIters:      maxIters,
		TokenBudget:   req.TokenBudget,
		StallLimit:    req.StallLimit,
		ContextBudget: req.ContextBudget,
		KeepRecent:    req.KeepRecent,
	})
	res := scientistResult{iterations: out.Iterations, usage: out.TotalUsage, povSubmissions: sess.PoVSubmissions, stopReason: out.StopReason, spawned: sess.Spawned, finalMessage: out.FinalMessage}
	// capture the best failed attempt for a child line — only when the line did NOT confirm.
	if !out.Confirmed {
		res.failureSummary = renderFailedAttempt(sess.LastPoV, sess.LastResult, out.FinalMessage)
	}
	if err != nil {
		_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypExhausted, "scientist error: "+err.Error())
		res.stopReason = "error: " + err.Error()
		return res
	}
	if out.Confirmed {
		// harvest FIRST, then record terminal state: the backstop can still refute an un-corroborated divergence.
		f, herr := l.produceFinding(ctx, runID, hyp, req, sess)
		switch {
		case errors.Is(herr, errSpuriousDivergence):
			_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypRefuted, herr.Error())
			res.stopReason = herr.Error()
		case herr != nil:
			// a confirmed bug that fails to harvest must NOT read as a dead-end.
			_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypConfirmed, "")
			res.confirmed = true
			l.log("CONFIRMED but harvest FAILED for %s: %v", hyp.ID, herr)
			res.stopReason = "CONFIRMED but harvest failed: " + herr.Error()
		case f == nil:
			_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypConfirmed, "")
			res.confirmed = true
			res.stopReason = "confirmed (deduped: same behavioral key as another line)"
		default:
			_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypConfirmed, "")
			res.confirmed = true
			res.finding = f
		}
		return res
	}
	_ = l.Store.SetHypothesisState(ctx, hyp.ID, store.HypExhausted, out.FinalMessage)
	return res
}

// errSpuriousDivergence marks a line the corroboration backstop REFUTED — distinct from a dedup or a harvest failure.
var errSpuriousDivergence = errors.New("divergence not corroborated (spurious)")

// produceFinding turns a confirmed hypothesis into a Finding via the shared harvest path.
func (l *Loop) produceFinding(ctx context.Context, runID string, hyp store.Hypothesis, req Request, sess *agent.Session) (*Finding, error) {
	// use the snapshotted PASSING result, not LastResult (a later failing run_pov would desync the identity).
	res := sess.ConfirmedResult
	if res == nil {
		return nil, fmt.Errorf("produceFinding: no confirming result")
	}
	// record the oracle that ACTUALLY produced the verdict (propose_reference can rewrite it in flight).
	eff := req
	eff.Oracle = sess.Oracle
	eff.Fixed = sess.Fixed
	// corroborate a model-authored reference-diff before accepting; a non-corroborated divergence is not a finding (vault: Loop Core).
	if eff.SkipCorroboration {
		l.log("divergence corroboration: SKIPPED (--no-corroborate; backstop disabled for A/B)")
	} else if ok, detail := l.corroborateDivergence(ctx, sess, eff, res); detail != "" {
		if !ok {
			l.log("finding REJECTED by divergence corroboration — %s", detail)
			return nil, fmt.Errorf("%w: %s", errSpuriousDivergence, detail)
		}
		l.log("divergence corroboration: %s", detail)
	}
	return l.harvestPoV(ctx, runID, hyp.ID, hyp.Statement, eff, sess.ConfirmedPoV, res, pathSig(eff), sess.Model, acquiredBy(eff))
}

// harvestPoV turns one oracle-confirmed PoV into a Finding; the SINGLE dedup path for every producer, serialized under harvestMu (vault: Loop Core).
func (l *Loop) harvestPoV(ctx context.Context, runID, hypID, statement string, req Request, pov []byte, res *verify.Result, pathSig, model, acquiredBy string) (*Finding, error) {
	l.harvestMu.Lock()
	defer l.harvestMu.Unlock()

	if res == nil {
		return nil, fmt.Errorf("harvestPoV: no confirming result")
	}
	createdAt := l.now().UTC().Format(time.RFC3339)

	blobHash, err := l.Store.PutBlob(ctx, pov, "application/x-quarry-specimen")
	if err != nil {
		return nil, err
	}

	// CrashFromPoV, not CrashFrom: folding the PoV digest into pathSig keeps frame-less findings distinct in the PERSISTED identity.
	crash := artifact.CrashFromPoV(res.Primary, pathSig, pov)
	// a SEMANTIC finding crashes nothing: derive a divergence/metamorphic frame that keys identically across producers.
	if !res.Primary.Sanitizer.Fired && res.Primary.TermSignal == 0 {
		if sc, ok := semanticCrash(req.Oracle, res, pathSig); ok {
			crash = sc
		}
	}

	// within-run dedup (under harvestMu): one Finding per behavioral identity across ALL producers.
	dk := artifact.ComputeBehavioralKey(crash)
	if l.harvested == nil {
		l.harvested = map[string]bool{}
	}
	if l.harvested[dk] {
		return nil, nil
	}
	l.harvested[dk] = true

	prov := artifact.Provenance{RunID: runID, ExperimentID: res.ExperimentID, Model: model, AcquiredBy: acquiredBy, ToolHashes: l.toolHashes()}
	abstract := summarize(req, crash)

	priv := &artifact.Envelope{
		Artifact: artifact.Artifact{
			Content: artifact.Content{
				Specimen: &artifact.SpecimenRef{BlobHash: blobHash, Media: "application/x-quarry-specimen", Bytes: int64(len(pov))},
				Crash:    crash,
			},
			Reproducer: &artifact.Reproducer{BlobHash: blobHash, Media: "application/x-quarry-specimen", Bytes: int64(len(pov)), Oracle: req.Oracle, Verdict: res.Verdict},
		},
		Placement:  artifact.Private,
		Abstract:   abstract,
		Provenance: prov,
		CreatedAt:  createdAt,
	}
	if err := priv.Artifact.ComputeID(); err != nil {
		return nil, err
	}

	pub := priv.PublicAbstract(abstract, createdAt)
	if err := pub.Artifact.ComputeID(); err != nil {
		return nil, err
	}

	// own the finding LOCALLY before anything leaves this machine: every FATAL write happens here, emit is last (vault: Loop Core).
	if err := l.Store.SaveArtifact(ctx, runID, priv); err != nil {
		return nil, err
	}
	if err := l.Store.SaveArtifact(ctx, runID, pub); err != nil {
		return nil, err
	}
	// fail the harvest on a failed index write: a silent one corrupts later novelty decisions.
	if err := l.Store.RegisterFinding(ctx, priv.Artifact.BehavioralKey(), priv.Artifact.ID, runID); err != nil {
		return nil, fmt.Errorf("register finding: %w", err)
	}
	// novelty is decided ONLY on the primary behavioral key below; the full key set only feeds the cross-reference.
	crashKeys := artifact.CrashKeys(crash)
	var priorArt, primaryHits []channels.PriorArt
	// the primary lookup is the ONE call novelty rests on; track incompletion since absence is not evidence.
	noveltyKnown := true
	if l.Source != nil {
		if pa, err := l.Source.Lookup(ctx, crashKeys); err != nil {
			l.log("prior-art lookup: %v", err)
		} else {
			priorArt = pa
		}
		if len(crashKeys) > 0 {
			pa, err := l.Source.Lookup(ctx, crashKeys[:1])
			if err != nil {
				l.log("primary-key prior-art lookup: %v — novelty undetermined", err)
				noveltyKnown = false
			}
			primaryHits = pa
		}
		l.record(ctx, runID, "query", map[string]string{"source": "prior-art", "keys": strconv.Itoa(len(crashKeys)), "hits": strconv.Itoa(len(priorArt))})
	}

	if err := l.Store.IndexKeys(ctx, priv.Artifact.ID, crashKeys); err != nil {
		return nil, fmt.Errorf("index keys: %w", err)
	}

	// emit last, best-effort: a gate/store failure must not fail the harvest; a TRANSFORMED envelope is persisted too.
	emittedPriv, pubOut := priv, pub
	if l.Gate != nil && l.Sink != nil {
		if e, err := l.Gate.Emit(ctx, l.Sink, priv); err != nil {
			l.log("emit private specimen: %v", err)
		} else {
			emittedPriv = e
		}
		if e, err := l.Gate.Emit(ctx, l.Sink, pub); err != nil {
			l.log("emit public abstract: %v", err)
		} else {
			pubOut = e
		}
		if emittedPriv.Artifact.ID != priv.Artifact.ID {
			if err := l.Store.SaveArtifact(ctx, runID, emittedPriv); err != nil {
				l.log("persist emitted private specimen: %v", err)
			}
		}
		if pubOut.Artifact.ID != pub.Artifact.ID {
			if err := l.Store.SaveArtifact(ctx, runID, pubOut); err != nil {
				l.log("persist emitted public abstract: %v", err)
			}
		}
		l.record(ctx, runID, "emit", map[string]string{"artifact": short(pubOut.Artifact.ID), "bug_class": crash.BugClass})
	}

	// the two federation calls are independent; report whichever hit set we actually have.
	hits := priorArt
	if len(hits) == 0 {
		hits = primaryHits
	}
	// a frame-less crash has only a coarse key: treat a hit as novel (prefer a false split over a false merge).
	novel, novelUnknown := false, false
	switch {
	case !artifact.FramesResolved(crash):
		novel = true
	case !noveltyKnown:
		novelUnknown = true
	default:
		novel = len(primaryHits) == 0
	}
	switch {
	case novelUnknown:
		l.log("harvested artifact %s (public sibling %s) — novelty UNDETERMINED (prior-art lookup failed; counted as neither novel nor rediscovery)",
			short(emittedPriv.Artifact.ID), short(pubOut.Artifact.ID))
	case novel:
		l.log("harvested artifact %s (public sibling %s) — novel", short(emittedPriv.Artifact.ID), short(pubOut.Artifact.ID))
	default:
		ref, src := "(unnamed)", "unknown"
		if len(hits) > 0 {
			ref, src = short(hits[0].ArtifactID), hits[0].Source
		}
		l.log("harvested artifact %s (public sibling %s) — rediscovery, %d prior match(es) incl. %s (%s)",
			short(emittedPriv.Artifact.ID), short(pubOut.Artifact.ID), len(hits), ref, src)
		l.record(ctx, runID, "token-savings", map[string]string{"reason": "rediscovery", "prior_matches": strconv.Itoa(len(hits))})
	}
	return &Finding{HypothesisID: hypID, Statement: statement, Private: emittedPriv, Public: pubOut, PriorArt: hits, Novel: novel, NoveltyUnknown: novelUnknown}, nil
}

// semanticCrash derives the behavioral identity of a SEMANTIC finding from the EXECUTED observation; ok is false for anything else.
func semanticCrash(spec oracle.Spec, res *verify.Result, pathSig string) (artifact.Crash, bool) {
	if d := res.Verdict.Differential; d != nil && d.Rule == oracle.DivergeOnOutput && res.Fixed != nil {
		if sig := divergenceSig(oracle.Observe(res.Primary), oracle.Observe(*res.Fixed)); sig != "" {
			return artifact.SemanticIdentity("logic-divergence", sig, pathSig), true
		}
	}
	// Verdict.Conditions is ordered like the spec's, so the matched condition names its own stream.
	for i, cr := range res.Verdict.Conditions {
		if cr.Type != oracle.CondMetamorphic || !cr.Matched {
			continue
		}
		pair := res.Primary.Stdout
		if i < len(spec.Conditions) && spec.Conditions[i].Stream == "stderr" {
			pair = res.Primary.Stderr
		}
		return artifact.SemanticIdentity("metamorphic-violation", "metamorphic:"+digest(strings.TrimRight(pair, "\n")), pathSig), true
	}
	return artifact.Crash{}, false
}

// divergenceSig names the observable that diverged and digests both sides' values (oracle.Observation set, shared with oracle.OutputsDiverge).
func divergenceSig(target, ref oracle.Observation) string {
	switch {
	case target.Completed != ref.Completed:
		return fmt.Sprintf("divergence:completion=%v/%v", target.Completed, ref.Completed)
	case target.Signal != ref.Signal:
		return fmt.Sprintf("divergence:signal=%d/%d", target.Signal, ref.Signal)
	case target.Exit != ref.Exit:
		return fmt.Sprintf("divergence:exit=%d/%d", target.Exit, ref.Exit)
	case target.Stdout != ref.Stdout:
		return "divergence:stdout=" + digest(target.Stdout) + "/" + digest(ref.Stdout)
	}
	return ""
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// frontierReport composes the run's conclusion (confirmed + also-confirmed + ruled out).
func (l *Loop) frontierReport(ctx context.Context, runID string, findings []Finding, ruledOut, alsoConfirmed []string) string {
	var b strings.Builder
	if len(findings) > 0 {
		fmt.Fprintf(&b, "Confirmed %d finding(s):\n", len(findings))
		for _, f := range findings {
			tag := "novel"
			switch {
			case f.NoveltyUnknown:
				tag = "novelty undetermined (prior-art lookup failed)"
			case !f.Novel:
				tag = fmt.Sprintf("rediscovery of %d", len(f.PriorArt))
			}
			fmt.Fprintf(&b, "  ✓ %s — %s (%s) [%s]\n", short(f.Private.Artifact.ID), f.Private.Artifact.Content.Crash.BugClass, f.Statement, tag)
		}
	}
	if len(alsoConfirmed) > 0 {
		b.WriteString("Also confirmed, not separately harvested (same behavior as another line, or harvest failed):\n")
		for _, c := range alsoConfirmed {
			b.WriteString("  " + c + "\n")
		}
	}
	if len(ruledOut) > 0 {
		b.WriteString("Ruled out within budget (not a proof of absence):\n")
		for _, r := range ruledOut {
			b.WriteString("  " + r + "\n")
		}
	}
	facts, _ := l.Store.Facts(ctx, runID)
	if len(facts) > 0 {
		b.WriteString("Verified facts gathered:\n")
		for _, f := range facts {
			fmt.Fprintf(&b, "  - [%s] %s\n", f.Kind, f.Value)
		}
	}
	return b.String()
}

const (
	seedMaxFileBytes = 1 << 20 // 1 MiB
	seedMaxFiles     = 5000
)

// seedWorkspace copies seed paths into the workspace (a dir under its base name, a file flat). Best-effort and bounded.
func seedWorkspace(ws *agent.Workspace, paths []string) {
	copied := 0
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if info.Size() <= seedMaxFileBytes && copied < seedMaxFiles {
				if b, rerr := os.ReadFile(p); rerr == nil {
					_ = ws.WriteFile(filepath.Base(p), string(b))
					copied++
				}
			}
			continue
		}
		base := filepath.Base(p)
		_ = filepath.WalkDir(p, func(fp string, d os.DirEntry, werr error) error {
			if werr != nil || d.IsDir() || copied >= seedMaxFiles {
				return nil
			}
			fi, ferr := d.Info()
			if ferr != nil || fi.Size() > seedMaxFileBytes {
				return nil
			}
			rel, rerr := filepath.Rel(p, fp)
			if rerr != nil {
				return nil
			}
			if b, rerr := os.ReadFile(fp); rerr == nil {
				_ = ws.WriteFile(filepath.Join(base, rel), string(b))
				copied++
			}
			return nil
		})
	}
}

// pathSig names the input vector a PoV was delivered on; ONE definition (artifact.PathSigFor) or frame-less bugs escape dedup.
func pathSig(req Request) string {
	return artifact.PathSigFor(req.Base.StdinPoV)
}

func acquiredBy(req Request) string {
	if req.Fixed != nil {
		return "differential"
	}
	return "single-snapshot"
}

func summarize(req Request, crash artifact.Crash) string {
	loc := "the target"
	if len(crash.Sites) > 0 && crash.Sites[0] != "" {
		loc = crash.Sites[0]
	}
	return fmt.Sprintf("oracle-confirmed %s reachable in %s via %s input (objective: %s)",
		crash.BugClass, loc, pathSig(req), req.Objective)
}

func short(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (l *Loop) agentRole() string {
	if l.AgentRole != "" {
		return l.AgentRole
	}
	return "exploit-dev"
}

func (l *Loop) catalogTools(sess *agent.Session) []agent.Tool {
	scoped := l.Catalog.ForRole(l.agentRole())
	if len(scoped) == 0 {
		return nil
	}
	broker := toolcat.NewBroker(scoped, wsExecer{sess.Workspace}, mcp.New())
	var out []agent.Tool
	for _, at := range broker.AgentTools() {
		out = append(out, at)
	}
	return out
}

func (l *Loop) toolHashes() []string {
	return toolcat.Hashes(l.Catalog.ForRole(l.agentRole()))
}

// wsExecer adapts a workspace to toolcat.Execer (same exec boundary).
type wsExecer struct{ ws *agent.Workspace }

func (w wsExecer) Exec(ctx context.Context, cmd string, args []string, stdin string, timeout time.Duration) (string, string, int, error) {
	r, err := w.ws.Exec(ctx, cmd, args, stdin, timeout)
	return r.Stdout, r.Stderr, r.ExitCode, err
}

func shortID(runID, hypID string) string {
	clean := func(s string, n int) string {
		s = strings.TrimPrefix(s, "run_")
		s = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, s)
		if len(s) > n {
			s = s[:n]
		}
		return s
	}
	return clean(runID, 12) + "-" + clean(hypID, 8)
}

func addUsage(dst *model.Usage, u model.Usage) {
	dst.PromptTokens += u.PromptTokens
	dst.CompletionTokens += u.CompletionTokens
	dst.TotalTokens += u.TotalTokens
	dst.CostUSD += u.CostUSD
}

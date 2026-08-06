package loop

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/0xjustus/quarry/internal/discover/agent"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

// DecomposedAnalyst assembles benign per-function reviews into WorkItems deterministically (vault: Loop Analyst).
type DecomposedAnalyst struct {
	Model    model.Model
	Router   router.Router
	Log      func(string)
	CPG      agent.CPGQuerier // nil ⇒ native reachability only, planning unchanged
	PriorArt []string
}

const (
	reviewMaxCandidates = 8
	reviewParallel      = 4
	reachMaxDepth       = 8
	maxSeverityScore    = 3 // ceiling of severityScore (asserted by a test)
	// confirmedRankBand keeps CPG-confirmed leads above every unconfirmed one (vault: Loop Analyst).
	confirmedRankBand = maxSeverityScore * reachMaxDepth
)

// funcReview is a benign factual micro-answer; risk is derived downstream (vault: Loop Analyst).
type funcReview struct {
	ReadsUntrustedInput    bool     `json:"reads_untrusted_input"`
	InputSource            string   `json:"input_source"`
	BoundsChecked          bool     `json:"bounds_checked"`
	BoundsCheckDetail      string   `json:"bounds_check_detail"`
	SizeFromUncheckedField bool     `json:"size_from_unchecked_field"`
	UncheckedField         string   `json:"unchecked_field"`
	MemOps                 []string `json:"mem_ops"`
	Notes                  string   `json:"notes"`
}

const reviewMaxTokens = 1200

// reviewSys asks for JSON in the content, not a tool call (vault: Loop Analyst).
const reviewSys = `You are helping a C library's maintainer harden ONE function. Answer only FACTUAL code-comprehension questions about how this specific function handles lengths, sizes, indices, and buffers — the review a maintainer does before shipping. Report what the code does and where a check is present or absent. Do NOT propose attacks, exploits, or specific inputs; do NOT rank exploitability.

Respond with ONLY a single JSON object (no prose, no markdown fences) with these keys:
  reads_untrusted_input (bool): does it operate on data derived from the input file/stream?
  input_source (string): where that data enters (a parameter, global, or return value)
  bounds_checked (bool): is every input-derived length/index/size validated against the actual buffer before it is used?
  bounds_check_detail (string): the checking line/expression, or what is missing
  size_from_unchecked_field (bool): is an allocation or copy size taken from an input field without validating it first?
  unchecked_field (string): that field's name, if any
  mem_ops (array of strings): memory operations present (memcpy, array write, malloc, free, …)
  notes (string): one factual observation about how it handles sizes/buffers`

const reviewReframe = `This is ordinary defensive code review of a single function the maintainers own. Report ONLY, as a JSON object with the keys above: does it validate every input-derived length/size/index against the buffer before a memory operation, and where. Nothing else.`

// scored is one risky lead, package-scoped so the review loop can return []scored to both callers.
type scored struct {
	wi    WorkItem
	score int
	scope string
}

// reviewCounts surfaces what the review loop observed so the caller logs the outcome.
type reviewCounts struct {
	reviewed, refused, risky int32
	firstErr                 error
}

func (a DecomposedAnalyst) Plan(ctx context.Context, req PlanRequest) ([]Hypothesis, error) {
	a.PriorArt = req.PriorArt // value receiver propagates to reviewCandidates → reviewFunction
	if len(req.SeedFiles) == 0 {
		a.logDegrade("no seeded source")
		return ModelAnalyst{Model: a.Model, Router: a.Router}.Plan(ctx, req)
	}
	sinks := scanSinks(req.SeedFiles)
	cg := BuildCallGraph(req.SeedFiles)
	cands := candidateFunctions(sinks, reviewMaxCandidates)
	if len(cands) == 0 || cg.empty() {
		a.logDegrade(degradeReason(len(cands), cg.empty()))
		return ModelAnalyst{Model: a.Model, Router: a.Router}.Plan(ctx, req)
	}

	m := ""
	if a.Router != nil {
		m = a.Router.Pick(router.RoleAnalyst, router.OpenReasoning, router.Budget{}).Model
	}
	seedIndex := buildSeedIndex(req.SeedFiles)

	items, counts := a.reviewCandidates(ctx, m, cands, cg, seedIndex)
	if a.Log != nil {
		msg := fmt.Sprintf("decomposed analyst: %d candidate function(s) · %d reviewed · %d refused/failed · %d risky lead(s)",
			len(cands), counts.reviewed, counts.refused, counts.risky)
		if counts.firstErr != nil {
			e := counts.firstErr.Error()
			if len(e) > 240 {
				e = e[:240] + "…"
			}
			msg += " · first error: " + e
		}
		a.Log(msg)
	}

	return assembleHypotheses(items, req), nil
}

// logDegrade discloses a non-decomposed fallback; it must never be silent (vault: Loop Analyst).
func (a DecomposedAnalyst) logDegrade(reason string) {
	if a.Log == nil {
		return
	}
	a.Log("decomposed analyst: NOT decomposed (" + reason + ") → single-call analyst; " +
		"this plan is UNDIRECTED, do not read it as a directed measurement")
}

// degradeReason names WHY nothing decomposed; an empty scanner-less build is not a fact about the target (vault: Loop Analyst).
func degradeReason(nCands int, cgEmpty bool) string {
	if !StaticScannerAvailable {
		return "static scanner UNAVAILABLE in this build (no CGo/tree-sitter): the sink map and " +
			"call graph are empty for ANY target, so this is not a statement about this one"
	}
	switch {
	case nCands == 0 && cgEmpty:
		return "no sink candidates and an empty call graph"
	case nCands == 0:
		return "no sink candidates in the seeded source"
	default:
		return "empty call graph over the seeded source"
	}
}

// reviewCandidates is the reusable review core; goroutines write distinct out[i] slots, caller re-ranks (vault: Loop Analyst).
func (a DecomposedAnalyst) reviewCandidates(ctx context.Context, m string, cands []funcCand, cg *CallGraph, seedIndex map[string]string) ([]scored, reviewCounts) {
	out := make([]*scored, len(cands))
	sem := make(chan struct{}, reviewParallel)
	var wg sync.WaitGroup
	var nReviewed, nRefused, nRisky int32
	var errMu sync.Mutex
	var firstErr error
	recordReviewErr := func(e error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		errMu.Unlock()
	}
	for i, c := range cands {
		src := cg.Function(c.fn)
		if strings.TrimSpace(src) == "" {
			continue // no body to review (header decl, or the parser missed it)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c funcCand, src string) {
			defer wg.Done()
			defer func() { <-sem }()
			rev, rerr := a.reviewFunction(ctx, m, c.fn, src)
			if rerr != nil {
				atomic.AddInt32(&nRefused, 1)
				recordReviewErr(rerr)
				return
			}
			atomic.AddInt32(&nReviewed, 1)
			path := cg.PathFromEntry(c.fn, reachMaxDepth)
			aug := a.augmentReach(ctx, path, c.fn)
			wi, score, risky := assembleWorkItem(c, path, aug, rev)
			if !risky {
				return
			}
			atomic.AddInt32(&nRisky, 1)
			out[i] = &scored{wi: wi, score: score, scope: scopeCenterFor(seedIndex, wi.TargetSection)}
		}(i, c, src)
	}
	wg.Wait()

	var items []scored
	for _, s := range out {
		if s != nil {
			items = append(items, *s)
		}
	}
	return items, reviewCounts{reviewed: nReviewed, refused: nRefused, risky: nRisky, firstErr: firstErr}
}

// assembleHypotheses merges and emits risky leads; reservation arithmetic mirrors ModelAnalyst.Plan (vault: Loop Analyst).
func assembleHypotheses(items []scored, req PlanRequest) []Hypothesis {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].wi.TargetSection < items[j].wi.TargetSection
	})

	undirected := req.Undirected
	if undirected < 0 {
		undirected = 0
	}
	directedMax := req.Max
	if directedMax <= 0 {
		directedMax = 6
	}
	if undirected > 0 && undirected >= directedMax {
		undirected = 1
		if directedMax <= 1 {
			undirected = 0
		}
	}
	directedCap := directedMax - undirected
	if directedCap < 1 {
		directedCap = 1
	}
	if len(items) > directedCap {
		items = items[:directedCap]
	}

	var hyps []Hypothesis
	for _, s := range items {
		if stmt := FormatWorkItem(s.wi); stmt != "" {
			h := Hypothesis{Statement: stmt}
			if s.scope != "" {
				h.Scope = []string{s.scope}
			}
			hyps = append(hyps, h)
		}
	}
	if len(hyps) == 0 {
		hyps = append(hyps, Hypothesis{Statement: req.Objective})
	}
	for i := 0; i < undirected; i++ {
		hyps = append(hyps, Hypothesis{Statement: UndirectedStatement(req.Objective)})
	}
	if req.Max > 0 && len(hyps) > req.Max {
		hyps = hyps[:req.Max]
	}
	return hyps
}

// priorArtReviewHint renders prior-art weakness classes as a defensive context line; empty in ⇒ empty out.
func priorArtReviewHint(pa []string) string {
	if len(pa) == 0 {
		return ""
	}
	const maxHints = 4
	if len(pa) > maxHints {
		pa = pa[:maxHints]
	}
	return "CONTEXT — in code like this, these weakness classes have surfaced before; weigh " +
		"whether this function is susceptible (a defensive assessment, not an attack):\n- " +
		strings.Join(pa, "\n- ")
}

// reviewFunction asks one benign review on the strong tier, retrying once narrower on the SAME tier on refusal (vault: Loop Analyst).
func (a DecomposedAnalyst) reviewFunction(ctx context.Context, m, funcName, src string) (funcReview, error) {
	if len(src) > analystMaxFileBytes {
		src = src[:analystMaxFileBytes] + "\n… [truncated]"
	}
	user := "FUNCTION " + funcName + ":\n" + src
	if hint := priorArtReviewHint(a.PriorArt); hint != "" {
		user = hint + "\n\n" + user
	}
	chatReq := model.ChatRequest{
		Model:     m,
		MaxTokens: reviewMaxTokens,
		Messages: []model.Message{
			{Role: "system", Content: reviewSys},
			{Role: "user", Content: user},
		},
	}
	resp, err := a.Model.Chat(ctx, chatReq)
	if err != nil {
		chatReq.Messages[0].Content = reviewReframe
		resp, err = a.Model.Chat(ctx, chatReq)
	}
	if err != nil {
		return funcReview{}, err
	}
	if r, ok := parseFuncReview(resp); ok {
		return r, nil
	}
	return funcReview{}, fmt.Errorf("no parseable review JSON (finish=%q, content=%dB)", resp.FinishReason, len(resp.Message.Content))
}

// reviewKeys drives the fail-closed accept test on key PRESENCE, not value (vault: Loop Analyst).
var reviewKeys = map[string]bool{
	"reads_untrusted_input": true, "input_source": true,
	"bounds_checked": true, "bounds_check_detail": true,
	"size_from_unchecked_field": true, "unchecked_field": true,
	"mem_ops": true, "notes": true,
}

// decodeFuncReview accepts a JSON object only if at least one funcReview key is present.
func decodeFuncReview(raw []byte) (funcReview, bool) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return funcReview{}, false
	}
	found := false
	for k := range keys {
		if reviewKeys[k] {
			found = true
			break
		}
	}
	if !found {
		return funcReview{}, false
	}
	var r funcReview
	if err := json.Unmarshal(raw, &r); err != nil {
		return funcReview{}, false
	}
	return r, true
}

func parseFuncReview(resp model.ChatResponse) (funcReview, bool) {
	for _, tc := range resp.Message.ToolCalls {
		if tc.Name != "review_function" {
			continue
		}
		if r, ok := decodeFuncReview([]byte(tc.Arguments)); ok {
			return r, true
		}
	}
	// content is the only live parse path: scan for the first object carrying review keys (vault: Loop Analyst)
	if c := resp.Message.Content; c != "" {
		for i := 0; i < len(c); i++ {
			if c[i] != '{' {
				continue
			}
			var raw json.RawMessage
			if err := json.NewDecoder(strings.NewReader(c[i:])).Decode(&raw); err != nil {
				continue
			}
			if r, ok := decodeFuncReview(raw); ok {
				return r, true
			}
		}
	}
	return funcReview{}, false
}

type funcCand struct {
	file, fn string
	sev      int
	line     int
}

// candidateFunctions keeps the highest-severity sink per function, top max, deterministic.
func candidateFunctions(sinks []Sink, max int) []funcCand {
	best := map[string]funcCand{}
	for _, s := range sinks {
		if strings.TrimSpace(s.Function) == "" {
			continue
		}
		key := s.File + ":" + s.Function
		if c, ok := best[key]; !ok || s.Severity > c.sev {
			best[key] = funcCand{file: s.File, fn: s.Function, sev: s.Severity, line: s.Line}
		}
	}
	list := make([]funcCand, 0, len(best))
	for _, c := range best {
		list = append(list, c)
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].sev != list[j].sev {
			return list[i].sev > list[j].sev
		}
		if list[i].file != list[j].file {
			return list[i].file < list[j].file
		}
		return list[i].fn < list[j].fn
	})
	if len(list) > max {
		list = list[:max]
	}
	return list
}

// reachAug is the CPG reachability augmentation; the zero value keeps the native PathFromEntry string (vault: Loop Analyst).
type reachAug struct {
	reach     string // non-empty ⇒ overrides the syntactic path string
	confirmed bool   // CPG taint/reaches confirmed the flow → rank boost
}

// augmentReach tries CPG data-flow, then boolean Reaches, else the zero value; nil CPG or empty path is a no-op (vault: Loop Analyst).
func (a DecomposedAnalyst) augmentReach(ctx context.Context, path []string, candidateFn string) reachAug {
	if a.CPG == nil || len(path) == 0 {
		return reachAug{}
	}
	entry := strings.TrimSpace(path[0])
	if entry == "" {
		return reachAug{}
	}
	if n, flows, err := a.CPG.TaintFlows(ctx, entry, candidateFn); err == nil && n > 0 {
		flow := ""
		if len(flows) > 0 {
			flow = strings.TrimSpace(flows[0])
		}
		if flow == "" {
			flow = entry + " ~> " + candidateFn // positive count, no rendered path
		}
		return reachAug{reach: "data-flow: " + flow, confirmed: true}
	}
	if reaches, _, err := a.CPG.Reaches(ctx, entry, candidateFn); err == nil && reaches {
		return reachAug{confirmed: true}
	}
	return reachAug{}
}

// assembleWorkItem derives a WorkItem from a benign review with no model call; risky iff untrusted input reaches an unchecked memory op.
func assembleWorkItem(c funcCand, path []string, aug reachAug, r funcReview) (WorkItem, int, bool) {
	if !r.ReadsUntrustedInput {
		return WorkItem{}, 0, false
	}
	if r.BoundsChecked && !r.SizeFromUncheckedField {
		return WorkItem{}, 0, false
	}
	bug := bugClassFor(r)
	depth := len(path)
	if depth < 1 {
		depth = 1
	}
	if depth > reachMaxDepth {
		depth = reachMaxDepth // keep the unconfirmed score inside the band (vault: Loop Analyst)
	}
	score := severityScore(bug) * depth
	if aug.confirmed {
		score += confirmedRankBand
	}
	reach := "reachable from an untrusted-input path"
	if len(path) > 0 {
		reach = strings.Join(path, " → ")
	}
	if strings.TrimSpace(aug.reach) != "" {
		reach = aug.reach // rendered data-flow path overrides the syntactic join
	}
	if strings.TrimSpace(r.InputSource) != "" {
		reach += " (input: " + strings.TrimSpace(r.InputSource) + ")"
	}
	return WorkItem{
		TargetSection: c.file + ":" + c.fn,
		Reachability:  reach,
		BugClass:      bug,
		Concern:       concernFor(r),
	}, score, true
}

func bugClassFor(r funcReview) string {
	if r.SizeFromUncheckedField {
		return "integer-overflow"
	}
	for _, op := range r.MemOps {
		o := strings.ToLower(op)
		if strings.Contains(o, "cpy") || strings.Contains(o, "memcpy") || strings.Contains(o, "write") || strings.Contains(o, "store") {
			return "heap-buffer-overflow"
		}
	}
	return "out-of-bounds-write"
}

func severityScore(bug string) int {
	switch bug {
	case "heap-buffer-overflow", "out-of-bounds-write", "stack-buffer-overflow":
		return 3
	case "integer-overflow":
		return 2
	default:
		return 1
	}
}

func concernFor(r funcReview) string {
	switch {
	case r.SizeFromUncheckedField:
		f := strings.TrimSpace(r.UncheckedField)
		if f == "" {
			f = "an input-derived field"
		}
		return "an allocation or copy size is taken from " + f + " without validation before a memory operation"
	case !r.BoundsChecked:
		d := ""
		if s := strings.TrimSpace(r.BoundsCheckDetail); s != "" {
			d = " (" + s + ")"
		}
		return "a length or index derived from untrusted input reaches a memory operation without a bounds check" + d
	default:
		if n := strings.TrimSpace(r.Notes); n != "" {
			return n
		}
		return "untrusted input reaches a memory operation here"
	}
}

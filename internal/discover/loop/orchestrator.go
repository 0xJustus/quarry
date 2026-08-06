package loop

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/0xjustus/quarry/internal/discover/agent"
	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

// OrchestratedAnalyst is the analyst-side map-reduce for large monoliths: per-file slices deep-audited then merged; subsumes DecomposedAnalyst.
type OrchestratedAnalyst struct {
	Model  model.Model
	Router router.Router
	Log    func(string)
	// CPG, when set, is threaded into every slice-worker for interprocedural taint; nil ⇒ native PathFromEntry only.
	CPG agent.CPGQuerier
	// MaxWorkers bounds how many sink-slices are deep-audited (excess dropped); <=0 ⇒ orchestratorDefaultWorkers.
	MaxWorkers int
}

const (
	orchestratorMaxCandidates  = 200
	orchestratorDefaultWorkers = 6
	// orchestratorSliceParallel: kept modest because all workers share one warm CPG session.
	orchestratorSliceParallel = 4
)

// fileSlice is one source file's candidate functions; sev is the summed severity used to rank slices.
type fileSlice struct {
	file  string
	cands []funcCand
	sev   int
}

// Plan runs the map-reduce, returning DecomposedAnalyst-shaped Hypotheses plus the undirected breadth slots.
func (a OrchestratedAnalyst) Plan(ctx context.Context, req PlanRequest) ([]Hypothesis, error) {
	if len(req.SeedFiles) == 0 {
		return DecomposedAnalyst{Model: a.Model, Router: a.Router, Log: a.Log, CPG: a.CPG}.Plan(ctx, req)
	}

	sinks := scanSinks(req.SeedFiles)
	cg := BuildCallGraph(req.SeedFiles)
	seedIndex := buildSeedIndex(req.SeedFiles)

	cands := candidateFunctions(sinks, orchestratorMaxCandidates)
	if len(cands) == 0 || cg.empty() {
		return DecomposedAnalyst{Model: a.Model, Router: a.Router, Log: a.Log, CPG: a.CPG}.Plan(ctx, req)
	}

	slices := partitionByFile(cands)

	sort.SliceStable(slices, func(i, j int) bool {
		if slices[i].sev != slices[j].sev {
			return slices[i].sev > slices[j].sev
		}
		return slices[i].file < slices[j].file
	})

	workers := a.MaxWorkers
	if workers <= 0 {
		workers = orchestratorDefaultWorkers
	}
	total := len(slices)
	dropped := 0
	if total > workers {
		dropped = total - workers
		slices = slices[:workers]
	}
	if a.Log != nil {
		a.Log(fmt.Sprintf("orchestrator: %d sink-slices, %d workers (%d dropped by budget)", total, workers, dropped))
	}

	m := ""
	if a.Router != nil {
		m = a.Router.Pick(router.RoleAnalyst, router.OpenReasoning, router.Budget{}).Model
	}

	// MAP: each slice is deep-audited in bounded parallel into per-slice slots (no arrival-order leak).
	worker := DecomposedAnalyst{Model: a.Model, Router: a.Router, CPG: a.CPG, PriorArt: req.PriorArt}
	merged := make([][]scored, len(slices))
	sem := make(chan struct{}, orchestratorSliceParallel)
	var wg sync.WaitGroup
	for i := range slices {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			items, _ := worker.reviewCandidates(ctx, m, slices[i].cands, cg, seedIndex)
			merged[i] = items
		}(i)
	}
	wg.Wait()

	// REDUCE: merge in deterministic slice order, dedup by target section, then the shared assembly.
	var all []scored
	for _, items := range merged {
		all = append(all, items...)
	}
	deduped := dedupByTargetSection(all)
	if a.Log != nil {
		a.Log(fmt.Sprintf("orchestrator: %d slices reviewed → %d risky leads (%d after dedup)", len(slices), len(all), len(deduped)))
	}
	return assembleHypotheses(deduped, req), nil
}

// partitionByFile groups candidates into per-file slices (summed severity), in deterministic first-encounter order.
func partitionByFile(cands []funcCand) []fileSlice {
	idx := map[string]int{}
	var out []fileSlice
	for _, c := range cands {
		i, ok := idx[c.file]
		if !ok {
			i = len(out)
			idx[c.file] = i
			out = append(out, fileSlice{file: c.file})
		}
		out[i].cands = append(out[i].cands, c)
		out[i].sev += c.sev
	}
	return out
}

// dedupByTargetSection collapses leads sharing a target section, keeping the highest score (first-appearance order).
func dedupByTargetSection(items []scored) []scored {
	at := map[string]int{}
	var out []scored
	for _, s := range items {
		if i, ok := at[s.wi.TargetSection]; ok {
			if s.score > out[i].score {
				out[i] = s
			}
			continue
		}
		at[s.wi.TargetSection] = len(out)
		out = append(out, s)
	}
	return out
}

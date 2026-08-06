package strategy

import (
	"context"
	"fmt"
	"math"
)

// stride/credit allocation: deterministic, no randomness, ties to lowest index
type Scheduler struct {
	strategies []Strategy
	minShare   float64
	alpha      float64

	credit []float64
	yield  []float64
	stat   []StratStat
}

// non-zero: a never-run leg must read as promising or it is locked out forever
const coldYield = 1.0

const defaultAlpha = 0.5

type StratStat struct {
	Name          string
	Kind          Kind
	Steps         int
	NewInputs     int
	CoverageDelta int
	Solved        int
	TotalYield    float64
	Errors        int
}

type Report struct {
	Epochs int
	Stats  []StratStat // index-parallel to the strategies given to NewScheduler
}

func NewScheduler(strategies []Strategy, minShare float64) (*Scheduler, error) {
	n := len(strategies)
	if n == 0 {
		return nil, fmt.Errorf("strategy: scheduler needs at least one strategy")
	}
	if minShare < 0 || math.IsNaN(minShare) {
		return nil, fmt.Errorf("strategy: minShare must be >= 0, got %v", minShare)
	}
	if float64(n)*minShare > 1+1e-9 {
		return nil, fmt.Errorf("strategy: minShare %v * %d strategies exceeds 1 (floors unsatisfiable)", minShare, n)
	}
	s := &Scheduler{
		strategies: strategies,
		minShare:   minShare,
		alpha:      defaultAlpha,
		credit:     make([]float64, n),
		yield:      make([]float64, n),
		stat:       make([]StratStat, n),
	}
	for i, st := range strategies {
		s.yield[i] = coldYield
		s.stat[i] = StratStat{Name: st.Name(), Kind: st.Kind()}
	}
	return s, nil
}

// mutates credit in place; Plan and RunEpochs must share it to allocate alike
func pick(credit, yields []float64, minShare float64) int {
	n := len(yields)
	total := 0.0
	for _, y := range yields {
		total += y
	}
	slack := 1 - float64(n)*minShare
	if slack < 0 {
		slack = 0
	}
	best, bestCredit := 0, math.Inf(-1)
	for i := 0; i < n; i++ {
		var prop float64
		if total > 0 {
			prop = yields[i] / total
		} else {
			prop = 1.0 / float64(n) // no signal yet: split evenly
		}
		credit[i] += minShare + slack*prop
		if credit[i] > bestCredit {
			bestCredit = credit[i]
			best = i
		}
	}
	credit[best] -= 1
	return best
}

func (s *Scheduler) Plan(epochs int) []int {
	counts := make([]int, len(s.strategies))
	if epochs <= 0 {
		return counts
	}
	// copies: a preview must not mutate live scheduler state
	credit := append([]float64(nil), s.credit...)
	yields := append([]float64(nil), s.yield...)
	for e := 0; e < epochs; e++ {
		counts[pick(credit, yields, s.minShare)]++
	}
	return counts
}

func (s *Scheduler) RunEpochs(ctx context.Context, epochs int, budget StepBudget) (Report, error) {
	for e := 0; e < epochs; e++ {
		if err := ctx.Err(); err != nil {
			return s.report(e), err
		}
		j := pick(s.credit, s.yield, s.minShare)
		prog, err := s.strategies[j].Step(ctx, budget)

		st := &s.stat[j]
		st.Steps++
		var observed float64
		if err != nil {
			st.Errors++
			observed = 0 // a failed step keeps its floor but loses share; never dropped
		} else {
			st.NewInputs += prog.NewInputs
			st.CoverageDelta += prog.CoverageDelta
			st.Solved += prog.Solved
			y := prog.Yield()
			st.TotalYield += y
			observed = y
		}
		s.yield[j] = s.alpha*observed + (1-s.alpha)*s.yield[j]
	}
	return s.report(epochs), nil
}

func (s *Scheduler) report(epochs int) Report {
	return Report{Epochs: epochs, Stats: append([]StratStat(nil), s.stat...)}
}

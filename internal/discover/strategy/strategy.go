// Package strategy wraps each search technique as one schedulable leg.
package strategy

import (
	"context"
	"time"
)

type Kind string

const (
	CoverageMutational Kind = "coverage-mutational"
	LLMDirected        Kind = "llm-directed"
	Concolic           Kind = "concolic"
)

// counts are for one Step only; the Scheduler accumulates them
type Progress struct {
	NewInputs     int
	CoverageDelta int
	Solved        int
	Detail        string
}

func (p Progress) Yield() float64 {
	return float64(p.NewInputs + p.CoverageDelta + p.Solved)
}

type StepBudget struct {
	MaxDuration time.Duration // 0 = the strategy's own default
	MaxExecs    int           // 0 = unbounded
}

// a leg only proposes leads; the oracle alone decides a finding
type Strategy interface {
	Name() string
	Kind() Kind
	// Step must be a bounded advance, not a whole campaign
	Step(ctx context.Context, budget StepBudget) (Progress, error)
}

type FuncStrategy struct {
	StrategyName string
	StrategyKind Kind
	StepFn       func(ctx context.Context, budget StepBudget) (Progress, error)
}

func (f FuncStrategy) Name() string { return f.StrategyName }
func (f FuncStrategy) Kind() Kind   { return f.StrategyKind }

func (f FuncStrategy) Step(ctx context.Context, budget StepBudget) (Progress, error) {
	if f.StepFn == nil {
		return Progress{Detail: "func-strategy: no StepFn wired"}, nil
	}
	return f.StepFn(ctx, budget)
}

var _ Strategy = FuncStrategy{}

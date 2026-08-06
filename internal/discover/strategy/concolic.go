package strategy

import (
	"context"
	"fmt"
)

type ConstraintSolver interface {
	// (nil, 0, nil) is the ONLY honest negative; anything unresolved must error
	Solve(ctx context.Context, seed []byte) (inputs [][]byte, solved int, err error)
}

// with no Engine wired Step is a real no-op: never fabricate inputs or coverage
type ConcolicStub struct {
	StrategyName string
	Engine       ConstraintSolver
	Seeds        func() []byte
	Sink         func([]byte) // nil ⇒ solved inputs are counted, not shared
}

func (c *ConcolicStub) Name() string {
	if c.StrategyName != "" {
		return c.StrategyName
	}
	return "concolic-stub"
}

func (c *ConcolicStub) Kind() Kind { return Concolic }

func (c *ConcolicStub) Step(ctx context.Context, budget StepBudget) (Progress, error) {
	if c.Engine == nil {
		return Progress{Detail: "concolic stub: no engine wired — no constraints solved"}, nil
	}
	var seed []byte
	if c.Seeds != nil {
		seed = c.Seeds()
	}
	if len(seed) == 0 {
		return Progress{Detail: "concolic: no seed available — nothing to drive"}, nil
	}
	// enforce the budget here: the ConstraintSolver seam only sees a ctx
	if budget.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget.MaxDuration)
		defer cancel()
	}
	inputs, solved, err := c.Engine.Solve(ctx, seed)
	if err != nil {
		return Progress{Detail: "concolic: solver error"}, err
	}
	// cut short before a verdict: inconclusive, never a clean negative
	if len(inputs) == 0 && solved == 0 && ctx.Err() != nil {
		return Progress{Detail: "concolic: cut short before the engine reached a verdict — INCONCLUSIVE, not a clean negative"},
			fmt.Errorf("concolic: step cut short before a verdict: %w", ctx.Err())
	}
	if c.Sink != nil {
		for _, in := range inputs {
			c.Sink(in)
		}
	}
	return Progress{
		NewInputs: len(inputs),
		Solved:    solved,
		Detail:    "concolic: solved path constraints",
	}, nil
}

var _ Strategy = (*ConcolicStub)(nil)

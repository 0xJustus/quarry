package fuzz

import (
	"math"
	"math/rand"
	"sort"
)

// FuncCoverage is one function's reached-vs-total instrumentation count (blocks or edges).
type FuncCoverage struct {
	Covered int
	Total   int
}

// no coverage data yet (Total <= 0) is maximally cold, never silently dropped
func coldness(fc FuncCoverage) float64 {
	if fc.Total <= 0 {
		return 1
	}
	c := 1 - float64(fc.Covered)/float64(fc.Total)
	if c < 0 {
		return 0
	}
	if c > 1 {
		return 1
	}
	return c
}

// softmax probability over coldness, summing to 1; temp → 0 sharpens toward the coldest
func ColdWeights(cov map[string]FuncCoverage, temp float64) map[string]float64 {
	weights := make(map[string]float64, len(cov))
	if len(cov) == 0 {
		return weights
	}
	if temp <= 0 {
		temp = 1e-6
	}
	// subtract the max logit first: a small temp would otherwise overflow to +Inf
	logits := make(map[string]float64, len(cov))
	maxLogit := math.Inf(-1)
	for fn, fc := range cov {
		l := coldness(fc) / temp
		logits[fn] = l
		if l > maxLogit {
			maxLogit = l
		}
	}
	var sum float64
	for fn, l := range logits {
		w := math.Exp(l - maxLogit)
		weights[fn] = w
		sum += w
	}
	for fn := range weights {
		weights[fn] /= sum
	}
	return weights
}

// draws one function ∝ its cold-softmax weight, consuming one r.Float64()
func SampleCold(cov map[string]FuncCoverage, temp float64, r *rand.Rand) (fn string, ok bool) {
	weights := ColdWeights(cov, temp)
	if len(weights) == 0 {
		return "", false
	}
	names := make([]string, 0, len(weights))
	for n := range weights {
		names = append(names, n)
	}
	sort.Strings(names) // map order must not change the pick: campaigns stay reproducible
	x := r.Float64()
	var cum float64
	for _, n := range names {
		cum += weights[n]
		if x < cum {
			return n, true
		}
	}
	// float rounding can leave the walk a hair short of 1.0
	return names[len(names)-1], true
}

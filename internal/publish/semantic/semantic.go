// Package semantic is the near-dup hint tier over artifact feature sets.
package semantic

import "sort"

// Score is comparable only within a single provider.
type Candidate struct {
	ID    string
	Score float64
}

// Retrieval only: Query never returns an id that was not Add-ed.
type HintProvider interface {
	Add(id string, features Features)
	Query(features Features, k int) []Candidate
}

type Features []string

// the one normalization point: equal sets must index identically
func (f Features) canonical() []string {
	seen := make(map[string]struct{}, len(f))
	out := make([]string, 0, len(f))
	for _, t := range f {
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (f Features) set() map[string]struct{} {
	c := f.canonical()
	m := make(map[string]struct{}, len(c))
	for _, t := range c {
		m[t] = struct{}{}
	}
	return m
}

func jaccard(a, b map[string]struct{}) float64 {
	inter := 0
	small, large := a, b
	if len(large) < len(small) {
		small, large = large, small
	}
	for t := range small {
		if _, ok := large[t]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// ties break by id: the ranking must be deterministic
func rankTopK(cands []Candidate, k int) []Candidate {
	if k <= 0 {
		return nil
	}
	kept := cands[:0:0]
	for _, c := range cands {
		if c.Score > 0 {
			kept = append(kept, c)
		}
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Score != kept[j].Score {
			return kept[i].Score > kept[j].Score
		}
		return kept[i].ID < kept[j].ID
	})
	if len(kept) > k {
		kept = kept[:k]
	}
	return kept
}

// Package serving is the semantic-retrieval boundary: a local index, plus a remote stub.
package serving

import (
	"context"
	"errors"
	"math"
	"sort"
)

type Item struct {
	ID     string
	Text   string
	Vector []float32
	Meta   map[string]string
}

type Match struct {
	ID    string
	Score float32
	Meta  map[string]string
}

type SemanticEndpoint interface {
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	Upsert(ctx context.Context, items []Item) error
	Query(ctx context.Context, text string, topK int) ([]Match, error)
}

const Dim = 256

// not concurrency-safe: callers own synchronisation
type LocalServing struct {
	dim   int
	items map[string]Item
}

func NewLocalServing() *LocalServing {
	return &LocalServing{dim: Dim, items: map[string]Item{}}
}

// token-hashing embedder: captures lexical overlap, not semantics
func (l *LocalServing) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = l.embed(t)
	}
	return out, nil
}

func (l *LocalServing) embed(text string) []float32 {
	v := make([]float32, l.dim)
	for _, tok := range tokenize(text) {
		v[fnv1a(tok)%uint32(l.dim)]++
	}
	normalize(v)
	return v
}

func (l *LocalServing) Upsert(ctx context.Context, items []Item) error {
	for _, it := range items {
		if it.ID == "" {
			return errors.New("serving: upsert: item has no id")
		}
		vec := it.Vector
		if len(vec) == 0 {
			if it.Text == "" {
				return errors.New("serving: upsert: item " + it.ID + " has neither vector nor text")
			}
			vec = l.embed(it.Text)
		} else {
			// copy + normalise so Query's dot product is a cosine
			vec = append([]float32(nil), vec...)
			normalize(vec)
		}
		if len(vec) != l.dim {
			return errors.New("serving: upsert: item " + it.ID + " vector dimension mismatch")
		}
		l.items[it.ID] = Item{ID: it.ID, Text: it.Text, Vector: vec, Meta: it.Meta}
	}
	return nil
}

func (l *LocalServing) Query(_ context.Context, text string, topK int) ([]Match, error) {
	if topK <= 0 {
		return nil, nil
	}
	q := l.embed(text)
	matches := make([]Match, 0, len(l.items))
	for _, it := range l.items {
		matches = append(matches, Match{ID: it.ID, Score: dot(q, it.Vector), Meta: it.Meta})
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].ID < matches[j].ID // ties break by id for determinism
	})
	if len(matches) > topK {
		matches = matches[:topK]
	}
	return matches, nil
}

func (l *LocalServing) Len() int { return len(l.items) }

func tokenize(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			cur = append(cur, r+('a'-'A'))
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			cur = append(cur, r)
		default:
			flush()
		}
	}
	flush()
	return out
}

func fnv1a(s string) uint32 {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}

func normalize(v []float32) {
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	if sum == 0 {
		return
	}
	inv := float32(1 / math.Sqrt(sum))
	for i := range v {
		v[i] *= inv
	}
}

func dot(a, b []float32) float32 {
	var s float32
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		s += a[i] * b[i]
	}
	return s
}

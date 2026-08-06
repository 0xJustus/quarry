package semantic

import "math"

// Embed must be deterministic: equal features always yield the same vector.
type Embedder interface {
	Embed(features Features) []float64
	Dim() int
}

type HashingEmbedder struct {
	D int
}

func NewHashingEmbedder(dim int) *HashingEmbedder {
	if dim <= 0 {
		dim = 256
	}
	return &HashingEmbedder{D: dim}
}

func (h *HashingEmbedder) Dim() int { return h.D }

// counts stay non-negative: a signed hash breaks cosine in [0,1]
func (h *HashingEmbedder) Embed(features Features) []float64 {
	v := make([]float64, h.D)
	for _, tok := range features.canonical() {
		v[baseHash(tok)%uint64(h.D)]++
	}
	var norm float64
	for _, x := range v {
		norm += x * x
	}
	if norm == 0 {
		return v
	}
	norm = math.Sqrt(norm)
	for i := range v {
		v[i] /= norm
	}
	return v
}

type VectorStore struct {
	emb  Embedder
	ids  []string
	vecs [][]float64
	idx  map[string]int // id -> slot: Add replaces, never duplicates
}

func NewVectorStore(emb Embedder) *VectorStore {
	if emb == nil {
		emb = NewHashingEmbedder(0)
	}
	return &VectorStore{emb: emb, idx: make(map[string]int)}
}

func (s *VectorStore) Len() int { return len(s.ids) }

func (s *VectorStore) Add(id string, features Features) {
	vec := s.emb.Embed(features)
	if slot, ok := s.idx[id]; ok {
		s.vecs[slot] = vec
		return
	}
	s.idx[id] = len(s.ids)
	s.ids = append(s.ids, id)
	s.vecs = append(s.vecs, vec)
}

func (s *VectorStore) Query(features Features, k int) []Candidate {
	if k <= 0 {
		return nil
	}
	q := s.emb.Embed(features)
	if allZero(q) {
		return nil
	}
	cands := make([]Candidate, 0, len(s.ids))
	for i, id := range s.ids {
		cands = append(cands, Candidate{ID: id, Score: cosine(q, s.vecs[i])})
	}
	return rankTopK(cands, k)
}

// a plain dot product: vectors arrive L2-normalized from the embedder
func cosine(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot float64
	for i := range a {
		dot += a[i] * b[i]
	}
	return dot
}

func allZero(v []float64) bool {
	for _, x := range v {
		if x != 0 {
			return false
		}
	}
	return true
}

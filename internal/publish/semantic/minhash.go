package semantic

import (
	"encoding/binary"
	"hash/fnv"
	"math"
	"math/bits"
	"math/rand"
)

// Candidates come from LSH; the Score is the exact Jaccard of the stored sets.
type Index struct {
	numPerm int
	rows    int
	bands   int

	a, b []uint64

	entries map[string]indexEntry
	buckets map[uint64][]string
}

type indexEntry struct {
	sig []uint64
	set map[string]struct{}
}

const mersennePrime = uint64((1 << 61) - 1)

// fixed seed: the index must rank identically across processes
const permSeed = 0x1247_5EED_C0DE_1234

func NewIndex() *Index { return NewIndexParams(128, 4) }

func NewIndexParams(numPerm, rows int) *Index {
	if numPerm <= 0 || rows <= 0 {
		panic("semantic: numPerm and rows must be positive")
	}
	if numPerm%rows != 0 {
		panic("semantic: rows must divide numPerm evenly")
	}
	idx := &Index{
		numPerm: numPerm,
		rows:    rows,
		bands:   numPerm / rows,
		a:       make([]uint64, numPerm),
		b:       make([]uint64, numPerm),
		entries: make(map[string]indexEntry),
		buckets: make(map[uint64][]string),
	}
	rng := rand.New(rand.NewSource(permSeed))
	for i := 0; i < numPerm; i++ {
		// a >= 1 keeps the universal hash non-degenerate
		idx.a[i] = 1 + uint64(rng.Int63n(int64(mersennePrime-1)))
		idx.b[i] = uint64(rng.Int63n(int64(mersennePrime)))
	}
	return idx
}

func (x *Index) Len() int { return len(x.entries) }

// stale bucket refs are harmless: Query rescores against the current set
func (x *Index) Add(id string, features Features) {
	set := features.set()
	sig := x.signature(set)
	x.entries[id] = indexEntry{sig: sig, set: set}
	for band := 0; band < x.bands; band++ {
		key := x.bandKey(band, sig)
		x.buckets[key] = append(x.buckets[key], id)
	}
}

func (x *Index) Query(features Features, k int) []Candidate {
	if k <= 0 {
		return nil
	}
	qset := features.set()
	if len(qset) == 0 {
		return nil
	}
	qsig := x.signature(qset)

	seen := make(map[string]struct{})
	var cands []Candidate
	for band := 0; band < x.bands; band++ {
		key := x.bandKey(band, qsig)
		for _, id := range x.buckets[key] {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			e, ok := x.entries[id]
			if !ok {
				continue // overwritten away from this stale bucket
			}
			cands = append(cands, Candidate{ID: id, Score: jaccard(qset, e.set)})
		}
	}
	return rankTopK(cands, k)
}

// an empty set stays all-MaxUint64, sharing no band with any real set
func (x *Index) signature(set map[string]struct{}) []uint64 {
	sig := make([]uint64, x.numPerm)
	for i := range sig {
		sig[i] = math.MaxUint64
	}
	for tok := range set {
		base := baseHash(tok)
		for i := 0; i < x.numPerm; i++ {
			h := (mulMod(x.a[i], base%mersennePrime) + x.b[i]) % mersennePrime
			if h < sig[i] {
				sig[i] = h
			}
		}
	}
	return sig
}

// the band index is hashed in: identical rows in different bands must not collide
func (x *Index) bandKey(band int, sig []uint64) uint64 {
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(band))
	h.Write(buf[:])
	start := band * x.rows
	for i := start; i < start+x.rows; i++ {
		binary.LittleEndian.PutUint64(buf[:], sig[i])
		h.Write(buf[:])
	}
	return h.Sum64()
}

func baseHash(tok string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(tok))
	return h.Sum64()
}

// a*b mod 2^61-1, folded via 2^64 ≡ 8 (mod p); operands must be < 2^61
func mulMod(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	rem := (lo & mersennePrime) + (lo >> 61) + hi*8
	for rem >= mersennePrime {
		rem = (rem & mersennePrime) + (rem >> 61)
	}
	return rem
}

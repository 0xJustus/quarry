// Package gitcommons materializes the public abstract tier as a git-native tree.
package gitcommons

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

type Bloom struct {
	n    uint32
	m    uint32
	k    uint32
	bits []byte
}

var bloomMagic = [4]byte{'q', 'b', 'l', 'm'}

func NewBloom(n int, p float64) *Bloom {
	if n < 1 {
		n = 1
	}
	if p <= 0 || p >= 1 {
		p = 0.01
	}
	m := int(math.Ceil(-float64(n) * math.Log(p) / (math.Ln2 * math.Ln2)))
	if m < 8 {
		m = 8
	}
	k := int(math.Round(float64(m) / float64(n) * math.Ln2))
	if k < 1 {
		k = 1
	}
	return &Bloom{n: uint32(n), m: uint32(m), k: uint32(k), bits: make([]byte, (m+7)/8)}
}

// cross-language wire contract; do not change (vault: Git Commons)
func (b *Bloom) positions(key string) []uint32 {
	d := sha256.Sum256([]byte(key))
	h1 := binary.BigEndian.Uint64(d[0:8])
	h2 := binary.BigEndian.Uint64(d[8:16])
	out := make([]uint32, b.k)
	for i := uint32(0); i < b.k; i++ {
		out[i] = uint32((h1 + uint64(i)*h2) % uint64(b.m))
	}
	return out
}

func (b *Bloom) Add(key string) {
	for _, p := range b.positions(key) {
		b.bits[p>>3] |= 1 << (p & 7)
	}
}

// true means MAY be present; false is definitive
func (b *Bloom) Test(key string) bool {
	for _, p := range b.positions(key) {
		if b.bits[p>>3]&(1<<(p&7)) == 0 {
			return false
		}
	}
	return true
}

// magic + n + m + k (big-endian u32) + bitset
func (b *Bloom) Marshal() []byte {
	out := make([]byte, 4+12+len(b.bits))
	copy(out[0:4], bloomMagic[:])
	binary.BigEndian.PutUint32(out[4:8], b.n)
	binary.BigEndian.PutUint32(out[8:12], b.m)
	binary.BigEndian.PutUint32(out[12:16], b.k)
	copy(out[16:], b.bits)
	return out
}

func UnmarshalBloom(data []byte) (*Bloom, error) {
	if len(data) < 16 || [4]byte{data[0], data[1], data[2], data[3]} != bloomMagic {
		return nil, errors.New("gitcommons: not a quarry bloom digest")
	}
	b := &Bloom{
		n: binary.BigEndian.Uint32(data[4:8]),
		m: binary.BigEndian.Uint32(data[8:12]),
		k: binary.BigEndian.Uint32(data[12:16]),
	}
	// reject params that would divide-by-zero or over-index in positions
	if b.m < 8 || b.k < 1 || b.k > 64 {
		return nil, errors.New("gitcommons: bloom parameters out of range")
	}
	// uint64: m near max-uint32 must not wrap m+7
	if uint64(len(data)-16) != (uint64(b.m)+7)/8 {
		return nil, errors.New("gitcommons: bloom bitset length mismatch")
	}
	b.bits = append([]byte(nil), data[16:]...)
	return b, nil
}

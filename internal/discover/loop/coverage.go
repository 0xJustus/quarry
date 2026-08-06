package loop

import (
	"context"
	"fmt"
	"maps"
	"math/rand"
	"sort"
	"strings"
	"sync"

	"github.com/0xjustus/quarry/internal/discover/fuzz"
)

// a nil feed must leave a run byte-for-byte unchanged
type CoverageFeed interface {
	SampleCold(ctx context.Context, n int) ([]string, bool)
}

// standalone CoverageFeed stub; higher weight = colder
type ColdSet struct {
	mu      sync.Mutex
	weights map[string]float64
}

func NewColdSet(cold ...string) *ColdSet {
	w := make(map[string]float64, len(cold))
	for _, c := range cold {
		w[c] = 1
	}
	return &ColdSet{weights: w}
}

func (s *ColdSet) Add(label string, delta float64) {
	if label == "" || delta <= 0 {
		return
	}
	s.mu.Lock()
	if s.weights == nil {
		s.weights = map[string]float64{}
	}
	s.weights[label] += delta
	s.mu.Unlock()
}

func (s *ColdSet) Observe(label string, hits float64) {
	if label == "" || hits <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.weights == nil {
		return
	}
	if _, ok := s.weights[label]; ok {
		s.weights[label] -= hits
		if s.weights[label] <= 0 {
			delete(s.weights, label)
		}
	}
}

func (s *ColdSet) SampleCold(_ context.Context, n int) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.weights) == 0 || n <= 0 {
		return nil, false
	}
	type kv struct {
		label string
		w     float64
	}
	all := make([]kv, 0, len(s.weights))
	for k, w := range s.weights {
		all = append(all, kv{k, w})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].w != all[j].w {
			return all[i].w > all[j].w
		}
		return all[i].label < all[j].label
	})
	n = min(n, len(all))
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = all[i].label
	}
	return out, true
}

const coverageHintMax = 6

func coverageHint(ctx context.Context, feed CoverageFeed) string {
	if feed == nil {
		return ""
	}
	cold, ok := feed.SampleCold(ctx, coverageHintMax)
	if !ok || len(cold) == 0 {
		return ""
	}
	return "COVERAGE GAPS — the coverage-guided fuzzer has NOT yet reached these locations; an input that drives execution into one of them is high-value new ground:\n  - " +
		strings.Join(cold, "\n  - ")
}

type FuzzerCoverage struct {
	Engine    string
	Edges     int
	Bitmap    float64 // fraction in [0,1]
	Plateaued bool
	Funcs     map[string]fuzz.FuncCoverage
}

func (c FuzzerCoverage) hasSignal() bool {
	return c.Edges > 0 || c.Bitmap > 0 || len(c.Funcs) > 0
}

// inverse-coverage softmax temperature: stochastic enough to not fixate on the coldest
const coverageTemp = 0.3

// fixed seed: a campaign's cold picks must be reproducible for a coverage sequence
const ensembleCoverageSeed = 0x9E3779B9

type liveCoverageFeed struct {
	source func() (FuzzerCoverage, bool) // re-read live state each call
	temp   float64
	mu     sync.Mutex
	rng    *rand.Rand
}

func newLiveCoverageFeed(source func() (FuzzerCoverage, bool), temp float64, seed int64) *liveCoverageFeed {
	if temp <= 0 {
		temp = coverageTemp
	}
	return &liveCoverageFeed{source: source, temp: temp, rng: rand.New(rand.NewSource(seed))}
}

func (f *liveCoverageFeed) SampleCold(_ context.Context, n int) ([]string, bool) {
	if f == nil || f.source == nil || n <= 0 {
		return nil, false
	}
	st, ok := f.source()
	if !ok || !st.hasSignal() {
		return nil, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var labels []string
	if agg := renderAggregate(st); agg != "" {
		labels = append(labels, agg)
	}
	if budget := n - len(labels); budget > 0 && len(st.Funcs) > 0 {
		seen := map[string]bool{}
		for tries := 0; len(seen) < budget && tries < budget*8; tries++ {
			fn, ok := fuzz.SampleCold(st.Funcs, f.temp, f.rng)
			if !ok {
				break
			}
			if seen[fn] {
				continue
			}
			seen[fn] = true
			labels = append(labels, renderFuncCold(fn, st.Funcs[fn]))
		}
	}
	if len(labels) == 0 {
		return nil, false
	}
	return labels[:min(len(labels), n)], true
}

func renderAggregate(st FuzzerCoverage) string {
	if st.Edges <= 0 && st.Bitmap <= 0 {
		return ""
	}
	eng := st.Engine
	if eng == "" {
		eng = "the coverage-guided fuzzer"
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "%s has reached %d edges", eng, st.Edges)
	if st.Bitmap > 0 {
		fmt.Fprintf(b, " (bitmap %.2f%% covered)", st.Bitmap*100)
	}
	if st.Plateaued {
		b.WriteString(" and has PLATEAUED — no new coverage recently; reason about an input class it cannot reach by blind mutation (a format/checksum/length wall) and steer there")
	}
	return b.String()
}

func renderFuncCold(fn string, fc fuzz.FuncCoverage) string {
	if fc.Total > 0 && fc.Covered > 0 {
		return fmt.Sprintf("function %s — only %d/%d edges exercised; drive execution deeper into it", fn, fc.Covered, fc.Total)
	}
	return fmt.Sprintf("function %s — not yet reached by the fuzzer", fn)
}

// re-reads fuzzer_stats + plot_data on every call; the AFL dir is live
func aflCoverageSource(outDir string) func() (FuzzerCoverage, bool) {
	return func() (FuzzerCoverage, bool) {
		stats, samples, ok := fuzz.ReadAFLCoverage(outDir)
		if !ok {
			return FuzzerCoverage{}, false
		}
		edges := stats.Edges()
		if e, has := fuzz.LatestEdges(samples); has && e > edges {
			edges = e
		}
		return FuzzerCoverage{
			Engine:    "the AFL fuzzer",
			Edges:     edges,
			Bitmap:    stats.BitmapCoverage,
			Plateaued: fuzz.Plateaued(samples, coveragePlateauWindow),
		}, true
	}
}

const coveragePlateauWindow = 5

// fed line-by-line from the campaign log, read concurrently as a coverage source
type libFuzzerCovAccum struct {
	mu     sync.Mutex
	cur    fuzz.LibFuzzerCov
	recent []int // trailing cov values, for plateau detection
	funcs  map[string]fuzz.FuncCoverage
	got    bool
}

func (a *libFuzzerCovAccum) observe(line string) {
	if c, ok := fuzz.ParseLibFuzzerCovLine(line); ok {
		a.mu.Lock()
		a.cur = c
		a.got = true
		a.recent = append(a.recent, c.Cov)
		if len(a.recent) > coveragePlateauWindow {
			a.recent = a.recent[len(a.recent)-coveragePlateauWindow:]
		}
		a.mu.Unlock()
		return
	}
	if name, fc, ok := fuzz.ParseLibFuzzerFuncLine(line); ok {
		a.mu.Lock()
		if a.funcs == nil {
			a.funcs = map[string]fuzz.FuncCoverage{}
		}
		a.funcs[name] = fc
		a.got = true
		a.mu.Unlock()
	}
}

func (a *libFuzzerCovAccum) state() (FuzzerCoverage, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.got {
		return FuzzerCoverage{}, false
	}
	plateaued := len(a.recent) >= coveragePlateauWindow
	if plateaued {
		last := a.recent[len(a.recent)-1]
		for _, v := range a.recent {
			if v != last {
				plateaued = false
				break
			}
		}
	}
	var funcs map[string]fuzz.FuncCoverage
	if len(a.funcs) > 0 {
		funcs = maps.Clone(a.funcs)
	}
	return FuzzerCoverage{
		Engine:    "the libFuzzer harness",
		Edges:     a.cur.Cov,
		Plateaued: plateaued,
		Funcs:     funcs,
	}, true
}

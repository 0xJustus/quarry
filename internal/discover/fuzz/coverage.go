package fuzz

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// absent or unparsable fields keep their zero value
type FuzzerStats struct {
	BitmapCoverage float64 // fraction in [0,1]; AFL prints "1.52%"
	EdgesFound     int     // AFL++ only
	PathsTotal     int     // queue size — the edges proxy on classic AFL
	ExecsPerSec    float64
	UniqueCrashes  int
}

func (s FuzzerStats) Edges() int {
	if s.EdgesFound > 0 {
		return s.EdgesFound
	}
	return s.PathsTotal
}

func ParseFuzzerStats(m map[string]string) FuzzerStats {
	return FuzzerStats{
		BitmapCoverage: parsePercent(m["bitmap_cvg"]),
		EdgesFound:     atoiSafe(m["edges_found"]),
		PathsTotal:     atoiSafe(m["paths_total"]),
		ExecsPerSec:    atofSafe(m["execs_per_sec"]),
		UniqueCrashes:  atoiSafe(m["unique_crashes"]),
	}
}

// PlotSample is one row of AFL's plot_data time series.
type PlotSample struct {
	RelTime     int64   // unix_time (classic) / relative_time (AFL++)
	PathsTotal  int     // paths_total (classic) / corpus_count (AFL++)
	MapSize     float64 // fraction in [0,1]
	EdgesFound  int     // AFL++ only
	ExecsPerSec float64
}

func (p PlotSample) edges() int {
	if p.EdgesFound > 0 {
		return p.EdgesFound
	}
	return p.PathsTotal
}

// classic AFL 2.52b plot_data column order (some builds emit no header row)
var classicPlotCols = []string{
	"unix_time", "cycles_done", "cur_path", "paths_total", "pending_total",
	"pending_favs", "map_size", "unique_crashes", "unique_hangs", "max_depth", "execs_per_sec",
}

// a "# a, b, c" header names the columns (AFL++ reorders them), else classic layout; bad rows skipped
func ParsePlotData(r io.Reader) ([]PlotSample, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	cols := classicPlotCols
	var out []PlotSample
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			cols = splitTrim(strings.TrimLeft(line, "# "))
			continue
		}
		fields := splitTrim(line)
		if len(fields) == 0 {
			continue
		}
		col := func(name string) string {
			for i, c := range cols {
				if c == name && i < len(fields) {
					return fields[i]
				}
			}
			return ""
		}
		s := PlotSample{
			RelTime:     int64(atoiSafe(firstNonEmpty(col("relative_time"), col("unix_time")))),
			PathsTotal:  atoiSafe(firstNonEmpty(col("corpus_count"), col("paths_total"))),
			MapSize:     parsePercent(col("map_size")),
			EdgesFound:  atoiSafe(col("edges_found")),
			ExecsPerSec: atofSafe(col("execs_per_sec")),
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func LatestEdges(samples []PlotSample) (int, bool) {
	if len(samples) == 0 {
		return 0, false
	}
	return samples[len(samples)-1].edges(), true
}

// no edge growth across the last window samples; too little history is never a plateau
func Plateaued(samples []PlotSample, window int) bool {
	if window < 2 || len(samples) < window {
		return false
	}
	tail := samples[len(samples)-window:]
	last := tail[len(tail)-1].edges()
	for _, s := range tail {
		if s.edges() != last {
			return false
		}
	}
	return true
}

// LibFuzzerCov is one status line's coverage counters: covered PCs and features (ft ≥ cov).
type LibFuzzerCov struct {
	Cov int
	Ft  int
}

// "#12345 REDUCE cov: 210 ft: 350 corp: 42/1024b ..."
var libfuzzCovLine = regexp.MustCompile(`\bcov:\s*(\d+)\b.*?\bft:\s*(\d+)\b`)

func ParseLibFuzzerCovLine(line string) (LibFuzzerCov, bool) {
	m := libfuzzCovLine.FindStringSubmatch(line)
	if m == nil {
		return LibFuzzerCov{}, false
	}
	return LibFuzzerCov{Cov: atoiSafe(m[1]), Ft: atoiSafe(m[2])}, true
}

// -print_coverage=1 emits one COVERED_FUNC/UNCOVERED_FUNC line per function at end of run
var (
	libfuzzCoveredFunc   = regexp.MustCompile(`^COVERED_FUNC:\s+hits:\s*\d+\s+edges:\s*(\d+)/(\d+)\s+(\S+)`)
	libfuzzUncoveredFunc = regexp.MustCompile(`^UNCOVERED_FUNC:\s+(\S+)`)
)

// an UNCOVERED_FUNC line yields {0,1}: maximally cold, so the softmax ranks it first
func ParseLibFuzzerFuncLine(line string) (string, FuncCoverage, bool) {
	line = strings.TrimSpace(line)
	if m := libfuzzCoveredFunc.FindStringSubmatch(line); m != nil {
		return m[3], FuncCoverage{Covered: atoiSafe(m[1]), Total: atoiSafe(m[2])}, true
	}
	if m := libfuzzUncoveredFunc.FindStringSubmatch(line); m != nil {
		return m[1], FuncCoverage{Covered: 0, Total: 1}, true
	}
	return "", FuncCoverage{}, false
}

// ok=false ⇒ neither artifact exists yet: the graceful-degrade signal (either alone suffices)
func ReadAFLCoverage(outDir string) (FuzzerStats, []PlotSample, bool) {
	stats := ParseFuzzerStats(parseStats(outDir))
	var samples []PlotSample
	for _, p := range aflArtifactPaths(outDir, "plot_data") {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		samples, _ = ParsePlotData(f)
		f.Close()
		if len(samples) > 0 {
			break
		}
	}
	ok := stats != (FuzzerStats{}) || len(samples) > 0
	return stats, samples, ok
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atofSafe(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// "12.34%" or a bare 0.1234 ⇒ a fraction; a bare value > 1 is taken as a percent
func parsePercent(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	pct := strings.HasSuffix(s, "%")
	v := atofSafe(strings.TrimSuffix(s, "%"))
	if pct || v > 1 {
		return v / 100
	}
	return v
}

func splitTrim(line string) []string {
	parts := strings.Split(line, ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

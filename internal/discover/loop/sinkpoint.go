package loop

import (
	"cmp"
	"path/filepath"
	"slices"
	"strings"
)

// a ranking heuristic, not a proof: a false positive never reaches a verdict
type Sink struct {
	File     string // workspace-relative label (matches the inventory label)
	Function string // enclosing function name, when resolvable
	Line     int
	Kind     string
	Severity int // 3 = high, 2 = medium
	Snippet  string
}

const (
	sinkScanFileCap  = 40
	sinkScanTotalCap = 2000
	sinkMapMax       = 50
	sinkSnippetMax   = 140
)

type sinkInfo struct {
	kind string
	sev  int
}

// exact-name match only, so a wrapper like ft_mem_alloc never counts as malloc
var sinkTable = map[string]sinkInfo{
	"strcpy": {"strcpy", 3}, "strcat": {"strcat", 3}, "stpcpy": {"stpcpy", 3},
	"wcscpy": {"wcscpy", 3}, "wcscat": {"wcscat", 3},
	"vsprintf": {"vsprintf", 3}, "sprintf": {"sprintf", 3}, "gets": {"gets", 3},
	"alloca": {"alloca", 3},

	"system": {"command-exec", 3}, "popen": {"command-exec", 3},
	"execve": {"command-exec", 3}, "execvp": {"command-exec", 3},
	"execlp": {"command-exec", 3}, "execl": {"command-exec", 3}, "execv": {"command-exec", 3},

	"memcpy": {"memcpy", 2}, "memmove": {"memmove", 2}, "memset": {"memset", 2},
	"bcopy": {"bcopy", 2}, "strncpy": {"strncpy", 2}, "strncat": {"strncat", 2},
	"vsnprintf": {"vsnprintf", 2}, "snprintf": {"snprintf", 2},

	"malloc": {"malloc", 2}, "realloc": {"realloc", 2}, "calloc": {"calloc", 2},
}

func isAllocToken(name string) bool {
	switch name {
	case "malloc", "realloc", "calloc", "alloca":
		return true
	}
	return false
}

func isSourceExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx",
		".inc", ".ipp", ".m", ".mm":
		return true
	}
	return false
}

// per-file parsing lives in the build-tagged scanFileSinks (no-op without cgo)
func scanSinks(paths []string) []Sink {
	var sinks []Sink
	walkSourceCandidates(paths, func(path, label string) bool {
		if len(sinks) >= sinkScanTotalCap {
			return false
		}
		if !isSourceExt(filepath.Ext(label)) {
			return true
		}
		scanFileSinks(path, label, &sinks)
		return true
	})
	return sinks
}

func snippet(s string) string {
	if len(s) > sinkSnippetMax {
		s = s[:sinkSnippetMax]
		for len(s) > 0 && s[len(s)-1] < 0x20 {
			s = s[:len(s)-1]
		}
		s += " …"
	}
	return s
}

func StaticSinkpoints(paths []string) []Sink { return scanSinks(paths) }

func FormatSinkpoints(sinks []Sink, max int) string { return renderSinkMap(sinks, max) }

// must stay the SAME inventory the Analyst sees (internal/synth relies on it)
func SourceInventory(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	return buildSourceInventory(paths, sinkScores(scanSinks(paths)))
}

func sinkScores(sinks []Sink) map[string]int {
	if len(sinks) == 0 {
		return nil
	}
	m := make(map[string]int, len(sinks))
	for _, s := range sinks {
		m[s.File] += s.Severity
	}
	return m
}

// severity, then file, then line — the ordering must stay deterministic
func renderSinkMap(sinks []Sink, max int) string {
	if len(sinks) == 0 {
		return ""
	}
	sorted := slices.Clone(sinks)
	slices.SortStableFunc(sorted, func(a, b Sink) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), cmp.Compare(a.File, b.File), cmp.Compare(a.Line, b.Line))
	})
	sorted = sorted[:min(len(sorted), max)]
	var b strings.Builder
	b.WriteString("STATIC SINKPOINTS (dangerous call-sites found by parsing the seeded source; ")
	b.WriteString("prefer work items whose reachability path ends at one of these sites — [H]igh, [M]edium):\n")
	for _, s := range sorted {
		sev := "M"
		if s.Severity >= 3 {
			sev = "H"
		}
		b.WriteString("  [")
		b.WriteString(sev)
		b.WriteString("] ")
		b.WriteString(s.File)
		b.WriteByte(':')
		b.WriteString(itoa(s.Line))
		b.WriteString("  ")
		b.WriteString(s.Kind)
		if s.Function != "" {
			b.WriteString("  ")
			b.WriteString(s.Function)
			b.WriteString("()")
		}
		if s.Snippet != "" {
			b.WriteString("  — ")
			b.WriteString(s.Snippet)
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

package loop

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	sliceScopeBudget   = 24 << 10
	sliceCenterBytes   = 16 << 10
	sliceNeighborBytes = 4 << 10
	sliceMaxNeighbors  = 4
)

// label must be the same base/rel the inventory and sink map use, or nothing resolves
func buildSeedIndex(paths []string) map[string]string {
	idx := map[string]string{}
	walkSourceCandidates(paths, func(path, label string) bool {
		idx[label] = path
		return true
	})
	return idx
}

// relies on seed paths being POSIX and colon-free
func fileTokenOf(section string) string {
	s := strings.TrimSpace(section)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ambiguous or missing must yield "": no scope is correct, a wrong scope is not
func scopeCenterFor(index map[string]string, targetSection string) string {
	file := fileTokenOf(targetSection)
	if file == "" || index == nil {
		return ""
	}
	if _, ok := index[file]; ok {
		return file
	}
	base := filepath.Base(file)
	suffixHit, suffixN := "", 0
	baseHit, baseN := "", 0
	for label := range index {
		if strings.HasSuffix(label, "/"+file) {
			suffixHit, suffixN = label, suffixN+1
		}
		if filepath.Base(label) == base {
			baseHit, baseN = label, baseN+1
		}
	}
	if suffixN == 1 {
		return suffixHit
	}
	if suffixN == 0 && baseN == 1 {
		return baseHit
	}
	return ""
}

var quotedIncludeRe = regexp.MustCompile(`(?m)^[ \t]*#[ \t]*include[ \t]*"([^"]+)"`)

func localIncludes(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 32<<10))
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range quotedIncludeRe.FindAllSubmatch(data, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func resolveByBasename(index map[string]string, name string) string {
	base := filepath.Base(name)
	hit, n := "", 0
	for label := range index {
		if filepath.Base(label) == base {
			hit, n = label, n+1
		}
	}
	if n == 1 {
		return hit
	}
	return ""
}

// directs, never gates: the full tree is still seeded, so "" is a valid answer
func sliceScope(index map[string]string, centers []string, budget int) string {
	if index == nil || len(centers) == 0 {
		return ""
	}
	var b strings.Builder
	seen := map[string]bool{}
	total := 0
	emit := func(label string, per int) bool {
		if label == "" || seen[label] {
			return false
		}
		path, ok := index[label]
		if !ok {
			return false
		}
		ex, n := fileExcerpt(path, label, per)
		if ex == "" || total+n > budget {
			return false
		}
		b.WriteString(ex)
		total += n
		seen[label] = true
		return true
	}
	for _, c := range centers {
		emit(c, sliceCenterBytes)
	}
	neighbors := 0
	for _, c := range centers {
		path, ok := index[c]
		if !ok {
			continue
		}
		for _, inc := range localIncludes(path) {
			if neighbors >= sliceMaxNeighbors || total >= budget {
				break
			}
			if emit(resolveByBasename(index, inc), sliceNeighborBytes) {
				neighbors++
			}
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

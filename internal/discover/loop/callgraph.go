package loop

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/0xjustus/quarry/internal/discover/agent"
)

const (
	callGraphBodyMax      = 6 << 10
	callGraphMaxDefs      = 3
	callGraphTotalFuncCap = 40000
)

type FuncDef struct {
	Name string
	File string // workspace-relative label (matches the inventory/sink label)
	Line int    // 1-based start line
	Body string
}

// a navigation aid, not a proof: a wrong edge only changes what is read next
type CallGraph struct {
	defs    map[string][]FuncDef       // name -> definition(s)
	callers map[string]map[string]bool // callee -> caller names
	callees map[string]map[string]bool // caller -> callee names
	nfuncs  int
}

func newCallGraph() *CallGraph {
	return &CallGraph{
		defs:    map[string][]FuncDef{},
		callers: map[string]map[string]bool{},
		callees: map[string]map[string]bool{},
	}
}

func (g *CallGraph) addEdge(caller, callee string) {
	if caller == "" || callee == "" || caller == callee {
		return
	}
	if g.callees[caller] == nil {
		g.callees[caller] = map[string]bool{}
	}
	g.callees[caller][callee] = true
	if g.callers[callee] == nil {
		g.callers[callee] = map[string]bool{}
	}
	g.callers[callee][caller] = true
}

func (g *CallGraph) addDef(d FuncDef) {
	if d.Name == "" || g.nfuncs >= callGraphTotalFuncCap {
		return
	}
	if len(d.Body) > callGraphBodyMax {
		d.Body = d.Body[:callGraphBodyMax] + "\n… [truncated]"
	}
	g.defs[d.Name] = append(g.defs[d.Name], d)
	g.nfuncs++
}

func (g *CallGraph) empty() bool {
	return g == nil || (len(g.defs) == 0 && len(g.callers) == 0 && len(g.callees) == 0)
}

func (g *CallGraph) Callers(name string) []string { return sortedKeys(g.callers[name]) }

func (g *CallGraph) Callees(name string) []string { return sortedKeys(g.callees[name]) }

func (g *CallGraph) Function(name string) string {
	defs := g.defs[name]
	if len(defs) == 0 {
		return ""
	}
	if len(defs) > callGraphMaxDefs {
		defs = defs[:callGraphMaxDefs]
	}
	var b strings.Builder
	for _, d := range defs {
		b.WriteString("--- ")
		b.WriteString(d.File)
		b.WriteByte(':')
		b.WriteString(itoa(d.Line))
		b.WriteString("  ")
		b.WriteString(d.Name)
		b.WriteString("() ---\n")
		b.WriteString(d.Body)
		if !strings.HasSuffix(d.Body, "\n") {
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(m))
}

// per-file parsing lives in the build-tagged scanFileCallGraph (no-op without cgo)
func BuildCallGraph(paths []string) *CallGraph {
	g := newCallGraph()
	walkSourceCandidates(paths, func(path, label string) bool {
		if g.nfuncs >= callGraphTotalFuncCap {
			return false
		}
		if isSourceExt(filepath.Ext(label)) {
			scanFileCallGraph(path, label, g)
		}
		return true
	})
	return g
}

func (g *CallGraph) FuncNames() []string {
	if g == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(g.defs))
}

func (g *CallGraph) Summary() (funcs, callers, callees int) {
	if g == nil {
		return 0, 0, 0
	}
	return len(g.defs), len(g.callers), len(g.callees)
}

func looksLikeEntry(name string) bool {
	l := strings.ToLower(name)
	for _, kw := range []string{"llvmfuzzer", "main", "harness", "_fuzz", "fuzz_", "parse", "load", "open", "read", "decode", "new_memory", "new_face", "init"} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

// walks UP caller edges to a root or entry-looking name; nil if not in the graph
func (g *CallGraph) PathFromEntry(target string, maxDepth int) []string {
	if g == nil {
		return nil
	}
	if _, defined := g.defs[target]; !defined {
		if _, called := g.callers[target]; !called {
			return nil
		}
	}
	if maxDepth <= 0 {
		maxDepth = 8
	}
	parent := map[string]string{}
	depth := map[string]int{target: 0}
	seen := map[string]bool{target: true}
	queue := []string{target}
	best := target // farthest-up node reached (fallback if no clean root)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		callers := g.Callers(cur) // sorted → deterministic
		if len(callers) == 0 || (cur != target && looksLikeEntry(cur)) {
			best = cur
			break
		}
		if depth[cur] >= maxDepth {
			best = cur
			continue
		}
		for _, c := range callers {
			if !seen[c] {
				seen[c] = true
				parent[c] = cur
				depth[c] = depth[cur] + 1
				queue = append(queue, c)
			}
		}
	}
	// parent points toward target, so walking it already reads entry→…→target
	var chain []string
	for cur := best; ; {
		chain = append(chain, cur)
		next, ok := parent[cur]
		if !ok {
			break
		}
		cur = next
	}
	return chain
}

// satisfies agent.CodeNavigator
type callGraphNav struct{ g *CallGraph }

func (n callGraphNav) Callers(name string) []string { return n.g.Callers(name) }
func (n callGraphNav) Callees(name string) []string { return n.g.Callees(name) }
func (n callGraphNav) Function(name string) string  { return n.g.Function(name) }

// nil result means the nav tools are omitted for the run
func buildCallGraphNav(paths []string) agent.CodeNavigator {
	if len(paths) == 0 {
		return nil
	}
	g := BuildCallGraph(paths)
	if g.empty() {
		return nil
	}
	return callGraphNav{g}
}

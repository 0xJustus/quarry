// Package binnav navigates a binary's call graph to find where to fuzz.
package binnav

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// copy/write sinks are the overflow sites, so they outweigh alloc/free
var sinkWeight = map[string]int{
	"memcpy": 3, "memmove": 3, "memset": 2, "strcpy": 3, "strncpy": 2,
	"strcat": 3, "sprintf": 3, "vsprintf": 3, "read": 2,
	"malloc": 1, "calloc": 1, "realloc": 1, "alloca": 1, "free": 1,
}

func isSink(imp string) bool { _, ok := sinkWeight[imp]; return ok }

var inputImports = map[string]bool{
	"fread": true, "read": true, "recv": true, "recvfrom": true, "fgets": true,
	"fgetc": true, "getline": true, "fopen": true, "open": true, "gets": true,
}

type Func struct {
	Addr uint64
	Name string
	Size int
}

type Nav struct {
	Funcs   map[uint64]Func // by start address
	Callees map[uint64][]uint64
	Sinks   map[uint64][]string
	Inputs  map[uint64][]string
	// these back Warnings(): 0 sink edges means "could not tell", not "clean"
	Edges     int
	SinkEdges int
	callers   map[uint64]bool // callee addrs, for root detection
}

type Target struct {
	Func            Func
	SinksCalled     []string
	HandlesInput    bool
	ReachableFromIn bool // incl. via a shared entry caller
	Score           int
}

// agCd dot edge: "0xSRC" -> "0xDST" [... URL="NAME/0x..."];
var reEdge = regexp.MustCompile(`"0x([0-9a-fA-F]+)"\s*->\s*"0x([0-9a-fA-F]+)"\s*\[.*URL="([^"/]+)`)

type r2func struct {
	Addr uint64 `json:"addr"`
	Name string `json:"name"`
	Size int    `json:"size"`
}

// Parse builds a Nav from r2's `aflj` (functions JSON) and `agCd` (call-graph dot).
func Parse(funcsJSON, edgesDot string) (*Nav, error) {
	var fns []r2func
	if err := json.Unmarshal([]byte(strings.TrimSpace(funcsJSON)), &fns); err != nil {
		return nil, fmt.Errorf("binnav: parse aflj: %w", err)
	}
	n := &Nav{Funcs: map[uint64]Func{}, Callees: map[uint64][]uint64{},
		Sinks: map[uint64][]string{}, Inputs: map[uint64][]string{}, callers: map[uint64]bool{}}
	for _, f := range fns {
		if strings.HasPrefix(f.Name, "sym.imp.") || strings.HasPrefix(f.Name, "reloc.") {
			continue // imports/relocs are not target functions
		}
		n.Funcs[f.Addr] = Func(f)
	}
	for _, line := range strings.Split(edgesDot, "\n") {
		m := reEdge.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		src, _ := strconv.ParseUint(m[1], 16, 64)
		dst, _ := strconv.ParseUint(m[2], 16, 64)
		name := m[3]
		n.Edges++
		// classify by the BARE libc name: a static link has no "sym.imp." prefix
		if imp := libcName(name); isSink(imp) || inputImports[imp] {
			if isSink(imp) {
				n.Sinks[src] = appendUniq(n.Sinks[src], imp)
				n.SinkEdges++
			}
			if inputImports[imp] {
				n.Inputs[src] = appendUniq(n.Inputs[src], imp)
			}
		}
		if isImportName(name) {
			continue // a PLT thunk / reloc stub, not one of the target's functions
		}
		n.Callees[src] = append(n.Callees[src], dst)
		n.callers[dst] = true
	}
	return n, nil
}

// r2's names for a call into a PLT thunk / reloc stub; static callees carry none.
var importPrefixes = []string{"sym.imp.", "imp.", "reloc.", "loc.imp."}

func isImportName(name string) bool {
	for _, p := range importPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// The result is matched EXACTLY, so `sym.parse_read` never becomes read(3).
func libcName(name string) string {
	s := name
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i] // memcpy@plt / memcpy@@GLIBC_2.14
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:] // any sym./sym.imp./reloc./dbg. prefix chain
	}
	s = strings.TrimPrefix(strings.TrimLeft(s, "_"), "isoc99_")
	return strings.TrimSuffix(s, "_chk") // fortified __memcpy_chk
}

// Directors ranks the functions worth fuzzing: those that call a memory sink.
func (n *Nav) Directors() []Target {
	inputFns := map[uint64]bool{}
	for a := range n.Inputs {
		inputFns[a] = true
	}
	reachFromInput := n.forwardClosure(inputFns)
	// seed with only entry roots that reach input: keeps read-then-process siblings correlated (one root reaches both)
	reachesInput := n.backwardClosure(inputFns)
	inputRoots := map[uint64]bool{}
	for a := range n.Funcs {
		if !n.callers[a] && reachesInput[a] {
			inputRoots[a] = true
		}
	}
	sharedEntryIn := n.forwardClosure(inputRoots)
	var out []Target
	for addr, sinks := range n.Sinks {
		f, ok := n.Funcs[addr]
		if !ok {
			continue // sink call from a thunk/plt we don't track as a function
		}
		if own := libcName(f.Name); isSink(own) || inputImports[own] {
			continue // libc's own statically linked implementation, not a target fn
		}
		t := Target{Func: f, SinksCalled: sinks, HandlesInput: len(n.Inputs[addr]) > 0}
		t.ReachableFromIn = reachFromInput[addr] || sharedEntryIn[addr]
		for _, s := range sinks {
			t.Score += sinkWeight[s]
		}
		if t.HandlesInput {
			t.Score += 2
		}
		if t.ReachableFromIn {
			t.Score += 3
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Func.Addr < out[j].Func.Addr
	})
	return out
}

func (n *Nav) forwardClosure(seed map[uint64]bool) map[uint64]bool {
	return closure(seed, n.Callees)
}

func (n *Nav) backwardClosure(seed map[uint64]bool) map[uint64]bool {
	rev := map[uint64][]uint64{}
	for src, cs := range n.Callees {
		for _, c := range cs {
			rev[c] = append(rev[c], src)
		}
	}
	return closure(seed, rev)
}

func closure(seed map[uint64]bool, adj map[uint64][]uint64) map[uint64]bool {
	seen := make(map[uint64]bool, len(seed))
	stack := make([]uint64, 0, len(seed))
	for a := range seed {
		seen[a] = true
		stack = append(stack, a)
	}
	for len(stack) > 0 {
		a := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range adj[a] {
			if !seen[c] {
				seen[c] = true
				stack = append(stack, c)
			}
		}
	}
	return seen
}

// An empty Directors() is INCONCLUSIVE, not negative, unless these are empty too.
func (n *Nav) Warnings() []string {
	var w []string
	if len(n.Funcs) == 0 {
		w = append(w, "INCONCLUSIVE: r2 recovered no functions from this binary — nothing was analyzed")
	}
	if n.SinkEdges == 0 {
		w = append(w, fmt.Sprintf("INCONCLUSIVE: 0 of %d call edges resolved to a known memory sink (%d functions): this binary's callees carry no recognizable libc names (fully stripped static link, or indirect dispatch r2 could not resolve), so an empty director list is NOT evidence that nothing reaches a sink",
			n.Edges, len(n.Funcs)))
	}
	if len(n.Inputs) == 0 && n.SinkEdges > 0 {
		w = append(w, "PARTIAL: no input-handling call (fread/read/recv/fopen/...) was resolved, so reachable-from-input could not be evaluated; the ranking is by sink weight alone")
	}
	return w
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// Run analyzes bin with radare2 in a container: static analysis, no target execution.
func Run(ctx context.Context, bin, dockerBin, image string) (*Nav, error) {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if image == "" {
		image = "radare/radare2:latest"
	}
	args := []string{"run", "--rm", "-v", bin + ":/t:ro", image,
		"r2", "-q", "-A", "-e", "scr.color=0", "-c", "aflj", "-c", "?e ===EDGES===", "-c", "agCd", "/t"}
	out, err := exec.CommandContext(ctx, dockerBin, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("binnav: r2 run: %w", err)
	}
	parts := strings.SplitN(string(out), "===EDGES===", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("binnav: unexpected r2 output (no delimiter)")
	}
	return Parse(parts[0], parts[1])
}

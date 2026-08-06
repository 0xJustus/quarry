package loop

import (
	"context"
	"encoding/binary"
	"os"
	"strings"

	"github.com/0xjustus/quarry/internal/discover/agent"
	"github.com/0xjustus/quarry/internal/discover/strategy"
)

// gates the leg OFF rather than fabricating a run; the reason is logged
func concolicAmenable(elfPath string) (bool, string) {
	f, err := os.Open(elfPath)
	if err != nil {
		return false, "no target ELF"
	}
	defer f.Close()
	var h [20]byte
	if _, err := f.ReadAt(h[:], 0); err != nil {
		return false, "unreadable ELF header"
	}
	if h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F' {
		return false, "not an ELF"
	}
	if h[4] != 2 { // EI_CLASS: 2 = ELFCLASS64
		return false, "not 64-bit"
	}
	etype := binary.LittleEndian.Uint16(h[16:18])
	emachine := binary.LittleEndian.Uint16(h[18:20])
	if emachine != 0x3e { // EM_X86_64
		return false, "not x86-64"
	}
	if etype != 2 && etype != 3 { // ET_EXEC (static) or ET_DYN (dynamic/PIE)
		return false, "not an executable/PIE ELF"
	}
	return true, ""
}

// detects by symbol-name substring in the binary, not by reading the symbol table
func concolicInputMode(elfPath string) string {
	b, err := os.ReadFile(elfPath)
	if err != nil {
		return "read"
	}
	if strings.Contains(string(b), "LLVMFuzzerTestOneInput") {
		return "libfuzzer"
	}
	return "read"
}

// parses the CPG sink-site wire form `callee in FUNC:line`
func concolicTargetsFromCPG(ctx context.Context, cpg agent.CPGQuerier, cap int) []string {
	if cpg == nil {
		return nil
	}
	sites, err := cpg.SinkSites(ctx)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range sites {
		i := strings.Index(s, " in ")
		if i < 0 {
			continue
		}
		fn := s[i+4:]
		if c := strings.LastIndex(fn, ":"); c >= 0 {
			fn = fn[:c]
		}
		fn = strings.TrimSpace(fn)
		if fn != "" && !seen[fn] {
			seen[fn] = true
			out = append(out, fn)
			if len(out) >= cap {
				break
			}
		}
	}
	return out
}

// a non-amenable target yields 0 and a skip log — never a fabricated input
func (l *Loop) runConcolicLeg(ctx context.Context, elfPath string, targetSyms []string, mkSolver func(sym string) strategy.ConstraintSolver, corpus *CorpusExchange) int {
	if ok, why := concolicAmenable(elfPath); !ok {
		l.log("ensemble: concolic leg skipped — %s", why)
		return 0
	}
	if len(targetSyms) == 0 {
		l.log("ensemble: concolic leg skipped — no CPG-named sink to aim at")
		return 0
	}
	solved := 0
	for _, sym := range targetSyms {
		stub := &strategy.ConcolicStub{
			Engine: mkSolver(sym),
			Seeds:  func() []byte { return []byte{0} }, // non-empty to pass the stub gate
			Sink: func(b []byte) {
				if _, added := corpus.Add(b); added {
					solved++
				}
			},
		}
		p, err := stub.Step(ctx, strategy.StepBudget{})
		if err != nil {
			l.log("ensemble: concolic leg aim=%s error: %v", sym, err)
			continue
		}
		if p.Solved > 0 {
			l.log("ensemble: concolic leg SOLVED a constraint reaching %s — contributed %d input(s) to the corpus", sym, p.NewInputs)
		}
	}
	return solved
}

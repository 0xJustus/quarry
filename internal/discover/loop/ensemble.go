package loop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xjustus/quarry/internal/discover/fuzz"
	"github.com/0xjustus/quarry/internal/discover/strategy"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

const corpusMaxBytes = 1 << 20

// CorpusExchange is a content-addressed dir of candidate inputs shared between ensemble legs; Add is idempotent and atomic (vault: Loop Analyst).
type CorpusExchange struct {
	dir  string
	mu   sync.Mutex
	seen map[string]bool
}

func NewCorpusExchange(dir string) (*CorpusExchange, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &CorpusExchange{dir: dir, seen: map[string]bool{}}, nil
}

func (x *CorpusExchange) Dir() string { return x.dir }

// Add writes bytes content-addressed and returns (path, isNew); empty/oversized/present are no-ops.
func (x *CorpusExchange) Add(b []byte) (string, bool) {
	if len(b) == 0 || len(b) > corpusMaxBytes {
		return "", false
	}
	sum := sha256.Sum256(b)
	name := hex.EncodeToString(sum[:])[:24]
	path := filepath.Join(x.dir, name)

	x.mu.Lock()
	if x.seen[name] {
		x.mu.Unlock()
		return path, false
	}
	x.seen[name] = true
	x.mu.Unlock()

	// dot-prefixed temp (PumpFrom skips "."); roll back seen on failure (vault: Loop Analyst)
	tmp := filepath.Join(x.dir, "."+name+".tmp")
	rollback := func() (string, bool) {
		x.mu.Lock()
		delete(x.seen, name)
		x.mu.Unlock()
		return "", false
	}
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return rollback()
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return rollback()
	}
	return path, true
}

// PumpFrom copies up to maxPerCall new files from srcDir into the exchange; returns the count added.
func (x *CorpusExchange) PumpFrom(srcDir string, maxPerCall int) int {
	ents, err := os.ReadDir(srcDir)
	if err != nil {
		return 0
	}
	added := 0
	for _, e := range ents {
		if added >= maxPerCall {
			break
		}
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "README") {
			continue
		}
		// reject oversized by stat before slurping a huge queue file into memory
		if info, ierr := e.Info(); ierr == nil && info.Size() > corpusMaxBytes {
			continue
		}
		b, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			continue
		}
		if _, isNew := x.Add(b); isNew {
			added++
		}
	}
	return added
}

// FuzzEngine selects the coverage-guided engine for the ensemble's fuzz leg.
type FuzzEngine string

const (
	EngineAFL       FuzzEngine = "afl" // zero value ("") resolves here — original default
	EngineLibFuzzer FuzzEngine = "libfuzzer"
	EngineAuto      FuzzEngine = "auto" // probe the image with fuzz.HasAFL at run time
)

// FuzzLeg configures the coverage-guided fuzzer leg. Field quirks/knobs: vault: Loop Analyst.
type FuzzLeg struct {
	Image       string
	SeedDir     string        // initial seed corpus (required)
	DictPath    string        // in-image static dictionary — AFL only
	CmplogBin   string        // in-image CMPLOG binary — AFL only
	HarnessArgv []string      // AFL uses it verbatim (…, "@@"); libFuzzer takes argv[0], "@@" dropped
	Budget      time.Duration // fuzzer wall-clock (0 → 60s)

	Engine FuzzEngine

	// classic-AFL knobs for ARVO's 2.52b; unset ⇒ AFL++ default (vault: Loop Analyst)
	AflBin      string
	OutMount    string
	NoWallClock bool

	AFLEngine fuzz.Engine // "" ⇒ original behavior; fuzz.EngineAFLPlusPlus ⇒ modern (-V, MOpt)
	MOpt      bool
}

// resolveFuzzEngine picks a concrete engine; pure (docker-free). Zero value/EngineAFL ⇒ AFL.
func resolveFuzzEngine(engine FuzzEngine, hasAFL bool) FuzzEngine {
	switch engine {
	case EngineLibFuzzer:
		return EngineLibFuzzer
	case EngineAuto:
		if hasAFL {
			return EngineAFL
		}
		return EngineLibFuzzer
	default:
		return EngineAFL
	}
}

// aflLeg builds the AFL Campaign; foreignDir is the scientists' PoV exchange (-F). Pure.
func aflLeg(leg FuzzLeg, outDir, foreignDir, dockerBin string) fuzz.Campaign {
	return fuzz.Campaign{
		Image: leg.Image, SeedDir: leg.SeedDir, OutDir: outDir,
		DictPath: leg.DictPath, CmplogBin: leg.CmplogBin, ForeignDirs: []string{foreignDir},
		HarnessArgv: leg.HarnessArgv, Duration: leg.Budget, StopOnCrash: false, DockerBin: dockerBin,
		AflBin: leg.AflBin, OutMount: leg.OutMount, NoWallClock: leg.NoWallClock,
		Engine: leg.AFLEngine, MOpt: leg.MOpt,
	}
}

// libFuzzerLeg builds the native-libFuzzer campaign (harness = HarnessArgv[0], corpusDir writable, importDirs read-only). Pure.
func libFuzzerLeg(leg FuzzLeg, corpusDir string, importDirs []string, dockerBin string) fuzz.LibFuzzerCampaign {
	harness := ""
	if len(leg.HarnessArgv) > 0 {
		harness = leg.HarnessArgv[0]
	}
	return fuzz.LibFuzzerCampaign{
		Image: leg.Image, Harness: harness, SeedDir: leg.SeedDir,
		CorpusDir: corpusDir, ImportDirs: importDirs,
		Duration: leg.Budget, DockerBin: dockerBin,
	}
}

// RunEnsemble runs the scientist and fuzzer legs in parallel over a shared corpus into one deduped Report (vault: Loop Analyst).
func (l *Loop) RunEnsemble(ctx context.Context, req Request, leg FuzzLeg) (Report, error) {
	root := l.WorkspaceRoot
	if root == "" {
		root = os.TempDir()
	}
	// WorkspaceRoot may not exist yet (Run creates it lazily; MkdirTemp does not)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return Report{}, err
	}
	exDir, err := os.MkdirTemp(root, "ensemble-")
	if err != nil {
		return Report{}, err
	}
	// per-run scratch; WorkspaceRoot is persistent and would leak otherwise
	defer os.RemoveAll(exDir)

	// seedsX: fuzzer → scientists (preloaded with the initial corpus); llmX: scientists → fuzzer
	seedsX, err := NewCorpusExchange(filepath.Join(exDir, "seeds"))
	if err != nil {
		return Report{}, err
	}
	llmX, err := NewCorpusExchange(filepath.Join(exDir, "llm"))
	if err != nil {
		return Report{}, err
	}
	seedsX.PumpFrom(leg.SeedDir, 1<<20)

	req.CorpusDir = seedsX.Dir()
	req.OnCandidate = func(b []byte) { llmX.Add(b) }

	// concolic leg: amenability-gated, no-ops on non-static/PIE/other-arch targets
	if req.ConcolicELF != "" {
		cq, closeCPG := l.openCPG(ctx, req)
		targets := concolicTargetsFromCPG(ctx, cq, 8)
		elf := req.ConcolicELF
		mode := concolicInputMode(elf)
		n := l.runConcolicLeg(ctx, elf, targets, func(sym string) strategy.ConstraintSolver {
			return strategy.TritonSolver{Binary: elf, TargetSym: sym, InputMode: mode}
		}, seedsX)
		if n > 0 {
			l.log("ensemble: concolic leg seeded %d constraint-solving input(s) into the shared corpus", n)
		}
		closeCPG()
	}

	engine := resolveFuzzEngine(leg.Engine, false)
	if leg.Engine == EngineAuto {
		engine = resolveFuzzEngine(leg.Engine, fuzz.HasAFL(ctx, l.DockerBin, leg.Image))
	}

	fuzzCtx, cancelFuzz := context.WithCancel(ctx)
	defer cancelFuzz()
	var fuzzCrashes []fuzz.Crash
	var fuzzErr error
	var drainDirs []string
	// fuzzer→scientist coverage arrow; nil until an engine wires a source (vault: Loop Analyst)
	var covFeed CoverageFeed
	fuzzDone := make(chan struct{})

	switch engine {
	case EngineLibFuzzer:
		libCorpus := filepath.Join(exDir, "lib-corpus")
		_ = os.MkdirAll(libCorpus, 0o755)
		drainDirs = []string{libCorpus}
		camp := libFuzzerLeg(leg, libCorpus, []string{llmX.Dir()}, l.DockerBin)
		accum := &libFuzzerCovAccum{}
		camp.Log = accum.observe
		covFeed = newLiveCoverageFeed(accum.state, coverageTemp, ensembleCoverageSeed)
		l.log("ensemble: fuzz engine = native libFuzzer (harness %s)", camp.Harness)
		go func() {
			defer close(fuzzDone)
			res, e := camp.Run(fuzzCtx)
			fuzzCrashes, fuzzErr = res.Crashes, e
		}()
	default: // EngineAFL
		// with -F the fuzzer runs as -M "quarry"; plain runs use default/ — drain both
		fuzzOut := filepath.Join(exDir, "fuzz-out")
		drainDirs = []string{filepath.Join(fuzzOut, "quarry", "queue"), filepath.Join(fuzzOut, "default", "queue")}
		camp := aflLeg(leg, fuzzOut, llmX.Dir(), l.DockerBin)
		covFeed = newLiveCoverageFeed(aflCoverageSource(fuzzOut), coverageTemp, ensembleCoverageSeed)
		l.log("ensemble: fuzz engine = AFL (%s)", camp.AflBin)
		go func() {
			defer close(fuzzDone)
			res, e := camp.Run(fuzzCtx)
			fuzzCrashes, fuzzErr = res.Crashes, e
		}()
	}

	// install the coverage arrow only if the caller has none, and restore it after (vault: Loop Analyst)
	if l.Coverage == nil && covFeed != nil {
		l.Coverage = covFeed
		defer func() { l.Coverage = nil }()
		l.log("ensemble: coverage arrow active (fuzzer→scientist cold-set + plateau steer)")
	}

	pumpStop := make(chan struct{})
	pumpDone := make(chan struct{})
	drainQueue := func() {
		for _, d := range drainDirs {
			seedsX.PumpFrom(d, 64)
		}
	}
	go func() {
		defer close(pumpDone)
		t := time.NewTicker(8 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pumpStop:
				return
			case <-t.C:
				drainQueue()
			}
		}
	}()

	l.log("ensemble: scientist + fuzzer legs over shared corpus %s (fuzz budget %s)", exDir, leg.Budget)
	rep, runErr := l.Run(ctx, req)
	close(pumpStop)
	<-pumpDone // quiesce the pump before harvesting (no post-return writes)

	if runErr != nil {
		cancelFuzz()
		<-fuzzDone
		return rep, runErr
	}
	// let the fuzzer run its own full budget even if scientists exhausted early (vault: Loop Analyst)
	if l.Log != nil {
		l.log("ensemble: scientist leg done; fuzzer continues to its %s budget", leg.Budget)
	}
	<-fuzzDone
	if fuzzErr != nil {
		l.log("ensemble: fuzzer leg ended: %v", fuzzErr)
	}

	// re-verify every crash on the trusted oracle build; harvestPoV dedups by behavioral key (vault: Loop Analyst)
	v := &verify.Verifier{Runner: l.Runner, Store: l.Store}
	ps, ab := pathSig(req), acquiredBy(req)
	fuzzConfirmed := 0
	for _, cr := range fuzzCrashes {
		vr, verr := v.Verify(ctx, verify.Request{Model: "fuzz", Spec: req.Oracle, Base: req.Base, Fixed: req.Fixed, PoV: cr.Bytes})
		if verr != nil || !vr.Verdict.Pass {
			continue // instrumented-build crash the oracle build doesn't reproduce → not a finding
		}
		f, herr := l.harvestPoV(ctx, rep.RunID, "fuzz", "coverage-guided mutation ("+cr.Name+")", req, cr.Bytes, &vr, ps, "fuzz", ab)
		if herr != nil {
			l.log("ensemble: fuzz-crash harvest: %v", herr)
			continue
		}
		if f == nil {
			continue // deduped against the scientist leg or an earlier fuzz crash
		}
		rep.Findings = append(rep.Findings, *f)
		fuzzConfirmed++
	}
	if fuzzConfirmed > 0 {
		rep.Confirmed = true
	}
	rep.PoVSubmissions += len(fuzzCrashes)
	l.log("ensemble: fuzzer contributed %d oracle-confirmed finding(s) from %d crash(es); %d total findings",
		fuzzConfirmed, len(fuzzCrashes), len(rep.Findings))
	return rep, nil
}

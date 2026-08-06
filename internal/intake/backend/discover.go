package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// FuzzerFor is the single place name→Fuzzer resolves, so the orchestrator and CLI agree.
func FuzzerFor(name, module, function string) (Fuzzer, bool) {
	switch name {
	case "c":
		return C{}, true
	case "go":
		return Go{FuzzFunc: function}, true
	case "python":
		return Python{Module: module, Function: function}, true
	case "java":
		return Java{Lib: module, Function: function}, true
	case "rust":
		return Rust{Crate: module, Function: function}, true
	case "js":
		return JS{Module: module, Function: function}, true
	case "php":
		return PHP{Lib: module, Function: function}, true
	default:
		return nil, false
	}
}

type DiscoverOpts struct {
	Backend    string // "" ⇒ auto-detect
	Module     string
	Function   string
	BudgetSecs int
	CorpusDir  string
}

type Discovered struct {
	PoV    []byte
	Fault  Fault
	Grader string
}

type Report struct {
	Backend    string
	Image      string
	RawCrashes int // total artifacts the fuzzer produced, pre-dedup
	Confirmed  []Discovered
}

// Discover re-confirms every fuzzer crash on our runner; dedup is by (class, signal, site).
func Discover(ctx context.Context, dir string, opts DiscoverOpts) (Report, error) {
	name := opts.Backend
	if name == "" {
		be := Detect(dir)
		if be == nil {
			return Report{}, fmt.Errorf("discover: no implemented backend recognizes %s", dir)
		}
		name = be.Name()
	}
	fz, ok := FuzzerFor(name, opts.Module, opts.Function)
	if !ok {
		return Report{}, fmt.Errorf("discover: %q is not a discovery backend (see the registry)", name)
	}
	rep := Report{Backend: name}
	image, err := fz.BuildImage(ctx, dir)
	if err != nil {
		return rep, fmt.Errorf("discover: build: %w", err)
	}
	rep.Image = image
	crashes, err := fz.Fuzz(ctx, image, opts.CorpusDir, opts.BudgetSecs)
	if err != nil {
		return rep, fmt.Errorf("discover: fuzz: %w", err)
	}
	rep.RawCrashes = len(crashes)

	seen := map[string]bool{}
	for _, pov := range crashes {
		fault, err := fz.RunOnce(ctx, image, pov)
		if err != nil || !fault.Faulted {
			continue // trust nothing that does not reproduce on our runner
		}
		key := string(fault.Class) + "|" + fault.Signal + "|" + fault.Site
		if seen[key] {
			continue
		}
		seen[key] = true
		rep.Confirmed = append(rep.Confirmed, Discovered{PoV: pov, Fault: fault, Grader: fault.Grader()})
	}
	return rep, nil
}

func PoVDigest(pov []byte) string {
	s := sha256.Sum256(pov)
	return hex.EncodeToString(s[:6])
}

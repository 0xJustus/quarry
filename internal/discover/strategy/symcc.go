package strategy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type SymCCSolver struct {
	// a SymCC-instrumented target build that writes solutions to SYMCC_OUTPUT_DIR
	SymCCBinary string
	// symcc_fuzzing_helper: unsupported, so a non-empty value is REFUSED not ignored
	HelperPath string
	ArgvTmpl   []string // target argv, "@@" is the seed file path
}

func SymCCAvailable(s SymCCSolver) bool {
	if s.SymCCBinary == "" {
		return false
	}
	if fi, err := os.Stat(s.SymCCBinary); err != nil || fi.IsDir() {
		return false
	}
	if s.HelperPath != "" {
		// never report available for a configuration the exec path ignores
		return false
	}
	return true
}

func (s SymCCSolver) Solve(ctx context.Context, seed []byte) (inputs [][]byte, solved int, err error) {
	if !SymCCAvailable(s) {
		if s.HelperPath != "" {
			return nil, 0, fmt.Errorf("symcc: HelperPath=%q is not supported — the symcc_fuzzing_helper flow is not implemented and would be silently ignored; unset HelperPath to run SymCCBinary directly (solutions are harvested from SYMCC_OUTPUT_DIR)", s.HelperPath)
		}
		return nil, 0, fmt.Errorf("symcc: no SymCC toolchain (SymCCBinary=%q) — install SymCC and point SymCCBinary at an instrumented target build", s.SymCCBinary)
	}
	wd, err := os.MkdirTemp("", "quarry-symcc-*")
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(wd)
	seedPath := filepath.Join(wd, "seed")
	if err := os.WriteFile(seedPath, seed, 0o644); err != nil {
		return nil, 0, err
	}
	outDir := filepath.Join(wd, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, 0, err
	}

	argv := s.ArgvTmpl
	if len(argv) == 0 {
		argv = []string{s.SymCCBinary, "@@"}
	}
	rendered := make([]string, len(argv))
	for i, a := range argv {
		rendered[i] = strings.ReplaceAll(a, "@@", seedPath)
	}
	cmd := exec.CommandContext(ctx, rendered[0], rendered[1:]...)
	cmd.Env = append(os.Environ(), "SYMCC_OUTPUT_DIR="+outDir, "SYMCC_INPUT_FILE="+seedPath)
	// a non-zero exit is normal (the target may reject the seed); harvest regardless
	_ = cmd.Run()

	entries, _ := os.ReadDir(outDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if b, rerr := os.ReadFile(filepath.Join(outDir, e.Name())); rerr == nil && len(b) > 0 {
			inputs = append(inputs, b)
		}
	}
	return inputs, len(inputs), nil
}

var _ ConstraintSolver = SymCCSolver{}

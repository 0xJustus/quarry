package strategy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type TritonSolver struct {
	DockerBin string // "" ⇒ "docker"
	Image     string // "" ⇒ "quarry-triton:latest"
	Binary    string // host path to the target ELF (static x86-64)
	InputMode string // "read" or "libfuzzer"; "" ⇒ read
	EntrySym  string // "" ⇒ main / LLVMFuzzerTestOneInput per InputMode
	TargetSym string // the sink symbol to reach (required)
	ReadSym   string // read-mode input symbol to hook; "" ⇒ driver default "read"
	InputLen  int    // symbolic input bytes; 0 ⇒ driver default 4
	MaxSteps  int    // emulation step cap; 0 ⇒ driver default
	// 0 ⇒ defaultTritonTimeout, but only when the caller declared no deadline
	Timeout time.Duration
}

// bounds a Solve whose caller declared no envelope: a concolic explore is unbounded
const defaultTritonTimeout = 2 * time.Minute

func (t TritonSolver) image() string {
	if t.Image != "" {
		return t.Image
	}
	return "quarry-triton:latest"
}

func (t TritonSolver) docker() string {
	if t.DockerBin != "" {
		return t.DockerBin
	}
	return "docker"
}

func TritonAvailable(t TritonSolver) bool {
	if t.Binary == "" || t.TargetSym == "" {
		return false
	}
	if fi, err := os.Stat(t.Binary); err != nil || fi.IsDir() {
		return false
	}
	return exec.Command(t.docker(), "image", "inspect", t.image()).Run() == nil
}

type tritonResult struct {
	Solved   bool   `json:"solved"`
	InputHex string `json:"input_hex"`
	Steps    int    `json:"steps"`
	Error    string `json:"error"`
}

// (nil, 0, nil) is reserved for a clean run that found no path; every other non-result must error.
func (t TritonSolver) Solve(ctx context.Context, _ []byte) (inputs [][]byte, solved int, err error) {
	if !TritonAvailable(t) {
		return nil, 0, fmt.Errorf("triton: unavailable (need target binary %q + the %s image; build it from testdata/Dockerfile.triton)", t.Binary, t.image())
	}
	wd, err := os.MkdirTemp("", "quarry-triton-run-*")
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(wd)
	if err := copyFile(t.Binary, filepath.Join(wd, "target")); err != nil {
		return nil, 0, err
	}
	spec := map[string]any{
		"binary": "/w/target", "input_len": orDefault(t.InputLen, 4),
		"target_sym": t.TargetSym, "entry_sym": t.EntrySym, "read_sym": t.ReadSym,
		"input_mode": t.InputMode,
	}
	if t.MaxSteps > 0 {
		spec["max_steps"] = t.MaxSteps
	}
	b, _ := json.Marshal(spec)
	if err := os.WriteFile(filepath.Join(wd, "spec.json"), b, 0o644); err != nil {
		return nil, 0, err
	}

	// a caller-declared deadline is authoritative over our own default
	rctx, cancel := ctx, context.CancelFunc(func() {})
	timeout := t.Timeout
	if timeout <= 0 {
		if _, declared := ctx.Deadline(); !declared {
			timeout = defaultTritonTimeout
		}
	}
	if timeout > 0 {
		rctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	// kill by name: CommandContext SIGKILLs only the docker CLI, not the container.
	name := filepath.Base(wd)
	cmd := exec.CommandContext(rctx, t.docker(), "run", "--rm", "--name", name, "--platform", "linux/amd64",
		"-v", wd+":/w", t.image(), "/usr/local/bin/triton_dse", "/w/spec.json")
	cliDone := make(chan struct{})
	reaped := make(chan struct{})
	go func() {
		defer close(reaped)
		select {
		case <-rctx.Done():
		case <-cliDone:
			// the CLI may have been killed rather than have finished
			if rctx.Err() == nil {
				return
			}
		}
		killContainer(t.docker(), name)
	}()
	out, runErr := cmd.CombinedOutput()
	close(cliDone)
	<-reaped // container gone BEFORE the deferred RemoveAll unmounts its /w

	if ctx.Err() != nil {
		return nil, 0, fmt.Errorf("triton: aim %s aborted before a verdict (%v) — inconclusive, not a no-path result", t.TargetSym, ctx.Err())
	}
	if rctx.Err() != nil {
		return nil, 0, fmt.Errorf("triton: aim %s exceeded its %s wall-clock cap — inconclusive, not a no-path result", t.TargetSym, timeout)
	}
	line := lastJSONLine(string(out))
	if line == "" {
		if runErr != nil {
			return nil, 0, fmt.Errorf("triton: driver failed: %v", runErr)
		}
		return nil, 0, fmt.Errorf("triton: driver produced no result line for aim %s — inconclusive", t.TargetSym)
	}
	var res tritonResult
	if uerr := json.Unmarshal([]byte(line), &res); uerr != nil {
		return nil, 0, fmt.Errorf("triton: unparseable driver result %q: %v", line, uerr)
	}
	// the driver reports its own hard failures here: it never ran the analysis
	if res.Error != "" {
		return nil, 0, fmt.Errorf("triton: driver error aiming at %s: %s", t.TargetSym, res.Error)
	}
	if runErr != nil {
		return nil, 0, fmt.Errorf("triton: driver exited non-zero aiming at %s: %v", t.TargetSym, runErr)
	}
	if !res.Solved {
		return nil, 0, nil // the one honest negative
	}
	sol, derr := hex.DecodeString(res.InputHex)
	if derr != nil || len(sol) == 0 {
		// solved but nothing usable: inconsistent, never fabricate and never launder
		return nil, 0, fmt.Errorf("triton: driver claimed solved for %s but input_hex is unusable (%q)", t.TargetSym, res.InputHex)
	}
	return [][]byte{sol}, 1, nil
}

// idempotent; with --rm an already-exited container is gone, so the error is ignored
func killContainer(dockerBin, name string) {
	_ = exec.Command(dockerBin, "kill", name).Run()
}

func orDefault(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// LAST, not first: Triton/loader chatter precedes the driver's result line
func lastJSONLine(s string) string {
	var last string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "{") && strings.HasSuffix(ln, "}") {
			last = ln
		}
	}
	return last
}

var _ ConstraintSolver = TritonSolver{}

package synth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ValidateSpec struct {
	// the Docker build context; harness.c and Dockerfile.quarry are written into it
	ContextDir string
	Dockerfile string
	HarnessC   string
	ImageTag   string
	DockerBin  string
	// bind-mounted byte-for-byte; never echoed through a shell
	BenignSeed []byte
	MinEdges   int
	// bounds EACH probe, enforced in-container so a hang is a verdict
	ProbeTimeout time.Duration
}

const (
	defaultMinEdges     = 16
	defaultProbeTimeout = 60 * time.Second
	// backstop only: the in-container `timeout` must be the bound that fires
	probeCLISlack    = 30 * time.Second
	timeoutKillGrace = "5"

	// mounted, not written by a container shell: no seed byte is ever parsed by /bin/sh
	seedDirInImage  = "/q_seed"
	seedFileName    = "seed.bin"
	seedPathInImage = seedDirInImage + "/" + seedFileName
	mapPathInImage  = "/q_map"

	// quarry-owned exit codes: the harness owns stdout, so status is the out-of-band channel
	probeTimeoutCode = 124
	probeNoMapCode   = 112
	// 0 and this are the ONLY exits that count as "did not self-crash"
	cleanSkeletonExit = 2
)

type ValidateResult struct {
	Built        bool
	SmokePass    bool // benign input → clean exit on the oracle build
	Edges        int
	CoveragePass bool
	BuildLog     string
	Reason       string // first failing gate; empty on a pass AND when INCONCLUSIVE
}

func (r ValidateResult) OK() bool { return r.Built && r.SmokePass && r.CoveragePass }

// rejection: Reason set + nil error. inconclusive: error + Reason left EMPTY.
func Validate(ctx context.Context, s ValidateSpec) (ValidateResult, error) {
	bin := s.DockerBin
	if bin == "" {
		bin = "docker"
	}
	minEdges := s.MinEdges
	if minEdges <= 0 {
		minEdges = defaultMinEdges
	}
	seed := s.BenignSeed
	if len(seed) == 0 {
		seed = []byte{0x00}
	}
	probeTimeout := s.ProbeTimeout
	if probeTimeout <= 0 {
		probeTimeout = defaultProbeTimeout
	}
	if err := writeContext(s.ContextDir, s.Dockerfile, s.HarnessC); err != nil {
		return ValidateResult{}, err
	}
	seedDir, err := os.MkdirTemp("", "quarry-synth-seed-*")
	if err != nil {
		return ValidateResult{}, err
	}
	defer os.RemoveAll(seedDir)
	if err := os.WriteFile(filepath.Join(seedDir, seedFileName), seed, 0o644); err != nil {
		return ValidateResult{}, err
	}

	var res ValidateResult
	buildOut, code, err := run(ctx, bin, "build", "-t", s.ImageTag, "-f", filepath.Join(s.ContextDir, "Dockerfile.quarry"), s.ContextDir)
	res.BuildLog = buildOut
	if err != nil {
		return res, fmt.Errorf("synth.Validate: docker build could not be run: %w", err)
	}
	if code != 0 {
		if dockerUnavailable(buildOut) {
			return res, fmt.Errorf("synth.Validate: docker is not usable, harness INCONCLUSIVE: %s", firstError(buildOut))
		}
		res.Reason = "image build failed: " + firstError(buildOut)
		return res, nil
	}
	res.Built = true

	// the verdict is the CLI's exit status: the harness writes stdout, so a marker there is forgeable
	smokeOut, code, err := runProbe(ctx, bin, probeTimeout, seedDir, s.ImageTag, nil,
		"timeout", "-k", timeoutKillGrace, probeSecs(probeTimeout), OracleBinPath, seedPathInImage)
	if err != nil {
		return res, fmt.Errorf("synth.Validate: benign-smoke probe could not be run, harness INCONCLUSIVE: %w: %s", err, firstError(smokeOut))
	}
	switch {
	case probeStartFailure(code):
		return res, fmt.Errorf("synth.Validate: benign-smoke probe never started (exit %d), harness INCONCLUSIVE: %s", code, firstError(smokeOut))
	case code == probeTimeoutCode:
		res.Reason = fmt.Sprintf("harness did not exit on benign input within %s (hang)", probeTimeout)
		return res, nil
	case code == 0 || code == cleanSkeletonExit:
		// exit 2 is no proof the library ran; the coverage gate below is what catches that
		res.SmokePass = true
	default:
		res.Reason = fmt.Sprintf("harness self-crashed or exited uncleanly on benign input (exit %d)", code)
		return res, nil
	}

	// every value spliced here is a quarry-owned constant; failures report as exit codes, never as "0 edges"
	covScript := fmt.Sprintf(
		"timeout -k %s %s afl-showmap -q -o %s -- %s %s >/dev/null 2>&1; st=$?; "+
			"if [ \"$st\" = %d ]; then exit %d; fi; "+
			"if [ ! -s %s ]; then exit %d; fi; exec wc -l < %s",
		timeoutKillGrace, probeSecs(probeTimeout), mapPathInImage, FuzzBinPath, seedPathInImage,
		probeTimeoutCode, probeTimeoutCode, mapPathInImage, probeNoMapCode, mapPathInImage)
	covOut, code, err := runProbe(ctx, bin, probeTimeout, seedDir, s.ImageTag,
		[]string{"AFL_MAP_SIZE=262144"}, "sh", "-c", covScript)
	if err != nil {
		return res, fmt.Errorf("synth.Validate: coverage probe could not be run, edge count INCONCLUSIVE: %w: %s", err, firstError(covOut))
	}
	switch {
	case probeStartFailure(code):
		return res, fmt.Errorf("synth.Validate: coverage probe never started (exit %d), edge count INCONCLUSIVE: %s", code, firstError(covOut))
	case code == probeTimeoutCode:
		res.Reason = fmt.Sprintf("harness did not exit on benign input within %s under afl-showmap (hang)", probeTimeout)
		return res, nil
	case code == probeNoMapCode:
		return res, fmt.Errorf("synth.Validate: afl-showmap produced no coverage map (missing or empty), edge count INCONCLUSIVE — is the fuzz build instrumented / AFL_MAP_SIZE large enough?: %s", firstError(covOut))
	case code != 0:
		return res, fmt.Errorf("synth.Validate: coverage probe failed (exit %d), edge count INCONCLUSIVE: %s", code, firstError(covOut))
	}
	edges, ok := countEdges(covOut)
	if !ok {
		return res, fmt.Errorf("synth.Validate: coverage probe emitted no edge count, INCONCLUSIVE: %s", firstError(covOut))
	}
	res.Edges = edges
	if res.Edges < minEdges {
		res.Reason = fmt.Sprintf("harness reaches too little library code: %d edges < %d floor", res.Edges, minEdges)
		return res, nil
	}
	res.CoveragePass = true
	return res, nil
}

// Dockerfile.quarry, not Dockerfile: never clobber the target's own.
func writeContext(dir, dockerfile, harnessC string) error {
	if dir == "" {
		return fmt.Errorf("synth.Validate: empty ContextDir")
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile.quarry"), []byte(dockerfile), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "harness.c"), []byte(harnessC), 0o644)
}

func runProbe(ctx context.Context, bin string, budget time.Duration, seedDir, image string, env []string, cmd ...string) (string, int, error) {
	cctx, cancel := context.WithTimeout(ctx, budget+probeCLISlack)
	defer cancel()
	return run(cctx, bin, probeRunArgs(seedDir, image, env, cmd)...)
}

// air-gapped, seed mounted read-only: the harness under test is model-authored code.
func probeRunArgs(seedDir, image string, env, cmd []string) []string {
	args := []string{"run", "--rm", "--network", "none", "-v", seedDir + ":" + seedDirInImage + ":ro"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image)
	return append(args, cmd...)
}

// err is non-nil ONLY when no exit status could be observed; code is then -1.
func run(ctx context.Context, bin string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	// TERM, not kill: docker proxies it, so --rm still cleans the container up
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err == nil {
		return buf.String(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() >= 0 {
		return buf.String(), ee.ExitCode(), nil
	}
	return buf.String(), -1, err
}

// `docker build` reports an unreachable daemon as a plain exit 1, not out of band like `run`.
func dockerUnavailable(out string) bool {
	l := strings.ToLower(out)
	for _, s := range []string{
		"cannot connect to the docker daemon",
		"is the docker daemon running",
		"permission denied while trying to connect to the docker daemon",
		"error during connect:",
	} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// 125/126/127: the probe never ran what we asked, so it is no evidence about the harness.
func probeStartFailure(code int) bool { return code >= 125 && code <= 127 }

func probeSecs(d time.Duration) string {
	secs := int64((d + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10)
}

// ok=false means no count was printed: a MISSING measurement, never zero coverage.
func countEdges(out string) (int, bool) {
	fields := strings.Fields(out)
	for i := len(fields) - 1; i >= 0; i-- {
		if n, err := strconv.Atoi(fields[i]); err == nil {
			return n, true
		}
	}
	return 0, false
}

// the LAST non-empty line, which is usually the actual error.
func firstError(log string) string {
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			if len(s) > 200 {
				s = s[:200] + "…"
			}
			return s
		}
	}
	return "no output"
}

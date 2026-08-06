package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

// image transfer gets its OWN budget, never the PoV's wall clock
const imagePullTimeout = 30 * time.Minute

type shimStatus int

const (
	shimStatusMissing shimStatus = iota
	shimStatusUntrusted
	shimStatusOK
)

func (s shimStatus) String() string {
	switch s {
	case shimStatusUntrusted:
		return "the status file carries no wait status authenticated by this run's nonce"
	case shimStatusOK:
		return "ok"
	}
	return "the status file could not be read"
}

// per-run secret the shim keeps out of the target's env; it authenticates the status file
func newStatusNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// parses "<nonce> signal:N" / "<nonce> exit:N"; content without this run's nonce is never parsed
func readShimStatus(path, nonce string) (sig, exit int, st shimStatus) {
	if path == "" {
		return 0, 0, shimStatusMissing
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, shimStatusMissing
	}
	s := strings.TrimSpace(string(b))
	body, authentic := strings.CutPrefix(s, nonce+" ")
	if nonce == "" || !authentic {
		return 0, 0, shimStatusUntrusted
	}
	if v, found := strings.CutPrefix(body, "signal:"); found {
		if n, err := strconv.Atoi(v); err == nil {
			return n, 0, shimStatusOK
		}
	}
	if v, found := strings.CutPrefix(body, "exit:"); found {
		if n, err := strconv.Atoi(v); err == nil {
			return 0, n, shimStatusOK
		}
	}
	return 0, 0, shimStatusUntrusted
}

// keep in sync with quarry-shim (exits 128+N signalled / N voluntary, propagated by --init's tini): cross-checks a container-side claim.
func shimCLICode(sig, exit int) int {
	if sig != 0 {
		return 128 + sig
	}
	return exit
}

// DockerRunner runs each PoV in a fresh, air-gapped container via the docker CLI.
type DockerRunner struct {
	DockerBin string
	PoVMount  string
	// linux/<container-arch> quarry-shim as entrypoint; without it an untrusted image forges the trusted exit code via exit(128+N).
	Shim string
}

func (d DockerRunner) bin() string {
	if d.DockerBin != "" {
		return d.DockerBin
	}
	return "docker"
}

func (d DockerRunner) shim() string {
	if d.Shim != "" {
		return d.Shim
	}
	return os.Getenv("QUARRY_SHIM")
}

func (d DockerRunner) povMount() string {
	if d.PoVMount != "" {
		return d.PoVMount
	}
	return "/pov"
}

func (d DockerRunner) Run(ctx context.Context, spec RunSpec) (oracle.RunResult, error) {
	if spec.Image == "" {
		return oracle.RunResult{}, errors.New("runner: DockerRunner needs an Image")
	}

	// fail closed BEFORE the container starts; provisioning never opens the air-gap
	var toolMounts []broker.BindMount
	if !spec.Toolset.Empty() {
		if spec.Provisioner == nil {
			return oracle.RunResult{}, errors.New("runner: a toolset is declared but no Provisioner is configured")
		}
		plan, perr := spec.Provisioner.Provision(spec.Toolset)
		if perr != nil {
			return oracle.RunResult{}, fmt.Errorf("runner: provisioning toolset: %w", perr)
		}
		toolMounts = plan.Mounts
	}

	// pull BEFORE the target's clock starts: a cold image inside spec.timeout() would fake TimedOut=true for a target that never ran.
	if err := d.ensureImage(ctx, spec.Image); err != nil {
		return oracle.RunResult{}, err
	}

	hostDir, err := os.MkdirTemp("", "quarry-pov-*")
	if err != nil {
		return oracle.RunResult{}, err
	}
	defer os.RemoveAll(hostDir)
	if !spec.NoPoV {
		if err := os.WriteFile(filepath.Join(hostDir, "poc.bin"), spec.PoV, 0o644); err != nil {
			return oracle.RunResult{}, err
		}
	}
	pocInContainer := d.povMount() + "/poc.bin"

	containerName := "quarry-run-" + filepath.Base(hostDir)

	// no --rm: it would delete the container before State.OOMKilled can be read
	args := []string{"run", "--init", "--name", containerName}
	if spec.StdinPoV && !spec.NoPoV {
		args = append(args, "-i")
	}
	if !spec.Network {
		args = append(args, "--network", "none")
	}
	// bounds a runaway spin by CPU-time; not what hang precision rests on.
	cpuCap := max(int(spec.timeout().Seconds())*4, 60)
	args = append(args,
		"--pids-limit", "512",
		"--memory", "2g", "--memory-swap", "2g",
		"--cpus", "1",
		"--ulimit", fmt.Sprintf("cpu=%d", cpuCap),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--ulimit", "core=0",
	)
	if !spec.NoPoV {
		args = append(args, "-v", hostDir+":"+d.povMount()+":ro")
	}
	for _, m := range toolMounts {
		args = append(args, "-v", m.HostPath+":"+m.ContainerPath+":ro")
	}
	if spec.Workdir != "" {
		args = append(args, "-w", spec.Workdir)
	}
	for _, e := range sanitizerEnv(spec) {
		args = append(args, "-e", e)
	}
	var statusFile, statusNonce string
	if s := d.shim(); s != "" {
		statusDir, serr := os.MkdirTemp("", "quarry-status-*")
		if serr != nil {
			// the shim IS the un-forgeability boundary: never continue without it
			return oracle.RunResult{}, fmt.Errorf("runner: could not create the shim status dir: %w", serr)
		}
		defer os.RemoveAll(statusDir)
		nonce, nerr := newStatusNonce()
		if nerr != nil {
			return oracle.RunResult{}, fmt.Errorf("runner: could not mint a shim status nonce: %w", nerr)
		}
		// file world-writable (shim runs as image uid), directory not (no unlink+recreate); the nonce, not the mode, authenticates.
		statusFile, statusNonce = filepath.Join(statusDir, "status"), nonce
		if werr := os.WriteFile(statusFile, nil, 0o666); werr != nil {
			return oracle.RunResult{}, fmt.Errorf("runner: could not create the shim status file: %w", werr)
		}
		if cerr := os.Chmod(statusFile, 0o666); cerr != nil { // umask-proof
			return oracle.RunResult{}, fmt.Errorf("runner: could not open the shim status file to the container: %w", cerr)
		}
		if cerr := os.Chmod(statusDir, 0o711); cerr != nil {
			return oracle.RunResult{}, fmt.Errorf("runner: could not set up the shim status dir: %w", cerr)
		}
		args = append(args,
			"-v", s+":/quarry-shim:ro",
			"-v", statusDir+":/quarry-status",
			"-e", "QUARRY_STATUS=/quarry-status/status",
			"-e", "QUARRY_STATUS_NONCE="+nonce,
			"--entrypoint", "/quarry-shim",
		)
	}
	args = append(args, spec.Image)
	args = append(args, spec.argv(pocInContainer)...)

	runCtx, cancel := context.WithTimeout(ctx, spec.timeout())
	defer cancel()

	cmd := exec.CommandContext(runCtx, d.bin(), args...)
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = maxOutputBytes, maxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if spec.StdinPoV {
		cmd.Stdin = bytes.NewReader(spec.PoV)
	}

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	// read the OOM state before removing the container ourselves
	oomKilled := d.inspectOOM(containerName)
	defer d.forceRemove(containerName)

	rr := oracle.RunResult{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Duration:  dur,
		Sanitizer: ParseSanitizer("", stderr.String()),
		OOMKilled: oomKilled,
	}
	// must precede the branches below: each of them returns this rr
	applyTaint(&rr, spec)

	if runCtx.Err() == context.DeadlineExceeded {
		// the supervisor's deadline outranks any out-of-band status: a run we cut off can never be cross-checked.
		rr.TimedOut = true
		rr.Sanitizer = corroborateSanitizer(rr)
		return rr, nil
	}

	cliCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return oracle.RunResult{}, fmt.Errorf("runner: docker invocation failed: %w (stderr: %s)", runErr, truncateStr(rr.Stderr, 300))
		}
		cliCode = exitErr.ExitCode()
	}

	sig, exitc, sst := readShimStatus(statusFile, statusNonce)
	switch {
	case statusFile != "" && sst != shimStatusOK:
		// shim wired but no authentic status ⇒ INCONCLUSIVE; 128+N inference would hand the target the exact forgery the shim exists to stop.
		if rr.OOMKilled {
			// a cgroup OOM comes from the daemon (un-forgeable) and explains why the shim never wrote; no exit-code inference.
			rr.Sanitizer = corroborateSanitizer(rr)
			return rr, nil
		}
		return oracle.RunResult{}, fmt.Errorf("runner: quarry-shim recorded no authentic wait status (%s; docker exit %d): the target's outcome is unobservable; stderr: %s", sst, cliCode, truncateStr(rr.Stderr, 200))

	case sst == shimStatusOK:
		// the claim must match the supervisor's own measurement, else the target wrote it
		if want := shimCLICode(sig, exitc); want != cliCode {
			return oracle.RunResult{}, fmt.Errorf("runner: shim wait status (signal=%d exit=%d ⇒ docker exit %d) contradicts docker's own exit %d; refusing to render a forged observation", sig, exitc, want, cliCode)
		}
		rr.TermSignal, rr.ExitCode = sig, exitc

	default:
		// 125/126/127 are docker's own failures: the target never ran, so no observation
		if cliCode == 125 || cliCode == 126 || cliCode == 127 {
			return oracle.RunResult{}, fmt.Errorf("runner: docker could not run the target (exit %d): %s", cliCode, truncateStr(rr.Stderr, 300))
		}
		// no shim: 128+N is indistinguishable from a voluntary exit(128+N) (vault: Runner)
		if cliCode > 128 && cliCode < 128+64 {
			rr.TermSignal = cliCode - 128
		} else {
			rr.ExitCode = cliCode
		}
	}

	rr.Sanitizer = corroborateSanitizer(rr)
	return rr, nil
}

// an image that never materialized produced no observation, so this is an infra error
func (d DockerRunner) ensureImage(ctx context.Context, image string) error {
	ictx, icancel := context.WithTimeout(ctx, 30*time.Second)
	defer icancel()
	if err := exec.CommandContext(ictx, d.bin(), "image", "inspect", image).Run(); err == nil {
		return nil
	}
	pctx, pcancel := context.WithTimeout(ctx, imagePullTimeout)
	defer pcancel()
	out, err := exec.CommandContext(pctx, d.bin(), "pull", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("runner: image %q is not present locally and could not be pulled: %w (%s)", image, err, truncateStr(string(out), 300))
	}
	return nil
}

func (d DockerRunner) forceRemove(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, d.bin(), "rm", "-f", name).Run()
}

// State.OOMKilled is the un-forgeable cgroup memory-kill signal; any error → false
func (d DockerRunner) inspectOOM(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, d.bin(), "inspect", name, "--format", "{{.State.OOMKilled}}").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

func truncateStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var _ Runner = DockerRunner{}
var _ Runner = LocalRunner{}

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Sandbox runs the agent's exec off-host; implementations MUST NOT expose the host fs (beyond the workspace), the docker socket, or (by default) the network.
type Sandbox interface {
	Exec(ctx context.Context, name string, args []string, stdin string, timeout time.Duration, maxOutput int) (ExecResult, error)
	Close() error
}

// ContainerSandbox isolates exec in a locked-down container.
type ContainerSandbox struct {
	DockerBin string        // default "docker"
	Image     string        // must be digest-pinned
	HostDir   string        // workspace root, bind-mounted at /work
	Name      string        // container name
	Memory    string        // e.g. "2g" (default)
	PidsLimit int           // default 512
	StartWait time.Duration // grace for the keepalive to come up (default 20s)
	Network   string        // default "none"; a named net scopes reachability to the broker only

	mu      sync.Mutex
	started bool
}

// NewContainerSandbox refuses a mutable tag; the container starts lazily.
func NewContainerSandbox(dockerBin, image, hostDir, name string) (*ContainerSandbox, error) {
	if !strings.Contains(image, "@sha256:") && !strings.HasPrefix(image, "sha256:") {
		return nil, fmt.Errorf("agent sandbox image must be digest-pinned (repo@sha256:… or sha256:…), got %q — a mutable tag is not reproducible and can drift", image)
	}
	abs, err := filepath.Abs(hostDir)
	if err != nil {
		return nil, err
	}
	if dockerBin == "" {
		dockerBin = "docker"
	}
	return &ContainerSandbox{DockerBin: dockerBin, Image: image, HostDir: abs, Name: name, Memory: "2g", PidsLimit: 512, StartWait: 20 * time.Second}, nil
}

// runArgs is the hardened keepalive argv; the isolation flags here are load-bearing (vault: Agent Core).
func (s *ContainerSandbox) runArgs() []string {
	mem := s.Memory
	if mem == "" {
		mem = "2g"
	}
	pids := s.PidsLimit
	if pids <= 0 {
		pids = 512
	}
	network := s.Network
	if network == "" {
		network = "none"
	}
	return []string{
		"run", "-d", "--rm", "--init",
		"--name", s.Name,
		"--network", network,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", fmt.Sprintf("%d", pids),
		"--memory", mem, "--memory-swap", mem,
		"--ulimit", "core=0",
		"--read-only",
		"--tmpfs", "/tmp:rw,exec",
		"-v", s.HostDir + ":/work", // the only host path exposed; no docker socket (no host pivot)
		"-w", "/work",
		s.Image,
		"tail", "-f", "/dev/null", // keepalive
	}
}

func (s *ContainerSandbox) start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}
	startCtx, cancel := context.WithTimeout(ctx, s.startWait())
	defer cancel()
	cmd := exec.CommandContext(startCtx, s.DockerBin, s.runArgs()...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sandbox: start container %s: %w (stderr: %s)", s.Name, err, truncate(errb.String(), 300))
	}
	s.started = true
	return nil
}

func (s *ContainerSandbox) startWait() time.Duration {
	if s.StartWait > 0 {
		return s.StartWait
	}
	return 20 * time.Second
}

// Exec runs one command via `docker exec`; semantics match host Workspace.Exec.
func (s *ContainerSandbox) Exec(ctx context.Context, name string, args []string, stdin string, timeout time.Duration, maxOutput int) (ExecResult, error) {
	if err := s.start(ctx); err != nil {
		return ExecResult{}, err
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dargs := []string{"exec"}
	if stdin != "" {
		dargs = append(dargs, "-i")
	}
	dargs = append(dargs, s.Name, name)
	dargs = append(dargs, args...)

	cmd := exec.CommandContext(runCtx, s.DockerBin, dargs...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	res := ExecResult{
		Stdout: capString(stdout.String(), maxOutput),
		Stderr: capString(stderr.String(), maxOutput),
	}
	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	if err == nil {
		return res, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	res.ExitCode = -1
	if res.Stderr == "" {
		res.Stderr = err.Error()
	}
	return res, nil
}

func (s *ContainerSandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return nil
	}
	s.started = false
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, s.DockerBin, "rm", "-f", s.Name).Run()
}

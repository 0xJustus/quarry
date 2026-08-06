package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/envscrub"
)

// Workspace is the agent's scratch dir, confined to its root; exec here is not the oracle and reaches no verdict.
type Workspace struct {
	Root        string
	ExecTimeout time.Duration // per exec call (default 60s)
	MaxOutput   int           // stdout/stderr cap per exec (default 64 KiB)
	Sandbox     Sandbox       // if set, exec runs isolated; file tools stay host-side
}

func (w *Workspace) Close() error {
	if w.Sandbox != nil {
		return w.Sandbox.Close()
	}
	return nil
}

func NewWorkspace(dir string) (*Workspace, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Workspace{Root: dir, ExecTimeout: 60 * time.Second, MaxOutput: 64 * 1024}, nil
}

// name normalizes rel to a clean root-relative name; os.Root confines it at open time.
func name(rel string) string {
	n := strings.TrimPrefix(path.Clean("/"+rel), "/")
	if n == "" {
		return "." // os.Root.Open("") is an "empty path" error
	}
	return n
}

// WriteFile writes a workspace-relative path; os.Root refuses escaping symlinks (closes the TOCTOU hole).
func (w *Workspace) WriteFile(rel, content string) error {
	root, err := os.OpenRoot(w.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	n := name(rel)
	if dir := path.Dir(n); dir != "." && dir != "/" && dir != "" {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := root.Create(n)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, content)
	return err
}

func (w *Workspace) ReadFile(rel string) (string, error) {
	root, err := os.OpenRoot(w.Root)
	if err != nil {
		return "", err
	}
	defer root.Close()
	f, err := root.Open(name(rel))
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return string(b), err
}

func (w *Workspace) List(rel string) ([]string, error) {
	root, err := os.OpenRoot(w.Root)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name(rel))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		nm := e.Name()
		if e.IsDir() {
			nm += "/"
		}
		names = append(names, nm)
	}
	return names, nil
}

type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	TimedOut bool
}

func (w *Workspace) Exec(ctx context.Context, name string, args []string, stdin string, timeout time.Duration) (ExecResult, error) {
	if timeout <= 0 {
		timeout = w.ExecTimeout
	}
	if w.Sandbox != nil {
		return w.Sandbox.Exec(ctx, name, args, stdin, timeout, w.MaxOutput)
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Dir = w.Root
	// scrub secrets: exec is reachable by target-derived text and is not a security boundary
	cmd.Env = envscrub.Environ()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := ExecResult{
		Stdout: capString(stdout.String(), w.MaxOutput),
		Stderr: capString(stderr.String(), w.MaxOutput),
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

func capString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n…[truncated]…"
}

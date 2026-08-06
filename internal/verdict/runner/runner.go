package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/broker"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

const pocPlaceholder = "{poc}"

// pin every sanitizer to abort: corroboration requires a real SIGABRT
const pinnedASanOptions = "abort_on_error=1:detect_leaks=0:handle_segv=1:handle_abort=1:print_summary=1:symbolize=1"
const pinnedUBSanOptions = "abort_on_error=1:halt_on_error=1:print_stacktrace=1:symbolize=1"
const pinnedMSanOptions = "abort_on_error=1:halt_on_error=1:print_stats=0"
const pinnedTSanOptions = "abort_on_error=1:halt_on_error=1"

const maxOutputBytes = 256 * 1024

// bounds cmd.Wait: a forked child keeps the output pipes open (vault: Runner)
const waitDrainGrace = 2 * time.Second

type RunSpec struct {
	// exactly one of Image or Binary is used
	Image  string
	Binary string

	Workdir  string
	ArgvTmpl []string // "{poc}" is replaced with the PoV path
	StdinPoV bool
	PoV      []byte
	Env      []string
	NoPoV    bool // self-contained reproducer: nothing written/mounted, argv verbatim

	Sanitizer string
	Timeout   time.Duration
	Network   bool // zero value = air-gapped (DockerRunner: --network none)
	// needs CAP_SYS_ADMIN (privileged microVM only); no-op off Linux
	IsolateNetwork bool

	// non-nil selects ServiceRunner; the repro path ignores it
	Service *ServiceSpec

	// nil → off; the runner never fabricates taint
	Taint TaintParser

	// honored by DockerRunner only; LocalRunner is not container-isolated
	Toolset broker.Toolset
	// required iff Toolset is non-empty; nil there is an error
	Provisioner *broker.Provisioner
}

func (s RunSpec) timeout() time.Duration {
	if s.Timeout <= 0 {
		return 30 * time.Second
	}
	return s.Timeout
}

func (s RunSpec) argv(pocPath string) []string {
	if s.NoPoV {
		return append([]string(nil), s.ArgvTmpl...)
	}
	return substituteArgv(s.ArgvTmpl, pocPath)
}

type Runner interface {
	Run(ctx context.Context, spec RunSpec) (oracle.RunResult, error)
}

// LocalRunner runs a local binary in a subprocess; not container-isolated.
type LocalRunner struct{}

func (LocalRunner) Run(ctx context.Context, spec RunSpec) (oracle.RunResult, error) {
	if spec.Binary == "" {
		return oracle.RunResult{}, errors.New("runner: LocalRunner needs a Binary")
	}
	dir, err := os.MkdirTemp("", "quarry-run-*")
	if err != nil {
		return oracle.RunResult{}, err
	}
	defer os.RemoveAll(dir)

	pocPath := filepath.Join(dir, "poc.bin")
	if !spec.NoPoV {
		if err := os.WriteFile(pocPath, spec.PoV, 0o644); err != nil {
			return oracle.RunResult{}, err
		}
	}

	argv := spec.argv(pocPath)

	runCtx, cancel := context.WithTimeout(ctx, spec.timeout())
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.Binary, argv...)
	if spec.Workdir != "" {
		cmd.Dir = spec.Workdir
	} else {
		cmd.Dir = dir
	}
	// untrusted target: never inherit the operator env (proxy key, QUARRY_* secrets)
	cmd.Env = localChildEnv(spec)
	if spec.StdinPoV {
		cmd.Stdin = bytes.NewReader(spec.PoV)
	}

	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = maxOutputBytes, maxOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	applyNetIsolation(cmd, spec.IsolateNetwork)
	// the deadline kill must reach the whole process tree
	cmd.WaitDelay = waitDrainGrace
	killedLive := applyProcessGroup(cmd)

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)
	// os/exec signals only the direct child; a forked descendant would survive into the NEXT run
	reapProcessGroup(cmd)

	rr, err := assemble(runCtx, cmd.ProcessState, killedLive(), runErr, stdout.String(), stderr.String(), dur)
	if err != nil {
		return oracle.RunResult{}, err
	}
	applyTaint(&rr, spec)
	return rr, nil
}

func substituteArgv(tmpl []string, pocPath string) []string {
	out := make([]string, 0, len(tmpl)+1)
	replaced := false
	for _, a := range tmpl {
		if strings.Contains(a, pocPlaceholder) {
			out = append(out, strings.ReplaceAll(a, pocPlaceholder, pocPath))
			replaced = true
		} else {
			out = append(out, a)
		}
	}
	if !replaced {
		out = append(out, pocPath)
	}
	return out
}

// fail closed: "did not run" and "not fully observed" are errors, never observations
func assemble(ctx context.Context, ps *os.ProcessState, killedLive bool, runErr error, stdout, stderr string, dur time.Duration) (oracle.RunResult, error) {
	rr := oracle.RunResult{
		Stdout:    stdout,
		Stderr:    stderr,
		Duration:  dur,
		Sanitizer: ParseSanitizer("", stderr),
	}
	var exitErr *exec.ExitError
	haveExit := errors.As(runErr, &exitErr)
	sig := 0
	if haveExit {
		sig = signalOf(exitErr)
	}
	// a signal WE sent is never the target's; a real fault signal that beat it is evidence
	weKilledIt := killedLive && !oracle.IsCrashSignal(sig)

	switch {
	case ps == nil:
		return oracle.RunResult{}, fmt.Errorf("runner: target did not run: %w", runErr)

	case weKilledIt && ctx.Err() == context.DeadlineExceeded:
		// only a target STILL RUNNING at the deadline is a hang (vault: Runner)
		rr.TimedOut = true

	case weKilledIt:
		return oracle.RunResult{}, fmt.Errorf("runner: run torn down before the target finished (%v)", ctx.Err())

	case errors.Is(runErr, exec.ErrWaitDelay):
		// output provably incomplete: neither a clean exit nor a hang, so refuse to judge
		return oracle.RunResult{}, fmt.Errorf("runner: target left descendants holding its output pipes; observation incomplete (%s)", ps)

	case runErr == nil:
		rr.ExitCode = 0

	case haveExit:
		if sig != 0 {
			rr.TermSignal = sig
		} else {
			rr.ExitCode = exitErr.ExitCode()
		}

	default:
		return oracle.RunResult{}, fmt.Errorf("runner: could not supervise the target: %w", runErr)
	}

	rr.Sanitizer = corroborateSanitizer(rr)
	return rr, nil
}

func sanitizerEnv(spec RunSpec) []string {
	var env []string
	for _, e := range spec.Env {
		if isSafetyCriticalEnv(e) {
			continue
		}
		env = append(env, e)
	}
	// pin ALL of them last (last-wins): a combined build must abort on a UBSan-only violation
	env = append(env,
		"ASAN_OPTIONS="+pinnedASanOptions,
		"UBSAN_OPTIONS="+pinnedUBSanOptions,
		"MSAN_OPTIONS="+pinnedMSanOptions,
		"TSAN_OPTIONS="+pinnedTSanOptions,
	)
	return env
}

// never os.Environ(): it would leak the proxy key to the target
func localChildEnv(spec RunSpec) []string {
	var env []string
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	if h := os.Getenv("HOME"); h != "" {
		env = append(env, "HOME="+h)
	}
	if sp := os.Getenv("ASAN_SYMBOLIZER_PATH"); sp != "" {
		env = append(env, "ASAN_SYMBOLIZER_PATH="+sp)
	}
	return append(env, sanitizerEnv(spec)...)
}

func isSafetyCriticalEnv(e string) bool {
	for _, k := range []string{"ASAN_OPTIONS=", "UBSAN_OPTIONS=", "LSAN_OPTIONS=", "MSAN_OPTIONS=", "TSAN_OPTIONS=", "LD_PRELOAD=", "DYLD_INSERT_LIBRARIES="} {
		if strings.HasPrefix(e, k) {
			return true
		}
	}
	return false
}

// cappedBuffer drops only the middle: sanitizer reports arrive at end-of-run, so the tail must survive.
type cappedBuffer struct {
	head  bytes.Buffer
	tail  []byte
	limit int
	total int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	c.total += n
	headLimit := c.limit / 2
	if c.head.Len() < headLimit {
		room := headLimit - c.head.Len()
		if room >= len(p) {
			c.head.Write(p)
			return n, nil
		}
		c.head.Write(p[:room])
		p = p[room:]
	}
	tailLimit := c.limit - headLimit
	c.tail = append(c.tail, p...)
	if len(c.tail) > tailLimit {
		c.tail = c.tail[len(c.tail)-tailLimit:]
	}
	return n, nil
}

func (c *cappedBuffer) String() string {
	if c.head.Len()+len(c.tail) >= c.total {
		return c.head.String() + string(c.tail)
	}
	return c.head.String() + "\n…[output truncated]…\n" + string(c.tail)
}

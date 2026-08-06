package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

// ServiceSpec addresses an already-running endpoint (Addr) or launches one the runner owns (Launch).
type ServiceSpec struct {
	Proto     string   // "tcp" | "udp" | "unix"; empty → tcp
	Addr      string   // host:port, or socket path for unix
	Launch    []string // runner owns this process's lifecycle
	ReadLimit int      // 0 → maxOutputBytes
}

func (s ServiceSpec) proto() string {
	if s.Proto == "" {
		return "tcp"
	}
	return s.Proto
}

func (s ServiceSpec) readLimit() int {
	if s.ReadLimit > 0 {
		return s.ReadLimit
	}
	return maxOutputBytes
}

// ServiceRunner drives a live target behind a socket, recording one connection's observation.
type ServiceRunner struct{}

func (ServiceRunner) Run(ctx context.Context, spec RunSpec) (oracle.RunResult, error) {
	svc := spec.Service
	if svc == nil {
		return oracle.RunResult{}, errors.New("runner: ServiceRunner needs a Service spec")
	}
	if svc.Addr == "" && len(svc.Launch) == 0 {
		return oracle.RunResult{}, errors.New("runner: ServiceRunner needs a service address or launch command")
	}

	timeout := spec.timeout()

	// take the address BEFORE the clock starts: queueing must not be charged to this PoV
	if len(svc.Launch) > 0 {
		release, err := acquireServiceSlot(ctx, svc.proto()+"|"+svc.Addr)
		if err != nil {
			return oracle.RunResult{}, fmt.Errorf("runner: waiting for exclusive use of service %s: %w", svc.Addr, err)
		}
		defer release()
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// deferred AFTER the slot release so LIFO frees the port before the next PoV is admitted
	var proc *managedService
	if len(svc.Launch) > 0 {
		p, err := launchService(runCtx, spec)
		if err != nil {
			return oracle.RunResult{}, err
		}
		proc = p
		defer proc.stop()
	}

	conn, err := dialService(runCtx, svc.proto(), svc.Addr, timeout, proc)
	if err != nil {
		if proc != nil {
			// our own listener's bind failure is infra, never the target's answer to this PoV
			return oracle.RunResult{}, fmt.Errorf("runner: service did not accept a connection: %w", err)
		}
		// an external endpoint being down IS an observation: exit -1 for the oracle to judge
		rr := oracle.RunResult{ExitCode: -1, Stderr: err.Error()}
		applyTaint(&rr, spec)
		return rr, nil
	}

	respBuf := &cappedBuffer{limit: svc.readLimit()}
	start := time.Now()
	timedOut := exchange(conn, spec.PoV, timeout, respBuf, svc.readLimit())
	dur := time.Since(start)

	rr := oracle.RunResult{
		Stdout:   respBuf.String(),
		Duration: dur,
		TimedOut: timedOut,
	}

	if proc != nil {
		sig, exit, alive := proc.reap(timeout)
		// only read buffers once reaped: reading a live service races os/exec's copy goroutines (log-flush jitter → false divergence).
		if !alive {
			rr.TermSignal, rr.ExitCode = sig, exit
			rr.Stderr = proc.stderr.String()
			if procOut := proc.stdout.String(); procOut != "" {
				if rr.Stdout != "" {
					rr.Stdout += "\n"
				}
				rr.Stdout += procOut
			}
			rr.Sanitizer = ParseSanitizer("", rr.Stderr)
			rr.Sanitizer = corroborateSanitizer(rr)
		}
	}

	applyTaint(&rr, spec)
	return rr, nil
}

var (
	serviceSlotsMu sync.Mutex
	serviceSlots   = map[string]chan struct{}{}
)

// serialize per-address use: unserialized, one PoV reaches another's process or records that PoV's bind failure as its own exit status (vault: Runner).
func acquireServiceSlot(ctx context.Context, key string) (func(), error) {
	serviceSlotsMu.Lock()
	slot, ok := serviceSlots[key]
	if !ok {
		slot = make(chan struct{}, 1)
		serviceSlots[key] = slot
	}
	serviceSlotsMu.Unlock()

	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// retries only for a listener we just launched (needs a moment to bind); an external endpoint is dialed once.
func dialService(ctx context.Context, proto, addr string, timeout time.Duration, proc *managedService) (net.Conn, error) {
	if addr == "" {
		return nil, errors.New("runner: empty service address")
	}
	d := net.Dialer{Timeout: timeout}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := d.DialContext(ctx, proto, addr)
		if err == nil {
			// our listener already exited ⇒ another process owns the address; the PoV would reach one whose wait status we never observe.
			if proc != nil && proc.dead() {
				_ = conn.Close()
				return nil, fmt.Errorf("the launched listener exited before accepting, so another process owns %s: %s", addr, truncateStr(proc.stderr.String(), 200))
			}
			return conn, nil
		}
		lastErr = err
		if proc == nil || time.Now().After(deadline) || ctx.Err() != nil {
			return nil, lastErr
		}
		if proc.dead() {
			return nil, fmt.Errorf("the launched listener exited before accepting: %s", truncateStr(proc.stderr.String(), 200))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// implemented by TCP and Unix stream conns, not UDP
type closeWriter interface{ CloseWrite() error }

// reports a silent hang: the deadline hit with no bytes received at all
func exchange(conn net.Conn, pov []byte, timeout time.Duration, out *cappedBuffer, limit int) (timedOut bool) {
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	_ = conn.SetWriteDeadline(deadline)
	if len(pov) > 0 {
		_, _ = conn.Write(pov)
	}
	// half-close so a read-until-EOF server sees the end of the request and replies
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}

	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 32*1024)
	got := 0
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
			got += n
			if got >= limit {
				break
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && got == 0 {
				return true
			}
			break
		}
	}
	return false
}

type managedService struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdout *cappedBuffer
	stderr *cappedBuffer
	done   chan error
	waited error
	exited bool
}

func launchService(ctx context.Context, spec RunSpec) (*managedService, error) {
	argv := spec.Service.Launch
	// lifetime detached from the per-PoV deadline: reaping OUR SIGKILL as the target's signal would fabricate a crash.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	cmd := exec.CommandContext(lifetime, argv[0], argv[1:]...)
	if spec.Workdir != "" {
		cmd.Dir = spec.Workdir
	}
	// untrusted target: never inherit the operator env (proxy key, QUARRY_* secrets)
	cmd.Env = localChildEnv(spec)
	so := &cappedBuffer{limit: maxOutputBytes}
	se := &cappedBuffer{limit: maxOutputBytes}
	cmd.Stdout = so
	cmd.Stderr = se
	applyNetIsolation(cmd, spec.IsolateNetwork)
	cmd.WaitDelay = waitDrainGrace
	applyProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("runner: launch service: %w", err)
	}
	m := &managedService{cmd: cmd, cancel: cancel, stdout: so, stderr: se, done: make(chan error, 1)}
	go func() { m.done <- cmd.Wait() }()
	return m, nil
}

// caches the wait status: m.done may be read once, and the dial-time poll and the reap must agree
func (m *managedService) waitFor(d time.Duration) bool {
	if m.exited {
		return true
	}
	if d <= 0 {
		select {
		case err := <-m.done:
			m.exited, m.waited = true, err
		default:
		}
		return m.exited
	}
	select {
	case err := <-m.done:
		m.exited, m.waited = true, err
	case <-time.After(d):
	}
	return m.exited
}

// true ⇒ cmd.Wait has returned, so the output buffers are safe to read
func (m *managedService) dead() bool { return m.waitFor(0) }

// alive=true ⇒ still running (no crash); the grace is bounded so a healthy service does not stall
func (m *managedService) reap(timeout time.Duration) (sig, exit int, alive bool) {
	grace := min(timeout, 1500*time.Millisecond)
	if !m.waitFor(grace) {
		return 0, 0, true
	}
	s, e := waitStatus(m.waited)
	return s, e, false
}

// everything from here on is our teardown, never the target's behavior
func (m *managedService) stop() {
	if m == nil || m.cmd == nil {
		return
	}
	if m.cancel != nil {
		m.cancel() // kills the whole process group
	}
	if !m.exited && m.cmd.Process != nil {
		select {
		case err := <-m.done:
			m.exited, m.waited = true, err
		case <-time.After(2 * time.Second):
		}
	}
	// a wrapper that started the server without `exec` would otherwise leak the port-holding process into the next PoV.
	reapProcessGroup(m.cmd)
}

// a fault signal wins; a clean/known exit yields its code; anything else is exit -1
func waitStatus(err error) (sig, exit int) {
	if err == nil {
		return 0, 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if s := signalOf(exitErr); s != 0 {
			return s, 0
		}
		return 0, exitErr.ExitCode()
	}
	return 0, -1
}

var _ Runner = ServiceRunner{}

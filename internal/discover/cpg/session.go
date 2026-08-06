package cpg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	sessionStartTimeout = 90 * time.Second
	sessionQueryTimeout = 90 * time.Second
)

var errSessionDead = errors.New("cpg: joern session is closed")

// Session is a warm Joern REPL bound to one CPG; a failed query kills it.
type Session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	workDir string

	mu   sync.Mutex
	seq  int
	dead bool
}

func StartSession(ctx context.Context, cpgPath, joernBin string) (*Session, error) {
	cmd := exec.Command(resolveBin(joernBin, "joern"), "--nocolors")
	workDir, err := os.MkdirTemp("", "quarry-joern-sess-*")
	if err != nil {
		return nil, fmt.Errorf("cpg: session scratch dir: %w", err)
	}
	cmd.Dir = workDir // an empty Dir is the caller's CWD, where joern would write ./workspace/
	// until the Session exists, killLocked cannot reclaim workDir
	started := false
	defer func() {
		if !started {
			_ = os.RemoveAll(workDir)
		}
	}()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cpg: start joern REPL: %w", err)
	}
	started = true
	s := &Session{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<20), workDir: workDir}
	// readiness needs POSITIVE evidence: a failed importCpg still prints the sentinel
	body := `importCpg("` + escapeScala(cpgPath) + `")` + "\n" +
		`println("RESULT cpg_methods=" + cpg.method.size)`
	out, err := s.query(ctx, body, sessionStartTimeout)
	if err != nil {
		s.kill()
		return nil, fmt.Errorf("cpg: importCpg failed: %w", err)
	}
	m, err := requireResults(out, "cpg_methods")
	if err != nil {
		s.kill()
		return nil, fmt.Errorf("cpg: importCpg(%s) did not load a queryable graph: %w", cpgPath, err)
	}
	if n := atoi(m["cpg_methods"]); n <= 0 {
		s.kill()
		return nil, fmt.Errorf("cpg: importCpg(%s) loaded a graph with 0 methods — it can answer no query, and every empty answer would read as 'nothing reachable'", cpgPath)
	}
	return s, nil
}

func (s *Session) Query(ctx context.Context, body string) (string, error) {
	return s.query(ctx, body, sessionQueryTimeout)
}

func (s *Session) query(ctx context.Context, body string, timeout time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return "", errSessionDead
	}
	s.seq++
	sentinel := fmt.Sprintf("__QUARRY_END_%d__", s.seq)
	if _, err := io.WriteString(s.stdin, body+"\nprintln(\""+sentinel+"\")\n"); err != nil {
		s.killLocked()
		return "", err
	}

	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := s.stdout.ReadString('\n')
			if strings.Contains(line, sentinel) {
				ch <- result{b.String(), nil}
				return
			}
			b.WriteString(line)
			if err != nil {
				ch <- result{b.String(), err}
				return
			}
		}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			s.killLocked()
			return r.out, fmt.Errorf("cpg: session read ended: %w", r.err)
		}
		return r.out, nil
	case <-ctx.Done():
		s.killLocked()
		return "", ctx.Err()
	case <-time.After(timeout):
		s.killLocked()
		return "", fmt.Errorf("cpg: query timed out after %s", timeout)
	}
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killLocked()
	return nil
}

func (s *Session) kill() { s.mu.Lock(); s.killLocked(); s.mu.Unlock() }

func (s *Session) killLocked() {
	if s.dead {
		return
	}
	s.dead = true
	_ = s.stdin.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	wd := s.workDir
	go func() {
		_ = s.cmd.Wait()
		if wd != "" {
			_ = os.RemoveAll(wd)
		}
	}()
}

//go:build unix

package runner

import (
	"os/exec"
	"sync/atomic"
	"syscall"
)

// Group id is the child's pid (never signals quarry's group); the predicate reports whether teardown killed a still-running child (vault: Runner).
func applyProcessGroup(cmd *exec.Cmd) func() bool {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	var killedLive atomic.Bool
	if cmd.Cancel == nil {
		return killedLive.Load // not context-bound: teardown goes through reapProcessGroup
	}
	cmd.Cancel = func() error {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		// kill the leader LAST: os.ErrProcessDone separates a real hang from a leftover background child holding the pipes.
		err := cmd.Process.Kill()
		if err == nil {
			killedLive.Store(true)
		}
		return err
	}
	return killedLive.Load
}

// only safe once the child is reaped: the group id is its pid, so this reaches only descendants
func reapProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

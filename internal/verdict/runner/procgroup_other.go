//go:build !unix

package runner

import (
	"os/exec"
	"sync/atomic"
)

// process groups are Unix-only: off Unix only the killed-a-live-child predicate is wired
func applyProcessGroup(cmd *exec.Cmd) func() bool {
	var killedLive atomic.Bool
	if cmd.Cancel == nil {
		return killedLive.Load
	}
	cmd.Cancel = func() error {
		err := cmd.Process.Kill()
		if err == nil {
			killedLive.Store(true)
		}
		return err
	}
	return killedLive.Load
}

func reapProcessGroup(_ *exec.Cmd) {}

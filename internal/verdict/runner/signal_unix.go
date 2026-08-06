//go:build unix

package runner

import (
	"os/exec"
	"syscall"
)

func signalOf(e *exec.ExitError) int {
	if ws, ok := e.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return int(ws.Signal())
	}
	return 0
}

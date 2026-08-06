//go:build linux

package runner

import (
	"os/exec"
	"syscall"
)

// needs CAP_SYS_ADMIN; the exec fails loudly rather than running the target with network
func applyNetIsolation(cmd *exec.Cmd, isolate bool) {
	if !isolate {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
}

//go:build !linux

package runner

import "os/exec"

// no-op: network namespaces are Linux-only
func applyNetIsolation(_ *exec.Cmd, _ bool) {}

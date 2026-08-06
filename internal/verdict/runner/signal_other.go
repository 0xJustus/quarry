//go:build !unix

package runner

import "os/exec"

// no-op off Unix; DockerRunner derives the signal from the exit code
func signalOf(_ *exec.ExitError) int { return 0 }

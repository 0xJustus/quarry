// Runs the target and records its true wait status, nonce-authenticated.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// the shim's own failures; keep in sync with runner/docker.go (125-127 read as infra)
const (
	exitUsage       = 2
	exitSpawnFailed = 126
	exitNoStatus    = 125
)

const (
	statusEnv = "QUARRY_STATUS"
	nonceEnv  = "QUARRY_STATUS_NONCE"
)

func main() { os.Exit(shim(os.Args)) }

func shim(argv []string) int {
	if len(argv) < 2 {
		fmt.Fprintln(os.Stderr, "quarry-shim: usage: quarry-shim <target> [args...]")
		return exitUsage
	}
	statusPath, nonce := os.Getenv(statusEnv), os.Getenv(nonceEnv)

	cmd := exec.Command(argv[1], argv[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// the target must never learn the status channel: it could forge "signal:11"
	cmd.Env = scrubStatusEnv(os.Environ())
	runErr := cmd.Run()

	status, code := "exit:0", 0
	if cmd.ProcessState != nil {
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				status, code = fmt.Sprintf("signal:%d", int(ws.Signal())), 128+int(ws.Signal())
			} else {
				status, code = fmt.Sprintf("exit:%d", ws.ExitStatus()), ws.ExitStatus()
			}
		}
	} else if runErr != nil {
		fmt.Fprintf(os.Stderr, "quarry-shim: %v\n", runErr)
		return exitSpawnFailed
	}

	if err := writeStatus(statusPath, nonce, status); err != nil {
		// fail loudly: a dropped status demotes the runner to forgeable exit(128+N)
		fmt.Fprintf(os.Stderr, "quarry-shim: could not record wait status (%s): %v\n", status, err)
		return exitNoStatus
	}
	return code
}

// wire format "<nonce> <status>"; parsed by runner.readShimStatus
func writeStatus(path, nonce, status string) error {
	if path == "" {
		return errors.New("no " + statusEnv + " in the environment")
	}
	if nonce == "" {
		return errors.New("no " + nonceEnv + " in the environment")
	}
	return os.WriteFile(path, []byte(nonce+" "+status), 0o644)
}

func scrubStatusEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, statusEnv+"=") || strings.HasPrefix(e, nonceEnv+"=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

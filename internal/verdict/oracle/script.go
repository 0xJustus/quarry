package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ScriptCheck runs Path with Args, the RunResult as JSON on stdin; exit 0 is a pass.
type ScriptCheck struct {
	Path    string
	Args    []string
	Timeout time.Duration // 0 ⇒ scriptDefaultTimeout
}

const scriptDefaultTimeout = 5 * time.Second

// off by default: an unregistered name is inert, so no unvetted binary can run
var (
	scriptMu        sync.RWMutex
	scriptAllowlist = map[string]ScriptCheck{}
)

func RegisterScriptCheck(name string, chk ScriptCheck) error {
	if name == "" {
		return fmt.Errorf("oracle: script check needs a non-empty name")
	}
	if !filepath.IsAbs(chk.Path) {
		return fmt.Errorf("oracle: script check %q path must be absolute, got %q", name, chk.Path)
	}
	scriptMu.Lock()
	defer scriptMu.Unlock()
	scriptAllowlist[name] = chk
	return nil
}

func UnregisterScriptCheck(name string) {
	scriptMu.Lock()
	defer scriptMu.Unlock()
	delete(scriptAllowlist, name)
}

func lookupScriptCheck(name string) (ScriptCheck, bool) {
	scriptMu.RLock()
	defer scriptMu.RUnlock()
	chk, ok := scriptAllowlist[name]
	return chk, ok
}

func (c Condition) evalScript(r RunResult) (bool, string) {
	chk, ok := lookupScriptCheck(c.Script)
	if !ok {
		return false, fmt.Sprintf("script check %q not in allowlist (disabled)", c.Script)
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return false, "script check: marshal run result: " + err.Error()
	}
	to := chk.Timeout
	if to <= 0 {
		to = scriptDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()

	cmd := exec.CommandContext(ctx, chk.Path, chk.Args...)
	cmd.Stdin = bytes.NewReader(payload)
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Sprintf("script check %q timed out after %s", c.Script, to)
	}
	if err == nil {
		return true, fmt.Sprintf("script check %q passed (exit 0)", c.Script)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, fmt.Sprintf("script check %q failed (exit %d)", c.Script, exitErr.ExitCode())
	}
	return false, fmt.Sprintf("script check %q could not run: %v", c.Script, err)
}

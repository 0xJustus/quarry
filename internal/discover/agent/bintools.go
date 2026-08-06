package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/envscrub"
)

const (
	binToolTimeout = 20 * time.Second
	binMaxOutput   = 64 * 1024
)

func binTools(s *Session) []Tool {
	if s.BinaryPath == "" {
		return nil
	}
	return []Tool{&binInfoTool{s}, &binStringsTool{s}, &binSymbolsTool{s}, &binDisasmTool{s}}
}

// keeps at most max bytes; reports full writes so the child never sees EPIPE
type capBuf struct {
	buf  bytes.Buffer
	max  int
	full bool
}

func (w *capBuf) Write(p []byte) (int, error) {
	if r := w.max - w.buf.Len(); r > 0 {
		if len(p) <= r {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:r])
			w.full = true
		}
	} else if len(p) > 0 {
		w.full = true
	}
	return len(p), nil
}

func (w *capBuf) String() string {
	if w.full {
		return w.buf.String() + "\n…[truncated]…"
	}
	return w.buf.String()
}

type toolOut struct {
	stdout   string
	stderr   string
	exit     int
	found    bool // false ONLY when the program could not be started
	timedOut bool
}

func (r toolOut) text() string {
	if strings.TrimSpace(r.stdout) != "" {
		return r.stdout
	}
	return r.stderr
}

// a killed run observed nothing: never report its silence as a fact about the binary
func timeoutUnknown(tool string) string {
	return fmt.Sprintf("%s did not finish within %s and was KILLED by the timeout — the result is UNKNOWN, "+
		"not a fact about the binary (do NOT conclude it has none)", tool, binToolTimeout)
}

func partialCapture(tool, out string) string {
	return "[INCOMPLETE] " + timeoutUnknown(tool) + ". The capture below is PARTIAL:\n" + out
}

// host os/exec, not Workspace.Exec: a sandbox mounts only the workspace, not the target
func hostRun(ctx context.Context, name string, args ...string) toolOut {
	runCtx, cancel := context.WithTimeout(ctx, binToolTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Env = envscrub.Environ()
	// cap as bytes ARRIVE: objdump can emit GBs inside the timeout window
	stdout := &capBuf{max: binMaxOutput}
	stderr := &capBuf{max: binMaxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	res := toolOut{
		stdout: stdout.String(),
		stderr: stderr.String(),
		found:  true,
	}
	// must precede the ExitError branch: cmd.Run reports the SIGKILL as an ordinary exit
	if runCtx.Err() == context.DeadlineExceeded {
		res.timedOut = true
		res.exit = -1
		if strings.TrimSpace(res.stderr) == "" {
			res.stderr = fmt.Sprintf("%s: killed after %s (timeout)", name, binToolTimeout)
		}
		return res
	}
	if err == nil {
		return res
	}
	if errors.Is(err, exec.ErrNotFound) {
		res.found = false
		return res
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.exit = exitErr.ExitCode()
		return res
	}
	res.exit = -1
	if strings.TrimSpace(res.stderr) == "" {
		res.stderr = err.Error()
	}
	return res
}

type binInfoTool struct{ s *Session }

func (binInfoTool) Name() string { return "bin_info" }
func (binInfoTool) Description() string {
	return "Identify the target binary (`file`): format, architecture, bitness, stripped/PIE, plus its section headers (best-effort readelf/objdump/otool). READ-ONLY recon to orient before crafting inputs — a lead, not a verdict."
}
func (binInfoTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t *binInfoTool) Invoke(ctx context.Context, _ json.RawMessage) (string, error) {
	bin := t.s.BinaryPath
	var b strings.Builder
	if r := hostRun(ctx, "file", bin); r.found {
		if r.timedOut {
			b.WriteString(timeoutUnknown("file"))
		} else {
			b.WriteString(strings.TrimRight(r.text(), "\n"))
		}
	} else {
		b.WriteString("(file: tool not available on this host)")
	}
	b.WriteString("\n\n--- section headers ---\n")
	got := false
	for _, c := range [][]string{{"readelf", "-S", bin}, {"objdump", "-h", bin}, {"otool", "-l", bin}} {
		if r := hostRun(ctx, c[0], c[1:]...); r.found {
			if r.timedOut {
				b.WriteString(partialCapture(c[0], strings.TrimRight(r.stdout, "\n")))
			} else {
				b.WriteString(strings.TrimRight(r.text(), "\n"))
			}
			got = true
			break
		}
	}
	if !got {
		b.WriteString("(no section-header tool available: tried readelf, objdump, otool)")
	}
	return capString(b.String(), binMaxOutput), nil
}

type binStringsTool struct{ s *Session }

func (binStringsTool) Name() string { return "bin_strings" }
func (binStringsTool) Description() string {
	return "List the printable strings in the target binary (strings -a -n 6): format tags, error messages, paths, and magic bytes that hint at the input grammar and interesting code paths. READ-ONLY recon; output is capped. Every hit is a lead, not a verdict."
}
func (binStringsTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t *binStringsTool) Invoke(ctx context.Context, _ json.RawMessage) (string, error) {
	r := hostRun(ctx, "strings", "-a", "-n", "6", t.s.BinaryPath)
	if !r.found {
		return "strings not available on this host — cannot extract printable strings.", nil
	}
	out := strings.TrimRight(r.text(), "\n")
	// must precede the empty-output branch: killed is UNKNOWN, never "no strings"
	if r.timedOut {
		if strings.TrimSpace(r.stdout) == "" {
			return timeoutUnknown("strings") + ". Retry on a smaller region, or use bin_info / bin_disasm.", nil
		}
		return capString(partialCapture("strings", strings.TrimRight(r.stdout, "\n")), binMaxOutput), nil
	}
	if strings.TrimSpace(out) == "" {
		return "no printable strings found (strings exit=" + fmt.Sprint(r.exit) + ").", nil
	}
	return capString(out, binMaxOutput), nil
}

type binSymbolsTool struct{ s *Session }

func (binSymbolsTool) Name() string { return "bin_symbols" }
func (binSymbolsTool) Description() string {
	return "List the symbol table of the target binary (nm; falls back to dynamic symbols nm -D). Names the functions/globals to aim bin_disasm at. Reports 'stripped' gracefully when no symbols survive. READ-ONLY recon — a lead, not a verdict."
}
func (binSymbolsTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t *binSymbolsTool) Invoke(ctx context.Context, _ json.RawMessage) (string, error) {
	bin := t.s.BinaryPath
	r := hostRun(ctx, "nm", bin)
	if !r.found {
		return "nm not available on this host — cannot list symbols (try bin_strings / bin_disasm).", nil
	}
	if r.exit == 0 && strings.TrimSpace(r.stdout) != "" {
		return capString(r.stdout, binMaxOutput), nil
	}
	// must precede the stripped fallback: a killed nm is UNKNOWN, never "stripped"
	if r.timedOut {
		if strings.TrimSpace(r.stdout) == "" {
			return timeoutUnknown("nm") + ". Proceed with bin_strings / bin_disasm, but treat the symbol table as UNDETERMINED.", nil
		}
		return capString(partialCapture("nm", r.stdout), binMaxOutput), nil
	}
	rd := hostRun(ctx, "nm", "-D", bin)
	if rd.found && rd.exit == 0 && strings.TrimSpace(rd.stdout) != "" {
		return "static symbols unavailable (binary likely stripped); dynamic symbols (nm -D):\n" + capString(rd.stdout, binMaxOutput), nil
	}
	if rd.timedOut {
		if strings.TrimSpace(rd.stdout) == "" {
			return timeoutUnknown("nm -D") + ". Proceed with bin_strings / bin_disasm, but treat the symbol table as UNDETERMINED.", nil
		}
		return capString(partialCapture("nm -D", rd.stdout), binMaxOutput), nil
	}
	diag := strings.TrimSpace(firstLine(strings.TrimLeft(r.stderr, "\n")))
	if diag == "" {
		diag = strings.TrimSpace(firstLine(strings.TrimLeft(rd.stderr, "\n")))
	}
	msg := "no symbols — the binary appears stripped"
	if diag != "" {
		msg += " (nm: " + diag + ")"
	}
	return msg + ". Use bin_strings and bin_disasm instead.", nil
}

type binDisasmTool struct{ s *Session }

func (binDisasmTool) Name() string { return "bin_disasm" }
func (binDisasmTool) Description() string {
	return "Disassemble the target binary, optionally scoped to a single {symbol}. Tries objdump -d, then llvm-objdump -d, then otool -tV (macOS); returns a clear message if none is installed. Read the machine code around a suspected sink to see what an input must satisfy. READ-ONLY recon; output is capped — a lead, not a verdict."
}
func (binDisasmTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"symbol":{"type":"string","description":"optional function/symbol name to scope the disassembly to (bare identifier)"}}}`)
}
func (t *binDisasmTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	sym := fnArg(args, "symbol")["symbol"]
	bin := t.s.BinaryPath

	// the first INSTALLED disassembler wins
	type cand struct {
		name         string
		scoped       []string
		plain        []string
		scopeCapable bool
	}
	cands := []cand{
		{"objdump", []string{"-d", "--disassemble=" + sym, bin}, []string{"-d", bin}, true},
		{"llvm-objdump", []string{"-d", "--disassemble-symbols=" + sym, bin}, []string{"-d", bin}, true},
		{"otool", []string{"-tV", "-p", sym, bin}, []string{"-tV", bin}, true},
	}
	for _, c := range cands {
		useScoped := sym != "" && c.scopeCapable
		argv := c.plain
		if useScoped {
			argv = c.scoped
		}
		r := hostRun(ctx, c.name, argv...)
		if !r.found {
			continue
		}
		note := ""
		// a timeout is NOT unsupported scoping: retrying unscoped only gets killed again
		if useScoped && !r.timedOut && (r.exit != 0 || strings.TrimSpace(r.stdout) == "") {
			r = hostRun(ctx, c.name, c.plain...)
			note = "(symbol scoping unavailable via " + c.name + " or symbol not found — showing full disassembly, capped)\n"
		}
		if r.timedOut {
			if strings.TrimSpace(r.stdout) == "" {
				return timeoutUnknown(c.name) + ". Scope the request to a single symbol (bin_disasm with `symbol`) so it can finish.", nil
			}
			return capString(partialCapture(c.name, strings.TrimRight(r.stdout, "\n")), binMaxOutput), nil
		}
		out := strings.TrimRight(r.text(), "\n")
		if strings.TrimSpace(out) == "" {
			return c.name + ": produced no disassembly (exit=" + fmt.Sprint(r.exit) + ").", nil
		}
		header := "disassembly (" + c.name + ")"
		if sym != "" && note == "" {
			header += " of " + sym
		}
		return capString(header+":\n"+note+out, binMaxOutput), nil
	}
	return "no disassembler available (tried objdump, llvm-objdump, otool). Install one for bin_disasm; bin_info/bin_strings/bin_symbols may still help.", nil
}

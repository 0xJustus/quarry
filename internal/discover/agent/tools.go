package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/verdict/verify"
)

type Tool interface {
	Name() string
	Description() string
	Schema() json.RawMessage
	Invoke(ctx context.Context, args json.RawMessage) (string, error)
}

// run_pov is the only tool on the belt that reaches a verdict
func Belt(s *Session) []Tool {
	belt := []Tool{
		&editTool{s},
		&readTool{s},
		&lsTool{s},
		&execTool{s},
		&runGeneratorTool{s},
		&runPoVTool{s},
		&spawnTool{s},
	}
	if s.CodeNav != nil {
		belt = append(belt, &callersTool{s}, &calleesTool{s}, &functionTool{s})
	}
	// fail closed: never offer a tool that would overwrite a declared oracle (vault: Agent Tool Belt)
	if s.Base.Image != "" && s.Oracle.Differential == nil && s.Fixed == nil {
		belt = append(belt, &proposeReferenceTool{s: s})
		if s.TargetSource != "" {
			belt = append(belt, &differentialFuzzTool{s})
		}
	}
	belt = append(belt, cpgTools(s)...)
	belt = append(belt, binTools(s)...)
	return belt
}

type CodeNavigator interface {
	Callers(name string) []string
	Callees(name string) []string
	Function(name string) string
}

type spawnTool struct{ s *Session }

func (spawnTool) Name() string { return "spawn_hypothesis" }
func (spawnTool) Description() string {
	return "Propose a narrower SUB-HYPOTHESIS to investigate as a child line when the current approach is stuck (e.g. 'the overflow is reachable via the length field, not the count field'). The supervisor dispatches it as a child; you keep working. Use sparingly — a focused, testable sub-claim, not a restatement."
}
func (spawnTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"statement":{"type":"string","description":"the sub-hypothesis to investigate"}},"required":["statement"]}`)
}
func (t *spawnTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	var a struct {
		Statement string `json:"statement"`
	}
	_ = json.Unmarshal(args, &a)
	a.Statement = strings.TrimSpace(a.Statement)
	if a.Statement == "" {
		return "", fmt.Errorf("spawn_hypothesis: statement is required")
	}
	const maxSpawn = 4
	if len(t.s.Spawned) >= maxSpawn {
		return fmt.Sprintf("spawn limit (%d) reached — keep working the current line", maxSpawn), nil
	}
	t.s.Spawned = append(t.s.Spawned, a.Statement)
	return "sub-hypothesis queued for the supervisor: " + a.Statement, nil
}

func ToolDefs(tools []Tool) []model.ToolDef {
	defs := make([]model.ToolDef, 0, len(tools))
	for _, t := range tools {
		defs = append(defs, model.ToolDef{Name: t.Name(), Description: t.Description(), Parameters: t.Schema()})
	}
	return defs
}

type editTool struct{ s *Session }

func (editTool) Name() string { return "edit" }
func (editTool) Description() string {
	return "Write a file in the workspace (creating or overwriting it). Use for harnesses, PoV scripts, and build files."
}
func (editTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"workspace-relative path"},"content":{"type":"string","description":"full file contents"}},"required":["path","content"]}`)
}
func (t *editTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	var a struct{ Path, Content string }
	if err := json.Unmarshal(args, &a); err != nil {
		return "", err
	}
	if a.Path == "" {
		return "", fmt.Errorf("edit: path is required")
	}
	if err := t.s.Workspace.WriteFile(a.Path, a.Content); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d bytes to %s", len(a.Content), a.Path), nil
}

type readTool struct{ s *Session }

// cap here, not in Workspace.ReadFile: run_pov needs untruncated PoV bytes
const readMaxBytes = 64 * 1024

func (readTool) Name() string { return "read_file" }
func (readTool) Description() string {
	return "Read a file from the workspace. Large files are truncated (read a specific range with exec instead)."
}
func (readTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)
}
func (t *readTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	var a struct{ Path string }
	if err := json.Unmarshal(args, &a); err != nil {
		return "", err
	}
	content, err := t.s.Workspace.ReadFile(a.Path)
	if err != nil {
		return "", err
	}
	max := readMaxBytes
	if t.s.Workspace.MaxOutput > 0 {
		max = t.s.Workspace.MaxOutput
	}
	if len(content) > max {
		return content[:max] + fmt.Sprintf("\n…[truncated: %s is %d bytes, showing the first %d. Read a specific range with exec (e.g. sed -n '1,200p' %s) or process the file with a script instead of reading it whole]…",
			a.Path, len(content), max, a.Path), nil
	}
	return content, nil
}

type lsTool struct{ s *Session }

func (lsTool) Name() string        { return "ls" }
func (lsTool) Description() string { return "List files under a workspace directory (default root)." }
func (lsTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"directory (default '.')"}}}`)
}
func (t *lsTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	var a struct{ Path string }
	_ = json.Unmarshal(args, &a)
	if a.Path == "" {
		a.Path = "."
	}
	names, err := t.s.Workspace.List(a.Path)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "(empty)", nil
	}
	return strings.Join(names, "\n"), nil
}

type execTool struct{ s *Session }

func (execTool) Name() string { return "exec" }
func (execTool) Description() string {
	return "Run a command in the workspace (compile, inspect, run helper scripts). This is NOT the oracle — it does not decide success. Output is capped. Container/image tooling (docker, podman, buildah, …) and privilege escalation (sudo, su) are refused, and the authoritative target itself is not writable."
}
func (execTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cmd":{"type":"string","description":"program to run"},"args":{"type":"array","items":{"type":"string"}},"stdin":{"type":"string"},"timeout_s":{"type":"integer","description":"per-call timeout seconds"}},"required":["cmd"]}`)
}
func (t *execTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	// lenient decode: models emit schema-imperfect types
	var a struct {
		Cmd      string          `json:"cmd"`
		Args     json.RawMessage `json:"args"`
		Stdin    string          `json:"stdin"`
		TimeoutS json.RawMessage `json:"timeout_s"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "", fmt.Errorf("exec: bad arguments %s: %w", truncateArgs(args), err)
	}
	if a.Cmd == "" {
		return "", fmt.Errorf("exec: cmd is required")
	}
	argv := coerceStringSlice(a.Args)
	if err := guardExec(t.s, a.Cmd, argv); err != nil {
		return "", err
	}
	res, err := t.s.Workspace.Exec(ctx, a.Cmd, argv, a.Stdin, time.Duration(coerceInt(a.TimeoutS))*time.Second)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "exit=%d", res.ExitCode)
	if res.TimedOut {
		b.WriteString(" (timed out)")
	}
	if res.Stdout != "" {
		fmt.Fprintf(&b, "\n--- stdout ---\n%s", res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprintf(&b, "\n--- stderr ---\n%s", res.Stderr)
	}
	return b.String(), nil
}

// these could rebuild or retag the target the oracle judges (vault: Agent Tool Belt)
var execDeniedPrograms = map[string]bool{
	"docker": true, "docker-compose": true, "dockerd": true, "podman": true, "podman-compose": true,
	"nerdctl": true, "ctr": true, "crictl": true, "buildah": true, "buildkitd": true, "buildctl": true,
	"skopeo": true, "crane": true, "regctl": true, "oras": true, "kaniko": true,
	"kubectl": true, "helm": true, "lima": true, "colima": true, "minikube": true,
	"sudo": true, "doas": true, "su": true,
}

// fail closed: refuse every argv that could tamper with what the oracle judges
func guardExec(s *Session, cmd string, argv []string) error {
	words := make([]string, 0, len(argv)+1)
	words = append(append(words, cmd), argv...)
	var root string
	if s.Workspace != nil {
		root = s.Workspace.Root
	}
	// refuse on the name: guessing which argv words are write targets fails open
	target := ""
	if bin := strings.TrimSpace(s.Base.Binary); bin != "" {
		if abs, err := filepath.Abs(bin); err == nil {
			target = abs
		}
	}
	for _, w := range words {
		for _, tok := range shellTokens(w) {
			if execDeniedPrograms[strings.ToLower(filepath.Base(tok))] {
				return fmt.Errorf("exec: refusing %q — container/image and privilege tooling is not available to the agent: "+
					"the target the oracle judges must stay exactly as the operator built it, and exec is not the oracle. "+
					"Build, run and inspect your own programs in the workspace instead", tok)
			}
			if target != "" && resolveExecPath(root, tok) == target {
				return fmt.Errorf("exec: refusing an argv that names the authoritative target binary (%s) — "+
					"it must stay exactly as the operator built it; work on copies inside the workspace", target)
			}
		}
	}
	return nil
}

// tokens a shell would see: a denied program hidden in `sh -c "…"` must still be caught
func shellTokens(word string) []string {
	return strings.FieldsFunc(word, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '<', '>', '"', '\'', '`', '=', ',':
			return true
		}
		return false
	})
}

// resolve as the child would: relative words against the workspace root (exec's cwd)
func resolveExecPath(root, tok string) string {
	if tok == "" {
		return ""
	}
	if filepath.IsAbs(tok) {
		return filepath.Clean(tok)
	}
	if root == "" {
		return ""
	}
	abs, err := filepath.Abs(filepath.Join(root, tok))
	if err != nil {
		return ""
	}
	return abs
}

const (
	genDefaultCount = 24
	genMaxVariants  = 64
	genMaxInputSize = 1 << 20
)

type runGeneratorTool struct{ s *Session }

func (runGeneratorTool) Name() string { return "run_generator" }
func (runGeneratorTool) Description() string {
	return "Author a DETERMINISTIC input GENERATOR and let quarry run it to produce many candidate inputs at once — the preferred way to explore a format (encode its structure ONCE in a small program instead of hand-writing inputs). Provide a script via generator_content (or generator_path) that, given an OUTPUT DIRECTORY and a COUNT as argv[1] and argv[2], writes that many input files into that directory (a generator that instead prints one input to stdout also works). quarry runs it in the workspace, feeds every produced input to the coverage-guided fuzzer's corpus when one is attached, and submits each to the air-gapped oracle, stopping at the first PASS. This is NOT the judge — only the oracle verdicts it."
}
func (runGeneratorTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"generator_content":{"type":"string","description":"full source of the generator program (used if generator_path is absent)"},"generator_path":{"type":"string","description":"workspace path to an existing generator program"},"interpreter":{"type":"string","description":"how to run it: python3 (default), sh, bash, or perl"},"count":{"type":"integer","description":"how many inputs to request (default 24, max 64)"},"note":{"type":"string","description":"what you expect these inputs to exercise"}},"required":[]}`)
}

func (t *runGeneratorTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		GeneratorContent string          `json:"generator_content"`
		GeneratorPath    string          `json:"generator_path"`
		Interpreter      string          `json:"interpreter"`
		Count            json.RawMessage `json:"count"`
		Note             string          `json:"note"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "", fmt.Errorf("run_generator: bad arguments %s: %w", truncateArgs(args), err)
	}
	interp := interpreterFor(a.Interpreter)
	if interp == "" {
		return "", fmt.Errorf("run_generator: unsupported interpreter %q (use python3, sh, bash, or perl)", a.Interpreter)
	}
	count := coerceInt(a.Count)
	if count <= 0 {
		count = genDefaultCount
	}
	if count > genMaxVariants {
		count = genMaxVariants
	}

	nonce := t.s.genRuns
	t.s.genRuns++
	scriptPath := strings.TrimSpace(a.GeneratorPath)
	if scriptPath == "" {
		if strings.TrimSpace(a.GeneratorContent) == "" {
			return "", fmt.Errorf("run_generator: provide generator_content or generator_path")
		}
		scriptPath = fmt.Sprintf(".quarry-gen/gen-%d.%s", nonce, scriptExt(interp))
		if err := t.s.Workspace.WriteFile(scriptPath, a.GeneratorContent); err != nil {
			return "", fmt.Errorf("run_generator: write script: %w", err)
		}
	}

	// fresh dir per run: the workspace has no delete, so never reuse a name
	outDir := fmt.Sprintf(".quarry-gen/out-%d", nonce)
	if err := t.s.Workspace.WriteFile(outDir+"/.keep", ""); err != nil {
		return "", fmt.Errorf("run_generator: make output dir: %w", err)
	}

	res, err := t.s.Workspace.Exec(ctx, interp, []string{scriptPath, outDir, strconv.Itoa(count)}, "", 0)
	if err != nil {
		return "", fmt.Errorf("run_generator: exec: %w", err)
	}

	inputs := t.collectGenerated(outDir, res.Stdout, count)
	if len(inputs) == 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "run_generator produced NO inputs (exit=%d). Ensure the program writes files into its argv[1] directory (or prints one input to stdout).", res.ExitCode)
		if tail := tailLines(res.Stderr, 8); tail != "" {
			fmt.Fprintf(&b, "\n--- generator stderr (tail) ---\n%s", tail)
		}
		return b.String(), nil
	}

	produced := len(inputs)
	verified := 0
	unjudged := 0 // oracle could not judge it: INCONCLUSIVE, never "clean"
	var firstErr error
	for i, pov := range inputs {
		if t.s.CandidateSink != nil {
			t.s.CandidateSink(pov)
		}
		vr, verr := t.s.Verifier.Verify(ctx, verify.Request{
			RunID: t.s.RunID, HypothesisID: t.s.HypothesisID, Model: t.s.Model,
			Spec: t.s.Oracle, Base: t.s.Base, Fixed: t.s.Fixed, PoV: pov,
		})
		if verr != nil {
			// an oracle outage is not an observation about this input
			unjudged++
			if firstErr == nil {
				firstErr = verr
			}
			continue
		}
		verified++
		t.s.PoVSubmissions++
		t.s.LastResult = &vr
		t.s.LastVerdict = &vr.Verdict
		t.s.LastPoV = pov
		if vr.Verdict.Pass {
			t.s.Confirmed = true
			t.s.ConfirmedPoV = pov
			snap := vr
			t.s.ConfirmedResult = &snap
			if t.s.Store != nil {
				provID, _ := t.s.Store.ProvenanceFor(ctx, vr.ExperimentID)
				_, _ = t.s.Store.AddEntry(ctx, t.s.RunID, t.s.HypothesisID, store.TagFact, "oracle-pass", summarizeResult(vr), provID)
			}
			// name it by POSITION in the batch: the verification count skips unjudged inputs
			return fmt.Sprintf("run_generator: %d input(s) produced, %d oracle-verified — input #%d SATISFIED the oracle (see the verdict).\n\n%s",
				produced, verified, i+1, summarizeResult(vr)), nil
		}
	}
	// fail closed: nothing judged is INCONCLUSIVE, never "the target may be correct"
	if verified == 0 && unjudged > 0 {
		if t.s.Store != nil {
			_, _ = t.s.Store.AddEntry(ctx, t.s.RunID, t.s.HypothesisID, store.TagObservation, "oracle-error",
				fmt.Sprintf("run_generator: %d input(s) produced, none judged: %v", produced, firstErr), "")
		}
		return "", fmt.Errorf("run_generator: the oracle could not judge ANY of the %d produced input(s) — INCONCLUSIVE, not a refutation (%d verification error(s), first: %w)",
			produced, unjudged, firstErr)
	}
	msg := fmt.Sprintf("run_generator: %d input(s) produced, %d oracle-verified — none satisfied the oracle yet. They were added to the fuzzer corpus. Refine the generator (target the suspect field/section, widen sizes/edge cases) and run it again, or mutate the closest seed.", produced, verified)
	if unjudged > 0 {
		msg += fmt.Sprintf("\nNOTE: %d input(s) could NOT be judged by the oracle (%s) — those are INCONCLUSIVE, not clean; nothing is ruled out for them.",
			unjudged, oneLine(firstErr.Error(), 200))
	}
	return msg, nil
}

func (t *runGeneratorTool) collectGenerated(outDir, stdout string, count int) [][]byte {
	names, err := t.s.Workspace.List(outDir)
	var inputs [][]byte
	if err == nil {
		sort.Strings(names)
		for _, nm := range names {
			if len(inputs) >= count {
				break
			}
			if strings.HasSuffix(nm, "/") || nm == ".keep" {
				continue
			}
			content, rerr := t.s.Workspace.ReadFile(outDir + "/" + nm)
			if rerr != nil || content == "" || len(content) > genMaxInputSize {
				continue
			}
			inputs = append(inputs, []byte(content))
		}
	}
	if len(inputs) == 0 && stdout != "" && len(stdout) <= genMaxInputSize {
		inputs = append(inputs, []byte(stdout))
	}
	return inputs
}

// allowlist: the model must never choose an arbitrary argv[0]
func interpreterFor(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "python3", "python":
		return "python3"
	case "sh":
		return "sh"
	case "bash":
		return "bash"
	case "perl":
		return "perl"
	}
	return ""
}

func scriptExt(interp string) string {
	switch interp {
	case "python3":
		return "py"
	case "perl":
		return "pl"
	default:
		return "sh"
	}
}

type runPoVTool struct{ s *Session }

func (runPoVTool) Name() string { return "run_pov" }
func (runPoVTool) Description() string {
	return "Submit a proof-of-vulnerability to the air-gapped oracle. The oracle runs it on a FRESH authoritative target you cannot tamper with and returns a deterministic verdict. This is the ONLY way to confirm success."
}
func (runPoVTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"pov_path":{"type":"string","description":"workspace path to the PoV input file"},"pov_content":{"type":"string","description":"inline PoV bytes (used if pov_path is absent)"},"pov_base64":{"type":"string","description":"base64 PoV bytes for non-text inputs (highest precedence)"},"note":{"type":"string","description":"what you expect to happen"}},"required":[]}`)
}
func (t *runPoVTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	var a struct {
		PoVPath    string `json:"pov_path"`
		PoVContent string `json:"pov_content"`
		PoVBase64  string `json:"pov_base64"`
		Note       string `json:"note"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "", err
	}
	var pov []byte
	switch {
	case a.PoVBase64 != "":
		b, err := base64.StdEncoding.DecodeString(a.PoVBase64)
		if err != nil {
			return "", fmt.Errorf("run_pov: bad base64: %w", err)
		}
		pov = b
	case a.PoVPath != "":
		content, err := t.s.Workspace.ReadFile(a.PoVPath)
		if err != nil {
			return "", fmt.Errorf("run_pov: read %s: %w", a.PoVPath, err)
		}
		pov = []byte(content)
	case a.PoVContent != "":
		pov = []byte(a.PoVContent)
	default:
		return "", fmt.Errorf("run_pov: provide pov_path, pov_content, or pov_base64")
	}

	t.s.PoVSubmissions++
	if t.s.CandidateSink != nil {
		t.s.CandidateSink(pov)
	}
	res, err := t.s.Verifier.Verify(ctx, verify.Request{
		RunID:        t.s.RunID,
		HypothesisID: t.s.HypothesisID,
		Model:        t.s.Model,
		Spec:         t.s.Oracle,
		Base:         t.s.Base,
		Fixed:        t.s.Fixed,
		PoV:          pov,
	})
	if err != nil {
		return "", fmt.Errorf("run_pov: %w", err)
	}
	t.s.LastResult = &res
	t.s.LastVerdict = &res.Verdict
	t.s.LastPoV = pov

	if t.s.Store != nil {
		_ = t.s.Store.AppendEvent(ctx, t.s.RunID, "observation", "oracle", map[string]any{
			"pass": res.Verdict.Pass, "experiment": res.ExperimentID,
			"signal": res.Primary.TermSignal, "exit": res.Primary.ExitCode,
		})
	}

	if res.Verdict.Pass {
		t.s.Confirmed = true
		t.s.ConfirmedPoV = pov
		snap := res
		t.s.ConfirmedResult = &snap
		if t.s.Store != nil {
			provID, _ := t.s.Store.ProvenanceFor(ctx, res.ExperimentID)
			_, _ = t.s.Store.AddEntry(ctx, t.s.RunID, t.s.HypothesisID, store.TagFact, "oracle-pass",
				summarizeResult(res), provID)
		}
	} else if t.s.Store != nil {
		_, _ = t.s.Store.AddEntry(ctx, t.s.RunID, t.s.HypothesisID, store.TagObservation, "oracle-fail",
			summarizeResult(res), "")
	}
	return summarizeResult(res), nil
}

func summarizeResult(res verify.Result) string {
	var b strings.Builder
	if res.Verdict.Pass {
		b.WriteString("ORACLE VERDICT: PASS ✓ — the target is confirmed vulnerable.\n")
	} else {
		b.WriteString("ORACLE VERDICT: FAIL — conditions not met. Iterate.\n")
	}
	p := res.Primary
	if p.TermSignal != 0 {
		fmt.Fprintf(&b, "terminated by signal %d\n", p.TermSignal)
	} else {
		fmt.Fprintf(&b, "exited with code %d\n", p.ExitCode)
	}
	if p.TimedOut {
		b.WriteString("run timed out\n")
	}
	if p.Sanitizer.Fired {
		fmt.Fprintf(&b, "sanitizer: %s %s at %s\n", p.Sanitizer.Tool, p.Sanitizer.BugClass, p.Sanitizer.CrashSite)
	}
	for _, cr := range res.Verdict.Conditions {
		fmt.Fprintf(&b, "  condition[%s]: matched=%v (%s)\n", cr.Type, cr.Matched, cr.Detail)
	}
	if res.Verdict.Differential != nil {
		d := res.Verdict.Differential
		fmt.Fprintf(&b, "  differential: vuln=%v fixed=%v satisfied=%v\n", d.MatchedOnVuln, d.MatchedOnFixed, d.Satisfied)
	}
	if len(res.Verdict.PartialCredit) > 0 {
		fmt.Fprintf(&b, "partial-credit signals: %s\n", strings.Join(res.Verdict.PartialCredit, ", "))
	}
	if tail := tailLines(p.Stderr, 12); tail != "" {
		fmt.Fprintf(&b, "--- target stderr (tail) ---\n%s\n", tail)
	}
	return b.String()
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func navFuncArg(args json.RawMessage) (string, error) {
	var a struct {
		Function string `json:"function"`
	}
	_ = json.Unmarshal(args, &a)
	a.Function = strings.TrimSpace(a.Function)
	if a.Function == "" {
		return "", fmt.Errorf("function is required")
	}
	return a.Function, nil
}

func navSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"function":{"type":"string","description":"function name (bare identifier, no parens)"}},"required":["function"]}`)
}

type callersTool struct{ s *Session }

func (callersTool) Name() string { return "get_callers" }
func (callersTool) Description() string {
	return "List the functions in the seeded source that CALL the named function — walk UP toward the input entry point to trace how untrusted bytes reach a sink."
}
func (callersTool) Schema() json.RawMessage { return navSchema() }
func (t *callersTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	fn, err := navFuncArg(args)
	if err != nil {
		return "", fmt.Errorf("get_callers: %w", err)
	}
	return renderNavList("callers of "+fn, t.s.CodeNav.Callers(fn)), nil
}

type calleesTool struct{ s *Session }

func (calleesTool) Name() string { return "get_callees" }
func (calleesTool) Description() string {
	return "List the functions the named function CALLS — walk DOWN toward the dangerous operation (sink) it may reach."
}
func (calleesTool) Schema() json.RawMessage { return navSchema() }
func (t *calleesTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	fn, err := navFuncArg(args)
	if err != nil {
		return "", fmt.Errorf("get_callees: %w", err)
	}
	return renderNavList("callees of "+fn, t.s.CodeNav.Callees(fn)), nil
}

type functionTool struct{ s *Session }

func (functionTool) Name() string { return "get_function" }
func (functionTool) Description() string {
	return "Show the source of the named function (with its file:line) from the seeded tree — read the exact code around a suspected weakness without grepping the whole tree."
}
func (functionTool) Schema() json.RawMessage { return navSchema() }
func (t *functionTool) Invoke(_ context.Context, args json.RawMessage) (string, error) {
	fn, err := navFuncArg(args)
	if err != nil {
		return "", fmt.Errorf("get_function: %w", err)
	}
	body := t.s.CodeNav.Function(fn)
	if strings.TrimSpace(body) == "" {
		return "no definition of " + fn + " found in the seeded source", nil
	}
	return body, nil
}

func renderNavList(title string, names []string) string {
	if len(names) == 0 {
		return "no " + title + " found in the seeded source"
	}
	return title + " (" + strconv.Itoa(len(names)) + "):\n  " + strings.Join(names, "\n  ")
}

func coerceStringSlice(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			out = append(out, scalarString(e))
		}
		return out
	}
	return []string{scalarString(raw)}
}

func scalarString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

func coerceInt(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return v
		}
	}
	return 0
}

func truncateArgs(raw json.RawMessage) string {
	s := string(raw)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

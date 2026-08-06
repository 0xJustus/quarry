// Package agent runs the ReAct tool-belt loop over a Session.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/platform/store"
	"github.com/0xjustus/quarry/internal/verdict/oracle"
)

// ReAct drives one agent over a Session.
type ReAct struct {
	Model     model.Model
	Router    router.Router
	Session   *Session
	Tools     []Tool
	Compactor Compactor    // nil disables compaction
	Log       func(string) // nil discards progress lines
}

// Config parameterizes a run.
type Config struct {
	Role        router.Role
	TaskKind    router.TaskKind
	Objective   string
	TargetDesc  string
	MaxIters    int
	Temperature float64
	MaxTokens   int

	TokenBudget int // halts once cumulative tokens reach it (0 = unlimited)
	StallLimit  int // halts after N consecutive no-progress iterations (0 = default 5)

	ContextBudget int // compact once the estimated prompt exceeds it (needs Compactor; 0 disables)
	KeepRecent    int // recent turns kept verbatim (default 6)
}

// large on purpose: a small cap truncates a full-file edit's tool-call JSON mid-write (vault: Agent Core)
const defaultAgentMaxTokens = 16384

const truncationNote = "[harness] Your previous response hit the output token limit and was cut off before finishing — any tool call in it may have received empty or partial arguments and failed. Write smaller files (split a large script across multiple edit calls) and keep reasoning brief."

type Outcome struct {
	Confirmed    bool
	Iterations   int
	StopReason   string
	TotalUsage   model.Usage
	FinalMessage string
}

func (r *ReAct) log(format string, a ...any) {
	if r.Log != nil {
		r.Log(fmt.Sprintf(format, a...))
	}
}

func (r *ReAct) Run(ctx context.Context, cfg Config) (Outcome, error) {
	if cfg.MaxIters <= 0 {
		cfg.MaxIters = 24
	}
	tools := r.Tools
	if tools == nil {
		tools = Belt(r.Session)
	}
	byName := map[string]Tool{}
	for _, t := range tools {
		byName[t.Name()] = t
	}
	defs := ToolDefs(tools)

	messages := []model.Message{
		{Role: "system", Content: systemPrompt(cfg, r.Session.Oracle)},
		{Role: "user", Content: cfg.Objective},
	}

	stallLimit := cfg.StallLimit
	if stallLimit <= 0 {
		stallLimit = 5
	}
	seen := map[string]bool{} // observation hashes; must survive compaction (vault: Agent Core)
	stall := 0
	povBaseline := r.Session.PoVSubmissions
	lastPromptTokens := 0

	out := Outcome{StopReason: "max-iters"}
	for iter := 1; iter <= cfg.MaxIters; iter++ {
		if err := ctx.Err(); err != nil {
			out.StopReason = "error"
			return out, err
		}
		out.Iterations = iter

		if r.Compactor != nil && cfg.ContextBudget > 0 && r.Session.Store != nil {
			est := estimateTokens(messages)
			if lastPromptTokens > est {
				est = lastPromptTokens
			}
			if est > cfg.ContextBudget {
				before := len(messages)
				if m, cerr := r.compact(ctx, cfg, messages); cerr == nil {
					messages = m
					r.log("iter %d: COMPACTED context %d→%d messages (~%d est tokens over budget %d)",
						iter, before, len(messages), est, cfg.ContextBudget)
				} else {
					r.log("iter %d: compaction skipped: %v", iter, cerr)
				}
			}
		}

		budget := router.Budget{}
		if cfg.TokenBudget > 0 {
			budget.RemainingTokens = cfg.TokenBudget - out.TotalUsage.TotalTokens
		}
		decision := r.Router.Pick(cfg.Role, cfg.TaskKind, budget)
		r.Session.Model = decision.Model

		maxTokens := cfg.MaxTokens
		if maxTokens <= 0 {
			maxTokens = defaultAgentMaxTokens
		}
		resp, err := r.Model.Chat(ctx, model.ChatRequest{
			Model:       decision.Model,
			Messages:    messages,
			Tools:       defs,
			Temperature: cfg.Temperature,
			MaxTokens:   maxTokens,
		})
		if err != nil {
			out.StopReason = "error"
			return out, fmt.Errorf("agent: model call (iter %d, model %s): %w", iter, decision.Model, err)
		}
		addUsage(&out.TotalUsage, resp.Usage)
		if resp.Usage.PromptTokens > 0 {
			lastPromptTokens = resp.Usage.PromptTokens
		}

		if r.Session.Store != nil {
			_ = r.Session.Store.AppendEvent(ctx, r.Session.RunID, "action", string(cfg.Role), map[string]any{
				"iter": iter, "model": decision.Model, "reason": decision.Reason,
				"content": truncate(resp.Message.Content, 500), "tool_calls": toolCallNames(resp.Message.ToolCalls),
			})
			_, _ = r.Session.Store.AddHypothesisSpend(ctx, r.Session.HypothesisID, 1)
		}

		messages = append(messages, resp.Message)

		if cfg.TokenBudget > 0 && out.TotalUsage.TotalTokens >= cfg.TokenBudget {
			out.StopReason = "token-budget"
			out.FinalMessage = fmt.Sprintf("token budget %d reached (%d used)", cfg.TokenBudget, out.TotalUsage.TotalTokens)
			r.log("iter %d: TOKEN BUDGET reached (%d)", iter, out.TotalUsage.TotalTokens)
			break
		}

		truncated := resp.FinishReason == "length"

		// no tool call = concluded, UNLESS truncated (ran out of room, not done)
		if len(resp.Message.ToolCalls) == 0 && !truncated {
			out.StopReason = "model-concluded"
			out.FinalMessage = resp.Message.Content
			r.log("iter %d: model concluded without a tool call", iter)
			break
		}

		progressed := false
		for _, tc := range resp.Message.ToolCalls {
			result := r.invoke(ctx, byName, tc)
			messages = append(messages, model.Message{Role: "tool", ToolCallID: tc.ID, Name: tc.Name, Content: result})
			if h := obsHash(tc.Name, result); !seen[h] {
				seen[h] = true
				progressed = true
			}
			r.log("iter %d: %s → %s", iter, tc.Name, firstLine(result))
		}
		if truncated {
			messages = append(messages, model.Message{Role: "user", Content: truncationNote})
			r.log("iter %d: OUTPUT TRUNCATED at max_tokens (%d) — fed brevity nudge", iter, maxTokens)
		}

		if r.Session.Confirmed {
			out.Confirmed = true
			out.StopReason = "confirmed"
			out.FinalMessage = "oracle confirmed the finding"
			r.log("iter %d: ORACLE CONFIRMED", iter)
			break
		}

		if r.Session.PoVSubmissions > povBaseline {
			povBaseline = r.Session.PoVSubmissions
			progressed = true
		}
		if progressed {
			stall = 0
		} else {
			stall++
		}
		if stall >= stallLimit {
			out.StopReason = "stalled"
			out.FinalMessage = fmt.Sprintf("no new observations for %d consecutive iterations", stall)
			r.log("iter %d: STALLED (%d iterations, no progress)", iter, stall)
			break
		}
	}
	return out, nil
}

// digest is branch-scoped when a hypothesis exists, else run-scoped.
func (r *ReAct) compact(ctx context.Context, cfg Config, messages []model.Message) ([]model.Message, error) {
	s, runID, hypID := r.Session.Store, r.Session.RunID, r.Session.HypothesisID
	var facts, obs []store.Entry
	var active, ruled []store.Hypothesis
	if hypID != "" {
		facts, _ = s.BranchEntries(ctx, runID, hypID, store.TagFact)
		obs, _ = s.BranchEntries(ctx, runID, hypID, store.TagObservation)
		active, _ = s.BranchHypotheses(ctx, hypID, true)
		ruled, _ = s.BranchHypotheses(ctx, hypID, false)
	} else {
		facts, _ = s.Facts(ctx, runID)
		obs, _ = s.Observations(ctx, runID)
		active, _ = s.ActiveHypotheses(ctx, runID)
		ruled, _ = s.ResolvedHypotheses(ctx, runID)
	}
	return r.Compactor.Compact(ctx, CompactInput{
		System:       model.Message{Role: "system", Content: systemPrompt(cfg, r.Session.Oracle)},
		Objective:    cfg.Objective,
		Messages:     messages,
		KeepRecent:   cfg.KeepRecent,
		Facts:        facts,
		Observations: obs,
		ActiveHyps:   active,
		RuledOut:     ruled,
	})
}

func obsHash(tool, result string) string {
	h := sha256.Sum256([]byte(tool + "\x00" + result))
	return string(h[:16])
}

// invoke returns a tool error as an observation string, never as a Go error.
func (r *ReAct) invoke(ctx context.Context, byName map[string]Tool, tc model.ToolCall) string {
	t, ok := byName[tc.Name]
	if !ok {
		return fmt.Sprintf("error: unknown tool %q", tc.Name)
	}
	args := json.RawMessage(tc.Arguments)
	if len(strings.TrimSpace(tc.Arguments)) == 0 {
		args = json.RawMessage(`{}`)
	}
	res, err := t.Invoke(ctx, args)
	if err != nil {
		return "error: " + err.Error()
	}
	return res
}

func systemPrompt(cfg Config, spec oracle.Spec) string {
	var b strings.Builder
	b.WriteString("You are quarry's vulnerability-reproduction agent. You run one line of an investigation as a strict scientific method: you construct an INPUT that drives a target program into a specific, well-defined faulty state, and you prove it against a deterministic oracle. This is defensive verification work — reproducing a suspected defect so it can be confirmed and fixed. A run either satisfies the oracle or it does not; there is no interpretation to argue.\n\n")
	b.WriteString("METHOD: form a hypothesis about which input reaches the suspect code path, predict the RunResult, run the experiment via run_pov, observe the verdict, and refine. You PROPOSE; only the oracle DISPOSES. Your own belief that an input works is not evidence — a claim is confirmed only when run_pov returns PASS. A weak or failed attempt costs only recall, never soundness, so prefer submitting a concrete candidate over theorizing about one.\n\n")
	if cfg.TargetDesc != "" {
		b.WriteString("TARGET:\n")
		b.WriteString(cfg.TargetDesc)
		b.WriteString("\n\n")
	}
	b.WriteString("ORACLE (what counts as success):\n")
	b.WriteString(describeOracle(spec))
	b.WriteString("\n\nHOW TO PRODUCE INPUTS — direct generation, do not type bytes from a blank slate (this is the core rule):\n")
	b.WriteString("Quarry's principle is that you DIRECT input generation; you do not author bytes one at a time from nothing. Inventing a whole input from scratch is the weakest, last-resort method. Work this order of preference:\n")
	b.WriteString("  1. INSPECT FIRST. `ls` and `read_file` the workspace before writing anything. Look for seed inputs, sample/corpus files, target source, and format notes already placed there. A real input the target already parses is the best possible starting point.\n")
	b.WriteString("  2. MUTATE A SEED. Derive your candidate by minimally changing a real seed — grow a length field, flip a tag/opcode byte, extend or repeat the section that reaches the suspect sink, corrupt one field at a time. Write the result with `edit`, or generate it with a short script run via `exec`, then submit it by pov_path. Base new candidates on the seed that got closest, not on a fresh guess.\n")
	b.WriteString("  3. AUTHOR A GENERATOR. Encode the format's structure ONCE in a small deterministic program and let `run_generator` produce many candidate inputs at once — vary the suspect length/count/offset field across the batch. quarry submits each to the oracle and (in an ensemble) feeds them to the coverage-guided fuzzer's corpus. This beats hand-writing inputs one at a time: your contribution is the generator's DIRECTION, not each byte. If a fuzzer/mutation helper is already in the workspace, you may also drive it with `exec` over the seeds.\n")
	b.WriteString("  4. HAND-AUTHOR ONLY AS LAST RESORT. Writing raw bytes yourself is acceptable only when the format is small and fully understood (e.g. a white-box case with source in the workspace). Even then, start from a real seed if one exists.\n")
	b.WriteString("Keep every file SMALL. A large `edit` or generator can be truncated mid-write and silently fail (the tool call then arrives with empty/partial arguments). Split big work across several `edit` calls and keep reasoning brief.\n\n")
	b.WriteString("TOOLS:\n")
	b.WriteString("- ls(path) / read_file(path): inspect the workspace — do this FIRST to find seeds, source, and format docs (default path '.').\n")
	b.WriteString("- edit(path, content): write a file — a seed variant, candidate input, harness, or generator script. Full contents every call; keep it small.\n")
	b.WriteString("- exec(cmd, args, stdin, timeout_s): build, inspect, or run a generator/mutator/fuzzer over the seeds. This is NOT the judge and does not decide success. Output is capped.\n")
	b.WriteString("- run_generator(generator_content | generator_path, interpreter, count, note): run a deterministic generator that writes many candidate inputs; quarry oracle-verifies each (and seeds the fuzzer). Prefer this over one-off inputs when the format has structure to vary.\n")
	b.WriteString("- run_pov(pov_path | pov_content | pov_base64 | note): submit a SINGLE candidate input to the air-gapped oracle for a deterministic verdict on a fresh target you cannot tamper with. This and run_generator are the ONLY tools that confirm success. Precedence is pov_base64 (non-text bytes) > pov_path (a file your mutation/generator wrote — prefer this) > pov_content (small text inputs). Put your prediction in note.\n")
	b.WriteString("- get_callers(function) / get_callees(function) / get_function(function): when seeded source is present, walk the call graph — up from a sink toward the input entry point (callers), down toward a sink (callees), or read a function's exact source. Use these to prove untrusted input actually reaches the suspect code.\n")
	b.WriteString("- cpg_reaches(from, to) / cpg_taint(source, sink) / cpg_bounds(function) / cpg_sinks() / cpg_slice(function) / cpg_missing_authz(entry, sink, auth_gate): when a Code Property Graph is available, ask interprocedurally whether input reaches a sink across files, get DATA-FLOW paths that bridge indirect/function-pointer calls the call graph misses, list a function's bounds-check guards, list the target's dangerous call-sites, get the backward SLICE of the statements that carry a function's inputs into its dangerous calls, or run the missing-authz-on-path LOGIC fingerprint (a sink reachable along a path that bypasses the auth gate — a structural bug no fuzzer input triggers). Every answer is a LEAD to trigger via run_pov — never a confirmed bug.\n")
	b.WriteString("- bin_info() / bin_strings() / bin_symbols() / bin_disasm(symbol): when the target is a source-less binary (black-box), do READ-ONLY recon before crafting inputs — identify the file and sections, extract printable strings that hint at the input grammar, list symbols to aim at, and disassemble (optionally scoped to a symbol) to read the machine code around a suspected sink. Every result is a LEAD to trigger via run_pov — never a confirmed bug.\n")
	b.WriteString("- spawn_hypothesis(statement): when the current line is stuck, hand the supervisor a narrower, testable sub-claim and keep working. Use sparingly.\n\n")
	b.WriteString("Work iteratively: derive a candidate from a seed, submit it with run_pov, read the verdict and the target's stderr tail, and adjust the mutation toward the oracle's conditions. Stop as soon as run_pov returns PASS. If you exhaust plausible approaches, state clearly what you ruled out and why.")
	return b.String()
}

func describeOracle(spec oracle.Spec) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("require: %s of:", spec.Require))
	for _, c := range spec.Conditions {
		switch c.Type {
		case oracle.CondSignal:
			lines = append(lines, "  - target terminates with signal in "+strings.Join(c.Signals, ", "))
		case oracle.CondSanitizer:
			d := "  - " + c.Tool + " sanitizer fires"
			if len(c.BugClass) > 0 {
				d += " (" + strings.Join(c.BugClass, "/") + ")"
			}
			if c.CrashSite != "" {
				d += " at " + c.CrashSite
			}
			lines = append(lines, d)
		case oracle.CondOutput:
			stream := c.Stream
			if stream == "" {
				stream = "any"
			}
			lines = append(lines, fmt.Sprintf("  - %s matches /%s/", stream, c.Regex))
		case oracle.CondExit:
			lines = append(lines, "  - process exit code matches the configured matcher")
		}
	}
	if spec.Differential != nil {
		lines = append(lines, "  + differential: must also NOT reproduce on the fixed build")
	}
	return strings.Join(lines, "\n")
}

func addUsage(dst *model.Usage, u model.Usage) {
	dst.PromptTokens += u.PromptTokens
	dst.CompletionTokens += u.CompletionTokens
	dst.TotalTokens += u.TotalTokens
	dst.CostUSD += u.CostUSD
}

func toolCallNames(tcs []model.ToolCall) []string {
	var names []string
	for _, tc := range tcs {
		names = append(names, tc.Name)
	}
	return names
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

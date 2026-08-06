package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// keep in sync with cpg.Client: the loop wraps that surface thinly
type CPGQuerier interface {
	Reaches(ctx context.Context, from, to string) (reaches bool, transitiveCallers int, err error)
	TaintFlows(ctx context.Context, source, sink string) (count int, paths []string, err error)
	BoundsChecks(ctx context.Context, fn string) ([]string, error)
	SinkSites(ctx context.Context) ([]string, error)
	Slice(ctx context.Context, fn string) (string, error)
	Callers(ctx context.Context, fn string) ([]string, error)
	Callees(ctx context.Context, fn string) ([]string, error)
	MissingAuthz(ctx context.Context, entry, sink, authGate string) (reachesSink, unauthedPath, authPresent bool, err error)
}

func cpgTools(s *Session) []Tool {
	if s.CPG == nil {
		return nil
	}
	return []Tool{&cpgReachesTool{s}, &cpgTaintTool{s}, &cpgBoundsTool{s}, &cpgSinksTool{s}, &cpgSliceTool{s}, &cpgCallersTool{s}, &cpgCalleesTool{s}, &cpgMissingAuthzTool{s}}
}

type cpgMissingAuthzTool struct{ s *Session }

func (cpgMissingAuthzTool) Name() string { return "cpg_missing_authz" }
func (cpgMissingAuthzTool) Description() string {
	return "Missing-authz-on-path LOGIC fingerprint: does ENTRY reach the sensitive SINK along a call path " +
		"that NEVER passes through AUTH_GATE? This finds an architectural bug a fuzzer cannot search for — the " +
		"structural absence of an authorization check, which no input triggers. A fired fingerprint (reaches_sink " +
		"AND unauthed_path) is a strong LEAD; confirm it by triggering the path and applying the oracle."
}
func (cpgMissingAuthzTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"entry":{"type":"string","description":"request-handling entry function (bare name)"},"sink":{"type":"string","description":"sensitive operation to guard (bare name)"},"auth_gate":{"type":"string","description":"the authorization function that should gate the sink (bare name)"}},"required":["entry","sink","auth_gate"]}`)
}
func (t *cpgMissingAuthzTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	a := fnArg(args, "entry", "sink", "auth_gate")
	reaches, unauthed, authPresent, err := t.s.CPG.MissingAuthz(ctx, a["entry"], a["sink"], a["auth_gate"])
	if err != nil {
		return "", fmt.Errorf("cpg_missing_authz: %w", err)
	}
	if reaches && unauthed {
		return fmt.Sprintf("FINGERPRINT FIRED: %q reaches sensitive sink %q along a path that bypasses %q "+
			"(auth_present_anywhere=%v). An unauthenticated route to the sink — a structural bug no fuzzer input can "+
			"trigger. LEAD: trigger this path and confirm with the oracle.", a["entry"], a["sink"], a["auth_gate"], authPresent), nil
	}
	if !reaches {
		return fmt.Sprintf("no fingerprint: %q does not reach %q in the call graph (may be an unresolved indirect call — try cpg_taint).", a["entry"], a["sink"]), nil
	}
	return fmt.Sprintf("no fingerprint: every path from %q to %q passes through %q — the sink is gated.", a["entry"], a["sink"], a["auth_gate"]), nil
}

func fnArg(args json.RawMessage, keys ...string) map[string]string {
	raw := map[string]string{}
	_ = json.Unmarshal(args, &raw)
	out := map[string]string{}
	for _, k := range keys {
		out[k] = strings.TrimSpace(raw[k])
	}
	return out
}

func cpgHop(ctx context.Context, tool, kind, fn string, hop func(context.Context, string) ([]string, error), whenNone string) (string, error) {
	names, err := hop(ctx, fn)
	if err != nil {
		return "", fmt.Errorf("%s: %w", tool, err)
	}
	if len(names) == 0 {
		return "no " + kind + "s of " + fn + " in the CPG (" + whenNone + ")", nil
	}
	return fmt.Sprintf("%d %s(s) of %s:\n  %s", len(names), kind, fn, strings.Join(names, "\n  ")), nil
}

type cpgReachesTool struct{ s *Session }

func (cpgReachesTool) Name() string { return "cpg_reaches" }
func (cpgReachesTool) Description() string {
	return "Ask the Code Property Graph whether untrusted input can reach a sink: is there a call path from FROM to TO, interprocedurally across files? A 'false' can be a broken indirect/function-pointer call rather than proof of unreachability — follow up with cpg_taint. A 'true' path is a LEAD to trigger, never a confirmed bug."
}
func (cpgReachesTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"from":{"type":"string","description":"entry function (bare name)"},"to":{"type":"string","description":"sink function (bare name)"}},"required":["from","to"]}`)
}
func (t *cpgReachesTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	a := fnArg(args, "from", "to")
	r, n, err := t.s.CPG.Reaches(ctx, a["from"], a["to"])
	if err != nil {
		return "", fmt.Errorf("cpg_reaches: %w", err)
	}
	return fmt.Sprintf("reaches(%s → %s) = %v  (%d functions transitively call %s)", a["from"], a["to"], r, n, a["to"]), nil
}

type cpgTaintTool struct{ s *Session }

func (cpgTaintTool) Name() string { return "cpg_taint" }
func (cpgTaintTool) Description() string {
	return "Ask the CPG for DATA-FLOW paths from SOURCE's inputs into SINK (reachableByFlows). This bridges indirect/function-pointer calls the plain call graph misses. A non-zero count is a LEAD (static taint over-approximates); the oracle still disposes."
}
func (cpgTaintTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"source":{"type":"string","description":"function where untrusted input enters (bare name)"},"sink":{"type":"string","description":"dangerous function (bare name)"}},"required":["source","sink"]}`)
}
func (t *cpgTaintTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	a := fnArg(args, "source", "sink")
	n, paths, err := t.s.CPG.TaintFlows(ctx, a["source"], a["sink"])
	if err != nil {
		return "", fmt.Errorf("cpg_taint: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "taint flows %s ~> %s: %d (LEAD, not a verdict)", a["source"], a["sink"], n)
	for i, p := range paths {
		fmt.Fprintf(&b, "\n  flow %d: %s", i+1, p)
	}
	return b.String(), nil
}

type cpgBoundsTool struct{ s *Session }

func (cpgBoundsTool) Name() string { return "cpg_bounds" }
func (cpgBoundsTool) Description() string {
	return "List the comparison guards (candidate bounds checks) inside a function — use it to judge whether an input-derived length/index is validated before a memory operation, or the check is missing."
}
func (cpgBoundsTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"function":{"type":"string","description":"function name (bare identifier)"}},"required":["function"]}`)
}
func (t *cpgBoundsTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	fn := fnArg(args, "function")["function"]
	checks, err := t.s.CPG.BoundsChecks(ctx, fn)
	if err != nil {
		return "", fmt.Errorf("cpg_bounds: %w", err)
	}
	if len(checks) == 0 {
		return "no comparison guards found in " + fn + " (a missing bounds check is a concern)", nil
	}
	return "guards in " + fn + ":\n  " + strings.Join(checks, "\n  "), nil
}

type cpgSinksTool struct{ s *Session }

func (cpgSinksTool) Name() string { return "cpg_sinks" }
func (cpgSinksTool) Description() string {
	return "List the dangerous call-sites in the target (memcpy/strcpy/alloc/exec/…) with their enclosing function — the graph-native sink map to aim reachability/taint queries at."
}
func (cpgSinksTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t *cpgSinksTool) Invoke(ctx context.Context, _ json.RawMessage) (string, error) {
	sites, err := t.s.CPG.SinkSites(ctx)
	if err != nil {
		return "", fmt.Errorf("cpg_sinks: %w", err)
	}
	if len(sites) == 0 {
		return "no dangerous call-sites found", nil
	}
	const max = 60
	if len(sites) > max {
		return fmt.Sprintf("%d dangerous call-sites (first %d):\n  %s\n  … %d more", len(sites), max, strings.Join(sites[:max], "\n  "), len(sites)-max), nil
	}
	return fmt.Sprintf("%d dangerous call-sites:\n  %s", len(sites), strings.Join(sites, "\n  ")), nil
}

type cpgSliceTool struct{ s *Session }

func (cpgSliceTool) Name() string { return "cpg_slice" }
func (cpgSliceTool) Description() string {
	return "Get the backward program SLICE for a function (LLMxCPG slice-as-context): the deduped data-flow statements that carry its tainted parameters into its dangerous call-site arguments — the conditions an exploit must satisfy, distilled from the surrounding noise. A LEAD to reason over and trigger via run_pov, never a confirmed bug."
}
func (cpgSliceTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"function":{"type":"string","description":"function name (bare identifier)"}},"required":["function"]}`)
}
func (t *cpgSliceTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	fn := fnArg(args, "function")["function"]
	slice, err := t.s.CPG.Slice(ctx, fn)
	if err != nil {
		return "", fmt.Errorf("cpg_slice: %w", err)
	}
	if slice == "" {
		return "no backward slice for " + fn + " (no data-flow from its parameters into a dangerous call)", nil
	}
	return "backward slice of " + fn + ":\n  " + strings.ReplaceAll(slice, "\n", "\n  "), nil
}

type cpgCallersTool struct{ s *Session }

func (cpgCallersTool) Name() string { return "cpg_callers" }
func (cpgCallersTool) Description() string {
	return "List the functions that CALL a function, interprocedurally over the whole program (one hop up the Joern call graph). Use it to walk backward from a sink toward the untrusted-input entry point — Joern resolves cross-file and some indirect edges the syntactic navigator misses. Each caller is a LEAD to keep tracing, never a confirmed path."
}
func (cpgCallersTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"function":{"type":"string","description":"function name (bare identifier)"}},"required":["function"]}`)
}
func (t *cpgCallersTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	return cpgHop(ctx, "cpg_callers", "caller", fnArg(args, "function")["function"], t.s.CPG.Callers,
		"an unreferenced/indirect-only entry, or a top-level harness")
}

type cpgCalleesTool struct{ s *Session }

func (cpgCalleesTool) Name() string { return "cpg_callees" }
func (cpgCalleesTool) Description() string {
	return "List the functions a function CALLS (one hop down the Joern call graph). Use it to descend from a harness entry toward a sink, or to see what a suspect function hands its tainted arguments to. Each callee is a LEAD to keep tracing, never a confirmed sink."
}
func (cpgCalleesTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"function":{"type":"string","description":"function name (bare identifier)"}},"required":["function"]}`)
}
func (t *cpgCalleesTool) Invoke(ctx context.Context, args json.RawMessage) (string, error) {
	return cpgHop(ctx, "cpg_callees", "callee", fnArg(args, "function")["function"], t.s.CPG.Callees,
		"a leaf, or its body is external/unresolved")
}

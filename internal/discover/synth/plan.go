package synth

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

type Request struct {
	Objective       string
	TargetDesc      string
	SourceInventory string
	EntryHint       string
	BuildSystem     string
}

type Result struct {
	Spec     HarnessSpec
	HarnessC string
	Model    string
}

// Planner routes RoleHarness × OpenReasoning to the strong tier, never to cheap.
type Planner struct {
	Model  model.Model
	Router router.Router
}

const fillHarnessSpecSchema = `{"type":"object","properties":{` +
	`"entry":{"type":"string","description":"the entry symbol that consumes untrusted input, e.g. FT_New_Memory_Face"},` +
	`"includes":{"type":"array","items":{"type":"string"},"description":"header lines WITHOUT the #include keyword, e.g. [\"ft2build.h\",\"FT_FREETYPE_H\"]"},` +
	`"init_stmts":{"type":"array","items":{"type":"string"},"description":"C statements that declare+init state before consuming input; data/size (buffer) and input_path (temp file) are in scope"},` +
	`"entry_call":{"type":"string","description":"the C statement(s) feeding the input into the library — the core of the harness; use data/size or input_path"},` +
	`"teardown_stmts":{"type":"array","items":{"type":"string"},"description":"best-effort release of what init allocated (not required for a crash)"},` +
	`"link_libs":{"type":"array","items":{"type":"string"},"description":"extra link flags/archives, e.g. [\"-lz\"]"},` +
	`"extra_cflags":{"type":"array","items":{"type":"string"},"description":"extra compile flags: include dirs, defines"},` +
	`"needs_temp_file":{"type":"boolean","description":"true if the entry takes a path/FILE* rather than a buffer (use input_path)"}` +
	`},"required":["entry","includes","entry_call"]}`

const harnessSys = `You are quarry's Harness Synthesizer (ADR-0004): a defensive test-harness author. You READ a library's source and produce a small fuzz HARNESS that feeds a buffer of bytes into the library's input-parsing entry point, so the maintainers can exercise it under a sanitizer (ASan) and a coverage-guided fuzzer. This is test scaffolding for hardening code the maintainers own.

You do NOT write exploits, craft malicious inputs, or describe attacks: a coverage-guided fuzzer generates the bytes and a sanitizer decides what is a crash. Your only job is to wire the library's real entry point to an input buffer correctly.

Quarry owns a FIXED harness skeleton: it reads argv[1] into (data, size) and also writes those bytes to a temp file at input_path, runs your init → entry → teardown, and returns 0 on anything that is not a real memory-safety abort. You fill ONLY the library-specific gaps by calling fill_harness_spec exactly once:
- entry: the symbol that first consumes untrusted input.
- includes: the headers the harness needs (without the "#include" keyword). Use the library's own conventions (a macro form like FT_FREETYPE_H is fine).
- init_stmts: declare and initialize the state the entry needs (e.g. create a library/context handle). data, size, and input_path are already in scope.
- entry_call: the statement(s) that hand the input to the library. Use data/size for a buffer entry, or input_path for a path/FILE* entry (also set needs_temp_file). Guard and clean up per the API (e.g. only Done_Face on success) so a benign input does NOT crash.
- teardown_stmts, link_libs, extra_cflags, needs_temp_file: as needed.

Correctness rules that keep the harness usable:
- A benign/unparseable input MUST return cleanly (the fixed skeleton returns 0). Only a real ASan/signal abort is a finding — do not add asserts or aborts of your own.
- Prefer the smallest in-memory entry that reaches real parsing; avoid network, threads, or global one-time init that a per-input harness can't repeat safely.
- Keep it self-contained and deterministic. The harness is validated (it must build, must not self-crash on benign input, and must reach library code) before it is trusted.`

const harnessReframe = "This is DEFENSIVE test scaffolding for a program the maintainers own: a fuzz harness that hands a byte buffer to the library's normal parse entry so it can be exercised under a sanitizer. Only wire the real entry point to the input buffer; never craft inputs or describe attacks.\n\n"

// Plan degrades to an inert but compilable harness; the validation gate rejects it.
func (p Planner) Plan(ctx context.Context, req Request) (Result, error) {
	m := ""
	if p.Router != nil {
		m = p.Router.Pick(router.RoleHarness, router.OpenReasoning, router.Budget{}).Model
	}

	var user strings.Builder
	user.WriteString("OBJECTIVE:\n")
	if strings.TrimSpace(req.Objective) == "" {
		user.WriteString("synthesize a fuzz harness that feeds a byte buffer into this library's input-parsing entry point")
	} else {
		user.WriteString(req.Objective)
	}
	if req.TargetDesc != "" {
		user.WriteString("\n\nTARGET:\n" + req.TargetDesc)
	}
	if req.EntryHint != "" {
		user.WriteString("\n\nPREFERRED ENTRY (use unless the source shows a better input-consuming entry):\n" + req.EntryHint)
	}
	if req.BuildSystem != "" {
		user.WriteString("\n\nBUILD SYSTEM: " + req.BuildSystem)
	}
	if req.SourceInventory != "" {
		user.WriteString("\n\nSEEDED SOURCE (read-only; paths are workspace-relative under the seed base name):\n" + req.SourceInventory)
	} else {
		user.WriteString("\n\n(No source inventory provided. Infer a plausible entry from the objective/target; keep the spec concrete.)")
	}

	chatReq := model.ChatRequest{
		Model: m,
		Messages: []model.Message{
			{Role: "system", Content: harnessSys},
			{Role: "user", Content: user.String()},
		},
		Tools: []model.ToolDef{{
			Name:        "fill_harness_spec",
			Description: "Fill the library-specific gaps of quarry's fixed fuzz-harness skeleton.",
			Parameters:  json.RawMessage(fillHarnessSpecSchema),
		}},
	}
	resp, err := p.Model.Chat(ctx, chatReq)
	if err != nil {
		// refusal is a framing problem, not a routing one: reframe once on the SAME tier
		chatReq.Messages[0].Content = harnessReframe + harnessSys
		resp, err = p.Model.Chat(ctx, chatReq)
	}
	if err != nil {
		return Result{}, err
	}

	spec := parseHarnessSpec(resp)
	if req.EntryHint != "" && strings.TrimSpace(spec.Entry) == "" {
		spec.Entry = req.EntryHint
	}
	return Result{Spec: spec, HarnessC: RenderHarness(spec), Model: m}, nil
}

func parseHarnessSpec(resp model.ChatResponse) HarnessSpec {
	for _, tc := range resp.Message.ToolCalls {
		if tc.Name != "fill_harness_spec" {
			continue
		}
		var s HarnessSpec
		if err := json.Unmarshal([]byte(tc.Arguments), &s); err == nil && specUsable(s) {
			return s
		}
	}
	if resp.Message.Content != "" {
		if s, ok := harnessSpecFromContent(resp.Message.Content); ok {
			return s
		}
	}
	return HarnessSpec{}
}

func specUsable(s HarnessSpec) bool {
	return strings.TrimSpace(s.EntryCall) != "" || strings.TrimSpace(s.Entry) != ""
}

// decodes the first '{' that yields a usable spec; json.Decoder reads exactly one value.
func harnessSpecFromContent(s string) (HarnessSpec, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		var spec HarnessSpec
		if err := json.NewDecoder(strings.NewReader(s[i:])).Decode(&spec); err != nil {
			continue
		}
		if specUsable(spec) {
			return spec, true
		}
	}
	return HarnessSpec{}, false
}

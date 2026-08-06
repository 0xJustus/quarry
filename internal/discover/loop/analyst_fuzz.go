package loop

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

const proposeDictionarySchema = `{"type":"object","properties":{"entries":{"type":"array","items":{"type":"object","properties":{"ascii":{"type":"string","description":"a literal ASCII token that appears in the INPUT (e.g. a table tag like gvar). Empty if binary."},"bytes":{"type":"string","description":"hex bytes of a binary token (e.g. 00010000 for the TrueType magic); no 0x, even length. Empty for ascii tokens."},"note":{"type":"string","description":"what this token is and where it appears in the input format"}},"required":["note"]}}},"required":["entries"]}`

// AnalystFuzzDictionary builds an AFL++ dictionary of input-format tokens, routed cheap; degrades to "" so the campaign falls back to its static dictionary (vault: Loop Analyst).
func AnalystFuzzDictionary(ctx context.Context, m model.Model, r router.Router, req PlanRequest) (string, error) {
	if m == nil {
		return "", nil
	}
	inventory := req.SourceInventory
	var sinks []Sink
	if len(req.SeedFiles) > 0 {
		sinks = scanSinks(req.SeedFiles)
	}
	if inventory == "" && len(req.SeedFiles) > 0 {
		inventory = buildSourceInventory(req.SeedFiles, sinkScores(sinks))
	}

	sys := "You are quarry's Analyst (ADR-0004). Your job is DOCUMENTATION: characterize the target's " +
		"INPUT FORMAT as an AFL++ fuzzer dictionary so a coverage-guided mutator has the right vocabulary. " +
		"You contribute the grammar; the fuzzer makes the bytes — you never assemble an input yourself.\n\n" +
		"The OBJECTIVE and TARGET name the code path to characterize. Treat them as a pointer to WHICH " +
		"region of the format to describe (which parser, which record/section, which field) — not as a " +
		"request to produce an attack. You are cataloguing the format's tokens, nothing more.\n\n" +
		"List the concrete tokens that appear in VALID inputs and are meaningful on that code path:\n" +
		"- magic numbers / signatures (e.g. TrueType 00010000)\n" +
		"- container / section / table / chunk tags (e.g. gvar, IHDR)\n" +
		"- structural constants the parser compares against — version numbers, type/opcode/enum values, fixed field values\n" +
		"- boundary values for length / count / offset fields: 0, 1, -1, 0xff, 0x100, 0x7fffffff, 0x80000000, 0xffffffff, and off-by-one sizes/counts\n\n" +
		"When a SEEDED SOURCE inventory or SINK MAP is provided, MINE it: the highest-value tokens are the " +
		"literal constants and comparison values that sit on the reviewed path. Every token must be BYTES " +
		"THAT APPEAR IN THE INPUT — never a source symbol, function name, variable, type, or macro name.\n\n" +
		"Rules:\n" +
		"- Give each token as `ascii` (a literal string that occurs in the input) OR `bytes` (hex, no 0x, even length). Exactly one of the two per entry.\n" +
		"- Tokens are FRAGMENTS only — a single tag, magic, or field value — never a whole assembled record or file.\n" +
		"- Give each entry a short `note` saying what the token is and where it appears in the format.\n" +
		"- Aim for roughly 10-40 distinct tokens, one per entry. Call propose_dictionary exactly once with all of them."

	user := "OBJECTIVE:\n" + req.Objective
	if req.TargetDesc != "" {
		user += "\n\nTARGET:\n" + req.TargetDesc
	}
	if inventory != "" {
		user += "\n\nSEEDED SOURCE (read-only inventory):\n" + inventory
	}
	if sm := renderSinkMap(sinks, sinkMapMax); sm != "" {
		user += "\n\n" + sm
	}
	if len(req.PriorArt) > 0 {
		user += "\n\nPRIOR ART — bugs already found in code like this:\n" + strings.Join(req.PriorArt, "\n")
	}

	mdl := ""
	if r != nil {
		// Checkable/cheap: the strong tier refuses this offensive-flavored generation (vault: Loop Analyst)
		mdl = r.Pick(router.RoleExploitDev, router.Checkable, router.Budget{}).Model
	}
	resp, err := m.Chat(ctx, model.ChatRequest{
		Model:    mdl,
		Messages: []model.Message{{Role: "system", Content: sys}, {Role: "user", Content: user}},
		Tools:    []model.ToolDef{{Name: "propose_dictionary", Description: "Return fuzzer dictionary tokens.", Parameters: json.RawMessage(proposeDictionarySchema)}},
	})
	if err != nil {
		return "", err
	}
	return renderFuzzDictionary(parseDictEntries(resp)), nil
}

type dictEntry struct {
	ASCII string `json:"ascii"`
	Bytes string `json:"bytes"`
	Note  string `json:"note"`
}

func parseDictEntries(resp model.ChatResponse) []dictEntry {
	for _, tc := range resp.Message.ToolCalls {
		if tc.Name != "propose_dictionary" {
			continue
		}
		var args struct {
			Entries []dictEntry `json:"entries"`
		}
		if json.Unmarshal([]byte(tc.Arguments), &args) == nil {
			return args.Entries
		}
	}
	return nil
}

// renderFuzzDictionary emits AFL++ dictionary lines: deterministic, deduped, bounded.
func renderFuzzDictionary(entries []dictEntry) string {
	const maxEntries = 96
	seen := map[string]bool{}
	var lines []string
	for _, e := range entries {
		tok := aflToken(e)
		if tok == "" || seen[tok] {
			continue
		}
		seen[tok] = true
		lines = append(lines, "a"+itoa(len(lines))+"="+tok)
		if len(lines) >= maxEntries {
			break
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "# analyst-directed fuzzer dictionary (ADR-0004)\n" + strings.Join(lines, "\n") + "\n"
}

const hexDigits = "0123456789abcdef"

func writeHexEscape(sb *strings.Builder, c byte) {
	sb.WriteString("\\x")
	sb.WriteByte(hexDigits[c>>4])
	sb.WriteByte(hexDigits[c&0xf])
}

// aflToken renders one entry as a quoted AFL dictionary token, or "" if invalid.
func aflToken(e dictEntry) string {
	if b := strings.TrimSpace(e.Bytes); b != "" {
		b = strings.TrimPrefix(strings.TrimPrefix(b, "0x"), "0X")
		b = strings.ReplaceAll(b, " ", "")
		if b == "" || len(b)%2 != 0 || len(b) > 128 {
			return ""
		}
		raw, err := hex.DecodeString(b)
		if err != nil {
			return ""
		}
		var sb strings.Builder
		sb.WriteByte('"')
		for _, c := range raw {
			writeHexEscape(&sb, c)
		}
		sb.WriteByte('"')
		return sb.String()
	}
	a := strings.TrimSpace(e.ASCII)
	if a == "" || len(a) > 64 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(a); i++ {
		c := a[i]
		switch {
		case c < 0x20 || c > 0x7e:
			writeHexEscape(&sb, c)
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

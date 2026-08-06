package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
	"github.com/0xjustus/quarry/internal/platform/store"
)

type Compactor interface {
	Compact(ctx context.Context, in CompactInput) ([]model.Message, error)
}

type CompactInput struct {
	System     model.Message
	Objective  string
	Messages   []model.Message // over-budget working history
	KeepRecent int             // recent turns kept verbatim (default 6)

	Facts        []store.Entry
	Observations []store.Entry
	ActiveHyps   []store.Hypothesis
	RuledOut     []store.Hypothesis // anti-drift memory: never re-propose these

	// accumulates compaction's own token spend; nil ⇒ ModelCompactor skips the call (vault: Agent Core)
	Spend *model.Usage
}

// TemplateCompactor renders the digest deterministically, with no model call.
type TemplateCompactor struct{}

func (TemplateCompactor) Compact(_ context.Context, in CompactInput) ([]model.Message, error) {
	keep := in.KeepRecent
	if keep <= 0 {
		keep = 6
	}
	digest := renderDigest(in)
	out := make([]model.Message, 0, keep+2)
	out = append(out, in.System)
	// objective + digest as one user message: keeps clean role alternation
	out = append(out, model.Message{Role: "user", Content: in.Objective + "\n\n" + digest})
	out = append(out, safeSuffix(in.Messages, keep)...)
	return out, nil
}

func renderDigest(in CompactInput) string {
	var b strings.Builder
	b.WriteString("INVESTIGATION STATE (compacted from the durable trajectory; the full record persists and is replayable):\n")

	b.WriteString("\nESTABLISHED FACTS (oracle-verified spine):\n")
	if len(in.Facts) == 0 {
		b.WriteString("  (none yet)\n")
	}
	for _, f := range in.Facts {
		fmt.Fprintf(&b, "  - %s: %s\n", f.Kind, oneLine(f.Value, 240))
	}

	b.WriteString("\nRULED OUT — already tried, do NOT re-propose:\n")
	if len(in.RuledOut) == 0 {
		b.WriteString("  (none yet)\n")
	}
	for _, h := range in.RuledOut {
		why := h.WhyRefuted
		if strings.TrimSpace(why) == "" {
			why = h.State
		}
		fmt.Fprintf(&b, "  - %q — %s\n", oneLine(h.Statement, 160), oneLine(why, 160))
	}

	b.WriteString("\nACTIVE HYPOTHESES (the open frontier):\n")
	if len(in.ActiveHyps) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, h := range in.ActiveHyps {
		fmt.Fprintf(&b, "  - %q\n", oneLine(h.Statement, 200))
	}

	b.WriteString("\nKEY OBSERVATIONS (run_pov verdicts and tool findings so far):\n")
	if len(in.Observations) == 0 {
		b.WriteString("  (none yet)\n")
	}
	for _, o := range in.Observations {
		fmt.Fprintf(&b, "  - %s: %s\n", o.Kind, oneLine(o.Value, 240))
	}

	b.WriteString("\nContinue the investigation from this state; the recent turns below are your live working set.")
	return b.String()
}

// count of leading system+objective msgs the suffix must never reach into
const workingPrefix = 2

// last keep msgs, backed up to an assistant turn (never an orphan tool result)
func safeSuffix(msgs []model.Message, keep int) []model.Message {
	if keep <= 0 || len(msgs) <= workingPrefix {
		return nil
	}
	start := len(msgs) - keep
	if start < workingPrefix {
		start = workingPrefix
	}
	for start > workingPrefix && msgs[start].Role == "tool" {
		start--
	}
	return msgs[start:]
}

func estimateTokens(msgs []model.Message) int {
	total := 0
	for _, m := range msgs {
		total += len(m.Content) + 8 // per-message framing overhead
		for _, tc := range m.ToolCalls {
			total += len(tc.Name) + len(tc.Arguments)
		}
	}
	return total / 4
}

func oneLine(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// ModelCompactor adds a lossy cheap-tier summary of the compacted-away turns; falls back to template-only on failure.
type ModelCompactor struct {
	Model  model.Model
	Router router.Router
}

func (c ModelCompactor) Compact(ctx context.Context, in CompactInput) ([]model.Message, error) {
	base, err := TemplateCompactor{}.Compact(ctx, in)
	if err != nil {
		return nil, err
	}
	if c.Model == nil || c.Router == nil || len(base) < 2 {
		return base, nil
	}
	// no accumulator ⇒ skip the call: unaccountable spend would understate the run (vault: Agent Core)
	if in.Spend == nil {
		return base, nil
	}
	middle := middleTurns(in.Messages, in.KeepRecent)
	if len(middle) == 0 {
		return base, nil
	}
	summary := c.summarize(ctx, middle, in.Spend)
	if strings.TrimSpace(summary) == "" {
		return base, nil // model unavailable; template-only
	}
	base[1].Content += "\n\nNARRATIVE OF THE COMPACTED-AWAY TURNS (lossy summary; the durable state above is authoritative):\n" + summary
	return base, nil
}

// middleTurns is the compacted-away slice: history minus the prefix and last-K suffix.
func middleTurns(msgs []model.Message, keep int) []model.Message {
	if len(msgs) <= workingPrefix {
		return nil
	}
	if keep <= 0 {
		keep = 6
	}
	end := len(msgs) - len(safeSuffix(msgs, keep))
	if end <= workingPrefix {
		return nil
	}
	return msgs[workingPrefix:end]
}

func (c ModelCompactor) summarize(ctx context.Context, middle []model.Message, spend *model.Usage) string {
	var log strings.Builder
	for _, m := range middle {
		log.WriteString(m.Role)
		log.WriteString(": ")
		log.WriteString(oneLine(m.Content, 600))
		for _, tc := range m.ToolCalls {
			fmt.Fprintf(&log, " [tool %s %s]", tc.Name, oneLine(tc.Arguments, 200))
		}
		log.WriteString("\n")
	}
	dec := c.Router.Pick(router.RoleCompactor, router.Checkable, router.Budget{})
	resp, err := c.Model.Chat(ctx, model.ChatRequest{
		Model:     dec.Model,
		MaxTokens: 512,
		Messages: []model.Message{
			{Role: "system", Content: "You compress an exploit-development agent's investigation log. Output a terse summary that PRESERVES: approaches tried, concrete findings (offsets, values, crash sites), and dead ends with the reason. Omit chatter. No preamble."},
			{Role: "user", Content: log.String()},
		},
	})
	// charge before the error check: a failed call still cost tokens
	addUsage(spend, resp.Usage)
	if err != nil {
		return ""
	}
	return resp.Message.Content
}

package loop

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

// ReviewRequest is what the critic sees (no agent history).
type ReviewRequest struct {
	Objective  string
	StopReason string
	Summary    string
}

type ReviewVerdict struct {
	Adequate   bool   `json:"adequate"`
	Reason     string `json:"reason"`
	Suggestion string `json:"suggestion"`
}

type Critic interface {
	Review(ctx context.Context, req ReviewRequest) (ReviewVerdict, error)
}

// ModelCritic is a model-backed critic; fresh context, never sees the trajectory.
type ModelCritic struct {
	Model  model.Model
	Router router.Router
}

func (c ModelCritic) Review(ctx context.Context, req ReviewRequest) (ReviewVerdict, error) {
	if c.Model == nil {
		return ReviewVerdict{Adequate: true}, nil
	}
	decision := router.Decision{Model: ""}
	if c.Router != nil {
		decision = c.Router.Pick(router.RoleCritic, router.OpenReasoning, router.Budget{})
	}
	sys := "You are a skeptical scientific reviewer auditing a defensive vulnerability-research agent (the \"scientist\"). Every candidate finding is decided by a deterministic oracle, which is the sole judge; the scientist just STOPPED without an oracle-confirmed result. You do NOT see its work — only the objective, the stop reason, and the conclusion it wrote for itself.\n\n" +
		"Make a calibrated adequacy judgment: was the objective plausibly explored well enough, or did the agent likely give up early, drift off the stated objective, or conclude generically without engaging the specific mechanism? You have thin evidence, so read the conclusion as a signal: a concrete, objective-specific account of what was examined and ruled out is evidence of adequate work; a vague \"nothing found\" with no named input region, code path, or failure mode is evidence of a premature stop. Do not demand certainty — you are flagging likely early-stop/drift, not proving it.\n\n" +
		"If the work is INADEQUATE, propose exactly ONE next step: a single sub-hypothesis that is strictly narrower than the original objective and directly testable by the oracle (for example a specific input region, parser/decoder state, size or length boundary, malformed-field class, or code path worth probing). State it as a defensive research hypothesis about how the program behaves under that condition — never as an exploit recipe or an instruction to trigger a crash. Under this project's method the agent DIRECTS a coverage-guided fuzzer rather than hand-authoring inputs, so express the sub-hypothesis in terms of what to fuzz: which seed/corpus to select, which grammar or dictionary tokens to add, and which target function/section to point the fuzzer at — never a literal byte string to submit. If the work is ADEQUATE, propose nothing.\n\n" +
		"Return STRICT JSON and nothing else: no markdown, no code fences, no text before or after, a single flat object with exactly these three keys and no others:\n" +
		"{\"adequate\": true|false, \"reason\": \"one or two sentences justifying the verdict\", \"suggestion\": \"the single sub-hypothesis, or an empty string\"}\n" +
		"`adequate` MUST be a JSON boolean literal (true or false), not a string. `reason` and `suggestion` MUST be plain JSON strings with no nested objects or braces. `suggestion` is non-empty only when `adequate` is false; when `adequate` is true it MUST be \"\". Do not add, rename, reorder-away, or nest keys."
	user := fmt.Sprintf("OBJECTIVE: %s\nSTOP REASON: %s\nAGENT CONCLUSION: %s", req.Objective, req.StopReason, truncate(req.Summary, 800))

	resp, err := c.Model.Chat(ctx, model.ChatRequest{
		Model:    decision.Model,
		Messages: []model.Message{{Role: "system", Content: sys}, {Role: "user", Content: user}},
	})
	if err != nil {
		return ReviewVerdict{Adequate: true}, err // fail-open on critic error
	}
	return parseVerdict(resp.Message.Content), nil
}

// parseVerdict extracts verdict JSON, tolerant of surrounding prose/fences.
func parseVerdict(s string) ReviewVerdict {
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	v := ReviewVerdict{Adequate: true}
	if i >= 0 && j > i {
		_ = json.Unmarshal([]byte(s[i:j+1]), &v)
	}
	v.Suggestion = strings.TrimSpace(v.Suggestion)
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

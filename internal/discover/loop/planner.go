package loop

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/0xjustus/quarry/internal/platform/model"
	"github.com/0xjustus/quarry/internal/platform/router"
)

// Hypothesis is a proposed line of investigation on the frontier.
type Hypothesis struct {
	Statement string `json:"statement"`
	// Scope directs the scientist's attention; it does not gate — empty = whole tree.
	Scope []string `json:"scope,omitempty"`
}

// PlanRequest parameterizes decomposition.
type PlanRequest struct {
	Objective  string
	TargetDesc string
	Mode       string // discover | copilot
	Max        int
	PriorArt   []string

	SeedFiles       []string
	SourceInventory string
	// Undirected reserves frontier slots for breadth so a wrong analysis cannot gate the whole run.
	Undirected int
}

// Planner decomposes an objective into hypotheses.
type Planner interface {
	Plan(ctx context.Context, req PlanRequest) ([]Hypothesis, error)
}

// SingleHypothesis is the trivial planner: the objective is the one hypothesis.
type SingleHypothesis struct{}

func (SingleHypothesis) Plan(_ context.Context, req PlanRequest) ([]Hypothesis, error) {
	return []Hypothesis{{Statement: req.Objective}}, nil
}

// ModelPlanner asks a model to decompose the objective; degrades to the objective itself.
type ModelPlanner struct {
	Model  model.Model
	Router router.Router
}

const proposeToolSchema = `{"type":"object","properties":{"hypotheses":{"type":"array","items":{"type":"object","properties":{"statement":{"type":"string","description":"a concrete, independently testable hypothesis, e.g. 'the length field in parse_header is unchecked and overflows buf'"}},"required":["statement"]}}},"required":["hypotheses"]}`

func (p ModelPlanner) Plan(ctx context.Context, req PlanRequest) ([]Hypothesis, error) {
	sys := `You are quarry's planner, the analysis stage of a defensive software-hardening pipeline that finds latent input-handling defects so maintainers can fix them. Decompose the OBJECTIVE for the given TARGET into a small set of INDEPENDENT, separately-testable hypotheses about where the target's handling of untrusted input could fail — the kind of reliability defect (memory-safety error, unbounded resource use, unhandled edge case) an auditor reports to be fixed.

Each hypothesis is a distinct branch that a separate analyst investigates in parallel, so they must not overlap: cover different functions, fields, input paths, or failure mechanisms rather than restating one idea in different words. Make each one concrete and falsifiable — in the statement, anchor it to a specific location (function, field, or input path), name the defect mechanism or class (e.g. unchecked length, integer overflow, missing bounds check, unbounded recursion, use-after-free), and state what a deterministic oracle would observe if the hypothesis holds (e.g. out-of-bounds write, hang/timeout, assertion failure, crash). Prefer sharp, checkable claims over vague ones. A good statement reads like: "the length field in parse_header is unchecked and overflows buf, giving an out-of-bounds write."

Describe WHERE a defect may be reachable and WHY it is plausible. Do NOT write exploit inputs, payloads, or concrete crafted bytes — downstream stages generate and test the inputs; your job is to point them at the right code and mechanism. If PRIOR ART is supplied, prioritize hypotheses in those defect classes and around those code sites. If a maximum count is given, propose at most that many, spent on the highest-value, most-distinct leads.

Return your analysis by calling propose_hypotheses exactly once. Put one entry per hypothesis in the ` + "`hypotheses`" + ` array, with the full hypothesis text in that entry's ` + "`statement`" + ` field.`
	user := "OBJECTIVE:\n" + req.Objective
	if req.TargetDesc != "" {
		user += "\n\nTARGET:\n" + req.TargetDesc
	}
	if len(req.PriorArt) > 0 {
		user += "\n\nPRIOR ART — vulnerabilities already found in code like this; let these DIRECT your hypotheses toward the same bug classes, crash sites, and techniques:\n" + strings.Join(req.PriorArt, "\n")
	}
	if req.Max > 0 {
		user += "\n\nPropose at most " + itoa(req.Max) + " hypotheses."
	}

	m := req.Objective
	if p.Router != nil {
		m = p.Router.Pick(router.RoleSupervisor, router.OpenReasoning, router.Budget{}).Model
	}
	resp, err := p.Model.Chat(ctx, model.ChatRequest{
		Model:    m,
		Messages: []model.Message{{Role: "system", Content: sys}, {Role: "user", Content: user}},
		Tools:    []model.ToolDef{{Name: "propose_hypotheses", Description: "Return the decomposed hypotheses.", Parameters: json.RawMessage(proposeToolSchema)}},
	})
	if err != nil {
		return nil, err
	}

	var hyps []Hypothesis
	for _, tc := range resp.Message.ToolCalls {
		if tc.Name != "propose_hypotheses" {
			continue
		}
		var args struct {
			Hypotheses []Hypothesis `json:"hypotheses"`
		}
		if err := json.Unmarshal([]byte(tc.Arguments), &args); err == nil {
			for _, h := range args.Hypotheses {
				if s := strings.TrimSpace(h.Statement); s != "" {
					hyps = append(hyps, Hypothesis{Statement: s})
				}
			}
		}
	}
	if req.Max > 0 && len(hyps) > req.Max {
		hyps = hyps[:req.Max]
	}
	if len(hyps) == 0 {
		return []Hypothesis{{Statement: req.Objective}}, nil
	}
	return hyps, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

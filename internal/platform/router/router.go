package router

import (
	"fmt"
	"strings"
)

// Role scopes an agent's prompt and tool access.
type Role string

const (
	RoleSupervisor Role = "supervisor"
	RoleAnalyst    Role = "analyst"
	RoleHarness    Role = "harness"
	RoleTriage     Role = "triage"
	RoleExploitDev Role = "exploit-dev"
	RoleCritic     Role = "critic"
	RoleVerifier   Role = "verifier"
	RoleCompactor  Role = "compactor"
)

// TaskKind is whether the output is machine-checkable.
type TaskKind string

const (
	Checkable     TaskKind = "checkable"
	OpenReasoning TaskKind = "open-reasoning"
)

// Budget is the remaining spend envelope.
type Budget struct {
	RemainingUSD    float64
	RemainingTokens int
}

type Decision struct {
	Model    string
	Role     Role
	TaskKind TaskKind
	Reason   string
}

type Router interface {
	Pick(role Role, kind TaskKind, budget Budget) Decision
}

// Degradable self-reports a collapse onto ONE tier — strong-tier corroboration becomes self-corroboration (vault: Model Access).
type Degradable interface {
	Degraded() string
}

func degradedTiers(cheap, strong string) string {
	switch {
	case strong == "":
		return fmt.Sprintf("no strong tier configured — every step routes to %q", cheap)
	case strong == cheap:
		return fmt.Sprintf("strong tier names the same model as the cheap tier (%q)", cheap)
	}
	return ""
}

// StaticRouter uses one default model, optionally overridden per-role.
type StaticRouter struct {
	Default string
	PerRole map[Role]string
}

func NewStaticRouter(defaultModel string) *StaticRouter {
	return &StaticRouter{Default: defaultModel, PerRole: map[Role]string{}}
}

func (r *StaticRouter) WithRole(role Role, model string) *StaticRouter {
	if r.PerRole == nil {
		r.PerRole = map[Role]string{}
	}
	r.PerRole[role] = model
	return r
}

func (r *StaticRouter) Pick(role Role, kind TaskKind, _ Budget) Decision {
	m := r.Default
	reason := "static default"
	if override, ok := r.PerRole[role]; ok && override != "" {
		m = override
		reason = "static per-role override"
	}
	return Decision{Model: m, Role: role, TaskKind: kind, Reason: reason}
}

// always degraded: single-tier by construction
func (r *StaticRouter) Degraded() string {
	return fmt.Sprintf("static router — every role routes to the single model %q", r.Default)
}

// TieredRouter routes by checkability and budget, with per-role overrides.
type TieredRouter struct {
	Cheap           string
	Strong          string
	PerRole         map[Role]string
	LowBudgetTokens int
}

func NewTieredRouter(cheap, strong string) *TieredRouter {
	if strong == "" {
		strong = cheap
	}
	return &TieredRouter{Cheap: cheap, Strong: strong, PerRole: map[Role]string{}, LowBudgetTokens: 0}
}

func (r *TieredRouter) WithRole(role Role, model string) *TieredRouter {
	if r.PerRole == nil {
		r.PerRole = map[Role]string{}
	}
	r.PerRole[role] = model
	return r
}

func (r *TieredRouter) Pick(role Role, kind TaskKind, budget Budget) Decision {
	if m, ok := r.PerRole[role]; ok && m != "" {
		return Decision{Model: m, Role: role, TaskKind: kind, Reason: "per-role override (decorrelation)"}
	}
	if r.LowBudgetTokens > 0 && budget.RemainingTokens > 0 && budget.RemainingTokens < r.LowBudgetTokens {
		return Decision{Model: r.Cheap, Role: role, TaskKind: kind, Reason: "budget cascade → cheap tier"}
	}
	if kind == Checkable {
		return Decision{Model: r.Cheap, Role: role, TaskKind: kind, Reason: "checkable → cheap tier (oracle backstops)"}
	}
	return Decision{Model: r.Strong, Role: role, TaskKind: kind, Reason: "open-reasoning → strong tier"}
}

func (r *TieredRouter) Degraded() string { return degradedTiers(r.Cheap, r.Strong) }

// CascadeRouter runs cheap by default and escalates only for frontier work with budget.
type CascadeRouter struct {
	Cheap         string
	Strong        string
	PerRole       map[Role]string
	FrontierRoles map[Role]bool
	// escalation floors; zero for a dimension means that dimension never gates
	EscalateFloorUSD    float64
	EscalateFloorTokens int
}

func NewCascadeRouter(cheap, strong string) *CascadeRouter {
	if strong == "" {
		strong = cheap
	}
	return &CascadeRouter{Cheap: cheap, Strong: strong, PerRole: map[Role]string{}, FrontierRoles: map[Role]bool{}}
}

func (r *CascadeRouter) WithRole(role Role, model string) *CascadeRouter {
	if r.PerRole == nil {
		r.PerRole = map[Role]string{}
	}
	r.PerRole[role] = model
	return r
}

// WithFrontierRole marks a role escalation-worthy even when its work is checkable.
func (r *CascadeRouter) WithFrontierRole(role Role) *CascadeRouter {
	if r.FrontierRoles == nil {
		r.FrontierRoles = map[Role]bool{}
	}
	r.FrontierRoles[role] = true
	return r
}

func (r *CascadeRouter) onFrontier(role Role, kind TaskKind) bool {
	return kind == OpenReasoning || r.FrontierRoles[role]
}

// an unreported budget dimension (Remaining == 0) must never block escalation
func (r *CascadeRouter) budgetAllows(budget Budget) bool {
	if r.EscalateFloorUSD > 0 && budget.RemainingUSD > 0 && budget.RemainingUSD < r.EscalateFloorUSD {
		return false
	}
	if r.EscalateFloorTokens > 0 && budget.RemainingTokens > 0 && budget.RemainingTokens < r.EscalateFloorTokens {
		return false
	}
	return true
}

func (r *CascadeRouter) Pick(role Role, kind TaskKind, budget Budget) Decision {
	if m, ok := r.PerRole[role]; ok && m != "" {
		return Decision{Model: m, Role: role, TaskKind: kind, Reason: "per-role override (decorrelation)"}
	}
	if !r.onFrontier(role, kind) {
		return Decision{Model: r.Cheap, Role: role, TaskKind: kind, Reason: "off-frontier → cheap tier (oracle backstops)"}
	}
	if !r.budgetAllows(budget) {
		return Decision{Model: r.Cheap, Role: role, TaskKind: kind, Reason: "frontier but budget below floor → hold at cheap"}
	}
	return Decision{Model: r.Strong, Role: role, TaskKind: kind, Reason: "cascade escalate → strong (frontier + budget)"}
}

func (r *CascadeRouter) Degraded() string { return degradedTiers(r.Cheap, r.Strong) }

// EnsembleDecision is a slate of models the caller runs in parallel.
type EnsembleDecision struct {
	Models   []string
	Role     Role
	TaskKind TaskKind
	Reason   string
}

type EnsembleRouter struct {
	// cheap-FIRST ordering: the head is the cheap tier, never the best model
	Pool    []string
	Strong  string
	PerRole map[Role]string
}

func NewEnsembleRouter(pool ...string) *EnsembleRouter {
	return &EnsembleRouter{Pool: pool, PerRole: map[Role]string{}}
}

func (r *EnsembleRouter) WithRole(role Role, model string) *EnsembleRouter {
	if r.PerRole == nil {
		r.PerRole = map[Role]string{}
	}
	r.PerRole[role] = model
	return r
}

// WithStrong declares the strong tier, joining the pool so the fan-out sees it too.
func (r *EnsembleRouter) WithStrong(model string) *EnsembleRouter {
	r.Strong = model
	if model == "" {
		return r
	}
	for _, m := range r.Pool {
		if m == model {
			return r
		}
	}
	r.Pool = append(r.Pool, model)
	return r
}

func (r *EnsembleRouter) head() string {
	for _, m := range r.Pool {
		if m != "" {
			return m
		}
	}
	return ""
}

// stay tier-aware: pool is cheap-first, so the head must never serve a strong-tier request as one (vault: Model Access).
func (r *EnsembleRouter) Pick(role Role, kind TaskKind, _ Budget) Decision {
	if m, ok := r.PerRole[role]; ok && m != "" {
		return Decision{Model: m, Role: role, TaskKind: kind, Reason: "per-role override (decorrelation)"}
	}
	cheap := r.head()
	if kind != Checkable && r.Strong != "" {
		return Decision{Model: r.Strong, Role: role, TaskKind: kind, Reason: "open-reasoning → strong tier"}
	}
	if cheap == "" {
		return Decision{Role: role, TaskKind: kind, Reason: "empty ensemble pool"}
	}
	if kind == Checkable {
		return Decision{Model: cheap, Role: role, TaskKind: kind, Reason: "checkable → ensemble head / cheap tier (oracle backstops)"}
	}
	return Decision{Model: cheap, Role: role, TaskKind: kind,
		Reason: "open-reasoning but NO strong tier declared → DEGRADED to ensemble head (strong-tier independence does not hold)"}
}

func (r *EnsembleRouter) Degraded() string {
	head := r.head()
	if head == "" {
		return "empty ensemble pool — no model declared"
	}
	return degradedTiers(head, r.Strong)
}

// PickN returns up to n models, one per unseen family in pool order, then distinct backfill; deterministic.
func (r *EnsembleRouter) PickN(n int, role Role, kind TaskKind) EnsembleDecision {
	d := EnsembleDecision{Role: role, TaskKind: kind}
	if n <= 0 || len(r.Pool) == 0 {
		d.Reason = "no ensemble picks (n<=0 or empty pool)"
		return d
	}
	seenModel := map[string]bool{}
	seenFamily := map[string]bool{}
	picked := []string{}
	for _, m := range r.Pool {
		if len(picked) >= n {
			break
		}
		if m == "" || seenModel[m] {
			continue
		}
		fam := Family(m)
		if seenFamily[fam] {
			continue
		}
		seenFamily[fam] = true
		seenModel[m] = true
		picked = append(picked, m)
	}
	for _, m := range r.Pool {
		if len(picked) >= n {
			break
		}
		if m == "" || seenModel[m] {
			continue
		}
		seenModel[m] = true
		picked = append(picked, m)
	}
	d.Models = picked
	d.Reason = "ensemble fan-out (family-diverse)"
	return d
}

// Family is LINEAGE not transport: the -ant wire tag is stripped before classifying (vault: Model Access).
func Family(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if t := strings.TrimSuffix(m, "-ant"); t != "" {
		m = t
	}
	switch {
	case m == "":
		return ""
	case strings.HasPrefix(m, "claude"), strings.HasPrefix(m, "opus"),
		strings.HasPrefix(m, "sonnet"), strings.HasPrefix(m, "haiku"):
		return "anthropic"
	case strings.HasPrefix(m, "gpt"), strings.HasPrefix(m, "o1"),
		strings.HasPrefix(m, "o3"), strings.HasPrefix(m, "o4"):
		return "openai"
	case strings.HasPrefix(m, "glm"), strings.Contains(m, "zhipu"):
		return "zhipu"
	case strings.HasPrefix(m, "gemini"), strings.Contains(m, "google"):
		return "google"
	case strings.HasPrefix(m, "llama"), strings.Contains(m, "llama"):
		return "meta"
	case strings.HasPrefix(m, "mistral"), strings.HasPrefix(m, "mixtral"):
		return "mistral"
	case strings.HasPrefix(m, "deepseek"):
		return "deepseek"
	case strings.HasPrefix(m, "qwen"):
		return "qwen"
	default:
		return m
	}
}

// CriticFor returns a cross-family critic, or "" — no decorrelated critic available, never license to self-review.
func CriticFor(worker string, tiers ...string) string {
	wf := Family(worker)
	for _, t := range tiers {
		if t == "" || t == worker {
			continue
		}
		if Family(t) != wf {
			return t
		}
	}
	return ""
}

var (
	_ Router = (*StaticRouter)(nil)
	_ Router = (*TieredRouter)(nil)
	_ Router = (*CascadeRouter)(nil)
	_ Router = (*EnsembleRouter)(nil)

	// every router must report its own tier collapse
	_ Degradable = (*StaticRouter)(nil)
	_ Degradable = (*TieredRouter)(nil)
	_ Degradable = (*CascadeRouter)(nil)
	_ Degradable = (*EnsembleRouter)(nil)
)

package artifact

import (
	"sort"
	"strings"
)

// LogicPattern is a logic bug reduced to its transferable shape — no target names/files/bytes (vault: Artifact Identity).
type LogicPattern struct {
	Kind      string
	Roles     []string
	Invariant string
}

// identical shape ⇒ identical behavioral key across targets
func (p LogicPattern) Crash() Crash {
	roles := normalizeRoles(p.Roles)
	frames := append([]string{"logic:" + normKind(p.Kind)}, roles...)
	return Crash{
		BugClass: "logic-pattern:" + normKind(p.Kind),
		Sites:    []string{normKind(p.Kind)},
		Frames:   frames,
		PathSig:  normInvariant(p.Invariant),
	}
}

func (p LogicPattern) Key() string { c := p.Crash(); return ComputeBehavioralKey(c) }

func (p LogicPattern) Abstract() string {
	roles := normalizeRoles(p.Roles)
	return "logic-pattern " + normKind(p.Kind) + " over roles [" + strings.Join(roles, ", ") + "]" +
		"; invariant violated: " + normInvariant(p.Invariant) + " (shape only — no target specimen)"
}

// the concrete entry/sink/auth names are DROPPED so the pattern transfers
func MissingAuthzPattern() LogicPattern {
	return LogicPattern{
		Kind:      "missing-authz",
		Roles:     []string{"entry", "auth-gate", "sink"},
		Invariant: "reach(entry, sink) AND NOT through(auth-gate)",
	}
}

func normalizeRoles(roles []string) []string {
	out := make([]string, 0, len(roles))
	seen := map[string]bool{}
	for _, r := range roles {
		r = normToken(r)
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out) // order-independent shape
	return out
}

func normKind(k string) string { return normToken(k) }

func normToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// phrasing differences must not fork the key
func normInvariant(inv string) string {
	inv = strings.ToLower(strings.TrimSpace(inv))
	return strings.Join(strings.Fields(inv), " ")
}
